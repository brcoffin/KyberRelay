package main

import (
	"crypto/sha1"
	"crypto/subtle"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// --- security headers (incl. HSTS) ---

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		// Scripts and styles are external (no inline) on every served page, so
		// the policy is strict same-origin with no 'unsafe-inline'.
		h.Set("Content-Security-Policy",
			"default-src 'self'; img-src 'self' data:; "+
				"style-src 'self'; script-src 'self'; "+
				"base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}

// clientIP returns the real client IP. X-Forwarded-For is a comma-separated
// chain in which the trusted reverse proxy (Caddy) appends the immediate client
// as the LAST entry; the leftmost entries are client-supplied and spoofable, so
// taking the rightmost prevents an attacker from forging the IP used for
// rate-limiting and audit logging.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[len(parts)-1])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// --- CSRF: cross-origin guard for cookie-authenticated, state-changing requests ---

// csrfGuard defends state-changing requests with two layers: a same-origin
// check (Origin/Referer), and — once a session exists — a per-session
// synchronizer token. The Bearer API (Authorization header, not sent cross-site
// automatically) and the signature-verified Stripe webhook are not
// cookie-authenticated, so they are exempt. Pre-auth POSTs (login/register/totp)
// have no session yet and rely on the origin check alone.
func (s *server) csrfGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
			if r.Header.Get("Authorization") != "" || r.URL.Path == "/api/billing/webhook" {
				break // not cookie-authenticated
			}
			if !sameOrigin(r, s.cfg.host) {
				http.Error(w, "cross-origin request blocked", http.StatusForbidden)
				return
			}
			// The public contact form has no session token; it relies on the
			// same-origin check above plus a honeypot + rate limit.
			if r.URL.Path != "/api/contact" {
				if sess, ok := s.sessions.current(r); ok && !validCSRFToken(r, sess.csrf) {
					http.Error(w, "invalid or missing CSRF token", http.StatusForbidden)
					return
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

// validCSRFToken checks the submitted token (X-CSRF-Token header for fetch/XHR,
// or the csrf_token field for plain HTML form posts) against the session's
// token in constant time. The form-field fallback only parses urlencoded bodies
// — multipart uploads always carry the header, so their body is never consumed
// here.
func validCSRFToken(r *http.Request, want string) bool {
	got := r.Header.Get("X-CSRF-Token")
	if got == "" {
		ct := r.Header.Get("Content-Type")
		if i := strings.IndexByte(ct, ';'); i >= 0 {
			ct = ct[:i]
		}
		if strings.TrimSpace(ct) == "application/x-www-form-urlencoded" {
			_ = r.ParseForm()
			got = r.PostForm.Get("csrf_token")
		}
	}
	return want != "" && subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

// sameOrigin reports whether the request's Origin (or Referer, as a fallback)
// host matches the service's own host. A missing or unparseable header fails
// closed — browsers send at least one of these on state-changing requests.
func sameOrigin(r *http.Request, allowedHost string) bool {
	o := r.Header.Get("Origin")
	if o == "" {
		o = r.Header.Get("Referer")
	}
	if o == "" {
		return false
	}
	u, err := url.Parse(o)
	if err != nil || u.Host == "" {
		return false
	}
	if strings.EqualFold(u.Host, r.Host) {
		return true
	}
	return allowedHost != "" && strings.EqualFold(u.Host, allowedHost)
}

// --- login brute-force guard ---

// loginGuard tracks recent failures per key (username and IP) and locks out
// after `max` failures within `window`.
type loginGuard struct {
	mu     sync.Mutex
	fails  map[string][]time.Time
	max    int
	window time.Duration
}

func newLoginGuard(max int, window time.Duration) *loginGuard {
	return &loginGuard{fails: make(map[string][]time.Time), max: max, window: window}
}

func (g *loginGuard) recent(key string, now time.Time) []time.Time {
	cutoff := now.Add(-g.window)
	kept := g.fails[key][:0]
	for _, t := range g.fails[key] {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	g.fails[key] = kept
	return kept
}

func (g *loginGuard) locked(key string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.recent(key, time.Now())) >= g.max
}

func (g *loginGuard) fail(key string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := time.Now()
	g.fails[key] = append(g.recent(key, now), now)
}

func (g *loginGuard) reset(key string) {
	g.mu.Lock()
	delete(g.fails, key)
	g.mu.Unlock()
}

// --- breached-password check (Have I Been Pwned, k-anonymity) ---

// passwordBreached reports whether the password appears in the HIBP corpus. It
// sends only the first 5 chars of the SHA-1 hash (k-anonymity) — never the
// password. Returns (false, err) if HIBP can't be reached; callers fail open.
func passwordBreached(password string) (bool, error) {
	sum := sha1.Sum([]byte(password))
	hash := strings.ToUpper(hex.EncodeToString(sum[:]))
	prefix, suffix := hash[:5], hash[5:]

	req, err := http.NewRequest(http.MethodGet,
		"https://api.pwnedpasswords.com/range/"+prefix, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Add-Padding", "true")
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return false, err
	}
	for _, line := range strings.Split(string(body), "\n") {
		row := strings.SplitN(strings.TrimSpace(line), ":", 2)
		if len(row) == 2 && strings.EqualFold(row[0], suffix) && row[1] != "0" {
			return true, nil
		}
	}
	return false, nil
}
