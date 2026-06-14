package main

import (
	"crypto/sha1"
	"encoding/hex"
	"io"
	"net"
	"net/http"
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

// clientIP returns the real client IP, honoring the proxy's X-Forwarded-For
// (Caddy sets it; RemoteAddr would otherwise be 127.0.0.1).
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.IndexByte(xff, ','); i >= 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
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
