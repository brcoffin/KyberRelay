// Command web is the Kyber-Zip hosted file-transfer service.
//
// Convenience-first, server-side model: a browser uploads a file plus a
// passphrase; the server compresses, encrypts (AES-256-GCM, key derived from
// the passphrase), and stores only ciphertext + a salt/nonce sidecar. A
// recipient opens the share link, enters the passphrase, and downloads. The
// server sees plaintext only transiently while processing; at rest, nothing is
// readable without the passphrase.
//
// This is the link+passphrase MVP; the storage and crypto layers are kept
// pluggable so a public-key/accounts model (ML-KEM) can be added later.
package main

import (
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

//go:embed templates/*.html
var templatesFS embed.FS

//go:embed static
var staticFS embed.FS

type config struct {
	addr       string
	dataDir    string
	baseURL    string
	host       string // baseURL's host, for the same-origin CSRF check
	maxBytes   int64
	defaultTTL time.Duration
	secure     bool // mark session cookies Secure (true when served over HTTPS)
}

func loadConfig() config {
	baseURL := env("WEB_BASE_URL", "http://127.0.0.1:8090")
	host := ""
	if u, err := url.Parse(baseURL); err == nil {
		host = u.Host
	}
	return config{
		addr:       env("WEB_ADDR", "127.0.0.1:8090"),
		dataDir:    env("WEB_DATA_DIR", "./web-data"),
		baseURL:    baseURL,
		host:       host,
		maxBytes:   envInt64("WEB_MAX_BYTES", 100<<20), // 100 MiB
		defaultTTL: envDuration("WEB_TTL", 24*time.Hour),
		secure:     strings.HasPrefix(baseURL, "https://"),
	}
}

type server struct {
	cfg        config
	store      *store
	accounts   *accounts
	msgs       *messages
	apikeys    *apikeyStore
	sessions   *sessionStore
	pending    *pendingStore
	loginGuard *loginGuard
	regGuard   *loginGuard // rate-limits registration and 2FA setup
	uploadSem  chan struct{}
	billing    *billingConfig
	audit      *auditor
	tmpl       *template.Template
}

func (s *server) render(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(w, name, data); err != nil {
		log.Printf("web: template %s: %v", name, err)
	}
}

// newServer builds the server and all its stores from cfg. Used by main() and
// by the integration tests (which point cfg.dataDir at a temp dir).
func newServer(cfg config) (*server, error) {
	st, err := newStore(cfg.dataDir)
	if err != nil {
		return nil, fmt.Errorf("data dir: %w", err)
	}
	acct, err := newAccounts(filepath.Join(cfg.dataDir, "users"))
	if err != nil {
		return nil, fmt.Errorf("accounts dir: %w", err)
	}
	msgs, err := newMessages(filepath.Join(cfg.dataDir, "inbox"))
	if err != nil {
		return nil, fmt.Errorf("inbox dir: %w", err)
	}
	keys, err := newAPIKeyStore(filepath.Join(cfg.dataDir, "apikeys"))
	if err != nil {
		return nil, fmt.Errorf("apikeys dir: %w", err)
	}
	tmpl, err := template.ParseFS(templatesFS, "templates/*.html")
	if err != nil {
		return nil, fmt.Errorf("templates: %w", err)
	}
	maxUploads := int(envInt64("WEB_MAX_UPLOADS", 6))
	if maxUploads < 1 {
		maxUploads = 1
	}
	return &server{
		cfg: cfg, store: st, accounts: acct, msgs: msgs, apikeys: keys,
		sessions:   newSessionStore(12 * time.Hour),
		pending:    newPendingStore(5 * time.Minute),
		loginGuard: newLoginGuard(5, 15*time.Minute),
		regGuard:   newLoginGuard(20, time.Hour),
		uploadSem:  make(chan struct{}, maxUploads),
		billing:    loadBilling(),
		audit:      newAuditor(cfg.dataDir),
		tmpl:       tmpl,
	}, nil
}

// handler builds the full routed handler chain (mux + security middleware).
func (s *server) handler() http.Handler {
	mux := http.NewServeMux()
	// Account-first: "/" routes to the app or login. The anonymous
	// link+passphrase endpoints are intentionally not registered.
	mux.HandleFunc("GET /", s.handleRoot)
	mux.HandleFunc("GET /healthz", s.handleHealth)

	// Static assets (logos, stylesheet) served from the embedded FS.
	if sub, err := fs.Sub(staticFS, "static"); err == nil {
		mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(sub)))
	}

	// Accounts (send-by-username)
	mux.HandleFunc("GET /register", s.handleRegisterPage)
	mux.HandleFunc("POST /api/register", s.handleRegister)
	mux.HandleFunc("GET /login", s.handleLoginPage)
	mux.HandleFunc("POST /api/login", s.handleLogin)
	mux.HandleFunc("POST /api/login/totp", s.handleLoginTOTP)
	mux.HandleFunc("POST /api/logout", s.handleLogout)
	mux.HandleFunc("POST /api/account/password", s.handleChangePassword)
	mux.HandleFunc("POST /api/2fa/setup", s.handle2FASetup)
	mux.HandleFunc("POST /api/2fa/enable", s.handle2FAEnable)
	mux.HandleFunc("POST /api/2fa/disable", s.handle2FADisable)
	mux.HandleFunc("POST /api/2fa/recovery", s.handle2FARecovery)
	mux.HandleFunc("GET /app", s.handleApp)
	mux.HandleFunc("POST /api/send", s.handleSend)
	mux.HandleFunc("GET /api/msg/{id}", s.handleMsgDownload)
	mux.HandleFunc("POST /api/msg/{id}/delete", s.handleMsgDelete)

	// API key management (session-authenticated, from the dashboard)
	mux.HandleFunc("POST /api/keys", s.handleKeyCreate)
	mux.HandleFunc("GET /api/keys", s.handleKeyList)
	mux.HandleFunc("POST /api/keys/{id}/delete", s.handleKeyRevoke)

	// Programmatic API (Bearer token auth)
	mux.HandleFunc("POST /api/v1/send", s.apiSend)
	mux.HandleFunc("GET /api/v1/inbox", s.apiInbox)
	mux.HandleFunc("GET /api/v1/messages/{id}", s.apiMsgGet)
	mux.HandleFunc("DELETE /api/v1/messages/{id}", s.apiMsgDelete)

	// Billing (Stripe)
	mux.HandleFunc("GET /pricing", s.handlePricing)
	mux.HandleFunc("POST /api/billing/checkout", s.handleCheckout)
	mux.HandleFunc("POST /api/billing/webhook", s.handleWebhook)
	mux.HandleFunc("GET /billing/success", s.handleBillingSuccess)

	return securityHeaders(s.csrfGuard(mux))
}

func main() {
	cfg := loadConfig()
	s, err := newServer(cfg)
	if err != nil {
		log.Fatalf("web: %v", err)
	}

	if err := s.audit.verify(); err != nil {
		log.Printf("web: AUDIT LOG INTEGRITY WARNING: %v", err)
	} else {
		log.Printf("web: audit log integrity OK")
	}

	// Periodic sweep of expired items + inbox messages.
	go func() {
		for {
			s.store.sweep()
			s.msgs.sweep()
			time.Sleep(cfg.defaultTTL / 4)
		}
	}()

	srv := &http.Server{
		Addr:              cfg.addr,
		Handler:           s.handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Printf("web: listening on %s (base %s), data=%s, max=%dB",
		cfg.addr, cfg.baseURL, cfg.dataDir, cfg.maxBytes)
	log.Fatal(srv.ListenAndServe())
}

// --- env helpers ---

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func envInt64(k string, def int64) int64 {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			return n
		}
	}
	return def
}

func envDuration(k string, def time.Duration) time.Duration {
	if v := os.Getenv(k); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}
