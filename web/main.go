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
	"html/template"
	"io/fs"
	"log"
	"net/http"
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
	maxBytes   int64
	defaultTTL time.Duration
	secure     bool // mark session cookies Secure (true when served over HTTPS)
}

func loadConfig() config {
	baseURL := env("WEB_BASE_URL", "http://127.0.0.1:8090")
	return config{
		addr:       env("WEB_ADDR", "127.0.0.1:8090"),
		dataDir:    env("WEB_DATA_DIR", "./web-data"),
		baseURL:    baseURL,
		maxBytes:   envInt64("WEB_MAX_BYTES", 100<<20), // 100 MiB
		defaultTTL: envDuration("WEB_TTL", 24*time.Hour),
		secure:     strings.HasPrefix(baseURL, "https://"),
	}
}

type server struct {
	cfg      config
	store    *store
	accounts *accounts
	msgs     *messages
	apikeys    *apikeyStore
	sessions   *sessionStore
	pending    *pendingStore
	loginGuard *loginGuard
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

func main() {
	cfg := loadConfig()

	st, err := newStore(cfg.dataDir)
	if err != nil {
		log.Fatalf("web: data dir: %v", err)
	}
	acct, err := newAccounts(filepath.Join(cfg.dataDir, "users"))
	if err != nil {
		log.Fatalf("web: accounts dir: %v", err)
	}
	msgs, err := newMessages(filepath.Join(cfg.dataDir, "inbox"))
	if err != nil {
		log.Fatalf("web: inbox dir: %v", err)
	}
	keys, err := newAPIKeyStore(filepath.Join(cfg.dataDir, "apikeys"))
	if err != nil {
		log.Fatalf("web: apikeys dir: %v", err)
	}

	tmpl, err := template.ParseFS(templatesFS, "templates/*.html")
	if err != nil {
		log.Fatalf("web: templates: %v", err)
	}

	s := &server{
		cfg: cfg, store: st, accounts: acct, msgs: msgs, apikeys: keys,
		sessions:   newSessionStore(12 * time.Hour),
		pending:    newPendingStore(5 * time.Minute),
		loginGuard: newLoginGuard(5, 15*time.Minute),
		billing:    loadBilling(),
		audit:      newAuditor(cfg.dataDir),
		tmpl:       tmpl,
	}

	// Periodic sweep of expired items + inbox messages.
	go func() {
		for {
			s.store.sweep()
			s.msgs.sweep()
			time.Sleep(cfg.defaultTTL / 4)
		}
	}()

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
	mux.HandleFunc("POST /api/2fa/setup", s.handle2FASetup)
	mux.HandleFunc("POST /api/2fa/enable", s.handle2FAEnable)
	mux.HandleFunc("POST /api/2fa/disable", s.handle2FADisable)
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

	srv := &http.Server{
		Addr:              cfg.addr,
		Handler:           securityHeaders(mux),
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
