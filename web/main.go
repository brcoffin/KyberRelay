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
	"log"
	"net/http"
	"os"
	"strconv"
	"time"
)

//go:embed templates/*.html
var templatesFS embed.FS

type config struct {
	addr       string
	dataDir    string
	baseURL    string
	maxBytes   int64
	defaultTTL time.Duration
}

func loadConfig() config {
	return config{
		addr:       env("WEB_ADDR", "127.0.0.1:8090"),
		dataDir:    env("WEB_DATA_DIR", "./web-data"),
		baseURL:    env("WEB_BASE_URL", "http://127.0.0.1:8090"),
		maxBytes:   envInt64("WEB_MAX_BYTES", 100<<20), // 100 MiB
		defaultTTL: envDuration("WEB_TTL", 24*time.Hour),
	}
}

type server struct {
	cfg   config
	store *store
	tmpl  *template.Template
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

	tmpl, err := template.ParseFS(templatesFS, "templates/*.html")
	if err != nil {
		log.Fatalf("web: templates: %v", err)
	}

	s := &server{cfg: cfg, store: st, tmpl: tmpl}

	// Periodic sweep of expired items.
	go func() {
		for {
			s.store.sweep()
			time.Sleep(cfg.defaultTTL / 4)
		}
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /", s.handleIndex)
	mux.HandleFunc("POST /api/upload", s.handleUpload)
	mux.HandleFunc("GET /d/{id}", s.handleDownloadPage)
	mux.HandleFunc("POST /api/download/{id}", s.handleDownload)
	mux.HandleFunc("GET /healthz", s.handleHealth)

	srv := &http.Server{
		Addr:              cfg.addr,
		Handler:           mux,
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
