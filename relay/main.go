// Command relay is the zero-knowledge blob store for Kyber-Zip secure transfer.
//
// It only ever stores opaque ciphertext: the payload is already encrypted to
// the recipient's ML-KEM public key by the client before upload, so the relay
// cannot read, decrypt, or tamper with file contents undetected. Its only jobs
// are to hold a blob briefly and hand it to whoever presents the claim code.
//
// API
//
//	POST /v1/blob          -> store request body, returns {"code","expires_in"}
//	GET  /v1/blob/{code}   -> stream the blob once, then delete it
//	GET  /healthz          -> liveness probe
//
// Blobs are one-time download and also expire after a TTL, so nothing lingers.
package main

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"time"
)

// config holds the runtime configuration, all sourced from the environment so
// the binary stays a drop-in single artifact with no config file to manage.
type config struct {
	addr     string        // listen address, e.g. ":8080"
	dataDir  string        // directory holding stored blobs
	maxBytes int64         // reject uploads larger than this
	ttl      time.Duration // delete blobs older than this
	tlsCert  string        // optional: path to TLS certificate (PEM)
	tlsKey   string        // optional: path to TLS private key (PEM)
}

func loadConfig() config {
	return config{
		addr:     env("RELAY_ADDR", ":8080"),
		dataDir:  env("RELAY_DATA_DIR", "./data"),
		maxBytes: envInt64("RELAY_MAX_BYTES", 2<<30), // 2 GiB
		ttl:      envDuration("RELAY_TTL", 24*time.Hour),
		tlsCert:  env("RELAY_TLS_CERT", ""),
		tlsKey:   env("RELAY_TLS_KEY", ""),
	}
}

// codeAlphabet is RFC 4648 base32 without padding, lowercased. 16 random bytes
// encode to 26 chars (~128 bits), so codes are infeasible to guess and safe to
// drop straight into a URL path.
var codeEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// validCode guards the download path against traversal and garbage: a code is
// exactly the characters our encoder emits, nothing else.
var validCode = regexp.MustCompile(`^[A-Z2-7]{26}$`)

func newCode() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return codeEncoding.EncodeToString(b[:]), nil
}

func main() {
	cfg := loadConfig()

	if err := os.MkdirAll(cfg.dataDir, 0o700); err != nil {
		log.Fatalf("relay: cannot create data dir %q: %v", cfg.dataDir, err)
	}

	srv := &server{cfg: cfg, limiter: newRateLimiter(10, time.Minute)}

	// Sweep expired blobs on a timer so abandoned transfers don't accumulate.
	go srv.sweepLoop()

	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/blob", srv.handleUpload)
	mux.HandleFunc("GET /v1/blob/{code}", srv.handleDownload)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	httpSrv := &http.Server{
		Addr:              cfg.addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	if cfg.tlsCert != "" && cfg.tlsKey != "" {
		log.Printf("relay: listening on %s (TLS), data=%s ttl=%s max=%dB",
			cfg.addr, cfg.dataDir, cfg.ttl, cfg.maxBytes)
		log.Fatal(httpSrv.ListenAndServeTLS(cfg.tlsCert, cfg.tlsKey))
	}
	log.Printf("relay: listening on %s (plaintext — terminate TLS upstream), data=%s ttl=%s max=%dB",
		cfg.addr, cfg.dataDir, cfg.ttl, cfg.maxBytes)
	log.Fatal(httpSrv.ListenAndServe())
}

type server struct {
	cfg     config
	limiter *rateLimiter
}

// uploadResponse is the JSON returned to a successful uploader.
type uploadResponse struct {
	Code      string `json:"code"`
	ExpiresIn int64  `json:"expires_in"` // seconds until the blob is swept
}

func (s *server) handleUpload(w http.ResponseWriter, r *http.Request) {
	if !s.limiter.allow(clientIP(r)) {
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	// Cap the body so a single client can't exhaust disk.
	r.Body = http.MaxBytesReader(w, r.Body, s.cfg.maxBytes)

	code, err := newCode()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Write to a temp file first, then atomically rename into place so a
	// download can never observe a half-written blob.
	tmp, err := os.CreateTemp(s.cfg.dataDir, ".upload-*")
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once the rename succeeds

	if _, err := io.Copy(tmp, r.Body); err != nil {
		tmp.Close()
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			http.Error(w, "payload too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "upload failed", http.StatusBadRequest)
		return
	}
	if err := tmp.Close(); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if err := os.Rename(tmpName, s.blobPath(code)); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(uploadResponse{
		Code:      code,
		ExpiresIn: int64(s.cfg.ttl.Seconds()),
	})
}

func (s *server) handleDownload(w http.ResponseWriter, r *http.Request) {
	code := r.PathValue("code")
	if !validCode.MatchString(code) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	// Atomically claim the blob by renaming it: whichever request wins the
	// rename gets to serve it, everyone else sees 404. This makes the
	// one-time-download guarantee race-free against concurrent fetches.
	claimed := s.blobPath(code) + ".claimed"
	if err := os.Rename(s.blobPath(code), claimed); err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	defer os.Remove(claimed)

	f, err := os.Open(claimed)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	defer f.Close()

	info, err := f.Stat()
	if err == nil {
		w.Header().Set("Content-Length", strconv.FormatInt(info.Size(), 10))
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	if _, err := io.Copy(w, f); err != nil {
		log.Printf("relay: download stream error for %s: %v", code, err)
	}
}

func (s *server) blobPath(code string) string {
	// code is regexp-validated before reaching here; Base is belt-and-braces.
	return filepath.Join(s.cfg.dataDir, filepath.Base(code))
}

// sweepLoop periodically deletes blobs (and stray temp/claimed files) older
// than the TTL.
func (s *server) sweepLoop() {
	interval := s.cfg.ttl / 4
	if interval < time.Minute {
		interval = time.Minute
	}
	for {
		s.sweepOnce()
		time.Sleep(interval)
	}
}

func (s *server) sweepOnce() {
	entries, err := os.ReadDir(s.cfg.dataDir)
	if err != nil {
		log.Printf("relay: sweep read dir: %v", err)
		return
	}
	cutoff := time.Now().Add(-s.cfg.ttl)
	for _, e := range entries {
		info, err := e.Info()
		if err != nil {
			continue
		}
		if info.ModTime().Before(cutoff) {
			_ = os.Remove(filepath.Join(s.cfg.dataDir, e.Name()))
		}
	}
}

// --- small helpers ---------------------------------------------------------

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envInt64(key string, def int64) int64 {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			return n
		}
	}
	return def
}

func envDuration(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
