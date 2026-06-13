package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"
)

// GET / — upload page.
func (s *server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	s.render(w, "index.html", map[string]any{
		"MaxBytes": s.cfg.maxBytes,
		"MaxMB":    s.cfg.maxBytes / (1 << 20),
	})
}

type uploadResponse struct {
	ID  string `json:"id"`
	URL string `json:"url"`
}

// POST /api/upload — multipart: file, passphrase, ttl (hours), one_time.
func (s *server) handleUpload(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, s.cfg.maxBytes+(1<<20))
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		http.Error(w, "upload too large or malformed", http.StatusRequestEntityTooLarge)
		return
	}

	passphrase := r.FormValue("passphrase")
	if len(passphrase) < 1 {
		http.Error(w, "passphrase required", http.StatusBadRequest)
		return
	}

	file, hdr, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "no file provided", http.StatusBadRequest)
		return
	}
	defer file.Close()

	data := make([]byte, 0, hdr.Size)
	buf := make([]byte, 64*1024)
	for {
		n, rerr := file.Read(buf)
		data = append(data, buf[:n]...)
		if rerr != nil {
			break
		}
	}

	salt, nonce, ct, err := seal(passphrase, hdr.Filename, data)
	if err != nil {
		http.Error(w, "encryption failed", http.StatusInternalServerError)
		return
	}

	id, err := newID()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	ttlHours, _ := strconv.Atoi(r.FormValue("ttl"))
	if ttlHours <= 0 {
		ttlHours = int(s.cfg.defaultTTL.Hours())
	}
	expires := time.Now().Add(time.Duration(ttlHours) * time.Hour).Unix()

	m := Meta{
		ID:      id,
		Salt:    salt,
		Nonce:   nonce,
		Created: time.Now().Unix(),
		Expires: expires,
		OneTime: r.FormValue("one_time") == "on" || r.FormValue("one_time") == "true",
	}
	if err := s.store.put(m, ct); err != nil {
		http.Error(w, "storage failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(uploadResponse{
		ID:  id,
		URL: fmt.Sprintf("%s/d/%s", s.cfg.baseURL, id),
	})
}

// GET /d/{id} — download page (asks for the passphrase).
func (s *server) handleDownloadPage(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !validID.MatchString(id) {
		http.NotFound(w, r)
		return
	}
	if _, err := os.Stat(s.store.metaPath(id)); err != nil {
		s.render(w, "gone.html", nil)
		return
	}
	s.render(w, "download.html", map[string]any{"ID": id})
}

// POST /api/download/{id} — passphrase -> decrypted file stream.
func (s *server) handleDownload(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !validID.MatchString(id) {
		http.NotFound(w, r)
		return
	}
	passphrase := r.FormValue("passphrase")

	m, ct, err := s.store.get(id)
	if err != nil {
		http.Error(w, "not found or expired", http.StatusNotFound)
		return
	}

	filename, data, err := open(passphrase, m.Salt, m.Nonce, ct)
	if err != nil {
		http.Error(w, "wrong passphrase", http.StatusUnauthorized)
		return
	}

	if m.OneTime {
		s.store.delete(id)
	}

	if filename == "" {
		filename = "download.bin"
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	_, _ = w.Write(data)
}

func (s *server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}
