package main

import (
	"crypto/mlkem"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// apiAuth resolves the Bearer API key into (username, decapsulation key, scope).
// dk is nil for send-only keys.
func (s *server) apiAuth(w http.ResponseWriter, r *http.Request) (string, *mlkem.DecapsulationKey768, string, bool) {
	const p = "Bearer "
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, p) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing bearer token"})
		return "", nil, "", false
	}
	username, scope, dk, err := s.apikeys.authenticate(strings.TrimSpace(strings.TrimPrefix(h, p)))
	if err != nil {
		msg := "invalid or revoked API key"
		if errors.Is(err, errKeyExpired) {
			msg = "API key has expired"
		}
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": msg})
		return "", nil, "", false
	}
	return username, dk, scope, true
}

// POST /api/v1/send — Bearer; multipart: recipient, file -> {id}.
func (s *server) apiSend(w http.ResponseWriter, r *http.Request) {
	username, _, _, ok := s.apiAuth(w, r) // any scope may send
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, s.cfg.maxBytes+(1<<20))
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "upload too large"})
		return
	}
	recipient := r.FormValue("recipient")
	filename, data, err := readUpload(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no file provided"})
		return
	}
	id, err := s.encryptAndStore(username, recipient, filename, data)
	if err != nil {
		switch err {
		case errNoSuchUser:
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "no such recipient"})
		case errTooLarge:
			writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": err.Error()})
		default:
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "send failed"})
		}
		return
	}
	s.audit.log("sent", username, clientIP(r), recipient+" (api)")
	writeJSON(w, http.StatusOK, map[string]string{"id": id, "recipient": recipient})
}

// GET /api/v1/inbox — Bearer -> [{id, from, size, created}].
func (s *server) apiInbox(w http.ResponseWriter, r *http.Request) {
	username, _, scope, ok := s.apiAuth(w, r)
	if !ok {
		return
	}
	if scope != scopeDecrypt {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "this key is send-only"})
		return
	}
	type item struct {
		ID      string `json:"id"`
		From    string `json:"from"`
		Size    int64  `json:"size"`
		Created int64  `json:"created"`
	}
	out := []item{}
	for _, m := range s.msgs.list(username) {
		out = append(out, item{ID: m.ID, From: m.Sender, Size: m.Size, Created: m.Created})
	}
	writeJSON(w, http.StatusOK, map[string]any{"messages": out})
}

// GET /api/v1/messages/{id} — Bearer -> decrypted file stream.
func (s *server) apiMsgGet(w http.ResponseWriter, r *http.Request) {
	username, dk, scope, ok := s.apiAuth(w, r)
	if !ok {
		return
	}
	if scope != scopeDecrypt || dk == nil {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "this key is send-only"})
		return
	}
	id := r.PathValue("id")
	if !validID.MatchString(id) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	filename, data, err := s.decryptMessage(dk, username, id)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	if filename == "" {
		filename = "download.bin"
	}
	s.audit.log("downloaded", username, clientIP(r), id+" (api)")
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	_, _ = w.Write(data)
}

// DELETE /api/v1/messages/{id} — Bearer.
func (s *server) apiMsgDelete(w http.ResponseWriter, r *http.Request) {
	username, _, scope, ok := s.apiAuth(w, r)
	if !ok {
		return
	}
	if scope != scopeDecrypt {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "this key is send-only"})
		return
	}
	id := r.PathValue("id")
	if validID.MatchString(id) {
		s.msgs.delete(username, id)
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- API key management (session-authenticated, used by the dashboard) ---

// POST /api/keys — create a key for the logged-in user. Returns the token once.
func (s *server) handleKeyCreate(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.requireSession(w, r)
	if !ok {
		return
	}
	label := strings.TrimSpace(r.FormValue("label"))
	if label == "" {
		label = "api key"
	}
	scope := r.FormValue("scope")
	if scope != scopeSend {
		scope = scopeDecrypt
	}
	var expires int64
	if d, _ := strconv.Atoi(r.FormValue("expires_days")); d > 0 {
		expires = time.Now().Add(time.Duration(d) * 24 * time.Hour).Unix()
	}
	var seed []byte
	if scope == scopeDecrypt {
		seed = sess.dk.Bytes() // send-only keys store no key material
	}
	token, err := s.apikeys.create(sess.username, label, scope, expires, seed)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not create key"})
		return
	}
	s.audit.log("apikey_created", sess.username, clientIP(r), scope)
	writeJSON(w, http.StatusOK, map[string]string{"token": token, "label": label, "scope": scope})
}

// GET /api/keys — list the logged-in user's keys (ids/labels only).
func (s *server) handleKeyList(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.requireSession(w, r)
	if !ok {
		return
	}
	keys := s.apikeys.list(sess.username)
	if keys == nil {
		keys = []APIKeyInfo{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"keys": keys})
}

// POST /api/keys/{id}/delete — revoke a key (form post from the dashboard).
func (s *server) handleKeyRevoke(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.requireSession(w, r)
	if !ok {
		return
	}
	_ = s.apikeys.revoke(sess.username, r.PathValue("id"))
	s.audit.log("apikey_revoked", sess.username, clientIP(r), r.PathValue("id"))
	http.Redirect(w, r, "/app", http.StatusSeeOther)
}
