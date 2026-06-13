package main

import (
	"crypto/mlkem"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// requireSession returns the active session or writes 401.
func (s *server) requireSession(w http.ResponseWriter, r *http.Request) (*session, bool) {
	sess, ok := s.sessions.current(r)
	if !ok {
		http.Error(w, "login required", http.StatusUnauthorized)
		return nil, false
	}
	return sess, true
}

func jsonError(w http.ResponseWriter, code int, msg string) {
	http.Error(w, msg, code)
}

// GET /register, GET /login — pages.
func (s *server) handleRegisterPage(w http.ResponseWriter, r *http.Request) {
	s.render(w, "register.html", nil)
}
func (s *server) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	s.render(w, "login.html", nil)
}

// POST /api/register — create account, then auto-login.
func (s *server) handleRegister(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")
	if _, err := s.accounts.register(username, password); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	_, dk, err := s.accounts.authenticate(username, password)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "registered, but login failed")
		return
	}
	s.startSession(w, username, dk)
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"ok":true}`))
}

// POST /api/login.
func (s *server) handleLogin(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")
	_, dk, err := s.accounts.authenticate(username, password)
	if err != nil {
		jsonError(w, http.StatusUnauthorized, "invalid username or password")
		return
	}
	s.startSession(w, username, dk)
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"ok":true}`))
}

func (s *server) startSession(w http.ResponseWriter, username string, dk *mlkem.DecapsulationKey768) {
	token, err := s.sessions.create(username, dk)
	if err != nil {
		return
	}
	setSessionCookie(w, token, s.sessions.ttl, s.cfg.secure)
}

// POST /api/logout.
func (s *server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		s.sessions.destroy(c.Value)
	}
	clearSessionCookie(w, s.cfg.secure)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

type inboxRow struct {
	ID     string
	Sender string
	Size   string
	When   string
}

func humanSize(n int64) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}

// GET /app — dashboard (send form + inbox). Requires login.
func (s *server) handleApp(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.sessions.current(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	var rows []inboxRow
	for _, m := range s.msgs.list(sess.username) {
		rows = append(rows, inboxRow{
			ID:     m.ID,
			Sender: m.Sender,
			Size:   humanSize(m.Size),
			When:   time.Unix(m.Created, 0).UTC().Format("2006-01-02 15:04 UTC"),
		})
	}
	s.render(w, "app.html", map[string]any{
		"User":  sess.username,
		"Inbox": rows,
		"MaxMB": s.cfg.maxBytes / (1 << 20),
	})
}

// POST /api/send — multipart: recipient, file. Requires login.
func (s *server) handleSend(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.requireSession(w, r)
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, s.cfg.maxBytes+(1<<20))
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		jsonError(w, http.StatusRequestEntityTooLarge, "upload too large")
		return
	}

	recipient := r.FormValue("recipient")
	ru, err := s.accounts.load(recipient)
	if err != nil {
		jsonError(w, http.StatusNotFound, "no such recipient")
		return
	}

	file, hdr, err := r.FormFile("file")
	if err != nil {
		jsonError(w, http.StatusBadRequest, "no file provided")
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

	ek, err := mlkem.NewEncapsulationKey768(ru.PubKey)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "recipient key invalid")
		return
	}
	sharedKey, kemCt := ek.Encapsulate()
	nonce, ct, err := sealWithKey(sharedKey, hdr.Filename, data)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "encryption failed")
		return
	}

	id, err := newID()
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "internal error")
		return
	}
	msg := Message{
		ID: id, Sender: sess.username, Recipient: recipient,
		KemCt: kemCt, Nonce: nonce, Size: int64(len(data)),
		Created: time.Now().Unix(),
		Expires: time.Now().Add(s.cfg.defaultTTL).Unix(),
	}
	if err := s.msgs.put(msg, ct); err != nil {
		jsonError(w, http.StatusInternalServerError, "storage failed")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"ok": "sent to " + recipient})
}

// GET /api/msg/{id} — decrypt + download one inbox message. Requires login.
func (s *server) handleMsgDownload(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.requireSession(w, r)
	if !ok {
		return
	}
	id := r.PathValue("id")
	if !validID.MatchString(id) {
		http.NotFound(w, r)
		return
	}
	msg, ct, err := s.msgs.get(sess.username, id)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	sharedKey, err := sess.dk.Decapsulate(msg.KemCt)
	if err != nil {
		http.Error(w, "decapsulation failed", http.StatusInternalServerError)
		return
	}
	filename, data, err := openWithKey(sharedKey, msg.Nonce, ct)
	if err != nil {
		http.Error(w, "decryption failed", http.StatusInternalServerError)
		return
	}
	if filename == "" {
		filename = "download.bin"
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	_, _ = w.Write(data)
}

// POST /api/msg/{id}/delete — remove a message from the inbox. Requires login.
func (s *server) handleMsgDelete(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.requireSession(w, r)
	if !ok {
		return
	}
	id := r.PathValue("id")
	if validID.MatchString(id) {
		s.msgs.delete(sess.username, id)
	}
	http.Redirect(w, r, "/app", http.StatusSeeOther)
}
