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

// readUpload reads the "file" part of a multipart request fully into memory.
func readUpload(r *http.Request) (filename string, data []byte, err error) {
	file, hdr, err := r.FormFile("file")
	if err != nil {
		return "", nil, err
	}
	defer file.Close()
	data = make([]byte, 0, hdr.Size)
	buf := make([]byte, 64*1024)
	for {
		n, rerr := file.Read(buf)
		data = append(data, buf[:n]...)
		if rerr != nil {
			break
		}
	}
	return hdr.Filename, data, nil
}

// encryptAndStore encapsulates to the recipient's public key, seals the file,
// and drops it in their inbox. Shared by the browser and API send handlers.
func (s *server) encryptAndStore(sender, recipient, filename string, data []byte) (string, error) {
	// The sender's plan governs the size limit and retention.
	plan := planFor("free")
	if su, err := s.accounts.load(sender); err == nil {
		plan = planFor(su.Plan)
	}
	if int64(len(data)) > plan.MaxFileBytes {
		return "", errTooLarge
	}

	ru, err := s.accounts.load(recipient)
	if err != nil {
		return "", errNoSuchUser
	}
	ek, err := mlkem.NewEncapsulationKey768(ru.PubKey)
	if err != nil {
		return "", err
	}
	sharedKey, kemCt := ek.Encapsulate()
	nonce, ct, err := sealWithKey(sharedKey, filename, data)
	if err != nil {
		return "", err
	}
	id, err := newID()
	if err != nil {
		return "", err
	}
	msg := Message{
		ID: id, Sender: sender, Recipient: recipient,
		KemCt: kemCt, Nonce: nonce, Size: int64(len(data)),
		Created: time.Now().Unix(),
		Expires: time.Now().Add(plan.TTL).Unix(),
	}
	if err := s.msgs.put(msg, ct); err != nil {
		return "", err
	}
	return id, nil
}

// decryptMessage fetches and decrypts one inbox message with the given key.
func (s *server) decryptMessage(dk *mlkem.DecapsulationKey768, username, id string) (string, []byte, error) {
	msg, ct, err := s.msgs.get(username, id)
	if err != nil {
		return "", nil, err
	}
	sharedKey, err := dk.Decapsulate(msg.KemCt)
	if err != nil {
		return "", nil, err
	}
	return openWithKey(sharedKey, msg.Nonce, ct)
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
	// Reject passwords found in known breaches (fail open if HIBP unreachable).
	if breached, err := passwordBreached(password); err == nil && breached {
		jsonError(w, http.StatusBadRequest,
			"That password has appeared in a data breach — please choose a different one.")
		return
	}
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

	ip := clientIP(r)
	if s.loginGuard.locked("u:"+username) || s.loginGuard.locked("ip:"+ip) {
		jsonError(w, http.StatusTooManyRequests, "too many attempts — try again in a few minutes")
		return
	}
	u, dk, err := s.accounts.authenticate(username, password)
	if err != nil {
		s.loginGuard.fail("u:" + username)
		s.loginGuard.fail("ip:" + ip)
		jsonError(w, http.StatusUnauthorized, "invalid username or password")
		return
	}
	s.loginGuard.reset("u:" + username) // password correct

	// If 2FA is on, stop here and require a TOTP code (second step).
	if u.TOTPEnabled {
		secret, err := aesUnwrap(totpKey(dk), u.TOTPNonce, u.TOTPSecret)
		if err != nil {
			jsonError(w, http.StatusInternalServerError, "could not load 2FA")
			return
		}
		token, err := s.pending.create(&pendingLogin{username: username, dk: dk, totpSecret: secret})
		if err != nil {
			jsonError(w, http.StatusInternalServerError, "internal error")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"totp_required": true, "pending": token})
		return
	}

	s.startSession(w, username, dk)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// POST /api/login/totp — second login step: verify the authenticator code.
func (s *server) handleLoginTOTP(w http.ResponseWriter, r *http.Request) {
	pl, ok := s.pending.get(r.FormValue("pending"))
	if !ok {
		jsonError(w, http.StatusUnauthorized, "login expired — start again")
		return
	}
	guardKey := "totp:" + pl.username
	if s.loginGuard.locked(guardKey) {
		jsonError(w, http.StatusTooManyRequests, "too many attempts — try again later")
		return
	}
	if !totpVerify(pl.totpSecret, r.FormValue("code")) {
		s.loginGuard.fail(guardKey)
		jsonError(w, http.StatusUnauthorized, "invalid code")
		return
	}
	s.loginGuard.reset(guardKey)
	s.pending.del(r.FormValue("pending"))
	s.startSession(w, pl.username, pl.dk)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
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

// GET / — account-first landing: send logged-in users to the app, others to login.
func (s *server) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if _, ok := s.sessions.current(r); ok {
		http.Redirect(w, r, "/app", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/login", http.StatusSeeOther)
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
	plan := planFor("free")
	totp := false
	if u, err := s.accounts.load(sess.username); err == nil {
		plan = planFor(u.Plan)
		totp = u.TOTPEnabled
	}
	keys := s.apikeys.list(sess.username)
	s.render(w, "app.html", map[string]any{
		"User":        sess.username,
		"Inbox":       rows,
		"Keys":        keys,
		"Plan":        plan.Label,
		"MaxMB":       plan.MaxFileBytes / (1 << 20),
		"RetentionH":  int(plan.TTL.Hours()),
		"TOTPEnabled": totp,
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
	filename, data, err := readUpload(r)
	if err != nil {
		jsonError(w, http.StatusBadRequest, "no file provided")
		return
	}
	if _, err := s.encryptAndStore(sess.username, recipient, filename, data); err != nil {
		switch err {
		case errNoSuchUser:
			jsonError(w, http.StatusNotFound, "no such recipient")
		case errTooLarge:
			jsonError(w, http.StatusRequestEntityTooLarge, err.Error())
		default:
			jsonError(w, http.StatusInternalServerError, "send failed")
		}
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
	filename, data, err := s.decryptMessage(sess.dk, sess.username, id)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
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
