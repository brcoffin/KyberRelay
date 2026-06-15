package main

import (
	"bytes"
	"compress/flate"
	"crypto/mlkem"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
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

// uploadLimit is the largest file the sender's plan permits, used to bound the
// request body (and thus memory) before reading.
func (s *server) uploadLimit(username string) int64 {
	plan := planFor("free")
	if u, err := s.accounts.load(username); err == nil {
		plan = planFor(u.Plan)
	}
	return plan.MaxFileBytes
}

// encryptAndStoreStream encapsulates to the recipient's public key and streams
// the upload through compression + chunked encryption straight to the recipient's
// inbox, so the file is never held whole in memory. Shared by the browser and API
// send handlers.
func (s *server) encryptAndStoreStream(sender, recipient, filename string, src io.Reader) (string, error) {
	// The sender's plan governs the size limit and retention.
	plan := planFor("free")
	if su, err := s.accounts.load(sender); err == nil {
		plan = planFor(su.Plan)
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
	id, err := newID()
	if err != nil {
		return "", err
	}

	// Logical plaintext stream = uint16(len(filename)) + filename + file bytes,
	// deflated, then chunk-encrypted (see stream.go / readFilename).
	var size int64
	seal := func(dst io.Writer) error {
		sw, err := newSealWriter(sharedKey, dst)
		if err != nil {
			return err
		}
		zw, err := flate.NewWriter(sw, flate.DefaultCompression)
		if err != nil {
			return err
		}
		var nl [2]byte
		binary.LittleEndian.PutUint16(nl[:], uint16(len(filename)))
		if _, err := zw.Write(nl[:]); err != nil {
			return err
		}
		if _, err := zw.Write([]byte(filename)); err != nil {
			return err
		}
		cr := &countingReader{r: src}
		if _, err := io.Copy(zw, cr); err != nil {
			return err
		}
		if err := zw.Close(); err != nil {
			return err
		}
		size = cr.n
		return sw.Close()
	}
	if err := s.msgs.writeBlob(recipient, id, seal); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			return "", errTooLarge
		}
		return "", err
	}
	if size > plan.MaxFileBytes {
		s.msgs.delete(recipient, id)
		return "", errTooLarge
	}

	msg := Message{
		ID: id, Sender: sender, Recipient: recipient,
		KemCt: kemCt, Stream: true, Size: size,
		Created: time.Now().Unix(),
		Expires: time.Now().Add(plan.TTL).Unix(),
	}
	if err := s.msgs.writeMeta(msg); err != nil {
		s.msgs.delete(recipient, id)
		return "", err
	}
	return id, nil
}

// setDownloadHeaders sets the attachment headers for a decrypted file.
func setDownloadHeaders(w http.ResponseWriter, filename string) {
	if filename == "" {
		filename = "download.bin"
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
}

// writeDecrypted streams one inbox message, decrypted, to w. It returns a
// non-nil error ONLY when nothing has been written yet (so the caller can send a
// 404 in its own format); once the body starts, mid-stream errors are logged and
// nil is returned. Handles both the chunked-stream format and legacy blobs.
func (s *server) writeDecrypted(w http.ResponseWriter, dk *mlkem.DecapsulationKey768, username, id string) error {
	msg, err := s.msgs.meta(username, id)
	if err != nil {
		return err
	}
	sharedKey, err := dk.Decapsulate(msg.KemCt)
	if err != nil {
		return err
	}
	f, err := s.msgs.openBlob(username, id)
	if err != nil {
		return err
	}
	closed := false
	closeBlob := func() {
		if !closed {
			f.Close()
			closed = true
		}
	}
	defer closeBlob()

	var filename string
	var body io.Reader
	if msg.Stream {
		sr, err := newStreamReader(sharedKey, f)
		if err != nil {
			return err
		}
		zr := flate.NewReader(sr)
		defer zr.Close()
		if filename, err = readFilename(zr); err != nil {
			return err
		}
		body = zr
	} else {
		ct, err := io.ReadAll(f)
		if err != nil {
			return err
		}
		fn, data, err := openWithKey(sharedKey, msg.Nonce, ct)
		if err != nil {
			return err
		}
		filename, body = fn, bytes.NewReader(data)
	}

	setDownloadHeaders(w, filename)
	_, copyErr := io.Copy(w, body)
	closeBlob() // release the file handle before deleting (Windows can't unlink an open file)
	if copyErr != nil {
		// Partial delivery — keep the message so the recipient can retry.
		log.Printf("web: stream message %s: %v", id, copyErr)
		return nil
	}
	// Burn-after-download: a successfully delivered file is deleted immediately,
	// so it exists on the server only until the recipient retrieves it once.
	s.msgs.delete(username, id)
	return nil
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
	ip := clientIP(r)
	if s.regGuard.locked("reg:" + ip) {
		jsonError(w, http.StatusTooManyRequests, "too many sign-ups from this address — try again later")
		return
	}
	s.regGuard.fail("reg:" + ip) // count every attempt (incl. the HIBP lookup below)

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
	s.audit.log("register", username, ip, "")
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
		s.audit.log("login_failed", username, ip, "")
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
	s.audit.log("login", username, ip, "")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// POST /api/account/password — change password (requires current password).
func (s *server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.requireSession(w, r)
	if !ok {
		return
	}
	newp := r.FormValue("new_password")
	if breached, err := passwordBreached(newp); err == nil && breached {
		jsonError(w, http.StatusBadRequest, "That password has appeared in a data breach — choose another.")
		return
	}
	err := s.accounts.changePassword(sess.username, r.FormValue("current_password"), newp)
	if err == errBadLogin {
		jsonError(w, http.StatusBadRequest, "current password is incorrect")
		return
	}
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	// A password change is the remediation for a compromised account, so cut off
	// every previously-issued credential: revoke all API keys and invalidate all
	// other sessions, then re-issue a fresh session so this browser stays in.
	s.apikeys.revokeAll(sess.username)
	s.sessions.destroyUser(sess.username)
	s.startSession(w, sess.username, sess.dk)
	s.audit.log("password_changed", sess.username, clientIP(r), "keys+sessions revoked")
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
	code := r.FormValue("code")
	how := "2fa"
	verified := s.accounts.consumeTOTP(pl.username, pl.totpSecret, code)
	if !verified && s.accounts.consumeRecovery(pl.username, code) {
		verified = true
		how = "recovery"
	}
	if !verified {
		s.loginGuard.fail(guardKey)
		s.audit.log("totp_failed", pl.username, clientIP(r), "")
		jsonError(w, http.StatusUnauthorized, "invalid code")
		return
	}
	s.loginGuard.reset(guardKey)
	s.pending.del(r.FormValue("pending"))
	s.startSession(w, pl.username, pl.dk)
	s.audit.log("login", pl.username, clientIP(r), how)
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
		if sess, ok := s.sessions.get(c.Value); ok {
			s.audit.log("logout", sess.username, clientIP(r), "")
		}
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
	case n >= 1<<30:
		return fmt.Sprintf("%g GB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}

// planMaxLabel renders a plan's per-transfer size cap (e.g. "2 GB", "100 GB").
func planMaxLabel(p Plan) string { return humanSize(p.MaxFileBytes) }

// retentionLabel renders a retention period in days or hours, whichever reads
// cleanly (e.g. "7 days", "30 days").
func retentionLabel(d time.Duration) string {
	if h := int(d.Hours()); h%24 == 0 && h >= 24 {
		days := h / 24
		if days == 1 {
			return "1 day"
		}
		return fmt.Sprintf("%d days", days)
	}
	return fmt.Sprintf("%dh", int(d.Hours()))
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
	recoveryLeft := 0
	if u, err := s.accounts.load(sess.username); err == nil {
		plan = planFor(u.Plan)
		totp = u.TOTPEnabled
		recoveryLeft = len(u.RecoveryCodes)
	}
	type keyRow struct{ KeyID, Label, Scope, Expiry string }
	var keyRows []keyRow
	for _, k := range s.apikeys.list(sess.username) {
		exp := "never"
		if k.Expires > 0 {
			exp = time.Unix(k.Expires, 0).UTC().Format("2006-01-02")
		}
		keyRows = append(keyRows, keyRow{k.KeyID, k.Label, k.Scope, exp})
	}
	type actRow struct{ When, Event, Detail string }
	var activity []actRow
	for _, e := range s.audit.recentForUser(sess.username, 12) {
		when := e.Time
		if t, err := time.Parse(time.RFC3339, e.Time); err == nil {
			when = t.UTC().Format("2006-01-02 15:04 UTC")
		}
		activity = append(activity, actRow{when, e.Event, e.Detail})
	}
	s.render(w, "app.html", map[string]any{
		"User":         sess.username,
		"CSRF":         sess.csrf,
		"Inbox":        rows,
		"Keys":         keyRows,
		"Activity":     activity,
		"Plan":         plan.Label,
		"MaxSize":      planMaxLabel(plan),
		"Retention":    retentionLabel(plan.TTL),
		"TOTPEnabled":  totp,
		"RecoveryLeft": recoveryLeft,
	})
}

// POST /api/send — multipart: recipient, file. Requires login.
func (s *server) handleSend(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.requireSession(w, r)
	if !ok {
		return
	}
	// Bound concurrent uploads so large transfers can't exhaust resources.
	s.uploadSem <- struct{}{}
	defer func() { <-s.uploadSem }()

	r.Body = http.MaxBytesReader(w, r.Body, s.uploadLimit(sess.username)+(1<<20))
	if err := r.ParseMultipartForm(8 << 20); err != nil {
		jsonError(w, http.StatusRequestEntityTooLarge, "upload too large")
		return
	}
	defer func() {
		if r.MultipartForm != nil {
			_ = r.MultipartForm.RemoveAll()
		}
	}()

	recipient := r.FormValue("recipient")
	file, hdr, err := r.FormFile("file")
	if err != nil {
		jsonError(w, http.StatusBadRequest, "no file provided")
		return
	}
	defer file.Close()
	if _, err := s.encryptAndStoreStream(sess.username, recipient, hdr.Filename, file); err != nil {
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
	s.audit.log("sent", sess.username, clientIP(r), recipient)
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
	if err := s.writeDecrypted(w, sess.dk, sess.username, id); err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	s.audit.log("downloaded", sess.username, clientIP(r), id)
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
