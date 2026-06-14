package main

import "net/http"

// POST /api/2fa/setup — generate a secret (not yet enabled) and return the
// otpauth URI + QR for enrollment. Requires login.
func (s *server) handle2FASetup(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.requireSession(w, r)
	if !ok {
		return
	}
	u, err := s.accounts.load(sess.username)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "could not load account")
		return
	}
	secret, err := newTOTPSecret()
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "internal error")
		return
	}
	nonce, wrapped, err := aesWrap(totpKey(sess.dk), secret)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "internal error")
		return
	}
	u.TOTPNonce = nonce
	u.TOTPSecret = wrapped
	u.TOTPEnabled = false // stays off until a code is verified
	if err := s.accounts.save(u); err != nil {
		jsonError(w, http.StatusInternalServerError, "could not save")
		return
	}
	uri := totpURI(u.Username, secret)
	qr, _ := totpQRDataURI(uri)
	writeJSON(w, http.StatusOK, map[string]string{
		"secret":  totpSecretB32(secret),
		"otpauth": uri,
		"qr":      qr,
	})
}

// POST /api/2fa/enable — confirm enrollment with a code. Requires login.
func (s *server) handle2FAEnable(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.requireSession(w, r)
	if !ok {
		return
	}
	u, err := s.accounts.load(sess.username)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "could not load account")
		return
	}
	if len(u.TOTPSecret) == 0 {
		jsonError(w, http.StatusBadRequest, "run setup first")
		return
	}
	secret, err := aesUnwrap(totpKey(sess.dk), u.TOTPNonce, u.TOTPSecret)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "could not load 2FA secret")
		return
	}
	if !totpVerify(secret, r.FormValue("code")) {
		jsonError(w, http.StatusBadRequest, "that code didn't match — try again")
		return
	}
	u.TOTPEnabled = true
	if err := s.accounts.save(u); err != nil {
		jsonError(w, http.StatusInternalServerError, "could not save")
		return
	}
	s.audit.log("2fa_enabled", sess.username, clientIP(r), "")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// POST /api/2fa/disable — turn off 2FA (requires a current code). Requires login.
func (s *server) handle2FADisable(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.requireSession(w, r)
	if !ok {
		return
	}
	u, err := s.accounts.load(sess.username)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "could not load account")
		return
	}
	if u.TOTPEnabled {
		secret, err := aesUnwrap(totpKey(sess.dk), u.TOTPNonce, u.TOTPSecret)
		if err != nil || !totpVerify(secret, r.FormValue("code")) {
			jsonError(w, http.StatusBadRequest, "invalid code")
			return
		}
	}
	u.TOTPEnabled = false
	u.TOTPSecret = nil
	u.TOTPNonce = nil
	if err := s.accounts.save(u); err != nil {
		jsonError(w, http.StatusInternalServerError, "could not save")
		return
	}
	s.audit.log("2fa_disabled", sess.username, clientIP(r), "")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
