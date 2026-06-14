package main

import (
	"errors"
	"net/http"
)

// Sentinel errors returned from accounts.update closures so the handlers can map
// them to the right HTTP status. Storage/crypto failures fall through to 500.
var (
	err2FASetupFirst = errors.New("run setup first")
	err2FABadCode    = errors.New("that code didn't match — try again")
	err2FANotEnabled = errors.New("2FA is not enabled")
)

// POST /api/2fa/setup — generate a secret (not yet enabled) and return the
// otpauth URI + QR for enrollment. Requires login.
func (s *server) handle2FASetup(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.requireSession(w, r)
	if !ok {
		return
	}
	if s.regGuard.locked("2fa:" + sess.username) {
		jsonError(w, http.StatusTooManyRequests, "too many attempts — try again later")
		return
	}
	s.regGuard.fail("2fa:" + sess.username)

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
	if err := s.accounts.update(sess.username, func(u *User) error {
		u.TOTPNonce = nonce
		u.TOTPSecret = wrapped
		u.TOTPEnabled = false // stays off until a code is verified
		u.TOTPLastUsed = 0
		return nil
	}); err != nil {
		jsonError(w, http.StatusInternalServerError, "could not save")
		return
	}
	uri := totpURI(sess.username, secret)
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
	code := r.FormValue("code")
	var display []string
	err := s.accounts.update(sess.username, func(u *User) error {
		if len(u.TOTPSecret) == 0 {
			return err2FASetupFirst
		}
		secret, err := aesUnwrap(totpKey(sess.dk), u.TOTPNonce, u.TOTPSecret)
		if err != nil {
			return err // 500: secret unreadable
		}
		valid, counter := totpVerify(secret, code)
		if !valid {
			return err2FABadCode
		}
		u.TOTPEnabled = true
		u.TOTPLastUsed = counter // the enrollment code can't be replayed at login
		var hashes []string
		display, hashes = newRecoveryCodes(10)
		u.RecoveryCodes = hashes
		return nil
	})
	switch err {
	case nil:
		s.audit.log("2fa_enabled", sess.username, clientIP(r), "")
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "recovery_codes": display})
	case err2FASetupFirst, err2FABadCode:
		jsonError(w, http.StatusBadRequest, err.Error())
	default:
		jsonError(w, http.StatusInternalServerError, "could not enable 2FA")
	}
}

// POST /api/2fa/recovery — regenerate recovery codes (invalidates old ones).
func (s *server) handle2FARecovery(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.requireSession(w, r)
	if !ok {
		return
	}
	var display []string
	err := s.accounts.update(sess.username, func(u *User) error {
		if !u.TOTPEnabled {
			return err2FANotEnabled
		}
		var hashes []string
		display, hashes = newRecoveryCodes(10)
		u.RecoveryCodes = hashes
		return nil
	})
	switch err {
	case nil:
		s.audit.log("2fa_recovery_regenerated", sess.username, clientIP(r), "")
		writeJSON(w, http.StatusOK, map[string]any{"recovery_codes": display})
	case err2FANotEnabled:
		jsonError(w, http.StatusBadRequest, err.Error())
	default:
		jsonError(w, http.StatusInternalServerError, "could not save")
	}
}

// POST /api/2fa/disable — turn off 2FA (requires a current code). Requires login.
func (s *server) handle2FADisable(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.requireSession(w, r)
	if !ok {
		return
	}
	code := r.FormValue("code")
	err := s.accounts.update(sess.username, func(u *User) error {
		if u.TOTPEnabled {
			secret, err := aesUnwrap(totpKey(sess.dk), u.TOTPNonce, u.TOTPSecret)
			if err != nil {
				return err2FABadCode
			}
			if valid, _ := totpVerify(secret, code); !valid {
				return err2FABadCode
			}
		}
		u.TOTPEnabled = false
		u.TOTPSecret = nil
		u.TOTPNonce = nil
		u.TOTPLastUsed = 0
		u.RecoveryCodes = nil
		return nil
	})
	switch err {
	case nil:
		s.audit.log("2fa_disabled", sess.username, clientIP(r), "")
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	case err2FABadCode:
		jsonError(w, http.StatusBadRequest, "invalid code")
	default:
		jsonError(w, http.StatusInternalServerError, "could not save")
	}
}
