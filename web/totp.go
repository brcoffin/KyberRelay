package main

import (
	"crypto/hmac"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"time"

	qrcode "github.com/skip2/go-qrcode"
)

// TOTP (RFC 6238): HMAC-SHA1, 6 digits, 30s period — the authenticator-app
// standard. Stdlib crypto only; QR is rendered as a PNG data URI.

const (
	totpDigits = 6
	totpPeriod = 30
)

var totpBase32 = base32.StdEncoding.WithPadding(base32.NoPadding)

func newTOTPSecret() ([]byte, error) {
	b := make([]byte, 20)
	_, err := rand.Read(b)
	return b, err
}

func totpCodeAt(secret []byte, counter int64) string {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(counter))
	h := hmac.New(sha1.New, secret)
	h.Write(buf[:])
	sum := h.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := (uint32(sum[off]&0x7f)<<24 | uint32(sum[off+1])<<16 |
		uint32(sum[off+2])<<8 | uint32(sum[off+3]))
	var mod uint32 = 1
	for i := 0; i < totpDigits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", totpDigits, v%mod)
}

// totpVerify checks a code against the current 30s window ±1 (clock skew).
func totpVerify(secret []byte, code string) bool {
	code = strings.TrimSpace(code)
	if len(code) != totpDigits {
		return false
	}
	c := time.Now().Unix() / totpPeriod
	for _, d := range []int64{-1, 0, 1} {
		if subtle.ConstantTimeCompare([]byte(totpCodeAt(secret, c+d)), []byte(code)) == 1 {
			return true
		}
	}
	return false
}

func totpSecretB32(secret []byte) string { return totpBase32.EncodeToString(secret) }

// totpURI builds the otpauth:// URI scanned by authenticator apps.
func totpURI(username string, secret []byte) string {
	label := url.PathEscape("KyberCrypt:" + username)
	q := url.Values{}
	q.Set("secret", totpSecretB32(secret))
	q.Set("issuer", "KyberCrypt")
	q.Set("algorithm", "SHA1")
	q.Set("digits", fmt.Sprint(totpDigits))
	q.Set("period", fmt.Sprint(totpPeriod))
	return "otpauth://totp/" + label + "?" + q.Encode()
}

func totpQRDataURI(uri string) (string, error) {
	png, err := qrcode.Encode(uri, qrcode.Medium, 240)
	if err != nil {
		return "", err
	}
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(png), nil
}

// totpKey derives the AES key that wraps a user's TOTP secret at rest, from
// their decapsulation key — so the secret is only recoverable with the private
// key (itself password-wrapped), and is available during login (we hold the
// unwrapped key in the pending-login state).
// --- 2FA recovery codes ---

// newRecoveryCodes returns n one-time codes for display ("abcd-efgh") and their
// SHA-256 hashes for storage. Codes are high-entropy, so a fast hash is fine.
func newRecoveryCodes(n int) (display []string, hashes []string) {
	for i := 0; i < n; i++ {
		b := make([]byte, 5)
		_, _ = rand.Read(b)
		s := strings.ToLower(totpBase32.EncodeToString(b)) // 8 chars
		display = append(display, s[:4]+"-"+s[4:])
		hashes = append(hashes, hashRecovery(s))
	}
	return display, hashes
}

func normalizeRecovery(s string) string {
	s = strings.ToLower(s)
	var b strings.Builder
	for _, c := range s {
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') {
			b.WriteRune(c)
		}
	}
	return b.String()
}

func hashRecovery(s string) string {
	sum := sha256.Sum256([]byte(normalizeRecovery(s)))
	return hex.EncodeToString(sum[:])
}

func totpKey(dk *mlkem.DecapsulationKey768) []byte {
	seed := dk.Bytes()
	sum := sha256.Sum256(append(append([]byte{}, seed...), []byte("totp-wrap")...))
	return sum[:]
}
