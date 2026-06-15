package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/mlkem"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
)

// Account system (public-key, send-by-username) for the web service.
//
// Each user gets an ML-KEM-768 keypair at registration. The public
// (encapsulation) key is stored as-is; the private (decapsulation) key's
// 64-byte seed is wrapped with AES-256-GCM under a key derived from the user's
// password (PBKDF2). The plaintext private key therefore exists on the server
// only transiently, inside a logged-in session — a database leak alone cannot
// decrypt anyone's files. (Trade-off: a forgotten password is unrecoverable.)

// KDF selection. New accounts/keys use Argon2id (memory-hard); legacy records
// (KDF "" or "pbkdf2") still verify with PBKDF2 so nothing breaks.
const (
	kdfArgon2id = "argon2id"
	kdfPBKDF2   = "pbkdf2"

	accountIter  = 200_000   // legacy PBKDF2 iterations
	argonTime    = 2         // Argon2id passes
	argonMemKiB  = 64 * 1024 // 64 MiB
	argonThreads = 2
)

// deriveKey derives a 32-byte key from a password using the named KDF.
func deriveKDFKey(kdf, password string, salt []byte) ([]byte, error) {
	if kdf == kdfPBKDF2 {
		return pbkdf2.Key(sha256.New, password, salt, accountIter, 32)
	}
	return argon2.IDKey([]byte(password), salt, argonTime, argonMemKiB, argonThreads, 32), nil
}

var (
	errUserExists = errors.New("username already taken")
	errBadLogin   = errors.New("invalid username or password")
	errNoSuchUser = errors.New("no such user")
	errTooLarge   = errors.New("file exceeds your plan's size limit")
	validUsername = regexp.MustCompile(`^[a-z0-9_-]{3,32}$`)

	// enumGuardSalt is a fixed salt used only to burn an equivalent KDF pass on
	// the user-not-found path, so login timing can't distinguish a missing user
	// from a wrong password (user enumeration).
	enumGuardSalt = make([]byte, 16)
)

type User struct {
	Username   string `json:"username"`
	SaltAuth   []byte `json:"salt_auth"`
	PwHash     []byte `json:"pw_hash"`
	PubKey     []byte `json:"pub_key"` // ML-KEM-768 encapsulation key (1184 B)
	SaltWrap   []byte `json:"salt_wrap"`
	WrapNonce  []byte `json:"wrap_nonce"`
	WrappedKey []byte `json:"wrapped_key"`       // AES-GCM-wrapped 64-byte decapsulation seed
	KDF        string `json:"kdf"`               // "argon2id" (new) or "pbkdf2"/"" (legacy)
	Plan       string `json:"plan"`              // "" / "free" / "pro"
	TeamID     string `json:"team_id,omitempty"` // member of this team, if any (grants Team plan)
	Created    int64  `json:"created"`

	// TOTP 2FA. Secret is wrapped under totpKey(decapsulation key).
	TOTPEnabled   bool     `json:"totp_enabled,omitempty"`
	TOTPNonce     []byte   `json:"totp_nonce,omitempty"`
	TOTPSecret    []byte   `json:"totp_secret,omitempty"`
	TOTPLastUsed  int64    `json:"totp_last_used,omitempty"` // last accepted time-step (replay guard)
	RecoveryCodes []string `json:"recovery_codes,omitempty"` // SHA-256 hashes, single-use

	// Billing (Stripe).
	StripeCustomerID string `json:"stripe_customer_id,omitempty"`
	StripeSubID      string `json:"stripe_sub_id,omitempty"`
}

// consumeRecovery verifies a 2FA recovery code and, if valid, removes it
// (single-use) and persists the change. Returns true on success.
func (a *accounts) consumeRecovery(username, code string) bool {
	if normalizeRecovery(code) == "" {
		return false
	}
	h := hashRecovery(code)
	consumed := false
	_ = a.update(username, func(u *User) error {
		for i, rc := range u.RecoveryCodes {
			if subtle.ConstantTimeCompare([]byte(rc), []byte(h)) == 1 {
				u.RecoveryCodes = append(u.RecoveryCodes[:i], u.RecoveryCodes[i+1:]...)
				consumed = true
				return nil
			}
		}
		return errNoChange // no match — don't persist
	})
	return consumed
}

// consumeTOTP verifies a code and, on success, records its time-step so the same
// code can't be replayed within its ±1 window. Returns false on a bad or
// already-used code. The check-and-record is atomic under the user's lock.
func (a *accounts) consumeTOTP(username string, secret []byte, code string) bool {
	ok, counter := totpVerify(secret, code)
	if !ok {
		return false
	}
	accepted := false
	_ = a.update(username, func(u *User) error {
		if counter <= u.TOTPLastUsed {
			return errNoChange // replay of an already-accepted code
		}
		u.TOTPLastUsed = counter
		accepted = true
		return nil
	})
	return accepted
}

// findByStripeCustomer scans for the user with the given Stripe customer ID.
func (a *accounts) findByStripeCustomer(custID string) (*User, bool) {
	if custID == "" {
		return nil, false
	}
	entries, err := os.ReadDir(a.dir)
	if err != nil {
		return nil, false
	}
	for _, e := range entries {
		if filepath.Ext(e.Name()) != ".json" {
			continue
		}
		b, err := os.ReadFile(filepath.Join(a.dir, e.Name()))
		if err != nil {
			continue
		}
		var u User
		if json.Unmarshal(b, &u) == nil && u.StripeCustomerID == custID {
			return &u, true
		}
	}
	return nil, false
}

// save atomically writes a user record (used for profile updates like 2FA).
func (a *accounts) save(u *User) error {
	b, err := json.Marshal(u)
	if err != nil {
		return err
	}
	tmp := a.path(u.Username) + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, a.path(u.Username))
}

type accounts struct {
	dir   string
	mu    sync.Mutex // guards the per-user lock table below
	locks map[string]*sync.Mutex
}

func newAccounts(dir string) (*accounts, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &accounts{dir: dir, locks: make(map[string]*sync.Mutex)}, nil
}

// userLock returns the per-username mutex, creating it on first use. Every
// read-modify-write sequence on a user's record must hold it, so concurrent
// updates (e.g. enable-2FA racing change-password) can't clobber each other,
// and a single-use recovery code can't be double-spent.
func (a *accounts) userLock(username string) *sync.Mutex {
	a.mu.Lock()
	defer a.mu.Unlock()
	l, ok := a.locks[username]
	if !ok {
		l = &sync.Mutex{}
		a.locks[username] = l
	}
	return l
}

// errNoChange aborts an update() without persisting (e.g. a recovery-code miss
// or a replayed TOTP code). It is internal and never surfaced to clients.
var errNoChange = errors.New("no change")

// update runs fn against the user's record under that user's lock and persists
// the result. If fn returns an error nothing is saved and the error is returned.
func (a *accounts) update(username string, fn func(*User) error) error {
	l := a.userLock(username)
	l.Lock()
	defer l.Unlock()
	u, err := a.load(username)
	if err != nil {
		return err
	}
	if err := fn(u); err != nil {
		return err
	}
	return a.save(u)
}

func (a *accounts) path(username string) string {
	return filepath.Join(a.dir, filepath.Base(username)+".json")
}

func (a *accounts) load(username string) (*User, error) {
	b, err := os.ReadFile(a.path(username))
	if err != nil {
		return nil, errNoSuchUser
	}
	var u User
	if err := json.Unmarshal(b, &u); err != nil {
		return nil, err
	}
	return &u, nil
}

func (a *accounts) register(username, password string) (*User, error) {
	if !validUsername.MatchString(username) {
		return nil, errors.New("invalid username (3-32 chars: a-z, 0-9, _, -)")
	}
	if len(password) < 12 {
		return nil, errors.New("password must be at least 12 characters")
	}

	l := a.userLock(username)
	l.Lock()
	defer l.Unlock()
	if _, err := os.Stat(a.path(username)); err == nil {
		return nil, errUserExists
	}

	saltAuth := make([]byte, 16)
	if _, err := rand.Read(saltAuth); err != nil {
		return nil, err
	}
	pwHash, err := deriveKDFKey(kdfArgon2id, password, saltAuth)
	if err != nil {
		return nil, err
	}

	dk, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, err
	}
	pub := dk.EncapsulationKey().Bytes()
	seed := dk.Bytes() // 64-byte seed

	saltWrap := make([]byte, 16)
	if _, err := rand.Read(saltWrap); err != nil {
		return nil, err
	}
	wrapKey, err := deriveKDFKey(kdfArgon2id, password, saltWrap)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(wrapKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	wrapNonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(wrapNonce); err != nil {
		return nil, err
	}
	wrapped := gcm.Seal(nil, wrapNonce, seed, nil)

	u := &User{
		Username: username, SaltAuth: saltAuth, PwHash: pwHash, PubKey: pub,
		SaltWrap: saltWrap, WrapNonce: wrapNonce, WrappedKey: wrapped,
		KDF: kdfArgon2id, Plan: "free", Created: time.Now().Unix(),
	}
	b, err := json.Marshal(u)
	if err != nil {
		return nil, err
	}
	tmp := a.path(username) + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return nil, err
	}
	if err := os.Rename(tmp, a.path(username)); err != nil {
		return nil, err
	}
	return u, nil
}

// authenticate verifies the password and returns the user plus the unwrapped
// decapsulation key (held in the session for the login's duration).
func (a *accounts) authenticate(username, password string) (*User, *mlkem.DecapsulationKey768, error) {
	u, err := a.load(username)
	if err != nil {
		// Equalize timing with the real KDF path below so a missing user is
		// indistinguishable from a wrong password.
		_, _ = deriveKDFKey(kdfArgon2id, password, enumGuardSalt)
		return nil, nil, errBadLogin
	}
	kdf := u.KDF
	if kdf == "" {
		kdf = kdfPBKDF2 // legacy records predate the KDF field
	}
	want, err := deriveKDFKey(kdf, password, u.SaltAuth)
	if err != nil {
		return nil, nil, err
	}
	if subtle.ConstantTimeCompare(want, u.PwHash) != 1 {
		return nil, nil, errBadLogin
	}

	wrapKey, err := deriveKDFKey(kdf, password, u.SaltWrap)
	if err != nil {
		return nil, nil, err
	}
	block, err := aes.NewCipher(wrapKey)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	seed, err := gcm.Open(nil, u.WrapNonce, u.WrappedKey, nil)
	if err != nil {
		return nil, nil, errBadLogin
	}
	dk, err := mlkem.NewDecapsulationKey768(seed)
	if err != nil {
		return nil, nil, err
	}
	return u, dk, nil
}

// changePassword verifies the current password, then re-derives the auth hash
// and re-wraps the private key under the new password. API keys are unaffected
// (they wrap the key under their own secret), and the session stays valid (the
// key itself doesn't change, only its password-wrapping).
func (a *accounts) changePassword(username, oldPassword, newPassword string) error {
	_, dk, err := a.authenticate(username, oldPassword)
	if err != nil {
		return errBadLogin // current password incorrect (or 2FA-wrapped load failed)
	}
	if len(newPassword) < 12 {
		return errors.New("new password must be at least 12 characters")
	}
	seed := dk.Bytes()

	saltAuth := make([]byte, 16)
	if _, err := rand.Read(saltAuth); err != nil {
		return err
	}
	pwHash, err := deriveKDFKey(kdfArgon2id, newPassword, saltAuth)
	if err != nil {
		return err
	}
	saltWrap := make([]byte, 16)
	if _, err := rand.Read(saltWrap); err != nil {
		return err
	}
	wrapKey, err := deriveKDFKey(kdfArgon2id, newPassword, saltWrap)
	if err != nil {
		return err
	}
	nonce, wrapped, err := aesWrap(wrapKey, seed)
	if err != nil {
		return err
	}

	return a.update(username, func(u *User) error {
		u.SaltAuth = saltAuth
		u.PwHash = pwHash
		u.SaltWrap = saltWrap
		u.WrapNonce = nonce
		u.WrappedKey = wrapped
		u.KDF = kdfArgon2id
		return nil
	})
}

// --- message (inbox) store ---

type Message struct {
	ID        string `json:"id"`
	Sender    string `json:"sender"`
	Recipient string `json:"recipient"`
	KemCt     []byte `json:"kem_ct"`           // ML-KEM ciphertext (encapsulated to recipient)
	Nonce     []byte `json:"nonce,omitempty"`  // AES-GCM nonce (legacy single-shot blobs only)
	Stream    bool   `json:"stream,omitempty"` // true: chunked-stream blob (see stream.go)
	Size      int64  `json:"size"`             // approx plaintext size, for display
	Created   int64  `json:"created"`
	Expires   int64  `json:"expires"`
}

type messages struct {
	dir string
}

func newMessages(dir string) (*messages, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &messages{dir: dir}, nil
}

func (m *messages) userDir(user string) string { return filepath.Join(m.dir, filepath.Base(user)) }
func (m *messages) metaPath(user, id string) string {
	return filepath.Join(m.userDir(user), filepath.Base(id)+".json")
}
func (m *messages) blobPath(user, id string) string {
	return filepath.Join(m.userDir(user), filepath.Base(id)+".blob")
}

// writeBlob streams an encrypted blob to <recipient>/<id>.blob via seal, writing
// to a temp file first and renaming on success so a partial write never lands.
func (m *messages) writeBlob(recipient, id string, seal func(io.Writer) error) error {
	if err := os.MkdirAll(m.userDir(recipient), 0o700); err != nil {
		return err
	}
	blob := m.blobPath(recipient, id)
	tmp := blob + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	bw := bufio.NewWriterSize(f, streamChunk)
	if err := seal(bw); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := bw.Flush(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, blob)
}

// writeMeta persists a message's metadata sidecar.
func (m *messages) writeMeta(msg Message) error {
	b, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	return os.WriteFile(m.metaPath(msg.Recipient, msg.ID), b, 0o600)
}

func (m *messages) list(user string) []Message {
	entries, err := os.ReadDir(m.userDir(user))
	if err != nil {
		return nil
	}
	now := time.Now().Unix()
	var out []Message
	for _, e := range entries {
		if filepath.Ext(e.Name()) != ".json" {
			continue
		}
		b, err := os.ReadFile(filepath.Join(m.userDir(user), e.Name()))
		if err != nil {
			continue
		}
		var msg Message
		if json.Unmarshal(b, &msg) != nil {
			continue
		}
		if msg.Expires > 0 && now > msg.Expires {
			m.delete(user, msg.ID)
			continue
		}
		out = append(out, msg)
	}
	return out
}

// meta reads a message's metadata sidecar (no blob).
func (m *messages) meta(user, id string) (Message, error) {
	var msg Message
	b, err := os.ReadFile(m.metaPath(user, id))
	if err != nil {
		return msg, err
	}
	err = json.Unmarshal(b, &msg)
	return msg, err
}

// openBlob opens the ciphertext blob for streaming.
func (m *messages) openBlob(user, id string) (*os.File, error) {
	return os.Open(m.blobPath(user, id))
}

func (m *messages) delete(user, id string) {
	_ = os.Remove(m.blobPath(user, id))
	_ = os.Remove(m.metaPath(user, id))
}

func (m *messages) sweep() {
	entries, err := os.ReadDir(m.dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() {
			m.list(e.Name()) // list() drops expired entries as a side effect
		}
	}
}

// --- key-based payload opening (legacy single-shot blobs; new blobs stream) ---

func openWithKey(key, nonce, ct []byte) (filename string, data []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", nil, err
	}
	compressed, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", nil, err
	}
	payload, err := inflateBytes(compressed)
	if err != nil {
		return "", nil, err
	}
	return unpackPayload(payload)
}
