package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/mlkem"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
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

	accountIter  = 200_000     // legacy PBKDF2 iterations
	argonTime    = 2           // Argon2id passes
	argonMemKiB  = 64 * 1024   // 64 MiB
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
)

type User struct {
	Username   string `json:"username"`
	SaltAuth   []byte `json:"salt_auth"`
	PwHash     []byte `json:"pw_hash"`
	PubKey     []byte `json:"pub_key"`     // ML-KEM-768 encapsulation key (1184 B)
	SaltWrap   []byte `json:"salt_wrap"`
	WrapNonce  []byte `json:"wrap_nonce"`
	WrappedKey []byte `json:"wrapped_key"` // AES-GCM-wrapped 64-byte decapsulation seed
	KDF        string `json:"kdf"`         // "argon2id" (new) or "pbkdf2"/"" (legacy)
	Plan       string `json:"plan"`        // "" / "free" / "pro"
	Created    int64  `json:"created"`
}

type accounts struct {
	dir string
	mu  sync.Mutex
}

func newAccounts(dir string) (*accounts, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &accounts{dir: dir}, nil
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

	a.mu.Lock()
	defer a.mu.Unlock()
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

// --- message (inbox) store ---

type Message struct {
	ID        string `json:"id"`
	Sender    string `json:"sender"`
	Recipient string `json:"recipient"`
	KemCt     []byte `json:"kem_ct"` // ML-KEM ciphertext (encapsulated to recipient)
	Nonce     []byte `json:"nonce"`  // AES-GCM nonce
	Size      int64  `json:"size"`   // approx plaintext size, for display
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

func (m *messages) put(msg Message, ct []byte) error {
	if err := os.MkdirAll(m.userDir(msg.Recipient), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(m.blobPath(msg.Recipient, msg.ID), ct, 0o600); err != nil {
		return err
	}
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

func (m *messages) get(user, id string) (Message, []byte, error) {
	var msg Message
	b, err := os.ReadFile(m.metaPath(user, id))
	if err != nil {
		return msg, nil, err
	}
	if err := json.Unmarshal(b, &msg); err != nil {
		return msg, nil, err
	}
	ct, err := os.ReadFile(m.blobPath(user, id))
	if err != nil {
		return msg, nil, err
	}
	return msg, ct, nil
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

// --- key-based payload sealing (filename sealed inside, like the passphrase path) ---

func sealWithKey(key []byte, filename string, data []byte) (nonce, ct []byte, err error) {
	payload, err := packPayload(filename, data)
	if err != nil {
		return nil, nil, err
	}
	compressed, err := deflateBytes(payload)
	if err != nil {
		return nil, nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	ct = gcm.Seal(nil, nonce, compressed, nil)
	return nonce, ct, nil
}

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
