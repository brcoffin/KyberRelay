package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Per-user API keys for programmatic access.
//
// A token is "kc_<keyid>.<secret>". The store keeps sha256(secret) for
// verification and the user's ML-KEM decapsulation seed wrapped under a key
// derived from <secret> (PBKDF2 + AES-256-GCM). So a token alone can both send
// AND decrypt inbox files — no interactive password needed — while the stored
// record by itself (without the token) cannot. Tokens are shown once at
// creation; only their hash and the wrapped seed are persisted.

const apiKeyPrefix = "kc_"

// Scopes. A "send" key carries no private-key material (sending uses the
// recipient's public key), so it can never decrypt — even if leaked. A
// "decrypt" key can send AND read/download the owner's inbox.
const (
	scopeSend    = "send"
	scopeDecrypt = "decrypt"
)

var (
	keyIDEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)
	errBadAPIKey  = errors.New("invalid or revoked API key")
	errKeyExpired = errors.New("API key has expired")
)

type APIKey struct {
	KeyID       string `json:"key_id"`
	Username    string `json:"username"`
	Label       string `json:"label"`
	SecretHash  []byte `json:"secret_hash"`
	SaltWrap    []byte `json:"salt_wrap"`
	WrapNonce   []byte `json:"wrap_nonce"`
	WrappedSeed []byte `json:"wrapped_seed"`
	KDF         string `json:"kdf"`
	Scope       string `json:"scope"`             // "send" or "decrypt" ("" = legacy decrypt)
	Expires     int64  `json:"expires,omitempty"` // 0 = never
	Created     int64  `json:"created"`
}

type apikeyStore struct {
	dir string
}

func newAPIKeyStore(dir string) (*apikeyStore, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &apikeyStore{dir: dir}, nil
}

func (k *apikeyStore) path(keyID string) string {
	return filepath.Join(k.dir, filepath.Base(keyID)+".json")
}

func randToken(nBytes int) ([]byte, error) {
	b := make([]byte, nBytes)
	_, err := rand.Read(b)
	return b, err
}

func aesWrap(key, plaintext []byte) (nonce, ct []byte, err error) {
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
	return nonce, gcm.Seal(nil, nonce, plaintext, nil), nil
}

func aesUnwrap(key, nonce, ct []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, ct, nil)
}

// create mints a new API key. For "decrypt" scope it wraps the given
// decapsulation seed so the token can decrypt; for "send" scope no key material
// is stored at all. expires is a Unix time (0 = never). Returns the token once.
func (k *apikeyStore) create(username, label, scope string, expires int64, seed []byte) (string, error) {
	idBytes, err := randToken(10)
	if err != nil {
		return "", err
	}
	secretBytes, err := randToken(32)
	if err != nil {
		return "", err
	}
	keyID := keyIDEncoding.EncodeToString(idBytes)
	secret := base64.RawURLEncoding.EncodeToString(secretBytes)

	sum := sha256.Sum256([]byte(secret))
	saltWrap, err := randToken(16)
	if err != nil {
		return "", err
	}

	var nonce, wrapped []byte
	if scope != scopeSend {
		wrapKey, err := deriveKDFKey(kdfArgon2id, secret, saltWrap)
		if err != nil {
			return "", err
		}
		nonce, wrapped, err = aesWrap(wrapKey, seed)
		if err != nil {
			return "", err
		}
	}

	rec := APIKey{
		KeyID: keyID, Username: username, Label: label,
		SecretHash: sum[:], SaltWrap: saltWrap, WrapNonce: nonce,
		WrappedSeed: wrapped, KDF: kdfArgon2id,
		Scope: scope, Expires: expires, Created: time.Now().Unix(),
	}
	b, err := json.Marshal(rec)
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(k.path(keyID), b, 0o600); err != nil {
		return "", err
	}
	return apiKeyPrefix + keyID + "." + secret, nil
}

// authenticate verifies a token and returns the owning username, scope, and
// (for decrypt scope) the unwrapped decapsulation key. dk is nil for send-only.
func (k *apikeyStore) authenticate(token string) (string, string, *mlkem.DecapsulationKey768, error) {
	if !strings.HasPrefix(token, apiKeyPrefix) {
		return "", "", nil, errBadAPIKey
	}
	rest := strings.TrimPrefix(token, apiKeyPrefix)
	keyID, secret, ok := strings.Cut(rest, ".")
	if !ok || keyID == "" || secret == "" {
		return "", "", nil, errBadAPIKey
	}

	b, err := os.ReadFile(k.path(keyID))
	if err != nil {
		return "", "", nil, errBadAPIKey
	}
	var rec APIKey
	if err := json.Unmarshal(b, &rec); err != nil {
		return "", "", nil, errBadAPIKey
	}

	if rec.Expires > 0 && time.Now().Unix() > rec.Expires {
		return "", "", nil, errKeyExpired
	}

	sum := sha256.Sum256([]byte(secret))
	if subtle.ConstantTimeCompare(sum[:], rec.SecretHash) != 1 {
		return "", "", nil, errBadAPIKey
	}

	scope := rec.Scope
	if scope == "" {
		scope = scopeDecrypt // legacy keys hold a wrapped seed
	}
	if scope == scopeSend {
		return rec.Username, scopeSend, nil, nil
	}

	kdf := rec.KDF
	if kdf == "" {
		kdf = kdfPBKDF2
	}
	wrapKey, err := deriveKDFKey(kdf, secret, rec.SaltWrap)
	if err != nil {
		return "", "", nil, err
	}
	seed, err := aesUnwrap(wrapKey, rec.WrapNonce, rec.WrappedSeed)
	if err != nil {
		return "", "", nil, errBadAPIKey
	}
	dk, err := mlkem.NewDecapsulationKey768(seed)
	if err != nil {
		return "", "", nil, errBadAPIKey
	}
	return rec.Username, scopeDecrypt, dk, nil
}

type APIKeyInfo struct {
	KeyID   string `json:"key_id"`
	Label   string `json:"label"`
	Scope   string `json:"scope"`
	Expires int64  `json:"expires"`
	Created int64  `json:"created"`
}

func (k *apikeyStore) list(username string) []APIKeyInfo {
	entries, err := os.ReadDir(k.dir)
	if err != nil {
		return nil
	}
	var out []APIKeyInfo
	for _, e := range entries {
		if filepath.Ext(e.Name()) != ".json" {
			continue
		}
		b, err := os.ReadFile(filepath.Join(k.dir, e.Name()))
		if err != nil {
			continue
		}
		var rec APIKey
		if json.Unmarshal(b, &rec) != nil || rec.Username != username {
			continue
		}
		scope := rec.Scope
		if scope == "" {
			scope = scopeDecrypt
		}
		out = append(out, APIKeyInfo{
			KeyID: rec.KeyID, Label: rec.Label, Scope: scope,
			Expires: rec.Expires, Created: rec.Created,
		})
	}
	return out
}

// revoke deletes a key if it belongs to username.
func (k *apikeyStore) revoke(username, keyID string) error {
	b, err := os.ReadFile(k.path(keyID))
	if err != nil {
		return errBadAPIKey
	}
	var rec APIKey
	if err := json.Unmarshal(b, &rec); err != nil || rec.Username != username {
		return errBadAPIKey
	}
	return os.Remove(k.path(keyID))
}
