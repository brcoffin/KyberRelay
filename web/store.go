package main

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

// Filesystem store: each item is <id>.json (metadata) + <id>.blob (ciphertext).
// No database for the MVP; swap for SQLite when accounts arrive.

var idEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)
var validID = regexp.MustCompile(`^[A-Z2-7]{26}$`)

func newID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return idEncoding.EncodeToString(b[:]), nil
}

// Meta is the plaintext sidecar. It deliberately holds no filename or contents
// — those are sealed inside the blob and need the passphrase.
type Meta struct {
	ID      string `json:"id"`
	Salt    []byte `json:"salt"`
	Nonce   []byte `json:"nonce"`
	Created int64  `json:"created"`
	Expires int64  `json:"expires"`
	OneTime bool   `json:"one_time"`
}

type store struct {
	dir string
}

func newStore(dir string) (*store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &store{dir: dir}, nil
}

func (s *store) metaPath(id string) string { return filepath.Join(s.dir, filepath.Base(id)+".json") }
func (s *store) blobPath(id string) string { return filepath.Join(s.dir, filepath.Base(id)+".blob") }

func (s *store) put(m Meta, ct []byte) error {
	if err := os.WriteFile(s.blobPath(m.ID), ct, 0o600); err != nil {
		return err
	}
	mj, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return os.WriteFile(s.metaPath(m.ID), mj, 0o600)
}

// get returns the item, or os.ErrNotExist if missing or expired (expired items
// are deleted lazily here).
func (s *store) get(id string) (Meta, []byte, error) {
	var m Meta
	mj, err := os.ReadFile(s.metaPath(id))
	if err != nil {
		return m, nil, err
	}
	if err := json.Unmarshal(mj, &m); err != nil {
		return m, nil, err
	}
	if m.Expires > 0 && time.Now().Unix() > m.Expires {
		s.delete(id)
		return m, nil, os.ErrNotExist
	}
	ct, err := os.ReadFile(s.blobPath(id))
	if err != nil {
		return m, nil, err
	}
	return m, ct, nil
}

func (s *store) delete(id string) {
	_ = os.Remove(s.blobPath(id))
	_ = os.Remove(s.metaPath(id))
}

// sweep deletes expired items.
func (s *store) sweep() {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return
	}
	now := time.Now().Unix()
	for _, e := range entries {
		name := e.Name()
		if filepath.Ext(name) != ".json" {
			continue
		}
		id := name[:len(name)-len(".json")]
		mj, err := os.ReadFile(filepath.Join(s.dir, name))
		if err != nil {
			continue
		}
		var m Meta
		if json.Unmarshal(mj, &m) != nil {
			continue
		}
		if m.Expires > 0 && now > m.Expires {
			s.delete(id)
		}
	}
}
