package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// auditor appends security-relevant events to a tamper-evident, append-only
// JSONL log (data/audit.log). Each entry is hash-chained to the previous one:
// hash = HMAC(key, {seq, prev, fields}). Editing, reordering, or inserting an
// entry breaks the chain; truncating the tail is caught by a separately stored
// head pointer (data/audit.head). With AUDIT_HMAC_KEY set (kept off the data
// dir / off-box), even an attacker who can write the file can't forge a valid
// chain; without it the chain still detects accidental or naive tampering.

type auditEntry struct {
	Seq    int64  `json:"seq"`
	Prev   string `json:"prev,omitempty"`
	Time   string `json:"time"`
	Event  string `json:"event"`
	User   string `json:"user,omitempty"`
	IP     string `json:"ip,omitempty"`
	Detail string `json:"detail,omitempty"`
	Hash   string `json:"hash"`
}

type auditor struct {
	mu       sync.Mutex
	path     string
	headPath string
	key      []byte
	seq      int64
	lastHash string
}

func newAuditor(dir string) *auditor {
	a := &auditor{
		path:     filepath.Join(dir, "audit.log"),
		headPath: filepath.Join(dir, "audit.head"),
		key:      []byte(env("AUDIT_HMAC_KEY", "")),
	}
	a.resume()
	return a
}

// resume reads the existing log's last entry so the chain continues across
// restarts.
func (a *auditor) resume() {
	data, err := os.ReadFile(a.path)
	if err != nil {
		return
	}
	lines := strings.Split(string(data), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}
		var e auditEntry
		if json.Unmarshal([]byte(line), &e) == nil {
			a.seq = e.Seq
			a.lastHash = e.Hash
		}
		return
	}
}

// chainHash computes an entry's hash over its fields with Hash cleared, keyed by
// AUDIT_HMAC_KEY (HMAC-SHA256) or unkeyed SHA-256 when no key is configured.
func (a *auditor) chainHash(e auditEntry) string {
	e.Hash = ""
	b, _ := json.Marshal(e)
	if len(a.key) > 0 {
		m := hmac.New(sha256.New, a.key)
		m.Write(b)
		return hex.EncodeToString(m.Sum(nil))
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// log records one event (best-effort; never blocks the request on error).
func (a *auditor) log(event, user, ip, detail string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	e := auditEntry{
		Seq:    a.seq + 1,
		Prev:   a.lastHash,
		Time:   time.Now().UTC().Format(time.RFC3339),
		Event:  event,
		User:   user,
		IP:     ip,
		Detail: detail,
	}
	e.Hash = a.chainHash(e)

	f, err := os.OpenFile(a.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	if err := json.NewEncoder(f).Encode(e); err != nil {
		f.Close()
		return
	}
	f.Close()

	a.seq = e.Seq
	a.lastHash = e.Hash
	a.writeHead()
}

// writeHead persists the latest (seq, hash) so a truncated tail is detectable.
func (a *auditor) writeHead() {
	b, _ := json.Marshal(map[string]any{"seq": a.seq, "hash": a.lastHash})
	tmp := a.headPath + ".tmp"
	if os.WriteFile(tmp, b, 0o600) == nil {
		_ = os.Rename(tmp, a.headPath)
	}
}

// verify walks the whole log, confirming the hash chain is intact and the tail
// matches the stored head. Returns a descriptive error at the first break.
func (a *auditor) verify() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	data, err := os.ReadFile(a.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // no log yet
		}
		return err
	}
	prev := ""
	var seq int64
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var e auditEntry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			return fmt.Errorf("unparseable entry after seq %d", seq)
		}
		if e.Seq != seq+1 {
			return fmt.Errorf("sequence gap: expected %d, got %d", seq+1, e.Seq)
		}
		if e.Prev != prev {
			return fmt.Errorf("broken chain at seq %d", e.Seq)
		}
		if e.Hash != a.chainHash(e) {
			return fmt.Errorf("hash mismatch at seq %d (entry tampered)", e.Seq)
		}
		prev = e.Hash
		seq = e.Seq
	}

	// Head check: detects truncation of the tail, which the chain alone cannot.
	if hb, err := os.ReadFile(a.headPath); err == nil {
		var head struct {
			Seq  int64  `json:"seq"`
			Hash string `json:"hash"`
		}
		if json.Unmarshal(hb, &head) == nil && (head.Seq != seq || head.Hash != prev) {
			return fmt.Errorf("head mismatch (log truncated?): head seq %d, log ends at %d", head.Seq, seq)
		}
	}
	return nil
}

// recentForUser returns up to limit of a user's most recent events (newest first).
func (a *auditor) recentForUser(user string, limit int) []auditEntry {
	a.mu.Lock()
	data, err := os.ReadFile(a.path)
	a.mu.Unlock()
	if err != nil {
		return nil
	}
	var out []auditEntry
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var e auditEntry
		if json.Unmarshal([]byte(line), &e) != nil || e.User != user {
			continue
		}
		out = append(out, e)
	}
	// newest first, capped
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}
