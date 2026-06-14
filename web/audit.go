package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// auditor appends security-relevant events to an append-only JSONL log
// (data/audit.log) for forensics, and can return a user's recent events for the
// dashboard.

type auditEntry struct {
	Time   string `json:"time"`
	Event  string `json:"event"`
	User   string `json:"user,omitempty"`
	IP     string `json:"ip,omitempty"`
	Detail string `json:"detail,omitempty"`
}

type auditor struct {
	mu   sync.Mutex
	path string
}

func newAuditor(dir string) *auditor {
	return &auditor{path: filepath.Join(dir, "audit.log")}
}

// log records one event (best-effort; never blocks the request on error).
func (a *auditor) log(event, user, ip, detail string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	f, err := os.OpenFile(a.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	_ = json.NewEncoder(f).Encode(auditEntry{
		Time:   time.Now().UTC().Format(time.RFC3339),
		Event:  event,
		User:   user,
		IP:     ip,
		Detail: detail,
	})
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
