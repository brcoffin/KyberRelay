package main

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Contact / support form. Submissions are appended to data/contact.jsonl (no
// email infra yet — see the deploy notes about wiring SMTP forwarding). Public
// and unauthenticated, so it's protected by the same-origin guard, a honeypot
// field, and an IP rate limit.

type contactMsg struct {
	Time    string `json:"time"`
	IP      string `json:"ip"`
	Name    string `json:"name"`
	Email   string `json:"email"`
	Topic   string `json:"topic"`
	Message string `json:"message"`
}

type contactStore struct {
	mu   sync.Mutex
	path string
}

func newContactStore(dir string) *contactStore {
	return &contactStore{path: filepath.Join(dir, "contact.jsonl")}
}

func (c *contactStore) add(m contactMsg) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	f, err := os.OpenFile(c.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	return json.NewEncoder(f).Encode(m)
}

// GET /contact — the contact/support form. ?topic= preselects the dropdown,
// ?sent=1 shows the confirmation.
func (s *server) handleContactPage(w http.ResponseWriter, r *http.Request) {
	s.render(w, "contact.html", map[string]any{
		"Topic": r.URL.Query().Get("topic"),
		"Sent":  r.URL.Query().Get("sent") == "1",
	})
}

// POST /api/contact — store a submission, then redirect to the confirmation.
func (s *server) handleContactSubmit(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if s.regGuard.locked("contact:" + ip) {
		http.Error(w, "too many messages — please try again later", http.StatusTooManyRequests)
		return
	}
	s.regGuard.fail("contact:" + ip)

	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	// Honeypot: bots fill the hidden "website" field; humans never see it.
	if strings.TrimSpace(r.PostFormValue("website")) != "" {
		http.Redirect(w, r, "/contact?sent=1", http.StatusSeeOther)
		return
	}

	name := trimCap(r.PostFormValue("name"), 200)
	email := trimCap(r.PostFormValue("email"), 200)
	topic := trimCap(r.PostFormValue("topic"), 40)
	msg := trimCap(r.PostFormValue("message"), 5000)
	if email == "" || msg == "" {
		http.Error(w, "email and message are required", http.StatusBadRequest)
		return
	}
	if topic == "" {
		topic = "General"
	}

	_ = s.contact.add(contactMsg{
		Time: time.Now().UTC().Format(time.RFC3339), IP: ip,
		Name: name, Email: email, Topic: topic, Message: msg,
	})
	s.audit.log("contact_submitted", "", ip, topic)
	http.Redirect(w, r, "/contact?sent=1", http.StatusSeeOther)
}

func trimCap(s string, max int) string {
	s = strings.TrimSpace(s)
	if len(s) > max {
		s = s[:max]
	}
	return s
}
