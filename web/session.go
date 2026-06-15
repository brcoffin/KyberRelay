package main

import (
	"crypto/mlkem"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"sync"
	"time"
)

const sessionCookie = "kyz_session"

// A session holds the logged-in user and their unwrapped decapsulation key,
// kept in memory only for the session's lifetime. Sessions are not persisted —
// a server restart logs everyone out (they simply log in again).
type session struct {
	username string
	dk       *mlkem.DecapsulationKey768
	csrf     string // per-session CSRF token (synchronizer pattern)
	expires  time.Time
}

type sessionStore struct {
	mu  sync.Mutex
	m   map[string]*session
	ttl time.Duration
}

func newSessionStore(ttl time.Duration) *sessionStore {
	return &sessionStore{m: make(map[string]*session), ttl: ttl}
}

func (s *sessionStore) create(username string, dk *mlkem.DecapsulationKey768) (string, error) {
	var b, c [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	if _, err := rand.Read(c[:]); err != nil {
		return "", err
	}
	token := base64.RawURLEncoding.EncodeToString(b[:])
	csrf := base64.RawURLEncoding.EncodeToString(c[:])
	s.mu.Lock()
	s.m[token] = &session{username: username, dk: dk, csrf: csrf, expires: time.Now().Add(s.ttl)}
	s.mu.Unlock()
	return token, nil
}

func (s *sessionStore) get(token string) (*session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.m[token]
	if !ok {
		return nil, false
	}
	if time.Now().After(sess.expires) {
		delete(s.m, token)
		return nil, false
	}
	return sess, true
}

func (s *sessionStore) destroy(token string) {
	s.mu.Lock()
	delete(s.m, token)
	s.mu.Unlock()
}

// destroyUser invalidates every session belonging to a user (used on password
// change, so a leaked/old session can't outlive the change).
func (s *sessionStore) destroyUser(username string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for tok, sess := range s.m {
		if sess.username == username {
			delete(s.m, tok)
		}
	}
}

// current returns the session for the request, if any.
func (s *sessionStore) current(r *http.Request) (*session, bool) {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return nil, false
	}
	return s.get(c.Value)
}

// setCookie writes the session cookie. secure=true once served over HTTPS.
func setSessionCookie(w http.ResponseWriter, token string, ttl time.Duration, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(ttl),
	})
}

// --- pending login (password verified, awaiting TOTP) ---

type pendingLogin struct {
	username   string
	dk         *mlkem.DecapsulationKey768
	totpSecret []byte
	expires    time.Time
}

type pendingStore struct {
	mu  sync.Mutex
	m   map[string]*pendingLogin
	ttl time.Duration
}

func newPendingStore(ttl time.Duration) *pendingStore {
	return &pendingStore{m: make(map[string]*pendingLogin), ttl: ttl}
}

func (p *pendingStore) create(pl *pendingLogin) (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	token := base64.RawURLEncoding.EncodeToString(b[:])
	pl.expires = time.Now().Add(p.ttl)
	p.mu.Lock()
	p.m[token] = pl
	p.mu.Unlock()
	return token, nil
}

func (p *pendingStore) get(token string) (*pendingLogin, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	pl, ok := p.m[token]
	if !ok {
		return nil, false
	}
	if time.Now().After(pl.expires) {
		delete(p.m, token)
		return nil, false
	}
	return pl, true
}

func (p *pendingStore) del(token string) {
	p.mu.Lock()
	delete(p.m, token)
	p.mu.Unlock()
}

func clearSessionCookie(w http.ResponseWriter, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: "", Path: "/",
		HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode,
		MaxAge: -1,
	})
}
