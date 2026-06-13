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
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	token := base64.RawURLEncoding.EncodeToString(b[:])
	s.mu.Lock()
	s.m[token] = &session{username: username, dk: dk, expires: time.Now().Add(s.ttl)}
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

func clearSessionCookie(w http.ResponseWriter, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: "", Path: "/",
		HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode,
		MaxAge: -1,
	})
}
