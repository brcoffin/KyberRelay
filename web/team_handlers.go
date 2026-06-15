package main

import (
	"net/http"
	"strconv"
)

// Team management endpoints (session-authenticated). A user belongs to at most
// one team; any member is resolved to the Team plan by server.planForUser.

// currentTeam returns the caller's team (and user record), or errNoTeam.
func (s *server) currentTeam(username string) (*Team, *User, error) {
	u, err := s.accounts.load(username)
	if err != nil {
		return nil, nil, err
	}
	if u.TeamID == "" {
		return nil, u, errNoTeam
	}
	t, err := s.teams.load(u.TeamID)
	return t, u, err
}

type teamView struct {
	ID      string   `json:"id"`
	Owner   string   `json:"owner"`
	IsOwner bool     `json:"is_owner"`
	Members []string `json:"members"`
	Seats   int      `json:"seats"`
	Used    int      `json:"used"`
}

func view(t *Team, me string) teamView {
	return teamView{ID: t.ID, Owner: t.Owner, IsOwner: t.Owner == me, Members: t.Members, Seats: t.Seats, Used: len(t.Members)}
}

// GET /api/team — the caller's team, or {"team":null}.
func (s *server) handleTeamGet(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.requireSession(w, r)
	if !ok {
		return
	}
	t, _, err := s.currentTeam(sess.username)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"team": nil})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"team": view(t, sess.username)})
}

// POST /api/team/create — create a team owned by the caller (seats optional).
func (s *server) handleTeamCreate(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.requireSession(w, r)
	if !ok {
		return
	}
	if _, _, err := s.currentTeam(sess.username); err == nil {
		jsonError(w, http.StatusBadRequest, "you're already on a team")
		return
	}
	seats := teamDefaultSeats
	if n, err := strconv.Atoi(r.FormValue("seats")); err == nil && n > 0 {
		seats = n
	}
	t, err := s.teams.create(sess.username, seats)
	if err == errBadSeatCount {
		jsonError(w, http.StatusBadRequest, "seats must be between 2 and 50")
		return
	}
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "could not create team")
		return
	}
	// Link the owner; undo the team if the user is somehow already on one.
	if err := s.accounts.update(sess.username, func(u *User) error {
		if u.TeamID != "" {
			return errAlreadyTeam
		}
		u.TeamID = t.ID
		return nil
	}); err != nil {
		s.teams.delete(t.ID)
		jsonError(w, http.StatusBadRequest, "you're already on a team")
		return
	}
	s.audit.log("team_created", sess.username, clientIP(r), t.ID)
	writeJSON(w, http.StatusOK, map[string]any{"team": view(t, sess.username)})
}

// POST /api/team/invite — owner adds an existing user (form: username).
func (s *server) handleTeamInvite(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.requireSession(w, r)
	if !ok {
		return
	}
	t, _, err := s.currentTeam(sess.username)
	if err != nil {
		jsonError(w, http.StatusBadRequest, "you're not on a team")
		return
	}
	if t.Owner != sess.username {
		jsonError(w, http.StatusForbidden, "only the owner can invite")
		return
	}
	target := r.FormValue("username")
	if _, err := s.accounts.load(target); err != nil {
		jsonError(w, http.StatusNotFound, "no such user")
		return
	}

	// Reserve the seat by adding to the team (serialized in the team store).
	addErr := s.teams.update(t.ID, func(t *Team) error {
		if t.hasMember(target) {
			return nil // idempotent
		}
		if len(t.Members) >= t.Seats {
			return errSeatsFull
		}
		t.Members = append(t.Members, target)
		return nil
	})
	switch addErr {
	case nil:
	case errSeatsFull:
		jsonError(w, http.StatusBadRequest, "no seats available — add seats first")
		return
	default:
		jsonError(w, http.StatusInternalServerError, "could not update team")
		return
	}

	// Link the user; if they already belong elsewhere, roll the seat back.
	if err := s.accounts.update(target, func(u *User) error {
		if u.TeamID != "" && u.TeamID != t.ID {
			return errAlreadyTeam
		}
		u.TeamID = t.ID
		return nil
	}); err != nil {
		_ = s.teams.update(t.ID, func(t *Team) error { t.removeMember(target); return nil })
		jsonError(w, http.StatusBadRequest, "that user is already on another team")
		return
	}
	s.audit.log("team_member_added", sess.username, clientIP(r), target)
	if t, _, err := s.currentTeam(sess.username); err == nil {
		writeJSON(w, http.StatusOK, map[string]any{"team": view(t, sess.username)})
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// POST /api/team/remove — owner removes a member (form: username).
func (s *server) handleTeamRemove(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.requireSession(w, r)
	if !ok {
		return
	}
	t, _, err := s.currentTeam(sess.username)
	if err != nil {
		jsonError(w, http.StatusBadRequest, "you're not on a team")
		return
	}
	if t.Owner != sess.username {
		jsonError(w, http.StatusForbidden, "only the owner can remove members")
		return
	}
	target := r.FormValue("username")
	if target == t.Owner {
		jsonError(w, http.StatusBadRequest, "the owner can't be removed")
		return
	}
	if !t.hasMember(target) {
		jsonError(w, http.StatusBadRequest, "that user isn't on this team")
		return
	}
	_ = s.teams.update(t.ID, func(t *Team) error { t.removeMember(target); return nil })
	_ = s.accounts.update(target, func(u *User) error {
		if u.TeamID == t.ID {
			u.TeamID = ""
		}
		return nil
	})
	s.audit.log("team_member_removed", sess.username, clientIP(r), target)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// POST /api/team/leave — a non-owner member leaves their team.
func (s *server) handleTeamLeave(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.requireSession(w, r)
	if !ok {
		return
	}
	t, _, err := s.currentTeam(sess.username)
	if err != nil {
		jsonError(w, http.StatusBadRequest, "you're not on a team")
		return
	}
	if t.Owner == sess.username {
		jsonError(w, http.StatusBadRequest, "the owner can't leave — delete or transfer the team instead")
		return
	}
	_ = s.teams.update(t.ID, func(t *Team) error { t.removeMember(sess.username); return nil })
	_ = s.accounts.update(sess.username, func(u *User) error {
		if u.TeamID == t.ID {
			u.TeamID = ""
		}
		return nil
	})
	s.audit.log("team_left", sess.username, clientIP(r), t.ID)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
