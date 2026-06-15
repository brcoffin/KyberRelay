package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Teams: a lightweight org scaffold. A team has one owner and a set of member
// usernames (owner included), bounded by a seat count. Any member of an existing
// team is resolved to the Team plan (see server.planForUser). Records are
// per-team JSON files, mutated under a single store lock.
//
// TODO(billing): seats are not yet wired to Stripe. createTeam grants the team
// immediately; a future change should drive seat count + status from a
// quantity-based Stripe subscription (teamPriceID) via the webhook.

const (
	teamMinSeats     = 2
	teamMaxSeats     = 50
	teamDefaultSeats = 5
)

var (
	errNoTeam       = errors.New("no such team")
	errNotOwner     = errors.New("only the team owner can do that")
	errSeatsFull    = errors.New("no seats available on this team")
	errAlreadyTeam  = errors.New("user is already on a team")
	errNotMember    = errors.New("user is not a member of this team")
	errOwnerLeave   = errors.New("the owner cannot leave their own team")
	errBadSeatCount = errors.New("seat count out of range")
)

type Team struct {
	ID               string   `json:"id"`
	Owner            string   `json:"owner"`
	Members          []string `json:"members"` // includes the owner
	Seats            int      `json:"seats"`
	StripeCustomerID string   `json:"stripe_customer_id,omitempty"`
	StripeSubID      string   `json:"stripe_sub_id,omitempty"`
	Created          int64    `json:"created"`
}

func (t *Team) hasMember(username string) bool {
	for _, m := range t.Members {
		if m == username {
			return true
		}
	}
	return false
}

func (t *Team) removeMember(username string) {
	out := t.Members[:0]
	for _, m := range t.Members {
		if m != username {
			out = append(out, m)
		}
	}
	t.Members = out
}

type teamStore struct {
	dir string
	mu  sync.Mutex
}

func newTeamStore(dir string) (*teamStore, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &teamStore{dir: dir}, nil
}

func (s *teamStore) path(id string) string {
	return filepath.Join(s.dir, filepath.Base(id)+".json")
}

func (s *teamStore) load(id string) (*Team, error) {
	if id == "" {
		return nil, errNoTeam
	}
	b, err := os.ReadFile(s.path(id))
	if err != nil {
		return nil, errNoTeam
	}
	var t Team
	if err := json.Unmarshal(b, &t); err != nil {
		return nil, err
	}
	return &t, nil
}

func (s *teamStore) save(t *Team) error {
	b, err := json.Marshal(t)
	if err != nil {
		return err
	}
	tmp := s.path(t.ID) + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path(t.ID))
}

// create mints a new team owned by owner with the given seat count.
func (s *teamStore) create(owner string, seats int) (*Team, error) {
	if seats < teamMinSeats || seats > teamMaxSeats {
		return nil, errBadSeatCount
	}
	id, err := newID()
	if err != nil {
		return nil, err
	}
	t := &Team{ID: id, Owner: owner, Members: []string{owner}, Seats: seats, Created: time.Now().Unix()}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.save(t); err != nil {
		return nil, err
	}
	return t, nil
}

// update runs fn against the team under the store lock and persists the result.
func (s *teamStore) update(id string, fn func(*Team) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, err := s.load(id)
	if err != nil {
		return err
	}
	if err := fn(t); err != nil {
		return err
	}
	return s.save(t)
}

func (s *teamStore) delete(id string) {
	_ = os.Remove(s.path(id))
}
