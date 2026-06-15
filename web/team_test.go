package main

import (
	"net/http"
	"net/url"
	"testing"
)

func TestTeamSeatBounds(t *testing.T) {
	store, err := newTeamStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.create("alice", 1); err != errBadSeatCount {
		t.Errorf("seats=1: err=%v, want errBadSeatCount", err)
	}
	if _, err := store.create("alice", 99); err != errBadSeatCount {
		t.Errorf("seats=99: err=%v, want errBadSeatCount", err)
	}
	if _, err := store.create("alice", 5); err != nil {
		t.Errorf("seats=5: unexpected err %v", err)
	}
}

func TestIntegration_TeamLifecycleAndPlan(t *testing.T) {
	s, ts := newTestServer(t)
	owner := newClient(t, ts.URL)
	ocsrf := owner.registerLogin(ts.URL, "owner", goodPass)
	member := newClient(t, ts.URL)
	member.registerLogin(ts.URL, "member", goodPass)
	outsider := newClient(t, ts.URL)
	ocsrf2 := outsider.registerLogin(ts.URL, "outsider", goodPass)

	// Before any team: free plan.
	if p := s.planForUser("owner"); p.Name != "free" {
		t.Fatalf("owner pre-team plan = %q, want free", p.Name)
	}

	// Create a 2-seat team → owner becomes Team plan.
	mustStatus(t, owner.form(http.MethodPost, "/api/team/create", ts.URL, ocsrf, url.Values{"seats": {"2"}}), 200, "create team")
	if p := s.planForUser("owner"); p.Name != "team" {
		t.Fatalf("owner plan after create = %q, want team", p.Name)
	}

	// Invite member → member becomes Team plan.
	mustStatus(t, owner.form(http.MethodPost, "/api/team/invite", ts.URL, ocsrf, url.Values{"username": {"member"}}), 200, "invite member")
	if p := s.planForUser("member"); p.Name != "team" {
		t.Fatalf("member plan after invite = %q, want team", p.Name)
	}

	// Third member exceeds 2 seats → 400.
	mustStatus(t, owner.form(http.MethodPost, "/api/team/invite", ts.URL, ocsrf, url.Values{"username": {"outsider"}}), 400, "seats full")

	// Non-owner can't invite.
	mcsrf := member.appCSRF()
	mustStatus(t, member.form(http.MethodPost, "/api/team/invite", ts.URL, mcsrf, url.Values{"username": {"outsider"}}), 403, "non-owner invite")

	// Can't poach a user already on another team: outsider makes their own team,
	// then owner's invite must fail.
	mustStatus(t, outsider.form(http.MethodPost, "/api/team/create", ts.URL, ocsrf2, url.Values{"seats": {"2"}}), 200, "outsider creates team")
	// free a seat first so the failure is the membership clash, not seats.
	mustStatus(t, owner.form(http.MethodPost, "/api/team/remove", ts.URL, ocsrf, url.Values{"username": {"member"}}), 200, "remove member")
	mustStatus(t, owner.form(http.MethodPost, "/api/team/invite", ts.URL, ocsrf, url.Values{"username": {"outsider"}}), 400, "poach already-teamed user")

	// Removed member is back to free.
	if p := s.planForUser("member"); p.Name != "free" {
		t.Fatalf("member plan after removal = %q, want free", p.Name)
	}

	// Owner can't leave their own team.
	mustStatus(t, owner.form(http.MethodPost, "/api/team/leave", ts.URL, ocsrf, nil), 400, "owner leave blocked")
}
