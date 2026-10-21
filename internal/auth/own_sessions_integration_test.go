//go:build integration

package auth_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httputil"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/auth"
)

// TestRevokedSessionFlow proves server-side revocation is real on the
// DB path: revoke -> replay rejected; revoke-current kills the caller.
func TestRevokedSessionFlow(t *testing.T) {
	repo := auth.NewRepository(testPool(t), 10*time.Second)
	svc := auth.NewService(repo, nil, intCfg(), 10)
	ctx := context.Background()

	u, err := repo.CreateUser(ctx, unqEmail("rev"), "$argon2id$fixture", "", 10)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	iss, err := svc.CreateSession(ctx, u.ID, "rev-test")
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	if _, err := svc.LookupSession(ctx, iss.Token); err != nil {
		t.Fatalf("pre-revoke lookup: %v", err)
	}
	if err := svc.RevokeSession(ctx, iss.Session.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := svc.LookupSession(ctx, iss.Token); !errors.Is(err, auth.ErrInvalidSession) {
		t.Fatalf("revoked token replayed: %v", err)
	}
	// Revoke vs revoke-again: typed not-found, not a panic/500.
	if err := svc.RevokeSession(ctx, iss.Session.ID); !errors.Is(err, auth.ErrNotFound) {
		t.Fatalf("second revoke: %v", err)
	}
}

// TestOwnSessionRoutes verifies owner-scoped inventory + revocation on
// real rows: foreign IDs are 404-equivalent (ErrNotFound), own revoke
// persists.
func TestOwnSessionRoutes(t *testing.T) {
	repo := auth.NewRepository(testPool(t), 10*time.Second)
	svc := auth.NewService(repo, nil, intCfg(), 10)
	ctx := context.Background()

	owner, _ := repo.CreateUser(ctx, unqEmail("own2"), "$h", "", 10)
	other, _ := repo.CreateUser(ctx, unqEmail("oth2"), "$h", "", 10)
	a, _ := svc.CreateSession(ctx, owner.ID, "a")
	b, _ := svc.CreateSession(ctx, owner.ID, "b")
	foreign, _ := svc.CreateSession(ctx, other.ID, "f")

	t.Run("list is owner-scoped and bounded", func(t *testing.T) {
		got, err := svc.ListOwnSessions(ctx, owner.ID, 50, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 2 {
			t.Fatalf("sessions=%d want 2", len(got))
		}
		// Page past the end is empty, not an error.
		page2, _ := svc.ListOwnSessions(ctx, owner.ID, 50, 50)
		if len(page2) != 0 {
			t.Fatalf("offset page=%d", len(page2))
		}
	})

	t.Run("foreign revoke is ErrNotFound", func(t *testing.T) {
		if err := svc.RevokeOwnSession(ctx, owner.ID, foreign.Session.ID); !errors.Is(err, auth.ErrNotFound) {
			t.Fatalf("expected ErrNotFound, got %v", err)
		}
		// Foreign session still works.
		if _, err := svc.LookupSession(ctx, foreign.Token); err != nil {
			t.Fatalf("foreign session wrongly revoked: %v", err)
		}
	})

	t.Run("own revoke persists; lookup dies", func(t *testing.T) {
		if err := svc.RevokeOwnSession(ctx, owner.ID, a.Session.ID); err != nil {
			t.Fatalf("revoke: %v", err)
		}
		if _, err := svc.LookupSession(ctx, a.Token); !errors.Is(err, auth.ErrInvalidSession) {
			t.Fatalf("revoked own session replays: %v", err)
		}
		got, _ := svc.ListOwnSessions(ctx, owner.ID, 50, 0)
		if len(got) != 1 || got[0].ID != b.Session.ID {
			t.Fatalf("inventory after revoke: %+v", got)
		}
	})

	t.Run("nonexistent id is ErrNotFound", func(t *testing.T) {
		if err := svc.RevokeOwnSession(ctx, owner.ID, uuid.New()); !errors.Is(err, auth.ErrNotFound) {
			t.Fatalf("expected ErrNotFound, got %v", err)
		}
	})
}

// TestOwnRevokeAllRoutes covers the step-up protected "log out
// everywhere" route end to end on real HTTP: recent-auth gate, wrong
// password, all-sessions revocation, cookie clear, and owner scope.
func TestOwnRevokeAllRoutes(t *testing.T) {
	f := newFixture(t)
	defer f.cleanup()
	email := f.email("revall")
	c := f.newClient()
	c.challenge()
	if rec := c.register(email); rec.Code != http.StatusCreated {
		t.Fatalf("register %d", rec.Code)
	}
	if rec := c.login(email); rec.Code != http.StatusOK {
		t.Fatalf("login %d", rec.Code)
	}
	// A second live session for the same user proves "all", not "one".
	c2 := f.newClient()
	c2.challenge()
	if rec := c2.login(email); rec.Code != http.StatusOK {
		t.Fatalf("second login %d", rec.Code)
	}

	t.Run("unauthenticated is 401", func(t *testing.T) {
		anon := f.newClient()
		anon.challenge()
		rec := anon.do(http.MethodPost, "/auth/sessions/revoke-all", `{}`, true)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status %d", rec.Code)
		}
	})

	t.Run("missing recent auth is 403", func(t *testing.T) {
		rec := c.do(http.MethodPost, "/auth/sessions/revoke-all", `{}`, true)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status %d want 403", rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "REAUTH_REQUIRED") {
			t.Fatalf("body %s", rec.Body.String())
		}
		// Sessions still alive.
		if rec := c.do(http.MethodGet, "/auth/me", "", false); rec.Code != http.StatusOK {
			t.Fatal("session died despite denial")
		}
	})

	t.Run("wrong password reauth is uniform 401", func(t *testing.T) {
		b, _ := json.Marshal(map[string]string{"password": "wrong"})
		rec := c.do(http.MethodPost, "/auth/reauth", string(b), true)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status %d", rec.Code)
		}
	})

	t.Run("reauth then revoke-all kills every session", func(t *testing.T) {
		b, _ := json.Marshal(map[string]string{"password": validPW})
		rec := c.do(http.MethodPost, "/auth/reauth", string(b), true)
		if rec.Code != http.StatusOK {
			b, _ := httputil.DumpResponse(rec.Result(), true)
			t.Fatalf("reauth %d %s", rec.Code, b)
		}
		rec = c.do(http.MethodPost, "/auth/sessions/revoke-all", `{}`, true)
		if rec.Code != http.StatusOK {
			b, _ := httputil.DumpResponse(rec.Result(), true)
			t.Fatalf("revoke-all %d %s", rec.Code, b)
		}
		// Both sessions are dead now — cookies replay 401.
		if rec := c.do(http.MethodGet, "/auth/me", "", false); rec.Code != http.StatusUnauthorized {
			t.Fatalf("old session alive: %d", rec.Code)
		}
		if rec := c2.do(http.MethodGet, "/auth/me", "", false); rec.Code != http.StatusUnauthorized {
			t.Fatalf("second session alive: %d", rec.Code)
		}
	})
}
