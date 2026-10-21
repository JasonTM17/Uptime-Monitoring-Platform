//go:build integration

package auth_test

import (
	"context"
	"errors"
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
