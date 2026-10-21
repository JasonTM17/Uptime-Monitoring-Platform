//go:build integration

package auth_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/auth"
)

// TestSessionRepository exercises the real DB path: hash-only storage,
// user-lock creation, lookup validation, revoke replay rejection.
func TestSessionRepository(t *testing.T) {
	repo := auth.NewRepository(testPool(t), 10*time.Second)
	svc := auth.NewService(repo, nil, intCfg(), 10)
	ctx := context.Background()

	u, err := repo.CreateUser(ctx, unqEmail("sess"), "$argon2id$fixture", "sess", 10)
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}

	var token string
	var sessID [16]byte

	t.Run("created session stores only the SHA-256 hash", func(t *testing.T) {
		iss, err := svc.CreateSession(ctx, u.ID, "test-device")
		if err != nil {
			t.Fatalf("create session: %v", err)
		}
		token = iss.Token
		sessID = iss.Session.ID
		conn := connect(t)
		defer conn.Close(ctx)
		var stored []byte
		if err := conn.QueryRow(ctx,
			"SELECT token_hash FROM uptime.sessions WHERE id=$1", sessID).Scan(&stored); err != nil {
			t.Fatalf("read hash: %v", err)
		}
		raw, _ := base64.RawURLEncoding.DecodeString(token)
		want := sha256.Sum256(raw)
		if string(stored) != string(want[:]) {
			t.Fatal("stored token_hash is not sha256(plaintext)")
		}
		if string(stored) == token {
			t.Fatal("plaintext token persisted")
		}
		if iss.Session.SecurityVersion != u.SecurityVersion {
			t.Fatalf("security_version %d, want %d", iss.Session.SecurityVersion, u.SecurityVersion)
		}
	})

	t.Run("lookup validates and slides idle", func(t *testing.T) {
		s, err := svc.LookupSession(ctx, token)
		if err != nil || s.UserID != u.ID {
			t.Fatalf("lookup: %v %+v", err, s)
		}
	})

	t.Run("revoked token replays as invalid", func(t *testing.T) {
		if err := svc.RevokeSession(ctx, sessID); err != nil {
			t.Fatalf("revoke: %v", err)
		}
		if _, err := svc.LookupSession(ctx, token); !errors.Is(err, auth.ErrInvalidSession) {
			t.Fatalf("expected ErrInvalidSession, got %v", err)
		}
		// Second revoke is a typed no-row, not a 500.
		if err := svc.RevokeSession(ctx, sessID); !errors.Is(err, auth.ErrNotFound) {
			t.Fatalf("expected ErrNotFound, got %v", err)
		}
	})

	t.Run("create under user lock for disabled user fails", func(t *testing.T) {
		conn := connect(t)
		defer conn.Close(ctx)
		if _, err := conn.Exec(ctx,
			"UPDATE uptime.users SET status='DISABLED',disabled_at=now() WHERE id=$1", u.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := svc.CreateSession(ctx, u.ID, ""); !errors.Is(err, auth.ErrInvalidSession) {
			t.Fatalf("expected ErrInvalidSession, got %v", err)
		}
	})

	t.Run("revoke vs lookup is race-safe", func(t *testing.T) {
		u2, err := repo.CreateUser(ctx, unqEmail("race2"), "$h", "", 10)
		if err != nil {
			t.Fatal(err)
		}
		iss, err := svc.CreateSession(ctx, u2.ID, "")
		if err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		for i := 0; i < 8; i++ {
			wg.Add(2)
			go func() { defer wg.Done(); _, _ = svc.LookupSession(ctx, iss.Token) }()
			go func() { defer wg.Done(); _ = svc.RevokeSession(ctx, iss.Session.ID) }()
		}
		wg.Wait()
	})
}
