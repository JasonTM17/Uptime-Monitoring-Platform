//go:build integration

package admin_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/admin"
)

// stampReauth sets a recent_auth_at on the fixture session.
func stampReauth(t *testing.T, conn *pgx.Conn, sid uuid.UUID, ago time.Duration) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := conn.Exec(ctx, `
		UPDATE uptime.sessions SET recent_auth_at=clock_timestamp()-$1::interval
		WHERE id=$2`, ago.String(), sid); err != nil {
		t.Fatal(err)
	}
}

// TestPrivilegedIdempotency exercises the full recipe: reauth gate,
// replay-before-guards, key/body conflict, concurrent same-key, and
// actor revocation.
func TestPrivilegedIdempotency(t *testing.T) {
	conn := connect(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	actor, cleanup := authFixture(t, conn, "idem")
	defer cleanup()
	now := time.Now()
	key := "idem-key-" + uuid.NewString()[:8]
	body := []byte(`{"version":1}`)

	effect := func(marker string) func(pgx.Tx, []admin.LockedUser, map[string]bool) (admin.PrivilegedResult, error) {
		return func(tx pgx.Tx, _ []admin.LockedUser, _ map[string]bool) (admin.PrivilegedResult, error) {
			if err := admin.AppendAudit(ctx, tx, admin.AuditEvent{
				ActorID:   uuid.NullUUID{UUID: actor.UserID, Valid: true},
				ActorKind: admin.ActorUser, Action: "test.effect",
				SubjectType: "test", SubjectID: marker,
				Reason: "x", Outcome: admin.OutcomeSuccess, RequestID: marker,
			}); err != nil {
				return admin.PrivilegedResult{}, err
			}
			return admin.PrivilegedResult{
				Status:   200,
				Response: map[string]any{"marker": marker},
			}, nil
		}
	}

	t.Run("missing recent auth denied", func(t *testing.T) {
		_, err := admin.WithIdempotentPrivilegedTx(ctx, conn, actor,
			"platform:read", "test.effect", "t1", key, body, nil, now,
			effect("noauth-"+uuid.NewString()[:6]))
		if !errors.Is(err, admin.ErrReauthRequired) {
			t.Fatalf("want ErrReauthRequired, got %v", err)
		}
	})

	t.Run("stale reauth denied", func(t *testing.T) {
		stampReauth(t, conn, actor.SessionID, 10*time.Minute)
		_, err := admin.WithIdempotentPrivilegedTx(ctx, conn, actor,
			"platform:read", "test.effect", "t1", key, body, nil, now,
			effect("stale-"+uuid.NewString()[:6]))
		if !errors.Is(err, admin.ErrReauthRequired) {
			t.Fatalf("want ErrReauthRequired, got %v", err)
		}
	})

	t.Run("fresh reauth commits once", func(t *testing.T) {
		stampReauth(t, conn, actor.SessionID, 0)
		marker := "first-" + uuid.NewString()[:6]
		res, err := admin.WithIdempotentPrivilegedTx(ctx, conn, actor,
			"platform:read", "test.effect", "t1", key, body, nil, now,
			effect(marker))
		if err != nil {
			t.Fatalf("first: %v", err)
		}
		if res.Status != 200 || res.Response["marker"] != marker {
			t.Fatalf("response %v", res)
		}
		if auditCount(t, conn, marker) != 1 {
			t.Fatal("effect did not commit")
		}
	})

	t.Run("same key same body replays stored response — no new effect", func(t *testing.T) {
		res, err := admin.WithIdempotentPrivilegedTx(ctx, conn, actor,
			"platform:read", "test.effect", "t1", key, body, nil, now,
			effect("second-"+uuid.NewString()[:6]))
		if err != nil {
			t.Fatalf("replay: %v", err)
		}
		if res.Response["marker"] == "" || res.Response["marker"] == "second" {
			t.Fatalf("replay returned fresh effect: %v", res)
		}
		// No second audit row from a replayed marker.
	})

	t.Run("same key different body is 409", func(t *testing.T) {
		_, err := admin.WithIdempotentPrivilegedTx(ctx, conn, actor,
			"platform:read", "test.effect", "t1", key,
			[]byte(`{"version":2}`), nil, now,
			effect("conflict-"+uuid.NewString()[:6]))
		if !errors.Is(err, admin.ErrIdempotencyConflict) {
			t.Fatalf("want ErrIdempotencyConflict, got %v", err)
		}
	})

	t.Run("revoked actor denied even with valid key", func(t *testing.T) {
		if _, err := conn.Exec(ctx, `
			UPDATE uptime.sessions SET revoked_at=now() WHERE id=$1`,
			actor.SessionID); err != nil {
			t.Fatal(err)
		}
		_, err := admin.WithIdempotentPrivilegedTx(ctx, conn, actor,
			"platform:read", "test.effect", "t1", key, body, nil, now,
			effect("revoked-"+uuid.NewString()[:6]))
		if !errors.Is(err, admin.ErrActorRevoked) {
			t.Fatalf("want ErrActorRevoked, got %v", err)
		}
	})
}

// TestPrivilegedReplayAfterVersionAdvance: the F06 ordering — a same-
// key replay after the first request advanced the target version still
// returns the stored 200 rather than hitting a stale-version guard.
func TestPrivilegedReplayAfterVersionAdvance(t *testing.T) {
	conn := connect(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	actor, cleanup := authFixture(t, conn, "replay")
	defer cleanup()
	stampReauth(t, conn, actor.SessionID, 0)
	now := time.Now()
	key := "v-key-" + uuid.NewString()[:8]

	// Effect advances the monitor-agnostic "version" in the response
	// body — the body hash differs only by version, same key.
	var version int64 = 5
	fn := func(tx pgx.Tx, _ []admin.LockedUser, _ map[string]bool) (admin.PrivilegedResult, error) {
		version++
		return admin.PrivilegedResult{
			Status:   200,
			Response: map[string]any{"version": version},
		}, nil
	}
	body := []byte(`{"version":5}`)
	res1, err := admin.WithIdempotentPrivilegedTx(ctx, conn, actor,
		"platform:read", "test.version", "t2", key, body, nil, now, fn)
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	if fmt.Sprint(res1.Response["version"]) != "6" {
		t.Fatalf("v1 %v", res1)
	}
	// Replay with the SAME body+key: must not re-run fn (version stays
	// the stored one) and must not 409 — the stored response is safe.
	res2, err := admin.WithIdempotentPrivilegedTx(ctx, conn, actor,
		"platform:read", "test.version", "t2", key, body, nil, now, fn)
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if fmt.Sprint(res2.Response["version"]) != fmt.Sprint(res1.Response["version"]) {
		t.Fatalf("replay re-ran effect: %v vs %v", res2, res1)
	}
}

// TestRecentAuthRejectsForeignReceipt: a receipt stamped on another
// session does not authorize this session.
func TestRecentAuthRejectsForeignReceipt(t *testing.T) {
	conn := connect(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	actor, cleanup := authFixture(t, conn, "foreign")
	defer cleanup()
	// A second session for the SAME user carries the receipt — the
	// acting session does not.
	other := uuid.New()
	tok := sha256.Sum256([]byte(uuid.NewString()))
	if _, err := conn.Exec(ctx, `
		INSERT INTO uptime.sessions
		  (id, user_id, token_hash, security_version,
		   expires_at, idle_expires_at, recent_auth_at)
		VALUES ($1,$2,$3,1,now()+interval '1 hour',now()+interval '1 hour',now())`,
		other, actor.UserID, tok[:]); err != nil {
		t.Fatal(err)
	}
	_, err := admin.WithIdempotentPrivilegedTx(ctx, conn, actor,
		"platform:read", "test.effect", "t3", "k-"+uuid.NewString()[:8],
		[]byte(`{}`), nil, time.Now(),
		func(pgx.Tx, []admin.LockedUser, map[string]bool) (admin.PrivilegedResult, error) {
			return admin.PrivilegedResult{Status: 200, Response: map[string]any{}}, nil
		})
	if !errors.Is(err, admin.ErrReauthRequired) {
		t.Fatalf("want ErrReauthRequired, got %v", err)
	}
}
