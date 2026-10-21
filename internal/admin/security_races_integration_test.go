//go:build integration

package admin_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/admin"
)

// C64 — the privilege-revocation race matrix. These are database
// concurrency tests (deterministic channel barriers between two real
// connections), not Go data-race hunts: the claim under attack is the
// linearization order inside the privileged recipe —
//   anchor → user locks (actor epoch) → session lock → grant FOR
//   SHARE + permission reload → recent-auth → idempotency replay →
//   business guards → mutation → audit → commit.
// Every test names the recipe step it stresses. Existing coverage
// mapped in docs/testing/admin-security.md:
//   TestRevokeWriteBarrier          — session revoke vs locked write
//   TestConcurrentSuperAdminRemoval — two-admin write skew, anchor
//   TestBootstrapRace               — recovery anchor serialization
//   TestAdminQuotaRace              — quota write vs write

// TestStaleEpochWriteDenied: the actor snapshot a request carries is
// stamped at issue time. If the user's security_version advanced
// before the tx locks the row — role removal, suspend, session
// revoke-all — the stale snapshot must be denied at the epoch check,
// never evaluated against a cached permission set.
func TestStaleEpochWriteDenied(t *testing.T) {
	conn := connect(t)
	actor, cleanup := authFixture(t, conn, "race-epoch")
	defer cleanup()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Any epoch-bumping mutation committed before the write's lock —
	// suspend uses the same column; the raw bump simulates it.
	if _, err := conn.Exec(ctx, `
		UPDATE uptime.users SET security_version=security_version+1
		WHERE id=$1`, actor.UserID); err != nil {
		t.Fatal(err)
	}
	req := "race-epoch-" + uuid.NewString()[:8]
	err := admin.WithPrivilegedTx(ctx, conn, actor, "platform:read",
		time.Now(), markerFn(ctx, actor, req))
	if !errors.Is(err, admin.ErrActorRevoked) {
		t.Fatalf("want ErrActorRevoked, got %v", err)
	}
	if auditCount(t, conn, req) != 0 {
		t.Fatal("stale-epoch write committed")
	}
}

// TestPermRevokeOrdering: the adversarial orderings of a grant
// delete — one committed before the write's guards run is ErrForbidden;
// one arriving while the tx holds its FOR SHARE on the grant rows
// serializes AFTER our commit — the write is honestly first, the
// revocation second, and the actor's next write is fenced. Even a
// naive delete (no epoch bump — the bypass path) cannot land mid-tx.
func TestPermRevokeOrdering(t *testing.T) {
	conn := connect(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	t.Run("delete before guards is denied", func(t *testing.T) {
		actor, cleanup := actorWithRole(t, conn, "race-po-a", operatorPreset)
		defer cleanup()
		if _, err := conn.Exec(ctx, `
			DELETE FROM uptime.user_roles WHERE user_id=$1`,
			actor.UserID); err != nil {
			t.Fatal(err)
		}
		req := "race-po-a-" + uuid.NewString()[:8]
		err := admin.WithPrivilegedTx(ctx, conn, actor, "deliveries:read",
			time.Now(), markerFn(ctx, actor, req))
		if !errors.Is(err, admin.ErrForbidden) {
			t.Fatalf("want ErrForbidden, got %v", err)
		}
		if auditCount(t, conn, req) != 0 {
			t.Fatal("write committed against a deleted grant")
		}
	})

	t.Run("delete during locked write serializes after", func(t *testing.T) {
		actor, cleanup := actorWithRole(t, conn, "race-po-b", operatorPreset)
		defer cleanup()
		req := "race-po-b-" + uuid.NewString()[:8]

		inside := make(chan struct{})
		proceed := make(chan struct{})
		var writeErr error
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := pgx.Connect(ctx, testDSN(t))
			if err != nil {
				writeErr = err
				return
			}
			defer c.Close(context.Background())
			writeErr = admin.WithPrivilegedTx(ctx, c, actor, "deliveries:read",
				time.Now(), func(tx pgx.Tx, p map[string]bool) error {
					close(inside)
					<-proceed
					return markerFn(ctx, actor, req)(tx, p)
				})
		}()

		<-inside
		delDone := make(chan error, 1)
		go func() {
			c, err := pgx.Connect(ctx, testDSN(t))
			if err != nil {
				delDone <- err
				return
			}
			defer c.Close(context.Background())
			_, err = c.Exec(ctx, `
				DELETE FROM uptime.user_roles WHERE user_id=$1`,
				actor.UserID)
			delDone <- err
		}()

		// The delete must block on the write's FOR SHARE — if it could
		// commit now, the write would be committing dead authority.
		select {
		case <-delDone:
			t.Fatal("grant delete committed while the write held FOR SHARE")
		case <-time.After(300 * time.Millisecond):
		}
		close(proceed)
		wg.Wait()
		if writeErr != nil {
			t.Fatalf("write: %v", writeErr)
		}
		if err := <-delDone; err != nil {
			t.Fatalf("delete: %v", err)
		}
		if auditCount(t, conn, req) != 1 {
			t.Fatal("the honestly-ordered write lost its audit")
		}
	})
}

// TestSessionRevokeBlocksReplay: a committed idempotent response
// exists — but replay must never bypass the CURRENT actor/session
// check. After the session is revoked, the same actor+key replay must
// hit ErrActorRevoked at the recipe's guard step, not the cached
// response at the replay step. The stored row staying reachable would
// be a revocation bypass.
func TestSessionRevokeBlocksReplay(t *testing.T) {
	conn := connect(t)
	actor, cleanup := actorWithRole(t, conn, "race-repl", operatorPreset)
	defer cleanup()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	stampReauth(t, conn, actor.SessionID, 0)

	key := "race-repl-" + uuid.NewString()[:12]
	body := []byte(`{"probe":1}`)
	target := uuid.NewString()
	first, err := admin.WithIdempotentPrivilegedTx(ctx, conn, actor,
		"deliveries:read", "test.probe", target, key, body, nil,
		time.Now(),
		func(tx pgx.Tx, _ []admin.LockedUser, _ map[string]bool) (admin.PrivilegedResult, error) {
			return admin.PrivilegedResult{
				Status:   200,
				Response: map[string]any{"ok": true},
			}, nil
		})
	if err != nil {
		t.Fatalf("original write: %v", err)
	}
	if first.Status != 200 {
		t.Fatalf("original status %d", first.Status)
	}

	// Revoke the session out from under the actor.
	if _, err := conn.Exec(ctx, `
		UPDATE uptime.sessions SET revoked_at=now() WHERE id=$1`,
		actor.SessionID); err != nil {
		t.Fatal(err)
	}

	_, err = admin.WithIdempotentPrivilegedTx(ctx, conn, actor,
		"deliveries:read", "test.probe", target, key, body, nil,
		time.Now(),
		func(tx pgx.Tx, _ []admin.LockedUser, _ map[string]bool) (admin.PrivilegedResult, error) {
			t.Fatal("replay ran the business fn — guard did not fence")
			return admin.PrivilegedResult{}, nil
		})
	if !errors.Is(err, admin.ErrActorRevoked) {
		t.Fatalf("want ErrActorRevoked, got %v — replay bypassed authz", err)
	}
}

// TestRemovalSerializesBehindWrite: the recipe-conformant removal —
// one that takes the actor's user lock and bumps the epoch, as
// AssignRoles does — cannot interleave with a locked write. It waits
// on the row lock, the write commits honestly, and the removal then
// fences the actor's NEXT write. Ordering is lock-derived, not
// sleep-derived: hold the write, prove the removal blocks, release,
// prove the epoch moved.
func TestRemovalSerializesBehindWrite(t *testing.T) {
	conn := connect(t)
	actor, cleanup := actorWithRole(t, conn, "race-rem", operatorPreset)
	defer cleanup()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	req := "race-rem-" + uuid.NewString()[:8]

	inside := make(chan struct{})
	proceed := make(chan struct{})
	var writeErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		c, err := pgx.Connect(ctx, testDSN(t))
		if err != nil {
			writeErr = err
			return
		}
		defer c.Close(context.Background())
		writeErr = admin.WithPrivilegedTx(ctx, c, actor, "deliveries:read",
			time.Now(), func(tx pgx.Tx, p map[string]bool) error {
				close(inside)
				<-proceed
				return markerFn(ctx, actor, req)(tx, p)
			})
	}()

	<-inside
	// The conformant removal: user-row lock + epoch bump + grant
	// delete in one tx — it MUST block on our held FOR UPDATE.
	remDone := make(chan error, 1)
	go func() {
		c, err := pgx.Connect(ctx, testDSN(t))
		if err != nil {
			remDone <- err
			return
		}
		defer c.Close(context.Background())
		tx, err := c.Begin(ctx)
		if err != nil {
			remDone <- err
			return
		}
		defer tx.Rollback(ctx)
		if _, err := tx.Exec(ctx, `
			UPDATE uptime.users SET security_version=security_version+1
			WHERE id=$1`, actor.UserID); err != nil {
			remDone <- err
			return
		}
		if _, err := tx.Exec(ctx, `
			DELETE FROM uptime.user_roles WHERE user_id=$1`,
			actor.UserID); err != nil {
			remDone <- err
			return
		}
		remDone <- tx.Commit(ctx)
	}()

	// The removal must still be waiting while our write holds the lock.
	select {
	case <-remDone:
		t.Fatal("removal committed while the write held the user lock")
	case <-time.After(300 * time.Millisecond):
	}
	close(proceed)
	wg.Wait()
	if writeErr != nil {
		t.Fatalf("write: %v", writeErr)
	}
	if err := <-remDone; err != nil {
		t.Fatalf("removal: %v", err)
	}
	if auditCount(t, conn, req) != 1 {
		t.Fatal("the honestly-ordered write lost its audit")
	}

	// The removal now fences the actor's next write — the stored
	// snapshot's epoch no longer matches.
	err := admin.WithPrivilegedTx(ctx, conn, actor, "deliveries:read",
		time.Now(), markerFn(ctx, actor, "race-rem-next"))
	if !errors.Is(err, admin.ErrActorRevoked) {
		t.Fatalf("post-removal write: want ErrActorRevoked, got %v", err)
	}
}

// TestReadGuardEpochFence: the read path (AuthorizeRead — no anchor)
// must fence the same revocations. A query issued with a stale
// snapshot after a removal is denied — reads are not a revocation
// side-channel.
func TestReadGuardEpochFence(t *testing.T) {
	conn := connect(t)
	actor, cleanup := actorWithRole(t, conn, "race-read", operatorPreset)
	defer cleanup()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if _, err := conn.Exec(ctx, `
		UPDATE uptime.users SET security_version=security_version+1
		WHERE id=$1`, actor.UserID); err != nil {
		t.Fatal(err)
	}
	_, _, err := admin.ListOutbox(ctx, conn, actor,
		admin.OutboxFilter{Limit: 1}, time.Now())
	if !errors.Is(err, admin.ErrActorRevoked) {
		t.Fatalf("stale read: want ErrActorRevoked, got %v", err)
	}
}
