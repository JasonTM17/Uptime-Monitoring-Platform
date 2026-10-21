//go:build integration

package admin_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/admin"
)

const viewerRoleID = "00000000-0000-4000-8000-000000000001"

// authFixture creates an ACTIVE user holding the VIEWER preset plus
// one live session, and returns the actor snapshot a request would
// carry.
func authFixture(t *testing.T, conn *pgx.Conn, prefix string) (admin.ActorRef, func()) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	uid := uuid.New()
	email := prefix + "-" + uid.String()[:8] + "@example.test"
	if _, err := conn.Exec(ctx, `
		INSERT INTO uptime.users (id, email, password_hash)
		VALUES ($1,$2,'x')`, uid, email); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, `
		INSERT INTO uptime.user_roles (user_id, role_id)
		VALUES ($1,$2)`, uid, viewerRoleID); err != nil {
		t.Fatal(err)
	}
	sid := uuid.New()
	tok := sha256.Sum256([]byte(uuid.NewString()))
	if _, err := conn.Exec(ctx, `
		INSERT INTO uptime.sessions
		  (id, user_id, token_hash, security_version,
		   expires_at, idle_expires_at)
		VALUES ($1,$2,$3,1,now()+interval '1 hour',now()+interval '1 hour')`,
		sid, uid, tok[:]); err != nil {
		t.Fatal(err)
	}
	cleanup := func() {
		c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, _ = conn.Exec(c, `DELETE FROM uptime.sessions WHERE user_id=$1`, uid)
		_, _ = conn.Exec(c, `DELETE FROM uptime.user_roles WHERE user_id=$1`, uid)
		_, _ = conn.Exec(c, `DELETE FROM uptime.users WHERE id=$1`, uid)
	}
	return admin.ActorRef{UserID: uid, SessionID: sid, SecurityVersion: 1}, cleanup
}

// mutateMarker is the smallest observable privileged effect: a row in
// audit_events proves the guarded fn ran.
func markerFn(ctx context.Context, actor admin.ActorRef, reqID string) func(pgx.Tx, map[string]bool) error {
	return func(tx pgx.Tx, _ map[string]bool) error {
		return admin.AppendAudit(ctx, tx, admin.AuditEvent{
			ActorID:   uuid.NullUUID{UUID: actor.UserID, Valid: true},
			ActorKind: admin.ActorUser, Action: "test.privileged",
			SubjectType: "test", SubjectID: reqID,
			Reason: "x", Outcome: admin.OutcomeSuccess, RequestID: reqID,
		})
	}
}

func auditCount(t *testing.T, conn *pgx.Conn, reqID string) int {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var n int
	if err := conn.QueryRow(ctx, `
		SELECT count(*) FROM uptime.audit_events WHERE request_id=$1`,
		reqID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// TestAuthorizationEpoch: epoch and permission state are re-verified
// inside the guarded transaction — the request-start snapshot is
// never authority.
func TestAuthorizationEpoch(t *testing.T) {
	conn := connect(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	actor, cleanup := authFixture(t, conn, "epoch")
	defer cleanup()
	now := time.Now()

	t.Run("valid actor commits", func(t *testing.T) {
		req := "epoch-ok-" + uuid.NewString()[:8]
		err := admin.WithPrivilegedTx(ctx, conn, actor, "platform:read", now,
			markerFn(ctx, actor, req))
		if err != nil {
			t.Fatalf("privileged tx: %v", err)
		}
		if auditCount(t, conn, req) != 1 {
			t.Fatal("mutation did not commit")
		}
	})

	t.Run("role removal denies next write", func(t *testing.T) {
		if _, err := conn.Exec(ctx, `
			DELETE FROM uptime.user_roles WHERE user_id=$1`,
			actor.UserID); err != nil {
			t.Fatal(err)
		}
		req := "epoch-deny-" + uuid.NewString()[:8]
		err := admin.WithPrivilegedTx(ctx, conn, actor, "platform:read", now,
			markerFn(ctx, actor, req))
		if !errors.Is(err, admin.ErrForbidden) {
			t.Fatalf("want ErrForbidden, got %v", err)
		}
		if auditCount(t, conn, req) != 0 {
			t.Fatal("denied mutation committed")
		}
	})

	t.Run("epoch bump kills stamped session", func(t *testing.T) {
		if _, err := conn.Exec(ctx, `
			INSERT INTO uptime.user_roles (user_id, role_id)
			VALUES ($1,$2)`, actor.UserID, viewerRoleID); err != nil {
			t.Fatal(err)
		}
		if _, err := conn.Exec(ctx, `
			UPDATE uptime.users SET security_version=2 WHERE id=$1`,
			actor.UserID); err != nil {
			t.Fatal(err)
		}
		req := "epoch-stale-" + uuid.NewString()[:8]
		err := admin.WithPrivilegedTx(ctx, conn, actor, "platform:read", now,
			markerFn(ctx, actor, req))
		if !errors.Is(err, admin.ErrActorRevoked) {
			t.Fatalf("want ErrActorRevoked, got %v", err)
		}
		if auditCount(t, conn, req) != 0 {
			t.Fatal("stale-epoch mutation committed")
		}
	})
}

// TestRevokeWriteBarrier: the deterministic two-sided barrier.
//
// Direction 1 (deny): revoke commits first, then the privileged tx
// rechecks under lock — ErrActorRevoked, no mutation.
//
// Direction 2 (serialize): the privileged tx holds the user lock
// while a session-revoke lands on another connection — the revoke
// cannot interleave; the write commits, and the revoke completes
// after with a clear order.
func TestRevokeWriteBarrier(t *testing.T) {
	conn := connect(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	t.Run("revoke before recheck denies write", func(t *testing.T) {
		actor, cleanup := authFixture(t, conn, "barrier-a")
		defer cleanup()
		if _, err := conn.Exec(ctx, `
			UPDATE uptime.sessions SET revoked_at=now() WHERE id=$1`,
			actor.SessionID); err != nil {
			t.Fatal(err)
		}
		req := "barrier-deny-" + uuid.NewString()[:8]
		err := admin.WithPrivilegedTx(ctx, conn, actor, "platform:read",
			time.Now(), markerFn(ctx, actor, req))
		if !errors.Is(err, admin.ErrActorRevoked) {
			t.Fatalf("want ErrActorRevoked, got %v", err)
		}
		if auditCount(t, conn, req) != 0 {
			t.Fatal("write committed after revoke")
		}
	})

	t.Run("revoke during locked write serializes after", func(t *testing.T) {
		actor, cleanup := authFixture(t, conn, "barrier-b")
		defer cleanup()
		req := "barrier-ser-" + uuid.NewString()[:8]

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
			writeErr = admin.WithPrivilegedTx(ctx, c, actor, "platform:read",
				time.Now(), func(tx pgx.Tx, p map[string]bool) error {
					close(inside)
					<-proceed // hold the locks while revoke waits
					return markerFn(ctx, actor, req)(tx, p)
				})
		}()

		<-inside
		revokeDone := make(chan error, 1)
		go func() {
			c, err := pgx.Connect(ctx, testDSN(t))
			if err != nil {
				revokeDone <- err
				return
			}
			defer c.Close(context.Background())
			_, err = c.Exec(ctx, `
				UPDATE uptime.sessions SET revoked_at=now() WHERE id=$1`,
				actor.SessionID)
			revokeDone <- err
		}()

		close(proceed)
		wg.Wait()
		if err := <-revokeDone; err != nil {
			t.Fatalf("revoke: %v", err)
		}
		if writeErr != nil {
			t.Fatalf("write: %v", writeErr)
		}
		if auditCount(t, conn, req) != 1 {
			t.Fatal("write did not commit — revoke should serialize after")
		}
	})
}

// TestAuthorizationLockOrder: concurrent privileged mutations over
// overlapping subjects take locks in ascending order and never
// deadlock.
func TestAuthorizationLockOrder(t *testing.T) {
	conn := connect(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	a1, c1 := authFixture(t, conn, "lock-a")
	defer c1()
	a2, c2 := authFixture(t, conn, "lock-b")
	defer c2()

	// Both txs lock the same two users; ascending order makes the
	// interleaving deterministic.
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(k int) {
			defer wg.Done()
			c, err := pgx.Connect(ctx, testDSN(t))
			if err != nil {
				errs[k] = err
				return
			}
			defer c.Close(context.Background())
			tx, err := c.Begin(ctx)
			if err != nil {
				errs[k] = err
				return
			}
			defer tx.Rollback(ctx)
			if err := admin.LockAnchor(ctx, tx); err != nil {
				errs[k] = err
				return
			}
			if _, err := admin.LockUsers(ctx, tx, a1.UserID, a2.UserID); err != nil {
				errs[k] = err
				return
			}
			errs[k] = tx.Commit(ctx)
		}(i)
	}
	wg.Wait()
	for i, e := range errs {
		if e != nil {
			t.Fatalf("tx %d: %v", i, e)
		}
	}
}
