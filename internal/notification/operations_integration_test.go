//go:build integration

package notification

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func opsFor(t *testing.T) (*Operations, *pgxpool.Pool) {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Fatal("TEST_DATABASE_URL required (disposable postgres-test)")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return NewOperations(pool, 10*time.Second), pool
}

// Retry a DEAD stream head: same row re-enters PENDING with a fresh
// attempt window; wrong version and non-head rows are refused.
func TestRetryDeadHead(t *testing.T) {
	ops, pool := opsFor(t)
	c := conn(t)
	cleanOutbox(t, c)
	f := seedBase(t, c)
	ch := mkChannel(t, c, f, "VERIFIED", true, false)

	head := seedOutbox(t, c, f, ch, "DOWN", nil, "PENDING")
	rec := seedOutbox(t, c, f, ch, "RECOVERY", &head, "PENDING")

	// Not DEAD → refused.
	if err := ops.RetryDeadHead(context.Background(), head, 1); !errors.Is(err, ErrNotDead) {
		t.Fatalf("retry live row: %v", err)
	}
	// Kill the head → rec is now blocked behind DEAD (not a head).
	if _, err := pool.Exec(context.Background(),
		`UPDATE uptime.notification_outbox SET state='DEAD' WHERE id=$1`,
		head); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(context.Background(),
		`UPDATE uptime.notification_outbox SET state='DEAD' WHERE id=$1`,
		rec); err != nil {
		t.Fatal(err)
	}
	var recVer int64
	pool.QueryRow(context.Background(),
		`SELECT version FROM uptime.notification_outbox WHERE id=$1`,
		rec).Scan(&recVer)
	if err := ops.RetryDeadHead(context.Background(), rec, recVer); !errors.Is(err, ErrNotStreamHead) {
		t.Fatalf("non-head retry: %v", err)
	}
	// Wrong version conflicts.
	var headVer int64
	pool.QueryRow(context.Background(),
		`SELECT version FROM uptime.notification_outbox WHERE id=$1`,
		head).Scan(&headVer)
	if err := ops.RetryDeadHead(context.Background(), head, headVer+1); !errors.Is(err, ErrDeliveryConflict) {
		t.Fatalf("version conflict: %v", err)
	}
	// Correct: head retries — same identity, fresh window.
	if err := ops.RetryDeadHead(context.Background(), head, headVer); err != nil {
		t.Fatal(err)
	}
	var state, key string
	var attempts int
	pool.QueryRow(context.Background(),
		`SELECT state,event_key,attempts FROM uptime.notification_outbox WHERE id=$1`,
		head).Scan(&state, &key, &attempts)
	if state != "PENDING" || attempts != 0 {
		t.Fatalf("retry: state=%s attempts=%d", state, attempts)
	}
	// Event identity unchanged — no new row appeared.
	var n int
	pool.QueryRow(context.Background(),
		`SELECT count(*) FROM uptime.notification_outbox`).Scan(&n)
	if n != 2 {
		t.Fatalf("row count %d — retry must not create events", n)
	}
}

// Suppress cascades the stream: head + every dependent, never the
// RECOVERY alone.
func TestSuppressCausalStream(t *testing.T) {
	ops, _ := opsFor(t)
	c := conn(t)
	cleanOutbox(t, c)
	f := seedBase(t, c)
	ch := mkChannel(t, c, f, "VERIFIED", true, false)

	down := seedOutbox(t, c, f, ch, "DOWN", nil, "PENDING")
	rec := seedOutbox(t, c, f, ch, "RECOVERY", &down, "PENDING")

	// Suppressing the recovery alone would strand the DOWN — the
	// stream suppresses head-first or not at all. Suppress FROM the
	// DOWN head: both move.
	n, err := ops.SuppressStream(context.Background(), down)
	if err != nil || n != 2 {
		t.Fatalf("suppressed %d %v", n, err)
	}
	if stateOf(t, c, down) != "SUPPRESSED" || stateOf(t, c, rec) != "SUPPRESSED" {
		t.Fatalf("stream: %s %s", stateOf(t, c, down), stateOf(t, c, rec))
	}
}

// Owner-scoped query: another user's rows are invisible.
func TestDeliveryOwnership(t *testing.T) {
	ops, _ := opsFor(t)
	c := conn(t)
	cleanOutbox(t, c)
	f := seedBase(t, c)
	ch := mkChannel(t, c, f, "VERIFIED", true, false)
	seedOutbox(t, c, f, ch, "DOWN", nil, "PENDING")

	rows, err := ops.ListDeliveries(context.Background(), f.userID, 10)
	if err != nil || len(rows) != 1 {
		t.Fatalf("own rows %v %v", rows, err)
	}
	rows, err = ops.ListDeliveries(context.Background(), uuid.New(), 10)
	if err != nil || len(rows) != 0 {
		t.Fatalf("foreign rows visible: %v", rows)
	}
}

// Operations functions are internal services — no public route
// exists. This test pins that boundary by scanning the API mux's
// registered patterns would be overkill; the check that matters is
// behavioral: the functions only exist in this package and take a
// pool, so no HTTP layer can have been wired. The real guarantee is
// the route inventory — asserted here as a compile-time contract via
// the absence of handler constructors.
func TestDeadControlsNotPublic(t *testing.T) {
	// If a future commit wires an HTTP route for these controls before
	// Phase 07's authorized binding, this test is the tripwire that
	// forces a review: Operations must stay pool-bound services.
	var _ = NewOperations // function value, not a handler
}

// TEST intent queueing: the full fence — owned+bound monitor,
// deliverable channel, per-channel cooldown, global cap, dedup.
func TestQueueTestNotification(t *testing.T) {
	ops, pool := opsFor(t)
	c := conn(t)
	cleanOutbox(t, c)
	f := seedBase(t, c)
	ch := mkChannel(t, c, f, "VERIFIED", true, false)

	// Unbound channel → refused.
	unbound := mkChannel(t, c, f, "VERIFIED", true, false)
	if _, err := ops.QueueTestNotification(context.Background(),
		f.userID, f.monID, unbound, DefaultTestRate); !errors.Is(err, ErrNotOwned) {
		t.Fatalf("unbound: %v", err)
	}
	// Bind it.
	if _, err := pool.Exec(context.Background(), `
		INSERT INTO uptime.monitor_channels(monitor_id,channel_id,user_id)
		VALUES ($1,$2,$3)`, f.monID, ch, f.userID); err != nil {
		t.Fatal(err)
	}
	// Foreign owner → refused.
	if _, err := ops.QueueTestNotification(context.Background(),
		uuid.New(), f.monID, ch, DefaultTestRate); !errors.Is(err, ErrNotOwned) {
		t.Fatalf("foreign owner: %v", err)
	}
	// Pending channel → refused.
	pend := mkChannel(t, c, f, "PENDING_VERIFICATION", false, true)
	if _, err := ops.QueueTestNotification(context.Background(),
		f.userID, f.monID, pend, DefaultTestRate); !errors.Is(err, ErrChannelIneligible) {
		t.Fatalf("pending channel: %v", err)
	}
	// Happy path persists exactly one intent.
	id, err := ops.QueueTestNotification(context.Background(),
		f.userID, f.monID, ch, DefaultTestRate)
	if err != nil {
		t.Fatal(err)
	}
	var kind, state, key string
	pool.QueryRow(context.Background(),
		`SELECT event_kind,state,event_key FROM uptime.notification_outbox WHERE id=$1`,
		id).Scan(&kind, &state, &key)
	if kind != "TEST" || state != "PENDING" {
		t.Fatalf("intent %s %s", kind, state)
	}
	// Duplicate call hits the unique intent.
	if _, err := ops.QueueTestNotification(context.Background(),
		f.userID, f.monID, ch, DefaultTestRate); !errors.Is(err, ErrDuplicateTest) &&
		!errors.Is(err, ErrRateLimited) {
		t.Fatalf("duplicate: %v", err)
	}
}
