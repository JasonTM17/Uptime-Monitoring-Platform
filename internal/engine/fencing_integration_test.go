//go:build integration

package engine

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// mkIdentity reserves a run and returns the identity a worker result
// would carry back, plus the writer owning the conn.
func mkIdentity(t *testing.T, conn *pgx.Conn, epoch int64) (FinalizeIdentity, uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	userID, monID := seedDue(t)
	res, err := ReserveRun(ctx, conn, monID, 1, caps, epoch)
	if err != nil {
		t.Fatalf("reserve: %v", err)
	}
	return FinalizeIdentity{
		RunID: res.RunID, MonitorID: monID, OwnerID: userID,
		SegmentID: res.SegmentID, Generation: 1,
		Sequence: res.Sequence, Epoch: epoch,
	}, userID
}

// monitorSnapshot captures the projections a denied finalize must
// leave untouched.
func monitorSnapshot(t *testing.T, conn *pgx.Conn, monID uuid.UUID) (int, int, time.Time) {
	t.Helper()
	var fs, ss int
	var nca time.Time
	if err := conn.QueryRow(context.Background(), `
		SELECT failure_streak, success_streak, next_check_at
		FROM uptime.monitors WHERE id=$1`, monID).Scan(&fs, &ss, &nca); err != nil {
		t.Fatal(err)
	}
	return fs, ss, nca
}

// Generation bump before finalize -> stale, and the run's mark leaves
// monitor projections untouched.
func TestResultGenerationFence(t *testing.T) {
	ctx := context.Background()
	conn := engineConn(t)
	owner, _ := AcquireOwner(ctx, conn, uuid.New())
	defer owner.Release(ctx)
	w := NewWriter(owner, time.Minute)

	id, _ := mkIdentity(t, conn, owner.Epoch())
	fs0, ss0, nca0 := monitorSnapshot(t, conn, id.MonitorID)

	// A mutation wins the race: generation bumps before finalize.
	if _, err := conn.Exec(ctx,
		`UPDATE uptime.monitors SET generation=generation+1 WHERE id=$1`,
		id.MonitorID); err != nil {
		t.Fatal(err)
	}
	v, err := w.ValidateResultIdentity(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if v != IdentityStale {
		t.Fatalf("stale-generation result admitted: %v", v)
	}

	// Persist terminal disposition - no health influence.
	tx, _ := conn.Begin(ctx)
	if _, err := tx.Exec(ctx, `SELECT 1`); err != nil {
		t.Fatal(err)
	}
	marked, err := MarkStaleRun(ctx, tx, id.RunID, "STALE", "generation_fenced")
	if err != nil || !marked {
		t.Fatalf("mark stale: marked=%v err=%v", marked, err)
	}
	tx.Commit(ctx)
	var status string
	conn.QueryRow(ctx, `SELECT status FROM uptime.check_runs WHERE id=$1`,
		id.RunID).Scan(&status)
	if status != "STALE" {
		t.Fatalf("run not STALE: %s", status)
	}
	fs1, ss1, nca1 := monitorSnapshot(t, conn, id.MonitorID)
	if fs1 != fs0 || ss1 != ss0 || !nca1.Equal(nca0) {
		t.Fatal("stale result changed monitor projections")
	}
}

// Takeover: an old-epoch run validated by the new owner is stale -
// its result must never land.
func TestResultEpochFence(t *testing.T) {
	ctx := context.Background()
	conn := engineConn(t)
	o1, _ := AcquireOwner(ctx, conn, uuid.New())
	id, _ := mkIdentity(t, conn, o1.Epoch())
	o1.Release(ctx)

	conn2 := engineConn(t)
	o2, err := AcquireOwner(ctx, conn2, uuid.New())
	if err != nil {
		t.Fatal(err)
	}
	defer o2.Release(ctx)
	w2 := NewWriter(o2, time.Minute)

	v, err := w2.ValidateResultIdentity(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if v != IdentityStale {
		t.Fatalf("old-epoch result admitted under new owner: %v", v)
	}
}

// A terminal run rejects any replay - same bytes, second arrival.
func TestDuplicateResult(t *testing.T) {
	ctx := context.Background()
	conn := engineConn(t)
	owner, _ := AcquireOwner(ctx, conn, uuid.New())
	defer owner.Release(ctx)
	w := NewWriter(owner, time.Minute)

	id, _ := mkIdentity(t, conn, owner.Epoch())
	if _, err := conn.Exec(ctx,
		`UPDATE uptime.check_runs SET status='COMPLETED',finished_at=now()
		 WHERE id=$1`, id.RunID); err != nil {
		t.Fatal(err)
	}
	v, err := w.ValidateResultIdentity(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if v != IdentityDuplicate {
		t.Fatalf("duplicate result admitted: %v", v)
	}
	// MarkStale on a terminal run is a no-op - dispositions don't rewrite.
	tx, _ := conn.Begin(ctx)
	marked, err := MarkStaleRun(ctx, tx, id.RunID, "STALE", "replay")
	if err != nil {
		t.Fatal(err)
	}
	tx.Commit(ctx)
	if marked {
		t.Fatal("terminal run disposition rewritten")
	}
}

// Disable-first ordering: when the owner disable commits BEFORE the
// finalize validation, the result is rejected. (Finalize-first may
// commit - linearization at the owner row lock.)
func TestSuspendFinalizeOrder(t *testing.T) {
	ctx := context.Background()
	conn := engineConn(t)
	owner, _ := AcquireOwner(ctx, conn, uuid.New())
	defer owner.Release(ctx)
	w := NewWriter(owner, time.Minute)

	id, ownerID := mkIdentity(t, conn, owner.Epoch())
	fs0, ss0, nca0 := monitorSnapshot(t, conn, id.MonitorID)

	// Owner disabled first.
	if _, err := conn.Exec(ctx, `
		UPDATE uptime.users SET status='DISABLED', disabled_at=now()
		WHERE id=$1`, ownerID); err != nil {
		t.Fatal(err)
	}
	v, err := w.ValidateResultIdentity(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if v != IdentityStale {
		t.Fatalf("result admitted after owner disable: %v", v)
	}
	tx, _ := conn.Begin(ctx)
	if _, err := MarkStaleRun(ctx, tx, id.RunID, "STALE", "owner_disabled"); err != nil {
		t.Fatal(err)
	}
	tx.Commit(ctx)
	fs1, ss1, nca1 := monitorSnapshot(t, conn, id.MonitorID)
	if fs1 != fs0 || ss1 != ss0 || !nca1.Equal(nca0) {
		t.Fatal("post-disable result changed monitor projections")
	}
}
