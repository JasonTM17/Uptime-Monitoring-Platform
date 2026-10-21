//go:build integration

package engine

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

var caps = AdmissionCaps{OwnerPer60s: 100, GlobalPer60s: 100}

// Seed an owner + monitor due right now; returns (userID, monitorID).
func seedDue(t *testing.T) (uuid.UUID, uuid.UUID) {
	t.Helper()
	conn := engineConn(t)
	ctx := context.Background()
	var userID, monID uuid.UUID
	if err := conn.QueryRow(ctx, `
		INSERT INTO uptime.users(id,email,password_hash,status,monitor_limit)
		VALUES (gen_random_uuid(),$1,'x','ACTIVE',10) RETURNING id`,
		"rsv+"+uuid.NewString()[:8]+"@test.invalid").Scan(&userID); err != nil {
		t.Fatal(err)
	}
	if err := conn.QueryRow(ctx, `
		INSERT INTO uptime.monitors(id,user_id,name,target_url,method,
		  interval_seconds,timeout_seconds,expected_status,next_check_at)
		VALUES (gen_random_uuid(),$1,'m','https://x.test','GET',60,5,NULL,now()-interval '1 second')
		RETURNING id`, userID).Scan(&monID); err != nil {
		t.Fatal(err)
	}
	return userID, monID
}

func TestReserveRun(t *testing.T) {
	ctx := context.Background()
	conn := engineConn(t)
	ownerID, monID := seedDue(t)

	r1, err := ReserveRun(ctx, conn, monID, caps, 7)
	if err != nil {
		t.Fatalf("reserve: %v", err)
	}
	if r1.Sequence != 1 || r1.Epoch != 7 || r1.OwnerID != ownerID {
		t.Fatalf("reservation fields: %+v", r1)
	}
	var status string
	if err := conn.QueryRow(ctx,
		`SELECT status FROM uptime.check_runs WHERE id=$1`, r1.RunID).
		Scan(&status); err != nil || status != "RESERVED" {
		t.Fatalf("run not RESERVED: %v %q", err, status)
	}
	// Schedule advanced past now --- charge and advance committed together.
	var nextDue time.Time
	if err := conn.QueryRow(ctx,
		`SELECT next_check_at FROM uptime.monitors WHERE id=$1`, monID).
		Scan(&nextDue); err != nil {
		t.Fatal(err)
	}
	if !nextDue.After(time.Now()) {
		t.Fatalf("next_check_at not advanced to future: %v", nextDue)
	}
	if !r1.SlotAt.Before(time.Now().Add(time.Second)) {
		t.Fatalf("slot not charged at/before now: %v", r1.SlotAt)
	}

	// A second reserve while the first is active is refused - one
	// in-flight run per monitor; sequence resumes after finalize.
	if _, err := ReserveRun(ctx, conn, monID, caps, 7); !errors.Is(err, ErrActiveRun) {
		t.Fatalf("active-run guard missing: %v", err)
	}
	if _, err := conn.Exec(ctx,
		`UPDATE uptime.check_runs SET status='COMPLETED',finished_at=now() WHERE id=$1`,
		r1.RunID); err != nil {
		t.Fatal(err)
	}
	r2, err := ReserveRun(ctx, conn, monID, caps, 7)
	if err != nil {
		t.Fatalf("reserve after finalize: %v", err)
	}
	if r2.Sequence != 2 || r2.SegmentID != r1.SegmentID {
		t.Fatalf("sequence/segment drift: %+v", r2)
	}
}

func TestAdmissionWindowFull(t *testing.T) {
	ctx := context.Background()
	conn := engineConn(t)
	_, monID := seedDue(t)
	tight := AdmissionCaps{OwnerPer60s: 1, GlobalPer60s: 100}

	if _, err := ReserveRun(ctx, conn, monID, tight, 1); err != nil {
		t.Fatalf("first admit: %v", err)
	}
	// The SAME monitor's next reservation is blocked... by the window,
	// even though the schedule allows it.
	// The window cap is checked before the active-run guard.
	if _, err := ReserveRun(ctx, conn, monID, tight, 1); !errors.Is(err, ErrAdmissionFull) {
		t.Fatalf("expected ErrAdmissionFull, got %v", err)
	}
	// After finalizing the active run the cap still bites: the
	// committed reservation keeps counting in the 60s window (F02).
	if _, err := conn.Exec(ctx,
		`UPDATE uptime.check_runs SET status='COMPLETED',finished_at=now() WHERE monitor_id=$1`,
		monID); err != nil {
		t.Fatal(err)
	}
	if _, err := ReserveRun(ctx, conn, monID, tight, 1); !errors.Is(err, ErrAdmissionFull) {
		t.Fatalf("expected ErrAdmissionFull after finalize, got %v", err)
	}
	// A DIFFERENT owner's monitor is still governed by the global cap.
	_, mon2 := seedDue(t)
	glob := AdmissionCaps{OwnerPer60s: 100, GlobalPer60s: 1}
	if _, err := ReserveRun(ctx, conn, mon2, glob, 1); !errors.Is(err, ErrAdmissionFull) {
		t.Fatalf("global cap not enforced: %v", err)
	}
	// Rolled-back admissions do NOT charge --- only the one commit counts.
	var n int
	if err := conn.QueryRow(ctx, `
		SELECT count(*) FROM uptime.check_runs WHERE monitor_id=$1`, monID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("rollback charged the window: %d runs", n)
	}
}

func TestNotAdmittableNoCharge(t *testing.T) {
	ctx := context.Background()
	conn := engineConn(t)
	_, monID := seedDue(t)
	if _, err := conn.Exec(ctx,
		`UPDATE uptime.monitors SET is_paused=true WHERE id=$1`, monID); err != nil {
		t.Fatal(err)
	}
	if _, err := ReserveRun(ctx, conn, monID, caps, 1); !errors.Is(err, ErrMonitorNotDue) {
		t.Fatalf("paused monitor admitted: %v", err)
	}
	var n int
	if err := conn.QueryRow(ctx,
		`SELECT count(*) FROM uptime.check_runs WHERE monitor_id=$1`, monID).
		Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("rejected admission left a charge: %d", n)
	}
}

func TestGenerationFences(t *testing.T) {
	ctx := context.Background()
	conn := engineConn(t)
	_, monID := seedDue(t)

	r1, err := ReserveRun(ctx, conn, monID, caps, 2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx,
		`UPDATE uptime.check_runs SET status='COMPLETED',finished_at=now() WHERE id=$1`,
		r1.RunID); err != nil {
		t.Fatal(err)
	}
	// A mutation bumps generation --- the next reserve must close the
	// stale segment and open one under the new generation.
	if _, err := conn.Exec(ctx,
		`UPDATE uptime.monitors SET generation=generation+1 WHERE id=$1`, monID); err != nil {
		t.Fatal(err)
	}
	r2, err := ReserveRun(ctx, conn, monID, caps, 3)
	if err != nil {
		t.Fatalf("reserve under new generation: %v", err)
	}
	if r2.SegmentID == r1.SegmentID {
		t.Fatal("stale-generation segment reused")
	}
	var open int
	if err := conn.QueryRow(ctx, `
		SELECT count(*) FROM uptime.schedule_segments
		WHERE monitor_id=$1 AND ends_at IS NULL`, monID).Scan(&open); err != nil {
		t.Fatal(err)
	}
	if open != 1 {
		t.Fatalf("expected exactly one current segment, got %d", open)
	}
}

func TestReconcileInterrupted(t *testing.T) {
	ctx := context.Background()
	conn := engineConn(t)
	_, monID := seedDue(t)

	old, err := ReserveRun(ctx, conn, monID, caps, 2)
	if err != nil {
		t.Fatal(err)
	}
	// The same-epoch run needs its own monitor - one active per monitor.
	_, monB := seedDue(t)
	same, err := ReserveRun(ctx, conn, monB, caps, 3)
	if err != nil {
		t.Fatal(err)
	}
	n, err := ReconcileInterrupted(ctx, conn, 3)
	if err != nil {
		t.Fatal(err)
	}
	if n < 1 {
		t.Fatal("no rows reconciled")
	}
	var sOld, sSame string
	if err := conn.QueryRow(ctx,
		`SELECT status FROM uptime.check_runs WHERE id=$1`, old.RunID).Scan(&sOld); err != nil {
		t.Fatal(err)
	}
	if err := conn.QueryRow(ctx,
		`SELECT status FROM uptime.check_runs WHERE id=$1`, same.RunID).Scan(&sSame); err != nil {
		t.Fatal(err)
	}
	if sOld != "INTERRUPTED" || sSame != "RESERVED" {
		t.Fatalf("reconcile fencing wrong: old=%q same=%q", sOld, sSame)
	}
}
