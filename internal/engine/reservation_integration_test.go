//go:build integration

package engine

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var caps = AdmissionCaps{OwnerPer60s: 100, GlobalPer60s: 100}

// Seed an owner + monitor due right now; returns (userID, monitorID).
func seedDue(t *testing.T) (uuid.UUID, uuid.UUID) {
	t.Helper()
	conn := engineConn(t)
	ctx := context.Background()
	var userID, monID uuid.UUID
	// The fail-closed quota singleton is app-seeded at startup
	// (migration leaves it empty); fixtures must create it honestly
	// rather than rely on residue from other packages' tests.
	if _, err := conn.Exec(ctx, `
		INSERT INTO uptime.quota_budgets(id,global_monitor_limit)
		VALUES (1,1000) ON CONFLICT (id) DO NOTHING`); err != nil {
		t.Fatal(err)
	}
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

	r1, err := ReserveRun(ctx, conn, monID, 1, caps, 7)
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
	if _, err := ReserveRun(ctx, conn, monID, 1, caps, 7); !errors.Is(err, ErrActiveRun) {
		t.Fatalf("active-run guard missing: %v", err)
	}
	if _, err := conn.Exec(ctx,
		`UPDATE uptime.check_runs SET status='COMPLETED',finished_at=now() WHERE id=$1`,
		r1.RunID); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx,
		`UPDATE uptime.monitors SET next_check_at=now()-interval '1 second'
		  WHERE id=$1`, monID); err != nil {
		t.Fatal(err)
	}
	r2, err := ReserveRun(ctx, conn, monID, 1, caps, 7)
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

	if _, err := ReserveRun(ctx, conn, monID, 1, tight, 1); err != nil {
		t.Fatalf("first admit: %v", err)
	}
	// The SAME monitor's next reservation is blocked... by the window,
	// even though the schedule allows it.
	// The window cap is checked before the active-run guard.
	if _, err := ReserveRun(ctx, conn, monID, 1, tight, 1); !errors.Is(err, ErrOwnerAdmissionFull) {
		t.Fatalf("expected ErrOwnerAdmissionFull, got %v", err)
	}
	// After finalizing the active run the cap still bites: the
	// committed reservation keeps counting in the 60s window (F02).
	if _, err := conn.Exec(ctx,
		`UPDATE uptime.check_runs SET status='COMPLETED',finished_at=now() WHERE monitor_id=$1`,
		monID); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx,
		`UPDATE uptime.monitors SET next_check_at=now()-interval '1 second'
		  WHERE id=$1`, monID); err != nil {
		t.Fatal(err)
	}
	if _, err := ReserveRun(ctx, conn, monID, 1, tight, 1); !errors.Is(err, ErrOwnerAdmissionFull) {
		t.Fatalf("expected ErrOwnerAdmissionFull after finalize, got %v", err)
	}
	// A DIFFERENT owner's monitor is still governed by the global cap.
	_, mon2 := seedDue(t)
	glob := AdmissionCaps{OwnerPer60s: 100, GlobalPer60s: 1}
	if _, err := ReserveRun(ctx, conn, mon2, 1, glob, 1); !errors.Is(err, ErrAdmissionFull) {
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

// ReserveRun's quota count is issued after it waits on the singleton
// quota_budgets row. With READ COMMITTED, the count statement sees any
// reservation that committed while this transaction waited. The server's
// default isolation is configurable, so admission must pin that contract
// instead of silently inheriting REPEATABLE READ's older transaction snapshot.
func TestConcurrentGlobalAdmissionCapUsesFreshPostLockSnapshot(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	ownerA, monitorA := seedDue(t)
	ownerB, monitorB := seedDue(t)
	if ownerA == ownerB || monitorA == monitorB {
		t.Fatal("fixtures must use distinct owners and monitors")
	}

	reserveA := engineConn(t)
	reserveB := engineConn(t)
	blocker := engineConn(t)
	observer := engineConn(t)
	for _, conn := range []*pgx.Conn{reserveA, reserveB} {
		if _, err := conn.Exec(ctx, `SET default_transaction_isolation = 'repeatable read'`); err != nil {
			t.Fatalf("set session isolation: %v", err)
		}
	}

	var baseline int
	if err := observer.QueryRow(ctx, `
		SELECT count(*) FROM uptime.check_runs
		WHERE reserved_at > clock_timestamp()-interval '60 seconds'`).Scan(&baseline); err != nil {
		t.Fatalf("read baseline reservations: %v", err)
	}
	caps := AdmissionCaps{OwnerPer60s: 10, GlobalPer60s: baseline + 1}

	// Hold the global admission mutex until both ReserveRun transactions have
	// taken their first statement snapshot and are waiting on that same row.
	// This makes the interleaving deterministic under a repeatable-read server
	// default and proves whether the post-lock count gets a fresh snapshot.
	blockTx, err := blocker.Begin(ctx)
	if err != nil {
		t.Fatalf("begin blocker: %v", err)
	}
	defer blockTx.Rollback(ctx)
	var budget int
	if err := blockTx.QueryRow(ctx, `
		SELECT global_monitor_limit FROM uptime.quota_budgets WHERE id=1 FOR UPDATE`).Scan(&budget); err != nil {
		t.Fatalf("lock global budget: %v", err)
	}

	type result struct {
		monitorID uuid.UUID
		err       error
	}
	start := make(chan struct{})
	results := make(chan result, 2)
	var wg sync.WaitGroup
	for _, item := range []struct {
		conn      *pgx.Conn
		monitorID uuid.UUID
	}{{reserveA, monitorA}, {reserveB, monitorB}} {
		item := item
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, reserveErr := ReserveRun(ctx, item.conn, item.monitorID, 1, caps, 1)
			results <- result{monitorID: item.monitorID, err: reserveErr}
		}()
	}
	close(start)

	deadline := time.Now().Add(10 * time.Second)
	for {
		var waiting int
		if err := observer.QueryRow(ctx, `
			SELECT count(*) FROM pg_stat_activity
			WHERE wait_event_type='Lock' AND query LIKE '%global_monitor_limit%'`).Scan(&waiting); err != nil {
			_ = blockTx.Rollback(ctx)
			wg.Wait()
			t.Fatalf("observe quota waiters: %v", err)
		}
		if waiting >= 2 {
			break
		}
		if time.Now().After(deadline) {
			_ = blockTx.Rollback(ctx)
			wg.Wait()
			t.Fatalf("only %d reservation transactions reached the held quota lock", waiting)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := blockTx.Rollback(ctx); err != nil {
		t.Fatalf("release quota lock: %v", err)
	}
	wg.Wait()
	close(results)

	succeeded := 0
	denied := 0
	for got := range results {
		if got.err == nil {
			succeeded++
			continue
		}
		if errors.Is(got.err, ErrAdmissionFull) {
			denied++
			continue
		}
		t.Errorf("reserve monitor %s: unexpected error: %v", got.monitorID, got.err)
	}
	if succeeded != 1 || denied != 1 {
		t.Fatalf("concurrent global cap outcomes: succeeded=%d denied=%d; want 1 each", succeeded, denied)
	}

	var committed int
	if err := observer.QueryRow(ctx, `
		SELECT count(*) FROM uptime.check_runs
		WHERE reserved_at > clock_timestamp()-interval '60 seconds'`).Scan(&committed); err != nil {
		t.Fatalf("read committed reservations: %v", err)
	}
	if committed != caps.GlobalPer60s {
		t.Fatalf("rolling-window charges=%d, cap=%d (baseline=%d)", committed, caps.GlobalPer60s, baseline)
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
	if _, err := ReserveRun(ctx, conn, monID, 1, caps, 1); !errors.Is(err, ErrMonitorNotDue) {
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

	r1, err := ReserveRun(ctx, conn, monID, 1, caps, 2)
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
		`UPDATE uptime.monitors SET generation=generation+1,
		   next_check_at=now()-interval '1 second' WHERE id=$1`, monID); err != nil {
		t.Fatal(err)
	}
	r2, err := ReserveRun(ctx, conn, monID, 2, caps, 3)
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

	old, err := ReserveRun(ctx, conn, monID, 1, caps, 2)
	if err != nil {
		t.Fatal(err)
	}
	// The same-epoch run needs its own monitor - one active per monitor.
	_, monB := seedDue(t)
	same, err := ReserveRun(ctx, conn, monB, 1, caps, 3)
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
