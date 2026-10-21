//go:build integration

package engine

import (
	"context"
	"testing"
	"time"

	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/checker"
	"github.com/google/uuid"
)

func testEngineParams(tickEvery time.Duration) EngineParams {
	return EngineParams{
		TickEvery:       tickEvery,
		BatchLimit:      10,
		Workers:         2,
		QueueSize:       4,
		Caps:            caps,
		HeartbeatEvery:  time.Minute,
		FinalizeTimeout: 3 * time.Second,
	}
}

// waitForResult polls until a committed check_results row exists for
// the monitor — proof the full pipeline ran (select -> reserve ->
// attempt -> atomic finalize).
func waitForResult(t *testing.T, monID uuid.UUID) {
	t.Helper()
	conn := engineConn(t)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var n int
		if err := conn.QueryRow(context.Background(),
			`SELECT count(*) FROM uptime.check_results WHERE monitor_id=$1`,
			monID).Scan(&n); err == nil && n > 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("no committed result within 5s — pipeline did not run")
}

// Full lifecycle: the assembled engine admits, checks, and finalizes;
// Shutdown flips readiness FIRST, finishes bounded, preserves
// committed state, releases the advisory lock for a fenced successor.
func TestOrderedShutdown(t *testing.T) {
	ctx := context.Background()
	probe := engineConn(t)
	cleanEngine(t, probe)

	engConn := engineConn(t)
	eng, err := StartEngine(ctx, engConn, uuid.New(),
		testEngineParams(50*time.Millisecond), &fakeChecker{})
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	if err := eng.Ready(ctx); err != nil {
		t.Fatalf("engine not ready after start: %v", err)
	}

	_, monID := seedDue(t)
	waitForResult(t, monID)
	epoch := eng.State().Epoch

	sctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	start := time.Now()
	if err := eng.Shutdown(sctx); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("shutdown exceeded its bound")
	}
	// Readiness flipped and stays flipped after the drain.
	if err := eng.Ready(ctx); err == nil {
		t.Fatal("readiness still reports ready after shutdown")
	}
	// Lifecycle goroutines all exited — tick/coord done channels are
	// observable proof (no goroutine leak, no blocked producer).
	select {
	case <-eng.tickDone:
	default:
		t.Fatal("scheduler loop still running after shutdown")
	}
	select {
	case <-eng.coordDone:
	default:
		t.Fatal("coordinator still running after shutdown")
	}

	// Committed state survives: result row + terminal run + health.
	var results int
	var status, health string
	probe.QueryRow(ctx, `SELECT count(*) FROM uptime.check_results
		WHERE monitor_id=$1`, monID).Scan(&results)
	probe.QueryRow(ctx, `SELECT status FROM uptime.check_runs
		WHERE monitor_id=$1 ORDER BY sequence DESC LIMIT 1`, monID).Scan(&status)
	probe.QueryRow(ctx, `SELECT health FROM uptime.monitors WHERE id=$1`,
		monID).Scan(&health)
	if results < 1 || status == "RESERVED" || status == "RUNNING" || health != "UP" {
		t.Fatalf("committed state lost: results=%d run=%s health=%s",
			results, status, health)
	}

	// The advisory lock was released: a successor acquires with a
	// strictly larger epoch — ownership moved on cleanly.
	next := engineConn(t)
	o2, err := AcquireOwner(ctx, next, uuid.New())
	if err != nil {
		t.Fatalf("successor cannot acquire after shutdown: %v", err)
	}
	defer o2.Release(ctx)
	if o2.Epoch() <= epoch {
		t.Fatalf("epoch did not advance across shutdown: %d -> %d",
			epoch, o2.Epoch())
	}
}

// SIGTERM mid-attempt inside a tight deadline: the in-flight check is
// canceled, the run stays RESERVED (recoverable), and NOTHING becomes
// DOWN — an interrupted collector is not target evidence. The next
// owner reconciles it to INTERRUPTED.
func TestShutdownDuringAttempt(t *testing.T) {
	ctx := context.Background()
	probe := engineConn(t)
	cleanEngine(t, probe)

	// Barrier checker: the seeded monitor's attempt blocks until the
	// worker context is canceled (stuck-checker honoring cancel).
	_, monID := seedDue(t)
	sc := newScriptedChecker()
	started := make(chan struct{})
	sc.scripts[monID] = func(ctx context.Context, tgt checker.Target) checker.Observation {
		close(started)
		<-ctx.Done() // honor the forced deadline — then stop
		o, _ := checker.NewObservation(tgt, checker.OutcomeCanceled, nil, nil, time.Now())
		return o
	}

	engConn := engineConn(t)
	eng, err := StartEngine(ctx, engConn, uuid.New(),
		testEngineParams(30*time.Millisecond), sc)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("attempt never reached the barrier")
	}

	// Tight shutdown deadline — the blocked attempt cannot finish:
	// deadline forces cancel, shutdown still completes bounded.
	sctx, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- eng.Shutdown(sctx) }()
	select {
	case <-done:
	case <-time.After(8 * time.Second):
		t.Fatal("shutdown hung past forced deadline + grace")
	}

	// Uncommitted work is never fabricated into target evidence.
	// Two honest outcomes exist on a forced deadline: the worker
	// dropped the canceled result (run stays RESERVED, recoverable),
	// or the drain committed it as EXCLUDED evidence — eligible=false,
	// streaks reset, health preserved. What may NEVER happen: an
	// eligible result, a COMPLETED run, an incident, or DOWN health.
	var status, health string
	var elig, incs, outs, fs int
	probe.QueryRow(ctx, `SELECT status FROM uptime.check_runs
		WHERE monitor_id=$1 ORDER BY sequence DESC LIMIT 1`, monID).Scan(&status)
	probe.QueryRow(ctx, `SELECT health, failure_streak FROM uptime.monitors WHERE id=$1`,
		monID).Scan(&health, &fs)
	probe.QueryRow(ctx, `SELECT count(*) FROM uptime.check_results
		WHERE monitor_id=$1 AND eligible`, monID).Scan(&elig)
	probe.QueryRow(ctx, `SELECT count(*) FROM uptime.incidents WHERE monitor_id=$1`,
		monID).Scan(&incs)
	probe.QueryRow(ctx, `SELECT count(*) FROM uptime.notification_outbox WHERE monitor_id=$1`,
		monID).Scan(&outs)
	if elig != 0 || incs != 0 || outs != 0 || health != "UNKNOWN" || fs != 0 {
		t.Fatalf("forced shutdown fabricated evidence: eligible=%d inc=%d out=%d health=%s fs=%d",
			elig, incs, outs, health, fs)
	}
	if status != "RESERVED" && status != "EXCLUDED" {
		t.Fatalf("interrupted run neither recoverable nor excluded: %s", status)
	}

	// Successor reconciles the orphaned run — visibly interrupted.
	next := engineConn(t)
	o2, err := AcquireOwner(ctx, next, uuid.New())
	if err != nil {
		t.Fatalf("successor acquire: %v", err)
	}
	defer o2.Release(ctx)
	if _, err := ReconcileInterrupted(ctx, next, o2.Epoch()); err != nil {
		t.Fatal(err)
	}
	probe.QueryRow(ctx, `SELECT status FROM uptime.check_runs
		WHERE monitor_id=$1 ORDER BY sequence DESC LIMIT 1`, monID).Scan(&status)
	// RESERVED orphans become INTERRUPTED; an honestly-committed
	// EXCLUDED run is already terminal and stays so.
	if status != "INTERRUPTED" && status != "EXCLUDED" {
		t.Fatalf("orphan neither reconciled nor terminally excluded: %s", status)
	}
}

// Graceful shutdown drains queued work: jobs already in the bounded
// queue complete their attempts and finalize — no RESERVED/RUNNING
// row survives an unforced stop.
func TestShutdownDrainsResults(t *testing.T) {
	ctx := context.Background()
	probe := engineConn(t)
	cleanEngine(t, probe)

	for i := 0; i < 3; i++ {
		seedDue(t)
	}
	engConn := engineConn(t)
	eng, err := StartEngine(ctx, engConn, uuid.New(),
		testEngineParams(30*time.Millisecond), &fakeChecker{})
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	// Let at least one full cycle land.
	time.Sleep(300 * time.Millisecond)

	sctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := eng.Shutdown(sctx); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	var active int
	probe.QueryRow(ctx, `SELECT count(*) FROM uptime.check_runs
		WHERE status IN ('RESERVED','RUNNING')`).Scan(&active)
	if active != 0 {
		t.Fatalf("graceful shutdown left active runs: %d", active)
	}
}

// Shutdown is idempotent: concurrent and repeated calls observe the
// same outcome — no double-close panic, no double release.
func TestShutdownIdempotent(t *testing.T) {
	ctx := context.Background()
	probe := engineConn(t)
	cleanEngine(t, probe)

	engConn := engineConn(t)
	eng, err := StartEngine(ctx, engConn, uuid.New(),
		testEngineParams(time.Minute), &fakeChecker{})
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	sctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	errs := make(chan error, 3)
	go func() { errs <- eng.Shutdown(sctx) }()
	go func() { errs <- eng.Shutdown(sctx) }()
	errs <- eng.Shutdown(sctx)
	for i := 0; i < 3; i++ {
		if err := <-errs; err != nil {
			t.Fatalf("shutdown %d: %v", i, err)
		}
	}
}
