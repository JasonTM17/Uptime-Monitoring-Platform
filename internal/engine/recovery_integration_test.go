//go:build integration

package engine

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/checker"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// cleanEngine resets every engine-owned projection so each schedule
// can assert exact durable counts (not just logs/status codes).
func cleanEngine(t *testing.T, conn *pgx.Conn) {
	t.Helper()
	ctx := context.Background()
	for _, tbl := range []string{
		"notification_outbox", "incidents", "check_results",
		"check_runs", "schedule_segments", "monitor_channels", "monitors",
	} {
		if _, err := conn.Exec(ctx, "DELETE FROM uptime."+tbl); err != nil {
			t.Fatalf("clean %s: %v", tbl, err)
		}
	}
}

// killBackend terminates target's PostgreSQL backend from a second
// connection — the deterministic equivalent of a process crash: the
// session, its advisory lock, and its in-flight tx all die at once.
func killBackend(t *testing.T, killer, target *pgx.Conn) {
	t.Helper()
	ctx := context.Background()
	var pid int
	if err := target.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&pid); err != nil {
		t.Fatalf("backend pid: %v", err)
	}
	if _, err := killer.Exec(ctx, "SELECT pg_terminate_backend($1)", pid); err != nil {
		t.Fatalf("terminate backend: %v", err)
	}
}

// Crash AFTER a committed reservation, BEFORE any worker attempt.
// Takeover must: bump epoch, reconcile the orphan to INTERRUPTED,
// preserve the already-advanced schedule (no catch-up replay), and
// fabricate zero result/incident/outbox rows for the missed slot.
func TestRestartSchedules(t *testing.T) {
	ctx := context.Background()
	c1 := engineConn(t)
	cleanEngine(t, c1)

	o1, err := AcquireOwner(ctx, c1, uuid.New())
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	e1 := o1.Epoch()

	_, monID := seedDue(t)
	res, err := ReserveRun(ctx, c1, monID, 1, caps, e1)
	if err != nil {
		t.Fatalf("reserve: %v", err)
	}
	// The committed schedule position the crash must NOT rewind.
	var nextAfter time.Time
	if err := c1.QueryRow(ctx,
		`SELECT next_check_at FROM uptime.monitors WHERE id=$1`, monID).
		Scan(&nextAfter); err != nil {
		t.Fatal(err)
	}

	// Deterministic crash: terminate the lock-holding backend.
	killer := engineConn(t)
	killBackend(t, killer, c1)

	// Takeover on a fresh connection: new epoch, reconcile orphans.
	c2 := engineConn(t)
	o2, err := AcquireOwner(ctx, c2, uuid.New())
	if err != nil {
		t.Fatalf("takeover acquire: %v", err)
	}
	defer o2.Release(ctx)
	if o2.Epoch() <= e1 {
		t.Fatalf("epoch not bumped across crash: %d -> %d", e1, o2.Epoch())
	}
	n, err := ReconcileInterrupted(ctx, c2, o2.Epoch())
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected exactly 1 reconciled run, got %d", n)
	}

	// Oracle 1: orphan is INTERRUPTED with the takeover reason —
	// visible as interrupted, never silently completed or re-run.
	var status, reason string
	if err := c2.QueryRow(ctx,
		`SELECT status, COALESCE(terminal_reason,'') FROM uptime.check_runs WHERE id=$1`,
		res.RunID).Scan(&status, &reason); err != nil {
		t.Fatal(err)
	}
	if status != "INTERRUPTED" || reason != "engine_takeover" {
		t.Fatalf("orphan disposition wrong: %s %q", status, reason)
	}
	// Oracle 2: schedule NOT rewound — the missed slot is not replayed.
	var nextNow time.Time
	if err := c2.QueryRow(ctx,
		`SELECT next_check_at FROM uptime.monitors WHERE id=$1`, monID).
		Scan(&nextNow); err != nil {
		t.Fatal(err)
	}
	if !nextNow.Equal(nextAfter) {
		t.Fatalf("schedule rewound across restart: %v -> %v", nextAfter, nextNow)
	}
	// Oracle 3: zero fabricated projections for the missed slot.
	var results, incs, outs int
	c2.QueryRow(ctx,
		`SELECT count(*) FROM uptime.check_results WHERE check_id=$1`, res.RunID).
		Scan(&results)
	c2.QueryRow(ctx,
		`SELECT count(*) FROM uptime.incidents WHERE monitor_id=$1`, monID).Scan(&incs)
	c2.QueryRow(ctx,
		`SELECT count(*) FROM uptime.notification_outbox WHERE monitor_id=$1`, monID).
		Scan(&outs)
	if results != 0 || incs != 0 || outs != 0 {
		t.Fatalf("restart fabricated rows: results=%d incidents=%d outbox=%d",
			results, incs, outs)
	}
	// Oracle 4: restart resumes FORWARD — the next reservation on the
	// same monitor continues the sequence, not a replay of slot 1.
	if _, err := c2.Exec(ctx,
		`UPDATE uptime.monitors SET next_check_at=now()-interval '1 second'
		  WHERE id=$1`, monID); err != nil {
		t.Fatal(err)
	}
	r2, err := ReserveRun(ctx, c2, monID, 1, caps, o2.Epoch())
	if err != nil {
		t.Fatalf("post-restart reserve: %v", err)
	}
	if r2.Sequence != res.Sequence+1 || r2.Epoch != o2.Epoch() {
		t.Fatalf("restart replayed or reset the sequence: %+v", r2)
	}
}

// Two lock contenders on one database behave as two processes: the
// second cannot acquire while the first lives, and after a crash the
// survivor owns a strictly larger epoch. Results stamped with the old
// epoch are fenced even when delivered through the NEW owner's writer.
func TestDualProcessOwnership(t *testing.T) {
	ctx := context.Background()
	c1 := engineConn(t)
	cleanEngine(t, c1)
	c2 := engineConn(t)

	o1, err := AcquireOwner(ctx, c1, uuid.New())
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	e1 := o1.Epoch()

	// Single-owner fence: the contender cannot start while c1 holds.
	bctx, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
	if o, err := AcquireOwner(bctx, c2, uuid.New()); err == nil || o != nil {
		cancel()
		t.Fatal("second process acquired while first owner alive")
	}
	cancel()
	// c2 is poisoned by the cancelled acquire — bring a fresh conn.
	c2 = engineConn(t)

	userID, monID := seedDue(t)
	res, err := ReserveRun(ctx, c1, monID, 1, caps, e1)
	if err != nil {
		t.Fatalf("reserve: %v", err)
	}
	oldIdentity := FinalizeIdentity{
		RunID: res.RunID, MonitorID: monID, OwnerID: userID,
		SegmentID: res.SegmentID, Generation: 1,
		Sequence: res.Sequence, Epoch: e1,
	}

	killBackend(t, c2, c1)
	o2, err := AcquireOwner(ctx, c2, uuid.New())
	if err != nil {
		t.Fatalf("survivor acquire: %v", err)
	}
	defer o2.Release(ctx)
	if o2.Epoch() <= e1 {
		t.Fatalf("survivor did not fence epoch: %d -> %d", e1, o2.Epoch())
	}

	// An old-epoch result arriving at the NEW owner is fenced stale:
	// run -> STALE, no result row, no health/streak/incident/outbox.
	w2 := NewWriter(o2, time.Minute)
	out, err := w2.FinalizeObservation(ctx, FinalizeInput{
		Identity:    oldIdentity,
		Observation: okObservation(t, monID)})
	if err != nil {
		t.Fatalf("stale finalize errored instead of fencing: %v", err)
	}
	if out != FinalizeStale {
		t.Fatalf("old-epoch result accepted under new owner: %v", out)
	}
	var status string
	var results, incs, outs, fs, ss int
	var health string
	c2.QueryRow(ctx, `SELECT status FROM uptime.check_runs WHERE id=$1`,
		res.RunID).Scan(&status)
	c2.QueryRow(ctx, `SELECT count(*) FROM uptime.check_results WHERE check_id=$1`,
		res.RunID).Scan(&results)
	c2.QueryRow(ctx, `SELECT health,failure_streak,success_streak
		FROM uptime.monitors WHERE id=$1`, monID).Scan(&health, &fs, &ss)
	c2.QueryRow(ctx, `SELECT count(*) FROM uptime.incidents WHERE monitor_id=$1`,
		monID).Scan(&incs)
	c2.QueryRow(ctx, `SELECT count(*) FROM uptime.notification_outbox
		WHERE monitor_id=$1`, monID).Scan(&outs)
	if status != "STALE" || results != 0 || health != "UNKNOWN" ||
		fs != 0 || ss != 0 || incs != 0 || outs != 0 {
		t.Fatalf("old owner leaked write: run=%s results=%d health=%s fs=%d ss=%d inc=%d out=%d",
			status, results, health, fs, ss, incs, outs)
	}
}

// A persistently full queue loses nothing: due monitors stay in the
// database until capacity exists — the scheduler never drops due work
// it could not admit.
func TestQueueFullRecovery(t *testing.T) {
	ctx := context.Background()
	conn := engineConn(t)
	cleanEngine(t, conn)

	o, err := AcquireOwner(ctx, conn, uuid.New())
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	defer o.Release(ctx)
	w := NewWriter(o, time.Minute)

	monIDs := map[uuid.UUID]bool{}
	for i := 0; i < 3; i++ {
		_, m := seedDue(t)
		monIDs[m] = true
	}

	// Capacity 1, workers NOT started: the queue fills and stays full.
	pool := NewWorkerPool(1, 1, &fakeChecker{})
	s := NewScheduler(w, pool, o.Epoch(), caps, 10)
	if n, err := s.Tick(ctx); err != nil || n != 1 {
		t.Fatalf("first tick: n=%d err=%v lastErr=%v", n, err, s.LastErr())
	}
	// Second tick while full: admits nothing, reserves nothing.
	if n, err := s.Tick(ctx); err != nil || n != 0 {
		t.Fatalf("full-queue tick leaked: n=%d err=%v", n, err)
	}
	// The two unadmitted monitors are still selectable — zero due loss.
	due, err := SelectDue(ctx, conn, time.Now(), 10)
	if err != nil {
		t.Fatal(err)
	}
	still := 0
	for _, d := range due {
		if monIDs[d.MonitorID] {
			still++
		}
	}
	if still != 2 {
		t.Fatalf("due work lost under full queue: %d/2 remain", still)
	}

	// Open capacity: workers drain the queue; subsequent ticks admit
	// the retained work exactly once each.
	pool.Start(ctx)
	stopDrain := drain(pool)
	defer func() { pool.CloseJobs(); pool.Wait(); stopDrain() }()
	deadline := time.Now().Add(5 * time.Second)
	for pool.Capacity() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	for i := 0; i < 10; i++ {
		if _, err := s.Tick(ctx); err != nil {
			t.Fatal(err)
		}
		var reserved int
		conn.QueryRow(ctx, `
			SELECT count(*) FROM uptime.check_runs
			WHERE status IN ('RESERVED','RUNNING','COMPLETED','EXCLUDED')`).
			Scan(&reserved)
		if reserved == 3 {
			break
		}
		deadline = time.Now().Add(500 * time.Millisecond)
		for pool.Capacity() == 0 && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
	}
	// Each seeded monitor got exactly one run — retained, not doubled.
	var perMonitor int
	if err := conn.QueryRow(ctx, `
		SELECT count(*) FROM (
		  SELECT monitor_id, count(*) c FROM uptime.check_runs
		  GROUP BY monitor_id) q WHERE c <> 1`).Scan(&perMonitor); err != nil {
		t.Fatal(err)
	}
	var total int
	conn.QueryRow(ctx, `SELECT count(*) FROM uptime.check_runs`).Scan(&total)
	if perMonitor != 0 || total != 3 {
		t.Fatalf("recovery duplicated or lost runs: total=%d offenders=%d",
			total, perMonitor)
	}
}

// scriptedChecker dispatches per monitor — the deterministic barrier
// for queue-delay and cancel-before-attempt schedules.
type scriptedChecker struct {
	mu       sync.Mutex
	scripts  map[uuid.UUID]func(ctx context.Context, t checker.Target) checker.Observation
	calls    map[uuid.UUID]int
	attempts map[uuid.UUID]time.Time
}

func newScriptedChecker() *scriptedChecker {
	return &scriptedChecker{
		scripts:  map[uuid.UUID]func(context.Context, checker.Target) checker.Observation{},
		calls:    map[uuid.UUID]int{},
		attempts: map[uuid.UUID]time.Time{},
	}
}

func (s *scriptedChecker) Check(ctx context.Context, t checker.Target) checker.Observation {
	s.mu.Lock()
	s.calls[t.MonitorID]++
	s.attempts[t.MonitorID] = time.Now()
	fn := s.scripts[t.MonitorID]
	s.mu.Unlock()
	if fn == nil {
		return okObs(t)
	}
	return fn(ctx, t)
}

func (s *scriptedChecker) attemptAt(m uuid.UUID) time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.attempts[m]
}

func (s *scriptedChecker) callCount(m uuid.UUID) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls[m]
}

// F01/F02 fault schedule: queue delay must NEVER consume the target's
// attempt budget or fabricate evidence. A job held in queue longer
// than its configured timeout still checks with a fresh budget; a
// genuinely slow target still yields an eligible TIMEOUT (positive
// control); and a job canceled before its attempt produces no
// observation at all — its reservation stays recoverable.
func TestQueueDelayCannotCreateTargetIncident(t *testing.T) {
	ctx := context.Background()
	conn := engineConn(t)
	cleanEngine(t, conn)

	o, err := AcquireOwner(ctx, conn, uuid.New())
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	defer o.Release(ctx)
	w := NewWriter(o, time.Minute)

	userID, monID := seedDue(t)
	res, err := ReserveRun(ctx, conn, monID, 1, caps, o.Epoch())
	if err != nil {
		t.Fatalf("reserve: %v", err)
	}
	id := FinalizeIdentity{
		RunID: res.RunID, MonitorID: monID, OwnerID: userID,
		SegmentID: res.SegmentID, Generation: 1,
		Sequence: res.Sequence, Epoch: o.Epoch(),
	}

	// Barrier: blocker monitor holds the single worker past the
	// queued job's 1s target budget; queued monitor answers instantly.
	blocker := uuid.New()
	release := make(chan struct{})
	sc := newScriptedChecker()
	sc.scripts[blocker] = func(ctx context.Context, t checker.Target) checker.Observation {
		select {
		case <-release:
		case <-ctx.Done():
		}
		return okObs(t)
	}
	sc.scripts[monID] = func(ctx context.Context, t checker.Target) checker.Observation {
		return okObs(t) // instant healthy response once attempted
	}

	pool := NewWorkerPool(1, 2, sc)
	pctx, pcancel := context.WithCancel(ctx)
	defer pcancel()
	pool.Start(pctx)

	// Job 1 occupies the only worker. Job 2 (the real reservation,
	// 1s target budget) queues behind it.
	pool.Submit(ctx, Job{
		RunID: uuid.New(), MonitorID: blocker, OwnerID: userID,
		SegmentID: uuid.New(), Sequence: 1, Epoch: o.Epoch(), SlotAt: time.Now(),
		Target: checker.Target{MonitorID: blocker, URL: "https://b.test",
			TimeoutSeconds: 5},
	})
	submittedAt := time.Now()
	pool.Submit(ctx, Job{
		RunID: res.RunID, MonitorID: monID, OwnerID: userID,
		SegmentID: res.SegmentID, Sequence: res.Sequence, Epoch: o.Epoch(),
		SlotAt: res.SlotAt,
		Target: checker.Target{MonitorID: monID, URL: "https://x.test",
			TimeoutSeconds: 1},
	})

	// Hold the barrier 1.2s — strictly longer than job2's budget —
	// then release; results arrive in completion order.
	time.Sleep(1200 * time.Millisecond)
	close(release)
	var delayed Result
	deadline := time.Now().Add(5 * time.Second)
	got := 0
	for got < 2 && time.Now().Before(deadline) {
		select {
		case r := <-pool.Results():
			got++
			if r.Job.MonitorID == monID {
				delayed = r
			}
		case <-time.After(100 * time.Millisecond):
		}
	}
	if got != 2 {
		t.Fatalf("expected 2 results, got %d", got)
	}
	if sc.attemptAt(monID).Sub(submittedAt) < time.Second {
		t.Fatalf("schedule invalid: queue wait %v did not exceed the 1s budget",
			sc.attemptAt(monID).Sub(submittedAt))
	}
	if delayed.Observation.Outcome != checker.OutcomeSuccess {
		t.Fatalf("queue delay consumed the attempt budget: outcome=%v",
			outcomeName(delayed.Observation.Outcome))
	}

	// The delayed observation commits as honest evidence: health UP,
	// no incident, no outbox — collector lag is not target evidence.
	out, err := w.FinalizeObservation(ctx, FinalizeInput{
		Identity: id, Observation: delayed.Observation})
	if err != nil || out != FinalizeCommitted {
		t.Fatalf("delayed finalize: %v %v", out, err)
	}
	var health string
	var ss, incs, outs int
	conn.QueryRow(ctx, `SELECT health,success_streak FROM uptime.monitors WHERE id=$1`,
		monID).Scan(&health, &ss)
	conn.QueryRow(ctx, `SELECT count(*) FROM uptime.incidents WHERE monitor_id=$1`,
		monID).Scan(&incs)
	conn.QueryRow(ctx, `SELECT count(*) FROM uptime.notification_outbox WHERE monitor_id=$1`,
		monID).Scan(&outs)
	if health != "UP" || ss != 1 || incs != 0 || outs != 0 {
		t.Fatalf("queue delay fabricated state: health=%s ss=%d inc=%d out=%d",
			health, ss, incs, outs)
	}

	// Positive control: a target that genuinely outruns its attempt
	// budget DOES produce an eligible TIMEOUT — the deadline is real.
	if _, err := conn.Exec(ctx,
		`UPDATE uptime.monitors SET next_check_at=now()-interval '1 second'
		  WHERE id=$1`, monID); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx,
		`UPDATE uptime.monitors SET next_check_at=now()-interval '1 second'
		  WHERE id=$1`, monID); err != nil {
		t.Fatal(err)
	}
	res2, err := ReserveRun(ctx, conn, monID, 1, caps, o.Epoch())
	if err != nil {
		t.Fatalf("control reserve: %v", err)
	}
	slow := uuid.New()
	sc.scripts[slow] = func(ctx context.Context, t checker.Target) checker.Observation {
		<-ctx.Done() // stall until the per-attempt deadline fires
		lat := int64(1000)
		o, err := checker.NewObservation(t, checker.OutcomeTimeout, nil, &lat, time.Now())
		if err != nil {
			panic("control observation: " + err.Error())
		}
		return o
	}
	// Rebind the job's monitor to the slow script while keeping the
	// real reservation identity for the result path.
	pool.Submit(ctx, Job{
		RunID: res2.RunID, MonitorID: slow, OwnerID: userID,
		SegmentID: res2.SegmentID, Sequence: res2.Sequence, Epoch: o.Epoch(),
		SlotAt: res2.SlotAt,
		Target: checker.Target{MonitorID: slow, URL: "https://slow.test",
			TimeoutSeconds: 1},
	})
	var ctrl Result
	deadline = time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case r := <-pool.Results():
			ctrl = r
		case <-time.After(100 * time.Millisecond):
		}
		if ctrl.Job.MonitorID == slow {
			break
		}
	}
	if ctrl.Observation.Outcome != checker.OutcomeTimeout {
		t.Fatalf("positive control failed: slow target outcome=%v",
			outcomeName(ctrl.Observation.Outcome))
	}
	// Commit the control under the REAL reservation identity — the
	// eligible failure advances the failure streak exactly once.
	id2 := id
	id2.RunID, id2.Sequence = res2.RunID, res2.Sequence
	out, err = w.FinalizeObservation(ctx, FinalizeInput{
		Identity: id2, Observation: ctrl.Observation})
	if err != nil || out != FinalizeCommitted {
		t.Fatalf("control finalize: %v %v", out, err)
	}
	var fs int
	conn.QueryRow(ctx, `SELECT failure_streak FROM uptime.monitors WHERE id=$1`,
		monID).Scan(&fs)
	if fs != 1 {
		t.Fatalf("eligible timeout did not advance failure streak: %d", fs)
	}

	// F02: cancel while a job still waits — its checker is never
	// invoked and the reservation stays RESERVED (recoverable).
	if _, err := conn.Exec(ctx,
		`UPDATE uptime.monitors SET next_check_at=now()-interval '1 second'
		  WHERE id=$1`, monID); err != nil {
		t.Fatal(err)
	}
	res3, err := ReserveRun(ctx, conn, monID, 1, caps, o.Epoch())
	if err != nil {
		t.Fatalf("cancel-case reserve: %v", err)
	}
	waiting := uuid.New()
	release2 := make(chan struct{})
	sc.scripts[blocker] = func(ctx context.Context, t checker.Target) checker.Observation {
		select {
		case <-release2:
		case <-ctx.Done():
		}
		return okObs(t)
	}
	pool.Submit(ctx, Job{
		RunID: uuid.New(), MonitorID: blocker, OwnerID: userID,
		SegmentID: uuid.New(), Sequence: 1, Epoch: o.Epoch(), SlotAt: time.Now(),
		Target: checker.Target{MonitorID: blocker, URL: "https://b.test",
			TimeoutSeconds: 5},
	})
	pool.Submit(ctx, Job{
		RunID: res3.RunID, MonitorID: waiting, OwnerID: userID,
		SegmentID: res3.SegmentID, Sequence: res3.Sequence, Epoch: o.Epoch(),
		SlotAt: res3.SlotAt,
		Target: checker.Target{MonitorID: waiting, URL: "https://w.test",
			TimeoutSeconds: 1},
	})
	// Give the worker a moment to pick the blocker, then cancel the
	// pool lifecycle while the second job still queues.
	time.Sleep(100 * time.Millisecond)
	pcancel()
	close(release2)
	pool.Wait()
	if sc.callCount(waiting) != 0 {
		t.Fatalf("canceled-before-attempt job ran a check: %d calls",
			sc.callCount(waiting))
	}
	var runStatus string
	conn.QueryRow(ctx, `SELECT status FROM uptime.check_runs WHERE id=$1`,
		res3.RunID).Scan(&runStatus)
	if runStatus != "RESERVED" {
		t.Fatalf("canceled job's reservation not recoverable: %s", runStatus)
	}
}
