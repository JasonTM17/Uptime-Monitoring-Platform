//go:build integration

package engine

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Capacity protocol (frozen per C80): 10 workers, queue 20, 60s
// cadence. These tests pin the mechanical bounds the report measures
// — the composition-root config in production is identical, so the
// invariants are the contract, not a tuned-for-test variant.
const (
	capWorkers = 10
	capQueue   = 20
)

// seedDueN seeds n due monitors spread across ceil(n/perOwner)
// owners — owner spread mirrors production fan-in so the round-robin
// path is exercised, not just the single-owner fast path.
func seedDueN(t *testing.T, n, perOwner int) []uuid.UUID {
	t.Helper()
	conn := engineConn(t)
	ctx := context.Background()
	if _, err := conn.Exec(ctx, `
		INSERT INTO uptime.quota_budgets(id,global_monitor_limit)
		VALUES (1,1000) ON CONFLICT (id) DO NOTHING`); err != nil {
		t.Fatal(err)
	}
	var ids []uuid.UUID
	var userID uuid.UUID
	for i := 0; i < n; i++ {
		if i%perOwner == 0 {
			if err := conn.QueryRow(ctx, `
				INSERT INTO uptime.users(id,email,password_hash,status,monitor_limit)
				VALUES (gen_random_uuid(),$1,'x','ACTIVE',1000) RETURNING id`,
				"cap+"+uuid.NewString()[:8]+"@test.invalid").Scan(&userID); err != nil {
				t.Fatal(err)
			}
		}
		var monID uuid.UUID
		if err := conn.QueryRow(ctx, `
			INSERT INTO uptime.monitors(id,user_id,name,target_url,method,
			  interval_seconds,timeout_seconds,expected_status,next_check_at)
			VALUES (gen_random_uuid(),$1,'m','https://x.test','GET',60,5,NULL,now()-interval '1 second')
			RETURNING id`, userID).Scan(&monID); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, monID)
	}
	return ids
}

func openRuns(t *testing.T, conn *pgx.Conn) int {
	t.Helper()
	var n int
	if err := conn.QueryRow(context.Background(),
		`SELECT count(*) FROM uptime.check_runs
		 WHERE status IN ('RESERVED','RUNNING')`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// In-flight ceiling is queue + workers at any instant; due work the
// scheduler could not admit must stay due — never dropped.
func TestCapacityBounds(t *testing.T) {
	ctx := context.Background()
	conn := engineConn(t)
	cleanEngine(t, conn)

	owner, err := AcquireOwner(ctx, conn, uuid.New())
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Release(ctx)
	w := NewWriter(owner, time.Minute)

	block := make(chan struct{})
	fc := &fakeChecker{block: block}
	pool := NewWorkerPool(capWorkers, capQueue, fc)
	pctx, pcancel := context.WithCancel(ctx)
	defer pcancel()
	pool.Start(pctx)
	go func() {
		for range pool.Results() {
		}
	}()

	caps := AdmissionCaps{OwnerPer60s: 1000, GlobalPer60s: 1000}
	s := NewScheduler(w, pool, owner.Epoch(), caps, 100)

	const total = 40 // > queue+workers so capacity gating must engage
	seedDueN(t, total, 5)

	maxQueue, maxOpen := 0, 0
	admitted := 0
	for i := 0; i < 10 && admitted < total; i++ {
		n, err := s.Tick(ctx)
		if err != nil {
			t.Fatalf("tick %d: %v", i, err)
		}
		admitted += n
		if b := pool.BusyWorkers(); b > capWorkers {
			t.Fatalf("busy workers %d exceed pool %d", b, capWorkers)
		}
		if q := pool.QueueDepth(); q > capQueue {
			t.Fatalf("queue depth %d exceeds bound %d", q, capQueue)
		} else if q > maxQueue {
			maxQueue = q
		}
		if o := openRuns(t, conn); o > maxOpen {
			maxOpen = o
		}
		if o := openRuns(t, conn); o > capWorkers+capQueue {
			t.Fatalf("in-flight runs %d exceed queue+worker bound", o)
		}
	}
	if admitted > capWorkers+capQueue {
		t.Fatalf("admitted %d exceeds in-flight bound %d", admitted, capWorkers+capQueue)
	}
	// What could not be admitted stayed due — nothing was dropped.
	var due int
	conn.QueryRow(ctx,
		`SELECT count(*) FROM uptime.monitors WHERE next_check_at <= now()`).Scan(&due)
	if want := total - admitted; due != want {
		t.Fatalf("unadmitted work lost: due=%d want %d", due, want)
	}

	close(block)
	deadline := time.Now().Add(10 * time.Second)
	for admitted < total && time.Now().Before(deadline) {
		n, err := s.Tick(ctx)
		if err != nil {
			t.Fatal(err)
		}
		admitted += n
		time.Sleep(25 * time.Millisecond)
	}
	if admitted != total {
		t.Fatalf("admitted %d want %d after drain", admitted, total)
	}
	deadline = time.Now().Add(5 * time.Second)
	for atomic.LoadInt32(&fc.calls) < int32(total) && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if c := atomic.LoadInt32(&fc.calls); c != int32(total) {
		t.Fatalf("executed %d checks want %d", c, total)
	}
	if int(fc.peaked) > capWorkers {
		t.Fatalf("peak concurrency %d exceeds workers", fc.peaked)
	}
	fc.mu.Lock()
	unique := len(fc.targets)
	fc.mu.Unlock()
	if unique != total {
		t.Fatalf("duplicate or missed monitors: %d unique of %d", unique, total)
	}
	if maxOpen > capWorkers+capQueue {
		t.Fatalf("observed in-flight ceiling %d over bound", maxOpen)
	}
	pcancel()
	pool.Wait()
}

// One owner with more due work than workers must saturate the whole
// pool — admission budgets are per-window counts, not a per-owner
// concurrency cap.
func TestSingleOwnerUsesAvailableWorkers(t *testing.T) {
	ctx := context.Background()
	conn := engineConn(t)
	cleanEngine(t, conn)

	owner, err := AcquireOwner(ctx, conn, uuid.New())
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Release(ctx)
	w := NewWriter(owner, time.Minute)

	block := make(chan struct{})
	defer close(block)
	fc := &fakeChecker{block: block}
	pool := NewWorkerPool(capWorkers, capQueue, fc)
	pctx, pcancel := context.WithCancel(ctx)
	defer pcancel()
	pool.Start(pctx)
	go func() {
		for range pool.Results() {
		}
	}()

	caps := AdmissionCaps{OwnerPer60s: 100, GlobalPer60s: 100}
	s := NewScheduler(w, pool, owner.Epoch(), caps, 100)

	// 12 due monitors, ONE user — more than the worker count.
	seedDueN(t, 12, 12)
	if n, err := s.Tick(ctx); err != nil || n != 12 {
		t.Fatalf("tick admitted %d of 12 (err=%v)", n, err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for atomic.LoadInt32(&fc.peaked) < capWorkers && time.Now().Before(deadline) {
		time.Sleep(15 * time.Millisecond)
	}
	if p := atomic.LoadInt32(&fc.peaked); int(p) != capWorkers {
		t.Fatalf("single owner peaked at %d workers, want %d", p, capWorkers)
	}
	var reserved int
	conn.QueryRow(ctx, `SELECT count(*) FROM uptime.check_runs WHERE status='RESERVED'`).Scan(&reserved)
	if reserved != 12 {
		t.Fatalf("RESERVED rows %d, want all 12 committed", reserved)
	}
	pcancel()
	pool.Wait()
}

// Crash after committed reservations: the takeover epoch reconciles
// the orphans to INTERRUPTED in one bounded UPDATE, the already-
// advanced schedule is preserved (no refund => no catch-up storm),
// and zero evidence is fabricated for the missed slots.
func TestReservationCrashRecovery(t *testing.T) {
	ctx := context.Background()
	c1 := engineConn(t)
	cleanEngine(t, c1)
	c2 := engineConn(t)

	o1, err := AcquireOwner(ctx, c1, uuid.New())
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	e1 := o1.Epoch()

	mons := seedDueN(t, 6, 3)
	var runIDs []uuid.UUID
	for i, monID := range mons {
		res, err := ReserveRun(ctx, c1, monID, 1, caps, e1)
		if err != nil {
			t.Fatalf("reserve %d: %v", i, err)
		}
		runIDs = append(runIDs, res.RunID)
	}
	// Two had started executing when the process died.
	for _, id := range runIDs[:2] {
		if _, err := c1.Exec(ctx,
			`UPDATE uptime.check_runs SET status='RUNNING' WHERE id=$1`, id); err != nil {
			t.Fatal(err)
		}
	}
	// Reservations already advanced the schedule — recovery must not
	// refund it into a catch-up storm.
	var dueNow int
	c1.QueryRow(ctx, `SELECT count(*) FROM uptime.monitors WHERE next_check_at <= now()`).Scan(&dueNow)
	if dueNow != 0 {
		t.Fatalf("schedule not advanced by reservations: %d still due", dueNow)
	}

	killBackend(t, c2, c1) // process crash: session + advisory lock die

	o2, err := AcquireOwner(ctx, c2, uuid.New())
	if err != nil {
		t.Fatalf("takeover: %v", err)
	}
	defer o2.Release(ctx)
	if o2.Epoch() <= e1 {
		t.Fatalf("epoch not fenced: %d -> %d", e1, o2.Epoch())
	}

	n, err := ReconcileInterrupted(ctx, c2, o2.Epoch())
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if n != int64(len(runIDs)) {
		t.Fatalf("reconciled %d orphan runs, want %d", n, len(runIDs))
	}

	var interrupted, results, incidents, outbox, due int
	var reason string
	c2.QueryRow(ctx, `SELECT count(*) FROM uptime.check_runs
		WHERE status='INTERRUPTED' AND terminal_reason='engine_takeover'`).Scan(&interrupted)
	c2.QueryRow(ctx, `SELECT count(*) FROM uptime.check_results`).Scan(&results)
	c2.QueryRow(ctx, `SELECT count(*) FROM uptime.incidents`).Scan(&incidents)
	c2.QueryRow(ctx, `SELECT count(*) FROM uptime.notification_outbox`).Scan(&outbox)
	c2.QueryRow(ctx, `SELECT count(*) FROM uptime.monitors WHERE next_check_at <= now()`).Scan(&due)
	if interrupted != len(runIDs) || results != 0 || incidents != 0 || outbox != 0 {
		t.Fatalf("fabricated evidence: interrupted=%d results=%d inc=%d out=%d",
			interrupted, results, incidents, outbox)
	}
	if due != 0 {
		t.Fatalf("catch-up storm: %d monitors immediately due post-takeover", due)
	}
	if err := c2.QueryRow(ctx,
		`SELECT terminal_reason FROM uptime.check_runs WHERE id=$1`,
		runIDs[0]).Scan(&reason); err != nil || reason != "engine_takeover" {
		t.Fatalf("orphan not dispositioned: %v %q", err, reason)
	}
}

// When the owner loses its lease (connection death => lock death),
// the dead writer must refuse further work: Exec gates on liveness,
// and an in-flight finalize that never committed stays uncommitted.
func TestOwnerLossStopsWrites(t *testing.T) {
	ctx := context.Background()
	c1 := engineConn(t)
	cleanEngine(t, c1)
	c2 := engineConn(t)

	o1, err := AcquireOwner(ctx, c1, uuid.New())
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	var backendPID int
	if err := c1.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&backendPID); err != nil {
		t.Fatal(err)
	}
	w1 := NewWriter(o1, 50*time.Millisecond)
	go w1.Run(ctx)
	deadline := time.Now().Add(2 * time.Second)
	for w1.Alive() && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if !w1.Alive() {
		t.Fatal("writer died before the kill")
	}

	_, monID := seedDue(t)
	// Reserve on c2: c1 is the running writer's conn and a pgx.Conn
	// must not be shared between goroutines. Fencing rides on the
	// epoch value, not the connection identity.
	res, err := ReserveRun(ctx, c2, monID, 1, caps, o1.Epoch())
	if err != nil {
		t.Fatalf("reserve: %v", err)
	}
	identity := FinalizeIdentity{
		RunID: res.RunID, MonitorID: monID, OwnerID: res.OwnerID,
		SegmentID: res.SegmentID, Generation: res.Generation,
		Sequence: res.Sequence, Epoch: o1.Epoch(),
	}

	// Same discipline for the kill: terminate the pid captured
	// before the writer started rather than querying c1 again.
	if _, err := c2.Exec(ctx, "SELECT pg_terminate_backend($1)", backendPID); err != nil {
		t.Fatalf("terminate backend: %v", err)
	}
	deadline = time.Now().Add(3 * time.Second)
	for w1.Alive() && time.Now().Before(deadline) {
		time.Sleep(25 * time.Millisecond)
	}
	if w1.Alive() {
		t.Fatal("writer still believes it owns a dead lease")
	}

	// The dead writer refuses both the generic Exec path and the
	// finalize path — nothing lands.
	if err := w1.Exec(ctx, func(ctx context.Context, conn *pgx.Conn) error {
		_, e := conn.Exec(ctx, `UPDATE uptime.monitors SET name='LEAKED' WHERE id=$1`, monID)
		return e
	}); err != ErrOwnerLost {
		t.Fatalf("dead writer Exec: %v", err)
	}
	if _, err := w1.FinalizeObservation(ctx, FinalizeInput{
		Identity: identity, Observation: okObservation(t, monID)}); err != ErrOwnerLost {
		t.Fatalf("dead writer finalize: %v", err)
	}

	var status, name string
	var results, incs, outs int
	c2.QueryRow(ctx, `SELECT status FROM uptime.check_runs WHERE id=$1`, res.RunID).Scan(&status)
	c2.QueryRow(ctx, `SELECT name FROM uptime.monitors WHERE id=$1`, monID).Scan(&name)
	c2.QueryRow(ctx, `SELECT count(*) FROM uptime.check_results WHERE check_id=$1`, res.RunID).Scan(&results)
	c2.QueryRow(ctx, `SELECT count(*) FROM uptime.incidents WHERE monitor_id=$1`, monID).Scan(&incs)
	c2.QueryRow(ctx, `SELECT count(*) FROM uptime.notification_outbox WHERE monitor_id=$1`, monID).Scan(&outs)
	if status != "RESERVED" || name == "LEAKED" || results != 0 || incs != 0 || outs != 0 {
		t.Fatalf("dead writer leaked: run=%s name=%q results=%d inc=%d out=%d",
			status, name, results, incs, outs)
	}
}
