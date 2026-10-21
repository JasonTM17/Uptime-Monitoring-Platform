package engine

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// EngineParams configures one assembled engine instance.
type EngineParams struct {
	TickEvery       time.Duration // scheduler cadence between bounded ticks
	BatchLimit      int           // SelectDue bound per tick
	Workers         int           // fixed worker count
	QueueSize       int           // bounded job AND result channel depth
	Caps            AdmissionCaps // rolling-60s admission budgets
	HeartbeatEvery  time.Duration // owner-liveness write cadence
	FinalizeTimeout time.Duration // per-result finalize bound
	Metrics         Counters      // nil = uninstrumented
}

var ErrEngineStopped = errors.New("engine: not accepting work")

// Engine is the assembled monitoring engine: one owner connection
// (advisory lock + epoch), one writer, one scheduler (sole job
// producer), a bounded worker pool, and one coordinator (sole result
// consumer, finalizing through the writer). PostgreSQL remains the
// only authority; these goroutines coordinate lifecycle only.
//
// Shutdown order is fixed and bounded by the caller's deadline:
//  1. readiness flips false and admission stops,
//  2. the scheduler loop exits, THEN the sole producer closes jobs,
//  3. workers drain within the deadline; a forced deadline cancels
//     in-flight attempts (their reservations stay recoverable),
//  4. the coordinator waits the worker WaitGroup before result
//     consumption ends; buffered leftovers finalize inside the
//     remaining budget or stay RESERVED for takeover,
//  5. heartbeat stops, the advisory lock releases, the dedicated
//     connection closes — always last, never before writes settle.
type Engine struct {
	conn   *pgx.Conn
	owner  *Owner
	writer *Writer
	pool   *WorkerPool
	sched  *Scheduler

	finalizeTimeout time.Duration
	metrics         Counters
	ready           atomic.Bool

	tickCtx    context.Context
	cancelTick context.CancelFunc
	tickDone   chan struct{}

	workerCtx    context.Context
	cancelWorker context.CancelFunc

	coordStop chan struct{}
	coordDone chan struct{}
	coordOnce sync.Once

	lastErr atomic.Value // error  -  most recent finalize failure

	once    sync.Once
	shutErr error
}

// StartEngine acquires ownership, reconciles the prior epoch's
// orphans, and launches the three lifecycle goroutines. The returned
// Engine owns conn — Shutdown releases the lock and closes it.
func StartEngine(ctx context.Context, conn *pgx.Conn, instance uuid.UUID,
	p EngineParams, ch Checker) (*Engine, error) {
	if p.TickEvery <= 0 || p.BatchLimit <= 0 || p.Workers <= 0 ||
		p.QueueSize <= 0 || p.HeartbeatEvery <= 0 || p.FinalizeTimeout <= 0 {
		return nil, errors.New("engine: invalid EngineParams (all bounds must be positive)")
	}
	owner, err := AcquireOwner(ctx, conn, instance)
	if err != nil {
		return nil, err
	}
	if _, err := ReconcileInterrupted(ctx, conn, owner.Epoch()); err != nil {
		_ = owner.Release(ctx)
		return nil, err
	}

	e := &Engine{
		conn:            conn,
		owner:           owner,
		writer:          NewWriter(owner, p.HeartbeatEvery),
		finalizeTimeout: p.FinalizeTimeout,
		metrics:         p.Metrics,
		tickDone:        make(chan struct{}),
		coordStop:       make(chan struct{}),
		coordDone:       make(chan struct{}),
	}
	e.tickCtx, e.cancelTick = context.WithCancel(context.Background())
	e.workerCtx, e.cancelWorker = context.WithCancel(context.Background())

	e.pool = NewWorkerPool(p.Workers, p.QueueSize, ch)
	e.pool.SetCounters(p.Metrics)
	e.pool.Start(e.workerCtx)
	e.sched = NewScheduler(e.writer, e.pool, owner.Epoch(), p.Caps, p.BatchLimit)
	e.sched.SetCounters(p.Metrics)
	e.writer.SetCounters(p.Metrics)

	e.ready.Store(true)
	go e.runScheduler(p.TickEvery)
	go e.runCoordinator()
	go e.writer.Run(e.tickCtx)
	// Ownership death quiesces the engine: a dead writer can never
	// write again  -  stop admission and the coordinator rather than
	// spin forever producing guaranteed-fenced work.
	go func() {
		<-e.writer.Done()
		if !e.writer.Alive() {
			e.ready.Store(false)
			e.cancelTick()
			e.coordOnce.Do(func() { close(e.coordStop) })
		}
	}()
	return e, nil
}

// Ready is the engine's contribution to /health/ready: false as soon
// as shutdown begins (before any drain), false after ownership dies.
func (e *Engine) Ready(context.Context) error {
	if !e.ready.Load() || !e.writer.Alive() {
		return ErrEngineStopped
	}
	return nil
}

// State exposes the immutable ownership snapshot for diagnostics.
func (e *Engine) State() OwnerState { return e.writer.State() }

// EngineGauges is the scrape-time read of engine internals: queue
// occupancy, worker utilization, configured workers, and owner
// liveness. All values are atomic reads --- collection never blocks
// or queries the database.
type EngineGauges struct {
	QueueDepth  int64
	WorkersBusy int64
	Workers     int64
	OwnerAlive  bool
}

// Gauges snapshots the engine's in-memory gauges.
func (e *Engine) Gauges() EngineGauges {
	return EngineGauges{
		QueueDepth:  int64(e.pool.QueueDepth()),
		WorkersBusy: e.pool.BusyWorkers(),
		Workers:     int64(e.pool.WorkerCount()),
		OwnerAlive:  e.writer.Alive(),
	}
}

// LastErr reports the most recent finalize failure, or nil  -  the
// diagnostic surface for errors the coordinator cannot return.
func (e *Engine) LastErr() error {
	if v := e.lastErr.Load(); v != nil {
		return v.(error)
	}
	return nil
}

func (e *Engine) runScheduler(every time.Duration) {
	defer close(e.tickDone)
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			_, _ = e.sched.Tick(e.tickCtx)
		case <-e.tickCtx.Done():
			return
		}
	}
}

func (e *Engine) runCoordinator() {
	defer close(e.coordDone)
	for {
		select {
		case r := <-e.pool.Results():
			e.finalize(context.Background(), r)
		case <-e.coordStop:
			return
		}
	}
}

// finalize commits one worker result through the owner writer with a
// per-result bound. Errors only lose THIS result — the reservation's
// durable state decides recovery, not the return value.
func (e *Engine) finalize(ctx context.Context, r Result) {
	fctx, cancel := context.WithTimeout(ctx, e.finalizeTimeout)
	defer cancel()
	outcome, ferr := e.writer.FinalizeObservation(fctx, FinalizeInput{
		Identity: FinalizeIdentity{
			RunID: r.Job.RunID, MonitorID: r.Job.MonitorID,
			OwnerID: r.Job.OwnerID, SegmentID: r.Job.SegmentID,
			Generation: r.Job.Generation, Sequence: r.Job.Sequence,
			Epoch: r.Job.Epoch,
		},
		Observation: r.Observation,
	})
	if e.metrics != nil {
		e.metrics.RecordFinalize(outcome, ferr == nil)
	}
	if ferr == nil {
		return
	}
	e.lastErr.Store(ferr)
	// A failed finalize leaves the run RESERVED  -  and one active run
	// pins the monitor forever. Best-effort STALE frees the slot; if
	// the commit actually landed, the terminal-status guard is a
	// no-op, so this is safe under commit ambiguity.
	_ = e.writer.Exec(context.Background(),
		func(ctx context.Context, conn *pgx.Conn) error {
			tx, err := conn.BeginTx(ctx, pgx.TxOptions{})
			if err != nil {
				return err
			}
			defer tx.Rollback(ctx)
			if _, err := MarkStaleRun(ctx, tx, r.Job.RunID,
				"STALE", "finalize_error"); err != nil {
				return err
			}
			return tx.Commit(ctx)
		})
}

// Shutdown runs the ordered, bounded stop. Idempotent: concurrent and
// repeated callers observe the same outcome. A forced deadline never
// corrupts state — in-flight work simply remains RESERVED until the
// next owner's reconciliation marks it INTERRUPTED.
func (e *Engine) Shutdown(ctx context.Context) error {
	e.once.Do(func() { e.shutErr = e.shutdown(ctx) })
	return e.shutErr
}

func (e *Engine) shutdown(ctx context.Context) error {
	// 1) readiness off + stop admission — always the first step.
	e.ready.Store(false)

	// 2) scheduler loop exits first; only then does the sole
	//    producer close jobs (a tick in-flight must never enqueue
	//    into a closed channel).
	e.cancelTick()
	select {
	case <-e.tickDone:
	case <-ctx.Done():
	}
	e.pool.CloseJobs()

	// 3) bounded worker drain — cancel attempts only when the
	//    deadline forces it. A worker that ignores cancellation is
	//    abandoned after a last-resort grace; its send drops on the
	//    dead context, never panics (results is never closed).
	workersDone := make(chan struct{})
	go func() { e.pool.Wait(); close(workersDone) }()
	select {
	case <-workersDone:
	case <-ctx.Done():
		e.cancelWorker()
		select {
		case <-workersDone:
		case <-time.After(2 * time.Second):
		}
	}

	// 4) coordinator waits the worker WaitGroup before result
	//    consumption ends. Leftover buffered results finalize inside
	//    the remaining budget, or stay RESERVED for the next owner.
	e.coordOnce.Do(func() { close(e.coordStop) })
	select {
	case <-e.coordDone:
	case <-ctx.Done():
	}
	for drained := false; !drained; {
		select {
		case r := <-e.pool.Results():
			if ctx.Err() == nil {
				e.finalize(ctx, r)
			}
		default:
			drained = true
		}
	}

	// 5) heartbeat stops, advisory lock releases, dedicated conn
	//    closes — the last DB operations, after every write settled.
	//    Fresh bounded ctx: lock release is cleanup, not work — it
	//    must still run when the caller's deadline is spent.
	relCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	e.writer.Stop(relCtx)
	return ctx.Err()
}
