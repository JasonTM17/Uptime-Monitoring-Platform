package engine

import (
	"context"
	"errors"
	"sort"
	"time"

	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/checker"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Clock makes ticks and slot math testable without sleeps.
type Clock interface {
	Now() time.Time
}

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

// DueMonitor is the scheduler's read-side projection of a monitor row.
type DueMonitor struct {
	MonitorID       uuid.UUID
	OwnerID         uuid.UUID
	TargetURL       string
	ExpectedStatus  *int
	TimeoutSeconds  int
	IntervalSeconds int
	Generation      int64
	NextCheckAt     time.Time
}

// SelectDue returns at most `limit` monitors whose next_check_at is
// at/before now --- excluding paused/deleted rows and any monitor with
// an in-flight reservation. Bounded query on the monitors_due index;
// no whole-table scans, no per-monitor queries.
func SelectDue(ctx context.Context, conn *pgx.Conn, now time.Time, limit int) ([]DueMonitor, error) {
	rows, err := conn.Query(ctx, `
		SELECT m.id, m.user_id, m.target_url, m.expected_status,
		       m.timeout_seconds, m.interval_seconds, m.generation,
		       m.next_check_at
		FROM uptime.monitors m
		JOIN uptime.users u ON u.id = m.user_id AND u.status='ACTIVE'
		WHERE m.next_check_at <= $1
		  AND NOT m.is_paused
		  AND m.deleted_at IS NULL
		  AND NOT EXISTS (
		    SELECT 1 FROM uptime.check_runs r
		    WHERE r.monitor_id = m.id
		      AND r.status IN ('RESERVED','RUNNING'))
		ORDER BY m.next_check_at, m.id
		LIMIT $2`, now, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DueMonitor
	for rows.Next() {
		var d DueMonitor
		if err := rows.Scan(&d.MonitorID, &d.OwnerID, &d.TargetURL,
			&d.ExpectedStatus, &d.TimeoutSeconds, &d.IntervalSeconds,
			&d.Generation, &d.NextCheckAt); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// RoundRobinOwners interleaves due candidates one-per-owner per round,
// deterministically: owners sorted by ID, rotated so the owner after
// `lastServed` leads. Single-owner input passes through unchanged ---
// fairness never caps one owner's utilization (F02).
func RoundRobinOwners(due []DueMonitor, lastServed uuid.UUID) []DueMonitor {
	if len(due) == 0 {
		return nil
	}
	byOwner := map[uuid.UUID][]DueMonitor{}
	var owners []uuid.UUID
	for _, d := range due {
		if _, seen := byOwner[d.OwnerID]; !seen {
			owners = append(owners, d.OwnerID)
		}
		byOwner[d.OwnerID] = append(byOwner[d.OwnerID], d)
	}
	sort.Slice(owners, func(i, j int) bool {
		return owners[i].String() < owners[j].String()
	})
	// Rotate: start after lastServed so a served owner goes to the back.
	start := 0
	for i, o := range owners {
		if o == lastServed {
			start = (i + 1) % len(owners)
			break
		}
	}
	out := make([]DueMonitor, 0, len(due))
	for round := 0; len(out) < len(due); round++ {
		for k := 0; k < len(owners); k++ {
			o := owners[(start+k)%len(owners)]
			if round < len(byOwner[o]) {
				out = append(out, byOwner[o][round])
			}
		}
	}
	return out
}

// Scheduler coordinates bounded due-selection, fair admission, and
// enqueue. It is the only caller of Submit --- workers never produce.
type Scheduler struct {
	writer     *Writer
	pool       *WorkerPool
	caps       AdmissionCaps
	batchLimit int
	clock      Clock
	lastOwner  uuid.UUID
	lastErr    error    // last denied reservation - diagnostic only
	metrics    Counters // nil-tolerant instrumentation seam

	// Seams for deterministic unit tests; production wires the real
	// DB-backed implementations in NewScheduler.
	selectDue func(ctx context.Context) ([]DueMonitor, error)
	reserve   func(ctx context.Context, d DueMonitor) (*Reservation, error)
}

func NewScheduler(w *Writer, pool *WorkerPool, epoch int64,
	caps AdmissionCaps, batchLimit int) *Scheduler {
	s := &Scheduler{
		writer: w, pool: pool, caps: caps,
		batchLimit: batchLimit, clock: realClock{},
	}
	s.selectDue = func(ctx context.Context) ([]DueMonitor, error) {
		var due []DueMonitor
		err := w.Exec(ctx, func(ctx context.Context, conn *pgx.Conn) error {
			var e error
			due, e = SelectDue(ctx, conn, s.clock.Now(), s.batchLimit)
			return e
		})
		return due, err
	}
	s.reserve = func(ctx context.Context, d DueMonitor) (*Reservation, error) {
		var res *Reservation
		err := w.Exec(ctx, func(ctx context.Context, conn *pgx.Conn) error {
			var e error
			res, e = ReserveRun(ctx, conn, d.MonitorID, d.Generation, s.caps, epoch)
			return e
		})
		return res, err
	}
	return s
}

// SetClock swaps the tick clock (tests); SetDueSource/SetReserver swap
// the DB seams for deterministic traces.
func (s *Scheduler) SetClock(c Clock) { s.clock = c }
func (s *Scheduler) SetDueSource(f func(context.Context) ([]DueMonitor, error)) {
	s.selectDue = f
}
func (s *Scheduler) SetReserver(f func(context.Context, DueMonitor) (*Reservation, error)) {
	s.reserve = f
}

// SetCounters attaches the metrics seam. Nil disables instrumentation.
func (s *Scheduler) SetCounters(c Counters) { s.metrics = c }

// markStale is the TrySubmit-false compensation: a committed
// reservation that can never be attempted is terminalized STALE so
// the monitor stays schedulable. Best-effort through the writer.
func (s *Scheduler) markStale(runID uuid.UUID) {
	if s.writer == nil {
		return
	}
	_ = s.writer.Exec(context.Background(), func(ctx context.Context,
		conn *pgx.Conn) error {
		tx, err := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
		if err != nil {
			return err
		}
		defer tx.Rollback(ctx)
		if _, err := MarkStaleRun(ctx, tx, runID, "STALE",
			"queue_rejected"); err != nil {
			return err
		}
		return tx.Commit(ctx)
	})
}

// LastErr exposes the most recent denied reservation for tests and
// operational diagnostics; nil when the last round had no denial.
func (s *Scheduler) LastErr() error { return s.lastErr }

// Tick runs one bounded admission round: fetch due candidates, order
// them fairly, then reserve+enqueue while capacity exists. A full
// queue or full window stops the round --- due monitors stay in the DB
// for the next tick; there is no catch-up amplification.
func (s *Scheduler) Tick(ctx context.Context) (admitted int, err error) {
	due, err := s.selectDue(ctx)
	if err != nil {
		return 0, err
	}
	for _, cand := range RoundRobinOwners(due, s.lastOwner) {
		if ctx.Err() != nil {
			return admitted, ctx.Err()
		}
		// Capacity BEFORE reserving: the scheduler is the only
		// producer, so a positive reading guarantees TrySubmit succeeds.
		if s.pool.Capacity() <= 0 {
			if s.metrics != nil {
				s.metrics.RecordDenial(DenialQueueFull)
			}
			return admitted, nil
		}
		res, err := s.reserve(ctx, cand)
		switch {
		case errors.Is(err, ErrAdmissionFull):
			s.lastErr = err // global window saturated --- stop
			if s.metrics != nil {
				s.metrics.RecordDenial(DenialGlobalWindow)
			}
			s.lastOwner = cand.OwnerID // rotate past the denied owner
			return admitted, nil
		case errors.Is(err, ErrOwnerAdmissionFull):
			s.lastErr = err // one owner's window --- skip, serve others
			if s.metrics != nil {
				s.metrics.RecordDenial(DenialOwnerWindow)
			}
			// Rotate past the saturated owner so the next tick does not
			// re-probe it first while its rolling window is still full.
			s.lastOwner = cand.OwnerID
			continue
		case err != nil:
			s.lastErr = err
			continue // not due / raced / inactive --- move to next candidate
		}
		job := Job{
			RunID: res.RunID, MonitorID: res.MonitorID,
			OwnerID: res.OwnerID, SegmentID: res.SegmentID,
			Sequence: res.Sequence, Epoch: res.Epoch, Generation: res.Generation,
			SlotAt: res.SlotAt,
			Target: checker.Target{
				MonitorID:      res.MonitorID,
				URL:            cand.TargetURL,
				ExpectedStatus: cand.ExpectedStatus,
				TimeoutSeconds: cand.TimeoutSeconds,
			},
		}
		if !s.pool.TrySubmit(job) {
			// Invariant: sole producer + capacity gate above makes a
			// full queue unreachable; a closed pool means shutdown is
			// already draining. Either way the committed reservation
			// must not pin the monitor's one-active slot --- mark it
			// STALE now rather than wait for the next takeover's
			// reconciliation.
			s.lastErr = ErrEngineStopped
			if s.metrics != nil {
				s.metrics.RecordDenial(DenialQueueFull)
			}
			s.markStale(res.RunID)
			s.lastOwner = cand.OwnerID
			return admitted, nil
		}
		s.lastOwner = cand.OwnerID
		admitted++
		if s.metrics != nil {
			s.metrics.RecordAdmissions(1)
		}
	}
	return admitted, nil
}
