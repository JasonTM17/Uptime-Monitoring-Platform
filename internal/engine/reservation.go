package engine

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// AdmissionCaps bounds the rolling 60-second charge window. Every
// committed reservation counts --- status is irrelevant (F02: no refund).
type AdmissionCaps struct {
	OwnerPer60s  int
	GlobalPer60s int
}

var (
	ErrAdmissionFull = errors.New("engine: admission window capacity reached")
	// ErrOwnerAdmissionFull denies only this owner's window  -  other
	// owners' due work may still fit the global cap in the same tick.
	ErrOwnerAdmissionFull = errors.New("engine: owner admission window capacity reached")
	ErrActiveRun          = errors.New("engine: monitor already has an active run")
	ErrMonitorNotDue      = errors.New("engine: monitor not admittable")
	ErrStaleGeneration    = errors.New("engine: monitor generation changed")
	ErrNoBudget           = errors.New("engine: quota budget row missing")
)

// Reservation is a committed check_run plus the schedule state it
// advanced --- the caller may enqueue work only AFTER Commit.
type Reservation struct {
	RunID      uuid.UUID
	MonitorID  uuid.UUID
	OwnerID    uuid.UUID
	SegmentID  uuid.UUID
	SlotAt     time.Time
	Sequence   int64
	Epoch      int64
	Generation int64
	NextDueAt  time.Time
}

// ReserveRun durably commits one run for monitorID inside a single
// transaction on the OWNER connection. Lock order is fixed:
// users --- quota_budgets --- monitor --- matching monitor.Create so a
// reservation and a mutation can never deadlock in opposite order.
//
// Atomicity: a committed row is a charge (no refund) AND a schedule
// advance; a rollback is neither. The caller enqueues only after this
// returns nil --- never before.
func ReserveRun(ctx context.Context, conn *pgx.Conn, monitorID uuid.UUID,
	expectedGen int64, caps AdmissionCaps, epoch int64) (*Reservation, error) {

	tx, err := conn.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	// 1) user row --- first lock; also the owner-scope discriminator.
	var ownerID uuid.UUID
	var userStatus string
	if err := tx.QueryRow(ctx,
		`SELECT user_id,u.status FROM uptime.monitors m
		 JOIN uptime.users u ON u.id=m.user_id
		 WHERE m.id=$1 FOR UPDATE OF u`, monitorID).
		Scan(&ownerID, &userStatus); err != nil {
		return nil, fmt.Errorf("lock owner: %w", err)
	}
	if userStatus != "ACTIVE" {
		return nil, ErrMonitorNotDue
	}

	// 2) global quota budget row --- fail closed if never seeded. A
	//    SELECT via Exec cannot see the missing row (command tags
	//    never carry ErrNoRows) --- scan it.
	var budget int
	if err := tx.QueryRow(ctx,
		`SELECT global_monitor_limit FROM uptime.quota_budgets WHERE id=1 FOR UPDATE`).
		Scan(&budget); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNoBudget
		}
		return nil, fmt.Errorf("lock budget: %w", err)
	}

	// 3) monitor row --- recheck admissibility under lock.
	var (
		gen       int64
		lastSeq   int64
		intervalS int
		paused    bool
		deleted   *time.Time
		dueNow    bool
	)
	err = tx.QueryRow(ctx, `
		SELECT generation,last_reserved_sequence,
		       interval_seconds,is_paused,deleted_at,
		       next_check_at <= clock_timestamp()
		FROM uptime.monitors WHERE id=$1 FOR UPDATE`, monitorID).
		Scan(&gen, &lastSeq, &intervalS, &paused,
			&deleted, &dueNow)
	if err != nil {
		return nil, fmt.Errorf("lock monitor: %w", err)
	}
	if deleted != nil || paused {
		return nil, ErrMonitorNotDue
	}
	// Recheck the select-time generation under lock: a mutation
	// committed in the SelectDue->reserve gap must not be honored
	// against the stale candidate projection. Due-ness is rechecked at
	// step 6, after the admission and active-run fences.
	if gen != expectedGen {
		return nil, ErrStaleGeneration
	}

	// 4) rolling-60s admission: owner scope, then global. Every status
	// counts --- a committed reservation is a charge.
	var ownerCount, globalCount int
	if err := tx.QueryRow(ctx, `
		SELECT count(*) FROM uptime.check_runs r
		JOIN uptime.monitors m ON m.id=r.monitor_id
		WHERE m.user_id=$1
		  AND r.reserved_at > clock_timestamp()-interval '60 seconds'`,
		ownerID).Scan(&ownerCount); err != nil {
		return nil, err
	}
	if ownerCount >= caps.OwnerPer60s {
		return nil, ErrOwnerAdmissionFull
	}
	if err := tx.QueryRow(ctx, `
		SELECT count(*) FROM uptime.check_runs
		WHERE reserved_at > clock_timestamp()-interval '60 seconds'`).
		Scan(&globalCount); err != nil {
		return nil, err
	}
	if globalCount >= caps.GlobalPer60s {
		return nil, ErrAdmissionFull
	}

	// 5) One in-flight run per monitor: an unfinished run means the
	//    scheduler must wait for finalize, not reserve again. Checked
	//    under the monitor lock; the partial unique index still fences
	//    any race the lock misses.
	var active int
	if err := tx.QueryRow(ctx, `
		SELECT count(*) FROM uptime.check_runs
		WHERE monitor_id=$1 AND status IN ('RESERVED','RUNNING')`,
		monitorID).Scan(&active); err != nil {
		return nil, err
	}
	if active > 0 {
		return nil, ErrActiveRun
	}

	// 6) Due-ness recheck under lock --- a mutation or a rival reserve
	//    committed in the SelectDue->reserve gap must not be honored
	//    against the stale candidate projection. Compared on the DB
	//    clock (single clock authority with the charged slot/advance),
	//    not the app clock.
	if !dueNow {
		return nil, ErrMonitorNotDue
	}

	// 7) Current segment --- engine-owned lifecycle: open one under the
	// CURRENT generation if missing or stale (a mutation closes it by
	// bumping generation; a stale open segment is closed here, same tx).
	var segID uuid.UUID
	var segGen int64
	err = tx.QueryRow(ctx, `
		SELECT id,generation FROM uptime.schedule_segments
		WHERE monitor_id=$1 AND ends_at IS NULL`, monitorID).
		Scan(&segID, &segGen)
	if err == nil && segGen != gen {
		if _, cerr := tx.Exec(ctx, `
			UPDATE uptime.schedule_segments SET ends_at=clock_timestamp()
			WHERE id=$1`, segID); cerr != nil {
			return nil, cerr
		}
		err = pgx.ErrNoRows
	}
	if err == pgx.ErrNoRows {
		// The segment anchors at the owed slot, not the reserve
		// instant: next_check_at is the first nominal slot the run
		// lattice charges, so starting coverage there keeps every
		// run slot inside its segment and the ExpectedSlots grid on
		// the same phase — no slot can fall outside all coverage.
		if cerr := tx.QueryRow(ctx, `
			INSERT INTO uptime.schedule_segments
			  (id,monitor_id,generation,starts_at,interval_seconds)
			SELECT gen_random_uuid(),$1,$2,
			       LEAST(clock_timestamp(), m.next_check_at),$3
			FROM uptime.monitors m WHERE m.id=$1
			RETURNING id`, monitorID, gen, intervalS).Scan(&segID); cerr != nil {
			return nil, cerr
		}
	} else if err != nil {
		return nil, fmt.Errorf("current segment: %w", err)
	}

	// 8) Latest nominal slot <= now inside this segment: an overdue
	// monitor charges the owed next_check_at; an early call charges
	// now. reserved_at is the DB clock taken AFTER the locks.
	seq := lastSeq + 1
	var runID uuid.UUID
	var slotAt, reservedAt time.Time
	err = tx.QueryRow(ctx, `
		INSERT INTO uptime.check_runs
		  (id,monitor_id,segment_id,slot_at,generation,sequence,
		   engine_epoch,status,reserved_at)
		SELECT gen_random_uuid(),$1,$2,
		       CASE WHEN m.next_check_at <= clock_timestamp()
		            THEN m.next_check_at ELSE clock_timestamp() END,
		       $3,$4,$5,'RESERVED',clock_timestamp()
		FROM uptime.monitors m WHERE m.id=$1
		RETURNING id, slot_at, reserved_at`,
		monitorID, segID, gen, seq, epoch).
		Scan(&runID, &slotAt, &reservedAt)
	if err != nil {
		return nil, fmt.Errorf("insert run: %w", err)
	}

	// AdvanceSchedule, same tx: next_due is the first cadence-aligned
	// slot strictly after reserved_at - every older slot is missed,
	// never caught up. Rollback revokes charge AND advance together.
	interval := time.Duration(intervalS) * time.Second
	advanceTo := slotAt
	for !advanceTo.After(reservedAt) {
		advanceTo = advanceTo.Add(interval)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE uptime.monitors
		SET last_reserved_sequence=$2, next_check_at=$3
		WHERE id=$1`, monitorID, seq, advanceTo); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &Reservation{
		RunID: runID, MonitorID: monitorID, OwnerID: ownerID,
		SegmentID: segID, SlotAt: slotAt, Sequence: seq,
		Epoch: epoch, Generation: gen, NextDueAt: advanceTo,
	}, nil
}
