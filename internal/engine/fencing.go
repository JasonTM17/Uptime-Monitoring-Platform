package engine

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// IdentityVerdict is the fence's decision about one incoming result.
type IdentityVerdict int

const (
	// IdentityValid - the result maps to the live active run under the
	// current generation and owner epoch; it may be committed.
	IdentityValid IdentityVerdict = iota
	// IdentityStale - the world moved on (generation bump, takeover,
	// monitor tombstone, owner disabled, superseded run): persist the
	// run as STALE and drop the result's health influence.
	IdentityStale
	// IdentityDuplicate - the run already holds a terminal disposition;
	// the result is a replay and must change nothing.
	IdentityDuplicate
)

func (v IdentityVerdict) String() string {
	switch v {
	case IdentityValid:
		return "valid"
	case IdentityStale:
		return "stale"
	case IdentityDuplicate:
		return "duplicate"
	}
	return "unknown"
}

// FinalizeIdentity is the proof a worker's result must carry: every
// field of the committed reservation it claims to answer.
type FinalizeIdentity struct {
	RunID      uuid.UUID
	MonitorID  uuid.UUID
	OwnerID    uuid.UUID
	SegmentID  uuid.UUID
	Generation int64
	Sequence   int64
	Epoch      int64
}

var ErrFenceRejected = errors.New("engine: result identity rejected")

// ValidateResultIdentity locks owner -> monitor -> run INSIDE the
// caller's transaction (same order as reservation; a finalizer and a
// mutation serialize on the monitor row lock - whichever commits
// first wins, and the loser sees the new state).
//
// Fences checked under lock, in order:
//  1. owner row exists and is ACTIVE,
//  2. monitor row exists and generation matches,
//  3. run exists, belongs to the monitor+segment, sequence+epoch match,
//  4. run is still active (else duplicate),
//  5. monitor not tombstoned.
func ValidateResultIdentity(ctx context.Context, tx pgx.Tx,
	ownerEpoch int64, id FinalizeIdentity) (IdentityVerdict, error) {

	// 1) owner user row FOR UPDATE - first lock.
	var uStatus string
	err := tx.QueryRow(ctx,
		`SELECT status FROM uptime.users WHERE id=$1 FOR UPDATE`,
		id.OwnerID).Scan(&uStatus)
	if err != nil {
		return IdentityStale, fmt.Errorf("lock owner: %w", err)
	}
	if uStatus != "ACTIVE" {
		return IdentityStale, nil
	}

	// 2) monitor row FOR UPDATE - generation + tombstone under lock.
	var mGen int64
	var mDeleted *time.Time
	err = tx.QueryRow(ctx, `
		SELECT generation, deleted_at FROM uptime.monitors
		WHERE id=$1 FOR UPDATE`, id.MonitorID).Scan(&mGen, &mDeleted)
	if err != nil {
		return IdentityStale, fmt.Errorf("lock monitor: %w", err)
	}
	if mDeleted != nil || mGen != id.Generation {
		return IdentityStale, nil
	}

	// 3) run row FOR UPDATE - full identity + liveness.
	var rSegment uuid.UUID
	var rSeq int64
	var rEpoch int64
	var rStatus string
	err = tx.QueryRow(ctx, `
		SELECT segment_id, sequence, engine_epoch, status
		FROM uptime.check_runs WHERE id=$1 AND monitor_id=$2 FOR UPDATE`,
		id.RunID, id.MonitorID).Scan(&rSegment, &rSeq, &rEpoch, &rStatus)
	if err != nil {
		return IdentityStale, fmt.Errorf("lock run: %w", err)
	}
	if rStatus != "RESERVED" && rStatus != "RUNNING" {
		return IdentityDuplicate, nil
	}
	if rSegment != id.SegmentID || rSeq != id.Sequence || rEpoch != id.Epoch {
		return IdentityStale, nil
	}
	if rEpoch != ownerEpoch {
		return IdentityStale, nil
	}
	return IdentityValid, nil
}

// Validate is the Writer-facing wrapper: runs the fence in its own tx
// on the lock-holding owner connection - never a pooled borrow.
func (w *Writer) ValidateResultIdentity(ctx context.Context,
	id FinalizeIdentity) (IdentityVerdict, error) {
	var verdict IdentityVerdict
	err := w.Exec(ctx, func(ctx context.Context, conn *pgx.Conn) error {
		tx, err := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
		if err != nil {
			return err
		}
		defer tx.Rollback(ctx)
		v, err := ValidateResultIdentity(ctx, tx, w.owner.epoch, id)
		if err != nil {
			return err
		}
		verdict = v
		return tx.Commit(ctx)
	})
	return verdict, err
}

// MarkStaleRun persists the terminal disposition for a run that lost
// the fence: STALE when a newer schedule superseded it, EXCLUDED when
// the work itself was inadmissible at finalize time. Idempotent - a
// run already terminal is left untouched so replays never rewrite
// committed dispositions.
func MarkStaleRun(ctx context.Context, tx pgx.Tx,
	runID uuid.UUID, status, reason string) (bool, error) {
	tag, err := tx.Exec(ctx, `
		UPDATE uptime.check_runs
		SET status=$2, finished_at=clock_timestamp(), terminal_reason=$3
		WHERE id=$1 AND status IN ('RESERVED','RUNNING')`,
		runID, status, reason)
	if err != nil {
		return false, fmt.Errorf("mark run %s: %w", status, err)
	}
	return tag.RowsAffected() == 1, nil
}
