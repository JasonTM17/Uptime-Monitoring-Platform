package monitor

// Lifecycle transitions: pause and resume are owner commands over the
// monitor's SCHEDULE state only. They are deliberately orthogonal to
// health — pause never fabricates DOWN and resume never fabricates UP
// or a check sample.
//
// Contract the engine inherits (C33–C34 wiring lands later):
//
//   - generation++ on every real transition is the single fence an
//     in-flight check result must compare; a run admitted under the
//     old generation finalizes STALE and writes nothing to config.
//   - A repeated transition to the current state is an idempotent
//     no-op: success, same generation, no write.
//   - Resume sets next_check_at = now() as ELIGIBILITY ONLY. Due-now
//     is not a check-now privilege: durable admission budget (60s
//     owner/global charge, no refund/reset) still gates the actual
//     run, and denied budget holds the slot due — it does not mint a
//     failure or recovery (RT F02). C34 admission wiring must exist
//     before the engine honors due rows.
//   - schedule_segments are created/closed by the engine admission
//     path (migration 003), not by this API; a request already sent
//     over the network cannot be recalled — cancellation is a
//     generation fence, not a recall promise.
//
// This file holds the service-level transition seam; the row-level
// mechanics live in repository.go's generation-fenced mutations.
import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// PauseTx suspends scheduling under the caller's actor lock. Health
// and streaks pass through untouched; next_check_at stays as recorded
// (the due index excludes paused rows anyway).
func (s *Service) PauseTx(ctx context.Context, tx pgx.Tx, ownerID, id uuid.UUID, gen int64) (Monitor, error) {
	return s.tx.SetMonitorPausedTx(ctx, tx, ownerID, id, gen, true)
}

// ResumeTx re-opens eligibility under the caller's actor lock.
// next_check_at = now() marks the monitor due-eligible; whether a
// check runs is decided later by the durable admission budget — no
// sample, no health claim, no privilege is fabricated here.
func (s *Service) ResumeTx(ctx context.Context, tx pgx.Tx, ownerID, id uuid.UUID, gen int64) (Monitor, error) {
	return s.tx.SetMonitorPausedTx(ctx, tx, ownerID, id, gen, false)
}
