package engine

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// ReconcileInterrupted marks every RESERVED/RUNNING row stamped with
// an older engine_epoch as INTERRUPTED at takeover. One bounded UPDATE
// — no catch-up loop: orphaned runs lose their worker already, and
// the schedule has already moved past their slots.
//
// Same-epoch rows are untouched: reconciliation after a graceful
// restart of the SAME owner may legitimately see live runs.
func ReconcileInterrupted(ctx context.Context, conn *pgx.Conn, epoch int64) (int64, error) {
	tag, err := conn.Exec(ctx, `
		UPDATE uptime.check_runs
		SET status='INTERRUPTED', finished_at=clock_timestamp(),
		    terminal_reason='engine_takeover'
		WHERE status IN ('RESERVED','RUNNING') AND engine_epoch < $1`,
		epoch)
	if err != nil {
		return 0, fmt.Errorf("reconcile interrupted: %w", err)
	}
	return tag.RowsAffected(), nil
}
