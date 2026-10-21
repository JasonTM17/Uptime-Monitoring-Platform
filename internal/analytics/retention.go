package analytics

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// RetentionConfig binds the retention contract to a profile.
// Local: raw 30d, hourly 30d. Hosted-free: raw 24h, hourly 30d.
// Batches are bounded and every batch is its own commit — a cancel
// or crash resumes from durable state, never inside a dead tx.
type RetentionConfig struct {
	RawRetentionHours    int
	HourlyRetentionDays  int
	OutboxRetentionDays  int // terminal SENT/SUPPRESSED intents
	Batch                int // max rows per commit
	BatchDelay           time.Duration
}

// RetentionReport counts what a sweep actually removed.
type RetentionReport struct {
	RunsPurged    int64
	ResultsPurged int64
	HourlyPurged  int64
	OutboxPurged  int64
}

// PurgeRolledBatch deletes up to batch terminal, rolled, unanchored
// run+result pairs older than rawCut — ONE transaction. Eligibility:
//
//   - run finished before rawCut (terminal + aged — active runs are
//     structurally excluded because finished_at is NULL);
//   - NO unrolled result — the rollup barrier: raw never leaves
//     before its counts are committed into hourly_stats;
//   - NOT referenced as an incident anchor (opened/resolved check) —
//     incident evidence outlives raw retention;
//   - NOT referenced by the outbox stream — the check that opened or
//     resolved an incident stays while any notification intent on
//     that incident exists (DEAD heads need the causal evidence).
//
// Results delete before runs in the same tx (FK order). Segments
// are schedule metadata — they are never purged, the denominator
// depends on them.
func PurgeRolledBatch(ctx context.Context, conn *pgx.Conn,
	rawCut time.Time, batch int) (runs, results int64, err error) {
	if batch <= 0 {
		return 0, 0, fmt.Errorf("retention batch must be positive")
	}
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return 0, 0, err
	}
	defer tx.Rollback(ctx)

	err = tx.QueryRow(ctx, `
		WITH picked AS (
		  SELECT cr.id, cr.monitor_id
		  FROM uptime.check_runs cr
		  WHERE cr.finished_at IS NOT NULL
		    AND cr.finished_at < $1
		    AND NOT EXISTS (
		      SELECT 1 FROM uptime.check_results r
		      WHERE r.check_id=cr.id AND r.rolled_up_at IS NULL)
		    AND NOT EXISTS (
		      SELECT 1 FROM uptime.incidents i
		      WHERE i.opened_check_id=cr.id
		         OR i.resolved_check_id=cr.id)
		    AND NOT EXISTS (
		      SELECT 1 FROM uptime.incidents i
		      JOIN uptime.notification_outbox o
		        ON o.incident_id=i.id
		      WHERE i.opened_check_id=cr.id
		         OR i.resolved_check_id=cr.id)
		  ORDER BY cr.finished_at, cr.id
		  LIMIT $2
		  FOR UPDATE OF cr SKIP LOCKED
		),
		del_res AS (
		  DELETE FROM uptime.check_results r
		  WHERE r.check_id IN (SELECT id FROM picked)
		  RETURNING 1
		),
		del_run AS (
		  DELETE FROM uptime.check_runs cr
		  WHERE cr.id IN (SELECT id FROM picked)
		  RETURNING 1
		)
		SELECT (SELECT count(*) FROM del_res),
		       (SELECT count(*) FROM del_run)`,
		rawCut, batch).Scan(&results, &runs)
	if err != nil {
		return 0, 0, fmt.Errorf("purge rolled: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, 0, fmt.Errorf("purge commit: %w", err)
	}
	return runs, results, nil
}

// PurgeHourlyBatch removes buckets older than the hourly retention
// horizon. Buckets carry no inbound references — this lane is a
// straight bounded delete.
func PurgeHourlyBatch(ctx context.Context, conn *pgx.Conn,
	hourlyCut time.Time, batch int) (int64, error) {
	if batch <= 0 {
		return 0, fmt.Errorf("retention batch must be positive")
	}
	tag, err := conn.Exec(ctx, `
		DELETE FROM uptime.hourly_stats
		WHERE (monitor_id,bucket_start) IN (
		  SELECT monitor_id,bucket_start FROM uptime.hourly_stats
		  WHERE bucket_start < $1
		  ORDER BY bucket_start, monitor_id
		  LIMIT $2
		  FOR UPDATE SKIP LOCKED)`,
		hourlyCut, batch)
	if err != nil {
		return 0, fmt.Errorf("purge hourly: %w", err)
	}
	return tag.RowsAffected(), nil
}

// PurgeOutboxBatch removes terminal SENT/SUPPRESSED intents older
// than the outbox horizon. DEAD rows are evidence — they keep the
// dead-letter record. PENDING/LEASED rows are live work. A row still
// referenced as a causal predecessor is never removed.
func PurgeOutboxBatch(ctx context.Context, conn *pgx.Conn,
	outboxCut time.Time, batch int) (int64, error) {
	if batch <= 0 {
		return 0, fmt.Errorf("retention batch must be positive")
	}
	tag, err := conn.Exec(ctx, `
		DELETE FROM uptime.notification_outbox
		WHERE id IN (
		  SELECT o.id FROM uptime.notification_outbox o
		  WHERE o.state IN ('SENT','SUPPRESSED')
		    AND o.created_at < $1
		    AND NOT EXISTS (
		      SELECT 1 FROM uptime.notification_outbox d
		      WHERE d.predecessor_id=o.id)
		  ORDER BY o.created_at, o.id
		  LIMIT $2
		  FOR UPDATE OF o SKIP LOCKED)`,
		outboxCut, batch)
	if err != nil {
		return 0, fmt.Errorf("purge outbox: %w", err)
	}
	return tag.RowsAffected(), nil
}

// RunRetention executes one bounded sweep across all three lanes.
// Each batch commits independently; ctx cancellation or an error
// mid-sweep stops cleanly with the report accumulated so far — the
// next run resumes from durable state, not from a scan position.
func RunRetention(ctx context.Context, pool *pgxpool.Pool,
	cfg RetentionConfig, now time.Time) (RetentionReport, error) {
	var rep RetentionReport
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return rep, err
	}
	defer conn.Release()

	rawCut := now.Add(-time.Duration(cfg.RawRetentionHours) * time.Hour)
	hourlyCut := now.Add(-time.Duration(cfg.HourlyRetentionDays) * 24 * time.Hour)
	outboxCut := now.Add(-time.Duration(cfg.OutboxRetentionDays) * 24 * time.Hour)

	drain := func(step func() (int64, error)) error {
		for {
			if err := ctx.Err(); err != nil {
				return err
			}
			n, err := step()
			if err != nil {
				return err
			}
			if n == 0 || int(n) < cfg.Batch {
				return nil
			}
			if cfg.BatchDelay > 0 {
				time.Sleep(cfg.BatchDelay)
			}
		}
	}

	if err := drain(func() (int64, error) {
		r, res, err := PurgeRolledBatch(ctx, conn.Conn(), rawCut, cfg.Batch)
		rep.RunsPurged += r
		rep.ResultsPurged += res
		return r, err
	}); err != nil {
		return rep, err
	}
	if err := drain(func() (int64, error) {
		n, err := PurgeHourlyBatch(ctx, conn.Conn(), hourlyCut, cfg.Batch)
		rep.HourlyPurged += n
		return n, err
	}); err != nil {
		return rep, err
	}
	err = drain(func() (int64, error) {
		n, err := PurgeOutboxBatch(ctx, conn.Conn(), outboxCut, cfg.Batch)
		rep.OutboxPurged += n
		return n, err
	})
	return rep, err
}
