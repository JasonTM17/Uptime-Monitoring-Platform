// Package analytics aggregates raw check evidence into weighted
// hourly buckets. The contract is weighted counts, never
// average-of-averages: a bucket's ratio derives from summed
// numerators and denominators, and merging windows merges the sums —
// never the ratios. Buckets are UTC half-open hours keyed by the
// run's nominal slot_at, not the observation timestamp; observed_at
// only labels first/last observation bounds.
package analytics

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// SampleCounts is the mergeable counter set. Ratios are computed
// only at the read edge — after every merge — never stored.
type SampleCounts struct {
	Valid          int64 // eligible evidence (successes + failures)
	Successes      int64
	Failures       int64
	Excluded       int64 // policy/cancel/internal — not evidence
	DurationSumMs  int64 // eligible rows only
	DurationCount  int64
}

// MergeSampleCounts adds two counter sets. This is the ONLY lawful
// way to combine windows: counts and sums add; ratios do not exist
// here to be averaged.
func MergeSampleCounts(a, b SampleCounts) SampleCounts {
	return SampleCounts{
		Valid:         a.Valid + b.Valid,
		Successes:     a.Successes + b.Successes,
		Failures:      a.Failures + b.Failures,
		Excluded:      a.Excluded + b.Excluded,
		DurationSumMs: a.DurationSumMs + b.DurationSumMs,
		DurationCount: a.DurationCount + b.DurationCount,
	}
}

// SampleUptime is successes/valid; nil when there is no eligible
// evidence — absence is not 0% and not 100%.
func SampleUptime(c SampleCounts) *float64 {
	if c.Valid == 0 {
		return nil
	}
	v := float64(c.Successes) / float64(c.Valid)
	return &v
}

// MeanDurationMs is duration_sum/duration_count; nil when nothing
// eligible was timed.
func MeanDurationMs(c SampleCounts) *float64 {
	if c.DurationCount == 0 {
		return nil
	}
	v := float64(c.DurationSumMs) / float64(c.DurationCount)
	return &v
}

// RollupConfig bounds one incremental pass.
type RollupConfig struct {
	Batch int // max pending results claimed per batch
}

// RollupReport records what one committed batch did.
type RollupReport struct {
	Processed int // result rows marked rolled_up_at
	Buckets   int // distinct (monitor,hour) buckets touched
}

// RollupBatch claims up to cfg.Batch unrolled check_results under
// row locks, folds them into hourly_stats keyed by the run's UTC
// slot hour, and stamps rolled_up_at — all in ONE transaction. A
// retry before commit changes nothing; after commit the rows are no
// longer pending, so replay cannot double-count. There is no
// watermark eligibility filter: a late result rolls into its own
// slot's bucket whenever it arrives.
func RollupBatch(ctx context.Context, pool *pgxpool.Pool,
	cfg RollupConfig) (RollupReport, error) {
	var rep RollupReport
	if cfg.Batch <= 0 {
		return rep, fmt.Errorf("rollup batch must be positive")
	}
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return rep, err
	}
	defer conn.Release()

	tx, err := conn.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return rep, err
	}
	defer tx.Rollback(ctx)

	err = tx.QueryRow(ctx, `
		WITH picked AS (
		  SELECT r.check_id, r.monitor_id, r.eligible, r.success,
		         r.duration_ms, r.observed_at,
		         cr.slot_at, cr.finished_at
		  FROM uptime.check_results r
		  JOIN uptime.check_runs cr
		    ON cr.id=r.check_id AND cr.monitor_id=r.monitor_id
		  WHERE r.rolled_up_at IS NULL
		  ORDER BY r.observed_at, r.check_id
		  LIMIT $1
		  FOR UPDATE OF r SKIP LOCKED
		),
		agg AS (
		  SELECT monitor_id,
		    date_trunc('hour', slot_at AT TIME ZONE 'UTC')
		      AT TIME ZONE 'UTC' AS bucket,
		    count(*) FILTER (WHERE eligible) AS valid,
		    count(*) FILTER (WHERE eligible AND success) AS successes,
		    count(*) FILTER (WHERE eligible AND NOT success) AS failures,
		    count(*) FILTER (WHERE NOT eligible) AS excluded,
		    COALESCE(sum(duration_ms) FILTER (WHERE eligible),0) AS dsum,
		    count(*) FILTER (WHERE eligible) AS dcount,
		    min(observed_at) AS first_o,
		    max(observed_at) AS last_o,
		    max(finished_at) AS fin_through
		  FROM picked
		  GROUP BY monitor_id, bucket
		),
		ups AS (
		  INSERT INTO uptime.hourly_stats
		    (monitor_id,bucket_start,valid_samples,successes,failures,
		     excluded_samples,duration_sum_ms,duration_count,
		     first_observed_at,last_observed_at,finalized_through,
		     updated_at)
		  SELECT monitor_id,bucket,valid,successes,failures,excluded,
		         dsum,dcount,first_o,last_o,fin_through,now()
		  FROM agg
		  ON CONFLICT (monitor_id,bucket_start) DO UPDATE SET
		    valid_samples   = hourly_stats.valid_samples   + EXCLUDED.valid_samples,
		    successes       = hourly_stats.successes       + EXCLUDED.successes,
		    failures        = hourly_stats.failures        + EXCLUDED.failures,
		    excluded_samples= hourly_stats.excluded_samples+ EXCLUDED.excluded_samples,
		    duration_sum_ms = hourly_stats.duration_sum_ms + EXCLUDED.duration_sum_ms,
		    duration_count  = hourly_stats.duration_count  + EXCLUDED.duration_count,
		    first_observed_at =
		      LEAST(hourly_stats.first_observed_at, EXCLUDED.first_observed_at),
		    last_observed_at =
		      GREATEST(hourly_stats.last_observed_at, EXCLUDED.last_observed_at),
		    finalized_through =
		      GREATEST(hourly_stats.finalized_through, EXCLUDED.finalized_through),
		    updated_at = now()
		  RETURNING 1
		),
		marked AS (
		  UPDATE uptime.check_results r
		  SET rolled_up_at = now()
		  FROM picked p
		  WHERE r.check_id = p.check_id
		  RETURNING 1
		)
		SELECT (SELECT count(*) FROM marked),
		       (SELECT count(*) FROM ups)`,
		cfg.Batch).Scan(&rep.Processed, &rep.Buckets)
	if err != nil {
		return rep, fmt.Errorf("rollup: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return rep, fmt.Errorf("rollup commit: %w", err)
	}
	return rep, nil
}

// RollupUntilQuiet drains pending rows in bounded batches. It stops
// when a batch picks nothing or ctx ends — each batch is its own
// commit, so an interruption never loses committed buckets.
func RollupUntilQuiet(ctx context.Context, pool *pgxpool.Pool,
	cfg RollupConfig) (RollupReport, error) {
	var total RollupReport
	for {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		rep, err := RollupBatch(ctx, pool, cfg)
		total.Processed += rep.Processed
		total.Buckets += rep.Buckets
		if err != nil {
			return total, err
		}
		if rep.Processed == 0 {
			return total, nil
		}
		time.Sleep(5 * time.Millisecond)
	}
}
