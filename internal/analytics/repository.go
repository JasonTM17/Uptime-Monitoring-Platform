package analytics

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrMonitorNotFound is indistinguishable from cross-user access —
// a foreign monitor id returns the same sentinel as a missing one.
var ErrMonitorNotFound = errors.New("monitor not found")

// Repository reads analytics projections. It never mutates state and
// never triggers network work.
type Repository struct {
	pool    *pgxpool.Pool
	timeout time.Duration
}

func NewRepository(pool *pgxpool.Pool, timeout time.Duration) *Repository {
	return &Repository{pool: pool, timeout: timeout}
}

func (r *Repository) ctx(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, r.timeout)
}

// OwnMonitor gates every per-monitor read: the row must exist, belong
// to the owner, and be undeleted — or the caller sees not-found.
func (r *Repository) OwnMonitor(ctx context.Context, ownerID,
	monID uuid.UUID) error {
	ctx, cancel := r.ctx(ctx)
	defer cancel()
	var n int
	err := r.pool.QueryRow(ctx, `
		SELECT 1 FROM uptime.monitors
		WHERE id=$1 AND user_id=$2 AND deleted_at IS NULL`,
		monID, ownerID).Scan(&n)
	if err == pgx.ErrNoRows {
		return ErrMonitorNotFound
	}
	return err
}

// CheckRow is one history entry: the run identity plus its accepted
// result fields when present. Slot is the nominal schedule slot —
// observed timestamps are separate labels.
type CheckRow struct {
	RunID       uuid.UUID
	SlotAt      time.Time
	StartedAt   *time.Time
	FinishedAt  *time.Time
	Status      string
	Outcome     *string
	Eligible    *bool
	Success     *bool
	HTTPStatus  *int
	DurationMs  *int64
	ObservedAt  *time.Time
}

// ListChecks pages run history newest-first over slot_at in [from,to).
// The keyset is (slot_at,id) descending; `after` is exclusive.
func (r *Repository) ListChecks(ctx context.Context, monID uuid.UUID,
	from, to time.Time, after *time.Time, afterID *uuid.UUID,
	limit int) ([]CheckRow, error) {
	ctx, cancel := r.ctx(ctx)
	defer cancel()
	rows, err := r.pool.Query(ctx, `
		SELECT cr.id, cr.slot_at, cr.started_at, cr.finished_at,
		       cr.status, res.outcome, res.eligible, res.success,
		       res.http_status, res.duration_ms, res.observed_at
		FROM uptime.check_runs cr
		LEFT JOIN uptime.check_results res
		  ON res.check_id=cr.id AND res.monitor_id=cr.monitor_id
		WHERE cr.monitor_id=$1 AND cr.slot_at>=$2 AND cr.slot_at<$3
		  AND ($4::timestamptz IS NULL
		       OR (cr.slot_at,cr.id) < ($4,$5::uuid))
		ORDER BY cr.slot_at DESC, cr.id DESC
		LIMIT $6`,
		monID, from, to, after, afterID, limit+1)
	if err != nil {
		return nil, fmt.Errorf("list checks: %w", err)
	}
	defer rows.Close()
	out := []CheckRow{}
	for rows.Next() {
		var c CheckRow
		if err := rows.Scan(&c.RunID, &c.SlotAt, &c.StartedAt,
			&c.FinishedAt, &c.Status, &c.Outcome, &c.Eligible,
			&c.Success, &c.HTTPStatus, &c.DurationMs,
			&c.ObservedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// IncidentRow is one incident history entry.
type IncidentRow struct {
	ID              uuid.UUID
	OpenedAt        time.Time
	ResolvedAt      *time.Time
	CloseReason     *string
	OpenedCheckID   uuid.UUID
	ResolvedCheckID *uuid.UUID
}

// ListIncidents pages incident history newest-first over opened_at.
// state: "" all, "open" unresolved, "resolved" closed.
func (r *Repository) ListIncidents(ctx context.Context, monID uuid.UUID,
	state string, after *time.Time, afterID *uuid.UUID,
	limit int) ([]IncidentRow, error) {
	ctx, cancel := r.ctx(ctx)
	defer cancel()
	var cond string
	switch state {
	case "open":
		cond = "AND i.resolved_at IS NULL"
	case "resolved":
		cond = "AND i.resolved_at IS NOT NULL"
	}
	rows, err := r.pool.Query(ctx, `
		SELECT i.id, i.opened_at, i.resolved_at, i.close_reason,
		       i.opened_check_id, i.resolved_check_id
		FROM uptime.incidents i
		WHERE i.monitor_id=$1 `+cond+`
		  AND ($2::timestamptz IS NULL
		       OR (i.opened_at,i.id) < ($2,$3::uuid))
		ORDER BY i.opened_at DESC, i.id DESC
		LIMIT $4`,
		monID, after, afterID, limit+1)
	if err != nil {
		return nil, fmt.Errorf("list incidents: %w", err)
	}
	defer rows.Close()
	out := []IncidentRow{}
	for rows.Next() {
		var v IncidentRow
		if err := rows.Scan(&v.ID, &v.OpenedAt, &v.ResolvedAt,
			&v.CloseReason, &v.OpenedCheckID,
			&v.ResolvedCheckID); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// RetentionBounds reports the earliest raw slot and the earliest
// hourly bucket still stored for the monitor — the truncation edges
// the represented window is computed against. Nil means no data.
func (r *Repository) RetentionBounds(ctx context.Context,
	monID uuid.UUID) (rawFrom *time.Time, hourlyFrom *time.Time,
	err error) {
	ctx, cancel := r.ctx(ctx)
	defer cancel()
	// A run without an accepted result (STALE/INTERRUPTED) is still
	// retained evidence the slot existed  --  bound on runs, not results.
	if err = r.pool.QueryRow(ctx, `
		SELECT min(slot_at) FROM uptime.check_runs
		WHERE monitor_id=$1`, monID).Scan(&rawFrom); err != nil {
		return nil, nil, err
	}
	if err = r.pool.QueryRow(ctx, `
		SELECT min(bucket_start) FROM uptime.hourly_stats
		WHERE monitor_id=$1`, monID).Scan(&hourlyFrom); err != nil {
		return nil, nil, err
	}
	return rawFrom, hourlyFrom, nil
}

// HourlyCounts sums complete buckets — buckets fully inside [ds,de)
// only; a partial boundary bucket is never split or prorated.
func (r *Repository) HourlyCounts(ctx context.Context, monID uuid.UUID,
	ds, de time.Time) (SampleCounts, error) {
	ctx, cancel := r.ctx(ctx)
	defer cancel()
	var c SampleCounts
	err := r.pool.QueryRow(ctx, `
		SELECT COALESCE(sum(valid_samples),0),
		       COALESCE(sum(successes),0),
		       COALESCE(sum(failures),0),
		       COALESCE(sum(excluded_samples),0),
		       COALESCE(sum(duration_sum_ms),0),
		       COALESCE(sum(duration_count),0)
		FROM uptime.hourly_stats
		WHERE monitor_id=$1
		  AND bucket_start >= $2
		  AND bucket_start + interval '1 hour' <= $3`,
		monID, ds, de).Scan(&c.Valid, &c.Successes, &c.Failures,
		&c.Excluded, &c.DurationSumMs, &c.DurationCount)
	return c, err
}

// RawCounts sums result rows whose nominal slot falls in [ds,de) and
// whose counts are NOT already inside a fully-covered bucket — the
// disjoint half of the merge. A rolled row in a partial boundary
// bucket still counts here because its bucket was not used.
func (r *Repository) RawCounts(ctx context.Context, monID uuid.UUID,
	ds, de time.Time) (SampleCounts, error) {
	ctx, cancel := r.ctx(ctx)
	defer cancel()
	var c SampleCounts
	err := r.pool.QueryRow(ctx, `
		SELECT count(*) FILTER (WHERE res.eligible),
		       count(*) FILTER (WHERE res.eligible AND res.success),
		       count(*) FILTER (WHERE res.eligible AND NOT res.success),
		       count(*) FILTER (WHERE NOT res.eligible),
		       COALESCE(sum(res.duration_ms)
		         FILTER (WHERE res.eligible),0),
		       count(*) FILTER (WHERE res.eligible)
		FROM uptime.check_results res
		JOIN uptime.check_runs cr
		  ON cr.id=res.check_id AND cr.monitor_id=res.monitor_id
		WHERE res.monitor_id=$1
		  AND cr.slot_at >= $2 AND cr.slot_at < $3
		  AND (res.rolled_up_at IS NULL
		       OR NOT (
		         date_trunc('hour', cr.slot_at AT TIME ZONE 'UTC')
		           AT TIME ZONE 'UTC' >= $2
		         AND date_trunc('hour', cr.slot_at AT TIME ZONE 'UTC')
		           AT TIME ZONE 'UTC' + interval '1 hour' <= $3))`,
		monID, ds, de).Scan(&c.Valid, &c.Successes, &c.Failures,
		&c.Excluded, &c.DurationSumMs, &c.DurationCount)
	return c, err
}

// ExpectedSlots counts nominal schedule slots — starts_at + k*iv —
// inside [ds,de) over every segment that ever covered the monitor.
// Paused/suspended time is outside segments by construction, so it
// never enters the denominator. Count uses the ceil-difference
// identity: slots in [a,b) = ceil((b-start)/iv) - ceil((a-start)/iv).
func (r *Repository) ExpectedSlots(ctx context.Context, monID uuid.UUID,
	ds, de time.Time) (int64, error) {
	ctx, cancel := r.ctx(ctx)
	defer cancel()
	var n int64
	err := r.pool.QueryRow(ctx, `
		SELECT COALESCE(sum(GREATEST(0,
		  CEIL(EXTRACT(EPOCH FROM
		    (LEAST(COALESCE(s.ends_at,$2),$2) - s.starts_at))::numeric
		    / s.interval_seconds)
		- CEIL(EXTRACT(EPOCH FROM
		    (GREATEST(s.starts_at,$1) - s.starts_at))::numeric
		    / s.interval_seconds)
		)),0)
		FROM uptime.schedule_segments s
		WHERE s.monitor_id=$3
		  AND s.starts_at < $2
		  AND COALESCE(s.ends_at,$2) > $1`,
		ds, de, monID).Scan(&n)
	return n, err
}

// PendingSlots counts in-flight reservations — slots with a RESERVED
// or RUNNING run and no accepted result yet.
func (r *Repository) PendingSlots(ctx context.Context, monID uuid.UUID,
	ds, de time.Time) (int64, error) {
	ctx, cancel := r.ctx(ctx)
	defer cancel()
	var n int64
	err := r.pool.QueryRow(ctx, `
		SELECT count(*) FROM uptime.check_runs
		WHERE monitor_id=$1 AND slot_at>=$2 AND slot_at<$3
		  AND status IN ('RESERVED','RUNNING')`,
		monID, ds, de).Scan(&n)
	return n, err
}

// RunsInRange counts runs of ANY status whose slot is in [ds,de)  -- 
// the completeness probe for the boundary-hour rule.
func (r *Repository) RunsInRange(ctx context.Context, monID uuid.UUID,
	ds, de time.Time) (int64, error) {
	ctx, cancel := r.ctx(ctx)
	defer cancel()
	var n int64
	err := r.pool.QueryRow(ctx, `
		SELECT count(*) FROM uptime.check_runs
		WHERE monitor_id=$1 AND slot_at>=$2 AND slot_at<$3`,
		monID, ds, de).Scan(&n)
	return n, err
}

// BucketAt reports whether an hourly bucket exists at the aligned
// instant  --  presence means the hour's aggregate survived rollup
// regardless of raw retention.
func (r *Repository) BucketAt(ctx context.Context, monID uuid.UUID,
	bucket time.Time) (bool, error) {
	ctx, cancel := r.ctx(ctx)
	defer cancel()
	var n int
	err := r.pool.QueryRow(ctx, `
		SELECT 1 FROM uptime.hourly_stats
		WHERE monitor_id=$1 AND bucket_start=$2`,
		monID, bucket.UTC()).Scan(&n)
	if err == pgx.ErrNoRows {
		return false, nil
	}
	return err == nil, err
}

// BucketPoint is one hour of series data. Uptime/latency are computed
// at the read edge and stay nil when the denominator is empty — gaps
// stay null, they are never bridged.
type BucketPoint struct {
	BucketStart   time.Time
	Counts        SampleCounts
}

// Series returns per-hour aggregates ordered ascending over [ds,de)
// from the same disjoint merge as the totals: complete buckets plus
// uncovered raw rows grouped by their slot hour.
func (r *Repository) Series(ctx context.Context, monID uuid.UUID,
	ds, de time.Time) ([]BucketPoint, error) {
	ctx, cancel := r.ctx(ctx)
	defer cancel()
	rows, err := r.pool.Query(ctx, `
		SELECT bucket_start, valid_samples, successes, failures,
		       excluded_samples, duration_sum_ms, duration_count
		FROM uptime.hourly_stats
		WHERE monitor_id=$1
		  AND bucket_start >= $2
		  AND bucket_start + interval '1 hour' <= $3
		UNION ALL
		SELECT date_trunc('hour', cr.slot_at AT TIME ZONE 'UTC')
		         AT TIME ZONE 'UTC',
		       count(*) FILTER (WHERE res.eligible),
		       count(*) FILTER (WHERE res.eligible AND res.success),
		       count(*) FILTER (WHERE res.eligible AND NOT res.success),
		       count(*) FILTER (WHERE NOT res.eligible),
		       COALESCE(sum(res.duration_ms)
		         FILTER (WHERE res.eligible),0),
		       count(*) FILTER (WHERE res.eligible)
		FROM uptime.check_results res
		JOIN uptime.check_runs cr
		  ON cr.id=res.check_id AND cr.monitor_id=res.monitor_id
		WHERE res.monitor_id=$1
		  AND cr.slot_at >= $2 AND cr.slot_at < $3
		  AND (res.rolled_up_at IS NULL
		       OR NOT (
		         date_trunc('hour', cr.slot_at AT TIME ZONE 'UTC')
		           AT TIME ZONE 'UTC' >= $2
		         AND date_trunc('hour', cr.slot_at AT TIME ZONE 'UTC')
		           AT TIME ZONE 'UTC' + interval '1 hour' <= $3))
		GROUP BY 1
		ORDER BY 1`,
		monID, ds, de)
	if err != nil {
		return nil, fmt.Errorf("series: %w", err)
	}
	defer rows.Close()
	var out []BucketPoint
	for rows.Next() {
		var p BucketPoint
		if err := rows.Scan(&p.BucketStart, &p.Counts.Valid,
			&p.Counts.Successes, &p.Counts.Failures,
			&p.Counts.Excluded, &p.Counts.DurationSumMs,
			&p.Counts.DurationCount); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// SummaryRow is the owner snapshot behind the dashboard — one
// consistent read, never a second sample of cap vs count.
type SummaryRow struct {
	Monitors        int64
	Active          int64 // unpaused — says nothing about health
	Paused          int64
	Up              int64
	Down            int64
	OpenIncidents   int64
	MonitorLimit    int64
	Valid24h        int64
	Success24h      int64
}

// DashboardSummary reads the owner's aggregate in one snapshot:
// nondeleted monitor counts by pause/health, open incidents, the
// effective own limit, and 24h weighted evidence from rolled buckets
// plus uncovered raw rows.
func (r *Repository) DashboardSummary(ctx context.Context,
	ownerID uuid.UUID, since time.Time) (SummaryRow, error) {
	ctx, cancel := r.ctx(ctx)
	defer cancel()
	var s SummaryRow
	err := r.pool.QueryRow(ctx, `
		SELECT count(*),
		       count(*) FILTER (WHERE NOT is_paused),
		       count(*) FILTER (WHERE is_paused),
		       count(*) FILTER (WHERE health='UP'),
		       count(*) FILTER (WHERE health='DOWN'),
		       (SELECT count(*) FROM uptime.incidents i
		          JOIN uptime.monitors m2 ON m2.id=i.monitor_id
		         WHERE m2.user_id=$1 AND m2.deleted_at IS NULL
		           AND i.resolved_at IS NULL),
		       (SELECT monitor_limit FROM uptime.users WHERE id=$1)
		FROM uptime.monitors
		WHERE user_id=$1 AND deleted_at IS NULL`,
		ownerID).Scan(&s.Monitors, &s.Active, &s.Paused, &s.Up,
		&s.Down, &s.OpenIncidents, &s.MonitorLimit)
	if err != nil {
		return s, fmt.Errorf("summary monitors: %w", err)
	}
	err = r.pool.QueryRow(ctx, `
		SELECT COALESCE((SELECT sum(valid_samples) FROM uptime.hourly_stats h
		  JOIN uptime.monitors m ON m.id=h.monitor_id
		  WHERE m.user_id=$1 AND m.deleted_at IS NULL
		    AND h.bucket_start >= $2),0)
		     + COALESCE((SELECT count(*) FROM uptime.check_results res
		  JOIN uptime.check_runs cr
		    ON cr.id=res.check_id AND cr.monitor_id=res.monitor_id
		  JOIN uptime.monitors m ON m.id=cr.monitor_id
		  WHERE m.user_id=$1 AND m.deleted_at IS NULL
		    AND res.eligible AND cr.slot_at >= $2
		    AND (res.rolled_up_at IS NULL OR NOT (
		     date_trunc('hour', cr.slot_at AT TIME ZONE 'UTC')
		       AT TIME ZONE 'UTC' >= $2
		     AND date_trunc('hour', cr.slot_at AT TIME ZONE 'UTC')
		       AT TIME ZONE 'UTC' + interval '1 hour' <= now()))),0),
		   COALESCE((SELECT sum(successes) FROM uptime.hourly_stats h
		  JOIN uptime.monitors m ON m.id=h.monitor_id
		  WHERE m.user_id=$1 AND m.deleted_at IS NULL
		    AND h.bucket_start >= $2),0)
		     + COALESCE((SELECT count(*) FROM uptime.check_results res
		  JOIN uptime.check_runs cr
		    ON cr.id=res.check_id AND cr.monitor_id=res.monitor_id
		  JOIN uptime.monitors m ON m.id=cr.monitor_id
		  WHERE m.user_id=$1 AND m.deleted_at IS NULL
		    AND res.eligible AND res.success AND cr.slot_at >= $2
		    AND (res.rolled_up_at IS NULL OR NOT (
		     date_trunc('hour', cr.slot_at AT TIME ZONE 'UTC')
		       AT TIME ZONE 'UTC' >= $2
		     AND date_trunc('hour', cr.slot_at AT TIME ZONE 'UTC')
		       AT TIME ZONE 'UTC' + interval '1 hour' <= now()))),0)`,
		ownerID, since).Scan(&s.Valid24h, &s.Success24h)
	return s, err
}

// RecentIncidents lists the owner's newest incidents across monitors —
// the bounded dashboard strip, never a cross-monitor feed.
func (r *Repository) RecentIncidents(ctx context.Context,
	ownerID uuid.UUID, limit int) ([]IncidentListRow, error) {
	ctx, cancel := r.ctx(ctx)
	defer cancel()
	rows, err := r.pool.Query(ctx, `
		SELECT i.id, i.monitor_id, m.name, i.opened_at, i.resolved_at,
		       i.close_reason
		FROM uptime.incidents i
		JOIN uptime.monitors m ON m.id=i.monitor_id
		WHERE m.user_id=$1 AND m.deleted_at IS NULL
		ORDER BY i.opened_at DESC, i.id DESC
		LIMIT $2`, ownerID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []IncidentListRow
	for rows.Next() {
		var v IncidentListRow
		if err := rows.Scan(&v.ID, &v.MonitorID, &v.MonitorName,
			&v.OpenedAt, &v.ResolvedAt, &v.CloseReason); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// IncidentListRow carries the monitor label for the dashboard strip.
type IncidentListRow struct {
	ID          uuid.UUID
	MonitorID   uuid.UUID
	MonitorName string
	OpenedAt    time.Time
	ResolvedAt  *time.Time
	CloseReason *string
}
