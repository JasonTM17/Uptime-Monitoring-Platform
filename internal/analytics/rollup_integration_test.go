//go:build integration

package analytics

// C49 — weighted hourly rollup against the disposable database.
// Oracles are hand-calculated counts and an INDEPENDENT plain-SQL
// re-aggregation of the raw tables — never a copy of the rollup's
// own query.

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func apool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Fatal("TEST_DATABASE_URL required (disposable postgres-test)")
	}
	p, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	return p
}

func aconn(t *testing.T) *pgx.Conn {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Fatal("TEST_DATABASE_URL required")
	}
	c, err := pgx.Connect(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close(context.Background()) })
	return c
}

func cleanAnalytics(t *testing.T, c *pgx.Conn) {
	t.Helper()
	for _, q := range []string{
		`DELETE FROM uptime.hourly_stats`,
		`DELETE FROM uptime.notification_outbox`,
		`DELETE FROM uptime.incidents`,
		`UPDATE uptime.check_results SET rolled_up_at=NULL`,
		`DELETE FROM uptime.check_results`,
		`DELETE FROM uptime.check_runs`,
		`DELETE FROM uptime.monitor_channels`,
		`DELETE FROM uptime.notification_channels`,
		`DELETE FROM uptime.sessions`,
		`DELETE FROM uptime.quota_budgets`,
		`DELETE FROM uptime.schedule_segments`,
		`DELETE FROM uptime.monitors`,
		// user-children with RESTRICT FKs — leftover rows from
		// another package (or an interrupted run) must not wedge
		// this cleanup on audit_events.actor_id et al.
		`DELETE FROM uptime.audit_events`,
		`DELETE FROM uptime.admin_idempotency`,
		`DELETE FROM uptime.user_roles`,
		`DELETE FROM uptime.users`,
	} {
		if _, err := c.Exec(context.Background(), q); err != nil {
			t.Fatal(err)
		}
	}
}

type monFixture struct{ userID, monID, segID uuid.UUID }

func mkMonitor(t *testing.T, c *pgx.Conn) monFixture {
	t.Helper()
	f := monFixture{}
	ctx := context.Background()
	if err := c.QueryRow(ctx, `
		INSERT INTO uptime.users(id,email,password_hash,status,monitor_limit)
		VALUES (gen_random_uuid(),$1,'x','ACTIVE',10) RETURNING id`,
		"an+"+uuid.NewString()[:8]+"@test.invalid").Scan(&f.userID); err != nil {
		t.Fatal(err)
	}
	if err := c.QueryRow(ctx, `
		INSERT INTO uptime.monitors(id,user_id,name,target_url,method,
		  interval_seconds,timeout_seconds,next_check_at)
		VALUES (gen_random_uuid(),$1,'m','https://x.test','GET',60,5,now())
		RETURNING id`, f.userID).Scan(&f.monID); err != nil {
		t.Fatal(err)
	}
	if err := c.QueryRow(ctx, `
		INSERT INTO uptime.schedule_segments(id,monitor_id,generation,
		  starts_at,interval_seconds)
		VALUES (gen_random_uuid(),$1,1,now(),60) RETURNING id`,
		f.monID).Scan(&f.segID); err != nil {
		t.Fatal(err)
	}
	return f
}

// mkResult seeds a terminal run plus its raw result row — the exact
// pair FinalizeObservation commits. slotAt is the nominal slot that
// owns the bucket; observedAt/finishedAt are the real timestamps.
func mkResult(t *testing.T, c *pgx.Conn, f monFixture, seq int64,
	slotAt, observedAt time.Time, outcome string, eligible bool,
	success *bool, durMs int64) {
	t.Helper()
	ctx := context.Background()
	var runID uuid.UUID
	if err := c.QueryRow(ctx, `
		INSERT INTO uptime.check_runs(id,monitor_id,segment_id,slot_at,
		  generation,sequence,engine_epoch,status,reserved_at,finished_at)
		VALUES (gen_random_uuid(),$1,$2,$3,1,$4,1,'COMPLETED',$5,$5)
		RETURNING id`,
		f.monID, f.segID, slotAt, seq, observedAt).Scan(&runID); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Exec(ctx, `
		INSERT INTO uptime.check_results(check_id,monitor_id,outcome,
		  eligible,success,duration_ms,observed_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		runID, f.monID, outcome, eligible, success, durMs,
		observedAt); err != nil {
		t.Fatal(err)
	}
}

func b(v bool) *bool { return &v }

func bucketCounts(t *testing.T, c *pgx.Conn, monID uuid.UUID,
	bucket time.Time) (v, s, f, x, dsum, dc int64, ok bool) {
	t.Helper()
	err := c.QueryRow(context.Background(), `
		SELECT valid_samples,successes,failures,excluded_samples,
		       duration_sum_ms,duration_count
		FROM uptime.hourly_stats
		WHERE monitor_id=$1 AND bucket_start=$2`,
		monID, bucket.UTC()).Scan(&v, &s, &f, &x, &dsum, &dc)
	if err == pgx.ErrNoRows {
		return 0, 0, 0, 0, 0, 0, false
	}
	if err != nil {
		t.Fatal(err)
	}
	return v, s, f, x, dsum, dc, true
}

// oracle recomputes the bucket straight from raw tables — an
// independent implementation the rollup's output is compared to.
func oracleCounts(t *testing.T, c *pgx.Conn, monID uuid.UUID,
	bucket time.Time) (v, s, f, x int64) {
	t.Helper()
	err := c.QueryRow(context.Background(), `
		SELECT count(*) FILTER (WHERE r.eligible),
		       count(*) FILTER (WHERE r.eligible AND r.success),
		       count(*) FILTER (WHERE r.eligible AND NOT r.success),
		       count(*) FILTER (WHERE NOT r.eligible)
		FROM uptime.check_results r
		JOIN uptime.check_runs cr
		  ON cr.id=r.check_id AND cr.monitor_id=r.monitor_id
		WHERE r.monitor_id=$1
		  AND date_trunc('hour', cr.slot_at AT TIME ZONE 'UTC')
		        AT TIME ZONE 'UTC' = $2`,
		monID, bucket.UTC()).Scan(&v, &s, &f, &x)
	if err != nil {
		t.Fatal(err)
	}
	return
}

var testRollup = RollupConfig{Batch: 500}

// Unequal sample counts across two monitors and mixed eligibility in
// one bucket — merged totals are weighted sums, never averaged
// ratios.
func TestWeightedSamples(t *testing.T) {
	pool, c := apool(t), aconn(t)
	cleanAnalytics(t, c)
	base := time.Date(2025, 1, 5, 10, 0, 0, 0, time.UTC)

	f1 := mkMonitor(t, c)
	f2 := mkMonitor(t, c)

	// monitor A: 3 valid (2 up, 1 down) + 1 excluded; monitor B: 1 valid.
	mkResult(t, c, f1, 1, base.Add(0*time.Minute), base, "SUCCESS", true, b(true), 100)
	mkResult(t, c, f1, 2, base.Add(1*time.Minute), base, "SUCCESS", true, b(true), 200)
	mkResult(t, c, f1, 3, base.Add(2*time.Minute), base, "TIMEOUT", true, b(false), 5000)
	mkResult(t, c, f1, 4, base.Add(3*time.Minute), base, "POLICY_BLOCKED", false, nil, 0)
	mkResult(t, c, f2, 1, base.Add(1*time.Minute), base, "CONNECT_ERROR", true, b(false), 3000)

	rep, err := RollupUntilQuiet(context.Background(), pool, testRollup)
	if err != nil || rep.Processed != 5 {
		t.Fatalf("rollup rep=%+v err=%v", rep, err)
	}

	v, s, f, x, dsum, dc, ok := bucketCounts(t, c, f1.monID, base)
	if !ok || v != 3 || s != 2 || f != 1 || x != 1 {
		t.Fatalf("mA bucket v=%d s=%d f=%d x=%d ok=%v", v, s, f, x, ok)
	}
	if dsum != 5300 || dc != 3 {
		t.Fatalf("mA duration sum=%d count=%d", dsum, dc)
	}
	vb, sb, fb, xb, _, _, okb := bucketCounts(t, c, f2.monID, base)
	if !okb || vb != 1 || sb != 0 || fb != 1 || xb != 0 {
		t.Fatalf("mB bucket v=%d s=%d f=%d x=%d ok=%v", vb, sb, fb, xb, okb)
	}

	// Weighted merge: 2 of 4 valid samples succeeded (50%). An
	// average of the per-monitor ratios — (66.7% + 0%) / 2 = 33.3% —
	// is the classic average-of-averages error this test exists to
	// reject.
	merged := MergeSampleCounts(
		SampleCounts{Valid: 3, Successes: 2, Failures: 1,
			Excluded: 1, DurationSumMs: 5300, DurationCount: 3},
		SampleCounts{Valid: 1, Successes: 0, Failures: 1,
			DurationSumMs: 3000, DurationCount: 1})
	if up := SampleUptime(merged); up == nil || *up != 0.5 {
		t.Fatalf("weighted uptime %v", up)
	}
	if m := MeanDurationMs(merged); m == nil || *m != 8300.0/4.0 {
		t.Fatalf("weighted mean %v", m)
	}
	if SampleUptime(SampleCounts{}) != nil {
		t.Fatal("zero-evidence uptime must be null, not 0 or 100")
	}

	// Independent oracle agreement.
	ov, os, of, ox := oracleCounts(t, c, f1.monID, base)
	if ov != v || os != s || of != f || ox != x {
		t.Fatalf("oracle %d/%d/%d/%d vs stored %d/%d/%d/%d",
			ov, os, of, ox, v, s, f, x)
	}
}

// Replay cannot double-count: processed markers commit atomically
// with the bucket increments.
func TestRollupIdempotency(t *testing.T) {
	pool, c := apool(t), aconn(t)
	cleanAnalytics(t, c)
	base := time.Date(2025, 1, 6, 14, 0, 0, 0, time.UTC)
	f := mkMonitor(t, c)
	mkResult(t, c, f, 1, base, base, "SUCCESS", true, b(true), 120)
	mkResult(t, c, f, 2, base.Add(time.Minute), base, "DNS_ERROR", true, b(false), 50)

	rep1, err := RollupBatch(context.Background(), pool, testRollup)
	if err != nil || rep1.Processed != 2 {
		t.Fatalf("first batch %+v %v", rep1, err)
	}
	v1, s1, f1, x1, _, _, _ := bucketCounts(t, c, f.monID, base)

	rep2, err := RollupBatch(context.Background(), pool, testRollup)
	if err != nil || rep2.Processed != 0 {
		t.Fatalf("replay must pick nothing, got %+v %v", rep2, err)
	}
	v2, s2, f2, x2, _, _, _ := bucketCounts(t, c, f.monID, base)
	if v1 != v2 || s1 != s2 || f1 != f2 || x1 != x2 {
		t.Fatal("replay changed committed counts")
	}

	var pending int
	if err := c.QueryRow(context.Background(), `
		SELECT count(*) FROM uptime.check_results
		WHERE rolled_up_at IS NULL`).Scan(&pending); err != nil || pending != 0 {
		t.Fatalf("pending=%d err=%v", pending, err)
	}
}

// A result finalized after its hour's rollup still lands in its own
// slot's bucket — the watermark is a retention hint, never an
// eligibility filter.
func TestLateObservationRollup(t *testing.T) {
	pool, c := apool(t), aconn(t)
	cleanAnalytics(t, c)
	base := time.Date(2025, 1, 7, 9, 0, 0, 0, time.UTC)
	f := mkMonitor(t, c)

	mkResult(t, c, f, 1, base, base, "SUCCESS", true, b(true), 100)
	if rep, err := RollupUntilQuiet(context.Background(), pool, testRollup); err != nil || rep.Processed != 1 {
		t.Fatalf("first rollup %+v %v", rep, err)
	}

	// Late sample for the SAME nominal slot arrives after the bucket
	// already exists.
	mkResult(t, c, f, 2, base.Add(30*time.Second),
		base.Add(48*time.Hour), "TIMEOUT", true, b(false), 4000)
	if rep, err := RollupUntilQuiet(context.Background(), pool, testRollup); err != nil || rep.Processed != 1 {
		t.Fatalf("late rollup %+v %v", rep, err)
	}

	v, s, f_, x, _, _, ok := bucketCounts(t, c, f.monID, base)
	if !ok || v != 2 || s != 1 || f_ != 1 || x != 0 {
		t.Fatalf("late bucket v=%d s=%d f=%d x=%d", v, s, f_, x)
	}
}

// Slot boundaries are strict UTC hours; observed_at never moves the
// bucket.
func TestHourBoundary(t *testing.T) {
	pool, c := apool(t), aconn(t)
	cleanAnalytics(t, c)
	h10 := time.Date(2025, 1, 8, 10, 0, 0, 0, time.UTC)
	h11 := h10.Add(time.Hour)
	f := mkMonitor(t, c)

	// 10:59:59 slot → 10:00 bucket even though it observed at 11:00:01.
	mkResult(t, c, f, 1, h11.Add(-time.Second), h11.Add(time.Second),
		"SUCCESS", true, b(true), 10)
	// 11:00:00 slot → 11:00 bucket.
	mkResult(t, c, f, 2, h11, h11, "SUCCESS", true, b(true), 20)

	if rep, err := RollupUntilQuiet(context.Background(), pool, testRollup); err != nil || rep.Processed != 2 {
		t.Fatalf("rollup %+v %v", rep, err)
	}
	if v, _, _, _, _, _, ok := bucketCounts(t, c, f.monID, h10); !ok || v != 1 {
		t.Fatalf("10:00 bucket v=%d ok=%v", v, ok)
	}
	if v, _, _, _, _, _, ok := bucketCounts(t, c, f.monID, h11); !ok || v != 1 {
		t.Fatalf("11:00 bucket v=%d ok=%v", v, ok)
	}

	var firstO, lastO time.Time
	if err := c.QueryRow(context.Background(), `
		SELECT first_observed_at,last_observed_at
		FROM uptime.hourly_stats WHERE monitor_id=$1 AND bucket_start=$2`,
		f.monID, h10).Scan(&firstO, &lastO); err != nil {
		t.Fatal(err)
	}
	// Labels are real observation times — past the bucket edge.
	if !lastO.After(h11) {
		t.Fatalf("last_observed_at %v not past bucket end", lastO)
	}
}
