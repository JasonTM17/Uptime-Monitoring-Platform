//go:build integration

package analytics

// C50 — owner-scoped history/statistics contract over the real
// merge path. Oracles are hand-computed denominators; no assertion
// copies the production SQL.

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func svcFor(t *testing.T) (*Service, *pgxpool.Pool, *pgx.Conn) {
	t.Helper()
	pool, c := apool(t), aconn(t)
	repo := NewRepository(pool, 10*time.Second)
	return NewService(repo, ServiceConfig{
		RawRetentionHours:   30 * 24,
		HourlyRetentionDays: 30,
		Profile:             "local",
	}), pool, c
}

// timedMonitor creates a monitor whose single segment covers
// [start,end) at the given interval — the nominal slot grid the
// denominator derives from.
func timedMonitor(t *testing.T, c *pgx.Conn, start time.Time,
	ivSeconds int, end *time.Time) monFixture {
	t.Helper()
	f := mkMonitor(t, c)
	if _, err := c.Exec(context.Background(), `
		DELETE FROM uptime.schedule_segments WHERE monitor_id=$1`,
		f.monID); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Exec(context.Background(), `
		INSERT INTO uptime.schedule_segments(id,monitor_id,generation,
		  starts_at,ends_at,interval_seconds)
		VALUES ($1,$2,1,$3,$4,$5)`,
		f.segID, f.monID, start, end, ivSeconds); err != nil {
		t.Fatal(err)
	}
	return f
}

// mkBareRun seeds a run with NO result row — the STALE/INTERRUPTED
// evidence shape the missed denominator relies on.
func mkBareRun(t *testing.T, c *pgx.Conn, f monFixture, seq int64,
	slotAt time.Time, status string) {
	t.Helper()
	if _, err := c.Exec(context.Background(), `
		INSERT INTO uptime.check_runs(id,monitor_id,segment_id,slot_at,
		  generation,sequence,engine_epoch,status,reserved_at)
		VALUES (gen_random_uuid(),$1,$2,$3,1,$4,1,$5,$3)`,
		f.monID, f.segID, slotAt, seq, status); err != nil {
		t.Fatal(err)
	}
}

var testCtx = context.Background()

// TestStatsContract — a hand-built eligible timeline: 4 nominal
// slots (T0..T0+4m at 60s), two eligible results (1 up, 1 down),
// one STALE run, one unreserved slot. expected=4, valid=2,
// missed=2, pending=0, coverage=0.5, uptime=0.5.
func TestStatsContract(t *testing.T) {
	svc, pool, c := svcFor(t)
	cleanAnalytics(t, c)
	t0 := time.Date(2025, 2, 1, 10, 0, 0, 0, time.UTC)
	end := t0.Add(4 * time.Minute)
	f := timedMonitor(t, c, t0, 60, &end)

	mkResult(t, c, f, 1, t0, t0, "SUCCESS", true, b(true), 100)
	mkResult(t, c, f, 2, t0.Add(time.Minute), t0.Add(time.Minute),
		"TIMEOUT", true, b(false), 5000)
	mkBareRun(t, c, f, 3, t0.Add(2*time.Minute), "STALE")
	// slot 3: never reserved — still owed by the schedule.

	now := t0.Add(time.Hour)
	res, err := svc.Statistics(testCtx, f.userID, f.monID,
		t0.Add(-time.Hour), now, now)
	if err != nil {
		t.Fatal(err)
	}
	// Represented start is the first retained instant (t0) — the
	// requested hour before it has no evidence, so the interval is
	// truncated and honestly marked partial.
	if res.DataStart == nil || !res.DataStart.Equal(t0) {
		t.Fatalf("data_start %v", res.DataStart)
	}
	if !res.IsPartial {
		t.Fatal("pre-evidence window must be partial")
	}
	if res.Expected != 4 || res.Counts.Valid != 2 ||
		res.Counts.Successes != 1 || res.Counts.Failures != 1 {
		t.Fatalf("counts %+v expected=%d", res.Counts, res.Expected)
	}
	if res.Pending != 0 || res.Missed != 2 {
		t.Fatalf("missed=%d pending=%d", res.Missed, res.Pending)
	}
	if res.SampleUptime == nil || *res.SampleUptime != 0.5 {
		t.Fatalf("uptime %v", res.SampleUptime)
	}
	if res.Coverage == nil || *res.Coverage != 0.5 {
		t.Fatalf("coverage %v", res.Coverage)
	}
	if res.Resolution != "raw" {
		t.Fatalf("resolution %q", res.Resolution)
	}
	_ = pool
}

// TestStatisticsNoData — no runs, no results, no buckets: honest
// empty representation, never a fabricated 100%.
func TestStatisticsNoData(t *testing.T) {
	svc, _, c := svcFor(t)
	cleanAnalytics(t, c)
	f := mkMonitor(t, c)
	now := time.Date(2025, 2, 2, 12, 0, 0, 0, time.UTC)
	res, err := svc.Statistics(testCtx, f.userID, f.monID,
		now.Add(-24*time.Hour), now, now)
	if err != nil {
		t.Fatal(err)
	}
	if res.DataStart != nil || res.DataEnd != nil {
		t.Fatalf("bounds %+v %+v", res.DataStart, res.DataEnd)
	}
	if !res.IsPartial || res.SampleUptime != nil ||
		res.Coverage != nil || res.Expected != 0 ||
		len(res.Series) != 0 {
		t.Fatalf("not empty: %+v", res)
	}
}

// TestHistoryOwnership — a foreign monitor is indistinguishable
// from a missing one across every read.
func TestHistoryOwnership(t *testing.T) {
	svc, _, c := svcFor(t)
	cleanAnalytics(t, c)
	f := mkMonitor(t, c)
	other := uuid.New()
	now := time.Now().UTC()

	if _, err := svc.Statistics(testCtx, other, f.monID,
		now.Add(-time.Hour), now, now); err != ErrMonitorNotFound {
		t.Fatalf("stats foreign: %v", err)
	}
	if _, err := svc.ListChecks(testCtx, other, f.monID,
		now.Add(-time.Hour), now, "", 10); err != ErrMonitorNotFound {
		t.Fatalf("checks foreign: %v", err)
	}
	if _, err := svc.ListIncidents(testCtx, other, f.monID, "", "",
		10); err != ErrMonitorNotFound {
		t.Fatalf("incidents foreign: %v", err)
	}
	if _, err := svc.ListChecks(testCtx, f.userID, uuid.New(),
		now.Add(-time.Hour), now, "", 10); err != ErrMonitorNotFound {
		t.Fatalf("checks missing: %v", err)
	}
}

// TestRawRollupMerge — totals must be identical whether evidence is
// still raw, already rolled, or split across the boundary. Roll half
// the rows, re-query, expect unchanged counts.
func TestRawRollupMerge(t *testing.T) {
	svc, pool, c := svcFor(t)
	cleanAnalytics(t, c)
	t0 := time.Date(2025, 2, 3, 10, 0, 0, 0, time.UTC)
	end := t0.Add(6 * time.Minute)
	f := timedMonitor(t, c, t0, 60, &end)

	mkResult(t, c, f, 1, t0, t0, "SUCCESS", true, b(true), 100)
	mkResult(t, c, f, 2, t0.Add(time.Minute), t0.Add(time.Minute),
		"SUCCESS", true, b(true), 200)
	mkResult(t, c, f, 3, t0.Add(2*time.Minute), t0.Add(2*time.Minute),
		"DNS_ERROR", true, b(false), 50)
	mkResult(t, c, f, 4, t0.Add(3*time.Minute), t0.Add(3*time.Minute),
		"POLICY_BLOCKED", false, nil, 0)
	mkBareRun(t, c, f, 5, t0.Add(4*time.Minute), "STALE")

	now := t0.Add(2 * time.Hour)
	ws := t0.Add(-30 * time.Minute)
	before, err := svc.Statistics(testCtx, f.userID, f.monID, ws, now, now)
	if err != nil {
		t.Fatal(err)
	}
	if before.Resolution != "raw" {
		t.Fatalf("pre-rollup resolution %q", before.Resolution)
	}

	// Roll everything: buckets take over, totals unchanged.
	if _, err := RollupUntilQuiet(testCtx, pool, RollupConfig{Batch: 500}); err != nil {
		t.Fatal(err)
	}
	after, err := svc.Statistics(testCtx, f.userID, f.monID, ws, now, now)
	if err != nil {
		t.Fatal(err)
	}
	if after.Counts != before.Counts {
		t.Fatalf("merge drifted: before=%+v after=%+v",
			before.Counts, after.Counts)
	}
	if after.Expected != before.Expected ||
		after.Missed != before.Missed {
		t.Fatalf("denominator drifted: exp %d->%d missed %d->%d",
			before.Expected, after.Expected,
			before.Missed, after.Missed)
	}
	if after.Resolution != "hourly" {
		t.Fatalf("post-rollup resolution %q", after.Resolution)
	}
}

// TestAgedPartialHourWindow — two monitors with identical hourly
// totals but outcomes in opposite half-hours. After the raw for the
// partial hour is purged, both must return the SAME normalized
// bounds and counts — the API never fabricates exactness it lost.
func TestAgedPartialHourWindow(t *testing.T) {
	svc, pool, c := svcFor(t)
	cleanAnalytics(t, c)
	h10 := time.Date(2025, 2, 4, 10, 0, 0, 0, time.UTC)
	segEnd := h10.Add(2 * time.Hour)

	mkTwin := func(firstHalfSuccess bool) monFixture {
		f := timedMonitor(t, c, h10, 60, &segEnd)
		s1, s2 := h10.Add(5*time.Minute), h10.Add(55*time.Minute)
		if !firstHalfSuccess {
			s1, s2 = s2, s1
		}
		mkResult(t, c, f, 1, s1, s1, "SUCCESS", true, b(true), 100)
		mkResult(t, c, f, 2, s2, s2, "TIMEOUT", true, b(false), 200)
		return f
	}
	fa := mkTwin(true)
	fb := mkTwin(false)

	if _, err := RollupUntilQuiet(testCtx, pool, RollupConfig{Batch: 500}); err != nil {
		t.Fatal(err)
	}
	// Purge the 10:00 hour's raw for both — the bucket survives.
	for _, f := range []monFixture{fa, fb} {
		if _, err := c.Exec(testCtx, `
			DELETE FROM uptime.check_results WHERE monitor_id=$1`,
			f.monID); err != nil {
			t.Fatal(err)
		}
		if _, err := c.Exec(testCtx, `
			DELETE FROM uptime.check_runs WHERE monitor_id=$1`,
			f.monID); err != nil {
			t.Fatal(err)
		}
	}

	now := h10.Add(3 * time.Hour)
	ws := h10.Add(-30 * time.Minute) // mid-hour request edge
	ra, err := svc.Statistics(testCtx, fa.userID, fa.monID, ws, now, now)
	if err != nil {
		t.Fatal(err)
	}
	rb, err := svc.Statistics(testCtx, fb.userID, fb.monID, ws, now, now)
	if err != nil {
		t.Fatal(err)
	}

	// Identical normalized answers regardless of intra-hour layout.
	if ra.DataStart == nil || rb.DataStart == nil {
		t.Fatal("expected represented bounds")
	}
	if !ra.DataStart.Equal(*rb.DataStart) {
		t.Fatalf("bounds differ %v vs %v", ra.DataStart, rb.DataStart)
	}
	if ra.Counts != rb.Counts {
		t.Fatalf("counts differ %+v vs %+v", ra.Counts, rb.Counts)
	}
	// data_start normalized to an hour boundary, never 09:30 exact.
	if ra.DataStart.Minute() != 0 {
		t.Fatalf("data_start not hour-aligned: %v", ra.DataStart)
	}
	if ra.Counts.Valid != 2 || ra.Counts.Successes != 1 {
		t.Fatalf("counts %+v", ra.Counts)
	}
	if !ra.IsPartial {
		t.Fatal("truncated window must be marked partial")
	}
}

// TestOwnQuotaProjection — the dashboard quota reads the owner's own
// snapshot: used counts every nondeleted monitor, active means
// unpaused, limit is the user's own cap.
func TestOwnQuotaProjection(t *testing.T) {
	svc, _, c := svcFor(t)
	cleanAnalytics(t, c)
	fa := mkMonitor(t, c)
	// second monitor for owner A, paused
	var mon2 uuid.UUID
	if err := c.QueryRow(testCtx, `
		INSERT INTO uptime.monitors(id,user_id,name,target_url,method,
		  interval_seconds,timeout_seconds,next_check_at,is_paused)
		VALUES (gen_random_uuid(),$1,'m2','https://y.test','GET',60,5,
		        now(),true) RETURNING id`, fa.userID).Scan(&mon2); err != nil {
		t.Fatal(err)
	}
	fb := mkMonitor(t, c) // user B

	da, err := svc.Dashboard(testCtx, fa.userID, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if da.Quota.Used != 2 || da.Quota.Active != 1 || da.Quota.Paused != 1 {
		t.Fatalf("quota A %+v", da.Quota)
	}
	if da.Quota.Limit != 10 || da.Quota.Profile != "local" ||
		da.Quota.Source != "server" {
		t.Fatalf("quota meta %+v", da.Quota)
	}
	db, err := svc.Dashboard(testCtx, fb.userID, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if db.Quota.Used != 1 || db.Quota.Active != 1 || db.Quota.Paused != 0 {
		t.Fatalf("quota B %+v", db.Quota)
	}
	if da.Monitors != 2 || db.Monitors != 1 {
		t.Fatalf("monitor counts A=%d B=%d", da.Monitors, db.Monitors)
	}
}
