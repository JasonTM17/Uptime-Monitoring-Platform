//go:build integration

package analytics

// C52 — the denominator contract under lifecycle change: hand-built
// timelines with independent arithmetic oracles. The invariant under
// test is expected = valid + excluded + missed + pending over the
// same represented window, stable across rollup and raw purge.
// Missed is a complement — no fake observations are created to
// balance the books.

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// mkSegmentRow inserts an explicit segment without disturbing the
// fixture's default one — multi-segment timelines need direct
// control of the eligible grid.
func mkSegmentRow(t *testing.T, c *pgx.Conn, monID uuid.UUID, gen int64,
	start time.Time, end *time.Time, ivSeconds int) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := c.QueryRow(context.Background(), `
		INSERT INTO uptime.schedule_segments(id,monitor_id,generation,
		  starts_at,ends_at,interval_seconds)
		VALUES (gen_random_uuid(),$1,$2,$3,$4,$5) RETURNING id`,
		monID, gen, start, end, ivSeconds).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

func mkResultSeg(t *testing.T, c *pgx.Conn, monID, segID uuid.UUID,
	seq int64, slotAt time.Time, outcome string, eligible bool,
	success *bool) {
	t.Helper()
	var runID uuid.UUID
	if err := c.QueryRow(context.Background(), `
		INSERT INTO uptime.check_runs(id,monitor_id,segment_id,slot_at,
		  generation,sequence,engine_epoch,status,reserved_at,finished_at)
		VALUES (gen_random_uuid(),$1,$2,$3,1,$4,1,'COMPLETED',$5,$5)
		RETURNING id`,
		monID, segID, slotAt, seq, slotAt).Scan(&runID); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Exec(context.Background(), `
		INSERT INTO uptime.check_results(check_id,monitor_id,outcome,
		  eligible,success,duration_ms,observed_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		runID, monID, outcome, eligible, success, int64(10), slotAt); err != nil {
		t.Fatal(err)
	}
}

func mkStaleRun(t *testing.T, c *pgx.Conn, monID, segID uuid.UUID,
	seq int64, slotAt time.Time) {
	t.Helper()
	if _, err := c.Exec(context.Background(), `
		INSERT INTO uptime.check_runs(id,monitor_id,segment_id,slot_at,
		  generation,sequence,engine_epoch,status,reserved_at,finished_at)
		VALUES (gen_random_uuid(),$1,$2,$3,1,$4,1,'STALE',$5,$5)`,
		monID, segID, slotAt, seq, slotAt); err != nil {
		t.Fatal(err)
	}
}

// assertDenom checks the full partition identity on one stats call.
func assertDenom(t *testing.T, res StatsResult, wantExp, wantValid,
	wantMissed, wantPending int64) {
	t.Helper()
	if res.Expected != wantExp || res.Counts.Valid != wantValid ||
		res.Missed != wantMissed || res.Pending != wantPending {
		t.Fatalf("exp=%d valid=%d missed=%d pending=%d (want %d/%d/%d/%d)",
			res.Expected, res.Counts.Valid, res.Missed, res.Pending,
			wantExp, wantValid, wantMissed, wantPending)
	}
	got := res.Counts.Valid + res.Counts.Excluded +
		res.Missed + res.Pending
	if got != res.Expected {
		t.Fatalf("partition broken: %d != expected %d", got, res.Expected)
	}
	if res.Expected > 0 && res.Coverage == nil {
		t.Fatal("coverage must exist when expected>0")
	}
	if res.Expected == 0 && res.Coverage != nil {
		t.Fatal("coverage must be null when expected=0")
	}
}

// TestStaleSlotCoverage — the spec's canonical schedule: reserve at
// 10:00, pause at 10:00:01, the late SUCCESS rejected STALE. The
// slot is owed and missed forever: expected1/missed1 — and the
// answer is IDENTICAL after rollup and raw purge because segments
// are the denominator's durable evidence.
func TestStaleSlotCoverage(t *testing.T) {
	svc, pool, c := svcFor(t)
	cleanAnalytics(t, c)
	t0 := time.Date(2025, 3, 1, 10, 0, 0, 0, time.UTC)
	segEnd := t0.Add(time.Minute)

	f := mkMonitor(t, c)
	// The fixture's own segment is unrelated; close it off-window.
	if _, err := c.Exec(context.Background(), `
		DELETE FROM uptime.schedule_segments WHERE id=$1`,
		f.segID); err != nil {
		t.Fatal(err)
	}
	seg := mkSegmentRow(t, c, f.monID, 1, t0, &segEnd, 60)
	mkStaleRun(t, c, f.monID, seg, 1, t0)

	ws, we, now := t0, t0.Add(time.Hour), t0.Add(time.Hour)
	res, err := svc.Statistics(context.Background(), f.userID, f.monID,
		ws, we, now)
	if err != nil {
		t.Fatal(err)
	}
	assertDenom(t, res, 1, 0, 1, 0)
	if res.SampleUptime != nil {
		t.Fatal("no eligible evidence — uptime must be null, not 0/100")
	}

	// Rollup (nothing to roll — the run has no result) then purge
	// the aged raw run: the denominator must not move.
	old := time.Now().Add(-40 * 24 * time.Hour)
	if _, err := c.Exec(context.Background(), `
		UPDATE uptime.check_runs SET finished_at=$2
		WHERE monitor_id=$1`, f.monID, old); err != nil {
		t.Fatal(err)
	}
	cut := time.Now().Add(-30 * 24 * time.Hour)
	if _, _, err := PurgeRolledBatch(context.Background(), c, cut, 100); err != nil {
		t.Fatal(err)
	}

	res, err = svc.Statistics(context.Background(), f.userID, f.monID,
		ws, we, now)
	if err != nil {
		t.Fatal(err)
	}
	assertDenom(t, res, 1, 0, 1, 0)
	_ = pool
}

// TestIntervalChangeDenominator — a 60s segment yields 5 slots, a
// 120s successor yields 3: expected is the SUM over segments, never
// the current interval stretched over history.
func TestIntervalChangeDenominator(t *testing.T) {
	svc, _, c := svcFor(t)
	cleanAnalytics(t, c)
	t0 := time.Date(2025, 3, 2, 10, 0, 0, 0, time.UTC)
	end1 := t0.Add(5 * time.Minute)
	end2 := t0.Add(10 * time.Minute)

	f := mkMonitor(t, c)
	if _, err := c.Exec(context.Background(), `
		DELETE FROM uptime.schedule_segments WHERE id=$1`,
		f.segID); err != nil {
		t.Fatal(err)
	}
	seg1 := mkSegmentRow(t, c, f.monID, 1, t0, &end1, 60)    // 5 slots
	seg2 := mkSegmentRow(t, c, f.monID, 2, end1, &end2, 120) // 3 slots

	mkResultSeg(t, c, f.monID, seg1, 1, t0, "SUCCESS", true, b(true))
	mkResultSeg(t, c, f.monID, seg1, 2, t0.Add(time.Minute),
		"SUCCESS", true, b(true))
	mkResultSeg(t, c, f.monID, seg2, 3, end1, "TIMEOUT", true, b(false))
	// remaining 5 nominal slots: downtime — missed, not fabricated.

	now := t0.Add(time.Hour)
	res, err := svc.Statistics(context.Background(), f.userID, f.monID,
		t0, t0.Add(time.Hour), now)
	if err != nil {
		t.Fatal(err)
	}
	assertDenom(t, res, 8, 3, 5, 0)
	if res.SampleUptime == nil || *res.SampleUptime != 2.0/3.0 {
		t.Fatalf("uptime %v", res.SampleUptime)
	}
}

// TestPausedWindowExcluded — paused/suspended time lives outside
// every segment, so it never enters the denominator even though the
// requested window spans it.
func TestPausedWindowExcluded(t *testing.T) {
	svc, _, c := svcFor(t)
	cleanAnalytics(t, c)
	t0 := time.Date(2025, 3, 3, 10, 0, 0, 0, time.UTC)
	end1 := t0.Add(5 * time.Minute)
	resume := t0.Add(15 * time.Minute)
	end2 := t0.Add(20 * time.Minute)

	f := mkMonitor(t, c)
	if _, err := c.Exec(context.Background(), `
		DELETE FROM uptime.schedule_segments WHERE id=$1`,
		f.segID); err != nil {
		t.Fatal(err)
	}
	seg1 := mkSegmentRow(t, c, f.monID, 1, t0, &end1, 60)
	seg2 := mkSegmentRow(t, c, f.monID, 2, resume, &end2, 60)

	mkResultSeg(t, c, f.monID, seg1, 1, t0, "SUCCESS", true, b(true))
	mkResultSeg(t, c, f.monID, seg2, 2, resume, "SUCCESS", true, b(true))

	now := t0.Add(time.Hour)
	res, err := svc.Statistics(context.Background(), f.userID, f.monID,
		t0, t0.Add(time.Hour), now)
	if err != nil {
		t.Fatal(err)
	}
	// 5 + 5 slots owed; the 10-minute pause contributes zero.
	assertDenom(t, res, 10, 2, 8, 0)
}

// TestPurgePreservesDenominator — the checkpoint invariant end to
// end: roll the results, purge aged raw, and the whole partition
// (counts AND denominators) is identical.
func TestPurgePreservesDenominator(t *testing.T) {
	svc, pool, c := svcFor(t)
	cleanAnalytics(t, c)
	t0 := time.Date(2025, 3, 4, 10, 0, 0, 0, time.UTC)
	segEnd := t0.Add(6 * time.Minute)

	f := mkMonitor(t, c)
	if _, err := c.Exec(context.Background(), `
		DELETE FROM uptime.schedule_segments WHERE id=$1`,
		f.segID); err != nil {
		t.Fatal(err)
	}
	seg := mkSegmentRow(t, c, f.monID, 1, t0, &segEnd, 60) // 6 slots

	mkResultSeg(t, c, f.monID, seg, 1, t0, "SUCCESS", true, b(true))
	mkResultSeg(t, c, f.monID, seg, 2, t0.Add(time.Minute),
		"TIMEOUT", true, b(false))
	mkResultSeg(t, c, f.monID, seg, 3, t0.Add(2*time.Minute),
		"POLICY_BLOCKED", false, nil)
	mkStaleRun(t, c, f.monID, seg, 4, t0.Add(3*time.Minute))
	// slots 4,5: unreserved — missed.

	now := t0.Add(time.Hour)
	ws, we := t0, t0.Add(time.Hour)
	before, err := svc.Statistics(context.Background(), f.userID,
		f.monID, ws, we, now)
	if err != nil {
		t.Fatal(err)
	}
	assertDenom(t, before, 6, 2, 3, 0)

	if _, err := RollupUntilQuiet(context.Background(), pool,
		RollupConfig{Batch: 500}); err != nil {
		t.Fatal(err)
	}
	// Age every run past the raw horizon and purge.
	old := time.Now().Add(-40 * 24 * time.Hour)
	if _, err := c.Exec(context.Background(), `
		UPDATE uptime.check_runs SET finished_at=$2
		WHERE monitor_id=$1`, f.monID, old); err != nil {
		t.Fatal(err)
	}
	cut := time.Now().Add(-30 * 24 * time.Hour)
	n, _, err := PurgeRolledBatch(context.Background(), c, cut, 100)
	if err != nil || n != 4 {
		t.Fatalf("purged %d err=%v", n, err)
	}

	after, err := svc.Statistics(context.Background(), f.userID,
		f.monID, ws, we, now)
	if err != nil {
		t.Fatal(err)
	}
	assertDenom(t, after, 6, 2, 3, 0)
	if after.Counts != before.Counts {
		t.Fatalf("counts drifted %+v -> %+v", before.Counts, after.Counts)
	}
}
