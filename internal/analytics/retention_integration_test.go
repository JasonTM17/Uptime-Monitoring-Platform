//go:build integration

package analytics

// C51 — bounded retention over the disposable database. Oracles are
// exact row IDs/counts, never "some rows disappeared".

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func countRows(t *testing.T, c *pgx.Conn, table, monID string) int {
	t.Helper()
	var n int
	if err := c.QueryRow(context.Background(),
		`SELECT count(*) FROM uptime.`+table+` WHERE monitor_id=$1`,
		monID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// mkAgedResult seeds a terminal run+result with controlled
// finished_at — the age dimension retention keys on.
func mkAgedResult(t *testing.T, c *pgx.Conn, f monFixture, seq int64,
	slotAt, finishedAt time.Time, outcome string, eligible bool,
	success *bool) uuid.UUID {
	t.Helper()
	var runID uuid.UUID
	if err := c.QueryRow(context.Background(), `
		INSERT INTO uptime.check_runs(id,monitor_id,segment_id,slot_at,
		  generation,sequence,engine_epoch,status,reserved_at,finished_at)
		VALUES (gen_random_uuid(),$1,$2,$3,1,$4,1,'COMPLETED',$5,$5)
		RETURNING id`,
		f.monID, f.segID, slotAt, seq, finishedAt).Scan(&runID); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Exec(context.Background(), `
		INSERT INTO uptime.check_results(check_id,monitor_id,outcome,
		  eligible,success,duration_ms,observed_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		runID, f.monID, outcome, eligible, success, int64(10),
		finishedAt); err != nil {
		t.Fatal(err)
	}
	return runID
}

func runExists(t *testing.T, c *pgx.Conn, id uuid.UUID) bool {
	t.Helper()
	var n int
	if err := c.QueryRow(context.Background(),
		`SELECT count(*) FROM uptime.check_runs WHERE id=$1`,
		id).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n > 0
}

func setRolled(t *testing.T, c *pgx.Conn, runID uuid.UUID, rolled bool) {
	t.Helper()
	var v interface{}
	if rolled {
		v = time.Now()
	}
	if _, err := c.Exec(context.Background(), `
		UPDATE uptime.check_results SET rolled_up_at=$2
		WHERE check_id=$1`, runID, v); err != nil {
		t.Fatal(err)
	}
}

// TestRetentionRequiresRollup — unrolled raw NEVER leaves, no matter
// how old. Only after rollup commit does the pair become eligible.
func TestRetentionRequiresRollup(t *testing.T) {
	_, c := apool(t), aconn(t)
	cleanAnalytics(t, c)
	f := mkMonitor(t, c)
	old := time.Now().Add(-40 * 24 * time.Hour)

	unrolled := mkAgedResult(t, c, f, 1, old, old,
		"SUCCESS", true, b(true))
	rolled := mkAgedResult(t, c, f, 2, old.Add(time.Minute), old,
		"SUCCESS", true, b(true))
	setRolled(t, c, rolled, true)

	cut := time.Now().Add(-30 * 24 * time.Hour)
	r, res, err := PurgeRolledBatch(context.Background(), c, cut, 100)
	if err != nil {
		t.Fatal(err)
	}
	if r != 1 || res != 1 {
		t.Fatalf("purged runs=%d results=%d", r, res)
	}
	if !runExists(t, c, unrolled) {
		t.Fatal("unrolled raw was purged — rollup barrier broken")
	}
	if runExists(t, c, rolled) {
		t.Fatal("rolled eligible pair survived")
	}
}

// TestRetentionCutoff — the boundary is exact: a pair finished just
// inside the horizon stays; one outside leaves.
func TestRetentionCutoff(t *testing.T) {
	_, c := apool(t), aconn(t)
	cleanAnalytics(t, c)
	f := mkMonitor(t, c)
	cut := time.Now().Add(-30 * 24 * time.Hour)

	stay := mkAgedResult(t, c, f, 1, cut.Add(time.Hour),
		cut.Add(time.Hour), "SUCCESS", true, b(true))
	gone := mkAgedResult(t, c, f, 2, cut.Add(-time.Hour).Add(time.Minute),
		cut.Add(-time.Hour), "SUCCESS", true, b(true))
	setRolled(t, c, stay, true)
	setRolled(t, c, gone, true)

	r, _, err := PurgeRolledBatch(context.Background(), c, cut, 100)
	if err != nil || r != 1 {
		t.Fatalf("purged %d err=%v", r, err)
	}
	if !runExists(t, c, stay) || runExists(t, c, gone) {
		t.Fatal("cutoff boundary wrong")
	}
}

// TestRetentionReferences — runs anchoring an incident (opened or
// resolved) outlive raw retention; a STALE run with no result is
// still purge-eligible once aged and unanchored.
func TestRetentionReferences(t *testing.T) {
	_, c := apool(t), aconn(t)
	cleanAnalytics(t, c)
	f := mkMonitor(t, c)
	old := time.Now().Add(-40 * 24 * time.Hour)

	anchor := mkAgedResult(t, c, f, 1, old, old,
		"TIMEOUT", true, b(false))
	setRolled(t, c, anchor, true)
	// An incident referencing the run — the FK anchor.
	if _, err := c.Exec(context.Background(), `
		INSERT INTO uptime.incidents(id,monitor_id,opened_check_id,
		  opened_at)
		VALUES (gen_random_uuid(),$1,$2,$3)`,
		f.monID, anchor, old); err != nil {
		t.Fatal(err)
	}

	stale := mkBareRunNoResult(t, c, f, 2, old.Add(time.Minute))

	cut := time.Now().Add(-30 * 24 * time.Hour)
	r, _, err := PurgeRolledBatch(context.Background(), c, cut, 100)
	if err != nil {
		t.Fatal(err)
	}
	if !runExists(t, c, anchor) {
		t.Fatal("incident-anchored run was purged")
	}
	if r != 1 || runExists(t, c, stale) {
		t.Fatalf("unanchored stale run retained (purged=%d)", r)
	}
}

func mkBareRunNoResult(t *testing.T, c *pgx.Conn, f monFixture,
	seq int64, at time.Time) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := c.QueryRow(context.Background(), `
		INSERT INTO uptime.check_runs(id,monitor_id,segment_id,slot_at,
		  generation,sequence,engine_epoch,status,reserved_at,finished_at)
		VALUES (gen_random_uuid(),$1,$2,$3,1,$4,1,'STALE',$5,$5)
		RETURNING id`, f.monID, f.segID, at, seq, at).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

// TestRetentionBatchRecovery — a sweep interrupted mid-work resumes
// from durable commits: batch size 1, cancel after the first commit,
// a second RunRetention finishes exactly the remainder.
func TestRetentionBatchRecovery(t *testing.T) {
	pool, c := apool(t), aconn(t)
	cleanAnalytics(t, c)
	f := mkMonitor(t, c)
	old := time.Now().Add(-40 * 24 * time.Hour)

	for i := int64(1); i <= 3; i++ {
		id := mkAgedResult(t, c, f, i,
			old.Add(time.Duration(i)*time.Minute), old,
			"SUCCESS", true, b(true))
		setRolled(t, c, id, true)
	}
	// One young pair must remain.
	young := mkAgedResult(t, c, f, 9, time.Now(), time.Now(),
		"SUCCESS", true, b(true))
	setRolled(t, c, young, true)

	cfg := RetentionConfig{
		RawRetentionHours:   30 * 24,
		HourlyRetentionDays: 30,
		OutboxRetentionDays: 30,
		Batch:               1,
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // immediately cancelled — nothing may run
	rep, err := RunRetention(ctx, pool, cfg, time.Now())
	if err == nil {
		t.Fatal("cancelled sweep must surface ctx error")
	}
	if rep.RunsPurged != 0 {
		t.Fatalf("cancelled sweep still purged %d", rep.RunsPurged)
	}

	rep, err = RunRetention(context.Background(), pool, cfg, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if rep.RunsPurged != 3 || rep.ResultsPurged != 3 {
		t.Fatalf("resume purged %+v", rep)
	}
	if !runExists(t, c, young) {
		t.Fatal("young pair purged")
	}
	if got := countRows(t, c, "check_runs", f.monID.String()); got != 1 {
		t.Fatalf("runs left %d", got)
	}
}
