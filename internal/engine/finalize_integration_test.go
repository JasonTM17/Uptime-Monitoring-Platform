//go:build integration

package engine

import (
	"context"
	"testing"
	"time"

	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/checker"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// finalizeFixture: owner + reserved run + identity ready to finalize.
func finalizeFixture(t *testing.T, conn *pgx.Conn, epoch int64) FinalizeIdentity {
	t.Helper()
	ctx := context.Background()
	userID, monID := seedDue(t)
	res, err := ReserveRun(ctx, conn, monID, 1, caps, epoch)
	if err != nil {
		t.Fatal(err)
	}
	return FinalizeIdentity{
		RunID: res.RunID, MonitorID: monID, OwnerID: userID,
		SegmentID: res.SegmentID, Generation: 1,
		Sequence: res.Sequence, Epoch: epoch,
	}
}

// reserveRunFor forces a DUE state and reserves one more run on the
// SAME monitor - multi-run scenarios need a shared monitor.
func reserveRunFor(t *testing.T, conn *pgx.Conn, monID uuid.UUID, epoch int64, seqGen int64) FinalizeIdentity {
	t.Helper()
	ctx := context.Background()
	var ownerID uuid.UUID
	if err := conn.QueryRow(ctx,
		`SELECT user_id FROM uptime.monitors WHERE id=$1`, monID).Scan(&ownerID); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx,
		`UPDATE uptime.monitors SET next_check_at=now()-interval '1 second' WHERE id=$1`, monID); err != nil {
		t.Fatal(err)
	}
	res, err := ReserveRun(ctx, conn, monID, 1, caps, epoch)
	if err != nil {
		t.Fatal(err)
	}
	var seg uuid.UUID
	conn.QueryRow(ctx,
		`SELECT segment_id FROM uptime.check_runs WHERE id=$1`, res.RunID).Scan(&seg)
	return FinalizeIdentity{
		RunID: res.RunID, MonitorID: monID, OwnerID: ownerID,
		SegmentID: seg, Generation: seqGen, Sequence: res.Sequence, Epoch: epoch,
	}
}

func failObs(t *testing.T, monID uuid.UUID) checker.Observation {
	t.Helper()
	lat := int64(4)
	o, err := checker.NewObservation(
		checker.Target{MonitorID: monID, URL: "https://x", TimeoutSeconds: 2},
		checker.OutcomeConnectError, nil, &lat, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return o
}

func okObservation(t *testing.T, monID uuid.UUID) checker.Observation {
	t.Helper()
	code := 200
	lat := int64(4)
	o, err := checker.NewObservation(
		checker.Target{MonitorID: monID, URL: "https://x", TimeoutSeconds: 2},
		checker.OutcomeSuccess, &code, &lat, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return o
}

func excludedObs(t *testing.T, monID uuid.UUID) checker.Observation {
	t.Helper()
	o, err := checker.NewObservation(
		checker.Target{MonitorID: monID, URL: "https://x", TimeoutSeconds: 2},
		checker.OutcomePolicyBlocked, nil, nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return o
}

// Three eligible failures finalize into: 3 result rows, health DOWN,
// one open incident, run COMPLETED --- all-or-none.
func TestFinalizeAtomicity(t *testing.T) {
	ctx := context.Background()
	conn := engineConn(t)
	owner, _ := AcquireOwner(ctx, conn, uuid.New())
	defer owner.Release(ctx)
	w := NewWriter(owner, time.Minute)

	// Clean slate for exact counts - children before parents so
	// RESTRICT foreign keys cannot silently veto a delete.
	for _, tbl := range []string{
		"hourly_stats", "notification_outbox", "incidents",
		"check_results",
		"check_runs", "schedule_segments", "monitor_channels", "monitors",
	} {
		if _, err := conn.Exec(ctx, "DELETE FROM uptime."+tbl); err != nil {
			t.Fatalf("clean %s: %v", tbl, err)
		}
	}

	// Drive ONE monitor DOWN through three committed finalizes.
	_, monID := seedDue(t)
	for i := 0; i < 3; i++ {
		id := reserveRunFor(t, conn, monID, owner.Epoch(), 1)
		out, err := w.FinalizeObservation(ctx, FinalizeInput{
			Identity: id, Observation: failObs(t, monID)})
		if err != nil || out != FinalizeCommitted {
			t.Fatalf("finalize %d: out=%v err=%v", i, out, err)
		}
	}

	var results, runs, incs int
	var health string
	conn.QueryRow(ctx, `SELECT count(*) FROM uptime.check_results`).Scan(&results)
	conn.QueryRow(ctx, `SELECT count(*) FROM uptime.check_runs WHERE status='COMPLETED'`).Scan(&runs)
	conn.QueryRow(ctx, `SELECT count(*) FROM uptime.incidents WHERE resolved_at IS NULL`).Scan(&incs)
	conn.QueryRow(ctx, `SELECT health FROM uptime.monitors WHERE id=$1`, monID).Scan(&health)
	if results != 3 || runs != 3 || incs != 1 || health != "DOWN" {
		t.Fatalf("projections: results=%d runs=%d incidents=%d health=%s",
			results, runs, incs, health)
	}
}

// Replaying the same run's result changes nothing --- unique check_id
// and terminal status fence the replay before counters move.
func TestFinalizeReplay(t *testing.T) {
	ctx := context.Background()
	conn := engineConn(t)
	owner, _ := AcquireOwner(ctx, conn, uuid.New())
	defer owner.Release(ctx)
	w := NewWriter(owner, time.Minute)

	id := finalizeFixture(t, conn, owner.Epoch())
	in := FinalizeInput{Identity: id, Observation: okObservation(t, id.MonitorID)}
	out, err := w.FinalizeObservation(ctx, in)
	if err != nil || out != FinalizeCommitted {
		t.Fatalf("first finalize: %v %v", out, err)
	}
	out, err = w.FinalizeObservation(ctx, in)
	if err != nil || out != FinalizeDuplicate {
		t.Fatalf("replay: %v %v", out, err)
	}
	var n, streak int
	conn.QueryRow(ctx,
		`SELECT count(*) FROM uptime.check_results WHERE check_id=$1`, id.RunID).Scan(&n)
	conn.QueryRow(ctx,
		`SELECT success_streak FROM uptime.monitors WHERE id=$1`, id.MonitorID).Scan(&streak)
	if n != 1 || streak != 1 {
		t.Fatalf("replay doubled effects: results=%d streak=%d", n, streak)
	}
}

// A finalize error leaves no partial state: when the tx dies before
// commit, result/incident/outbox/monitor all stay untouched and a
// retry is safe (the run is still RESERVED and revalidates).
func TestFinalizeCommitAmbiguity(t *testing.T) {
	ctx := context.Background()
	conn := engineConn(t)
	owner, _ := AcquireOwner(ctx, conn, uuid.New())
	defer owner.Release(ctx)
	w := NewWriter(owner, time.Minute)

	id := finalizeFixture(t, conn, owner.Epoch())
	// Deterministic mid-transaction fault: a result row already exists
	// for this check_id, so the finalize INSERT violates the PK, the
	// tx aborts, and every earlier statement rolls back with it.
	lat := int64(1)
	if _, err := conn.Exec(ctx, `
		INSERT INTO uptime.check_results
		  (check_id,monitor_id,outcome,eligible,success,duration_ms,observed_at)
		VALUES ($1,$2,'SUCCESS',true,true,$3,now())`,
		id.RunID, id.MonitorID, lat); err != nil {
		t.Fatal(err)
	}
	out, err := w.FinalizeObservation(ctx, FinalizeInput{
		Identity: id, Observation: okObservation(t, id.MonitorID)})
	if err == nil {
		t.Fatalf("faulted finalize committed: %v", out)
	}
	// Nothing partial persisted - run still RESERVED, monitor untouched.
	var status, health string
	conn.QueryRow(ctx,
		`SELECT status FROM uptime.check_runs WHERE id=$1`, id.RunID).Scan(&status)
	conn.QueryRow(ctx,
		`SELECT health FROM uptime.monitors WHERE id=$1`, id.MonitorID).Scan(&health)
	if status != "RESERVED" || health != "UNKNOWN" {
		t.Fatalf("partial finalize leaked: status=%s health=%s", status, health)
	}
	// Remove the planted row - retry revalidates and commits once.
	if _, err := conn.Exec(ctx,
		`DELETE FROM uptime.check_results WHERE check_id=$1`, id.RunID); err != nil {
		t.Fatal(err)
	}
	out, err = w.FinalizeObservation(ctx, FinalizeInput{
		Identity: id, Observation: okObservation(t, id.MonitorID)})
	if err != nil || out != FinalizeCommitted {
		t.Fatalf("retry finalize: %v %v", out, err)
	}
}

// An excluded observation: run -> EXCLUDED, streaks reset, health
// unchanged, NO incident/outbox --- collector faults are not evidence.
func TestExcludedFinalize(t *testing.T) {
	ctx := context.Background()
	conn := engineConn(t)
	owner, _ := AcquireOwner(ctx, conn, uuid.New())
	defer owner.Release(ctx)
	w := NewWriter(owner, time.Minute)

	// Seed health UP + streaks via two successes on ONE monitor.
	_, monID := seedDue(t)
	for i := 0; i < 2; i++ {
		id := reserveRunFor(t, conn, monID, owner.Epoch(), 1)
		if _, err := w.FinalizeObservation(ctx, FinalizeInput{
			Identity: id, Observation: okObservation(t, monID)}); err != nil {
			t.Fatal(err)
		}
	}
	var health0 string
	var ss0 int
	if err := conn.QueryRow(ctx,
		`SELECT health,success_streak FROM uptime.monitors WHERE id=$1`, monID).
		Scan(&health0, &ss0); err != nil {
		t.Fatal(err)
	}
	if health0 != "UP" || ss0 != 2 {
		t.Fatalf("seed state wrong: health=%s ss=%d", health0, ss0)
	}

	id := reserveRunFor(t, conn, monID, owner.Epoch(), 1)
	out, err := w.FinalizeObservation(ctx, FinalizeInput{
		Identity: id, Observation: excludedObs(t, monID)})
	if err != nil || out != FinalizeCommitted {
		t.Fatalf("excluded finalize: %v %v", out, err)
	}

	var status, reason string
	var health string
	var fs, ss int
	var incs, obs int
	conn.QueryRow(ctx,
		`SELECT status,COALESCE(terminal_reason,'') FROM uptime.check_runs WHERE id=$1`,
		id.RunID).Scan(&status, &reason)
	conn.QueryRow(ctx,
		`SELECT health,failure_streak,success_streak FROM uptime.monitors WHERE id=$1`,
		id.MonitorID).Scan(&health, &fs, &ss)
	conn.QueryRow(ctx,
		`SELECT count(*) FROM uptime.incidents WHERE monitor_id=$1`, id.MonitorID).Scan(&incs)
	conn.QueryRow(ctx,
		`SELECT count(*) FROM uptime.notification_outbox WHERE monitor_id=$1`, id.MonitorID).Scan(&obs)

	if status != "EXCLUDED" || health != health0 || fs != 0 || ss != 0 {
		t.Fatalf("excluded effects wrong: status=%s health=%s fs=%d ss=%d",
			status, health, fs, ss)
	}
	if incs != 0 || obs != 0 {
		t.Fatalf("excluded produced incident/outbox: %d %d", incs, obs)
	}
}

// Regression for the streak/schema contract: persisted streaks are
// capped (failure<=3, success<=2), so sustained same-direction
// evidence must saturate at the threshold instead of wedging the
// monitor's next reservation on a CHECK violation.
func TestStreakSaturation(t *testing.T) {
	ctx := context.Background()
	conn := engineConn(t)
	owner, _ := AcquireOwner(ctx, conn, uuid.New())
	defer owner.Release(ctx)
	w := NewWriter(owner, time.Minute)
	for _, tbl := range []string{
		"hourly_stats", "notification_outbox", "incidents",
		"check_results",
		"check_runs", "schedule_segments", "monitor_channels", "monitors",
	} {
		if _, err := conn.Exec(ctx, "DELETE FROM uptime."+tbl); err != nil {
			t.Fatalf("clean %s: %v", tbl, err)
		}
	}
	_, monID := seedDue(t)

	fin := func(obs checker.Observation) {
		id := reserveRunFor(t, conn, monID, owner.Epoch(), 1)
		out, err := w.FinalizeObservation(ctx,
			FinalizeInput{Identity: id, Observation: obs})
		if err != nil || out != FinalizeCommitted {
			t.Fatalf("finalize: out=%v err=%v", out, err)
		}
	}

	// Three failures reach DOWN; four more must saturate fs at 3 and
	// still commit - every run reaches a terminal state.
	for i := 0; i < 7; i++ {
		fin(failObs(t, monID))
	}
	var fs int
	var health string
	conn.QueryRow(ctx,
		`SELECT failure_streak, health::text FROM uptime.monitors WHERE id=$1`,
		monID).Scan(&fs, &health)
	if health != "DOWN" || fs != 3 {
		t.Fatalf("post-failures: health=%s fs=%d want DOWN/3", health, fs)
	}

	// Two successes recover UP; three more saturate ss at 2.
	for i := 0; i < 2; i++ {
		fin(okObservation(t, monID))
	}
	var ss int
	conn.QueryRow(ctx,
		`SELECT success_streak, health::text FROM uptime.monitors WHERE id=$1`,
		monID).Scan(&ss, &health)
	if health != "UP" {
		t.Fatalf("post-recovery: health=%s want UP", health)
	}
	for i := 0; i < 3; i++ {
		fin(okObservation(t, monID))
	}
	conn.QueryRow(ctx,
		`SELECT success_streak, health::text FROM uptime.monitors WHERE id=$1`,
		monID).Scan(&ss, &health)
	if health != "UP" || ss != 2 {
		t.Fatalf("saturated: health=%s ss=%d want UP/2", health, ss)
	}

	// The monitor remains schedulable - no wedged active run.
	var active int
	conn.QueryRow(ctx,
		`SELECT count(*) FROM uptime.check_runs
		  WHERE monitor_id=$1 AND status IN ('RESERVED','RUNNING')`, monID).Scan(&active)
	if active != 0 {
		t.Fatalf("active runs wedge: %d", active)
	}
}
