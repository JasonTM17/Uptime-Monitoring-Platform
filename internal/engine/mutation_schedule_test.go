//go:build integration

package engine

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// snapMonitor captures the projections a fenced result must not move.
type monSnapshot struct {
	health string
	fs, ss int
	nextAt time.Time
}

func snapMon(t *testing.T, conn *pgx.Conn, monID uuid.UUID) monSnapshot {
	t.Helper()
	var s monSnapshot
	if err := conn.QueryRow(context.Background(), `
		SELECT health, failure_streak, success_streak, next_check_at
		FROM uptime.monitors WHERE id=$1`, monID).
		Scan(&s.health, &s.fs, &s.ss, &s.nextAt); err != nil {
		t.Fatal(err)
	}
	return s
}

// Zero durable side-effects for a run: no result row, STALE terminal
// disposition, no incident, no outbox intent.
func assertFencedRun(t *testing.T, conn *pgx.Conn, runID, monID uuid.UUID,
	before monSnapshot) {
	t.Helper()
	ctx := context.Background()
	var status, reason string
	if err := conn.QueryRow(ctx, `
		SELECT status, COALESCE(terminal_reason,'')
		FROM uptime.check_runs WHERE id=$1`, runID).Scan(&status, &reason); err != nil {
		t.Fatal(err)
	}
	if status != "STALE" || reason != "identity_fenced" {
		t.Fatalf("fenced run disposition wrong: %s %q", status, reason)
	}
	var results, incs, outs int
	conn.QueryRow(ctx,
		`SELECT count(*) FROM uptime.check_results WHERE check_id=$1`,
		runID).Scan(&results)
	conn.QueryRow(ctx,
		`SELECT count(*) FROM uptime.incidents WHERE monitor_id=$1`,
		monID).Scan(&incs)
	conn.QueryRow(ctx,
		`SELECT count(*) FROM uptime.notification_outbox WHERE monitor_id=$1`,
		monID).Scan(&outs)
	if results != 0 || incs != 0 || outs != 0 {
		t.Fatalf("fenced result left durable effects: results=%d inc=%d out=%d",
			results, incs, outs)
	}
	after := snapMon(t, conn, monID)
	if after.health != before.health || after.fs != before.fs ||
		after.ss != before.ss || !after.nextAt.Equal(before.nextAt) {
		t.Fatalf("stale result mutated monitor: %+v -> %+v", before, after)
	}
}

// Every lifecycle mutation fences a result committed against the
// pre-mutation world: pause, edit, delete, and owner-disable each
// serialize against finalize on the owner/monitor row locks, and the
// loser (the in-flight result) is absorbed with zero durable effect.
// Mutations mirror the repository contract — each bumps generation
// exactly once.
func TestMutationFinalizeSchedules(t *testing.T) {
	ctx := context.Background()

	mutations := []struct {
		name string
		sql  string
		arg  func(userID, monID uuid.UUID) interface{}
	}{
		{"pause",
			`UPDATE uptime.monitors SET is_paused=true,
			   generation=generation+1, updated_at=now() WHERE id=$1`,
			func(u, m uuid.UUID) interface{} { return m }},
		{"edit",
			`UPDATE uptime.monitors SET target_url='https://edited.test',
			   generation=generation+1, updated_at=now() WHERE id=$1`,
			func(u, m uuid.UUID) interface{} { return m }},
		{"delete",
			`UPDATE uptime.monitors SET deleted_at=now(),
			   generation=generation+1, updated_at=now() WHERE id=$1`,
			func(u, m uuid.UUID) interface{} { return m }},
		{"disable-owner",
			`UPDATE uptime.users SET status='DISABLED', disabled_at=now()
			 WHERE id=$1`,
			func(u, m uuid.UUID) interface{} { return u }},
	}

	for _, mut := range mutations {
		t.Run(mut.name, func(t *testing.T) {
			conn := engineConn(t)
			cleanEngine(t, conn)
			o, err := AcquireOwner(ctx, conn, uuid.New())
			if err != nil {
				t.Fatalf("acquire: %v", err)
			}
			defer o.Release(ctx)
			w := NewWriter(o, time.Minute)

			userID, monID := seedDue(t)
			res, err := ReserveRun(ctx, conn, monID, caps, o.Epoch())
			if err != nil {
				t.Fatalf("reserve: %v", err)
			}
			id := FinalizeIdentity{
				RunID: res.RunID, MonitorID: monID, OwnerID: userID,
				SegmentID: res.SegmentID, Generation: 1,
				Sequence: res.Sequence, Epoch: o.Epoch(),
			}
			before := snapMon(t, conn, monID)

			// Barrier: the mutation commits BEFORE the in-flight
			// result is released — the deterministic interleaving
			// where a worker's observation outlives its schedule.
			if _, err := conn.Exec(ctx, mut.sql, mut.arg(userID, monID)); err != nil {
				t.Fatalf("mutation: %v", err)
			}
			out, err := w.FinalizeObservation(ctx, FinalizeInput{
				Identity: id, Observation: okObservation(t, monID)})
			if err != nil {
				t.Fatalf("finalize errored instead of fencing: %v", err)
			}
			if out != FinalizeStale {
				t.Fatalf("post-%s result committed: %v", mut.name, out)
			}
			assertFencedRun(t, conn, res.RunID, monID, before)
		})
	}

	// Reverse order: finalize commits BEFORE disable — the owner row
	// lock serializes them, committed evidence is preserved, and the
	// subsequent disable does not rewrite history.
	t.Run("finalize-then-disable", func(t *testing.T) {
		conn := engineConn(t)
		cleanEngine(t, conn)
		o, err := AcquireOwner(ctx, conn, uuid.New())
		if err != nil {
			t.Fatalf("acquire: %v", err)
		}
		defer o.Release(ctx)
		w := NewWriter(o, time.Minute)

		userID, monID := seedDue(t)
		res, err := ReserveRun(ctx, conn, monID, caps, o.Epoch())
		if err != nil {
			t.Fatalf("reserve: %v", err)
		}
		id := FinalizeIdentity{
			RunID: res.RunID, MonitorID: monID, OwnerID: userID,
			SegmentID: res.SegmentID, Generation: 1,
			Sequence: res.Sequence, Epoch: o.Epoch(),
		}
		out, err := w.FinalizeObservation(ctx, FinalizeInput{
			Identity: id, Observation: okObservation(t, monID)})
		if err != nil || out != FinalizeCommitted {
			t.Fatalf("pre-disable finalize: %v %v", out, err)
		}
		if _, err := conn.Exec(ctx,
			`UPDATE uptime.users SET status='DISABLED', disabled_at=now()
			 WHERE id=$1`, userID); err != nil {
			t.Fatal(err)
		}
		// Committed evidence survives the disable — no resurrection,
		// no rewrite: 1 result, run COMPLETED, health UP, streak 1.
		var results int
		var status, health string
		var ss int
		conn.QueryRow(ctx, `SELECT count(*) FROM uptime.check_results
			WHERE check_id=$1`, res.RunID).Scan(&results)
		conn.QueryRow(ctx, `SELECT status FROM uptime.check_runs WHERE id=$1`,
			res.RunID).Scan(&status)
		conn.QueryRow(ctx, `SELECT health,success_streak FROM uptime.monitors
			WHERE id=$1`, monID).Scan(&health, &ss)
		if results != 1 || status != "COMPLETED" || health != "UP" || ss != 1 {
			t.Fatalf("committed state rewritten by disable: results=%d run=%s health=%s ss=%d",
				results, status, health, ss)
		}
	})

	// Old result released AFTER a new generation took over: the old
	// run is fenced STALE while the new-generation run commits —
	// exactly one result row, health moved once, no resurrection.
	t.Run("old-result-after-regeneration", func(t *testing.T) {
		conn := engineConn(t)
		cleanEngine(t, conn)
		o, err := AcquireOwner(ctx, conn, uuid.New())
		if err != nil {
			t.Fatalf("acquire: %v", err)
		}
		defer o.Release(ctx)
		w := NewWriter(o, time.Minute)

		userID, monID := seedDue(t)
		resOld, err := ReserveRun(ctx, conn, monID, caps, o.Epoch())
		if err != nil {
			t.Fatalf("reserve old: %v", err)
		}
		oldID := FinalizeIdentity{
			RunID: resOld.RunID, MonitorID: monID, OwnerID: userID,
			SegmentID: resOld.SegmentID, Generation: 1,
			Sequence: resOld.Sequence, Epoch: o.Epoch(),
		}
		// Edit commits: generation 1 -> 2, new schedule segment.
		if _, err := conn.Exec(ctx, `
			UPDATE uptime.monitors SET target_url='https://v2.test',
			  generation=generation+1, updated_at=now(),
			  next_check_at=now()-interval '1 second'
			WHERE id=$1`, monID); err != nil {
			t.Fatal(err)
		}
		// The delayed OLD result now arrives — the generation fence
		// absorbs it: run -> STALE, zero durable effect, which also
		// frees the one-active-run slot for the new schedule.
		out, err := w.FinalizeObservation(ctx, FinalizeInput{
			Identity: oldID, Observation: okObservation(t, monID)})
		if err != nil || out != FinalizeStale {
			t.Fatalf("late old-gen result: %v %v", out, err)
		}
		resNew, err := ReserveRun(ctx, conn, monID, caps, o.Epoch())
		if err != nil {
			t.Fatalf("reserve new gen: %v", err)
		}
		newID := FinalizeIdentity{
			RunID: resNew.RunID, MonitorID: monID, OwnerID: userID,
			SegmentID: resNew.SegmentID, Generation: 2,
			Sequence: resNew.Sequence, Epoch: o.Epoch(),
		}
		// The new-generation result commits normally.
		out, err = w.FinalizeObservation(ctx, FinalizeInput{
			Identity: newID, Observation: okObservation(t, monID)})
		if err != nil || out != FinalizeCommitted {
			t.Fatalf("new-gen finalize: %v %v", out, err)
		}
		var results int
		var ss int
		conn.QueryRow(ctx, `SELECT count(*) FROM uptime.check_results
			WHERE monitor_id=$1`, monID).Scan(&results)
		conn.QueryRow(ctx, `SELECT success_streak FROM uptime.monitors WHERE id=$1`,
			monID).Scan(&ss)
		if results != 1 || ss != 1 {
			t.Fatalf("late result resurrected or doubled: results=%d ss=%d",
				results, ss)
		}
	})
}
