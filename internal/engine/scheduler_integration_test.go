//go:build integration

package engine

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

// End-to-end churn: reserve -> complete -> pause -> resume -> edit ->
// delete+recreate under the REAL SelectDue/ReserveRun seams, with a
// bounded admission budget and positive cadence controls.
func TestLifecycleChurnAdmissionBudget(t *testing.T) {
	ctx := context.Background()
	conn := engineConn(t)
	caps := AdmissionCaps{OwnerPer60s: 10, GlobalPer60s: 10}

	// Clean slate: prior engine tests leave due monitors + window
	// charges on this disposable DB. Children before parents (RESTRICT).
	for _, tbl := range []string{
		"check_results", "check_runs", "schedule_segments", "monitor_channels", "monitors",
	} {
		if _, err := conn.Exec(ctx, "DELETE FROM uptime."+tbl); err != nil {
			t.Fatalf("clean %s: %v", tbl, err)
		}
	}

	owner, err := AcquireOwner(ctx, conn, uuid.New())
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Release(ctx)
	w := NewWriter(owner, 60*time.Second)
	s := NewScheduler(w, NewWorkerPool(2, 8, &fakeChecker{}), owner.Epoch(), caps, 50)

	seed := func(t *testing.T) uuid.UUID {
		_, monID := seedDue(t)
		return monID
	}
	complete := func(monID uuid.UUID) {
		t.Helper()
		if _, err := conn.Exec(ctx,
			`UPDATE uptime.check_runs SET status='COMPLETED',finished_at=now()
			 WHERE monitor_id=$1`, monID); err != nil {
			t.Fatal(err)
		}
	}

	// One due monitor -> one admission through the real tick path.
	monID := seed(t)
	n, err := s.Tick(ctx)
	if err != nil || n != 1 {
		t.Fatalf("first tick: n=%d err=%v", n, err)
	}
	// Active run exists -> no duplicate admission.
	if n, _ := s.Tick(ctx); n != 0 {
		t.Fatalf("duplicate admission with active run: %d", n)
	}
	// After completion the schedule already advanced - not a hot loop.
	complete(monID)
	if n, _ := s.Tick(ctx); n != 0 {
		t.Fatalf("schedule advanced but monitor re-admitted early: %d", n)
	}

	// Pause -> skipped even when due-forced.
	if _, err := conn.Exec(ctx, `
		UPDATE uptime.monitors SET is_paused=true, next_check_at=now()
		WHERE id=$1`, monID); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.Tick(ctx); n != 0 {
		t.Fatalf("paused monitor admitted: %d", n)
	}
	// Resume -> admitted.
	if _, err := conn.Exec(ctx, `
		UPDATE uptime.monitors SET is_paused=false WHERE id=$1`, monID); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.Tick(ctx); n != 1 {
		t.Fatalf("resumed monitor not admitted: %d", n)
	}
	complete(monID)

	// Edit (generation bump): fresh segment required - stale-gen reuse
	// would be a fence hole.
	if _, err := conn.Exec(ctx, `
		UPDATE uptime.monitors SET generation=generation+1, next_check_at=now()
		WHERE id=$1`, monID); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.Tick(ctx); n != 1 {
		t.Fatalf("edited monitor not admitted: %d", n)
	}
	complete(monID)

	// Delete: tombstoned monitor is never due.
	if _, err := conn.Exec(ctx, `
		UPDATE uptime.monitors SET deleted_at=now(), next_check_at=now()
		WHERE id=$1`, monID); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.Tick(ctx); n != 0 {
		t.Fatalf("deleted monitor admitted: %d", n)
	}
	// Recreate -> fresh monitor admitted.
	mon2 := seed(t)
	if n, _ := s.Tick(ctx); n != 1 {
		t.Fatalf("recreated monitor not admitted: %d", n)
	}
	complete(mon2)

	// Budget exhaustion: the window is wall-clock 60s - commits from
	// earlier suite tests can live inside it, so re-clean for a
	// deterministic baseline before measuring the cap.
	for _, tbl := range []string{
		"check_results", "check_runs", "schedule_segments",
		"monitor_channels", "monitors",
	} {
		if _, err := conn.Exec(ctx, "DELETE FROM uptime."+tbl); err != nil {
			t.Fatalf("re-clean %s: %v", tbl, err)
		}
	}
	// Seed cap+2 due monitors; committed runs in the window must
	// never exceed the global cap.
	for i := 0; i < caps.GlobalPer60s+2; i++ {
		seed(t)
	}
	for i := 0; i < 3; i++ {
		s.Tick(ctx)
	}
	var windowCount int
	if err := conn.QueryRow(ctx, `
		SELECT count(*) FROM uptime.check_runs
		WHERE reserved_at > now()-interval '60 seconds'`).Scan(&windowCount); err != nil {
		t.Fatal(err)
	}
	if windowCount > caps.GlobalPer60s {
		t.Fatalf("window exceeded cap: %d > %d", windowCount, caps.GlobalPer60s)
	}
}
