//go:build integration

package incident

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func conn(t *testing.T) *pgx.Conn {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Fatal("TEST_DATABASE_URL required (disposable postgres-test)")
	}
	c, err := pgx.Connect(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close(context.Background()) })
	return c
}

// seedRun creates owner+monitor+segment+run; returns run id.
func seedRun(t *testing.T, c *pgx.Conn) (monID, runID uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	var userID uuid.UUID
	if err := c.QueryRow(ctx, `
		INSERT INTO uptime.users(id,email,password_hash,status,monitor_limit)
		VALUES (gen_random_uuid(),$1,'x','ACTIVE',10) RETURNING id`,
		"inc+"+uuid.NewString()[:8]+"@test.invalid").Scan(&userID); err != nil {
		t.Fatal(err)
	}
	if err := c.QueryRow(ctx, `
		INSERT INTO uptime.monitors(id,user_id,name,target_url,method,
		  interval_seconds,timeout_seconds,next_check_at)
		VALUES (gen_random_uuid(),$1,'m','https://x.test','GET',60,5,now())
		RETURNING id`, userID).Scan(&monID); err != nil {
		t.Fatal(err)
	}
	var segID uuid.UUID
	if err := c.QueryRow(ctx, `
		INSERT INTO uptime.schedule_segments(id,monitor_id,generation,starts_at,interval_seconds)
		VALUES (gen_random_uuid(),$1,1,now(),60) RETURNING id`, monID).Scan(&segID); err != nil {
		t.Fatal(err)
	}
	if err := c.QueryRow(ctx, `
		INSERT INTO uptime.check_runs(id,monitor_id,segment_id,slot_at,generation,
		  sequence,engine_epoch,status)
		VALUES (gen_random_uuid(),$1,$2,now(),1,1,1,'COMPLETED') RETURNING id`,
		monID, segID).Scan(&runID); err != nil {
		t.Fatal(err)
	}
	return monID, runID
}

// Schema oracles: close_reason enum, resolved>=opened, one open max,
// run-FK anchors - all enforced by the migration itself.
func TestIncidentMigration(t *testing.T) {
	ctx := context.Background()
	c := conn(t)
	monID, runID := seedRun(t, c)

	tx, _ := c.Begin(ctx)
	if _, err := tx.Exec(ctx, `
		INSERT INTO uptime.incidents(id,monitor_id,opened_check_id,opened_at,
		  resolved_at,close_reason)
		VALUES (gen_random_uuid(),$1,$2,now(),now(),'NOT_A_REASON')`,
		monID, runID); err == nil {
		t.Fatal("invalid close_reason accepted")
	}
	tx.Rollback(ctx)

	tx, _ = c.Begin(ctx)
	if _, err := tx.Exec(ctx, `
		INSERT INTO uptime.incidents(id,monitor_id,opened_check_id,opened_at,
		  resolved_at,close_reason)
		VALUES (gen_random_uuid(),$1,$2,now(),now()-interval '1 hour','RECOVERED')`,
		monID, runID); err == nil {
		t.Fatal("resolved_at before opened_at accepted")
	}
	tx.Rollback(ctx)

	// Resolved row without reason is rejected.
	tx, _ = c.Begin(ctx)
	if _, err := tx.Exec(ctx, `
		INSERT INTO uptime.incidents(id,monitor_id,opened_check_id,opened_at,resolved_at)
		VALUES (gen_random_uuid(),$1,$2,now(),now())`, monID, runID); err == nil {
		t.Fatal("resolved without reason accepted")
	}
	tx.Rollback(ctx)

	// Run FK anchor: a run id belonging to a DIFFERENT monitor fails.
	mon2, _ := seedRun(t, c)
	tx, _ = c.Begin(ctx)
	if _, err := tx.Exec(ctx, `
		INSERT INTO uptime.incidents(id,monitor_id,opened_check_id,opened_at)
		VALUES (gen_random_uuid(),$1,$2,now())`, mon2, runID); err == nil {
		t.Fatal("cross-monitor run anchor accepted")
	}
	tx.Rollback(ctx)
}

// Open -> repeat open fails (ErrAlreadyOpen) -> close -> reopen ok.
func TestOneOpenIncident(t *testing.T) {
	ctx := context.Background()
	c := conn(t)
	monID, runID := seedRun(t, c)
	repo := Repository{}

	// tx1: open + commit.
	tx, _ := c.Begin(ctx)
	in, err := repo.OpenIncident(ctx, tx, monID, runID)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	tx.Commit(ctx)
	// tx2: concurrent second open surfaces ErrAlreadyOpen (the tx is
	// poisoned by the constraint - it dies with this attempt).
	tx, _ = c.Begin(ctx)
	if _, err := repo.OpenIncident(ctx, tx, monID, runID); !errors.Is(err, ErrAlreadyOpen) {
		t.Fatalf("second open: %v", err)
	}
	tx.Rollback(ctx)
	// tx3: active lookup, close, reopen in one transaction.
	tx, _ = c.Begin(ctx)
	got, err := repo.GetActiveIncident(ctx, tx, monID)
	if err != nil || got.ID != in.ID {
		t.Fatalf("active lookup: %v %+v", err, got)
	}
	closed, err := repo.CloseIncident(ctx, tx, monID, &runID, ReasonRecovered)
	if err != nil || !closed {
		t.Fatalf("close: %v closed=%v", err, closed)
	}
	// After close, a fresh open is legal (new incident, not a rewrite).
	in2, err := repo.OpenIncident(ctx, tx, monID, runID)
	if err != nil || in2.ID == in.ID {
		t.Fatalf("reopen: %v", err)
	}
	tx.Commit(ctx)
}

// Repository mutations live inside the CALLER's tx: rollback removes
// the incident entirely.
func TestIncidentRollback(t *testing.T) {
	ctx := context.Background()
	c := conn(t)
	monID, runID := seedRun(t, c)
	repo := Repository{}

	tx, _ := c.Begin(ctx)
	if _, err := repo.OpenIncident(ctx, tx, monID, runID); err != nil {
		t.Fatal(err)
	}
	tx.Rollback(ctx)

	var n int
	if err := c.QueryRow(ctx,
		`SELECT count(*) FROM uptime.incidents WHERE monitor_id=$1`,
		monID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("rollback left incident: %d", n)
	}
}

// Administrative closure writes the reason verbatim - CONFIG_CHANGED
// and DELETED never masquerade as RECOVERED.
func TestLifecycleClosureCause(t *testing.T) {
	ctx := context.Background()
	c := conn(t)
	repo := Repository{}

	for _, reason := range []CloseReason{ReasonConfigChanged, ReasonDeleted, ReasonRecovered} {
		monID, runID := seedRun(t, c)
		tx, _ := c.Begin(ctx)
		if _, err := repo.OpenIncident(ctx, tx, monID, runID); err != nil {
			t.Fatal(err)
		}
		if _, err := repo.CloseIncident(ctx, tx, monID, &runID, reason); err != nil {
			t.Fatal(err)
		}
		tx.Commit(ctx)
		var got string
		if err := c.QueryRow(ctx,
			`SELECT close_reason FROM uptime.incidents WHERE monitor_id=$1`,
			monID).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != string(reason) {
			t.Fatalf("reason %q recorded %q", reason, got)
		}
	}
	// Closing with nothing open reports false - no fabricated closure.
	monID, runID := seedRun(t, c)
	tx, _ := c.Begin(ctx)
	closed, err := repo.CloseIncident(ctx, tx, monID, &runID, ReasonRecovered)
	if err != nil {
		t.Fatal(err)
	}
	tx.Commit(ctx)
	if closed {
		t.Fatal("close reported on monitor with no open incident")
	}
}
