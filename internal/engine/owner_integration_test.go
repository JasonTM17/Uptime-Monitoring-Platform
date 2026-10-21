//go:build integration

package engine

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func engineConn(t *testing.T) *pgx.Conn {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Fatal("TEST_DATABASE_URL is required for integration tests (point it at the disposable postgres-test database)")
	}
	conn, err := pgx.Connect(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { conn.Close(context.Background()) })
	return conn
}

// Two instances, one database: the first acquires, the second blocks
// on the same advisory key — lock contention means not-owner, not
// "start anyway".
func TestSingleEngineOwner(t *testing.T) {
	ctx := context.Background()
	c1 := engineConn(t)
	c2 := engineConn(t)

	o1, err := AcquireOwner(ctx, c1, uuid.New())
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	defer o1.Release(ctx)
	e1 := o1.Epoch()

	acquireCtx, cancel := context.WithTimeout(ctx, 700*time.Millisecond)
	defer cancel()
	o2, err := AcquireOwner(acquireCtx, c2, uuid.New())
	if err == nil {
		t.Fatalf("second instance acquired while first held the lock — scheduler must not start")
	}
	if o2 != nil {
		t.Fatal("second owner non-nil")
	}

	// Release lets a contender take over — with a NEW, larger epoch.
	// c2 is dead after the cancelled acquire (pgx closes on ctx
	// cancellation); a contender must bring its own connection.
	if err := o1.Release(ctx); err != nil {
		t.Fatal(err)
	}
	c3 := engineConn(t)
	o3, err := AcquireOwner(ctx, c3, uuid.New())
	if err != nil {
		t.Fatalf("takeover acquire: %v", err)
	}
	defer o3.Release(ctx)
	if o3.Epoch() <= e1 {
		t.Fatalf("epoch did not bump on takeover: %d -> %d", e1, o3.Epoch())
	}
	if o3.Instance() == uuid.Nil {
		t.Fatal("owner instance not stamped")
	}
}

// Killing the lock-holding conn must poison the writer — the engine
// fails closed, and a fresh instance then takes a new epoch.
func TestOwnerConnectionLoss(t *testing.T) {
	ctx := context.Background()
	c1 := engineConn(t)
	c2 := engineConn(t)

	o1, err := AcquireOwner(ctx, c1, uuid.New())
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	w := NewWriter(o1, 50*time.Millisecond)
	go w.Run(ctx)
	deadline := time.Now().Add(2 * time.Second)
	for w.Alive() && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if !w.Alive() {
		t.Fatal("writer died before the kill")
	}

	// Terminate the backend holding the advisory lock.
	var backendPID int
	if err := c1.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&backendPID); err != nil {
		t.Fatal(err)
	}
	if _, err := c2.Exec(ctx, "SELECT pg_terminate_backend($1)", backendPID); err != nil {
		t.Fatalf("terminate: %v", err)
	}

	deadline = time.Now().Add(3 * time.Second)
	for w.Alive() && time.Now().Before(deadline) {
		time.Sleep(30 * time.Millisecond)
	}
	if w.Alive() {
		t.Fatal("writer still believes it owns a dead connection")
	}

	// The advisory lock died with the session — a new instance can
	// take over with a fenced, larger epoch.
	old := o1.Epoch()
	o2, err := AcquireOwner(ctx, c2, uuid.New())
	if err != nil {
		t.Fatalf("takeover after conn loss: %v", err)
	}
	defer o2.Release(ctx)
	if o2.Epoch() <= old {
		t.Fatalf("epoch not fenced across takeover: %d -> %d", old, o2.Epoch())
	}
}

// Migration 003 constraints: singleton control row, one current
// segment per monitor, one in-flight run per monitor.
func TestEngineMigration(t *testing.T) {
	ctx := context.Background()
	conn := engineConn(t)

	var epoch int64
	if err := conn.QueryRow(ctx,
		"SELECT epoch FROM uptime.engine_control WHERE id=1").Scan(&epoch); err != nil {
		t.Fatalf("engine_control seed: %v", err)
	}
	// A second control row must be impossible.
	if _, err := conn.Exec(ctx,
		"INSERT INTO uptime.engine_control(id,epoch) VALUES (2,1)"); err == nil {
		t.Fatal("second engine_control row accepted")
	}

	// Seed owner+monitor for segment/run constraints.
	var userID uuid.UUID
	if err := conn.QueryRow(ctx, `
		INSERT INTO uptime.users(id,email,password_hash,status,monitor_limit)
		VALUES (gen_random_uuid(), $1, 'x', 'ACTIVE', 10) RETURNING id`,
		"engmig+"+uuid.NewString()[:8]+"@test.invalid").Scan(&userID); err != nil {
		t.Fatal(err)
	}
	var monID uuid.UUID
	if err := conn.QueryRow(ctx, `
		INSERT INTO uptime.monitors(id,user_id,name,target_url,method,
		  interval_seconds,timeout_seconds,expected_status,next_check_at)
		VALUES (gen_random_uuid(),$1,'m','https://x.test','GET',60,5,NULL,now())
		RETURNING id`, userID).Scan(&monID); err != nil {
		t.Fatal(err)
	}
	var segID uuid.UUID
	if err := conn.QueryRow(ctx, `
		INSERT INTO uptime.schedule_segments(id,monitor_id,generation,starts_at,interval_seconds)
		VALUES (gen_random_uuid(),$1,1,now(),60) RETURNING id`, monID).Scan(&segID); err != nil {
		t.Fatal(err)
	}
	// Second current segment for same monitor → partial unique index.
	if _, err := conn.Exec(ctx, `
		INSERT INTO uptime.schedule_segments(id,monitor_id,generation,starts_at,interval_seconds)
		VALUES (gen_random_uuid(),$1,1,now(),60)`, monID); err == nil {
		t.Fatal("two current segments accepted for one monitor")
	}
	// One active run per monitor.
	if _, err := conn.Exec(ctx, `
		INSERT INTO uptime.check_runs(id,monitor_id,segment_id,slot_at,generation,sequence,engine_epoch,status)
		VALUES (gen_random_uuid(),$1,$2,now(),1,1,1,'RESERVED')`, monID, segID); err != nil {
		t.Fatalf("first run: %v", err)
	}
	if _, err := conn.Exec(ctx, `
		INSERT INTO uptime.check_runs(id,monitor_id,segment_id,slot_at,generation,sequence,engine_epoch,status)
		VALUES (gen_random_uuid(),$1,$2,now()+interval '1 minute',1,2,1,'RUNNING')`, monID, segID); err == nil {
		t.Fatal("two active runs accepted for one monitor")
	}
	// A TERMINAL second run is fine — the partial index only covers active.
	if _, err := conn.Exec(ctx, `
		INSERT INTO uptime.check_runs(id,monitor_id,segment_id,slot_at,generation,sequence,engine_epoch,status,finished_at)
		VALUES (gen_random_uuid(),$1,$2,now()+interval '2 minutes',1,3,1,'COMPLETED',now())`, monID, segID); err != nil {
		t.Fatalf("terminal run rejected: %v", err)
	}
}
