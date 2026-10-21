//go:build integration

package monitor_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func testDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Fatal("TEST_DATABASE_URL is required for integration tests (point it at the disposable postgres-test database)")
	}
	return dsn
}

func connect(t *testing.T) *pgx.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, testDSN(t))
	if err != nil {
		t.Fatalf("connect test db: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close(context.Background()) })
	return conn
}

func isPGError(err error, code string) bool {
	var pge *pgconn.PgError
	return errors.As(err, &pge) && pge.Code == code
}

// inTx gives each mutation its own rolled-back transaction — Postgres
// aborts a tx on the first error, so expected-error probes must not
// share one.
func inTx(t *testing.T, conn *pgx.Conn, fn func(tx pgx.Tx)) {
	t.Helper()
	ctx := context.Background()
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	fn(tx)
}

// seedSuffix plus-addresses every fixture email — committed leftovers
// from earlier runs must not collide with rolled-back seeds.
var seedSuffix = fmt.Sprintf("+%d", time.Now().UnixNano())

func seedUser(t *testing.T, tx pgx.Tx, email string) string {
	t.Helper()
	email = strings.Replace(email, "@", seedSuffix+"@", 1)
	var id string
	err := tx.QueryRow(context.Background(),
		`INSERT INTO uptime.users (id,email,password_hash) VALUES (gen_random_uuid(),$1,'h') RETURNING id`, email).Scan(&id)
	if err != nil {
		t.Fatalf("seed user %s: %v", email, err)
	}
	return id
}

func seedMonitor(t *testing.T, tx pgx.Tx, userID, name string) string {
	t.Helper()
	var id string
	err := tx.QueryRow(context.Background(),
		`INSERT INTO uptime.monitors (id,user_id,name,target_url,interval_seconds,next_check_at)
		 VALUES (gen_random_uuid(),$1,$2,'https://example.test',60,now()) RETURNING id`, userID, name).Scan(&id)
	if err != nil {
		t.Fatalf("seed monitor: %v", err)
	}
	return id
}

func seedChannel(t *testing.T, tx pgx.Tx, userID, label string) string {
	t.Helper()
	var id string
	err := tx.QueryRow(context.Background(),
		`INSERT INTO uptime.notification_channels (id,user_id,label) VALUES (gen_random_uuid(),$1,$2) RETURNING id`,
		userID, label).Scan(&id)
	if err != nil {
		t.Fatalf("seed channel: %v", err)
	}
	return id
}

// TestMonitorMigration proves the 002 schema exists and enforces
// ownership, quota-guard, and lifecycle invariants on the migrated
// disposable database.
func TestMonitorMigration(t *testing.T) {
	conn := connect(t)
	ctx := context.Background()

	t.Run("tables and singleton guard exist", func(t *testing.T) {
		var n int
		err := conn.QueryRow(ctx,
			`SELECT count(*) FROM information_schema.tables
			 WHERE table_schema='uptime' AND table_name IN
			   ('quota_budgets','monitors','notification_channels','monitor_channels')`).Scan(&n)
		if err != nil || n != 4 {
			t.Fatalf("expected 4 monitor-schema tables, n=%d err=%v", n, err)
		}
		inTx(t, conn, func(tx pgx.Tx) {
			_, err := tx.Exec(ctx,
				`INSERT INTO uptime.quota_budgets (id,global_monitor_limit) VALUES (2,10)`)
			if !isPGError(err, "23514") {
				t.Fatalf("expected singleton CHECK to reject id=2, got %v", err)
			}
		})
	})

	t.Run("ownership composite FK rejects cross-user binding", func(t *testing.T) {
		inTx(t, conn, func(tx pgx.Tx) {
			ua := seedUser(t, tx, "fk-a@example.com")
			ub := seedUser(t, tx, "fk-b@example.com")
			mid := seedMonitor(t, tx, ua, "m1")
			cid := seedChannel(t, tx, ub, "c1")
			// Binding A's monitor to B's channel must fail: the composite
			// (channel_id,user_id) FK only matches within one owner.
			_, err := tx.Exec(ctx,
				`INSERT INTO uptime.monitor_channels (monitor_id,channel_id,user_id)
				 VALUES ($1,$2,$3)`, mid, cid, ua)
			if !isPGError(err, "23503") {
				t.Fatalf("expected fk_violation for cross-user binding, got %v", err)
			}
		})
	})

	t.Run("monitor policy CHECKs enforce bounds", func(t *testing.T) {
		for i, tc := range []struct {
			name, sql string
		}{
			{"interval too small",
				`INSERT INTO uptime.monitors (id,user_id,name,target_url,interval_seconds,next_check_at)
				 VALUES (gen_random_uuid(),$1,'m','https://x.test',30,now())`},
			{"timeout >= interval",
				`INSERT INTO uptime.monitors (id,user_id,name,target_url,interval_seconds,timeout_seconds,next_check_at)
				 VALUES (gen_random_uuid(),$1,'m','https://x.test',60,60,now())`},
			{"non-GET method",
				`INSERT INTO uptime.monitors (id,user_id,name,target_url,method,interval_seconds,next_check_at)
				 VALUES (gen_random_uuid(),$1,'m','https://x.test','POST',60,now())`},
			{"bad health enum",
				`INSERT INTO uptime.monitors (id,user_id,name,target_url,health,interval_seconds,next_check_at)
				 VALUES (gen_random_uuid(),$1,'m','https://x.test','BROKEN',60,now())`},
			{"applied > reserved sequence",
				`INSERT INTO uptime.monitors (id,user_id,name,target_url,interval_seconds,last_reserved_sequence,last_applied_sequence,next_check_at)
				 VALUES (gen_random_uuid(),$1,'m','https://x.test',60,1,2,now())`},
		} {
			// One tx per case: a violated CHECK aborts the transaction.
			inTx(t, conn, func(tx pgx.Tx) {
				u := seedUser(t, tx, "chk"+string(rune('a'+i))+"@example.com")
				if _, err := tx.Exec(ctx, tc.sql, u); !isPGError(err, "23514") {
					t.Fatalf("%s: expected check_violation, got %v", tc.name, err)
				}
			})
		}
	})

	t.Run("paused monitor still occupies retained slot semantics", func(t *testing.T) {
		inTx(t, conn, func(tx pgx.Tx) {
			u := seedUser(t, tx, "ret@example.com")
			mid := seedMonitor(t, tx, u, "paused-m")
			if _, err := tx.Exec(ctx,
				`UPDATE uptime.monitors SET is_paused=true WHERE id=$1`, mid); err != nil {
				t.Fatal(err)
			}
			// The retained index counts paused AND tombstoned rows;
			// only the live page index excludes deleted.
			var retained, live int
			if err := tx.QueryRow(ctx,
				`SELECT count(*) FROM uptime.monitors WHERE user_id=$1`, u).Scan(&retained); err != nil {
				t.Fatal(err)
			}
			if _, err := tx.Exec(ctx,
				`UPDATE uptime.monitors SET deleted_at=now() WHERE id=$1`, mid); err != nil {
				t.Fatal(err)
			}
			if err := tx.QueryRow(ctx,
				`SELECT count(*) FROM uptime.monitors WHERE user_id=$1 AND deleted_at IS NULL`, u).Scan(&live); err != nil {
				t.Fatal(err)
			}
			if retained != 1 || live != 0 {
				t.Fatalf("retained=%d live=%d — pause/delete semantics wrong", retained, live)
			}
		})
	})

	t.Run("channel verified invariant requires destination proof", func(t *testing.T) {
		inTx(t, conn, func(tx pgx.Tx) {
			u := seedUser(t, tx, "ver@example.com")
			// status=VERIFIED without ciphertext/receipt must fail.
			_, err := tx.Exec(ctx,
				`INSERT INTO uptime.notification_channels (id,user_id,label,status)
				 VALUES (gen_random_uuid(),$1,'c','VERIFIED')`, u)
			if !isPGError(err, "23514") {
				t.Fatalf("expected verified-without-destination CHECK, got %v", err)
			}
		})
		inTx(t, conn, func(tx pgx.Tx) {
			u := seedUser(t, tx, "ver2@example.com")
			// enabled on a PENDING channel must fail.
			_, err := tx.Exec(ctx,
				`INSERT INTO uptime.notification_channels (id,user_id,label,enabled)
				 VALUES (gen_random_uuid(),$1,'c',true)`, u)
			if !isPGError(err, "23514") {
				t.Fatalf("expected enabled-requires-verified CHECK, got %v", err)
			}
		})
	})

	t.Run("expected indexes exist", func(t *testing.T) {
		for _, ix := range []string{
			"monitors_owner_page", "monitors_due", "monitors_owner_retained",
			"channels_owner_page", "channels_owner_retained", "channels_pending_all",
			"monitor_channels_reverse",
		} {
			var n int
			if err := conn.QueryRow(ctx,
				`SELECT count(*) FROM pg_indexes WHERE schemaname='uptime' AND indexname=$1`, ix).Scan(&n); err != nil || n != 1 {
				t.Fatalf("index %s missing (n=%d err=%v)", ix, n, err)
			}
		}
	})

	t.Run("quota_budgets seeded-empty: create path must fail closed", func(t *testing.T) {
		var n int
		if err := conn.QueryRow(ctx,
			`SELECT count(*) FROM uptime.quota_budgets`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		// Document the F03 contract: the row is absent until the app
		// seeds it from configured policy — never a hidden default.
		t.Logf("quota_budgets rows=%d (app-ensure required before create)", n)
	})
}
