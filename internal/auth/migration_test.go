//go:build integration

package auth_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// testDSN returns the disposable test-database DSN. Integration tests
// REQUIRE it — running with -tags=integration without a migrated
// disposable database is an operator error, not a skip.
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

// inTx runs fn inside a transaction rolled back afterwards. Each subtest
// gets its own so an intentionally-failing statement cannot poison the
// rest of the test — Postgres aborts a transaction on the first error.
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

// TestIdentityMigration proves the 001 schema exists and enforces its
// invariants on the migrated disposable database.
func TestIdentityMigration(t *testing.T) {
	conn := connect(t)
	ctx := context.Background()

	t.Run("identity schema and tables exist", func(t *testing.T) {
		var n int
		err := conn.QueryRow(ctx,
			`SELECT count(*) FROM information_schema.tables
			 WHERE table_schema='uptime' AND table_name IN ('users','sessions')`).Scan(&n)
		if err != nil || n != 2 {
			t.Fatalf("expected users+sessions in uptime schema, n=%d err=%v", n, err)
		}
	})

	t.Run("sessions stores no plaintext token column", func(t *testing.T) {
		var bad int
		err := conn.QueryRow(ctx,
			`SELECT count(*) FROM information_schema.columns
			 WHERE table_schema='uptime' AND table_name='sessions'
			   AND column_name IN ('token','token_plaintext','raw_token','session_token')`).Scan(&bad)
		if err != nil {
			t.Fatal(err)
		}
		if bad != 0 {
			t.Fatalf("sessions exposes %d plaintext token columns", bad)
		}
	})

	// Per-run unique ids/emails — rolled-back seeds must not collide
	// with committed leftovers on the disposable DB.
	uid := uuid.NewString()
	sfx := fmt.Sprintf("+%d", time.Now().UnixNano())
	caseE := "case" + sfx + "@example.com"
	sessE := "sess" + sfx + "@example.com"
	sess2E := "sess2" + sfx + "@example.com"
	sess3E := "sess3" + sfx + "@example.com"
	expE := "exp" + sfx + "@example.com"
	exp2E := "exp2" + sfx + "@example.com"
	t.Run("insert user enforces canonical email check", func(t *testing.T) {
		inTx(t, conn, func(tx pgx.Tx) {
			_, err := tx.Exec(ctx,
				`INSERT INTO uptime.users (id,email,password_hash) VALUES ($1,'MixedCase@Example.com','h')`, uid)
			if !isPGError(err, "23514") {
				t.Fatalf("expected check_violation for non-canonical email, got %v", err)
			}
		})
	})

	t.Run("valid user defaults to ACTIVE non-elevated", func(t *testing.T) {
		inTx(t, conn, func(tx pgx.Tx) {
			_, err := tx.Exec(ctx,
				`INSERT INTO uptime.users (id,email,password_hash) VALUES ($1,$2,'h')`, uid, caseE)
			if err != nil {
				t.Fatalf("insert user: %v", err)
			}
			var status string
			var sv int64
			err = tx.QueryRow(ctx,
				`SELECT status,security_version FROM uptime.users WHERE id=$1`, uid).Scan(&status, &sv)
			if err != nil || status != "ACTIVE" || sv != 1 {
				t.Fatalf("unexpected defaults status=%q sv=%d err=%v", status, sv, err)
			}
		})
	})

	t.Run("duplicate canonical email rejected by unique constraint", func(t *testing.T) {
		inTx(t, conn, func(tx pgx.Tx) {
			_, err := tx.Exec(ctx,
				`INSERT INTO uptime.users (id,email,password_hash) VALUES ($1,$2,'h')`, uid, caseE)
			if err != nil {
				t.Fatalf("seed user: %v", err)
			}
			_, err = tx.Exec(ctx,
				`INSERT INTO uptime.users (id,email,password_hash) VALUES (gen_random_uuid(),$1,'h')`, caseE)
			if !isPGError(err, "23505") {
				t.Fatalf("expected unique_violation, got %v", err)
			}
		})
	})

	sid := uuid.NewString()
	t.Run("session FK restrict and token_hash length", func(t *testing.T) {
		inTx(t, conn, func(tx pgx.Tx) {
			_, err := tx.Exec(ctx,
				`INSERT INTO uptime.users (id,email,password_hash) VALUES ($1,$2,'h')`, uid, sessE)
			if err != nil {
				t.Fatalf("seed user: %v", err)
			}
			_, err = tx.Exec(ctx,
				`INSERT INTO uptime.sessions (id,user_id,token_hash,security_version,expires_at,idle_expires_at)
				 VALUES (gen_random_uuid(),$1,$2,1,now()+interval '1 day',now()+interval '1 day')`,
				"99999999-9999-9999-9999-999999999999", make([]byte, 32))
			if !isPGError(err, "23503") {
				t.Fatalf("expected fk_violation for orphan session, got %v", err)
			}
		})
		inTx(t, conn, func(tx pgx.Tx) {
			_, err := tx.Exec(ctx,
				`INSERT INTO uptime.users (id,email,password_hash) VALUES ($1,$2,'h')`, uid, sess2E)
			if err != nil {
				t.Fatalf("seed user: %v", err)
			}
			_, err = tx.Exec(ctx,
				`INSERT INTO uptime.sessions (id,user_id,token_hash,security_version,expires_at,idle_expires_at)
				 VALUES ($1,$2,$3,1,now()+interval '1 day',now()+interval '1 day')`,
				sid, uid, make([]byte, 31))
			if !isPGError(err, "23514") {
				t.Fatalf("expected check_violation for 31-byte token_hash, got %v", err)
			}
		})
		inTx(t, conn, func(tx pgx.Tx) {
			_, err := tx.Exec(ctx,
				`INSERT INTO uptime.users (id,email,password_hash) VALUES ($1,$2,'h')`, uid, sess3E)
			if err != nil {
				t.Fatalf("seed user: %v", err)
			}
			_, err = tx.Exec(ctx,
				`INSERT INTO uptime.sessions (id,user_id,token_hash,security_version,expires_at,idle_expires_at)
				 VALUES ($1,$2,$3,1,now()+interval '1 day',now()+interval '1 day')`,
				sid, uid, make([]byte, 32))
			if err != nil {
				t.Fatalf("valid session insert: %v", err)
			}
			var tz string
			err = tx.QueryRow(ctx, `SELECT pg_typeof(created_at)::text FROM uptime.sessions WHERE id=$1`, sid).Scan(&tz)
			if err != nil || tz != "timestamp with time zone" {
				t.Fatalf("expected timestamptz, got %q err=%v", tz, err)
			}
		})
	})

	t.Run("session expiry check and token uniqueness", func(t *testing.T) {
		inTx(t, conn, func(tx pgx.Tx) {
			_, err := tx.Exec(ctx,
				`INSERT INTO uptime.users (id,email,password_hash) VALUES ($1,$2,'h')`, uid, expE)
			if err != nil {
				t.Fatalf("seed user: %v", err)
			}
			_, err = tx.Exec(ctx,
				`INSERT INTO uptime.sessions (id,user_id,token_hash,security_version,expires_at,idle_expires_at)
				 VALUES (gen_random_uuid(),$1,$2,1,now()-interval '1 hour',now()-interval '2 hours')`,
				uid, make([]byte, 32))
			if !isPGError(err, "23514") {
				t.Fatalf("expected check_violation expires_at<=created_at, got %v", err)
			}
		})
		inTx(t, conn, func(tx pgx.Tx) {
			_, err := tx.Exec(ctx,
				`INSERT INTO uptime.users (id,email,password_hash) VALUES ($1,$2,'h')`, uid, exp2E)
			if err != nil {
				t.Fatalf("seed user: %v", err)
			}
			_, err = tx.Exec(ctx,
				`INSERT INTO uptime.sessions (id,user_id,token_hash,security_version,expires_at,idle_expires_at)
				 VALUES (gen_random_uuid(),$1,$2,1,now()+interval '1 day',now()+interval '1 day')`,
				uid, []byte("0123456789abcdef0123456789abcdef"))
			if err != nil {
				t.Fatalf("seed session: %v", err)
			}
			_, err = tx.Exec(ctx,
				`INSERT INTO uptime.sessions (id,user_id,token_hash,security_version,expires_at,idle_expires_at)
				 VALUES (gen_random_uuid(),$1,$2,1,now()+interval '1 day',now()+interval '1 day')`,
				uid, []byte("0123456789abcdef0123456789abcdef"))
			if !isPGError(err, "23505") {
				t.Fatalf("expected unique_violation on duplicate token_hash, got %v", err)
			}
		})
	})
}
