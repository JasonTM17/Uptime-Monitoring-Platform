//go:build integration

package admin_test

import (
	"context"
	"errors"
	"os"
	"sort"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/admin"
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

// TestRBACMigration pins the migration-007 schema to the Go registry:
// the catalog, the preset matrix and the enforcing constraints must be
// the same single source of truth.
func TestRBACMigration(t *testing.T) {
	conn := connect(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	t.Run("schema catalog equals registry", func(t *testing.T) {
		rows, err := conn.Query(ctx,
			`SELECT id FROM uptime.permissions ORDER BY id`)
		if err != nil {
			t.Fatalf("read catalog: %v", err)
		}
		var ids []string
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				t.Fatal(err)
			}
			ids = append(ids, id)
		}
		rows.Close()
		var want []string
		for _, p := range admin.PermissionRegistry {
			want = append(want, p.ID)
		}
		sort.Strings(want)
		if len(ids) != len(want) {
			t.Fatalf("schema catalog %v, want %v", ids, want)
		}
		for i := range ids {
			if ids[i] != want[i] {
				t.Fatalf("schema catalog %v, want %v", ids, want)
			}
		}
	})

	t.Run("preset matrix equals Go presets", func(t *testing.T) {
		rows, err := conn.Query(ctx, `
			SELECT r.code, rp.permission_id
			FROM uptime.roles r JOIN uptime.role_permissions rp
			  ON rp.role_id = r.id
			WHERE r.is_preset ORDER BY r.code, rp.permission_id`)
		if err != nil {
			t.Fatalf("read preset grants: %v", err)
		}
		got := map[string][]string{}
		for rows.Next() {
			var code, perm string
			if err := rows.Scan(&code, &perm); err != nil {
				t.Fatal(err)
			}
			got[code] = append(got[code], perm)
		}
		rows.Close()
		for code, want := range admin.PresetPermissions {
			sorted := append([]string(nil), want...)
			sort.Strings(sorted)
			g := got[code]
			if len(g) != len(sorted) {
				t.Fatalf("%s schema grants %v, want %v", code, g, sorted)
			}
			for i := range g {
				if g[i] != sorted[i] {
					t.Fatalf("%s schema grants %v, want %v", code, g, sorted)
				}
			}
		}
		if len(got) != len(admin.PresetPermissions) {
			t.Fatalf("schema presets %v", got)
		}
	})

	t.Run("security anchor singleton seeded", func(t *testing.T) {
		var id int
		var version int64
		err := conn.QueryRow(ctx,
			`SELECT id, version FROM uptime.security_anchor`).Scan(&id, &version)
		if err != nil {
			t.Fatalf("anchor: %v", err)
		}
		if id != 1 || version < 1 {
			t.Fatalf("anchor id=%d version=%d", id, version)
		}
	})

	t.Run("foreign keys reject unknown permission", func(t *testing.T) {
		tx, err := conn.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		_, err = tx.Exec(ctx, `
			INSERT INTO uptime.role_permissions (role_id, permission_id)
			SELECT id, 'not-a-real-permission'
			FROM uptime.roles WHERE code='VIEWER'`)
		if !isPGError(err, "23503") {
			t.Fatalf("want FK violation, got %v", err)
		}
	})

	t.Run("duplicate grant rejected", func(t *testing.T) {
		tx, err := conn.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		_, err = tx.Exec(ctx, `
			INSERT INTO uptime.role_permissions (role_id, permission_id)
			SELECT id, 'platform:read'
			FROM uptime.roles WHERE code='VIEWER'`)
		if !isPGError(err, "23505") {
			t.Fatalf("want unique violation, got %v", err)
		}
	})

	t.Run("duplicate role assignment rejected", func(t *testing.T) {
		tx, err := conn.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		uid := uuid.New()
		if _, err := tx.Exec(ctx, `
			INSERT INTO uptime.users (id, email, password_hash)
			VALUES ($1, $2, 'x')`, uid, "dup-"+uid.String()[:8]+"@example.test"); err != nil {
			t.Fatal(err)
		}
		q := `INSERT INTO uptime.user_roles (user_id, role_id)
		      SELECT $1, id FROM uptime.roles WHERE code='VIEWER'`
		if _, err := tx.Exec(ctx, q, uid); err != nil {
			t.Fatal(err)
		}
		_, err = tx.Exec(ctx, q, uid)
		if !isPGError(err, "23505") {
			t.Fatalf("want unique violation, got %v", err)
		}
	})

	t.Run("anchor rejects second row", func(t *testing.T) {
		tx, err := conn.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		_, err = tx.Exec(ctx,
			`INSERT INTO uptime.security_anchor (id, version) VALUES (2,1)`)
		if !isPGError(err, "23514") {
			t.Fatalf("want CHECK violation, got %v", err)
		}
	})

	t.Run("audit outcome check enforced", func(t *testing.T) {
		tx, err := conn.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		_, err = tx.Exec(ctx, `
			INSERT INTO uptime.audit_events
			  (id, actor_kind, action, subject_type, subject_id,
			   reason, outcome, request_id)
			VALUES ($1,'USER','x','user','t','r','MAYBE','r1')`, uuid.New())
		if !isPGError(err, "23514") {
			t.Fatalf("want CHECK violation, got %v", err)
		}
	})

	t.Run("idempotency requires future expiry", func(t *testing.T) {
		tx, err := conn.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		uid := uuid.New()
		if _, err := tx.Exec(ctx, `
			INSERT INTO uptime.users (id, email, password_hash)
			VALUES ($1, $2, 'x')`, uid, "idem-"+uid.String()[:8]+"@example.test"); err != nil {
			t.Fatal(err)
		}
		_, err = tx.Exec(ctx, `
			INSERT INTO uptime.admin_idempotency
			  (actor_id, action, target_id, key_hash, request_hash,
			   safe_response, http_status, expires_at)
			VALUES ($1,'act','t','\x00','\x00','{}',200,now()-interval '1 second')`, uid)
		if !isPGError(err, "23514") {
			t.Fatalf("want CHECK violation, got %v", err)
		}
	})
}
