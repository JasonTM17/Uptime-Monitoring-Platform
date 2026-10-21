//go:build integration

package admin_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/admin"
)

// seedNamedUser inserts a bare ACTIVE user and returns its id.
func seedNamedUser(t *testing.T, conn *pgx.Conn, email string) uuid.UUID {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	uid := uuid.New()
	if _, err := conn.Exec(ctx, `
		INSERT INTO uptime.users (id, email, password_hash)
		VALUES ($1,$2,'x')`, uid, email); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	return uid
}

// cleanBootstrap removes users + grants created by these tests.
func cleanBootstrap(t *testing.T, conn *pgx.Conn, emails ...string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, e := range emails {
		if _, err := conn.Exec(ctx, `
			DELETE FROM uptime.sessions WHERE user_id IN
			(SELECT id FROM uptime.users WHERE email=$1)`, e); err != nil {
			t.Fatalf("clean sessions %s: %v", e, err)
		}
		if _, err := conn.Exec(ctx, `
			DELETE FROM uptime.user_roles WHERE user_id IN
			(SELECT id FROM uptime.users WHERE email=$1)`, e); err != nil {
			t.Fatalf("clean grants %s: %v", e, err)
		}
		if _, err := conn.Exec(ctx, `
			DELETE FROM uptime.users WHERE email=$1`, e); err != nil {
			t.Fatalf("clean %s: %v", e, err)
		}
	}
}

// TestBootstrapRace: exactly one of two concurrent bootstraps may
// win — the anchor lock serializes the active-superadmin check and
// the grant.
func TestBootstrapRace(t *testing.T) {
	conn := connect(t)
	email := "race-winner-" + uuid.NewString()[:8] + "@example.test"
	seedNamedUser(t, conn, email)
	t.Cleanup(func() { cleanBootstrap(t, conn, email) })

	// Remove any superadmin grants so the gate is open.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := conn.Exec(ctx, `
		DELETE FROM uptime.user_roles WHERE role_id=$1`,
		"00000000-0000-4000-8000-000000000005"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := conn.Exec(context.Background(), `
			DELETE FROM uptime.user_roles WHERE role_id=$1`,
			"00000000-0000-4000-8000-000000000005"); err != nil {
			t.Fatal(err)
		}
	})

	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(k int) {
			defer wg.Done()
			c, err := pgx.Connect(ctx, testDSN(t))
			if err != nil {
				errs[k] = err
				return
			}
			defer c.Close(context.Background())
			errs[k] = admin.BootstrapSuperAdmin(
				ctx, c, email, "concurrent test", "race-"+uuid.NewString()[:8])
		}(i)
	}
	wg.Wait()

	var wins, denied int
	for _, e := range errs {
		switch {
		case e == nil:
			wins++
		case errors.Is(e, admin.ErrSuperAdminExists):
			denied++
		default:
			t.Fatalf("unexpected error: %v", e)
		}
	}
	if wins != 1 || denied != 1 {
		t.Fatalf("bootstrap wins=%d denied=%d — invariant broken", wins, denied)
	}
	var grants int
	if err := conn.QueryRow(ctx, `
		SELECT count(*) FROM uptime.user_roles ur
		JOIN uptime.users u ON u.id=ur.user_id
		WHERE ur.role_id=$1 AND u.email=$2`,
		"00000000-0000-4000-8000-000000000005", email).Scan(&grants); err != nil {
		t.Fatal(err)
	}
	if grants != 1 {
		t.Fatalf("grants=%d", grants)
	}
}

// TestRecoveryAtomicity: target validation, audit/rollback symmetry
// and the session-revocation side effect.
func TestRecoveryAtomicity(t *testing.T) {
	conn := connect(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	t.Run("missing reason rejected", func(t *testing.T) {
		err := admin.BootstrapSuperAdmin(ctx, conn, "x@example.test", "  ", "r1")
		if !errors.Is(err, admin.ErrReasonRequired) {
			t.Fatalf("want ErrReasonRequired, got %v", err)
		}
	})

	t.Run("unknown user rejected — no implicit creation", func(t *testing.T) {
		ghost := "ghost-" + uuid.NewString()[:8] + "@example.test"
		if _, err := conn.Exec(ctx, `
			DELETE FROM uptime.user_roles WHERE role_id=$1`,
			"00000000-0000-4000-8000-000000000005"); err != nil {
			t.Fatal(err)
		}
		err := admin.BootstrapSuperAdmin(ctx, conn, ghost, "why", "r2")
		if !errors.Is(err, admin.ErrBootstrapTarget) {
			t.Fatalf("want ErrBootstrapTarget, got %v", err)
		}
		var n int
		if err := conn.QueryRow(ctx,
			`SELECT count(*) FROM uptime.users WHERE email=$1`, ghost).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Fatal("bootstrap created a user — forbidden")
		}
	})

	t.Run("disabled target rejected", func(t *testing.T) {
		email := "disabled-" + uuid.NewString()[:8] + "@example.test"
		uid := seedNamedUser(t, conn, email)
		t.Cleanup(func() { cleanBootstrap(t, conn, email) })
		if _, err := conn.Exec(ctx, `
			UPDATE uptime.users SET status='DISABLED', disabled_at=now()
			WHERE id=$1`, uid); err != nil {
			t.Fatal(err)
		}
		err := admin.RecoverAdministrativeAccess(ctx, conn, email, "x", "r3")
		if !errors.Is(err, admin.ErrBootstrapTarget) {
			t.Fatalf("want ErrBootstrapTarget, got %v", err)
		}
	})

	t.Run("existing superadmin blocks bootstrap but not recover", func(t *testing.T) {
		e1 := "first-admin-" + uuid.NewString()[:8] + "@example.test"
		e2 := "second-admin-" + uuid.NewString()[:8] + "@example.test"
		u1 := seedNamedUser(t, conn, e1)
		u2 := seedNamedUser(t, conn, e2)
		t.Cleanup(func() { cleanBootstrap(t, conn, e1, e2) })
		if _, err := conn.Exec(ctx, `
			DELETE FROM uptime.user_roles WHERE role_id=$1`,
			"00000000-0000-4000-8000-000000000005"); err != nil {
			t.Fatal(err)
		}
		req4 := "req-" + uuid.NewString()[:8]
		req6 := "req-" + uuid.NewString()[:8]
		if err := admin.BootstrapSuperAdmin(ctx, conn, e1, "first", req4); err != nil {
			t.Fatalf("first bootstrap: %v", err)
		}
		err := admin.BootstrapSuperAdmin(ctx, conn, e2, "second", "r5")
		if !errors.Is(err, admin.ErrSuperAdminExists) {
			t.Fatalf("want ErrSuperAdminExists, got %v", err)
		}
		// Recovery on a second user stays open (maintenance path) and
		// revokes that user's sessions.
		tok := sha256.Sum256([]byte(uuid.NewString()))
		if _, err := conn.Exec(ctx, `
			INSERT INTO uptime.sessions
			  (id, user_id, token_hash, security_version,
			   expires_at, idle_expires_at)
			VALUES ($1,$2,$3,1,now()+interval '1 hour',now()+interval '1 hour')`,
			uuid.New(), u2, tok[:]); err != nil {
			t.Fatal(err)
		}
		if err := admin.RecoverAdministrativeAccess(
			ctx, conn, e2, "maintenance window", req6); err != nil {
			t.Fatalf("recover: %v", err)
		}
		var revoked, sec int64
		if err := conn.QueryRow(ctx, `
			SELECT count(*), (SELECT security_version FROM uptime.users WHERE id=$1)
			FROM uptime.sessions WHERE user_id=$1 AND revoked_at IS NULL`,
			u2).Scan(&revoked, &sec); err != nil {
			t.Fatal(err)
		}
		if revoked != 0 {
			t.Fatalf("%d sessions left unrevoked", revoked)
		}
		if sec != 2 {
			t.Fatalf("security_version=%d, want 2 after grant", sec)
		}
		// Audit rows exist for both grants.
		var audits int
		if err := conn.QueryRow(ctx, `
			SELECT count(*) FROM uptime.audit_events
			WHERE request_id IN ($1,$2) AND outcome='SUCCESS'`,
			req4, req6).Scan(&audits); err != nil {
			t.Fatal(err)
		}
		if audits != 2 {
			t.Fatalf("audit rows=%d, want 2", audits)
		}
		_ = u1
	})
}
