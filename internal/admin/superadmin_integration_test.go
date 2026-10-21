//go:build integration

package admin_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/admin"
)

const superRoleID = "00000000-0000-4000-8000-000000000005"

// grantSuper assigns SUPER_ADMIN to a user (fixture; not the guarded
// bootstrap path — setup only).
func grantSuper(t *testing.T, conn *pgx.Conn, uid uuid.UUID) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := conn.Exec(ctx, `
		INSERT INTO uptime.user_roles (user_id, role_id)
		VALUES ($1,$2) ON CONFLICT DO NOTHING`, uid, superRoleID); err != nil {
		t.Fatal(err)
	}
}

func clearSupers(t *testing.T, conn *pgx.Conn) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := conn.Exec(ctx, `
		DELETE FROM uptime.user_roles WHERE role_id=$1`, superRoleID); err != nil {
		t.Fatal(err)
	}
}

func activeSupers(t *testing.T, conn *pgx.Conn) int {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var n int
	if err := conn.QueryRow(ctx, `
		SELECT count(*) FROM uptime.user_roles ur
		JOIN uptime.users u ON u.id=ur.user_id
		WHERE ur.role_id=$1 AND u.status='ACTIVE'`, superRoleID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// demoteOnce models one guarded removal path: anchor lock -> demote
// SQL -> last-superadmin guard -> commit.
func demoteOnce(ctx context.Context, conn *pgx.Conn, uid uuid.UUID) error {
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := admin.LockAnchor(ctx, tx); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		DELETE FROM uptime.user_roles WHERE user_id=$1 AND role_id=$2`,
		uid, superRoleID); err != nil {
		return err
	}
	if err := admin.AssertActiveSuperAdminRemaining(ctx, tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// TestFinalSuperAdmin: every path that could remove the last active
// administrator is guarded.
func TestFinalSuperAdmin(t *testing.T) {
	conn := connect(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	clearSupers(t, conn)
	t.Cleanup(func() { clearSupers(t, conn) })

	t.Run("single admin self-demote is 409 and grant survives", func(t *testing.T) {
		email := "sole-" + uuid.NewString()[:8] + "@example.test"
		u := seedNamedUser(t, conn, email)
		grantSuper(t, conn, u)
		defer cleanBootstrap(t, conn, email)
		err := demoteOnce(ctx, conn, u)
		if !errors.Is(err, admin.ErrLastSuperAdmin) {
			t.Fatalf("want ErrLastSuperAdmin, got %v", err)
		}
		if activeSupers(t, conn) != 1 {
			t.Fatal("grant lost despite denial")
		}
	})

	t.Run("suspend of last admin equally denied", func(t *testing.T) {
		email := "sole-susp-" + uuid.NewString()[:8] + "@example.test"
		u := seedNamedUser(t, conn, email)
		grantSuper(t, conn, u)
		defer cleanBootstrap(t, conn, email)
		tx, err := conn.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		if err := admin.LockAnchor(ctx, tx); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, `
			UPDATE uptime.users SET status='DISABLED', disabled_at=now()
			WHERE id=$1`, u); err != nil {
			t.Fatal(err)
		}
		err = admin.AssertActiveSuperAdminRemaining(ctx, tx)
		if !errors.Is(err, admin.ErrLastSuperAdmin) {
			t.Fatalf("suspend path: want ErrLastSuperAdmin, got %v", err)
		}
	})

	t.Run("disabled admin does not count as successor", func(t *testing.T) {
		// A is disabled but holds the grant; B is active. B demoting
		// self leaves only a disabled admin — still denied.
		eA := "dis-sup-" + uuid.NewString()[:8] + "@example.test"
		eB := "act-sup-" + uuid.NewString()[:8] + "@example.test"
		uA := seedNamedUser(t, conn, eA)
		uB := seedNamedUser(t, conn, eB)
		grantSuper(t, conn, uA)
		grantSuper(t, conn, uB)
		defer cleanBootstrap(t, conn, eA, eB)
		if _, err := conn.Exec(ctx, `
			UPDATE uptime.users SET status='DISABLED', disabled_at=now()
			WHERE id=$1`, uA); err != nil {
			t.Fatal(err)
		}
		err := demoteOnce(ctx, conn, uB)
		if !errors.Is(err, admin.ErrLastSuperAdmin) {
			t.Fatalf("want ErrLastSuperAdmin, got %v", err)
		}
	})

	t.Run("custom role with many perms is not SUPER_ADMIN", func(t *testing.T) {
		// A user holding a custom role over the whole delegation
		// ceiling (no roles:manage) is not a builtin superadmin —
		// removing the real last admin is still denied.
		email := "custom-" + uuid.NewString()[:8] + "@example.test"
		u := seedNamedUser(t, conn, email)
		defer cleanBootstrap(t, conn, email)
		roleID := uuid.New()
		if _, err := conn.Exec(ctx, `
			INSERT INTO uptime.roles (id, code, name)
			VALUES ($1,$2,'Near-super')`, roleID, "NEAR-"+roleID.String()[:8]); err != nil {
			t.Fatal(err)
		}
		if _, err := conn.Exec(ctx, `
			INSERT INTO uptime.role_permissions (role_id, permission_id)
			SELECT $1, id FROM uptime.permissions WHERE id <> 'roles:manage'`,
			roleID); err != nil {
			t.Fatal(err)
		}
		if _, err := conn.Exec(ctx, `
			INSERT INTO uptime.user_roles (user_id, role_id)
			VALUES ($1,$2)`, u, roleID); err != nil {
			t.Fatal(err)
		}
		defer func() {
			c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_, _ = conn.Exec(c, `DELETE FROM uptime.role_permissions WHERE role_id=$1`, roleID)
			_, _ = conn.Exec(c, `DELETE FROM uptime.roles WHERE id=$1`, roleID)
		}()
		// The custom holder is NOT counted: removing the last real
		// superadmin still trips the guard.
		err := demoteOnce(ctx, conn, u)
		// u is not superadmin at all — the demote removes nothing and
		// leaves zero active superadmins: still denied.
		if !errors.Is(err, admin.ErrLastSuperAdmin) {
			t.Fatalf("want ErrLastSuperAdmin, got %v", err)
		}
	})
}

// TestConcurrentSuperAdminRemoval: two admins demote each other at
// the same time — the anchor serializes both mutations so at least
// one active SUPER_ADMIN always survives. Deterministic, no sleeps.
func TestConcurrentSuperAdminRemoval(t *testing.T) {
	conn := connect(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	clearSupers(t, conn)
	t.Cleanup(func() { clearSupers(t, conn) })

	eA := "ca-" + uuid.NewString()[:8] + "@example.test"
	eB := "cb-" + uuid.NewString()[:8] + "@example.test"
	uA := seedNamedUser(t, conn, eA)
	uB := seedNamedUser(t, conn, eB)
	grantSuper(t, conn, uA)
	grantSuper(t, conn, uB)
	defer cleanBootstrap(t, conn, eA, eB)

	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i, target := range []uuid.UUID{uA, uB} {
		wg.Add(1)
		go func(k int, uid uuid.UUID) {
			defer wg.Done()
			c, err := pgx.Connect(ctx, testDSN(t))
			if err != nil {
				errs[k] = err
				return
			}
			defer c.Close(context.Background())
			errs[k] = demoteOnce(ctx, c, uid)
		}(i, target)
	}
	wg.Wait()

	var wins, denied int
	for _, e := range errs {
		switch {
		case e == nil:
			wins++
		case errors.Is(e, admin.ErrLastSuperAdmin):
			denied++
		default:
			t.Fatalf("unexpected: %v", e)
		}
	}
	if wins != 1 || denied != 1 {
		t.Fatalf("wins=%d denied=%d — write skew escaped the anchor", wins, denied)
	}
	if activeSupers(t, conn) != 1 {
		t.Fatalf("active superadmins=%d, want exactly 1", activeSupers(t, conn))
	}
}
