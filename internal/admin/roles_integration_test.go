//go:build integration

package admin_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/admin"
)

const (
	testRoleID   = "00000000-0000-4000-8000-000000000005"
	viewerPreset = "00000000-0000-4000-8000-000000000001"
)

// superActor seeds an ACTIVE user with the builtin SUPER_ADMIN grant,
// a session, and a fresh step-up receipt — the only actor allowed to
// run role mutations.
func superActor(t *testing.T, conn *pgx.Conn, prefix string) (admin.ActorRef, func()) {
	t.Helper()
	actor, cleanup := authFixture(t, conn, prefix)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := conn.Exec(ctx, `
		DELETE FROM uptime.user_roles WHERE user_id=$1`, actor.UserID); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, `
		INSERT INTO uptime.user_roles (user_id, role_id)
		VALUES ($1,$2)`, actor.UserID, testRoleID); err != nil {
		t.Fatal(err)
	}
	stampReauth(t, conn, actor.SessionID, 0)
	return actor, cleanup
}

// plainUser seeds an ACTIVE user with VIEWER and returns its ActorRef.
func plainUser(t *testing.T, conn *pgx.Conn, prefix string) (admin.ActorRef, func()) {
	t.Helper()
	return authFixture(t, conn, prefix)
}

func userVersion(t *testing.T, conn *pgx.Conn, uid uuid.UUID) (int64, int64) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var ver, sec int64
	if err := conn.QueryRow(ctx, `
		SELECT version, security_version FROM uptime.users WHERE id=$1`,
		uid).Scan(&ver, &sec); err != nil {
		t.Fatal(err)
	}
	return ver, sec
}

// TestCustomRoleReadPrerequisites: users:manage without users:read is
// a bounded 422 carrying missing_permissions — never an auto-grant.
func TestCustomRoleReadPrerequisites(t *testing.T) {
	conn := connect(t)
	actor, cleanup := superActor(t, conn, "c59-pre")
	defer cleanup()

	body := []byte(`{"code":"NO_READ","name":"x"}`)
	_, err := admin.CreateCustomRole(context.Background(), conn, actor,
		"k-pre-1", body, admin.CreateRoleInput{
			Code: "NR_" + uuid.NewString()[:8], Name: "no read",
			Permissions: []string{"users:manage"}, Reason: "test",
		}, time.Now())
	var ve *admin.ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("want ValidationError, got %v", err)
	}
	missing, ok := ve.Fields["missing_permissions"].([]string)
	if !ok || len(missing) != 1 || missing[0] != "users:read" {
		t.Fatalf("missing_permissions=%v, want [users:read]", ve.Fields)
	}

	// With the read prerequisite present the same grant succeeds.
	res, err := admin.CreateCustomRole(context.Background(), conn, actor,
		"k-pre-2", body, admin.CreateRoleInput{
			Code: "HR_" + uuid.NewString()[:8], Name: "has read",
			Permissions: []string{"users:read", "users:manage"},
			Reason:      "test",
		}, time.Now())
	if err != nil {
		t.Fatalf("create with requires satisfied: %v", err)
	}
	if res.Status != 201 {
		t.Fatalf("status=%d", res.Status)
	}
}

// TestRoleDelegation: the ceiling is enforced — roles:manage can never
// enter a custom role even when the actor holds it.
func TestRoleDelegation(t *testing.T) {
	conn := connect(t)
	actor, cleanup := superActor(t, conn, "c59-del")
	defer cleanup()

	body := []byte(`{"code":"X"}`)
	_, err := admin.CreateCustomRole(context.Background(), conn, actor,
		"k-del-1", body, admin.CreateRoleInput{
			Code: "OV_" + uuid.NewString()[:8], Name: "over",
			Permissions: []string{"users:read", "roles:manage"},
			Reason:      "test",
		}, time.Now())
	if !errors.Is(err, admin.ErrForbidden) {
		t.Fatalf("want ErrForbidden over ceiling, got %v", err)
	}

	// Unknown permission IDs are rejected, not silently created.
	_, err = admin.CreateCustomRole(context.Background(), conn, actor,
		"k-del-2", body, admin.CreateRoleInput{
			Code: "UK_" + uuid.NewString()[:8], Name: "unk",
			Permissions: []string{"no:such:perm"}, Reason: "test",
		}, time.Now())
	if !errors.Is(err, admin.ErrValidation) {
		t.Fatalf("want ErrValidation unknown perm, got %v", err)
	}

	// Presets are immutable through the update path.
	presetID := uuid.MustParse(viewerPreset)
	_, err = admin.UpdateRole(context.Background(), conn, actor, presetID,
		admin.UpdateRoleInput{
			Permissions:     []string{"platform:read"},
			ExpectedVersion: 1, Reason: "test",
		}, "k-del-3", body, time.Now())
	if !errors.Is(err, admin.ErrForbidden) {
		t.Fatalf("want ErrForbidden editing preset, got %v", err)
	}
}

// TestRoleEpochFanout: editing a role's grants advances the security
// epoch of every holder — stale sessions lose authority atomically.
func TestRoleEpochFanout(t *testing.T) {
	conn := connect(t)
	actor, cleanup := superActor(t, conn, "c59-fan")
	defer cleanup()
	subject, subCleanup := plainUser(t, conn, "c59-sub")
	defer subCleanup()

	body := []byte(`{"code":"FAN","permissions":["users:read"]}`)
	res, err := admin.CreateCustomRole(context.Background(), conn, actor,
		"k-fan-1", body, admin.CreateRoleInput{
			Code: "FN_" + uuid.NewString()[:8], Name: "fan",
			Permissions: []string{"users:read"}, Reason: "test",
		}, time.Now())
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	role := res.Response["role"].(admin.RoleDTO)

	ver, secBefore := userVersion(t, conn, subject.UserID)
	_, err = admin.AssignUserRoles(context.Background(), conn, actor,
		subject.UserID, admin.AssignRolesInput{
			RoleIDs: []uuid.UUID{role.ID}, ExpectedVersion: ver,
			Reason: "test",
		}, "k-fan-2", body, time.Now())
	if err != nil {
		t.Fatalf("assign: %v", err)
	}
	_, secAfter := userVersion(t, conn, subject.UserID)
	if secAfter != secBefore+1 {
		t.Fatalf("assign did not bump epoch: %d -> %d", secBefore, secAfter)
	}

	// Editing the role's grants bumps every holder's epoch again.
	_, err = admin.UpdateRole(context.Background(), conn, actor, role.ID,
		admin.UpdateRoleInput{
			Permissions:     []string{"users:read", "users:manage"},
			ExpectedVersion: role.Version, Reason: "test",
		}, "k-fan-3", body, time.Now())
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	_, secFinal := userVersion(t, conn, subject.UserID)
	if secFinal != secAfter+1 {
		t.Fatalf("update did not fan out epoch: %d -> %d", secAfter, secFinal)
	}
}

// TestRoleAssignmentAPI exercises the guarded assignment path end to
// end: stale versions, unknown role IDs, idempotent replay, and the
// last-superadmin guard on the same code path.
func TestRoleAssignmentAPI(t *testing.T) {
	conn := connect(t)
	actor, cleanup := superActor(t, conn, "c59-api")
	defer cleanup()
	subject, subCleanup := plainUser(t, conn, "c59-tgt")
	defer subCleanup()

	body := []byte(`{"role_ids":["00000000-0000-4000-8000-000000000001"]}`)
	viewerID := uuid.MustParse(viewerPreset)
	ver, _ := userVersion(t, conn, subject.UserID)

	t.Run("stale expected version is 409", func(t *testing.T) {
		_, err := admin.AssignUserRoles(context.Background(), conn, actor,
			subject.UserID, admin.AssignRolesInput{
				RoleIDs: []uuid.UUID{viewerID}, ExpectedVersion: ver + 9,
				Reason: "test",
			}, "k-api-1", body, time.Now())
		if !errors.Is(err, admin.ErrStaleEpoch) {
			t.Fatalf("want ErrStaleEpoch, got %v", err)
		}
	})

	t.Run("unknown role id is 422 not partial", func(t *testing.T) {
		_, err := admin.AssignUserRoles(context.Background(), conn, actor,
			subject.UserID, admin.AssignRolesInput{
				RoleIDs:         []uuid.UUID{viewerID, uuid.New()},
				ExpectedVersion: ver, Reason: "test",
			}, "k-api-2", body, time.Now())
		var ve *admin.ValidationError
		if !errors.As(err, &ve) {
			t.Fatalf("want ValidationError, got %v", err)
		}
		// No partial assignment: the subject still holds exactly VIEWER.
		var n int
		_ = conn.QueryRow(context.Background(), `
			SELECT count(*) FROM uptime.user_roles WHERE user_id=$1`,
			subject.UserID).Scan(&n)
		if n != 1 {
			t.Fatalf("partial assignment happened: %d roles", n)
		}
	})

	t.Run("assign commits and replays", func(t *testing.T) {
		res, err := admin.AssignUserRoles(context.Background(), conn, actor,
			subject.UserID, admin.AssignRolesInput{
				RoleIDs: []uuid.UUID{viewerID}, ExpectedVersion: ver,
				Reason: "test",
			}, "k-api-3", body, time.Now())
		if err != nil {
			t.Fatalf("assign: %v", err)
		}
		if res.Status != 200 {
			t.Fatalf("status=%d", res.Status)
		}
		// Idempotent replay returns the stored response, no reapply.
		replay, err := admin.AssignUserRoles(context.Background(), conn, actor,
			subject.UserID, admin.AssignRolesInput{
				RoleIDs: []uuid.UUID{viewerID}, ExpectedVersion: ver + 1,
				Reason: "changed",
			}, "k-api-3", body, time.Now())
		if err != nil {
			t.Fatalf("replay: %v", err)
		}
		if replay.Status != res.Status {
			t.Fatalf("replay status %d != %d", replay.Status, res.Status)
		}
	})

	t.Run("removing last superadmin is denied", func(t *testing.T) {
		// The actor is the only superadmin — demoting them through the
		// assignment path must hit the invariant.
		aver, _ := userVersion(t, conn, actor.UserID)
		_, err := admin.AssignUserRoles(context.Background(), conn, actor,
			actor.UserID, admin.AssignRolesInput{
				RoleIDs: []uuid.UUID{viewerID}, ExpectedVersion: aver,
				Reason: "test",
			}, "k-api-4", body, time.Now())
		if !errors.Is(err, admin.ErrLastSuperAdmin) {
			t.Fatalf("want ErrLastSuperAdmin, got %v", err)
		}
		if activeSupers(t, conn) != 1 {
			t.Fatal("denied demotion still removed the superadmin")
		}
	})
}
