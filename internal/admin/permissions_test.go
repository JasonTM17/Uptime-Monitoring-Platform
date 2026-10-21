package admin_test

import (
	"sort"
	"testing"

	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/admin"
)

func TestPermissionRegistry(t *testing.T) {
	t.Run("all preset grants are catalog IDs", func(t *testing.T) {
		for code, grants := range admin.PresetPermissions {
			for _, id := range grants {
				if !admin.KnownPermission(id) {
					t.Fatalf("preset %s grants unknown permission %q", code, id)
				}
			}
		}
	})

	t.Run("super admin holds the exact full catalog", func(t *testing.T) {
		got := append([]string(nil), admin.PresetPermissions[admin.RoleSuperAdmin]...)
		want := make([]string, 0, len(admin.PermissionRegistry))
		for _, p := range admin.PermissionRegistry {
			want = append(want, p.ID)
		}
		sort.Strings(got)
		sort.Strings(want)
		if len(got) != len(want) {
			t.Fatalf("SUPER_ADMIN grants %v, want full catalog %v", got, want)
		}
		for i := range got {
			if got[i] != want[i] {
				t.Fatalf("SUPER_ADMIN grants %v, want %v", got, want)
			}
		}
	})

	t.Run("every preset satisfies its own read prerequisites", func(t *testing.T) {
		for code, grants := range admin.PresetPermissions {
			if _, _, missing := admin.ValidateRoleGrants(grants, false); len(missing) > 0 {
				t.Fatalf("preset %s misses read prerequisites %v", code, missing)
			}
		}
	})

	t.Run("registry has no duplicate IDs", func(t *testing.T) {
		seen := map[string]bool{}
		for _, p := range admin.PermissionRegistry {
			if seen[p.ID] {
				t.Fatalf("duplicate permission %q", p.ID)
			}
			seen[p.ID] = true
			for _, req := range p.Requires {
				if !admin.KnownPermission(req) {
					t.Fatalf("%s requires unknown permission %q", p.ID, req)
				}
			}
		}
	})
}

func TestDelegationCeiling(t *testing.T) {
	t.Run("ceiling excludes roles manage only", func(t *testing.T) {
		ceiling := admin.DelegationCeiling()
		if ceiling["roles:manage"] {
			t.Fatal("delegation ceiling must never include roles:manage")
		}
		if got, want := len(ceiling), len(admin.PermissionRegistry)-1; got != want {
			t.Fatalf("ceiling size %d, want %d", got, want)
		}
	})

	t.Run("custom role over ceiling rejected", func(t *testing.T) {
		_, over, _ := admin.ValidateRoleGrants(
			[]string{"users:read", "roles:manage"}, true)
		if len(over) != 1 || over[0] != "roles:manage" {
			t.Fatalf("over-ceiling %v, want [roles:manage]", over)
		}
	})

	t.Run("presets are not ceiling-checked but customs are", func(t *testing.T) {
		// SUPER_ADMIN legitimately holds roles:manage; a custom role
		// with the same set is still rejected.
		_, over, _ := admin.ValidateRoleGrants(
			admin.PresetPermissions[admin.RoleSuperAdmin], false)
		if len(over) != 0 {
			t.Fatalf("preset path over-ceiling %v", over)
		}
		_, over, _ = admin.ValidateRoleGrants(
			admin.PresetPermissions[admin.RoleSuperAdmin], true)
		if len(over) != 1 {
			t.Fatalf("custom super-set over-ceiling %v, want 1", over)
		}
	})

	t.Run("unknown permission rejected", func(t *testing.T) {
		unknown, _, _ := admin.ValidateRoleGrants(
			[]string{"users:read", "monitors:delete-everything"}, false)
		if len(unknown) != 1 || unknown[0] != "monitors:delete-everything" {
			t.Fatalf("unknown %v", unknown)
		}
	})

	t.Run("mutation grant without read prerequisite", func(t *testing.T) {
		_, _, missing := admin.ValidateRoleGrants(
			[]string{"users:manage"}, true)
		if len(missing) != 1 || missing[0] != "users:read" {
			t.Fatalf("missing %v, want [users:read]", missing)
		}
	})

	t.Run("retry and suppress each require deliveries read", func(t *testing.T) {
		_, _, missing := admin.ValidateRoleGrants(
			[]string{"deliveries:retry", "deliveries:suppress"}, true)
		if len(missing) != 1 || missing[0] != "deliveries:read" {
			t.Fatalf("missing %v", missing)
		}
	})

	t.Run("user is not an admin preset", func(t *testing.T) {
		if _, ok := admin.PresetPermissions["USER"]; ok {
			t.Fatal("USER must not appear in the admin preset map")
		}
		if admin.IsPresetRole("USER") {
			t.Fatal("USER is not a preset role")
		}
		for _, code := range []string{
			admin.RoleViewer, admin.RoleSupport, admin.RoleOperator,
			admin.RoleSecurityAdmin, admin.RoleSuperAdmin,
		} {
			if !admin.IsPresetRole(code) {
				t.Fatalf("%s must be recognized as preset", code)
			}
		}
	})
}
