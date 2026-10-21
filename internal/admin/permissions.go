package admin

import "sort"

// Permission is one entry in the fixed capability catalog. IDs are
// contract identifiers (spec 04 admin API table); Requires lists the
// read grant a mutation grant implies inside a single custom role
// (spec 07, custom-role read prerequisites — RT F10).
type Permission struct {
	ID       string
	Requires []string
}

// Preset role codes. Presets are seeded by migration 007 and are
// immutable through the HTTP surface.
const (
	RoleViewer        = "VIEWER"
	RoleSupport       = "SUPPORT"
	RoleOperator      = "OPERATOR"
	RoleSecurityAdmin = "SECURITY_ADMIN"
	RoleSuperAdmin    = "SUPER_ADMIN"
)

// PermissionRegistry is the single authoritative catalog. SUPER_ADMIN
// holds this exact set explicitly — there is no wildcard that
// auto-approves future permissions.
var PermissionRegistry = []Permission{
	{ID: "platform:read"},
	{ID: "users:read"},
	{ID: "users:manage", Requires: []string{"users:read"}},
	{ID: "sessions:manage", Requires: []string{"users:read"}},
	{ID: "quotas:manage", Requires: []string{"users:read"}},
	{ID: "roles:read"},
	{ID: "roles:manage"},
	{ID: "monitors:global:read"},
	{ID: "monitors:operate", Requires: []string{"monitors:global:read"}},
	{ID: "operations:read"},
	{ID: "deliveries:read"},
	{ID: "deliveries:retry", Requires: []string{"deliveries:read"}},
	{ID: "deliveries:suppress", Requires: []string{"deliveries:read"}},
	{ID: "audit:read"},
}

// PresetPermissions maps each builtin preset to its explicit grant
// set (spec 07 matrix). USER is intentionally absent: it is not an
// admin preset and carries no global permission.
var PresetPermissions = map[string][]string{
	RoleViewer: {
		"platform:read",
		"monitors:global:read",
		"operations:read",
	},
	RoleSupport: {
		"platform:read",
		"users:read",
		"monitors:global:read",
		"operations:read",
		"deliveries:read",
	},
	RoleOperator: {
		"platform:read",
		"monitors:global:read",
		"monitors:operate",
		"operations:read",
		"deliveries:read",
		"deliveries:retry",
		"deliveries:suppress",
	},
	RoleSecurityAdmin: {
		"platform:read",
		"users:read",
		"users:manage",
		"sessions:manage",
		"roles:read",
		"monitors:global:read",
		"operations:read",
		"audit:read",
	},
	RoleSuperAdmin: registryIDs(),
}

// DelegationCeiling is the set a custom role may hold: every catalog
// permission except roles:manage (spec 07 — delegation ceiling never
// includes the power to mint new role authority).
func DelegationCeiling() map[string]bool {
	out := make(map[string]bool, len(PermissionRegistry))
	for _, p := range PermissionRegistry {
		if p.ID != "roles:manage" {
			out[p.ID] = true
		}
	}
	return out
}

var (
	registrySet = func() map[string]Permission {
		m := make(map[string]Permission, len(PermissionRegistry))
		for _, p := range PermissionRegistry {
			m[p.ID] = p
		}
		return m
	}()
	presetSet = func() map[string]bool {
		m := map[string]bool{
			RoleViewer: true, RoleSupport: true, RoleOperator: true,
			RoleSecurityAdmin: true, RoleSuperAdmin: true,
		}
		return m
	}()
)

func registryIDs() []string {
	ids := make([]string, 0, len(PermissionRegistry))
	for _, p := range PermissionRegistry {
		ids = append(ids, p.ID)
	}
	return ids
}

// IsPresetRole reports whether code names a builtin preset.
func IsPresetRole(code string) bool { return presetSet[code] }

// KnownPermission reports whether id is in the fixed catalog.
func KnownPermission(id string) bool {
	_, ok := registrySet[id]
	return ok
}

// ValidateRoleGrants checks a proposed grant set for one role.
// Returns sorted lists so responses and tests are deterministic:
//   - unknown:        IDs not in the catalog (never grantable)
//   - overCeiling:    catalog IDs outside the delegation ceiling
//     (only checked for custom roles)
//   - missingRequires: read grants the mutation grants imply but
//     the set does not carry
func ValidateRoleGrants(ids []string, custom bool) (unknown, overCeiling, missing []string) {
	set := make(map[string]bool, len(ids))
	for _, id := range ids {
		p, ok := registrySet[id]
		if !ok {
			unknown = append(unknown, id)
			continue
		}
		set[id] = true
		for _, req := range p.Requires {
			if !contains(ids, req) && !contains(missing, req) {
				missing = append(missing, req)
			}
		}
	}
	if custom {
		ceiling := DelegationCeiling()
		for _, id := range ids {
			if _, ok := registrySet[id]; ok && !ceiling[id] {
				overCeiling = append(overCeiling, id)
			}
		}
		sort.Strings(overCeiling)
	}
	sort.Strings(unknown)
	sort.Strings(missing)
	return unknown, overCeiling, missing
}

func contains(ids []string, want string) bool {
	for _, id := range ids {
		if id == want {
			return true
		}
	}
	return false
}
