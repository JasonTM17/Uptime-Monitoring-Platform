package admin

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// RoleDTO is the redacted catalog row — the API projection never
// carries grants beyond catalog permission IDs.
type RoleDTO struct {
	ID          uuid.UUID `json:"id"`
	Code        string    `json:"code"`
	Name        string    `json:"name"`
	IsPreset    bool      `json:"is_preset"`
	Version     int64     `json:"version"`
	Permissions []string  `json:"permissions"`
}

// RoleCatalogDTO is the full role-management read model: catalog,
// presets, delegation ceiling and explicit read prerequisites.
type RoleCatalogDTO struct {
	Catalog           []PermissionInfo `json:"catalog"`
	Roles             []RoleDTO        `json:"roles"`
	DelegationCeiling []string         `json:"delegation_ceiling"`
}

// PermissionInfo exposes one catalog entry with its explicit requires.
type PermissionInfo struct {
	ID       string   `json:"id"`
	Requires []string `json:"requires"`
}

// Catalog exposes the registry with explicit requires — the same
// single source the schema seeds.
func Catalog() []PermissionInfo {
	out := make([]PermissionInfo, 0, len(PermissionRegistry))
	for _, p := range PermissionRegistry {
		req := append([]string(nil), p.Requires...)
		if req == nil {
			req = []string{}
		}
		out = append(out, PermissionInfo{ID: p.ID, Requires: req})
	}
	return out
}

// Ceiling returns the delegation ceiling as a sorted list.
func Ceiling() []string {
	set := DelegationCeiling()
	out := make([]string, 0, len(set))
	for id := range set {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// ListRoleCatalog is the roles:read projection.
func ListRoleCatalog(ctx context.Context, conn Beginner,
	actor ActorRef, now time.Time) (RoleCatalogDTO, error) {
	var out RoleCatalogDTO
	err := AuthorizeRead(ctx, conn, actor, "roles:read", now,
		func(tx pgx.Tx, perms map[string]bool) error {
			rows, err := tx.Query(ctx, `
				SELECT id, code, name, is_preset, version FROM uptime.roles
				ORDER BY is_preset DESC, code`)
			if err != nil {
				return err
			}
			defer rows.Close()
			var roles []RoleDTO
			var ids []uuid.UUID
			for rows.Next() {
				var r RoleDTO
				if err := rows.Scan(&r.ID, &r.Code, &r.Name, &r.IsPreset, &r.Version); err != nil {
					return err
				}
				r.Permissions = []string{}
				roles = append(roles, r)
				ids = append(ids, r.ID)
			}
			if err := rows.Err(); err != nil {
				return err
			}
			grants, err := tx.Query(ctx, `
				SELECT role_id, permission_id FROM uptime.role_permissions
				WHERE role_id = ANY($1) ORDER BY permission_id`, ids)
			if err != nil {
				return err
			}
			defer grants.Close()
			byRole := map[uuid.UUID][]string{}
			for grants.Next() {
				var rid uuid.UUID
				var perm string
				if err := grants.Scan(&rid, &perm); err != nil {
					return err
				}
				byRole[rid] = append(byRole[rid], perm)
			}
			for i := range roles {
				if g, ok := byRole[roles[i].ID]; ok {
					roles[i].Permissions = g
				}
			}
			out = RoleCatalogDTO{
				Catalog:           Catalog(),
				Roles:             roles,
				DelegationCeiling: Ceiling(),
			}
			return nil
		})
	return out, err
}

// CreateRoleInput is the bounded custom-role request.
type CreateRoleInput struct {
	Code        string   `json:"code"`
	Name        string   `json:"name"`
	Permissions []string `json:"permissions"`
	Reason      string   `json:"reason"`
}

// UpdateRoleInput is the PATCH shape — Permissions, when present,
// replaces the grant set wholesale (full-set atomic update).
type UpdateRoleInput struct {
	Name            *string  `json:"name"`
	Permissions     []string `json:"permissions"`
	ExpectedVersion int64    `json:"expected_version"`
	Reason          string   `json:"reason"`
}

// AssignRolesInput is the PUT shape for one user's role set.
type AssignRolesInput struct {
	RoleIDs         []uuid.UUID `json:"role_ids"`
	ExpectedVersion int64       `json:"expected_version"`
	Reason          string      `json:"reason"`
}

// grantValidation produces the bounded missing_permissions response:
// 422 with the sorted missing IDs — the contract's failure shape for
// unmet read prerequisites.
func grantValidation(ids []string) (map[string]any, bool) {
	_, _, missing := ValidateRoleGrants(ids, true)
	if len(missing) == 0 {
		return nil, false
	}
	return map[string]any{"missing_permissions": missing}, true
}

// CreateCustomRole creates a bounded custom role under the
// SUPER_ADMIN-only roles:manage guard.
func CreateCustomRole(ctx context.Context, conn Beginner,
	actor ActorRef, idemKey string, body []byte, in CreateRoleInput,
	now time.Time) (PrivilegedResult, error) {
	return WithIdempotentPrivilegedTx(ctx, conn, actor,
		"roles:manage", "role.create", "roles", idemKey, body, nil, now,
		func(tx pgx.Tx, _ []LockedUser, _ map[string]bool) (PrivilegedResult, error) {
			if len(in.Code) < 2 || len(in.Code) > 40 || len(in.Name) < 1 ||
				len(in.Name) > 80 || len(in.Reason) == 0 || len(in.Reason) > 500 {
				return PrivilegedResult{}, ErrValidation
			}
			unknown, over, _ := ValidateRoleGrants(in.Permissions, true)
			if len(unknown) > 0 {
				return PrivilegedResult{}, fmt.Errorf("%w: unknown %v",
					ErrValidation, unknown)
			}
			if len(over) > 0 {
				return PrivilegedResult{}, ErrForbidden
			}
			if fields, bad := grantValidation(in.Permissions); bad {
				return PrivilegedResult{}, &ValidationError{Fields: fields}
			}
			id := uuid.New()
			if _, err := tx.Exec(ctx, `
				INSERT INTO uptime.roles (id, code, name)
				VALUES ($1,$2,$3)`, id, in.Code, in.Name); err != nil {
				return PrivilegedResult{}, err
			}
			for _, perm := range in.Permissions {
				if _, err := tx.Exec(ctx, `
					INSERT INTO uptime.role_permissions (role_id, permission_id)
					VALUES ($1,$2)`, id, perm); err != nil {
					return PrivilegedResult{}, err
				}
			}
			if err := AppendAudit(ctx, tx, AuditEvent{
				ActorID:   uuid.NullUUID{UUID: actor.UserID, Valid: true},
				ActorKind: ActorUser, Action: "role.create",
				SubjectType: "role", SubjectID: id.String(),
				Reason: in.Reason, Outcome: OutcomeSuccess,
				Diff: RedactAuditDiff(map[string]any{
					"code": in.Code, "permissions": in.Permissions,
				}),
				RequestID: "role-create-" + id.String()[:8],
			}); err != nil {
				return PrivilegedResult{}, err
			}
			return PrivilegedResult{Status: 201, Response: map[string]any{
				"role": RoleDTO{ID: id, Code: in.Code, Name: in.Name,
					Version: 1, Permissions: append([]string(nil), in.Permissions...)},
			}}, nil
		})
}

// UpdateRole replaces a custom role's grant set wholesale. Presets
// are immutable through HTTP. Every affected user's security epoch
// advances in the same transaction — no cached authority survives.
func UpdateRole(ctx context.Context, conn Beginner,
	actor ActorRef, roleID uuid.UUID, in UpdateRoleInput,
	idemKey string, body []byte, now time.Time) (PrivilegedResult, error) {
	return WithIdempotentPrivilegedTx(ctx, conn, actor,
		"roles:manage", "role.update", roleID.String(), idemKey, body, nil, now,
		func(tx pgx.Tx, _ []LockedUser, _ map[string]bool) (PrivilegedResult, error) {
			var code, name string
			var preset bool
			var version int64
			err := tx.QueryRow(ctx, `
				SELECT code, name, is_preset, version FROM uptime.roles
				WHERE id=$1 FOR UPDATE`, roleID).Scan(&code, &name, &preset, &version)
			if errors.Is(err, pgx.ErrNoRows) {
				return PrivilegedResult{}, ErrSubjectRevoked
			}
			if err != nil {
				return PrivilegedResult{}, err
			}
			if preset {
				return PrivilegedResult{}, ErrForbidden
			}
			if in.ExpectedVersion != version {
				return PrivilegedResult{}, ErrStaleEpoch
			}
			if len(in.Reason) == 0 || len(in.Reason) > 500 {
				return PrivilegedResult{}, ErrValidation
			}
			newName := name
			if in.Name != nil {
				if len(*in.Name) < 1 || len(*in.Name) > 80 {
					return PrivilegedResult{}, ErrValidation
				}
				newName = *in.Name
			}
			unknown, over, _ := ValidateRoleGrants(in.Permissions, true)
			if len(unknown) > 0 {
				return PrivilegedResult{}, fmt.Errorf("%w: unknown %v",
					ErrValidation, unknown)
			}
			if len(over) > 0 {
				return PrivilegedResult{}, ErrForbidden
			}
			if fields, bad := grantValidation(in.Permissions); bad {
				return PrivilegedResult{}, &ValidationError{Fields: fields}
			}
			if _, err := tx.Exec(ctx, `
				DELETE FROM uptime.role_permissions WHERE role_id=$1`, roleID); err != nil {
				return PrivilegedResult{}, err
			}
			for _, perm := range in.Permissions {
				if _, err := tx.Exec(ctx, `
					INSERT INTO uptime.role_permissions (role_id, permission_id)
					VALUES ($1,$2)`, roleID, perm); err != nil {
					return PrivilegedResult{}, err
				}
			}
			if _, err := tx.Exec(ctx, `
				UPDATE uptime.roles SET name=$2, version=version+1, updated_at=now()
				WHERE id=$1`, roleID, newName); err != nil {
				return PrivilegedResult{}, err
			}
			// Epoch fanout: every holder of this role must re-authorize.
			if _, err := tx.Exec(ctx, `
				UPDATE uptime.users SET security_version=security_version+1,
				  version=version+1, updated_at=now()
				WHERE id IN (SELECT user_id FROM uptime.user_roles WHERE role_id=$1)`,
				roleID); err != nil {
				return PrivilegedResult{}, err
			}
			if err := AppendAudit(ctx, tx, AuditEvent{
				ActorID:   uuid.NullUUID{UUID: actor.UserID, Valid: true},
				ActorKind: ActorUser, Action: "role.update",
				SubjectType: "role", SubjectID: roleID.String(),
				Reason: in.Reason, Outcome: OutcomeSuccess,
				Diff: RedactAuditDiff(map[string]any{
					"version":     map[string]any{"before": version, "after": version + 1},
					"permissions": in.Permissions,
				}),
				RequestID: "role-update-" + roleID.String()[:8],
			}); err != nil {
				return PrivilegedResult{}, err
			}
			return PrivilegedResult{Status: 200, Response: map[string]any{
				"role": RoleDTO{ID: roleID, Code: code, Name: newName,
					Version:     version + 1,
					Permissions: append([]string(nil), in.Permissions...)},
			}}, nil
		})
}

// AssignUserRoles replaces one user's role set atomically: validate
// every ID first, replace, bump the subject's security epoch, guard
// the last superadmin, audit — one commit or nothing.
func AssignUserRoles(ctx context.Context, conn Beginner,
	actor ActorRef, target uuid.UUID, in AssignRolesInput,
	idemKey string, body []byte, now time.Time) (PrivilegedResult, error) {
	return WithIdempotentPrivilegedTx(ctx, conn, actor,
		"roles:manage", "roles.assign", target.String(), idemKey, body,
		[]uuid.UUID{target}, now,
		func(tx pgx.Tx, subjects []LockedUser, _ map[string]bool) (PrivilegedResult, error) {
			if len(subjects) != 1 {
				return PrivilegedResult{}, ErrSubjectRevoked
			}
			subject := subjects[0]
			if in.ExpectedVersion != subject.Version {
				return PrivilegedResult{}, ErrStaleEpoch
			}
			if len(in.Reason) == 0 || len(in.Reason) > 500 {
				return PrivilegedResult{}, ErrValidation
			}
			// Every role ID must exist — validate the whole set before
			// touching assignments (no partial update).
			if len(in.RoleIDs) > 20 {
				return PrivilegedResult{}, ErrValidation
			}
			var found int
			if err := tx.QueryRow(ctx, `
				SELECT count(*) FROM uptime.roles WHERE id = ANY($1)`,
				in.RoleIDs).Scan(&found); err != nil {
				return PrivilegedResult{}, err
			}
			if found != len(in.RoleIDs) {
				return PrivilegedResult{}, &ValidationError{
					Fields: map[string]any{"role_ids": "unknown role id(s)"}}
			}
			if _, err := tx.Exec(ctx, `
				DELETE FROM uptime.user_roles WHERE user_id=$1`, target); err != nil {
				return PrivilegedResult{}, err
			}
			for _, rid := range in.RoleIDs {
				if _, err := tx.Exec(ctx, `
					INSERT INTO uptime.user_roles (user_id, role_id)
					VALUES ($1,$2)`, target, rid); err != nil {
					return PrivilegedResult{}, err
				}
			}
			if _, err := tx.Exec(ctx, `
				UPDATE uptime.users SET security_version=security_version+1,
				  version=version+1, updated_at=now()
				WHERE id=$1`, target); err != nil {
				return PrivilegedResult{}, err
			}
			if err := AssertActiveSuperAdminRemaining(ctx, tx); err != nil {
				return PrivilegedResult{}, err
			}
			if err := AppendAudit(ctx, tx, AuditEvent{
				ActorID:   uuid.NullUUID{UUID: actor.UserID, Valid: true},
				ActorKind: ActorUser, Action: "roles.assign",
				SubjectType: "user", SubjectID: target.String(),
				Reason: in.Reason, Outcome: OutcomeSuccess,
				Diff: RedactAuditDiff(map[string]any{
					"role_ids": in.RoleIDs,
				}),
				RequestID: "roles-assign-" + target.String()[:8],
			}); err != nil {
				return PrivilegedResult{}, err
			}
			return PrivilegedResult{Status: 200, Response: map[string]any{
				"user_id":          target.String(),
				"role_ids":         in.RoleIDs,
				"security_version": subject.SecurityVersion + 1,
			}}, nil
		})
}
