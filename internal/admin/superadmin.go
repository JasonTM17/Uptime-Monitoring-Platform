package admin

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ErrLastSuperAdmin maps to 409 LAST_SUPERADMIN: the mutation would
// leave zero active administrators. It is raised AFTER the mutating
// statement inside the same anchor-locked transaction, so every
// removal path — demote, suspend, role removal, recovery — rolls
// back atomically rather than partially applying.
var ErrLastSuperAdmin = errors.New("operation would remove the last active SUPER_ADMIN")

// AssertActiveSuperAdminRemaining enforces the aggregate invariant:
// at least one ACTIVE user must hold the SUPER_ADMIN preset after
// this transaction's changes.
//
// Why a post-mutation count, not a pre-check: write skew. Two
// concurrent transactions that each "check then remove" can both see
// two admins and both delete — the count must run after the mutation
// under the security anchor that serializes all privileged writes.
// A DISABLED admin does not count as successor: a suspended
// superadmin cannot rescue the platform.
func AssertActiveSuperAdminRemaining(ctx context.Context, tx pgx.Tx) error {
	var remaining int
	err := tx.QueryRow(ctx, `
		SELECT count(*) FROM uptime.user_roles ur
		JOIN uptime.users u ON u.id = ur.user_id
		WHERE ur.role_id = $1 AND u.status = 'ACTIVE'`,
		superAdminRoleID).Scan(&remaining)
	if err != nil {
		return err
	}
	if remaining == 0 {
		return ErrLastSuperAdmin
	}
	return nil
}

// AssertNotProtectedSubject verifies a mutation may act on the target:
// SECURITY_ADMIN subjects may never mutate a SUPER_ADMIN holder — only
// another SUPER_ADMIN can. Actor permission is already proven by the
// privileged guard; this adds the protected-subject rule on top.
func AssertNotProtectedSubject(ctx context.Context, tx pgx.Tx,
	actorPerms map[string]bool, targetIsSuperAdmin bool) error {
	if targetIsSuperAdmin && !actorPerms["roles:manage"] {
		return ErrForbidden
	}
	return nil
}

// IsSuperAdmin reports whether the user currently holds the
// SUPER_ADMIN preset — inside the guarded transaction.
func IsSuperAdmin(ctx context.Context, tx pgx.Tx, userID uuid.UUID) (bool, error) {
	var n int
	err := tx.QueryRow(ctx, `
		SELECT count(*) FROM uptime.user_roles
		WHERE user_id=$1 AND role_id=$2`, userID, superAdminRoleID).Scan(&n)
	return n > 0, err
}
