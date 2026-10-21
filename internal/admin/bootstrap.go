package admin

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Bootstrap and recovery errors — surfaced to the operator CLI, never
// to a public API.
var (
	ErrSuperAdminExists = errors.New("bootstrap denied: an active SUPER_ADMIN already exists")
	ErrBootstrapTarget  = errors.New("bootstrap target must be an existing ACTIVE user")
	ErrReasonRequired   = errors.New("a reason (1-500 chars) is required")
)

// superAdminRoleID is the deterministic preset UUID seeded by
// migration 007.
const superAdminRoleID = "00000000-0000-4000-8000-000000000005"

// BootstrapSuperAdmin grants the SUPER_ADMIN preset to an existing
// ACTIVE user — the one-time, CLI-only path from zero to an
// administrable system. It refuses to run while any active
// SUPER_ADMIN exists (counted under the anchor lock, so a concurrent
// demote cannot slip past the check), never creates a user, and
// never runs at process startup.
func BootstrapSuperAdmin(ctx context.Context, conn *pgx.Conn, email, reason, requestID string) error {
	reason = strings.TrimSpace(reason)
	if len(reason) == 0 || len(reason) > maxAuditReason {
		return ErrReasonRequired
	}
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	// Anchor first — the single serialization point shared by every
	// privileged path (API and CLI alike).
	if _, err := tx.Exec(ctx,
		`SELECT id FROM uptime.security_anchor WHERE id=1 FOR UPDATE`); err != nil {
		return fmt.Errorf("lock anchor: %w", err)
	}

	var active int
	if err := tx.QueryRow(ctx, `
		SELECT count(*) FROM uptime.user_roles ur
		JOIN uptime.users u ON u.id = ur.user_id
		WHERE ur.role_id = $1 AND u.status = 'ACTIVE'`,
		superAdminRoleID).Scan(&active); err != nil {
		return err
	}
	if active > 0 {
		return ErrSuperAdminExists
	}

	var targetID uuid.UUID
	var status string
	err = tx.QueryRow(ctx, `
		SELECT id, status FROM uptime.users
		WHERE email = lower(btrim($1)) FOR UPDATE`, email).Scan(&targetID, &status)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrBootstrapTarget
	}
	if err != nil {
		return err
	}
	if status != "ACTIVE" {
		return ErrBootstrapTarget
	}

	if err := grantSuperAdmin(ctx, tx, targetID); err != nil {
		return err
	}
	if err := AppendAudit(ctx, tx, AuditEvent{
		ActorKind: ActorCLI, Action: "admin.bootstrap",
		SubjectType: "user", SubjectID: targetID.String(),
		Reason: reason, Outcome: OutcomeSuccess, RequestID: requestID,
	}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// RecoverAdministrativeAccess grants SUPER_ADMIN to an existing
// ACTIVE user during operator maintenance — the controlled way back
// when the last administrator lost access. It revokes every session
// the target holds (authority changes must re-authenticate) and
// bumps the security version, all inside the anchor-locked
// transaction with its audit row.
func RecoverAdministrativeAccess(ctx context.Context, conn *pgx.Conn, email, reason, requestID string) error {
	reason = strings.TrimSpace(reason)
	if len(reason) == 0 || len(reason) > maxAuditReason {
		return ErrReasonRequired
	}
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx,
		`SELECT id FROM uptime.security_anchor WHERE id=1 FOR UPDATE`); err != nil {
		return fmt.Errorf("lock anchor: %w", err)
	}

	var targetID uuid.UUID
	var status string
	err = tx.QueryRow(ctx, `
		SELECT id, status FROM uptime.users
		WHERE email = lower(btrim($1)) FOR UPDATE`, email).Scan(&targetID, &status)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrBootstrapTarget
	}
	if err != nil {
		return err
	}
	if status != "ACTIVE" {
		return ErrBootstrapTarget
	}

	if err := grantSuperAdmin(ctx, tx, targetID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE uptime.sessions SET revoked_at=clock_timestamp()
		WHERE user_id=$1 AND revoked_at IS NULL`, targetID); err != nil {
		return err
	}
	if err := AppendAudit(ctx, tx, AuditEvent{
		ActorKind: ActorCLI, Action: "admin.recover",
		SubjectType: "user", SubjectID: targetID.String(),
		Reason: reason, Outcome: OutcomeSuccess, RequestID: requestID,
	}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// grantSuperAdmin inserts the assignment idempotently and bumps the
// target's security epoch so prior authorization decisions die with
// the transaction.
func grantSuperAdmin(ctx context.Context, tx pgx.Tx, targetID uuid.UUID) error {
	tag, err := tx.Exec(ctx, `
		INSERT INTO uptime.user_roles (user_id, role_id)
		VALUES ($1, $2) ON CONFLICT (user_id, role_id) DO NOTHING`,
		targetID, superAdminRoleID)
	if err != nil {
		var pge *pgconn.PgError
		if errors.As(err, &pge) && pge.Code == "23503" {
			return ErrBootstrapTarget
		}
		return err
	}
	if tag.RowsAffected() > 0 {
		if _, err := tx.Exec(ctx, `
			UPDATE uptime.users
			SET security_version=security_version+1, version=version+1,
			    updated_at=now()
			WHERE id=$1`, targetID); err != nil {
			return err
		}
	}
	return nil
}
