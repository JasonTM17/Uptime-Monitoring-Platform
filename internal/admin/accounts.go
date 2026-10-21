package admin

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// SuspendInput is the bounded suspend/restore request shape —
// expected_version is the optimistic-concurrency fence on the subject.
type SuspendInput struct {
	ExpectedVersion int64  `json:"expected_version"`
	Reason          string `json:"reason"`
}

// SuspendAccount disables a user end to end inside the anchor-locked
// privileged transaction:
//
//   - user row: status DISABLED, security_version+1 (every existing
//     session/authorization snapshot dies with the epoch),
//   - sessions: every live session is revoked in the same commit —
//     no straggler token survives to the next request,
//   - segments: open schedule_segments close at the suspend instant
//     so the suspension window is never owed by the denominator,
//   - generation: active monitors bump generation — in-flight
//     RESERVED/RUNNING results hit the generation fence (on top of
//     the owner-status fence) and can never commit post-suspend
//     observations,
//   - invariant: the last-superadmin guard runs post-mutation.
//
// Engine/dispatcher coordination is fence-based, not signal-based:
// admission joins users.status, finalize locks the owner row first,
// and the dispatcher suppresses non-ACTIVE owners — no network or
// cross-process call is needed inside the transaction.
func SuspendAccount(ctx context.Context, conn Beginner,
	actor ActorRef, target uuid.UUID, in SuspendInput,
	idemKey string, body []byte, now time.Time) (PrivilegedResult, error) {
	return WithIdempotentPrivilegedTx(ctx, conn, actor,
		"users:manage", "account.suspend", target.String(), idemKey, body,
		[]uuid.UUID{target}, now,
		func(tx pgx.Tx, subjects []LockedUser, perms map[string]bool) (PrivilegedResult, error) {
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
			if subject.Status != "ACTIVE" {
				// Idempotent no-op: the account is already disabled —
				// nothing to re-revoke, nothing to re-audit.
				return PrivilegedResult{Status: 200, Response: map[string]any{
					"user_id": target.String(), "status": "DISABLED",
					"already": true,
				}}, nil
			}
			isSuper, err := IsSuperAdmin(ctx, tx, target)
			if err != nil {
				return PrivilegedResult{}, err
			}
			if err := AssertNotProtectedSubject(ctx, tx, perms, isSuper); err != nil {
				return PrivilegedResult{}, err
			}
			if _, err := tx.Exec(ctx, `
				UPDATE uptime.users
				SET status='DISABLED', disabled_at=clock_timestamp(),
				  security_version=security_version+1,
				  version=version+1, updated_at=clock_timestamp()
				WHERE id=$1`, target); err != nil {
				return PrivilegedResult{}, err
			}
			sessions, err := tx.Exec(ctx, `
				UPDATE uptime.sessions SET revoked_at=clock_timestamp()
				WHERE user_id=$1 AND revoked_at IS NULL`, target)
			if err != nil {
				return PrivilegedResult{}, err
			}
			// Close the coverage window — suspension is never owed.
			if _, err := tx.Exec(ctx, `
				UPDATE uptime.schedule_segments SET ends_at=clock_timestamp()
				WHERE ends_at IS NULL AND monitor_id IN
				  (SELECT id FROM uptime.monitors WHERE user_id=$1)`,
				target); err != nil {
				return PrivilegedResult{}, err
			}
			// Fence in-flight results at the generation level too.
			fenced, err := tx.Exec(ctx, `
				UPDATE uptime.monitors SET generation=generation+1,
				  updated_at=clock_timestamp()
				WHERE user_id=$1 AND deleted_at IS NULL AND NOT is_paused`,
				target)
			if err != nil {
				return PrivilegedResult{}, err
			}
			if err := AssertActiveSuperAdminRemaining(ctx, tx); err != nil {
				return PrivilegedResult{}, err
			}
			if err := AppendAudit(ctx, tx, AuditEvent{
				ActorID:   uuid.NullUUID{UUID: actor.UserID, Valid: true},
				ActorKind: ActorUser, Action: "account.suspend",
				SubjectType: "user", SubjectID: target.String(),
				Reason: in.Reason, Outcome: OutcomeSuccess,
				Diff: RedactAuditDiff(map[string]any{
					"status":           map[string]any{"before": "ACTIVE", "after": "DISABLED"},
					"sessions_revoked": sessions.RowsAffected(),
					"monitors_fenced":  fenced.RowsAffected(),
				}),
				RequestID: "suspend-" + target.String()[:8],
			}); err != nil {
				return PrivilegedResult{}, err
			}
			return PrivilegedResult{Status: 200, Response: map[string]any{
				"user_id":          target.String(),
				"status":           "DISABLED",
				"already":          false,
				"sessions_revoked": sessions.RowsAffected(),
				"version":          subject.Version + 1,
			}}, nil
		})
}

// RestoreAccount re-activates a DISABLED user. Restore never
// resurrects what suspend revoked: old sessions stay revoked (new
// login required), role grants that were removed stay removed, and
// user-paused monitors stay paused. Eligible monitors become due
// immediately — the next admission opens a fresh segment at the
// restore-time grid, identical to the monitor-resume seam.
func RestoreAccount(ctx context.Context, conn Beginner,
	actor ActorRef, target uuid.UUID, in SuspendInput,
	idemKey string, body []byte, now time.Time) (PrivilegedResult, error) {
	return WithIdempotentPrivilegedTx(ctx, conn, actor,
		"users:manage", "account.restore", target.String(), idemKey, body,
		[]uuid.UUID{target}, now,
		func(tx pgx.Tx, subjects []LockedUser, perms map[string]bool) (PrivilegedResult, error) {
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
			if subject.Status != "DISABLED" {
				return PrivilegedResult{Status: 200, Response: map[string]any{
					"user_id": target.String(), "status": subject.Status,
					"already": true,
				}}, nil
			}
			isSuper, err := IsSuperAdmin(ctx, tx, target)
			if err != nil {
				return PrivilegedResult{}, err
			}
			if err := AssertNotProtectedSubject(ctx, tx, perms, isSuper); err != nil {
				return PrivilegedResult{}, err
			}
			if _, err := tx.Exec(ctx, `
				UPDATE uptime.users
				SET status='ACTIVE', disabled_at=NULL,
				  security_version=security_version+1,
				  version=version+1, updated_at=clock_timestamp()
				WHERE id=$1`, target); err != nil {
				return PrivilegedResult{}, err
			}
			// Due at the first future slot — segments open lazily at
			// admission (the Phase-06 resume seam), paused/deleted
			// monitors are untouched.
			due, err := tx.Exec(ctx, `
				UPDATE uptime.monitors SET next_check_at=clock_timestamp(),
				  updated_at=clock_timestamp()
				WHERE user_id=$1 AND deleted_at IS NULL AND NOT is_paused`,
				target)
			if err != nil {
				return PrivilegedResult{}, err
			}
			if err := AppendAudit(ctx, tx, AuditEvent{
				ActorID:   uuid.NullUUID{UUID: actor.UserID, Valid: true},
				ActorKind: ActorUser, Action: "account.restore",
				SubjectType: "user", SubjectID: target.String(),
				Reason: in.Reason, Outcome: OutcomeSuccess,
				Diff: RedactAuditDiff(map[string]any{
					"status":        map[string]any{"before": "DISABLED", "after": "ACTIVE"},
					"monitors_dued": due.RowsAffected(),
				}),
				RequestID: "restore-" + target.String()[:8],
			}); err != nil {
				return PrivilegedResult{}, err
			}
			return PrivilegedResult{Status: 200, Response: map[string]any{
				"user_id":       target.String(),
				"status":        "ACTIVE",
				"already":       false,
				"monitors_dued": due.RowsAffected(),
				"version":       subject.Version + 1,
			}}, nil
		})
}
