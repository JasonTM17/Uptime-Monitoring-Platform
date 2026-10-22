package admin

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// RevokeSessionsInput is the bounded admin session-revoke request.
type RevokeSessionsInput struct {
	ExpectedVersion int64  `json:"expected_version"`
	Reason          string `json:"reason"`
}

// RevokeUserSessions kills every live session of the target inside
// the anchor-locked privileged transaction and advances the subject's
// security epoch — an in-flight privileged write that lost the
// serialization rechecks its session under the same locks and fails
// as revoked, while a committed write simply precedes the revoke.
// Sessions stay revoked; nothing resurrects them.
func RevokeUserSessions(ctx context.Context, conn Beginner,
	actor ActorRef, target uuid.UUID, in RevokeSessionsInput,
	idemKey string, body []byte, now time.Time) (PrivilegedResult, error) {
	return WithIdempotentPrivilegedTx(ctx, conn, actor,
		"sessions:manage", "sessions.revoke", target.String(), idemKey, body,
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
			isSuper, err := IsSuperAdmin(ctx, tx, target)
			if err != nil {
				return PrivilegedResult{}, err
			}
			if err := AssertNotProtectedSubject(ctx, tx, perms, isSuper); err != nil {
				return PrivilegedResult{}, err
			}
			revoked, err := tx.Exec(ctx, `
				UPDATE uptime.sessions SET revoked_at=clock_timestamp()
				WHERE user_id=$1 AND revoked_at IS NULL`, target)
			if err != nil {
				return PrivilegedResult{}, err
			}
			if _, err := tx.Exec(ctx, `
				UPDATE uptime.users SET security_version=security_version+1,
				  version=version+1, updated_at=clock_timestamp()
				WHERE id=$1`, target); err != nil {
				return PrivilegedResult{}, err
			}
			if err := AppendAudit(ctx, tx, AuditEvent{
				ActorID:   uuid.NullUUID{UUID: actor.UserID, Valid: true},
				ActorKind: ActorUser, Action: "sessions.revoke",
				SubjectType: "user", SubjectID: target.String(),
				Reason: in.Reason, Outcome: OutcomeSuccess,
				Diff: RedactAuditDiff(map[string]any{
					"sessions_revoked": revoked.RowsAffected(),
				}),
				RequestID: "revoke-" + target.String()[:8],
			}); err != nil {
				return PrivilegedResult{}, err
			}
			// Counts, never tokens — the response carries no session
			// identifiers or client data beyond the affected count.
			return PrivilegedResult{Status: 200, Response: map[string]any{
				"user_id":          target.String(),
				"sessions_revoked": revoked.RowsAffected(),
				"security_version": subject.SecurityVersion + 1,
				"version":          subject.Version + 1,
			}}, nil
		})
}
