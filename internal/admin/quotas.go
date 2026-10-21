package admin

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// QuotaCeilings pins the runtime ceilings the HTTP surface may never
// raise — the composition root supplies config allocation limits; an
// admin can only lower or move a user's live cap inside them.
type QuotaCeilings struct {
	// RetainedOwner is the per-owner retained-monitor ceiling from
	// config (live cap may never exceed it — a user whose live cap
	// beat their retained ceiling would exhaust into silent purge
	// territory).
	RetainedOwner int
	// ColumnBound mirrors users.monitor_limit CHECK (0..10000).
	ColumnBound int
}

// QuotaInput is the bounded quota-mutation request.
type QuotaInput struct {
	MonitorLimit    int    `json:"monitor_limit"`
	ExpectedVersion int64  `json:"expected_version"`
	Reason          string `json:"reason"`
}

// SetUserQuota rewrites one user's live monitor cap inside the
// anchor-locked privileged transaction. The ordering guarantees:
//
//   - the target user row is already locked (anchor → users asc) —
//     a concurrent create holds the same users→budget order, so
//     cap-lower and create serialize; usage can never exceed the
//     committed cap,
//   - cap below the LOCKED non-deleted usage (paused counts) is 409 —
//     no cap change, no version bump, no success audit, and nothing
//     is auto-deleted,
//   - cap above the pinned retained-owner ceiling, the global live
//     ceiling, or the column bound is rejected — HTTP never raises
//     runtime allocation ceilings,
//   - negative or out-of-range values are 422.
func SetUserQuota(ctx context.Context, conn Beginner, ceilings QuotaCeilings,
	actor ActorRef, target uuid.UUID, in QuotaInput,
	idemKey string, body []byte, now time.Time) (PrivilegedResult, error) {
	return WithIdempotentPrivilegedTx(ctx, conn, actor,
		"quotas:manage", "quota.set", target.String(), idemKey, body,
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
			if in.MonitorLimit < 0 || in.MonitorLimit > ceilings.ColumnBound {
				return PrivilegedResult{}, &ValidationError{Fields: map[string]any{
					"monitor_limit": "must be between 0 and 10000"}}
			}
			// Ceiling reads under the same transaction: the global live
			// ceiling and the pinned retained-owner bound.
			var globalLive int
			err := tx.QueryRow(ctx, `
				SELECT global_monitor_limit FROM uptime.quota_budgets
				WHERE id=1 FOR SHARE`).Scan(&globalLive)
			if err != nil {
				return PrivilegedResult{}, err
			}
			if in.MonitorLimit > globalLive || in.MonitorLimit > ceilings.RetainedOwner {
				return PrivilegedResult{}, ErrStaleEpoch // 409: ceiling exceeded
			}
			var usage int
			if err := tx.QueryRow(ctx, `
				SELECT count(*) FROM uptime.monitors
				WHERE user_id=$1 AND deleted_at IS NULL`, target).
				Scan(&usage); err != nil {
				return PrivilegedResult{}, err
			}
			if in.MonitorLimit < usage {
				return PrivilegedResult{}, &QuotaConflict{
					Usage: usage, Requested: in.MonitorLimit}
			}
			var prev int
			if err := tx.QueryRow(ctx, `
				SELECT monitor_limit FROM uptime.users WHERE id=$1`,
				target).Scan(&prev); err != nil {
				return PrivilegedResult{}, err
			}
			if _, err := tx.Exec(ctx, `
				UPDATE uptime.users SET monitor_limit=$2,
				  version=version+1, updated_at=clock_timestamp()
				WHERE id=$1`, target, in.MonitorLimit); err != nil {
				return PrivilegedResult{}, err
			}
			if err := AppendAudit(ctx, tx, AuditEvent{
				ActorID:   uuid.NullUUID{UUID: actor.UserID, Valid: true},
				ActorKind: ActorUser, Action: "quota.set",
				SubjectType: "user", SubjectID: target.String(),
				Reason: in.Reason, Outcome: OutcomeSuccess,
				Diff: RedactAuditDiff(map[string]any{
					"monitor_limit": map[string]any{"before": prev, "after": in.MonitorLimit},
				}),
				RequestID: "quota-" + target.String()[:8],
			}); err != nil {
				return PrivilegedResult{}, err
			}
			return PrivilegedResult{Status: 200, Response: map[string]any{
				"user_id":       target.String(),
				"monitor_limit": in.MonitorLimit,
				"usage":         usage,
				"version":       subject.Version + 1,
			}}, nil
		})
}

// QuotaConflict is the cap-below-usage 409 — carries the bounded
// usage/requested counts so the handler can shape the envelope.
type QuotaConflict struct {
	Usage, Requested int
}

func (e *QuotaConflict) Error() string {
	return "quota cap below current usage"
}
