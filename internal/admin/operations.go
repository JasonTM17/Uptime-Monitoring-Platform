package admin

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/incident"
)

// ErrDeliveryNotHead is the 409 for suppressing a mid-stream row.
var ErrDeliveryNotHead = errors.New("delivery has a live causal predecessor")

// ErrDeliveryState rejects retrying a non-DEAD delivery.
var ErrDeliveryState = errors.New("delivery is not DEAD")

// MonitorActionInput carries the optimistic fence + operator reason.
type MonitorActionInput struct {
	ExpectedGeneration int64  `json:"expected_generation"`
	Reason             string `json:"reason"`
}

// DeliveryActionInput carries the row version fence + operator reason.
type DeliveryActionInput struct {
	ExpectedVersion int64  `json:"expected_version"`
	Reason          string `json:"reason"`
}

// monitorOwner resolves the immutable owner for the lock order: the
// anchor -> users -> monitor order requires the owner ID before the
// privileged transaction begins. owner_id never changes, so the
// pre-read is safe.
func monitorOwner(ctx context.Context, conn Beginner, monitorID uuid.UUID) (uuid.UUID, error) {
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return uuid.Nil, err
	}
	defer tx.Rollback(ctx)
	var owner uuid.UUID
	err = tx.QueryRow(ctx, `
		SELECT user_id FROM uptime.monitors
		WHERE id=$1 AND deleted_at IS NULL`, monitorID).Scan(&owner)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, ErrSubjectRevoked
	}
	return owner, err
}

// transitionMonitor is the shared global pause/resume recipe — the
// same writes the owner path commits (generation fence, segment
// close on pause, next_check_at on resume) minus the ownership
// predicate. The caller supplies whether pause (true) or resume.
func transitionMonitor(ctx context.Context, conn Beginner,
	actor ActorRef, monitorID uuid.UUID, in MonitorActionInput,
	paused bool, action, idemKey string, body []byte, now time.Time) (PrivilegedResult, error) {
	owner, err := monitorOwner(ctx, conn, monitorID)
	if err != nil {
		return PrivilegedResult{}, err
	}
	return WithIdempotentPrivilegedTx(ctx, conn, actor,
		"monitors:operate", action, monitorID.String(), idemKey, body,
		[]uuid.UUID{owner}, now,
		func(tx pgx.Tx, subjects []LockedUser, _ map[string]bool) (PrivilegedResult, error) {
			if len(in.Reason) == 0 || len(in.Reason) > 500 {
				return PrivilegedResult{}, ErrValidation
			}
			// Resume of a suspended owner's monitor is denied — the
			// account fence outranks the operational one.
			if !paused && len(subjects) == 1 && subjects[0].Status != "ACTIVE" {
				return PrivilegedResult{}, ErrStaleEpoch // 409
			}
			var gen int64
			var isPaused bool
			err := tx.QueryRow(ctx, `
				SELECT generation, is_paused FROM uptime.monitors
				WHERE id=$1 AND deleted_at IS NULL FOR UPDATE`,
				monitorID).Scan(&gen, &isPaused)
			if errors.Is(err, pgx.ErrNoRows) {
				return PrivilegedResult{}, ErrSubjectRevoked
			}
			if err != nil {
				return PrivilegedResult{}, err
			}
			if in.ExpectedGeneration != gen {
				return PrivilegedResult{}, ErrStaleEpoch
			}
			if isPaused == paused {
				// Idempotent no-op — already in the requested state.
				return PrivilegedResult{Status: 200, Response: map[string]any{
					"monitor_id": monitorID.String(), "is_paused": isPaused,
					"generation": gen, "already": true,
				}}, nil
			}
			if paused {
				if _, err := tx.Exec(ctx, `
					UPDATE uptime.monitors SET is_paused=true,
					  generation=generation+1, updated_at=clock_timestamp()
					WHERE id=$1`, monitorID); err != nil {
					return PrivilegedResult{}, err
				}
				// Same contract as owner pause: the schedule stops
				// here; the open segment closes so paused time is
				// never owed by the denominator.
				if _, err := tx.Exec(ctx, `
					UPDATE uptime.schedule_segments
					SET ends_at=clock_timestamp()
					WHERE monitor_id=$1 AND ends_at IS NULL`, monitorID); err != nil {
					return PrivilegedResult{}, err
				}
				if _, err := (incident.Repository{}).CloseIncident(ctx, tx,
					monitorID, nil, incident.ReasonConfigChanged); err != nil {
					return PrivilegedResult{}, err
				}
			} else {
				// Resume is eligibility only — next_check_at=now()
				// marks due; the rolling admission gate still gates
				// the actual check. No check-now privilege. A stale
				// DOWN health resets to UNKNOWN so fresh failures can
				// re-open an incident (pause closed it CONFIG_CHANGED).
				// The reset is gated on DOWN: pause+resume is also the
				// due-now mechanism, so unconditional streak resets
				// would stop failure streaks from ever accumulating.
				if _, err := tx.Exec(ctx, `
					UPDATE uptime.monitors SET is_paused=false,
					  next_check_at=clock_timestamp(),
					  health=CASE WHEN health='DOWN' THEN 'UNKNOWN' ELSE health END,
					  failure_streak=CASE WHEN health='DOWN' THEN 0 ELSE failure_streak END,
					  success_streak=CASE WHEN health='DOWN' THEN 0 ELSE success_streak END,
					  generation=generation+1, updated_at=clock_timestamp()
					WHERE id=$1`, monitorID); err != nil {
					return PrivilegedResult{}, err
				}
			}
			if err := AppendAudit(ctx, tx, AuditEvent{
				ActorID:   uuid.NullUUID{UUID: actor.UserID, Valid: true},
				ActorKind: ActorUser, Action: action,
				SubjectType: "monitor", SubjectID: monitorID.String(),
				Reason: in.Reason, Outcome: OutcomeSuccess,
				Diff: RedactAuditDiff(map[string]any{
					"is_paused": map[string]any{"before": isPaused, "after": paused},
				}),
				RequestID: action + "-" + monitorID.String()[:8],
			}); err != nil {
				return PrivilegedResult{}, err
			}
			return PrivilegedResult{Status: 200, Response: map[string]any{
				"monitor_id": monitorID.String(), "is_paused": paused,
				"generation": gen + 1, "already": false,
			}}, nil
		})
}

// PauseGlobalMonitor pauses any monitor by ID under monitors:operate —
// global scope by permission, not by a tenant-bypass flag. In-flight
// RESERVED/RUNNING results die at the generation fence.
func PauseGlobalMonitor(ctx context.Context, conn Beginner,
	actor ActorRef, monitorID uuid.UUID, in MonitorActionInput,
	idemKey string, body []byte, now time.Time) (PrivilegedResult, error) {
	return transitionMonitor(ctx, conn, actor, monitorID, in, true,
		"monitor.pause", idemKey, body, now)
}

// ResumeGlobalMonitor unpauses and marks the monitor due at the
// resume instant — never an immediate check. A suspended owner's
// monitor cannot be resumed (409).
func ResumeGlobalMonitor(ctx context.Context, conn Beginner,
	actor ActorRef, monitorID uuid.UUID, in MonitorActionInput,
	idemKey string, body []byte, now time.Time) (PrivilegedResult, error) {
	return transitionMonitor(ctx, conn, actor, monitorID, in, false,
		"monitor.resume", idemKey, body, now)
}

// RetryDeliveryChain re-arms ONE DEAD stream head: same row, same
// event_key, same channel, same payload — only the attempt budget
// restarts. Mirrors notification.RetryDeadHead's contract inside the
// privileged transaction: state must be DEAD, the version fence must
// match, and no non-terminal predecessor may exist (a dead row
// behind a live head is not the head — resolve the head).
func RetryDeliveryChain(ctx context.Context, conn Beginner,
	actor ActorRef, deliveryID uuid.UUID, in DeliveryActionInput,
	idemKey string, body []byte, now time.Time) (PrivilegedResult, error) {
	return WithIdempotentPrivilegedTx(ctx, conn, actor,
		"deliveries:retry", "delivery.retry", deliveryID.String(), idemKey, body,
		nil, now,
		func(tx pgx.Tx, _ []LockedUser, _ map[string]bool) (PrivilegedResult, error) {
			if len(in.Reason) == 0 || len(in.Reason) > 500 {
				return PrivilegedResult{}, ErrValidation
			}
			var state string
			var ver int64
			var pred *uuid.UUID
			err := tx.QueryRow(ctx, `
				SELECT state, version, predecessor_id
				FROM uptime.notification_outbox WHERE id=$1 FOR UPDATE`,
				deliveryID).Scan(&state, &ver, &pred)
			if errors.Is(err, pgx.ErrNoRows) {
				return PrivilegedResult{}, ErrSubjectRevoked
			}
			if err != nil {
				return PrivilegedResult{}, err
			}
			if ver != in.ExpectedVersion {
				return PrivilegedResult{}, ErrStaleEpoch
			}
			if state != "DEAD" {
				return PrivilegedResult{}, ErrDeliveryState
			}
			if pred != nil {
				var predState string
				if err := tx.QueryRow(ctx, `
					SELECT state FROM uptime.notification_outbox WHERE id=$1`,
					*pred).Scan(&predState); err != nil {
					return PrivilegedResult{}, err
				}
				if predState != "SENT" && predState != "SUPPRESSED" {
					return PrivilegedResult{}, ErrDeliveryNotHead
				}
			}
			tag, err := tx.Exec(ctx, `
				UPDATE uptime.notification_outbox
				SET state='PENDING', attempts=0,
				    next_attempt_at=clock_timestamp(),
				    lease_token=NULL, lease_expires_at=NULL,
				    last_error_code=NULL, version=version+1
				WHERE id=$1 AND state='DEAD'`, deliveryID)
			if err != nil {
				return PrivilegedResult{}, err
			}
			if tag.RowsAffected() != 1 {
				return PrivilegedResult{}, ErrDeliveryState
			}
			if err := AppendAudit(ctx, tx, AuditEvent{
				ActorID:   uuid.NullUUID{UUID: actor.UserID, Valid: true},
				ActorKind: ActorUser, Action: "delivery.retry",
				SubjectType: "delivery", SubjectID: deliveryID.String(),
				Reason: in.Reason, Outcome: OutcomeSuccess,
				Diff: RedactAuditDiff(map[string]any{
					"state": map[string]any{"before": "DEAD", "after": "PENDING"},
				}),
				RequestID: "retry-" + deliveryID.String()[:8],
			}); err != nil {
				return PrivilegedResult{}, err
			}
			return PrivilegedResult{Status: 202, Response: map[string]any{
				"delivery_id": deliveryID.String(), "state": "PENDING",
				"version": ver + 1,
			}}, nil
		})
}

// SuppressDeliveryChain cascades the authorized skip across a causal
// stream: the named head plus every descendant whose chain reaches
// it — a RECOVERY is never suppressed alone behind a live DOWN.
// Mirrors notification.SuppressStream inside the privileged
// transaction, with the operator's reason recorded in both the
// outbox error code's audit row and the audit event itself. Returns
// the number of rows suppressed.
func SuppressDeliveryChain(ctx context.Context, conn Beginner,
	actor ActorRef, deliveryID uuid.UUID, in DeliveryActionInput,
	idemKey string, body []byte, now time.Time) (PrivilegedResult, error) {
	return WithIdempotentPrivilegedTx(ctx, conn, actor,
		"deliveries:suppress", "delivery.suppress", deliveryID.String(), idemKey, body,
		nil, now,
		func(tx pgx.Tx, _ []LockedUser, _ map[string]bool) (PrivilegedResult, error) {
			if len(in.Reason) == 0 || len(in.Reason) > 500 {
				return PrivilegedResult{}, ErrValidation
			}
			var ver int64
			var predLive bool
			err := tx.QueryRow(ctx, `
				SELECT o.version, COALESCE((SELECT p.state IN ('PENDING','LEASED')
				  FROM uptime.notification_outbox p
				  WHERE p.id = o.predecessor_id), false)
				FROM uptime.notification_outbox o WHERE o.id=$1 FOR UPDATE`,
				deliveryID).Scan(&ver, &predLive)
			if errors.Is(err, pgx.ErrNoRows) {
				return PrivilegedResult{}, ErrSubjectRevoked
			}
			if err != nil {
				return PrivilegedResult{}, err
			}
			if ver != in.ExpectedVersion {
				return PrivilegedResult{}, ErrStaleEpoch
			}
			if predLive {
				return PrivilegedResult{}, ErrDeliveryNotHead
			}
			tag, err := tx.Exec(ctx, `
				WITH RECURSIVE chain AS (
				  SELECT id FROM uptime.notification_outbox WHERE id=$1
				  UNION ALL
				  SELECT o.id FROM uptime.notification_outbox o
				  JOIN chain c ON o.predecessor_id = c.id
				)
				UPDATE uptime.notification_outbox
				SET state='SUPPRESSED', lease_token=NULL,
				    lease_expires_at=NULL,
				    last_error_code='OPERATOR_SUPPRESSED',
				    version=version+1
				WHERE id IN (SELECT id FROM chain)
				  AND state IN ('PENDING','DEAD','LEASED')`, deliveryID)
			if err != nil {
				return PrivilegedResult{}, err
			}
			n := tag.RowsAffected()
			if err := AppendAudit(ctx, tx, AuditEvent{
				ActorID:   uuid.NullUUID{UUID: actor.UserID, Valid: true},
				ActorKind: ActorUser, Action: "delivery.suppress",
				SubjectType: "delivery", SubjectID: deliveryID.String(),
				Reason: in.Reason, Outcome: OutcomeSuccess,
				Diff: RedactAuditDiff(map[string]any{
					"rows_suppressed": n,
				}),
				RequestID: "suppress-" + deliveryID.String()[:8],
			}); err != nil {
				return PrivilegedResult{}, err
			}
			return PrivilegedResult{Status: 202, Response: map[string]any{
				"delivery_id":     deliveryID.String(),
				"state":           "SUPPRESSED",
				"rows_suppressed": n,
			}}, nil
		})
}
