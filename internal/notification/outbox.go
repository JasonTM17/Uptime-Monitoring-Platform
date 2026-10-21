package notification

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// EventKind is the durable transition stream. TEST intents (Phase 06)
// get unique keys and no incident anchor.
type EventKind string

const (
	EventDown     EventKind = "DOWN"
	EventRecovery EventKind = "RECOVERY"
	EventTest     EventKind = "TEST"
)

// DeliveryIntent is one logical outbox event for one channel -
// durable notification intent, never a delivery attempt.
type DeliveryIntent struct {
	ID             uuid.UUID
	ChannelID      uuid.UUID
	Kind           EventKind
	PredecessorID  *uuid.UUID
	ChannelVersion int64
}

// TransitionInput carries the incident + monitor projection for one
// health transition. safe_payload intentionally contains NO target
// URL, chat ID, or token - only non-secret identity and timing.
type TransitionInput struct {
	UserID      uuid.UUID
	MonitorID   uuid.UUID
	MonitorName string
	IncidentID  uuid.UUID
	Kind        EventKind
	ObservedAt  time.Time
}

// AppendTransitionDeliveries writes one PENDING outbox row per
// eligible bound channel inside the caller's transaction. Eligibility
// is re-filtered AT WRITE TIME: status VERIFIED, enabled, not
// deleted, bound to this monitor, same owner - a cross-owner or
// pending binding never becomes an intent.
//
// Idempotent on event_key (incident:kind:channel): a duplicate
// finalize re-derives the same logical event and inserts nothing.
// RECOVERY rows link the DOWN predecessor of the same stream.
// No channels -> returns empty; the incident itself is the durable
// transition record - nothing fabricated.
func AppendTransitionDeliveries(ctx context.Context, tx pgx.Tx,
	in TransitionInput) ([]DeliveryIntent, error) {

	if in.Kind != EventDown && in.Kind != EventRecovery {
		return nil, fmt.Errorf("outbox: unsupported transition kind %q", in.Kind)
	}

	rows, err := tx.Query(ctx, `
		SELECT c.id, c.version
		FROM uptime.notification_channels c
		JOIN uptime.monitor_channels mc
		  ON mc.channel_id = c.id AND mc.user_id = c.user_id
		WHERE mc.monitor_id = $1
		  AND c.user_id = $2
		  AND c.status = 'VERIFIED'
		  AND c.enabled
		  AND c.deleted_at IS NULL
		ORDER BY c.id`, in.MonitorID, in.UserID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	type chanV struct {
		id uuid.UUID
		v  int64
	}
	var chans []chanV
	for rows.Next() {
		var cv chanV
		if err := rows.Scan(&cv.id, &cv.v); err != nil {
			return nil, err
		}
		chans = append(chans, cv)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(chans) == 0 {
		return nil, nil // durable transition stands on the incident row
	}

	payload, err := json.Marshal(map[string]any{
		"monitor_id":   in.MonitorID.String(),
		"monitor_name": in.MonitorName,
		"event_kind":   string(in.Kind),
		"incident_id":  in.IncidentID.String(),
		"observed_at":  in.ObservedAt.UTC().Format(time.RFC3339Nano),
	})
	if err != nil {
		return nil, err
	}

	var out []DeliveryIntent
	for _, cv := range chans {
		key := fmt.Sprintf("%s:%s:%s", in.IncidentID, in.Kind, cv.id)

		var pred *uuid.UUID
		if in.Kind == EventRecovery {
			var p uuid.UUID
			err := tx.QueryRow(ctx, `
				SELECT id FROM uptime.notification_outbox
				WHERE incident_id=$1 AND channel_id=$2 AND event_kind='DOWN'`,
				in.IncidentID, cv.id).Scan(&p)
			switch {
			case err == pgx.ErrNoRows:
				// The incident's channel set is frozen at DOWN
				// (spec-06): a channel whose DOWN intent was never
				// created — bound or verified mid-incident — must
				// never receive a standalone "recovered".
				continue
			case err != nil:
				return nil, err
			default:
				pred = &p
			}
		}

		var id uuid.UUID
		err := tx.QueryRow(ctx, `
			INSERT INTO uptime.notification_outbox
			  (id,user_id,monitor_id,incident_id,channel_id,event_kind,
			   event_key,predecessor_id,channel_version,safe_payload,state)
			VALUES (gen_random_uuid(),$1,$2,$3,$4,$5,$6,$7,$8,$9,'PENDING')
			ON CONFLICT (event_key) DO NOTHING
			RETURNING id`,
			in.UserID, in.MonitorID, in.IncidentID, cv.id, string(in.Kind),
			key, pred, cv.v, payload).Scan(&id)
		if err == pgx.ErrNoRows {
			continue // already durable - idempotent replay
		}
		if err != nil {
			return nil, fmt.Errorf("outbox insert: %w", err)
		}
		out = append(out, DeliveryIntent{
			ID: id, ChannelID: cv.id, Kind: in.Kind,
			PredecessorID: pred, ChannelVersion: cv.v,
		})
	}
	return out, nil
}
