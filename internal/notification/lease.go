package notification

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Outbox leasing (C45): claim → send → ACK in SEPARATE transactions.
// A lease is a finite right to attempt delivery — never a promise of
// exactly-once external effect. Lease expiry means the attempt's
// outcome is unknown; the row becomes claimable again and a retry
// may duplicate a provider message the lost ACK never recorded.
// Dedup discipline is the event_key's; the lease only bounds
// concurrent processing of the same row.

var (
	ErrClaimClosed  = errors.New("no causally-eligible due outbox rows")
	ErrLeaseLost    = errors.New("lease token no longer owns the row")
	ErrLeaseConfig  = errors.New("invalid lease configuration")
)

// LeaseConfig bounds every claim/reclaim pass. LeaseFor must exceed
// the bounded send+ACK margin so a live attempt can never be
// reclaimed mid-flight by an honest clock.
type LeaseConfig struct {
	Batch       int           // max rows per ClaimDue/ReclaimExpired
	LeaseFor    time.Duration // lease validity window
	MaxAttempts int           // attempts budget; exhausted → DEAD
}

func (c LeaseConfig) valid() error {
	if c.Batch <= 0 || c.LeaseFor <= 0 || c.MaxAttempts <= 0 {
		return ErrLeaseConfig
	}
	return nil
}

// Claim is leased work: the row identity plus the lease token that
// alone may ACK or reschedule it.
type Claim struct {
	ID             uuid.UUID
	MonitorID      uuid.UUID
	UserID         uuid.UUID
	ChannelID      uuid.UUID
	IncidentID     *uuid.UUID
	EventKind      string
	ChannelVersion int64
	LeaseToken     uuid.UUID
	LeaseExpires   time.Time
	Attempts       int
	SafePayload    []byte
}

// ClaimDue leases up to cfg.Batch causally-eligible due rows in ONE
// short transaction: SKIP LOCKED selection, per-row lease stamp,
// attempts increment, commit — all before the caller touches any
// network. Eligibility: PENDING, next_attempt_at due, and the causal
// predecessor (if any) already terminal-SENT or SUPPRESSED — a
// PENDING or DEAD predecessor blocks its RECOVERY forever until
// operations resolves the head.
func ClaimDue(ctx context.Context, conn *pgx.Conn,
	cfg LeaseConfig) ([]Claim, error) {
	if err := cfg.valid(); err != nil {
		return nil, err
	}
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	rows, err := tx.Query(ctx, `
		SELECT o.id,o.monitor_id,o.user_id,o.channel_id,o.incident_id,
		       o.event_kind,o.channel_version,o.attempts,o.safe_payload
		FROM uptime.notification_outbox o
		WHERE o.state='PENDING' AND o.next_attempt_at <= clock_timestamp()
		  AND (o.predecessor_id IS NULL OR EXISTS (
		    SELECT 1 FROM uptime.notification_outbox p
		    WHERE p.id=o.predecessor_id
		      AND p.state IN ('SENT','SUPPRESSED')))
		ORDER BY o.next_attempt_at, o.created_at, o.id
		LIMIT $1
		FOR UPDATE OF o SKIP LOCKED`, cfg.Batch)
	if err != nil {
		return nil, fmt.Errorf("claim select: %w", err)
	}
	var claims []Claim
	for rows.Next() {
		var c Claim
		if err := rows.Scan(&c.ID, &c.MonitorID, &c.UserID, &c.ChannelID,
			&c.IncidentID, &c.EventKind, &c.ChannelVersion, &c.Attempts,
			&c.SafePayload); err != nil {
			rows.Close()
			return nil, err
		}
		claims = append(claims, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(claims) == 0 {
		return nil, ErrClaimClosed
	}
	for i := range claims {
		token := uuid.New()
		expires := time.Now().Add(cfg.LeaseFor)
		if _, err := tx.Exec(ctx, `
			UPDATE uptime.notification_outbox
			SET state='LEASED', lease_token=$2, lease_expires_at=$3,
			    attempts=attempts+1, version=version+1
			WHERE id=$1 AND state='PENDING'`,
			claims[i].ID, token, expires); err != nil {
			return nil, fmt.Errorf("lease stamp: %w", err)
		}
		claims[i].LeaseToken = token
		claims[i].LeaseExpires = expires
		claims[i].Attempts++
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("claim commit: %w", err)
	}
	return claims, nil
}

// AckDelivery terminalizes a leased row SENT — strictly conditional
// on (id, token, LEASED): a stale token (lease expired, reclaimed,
// re-leased by another claimant) ACKs nothing and returns false, so
// a late success can never overwrite a newer lease's work.
func AckDelivery(ctx context.Context, conn *pgx.Conn,
	id, token uuid.UUID) (bool, error) {
	tag, err := conn.Exec(ctx, `
		UPDATE uptime.notification_outbox
		SET state='SENT', sent_at=clock_timestamp(), lease_token=NULL,
		    lease_expires_at=NULL, last_error_code=NULL,
		    version=version+1
		WHERE id=$1 AND lease_token=$2 AND state='LEASED'`,
		id, token)
	if err != nil {
		return false, fmt.Errorf("ack: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// Disposition names the terminal or deferred state a reschedule or
// reclaim produced.
type Disposition string

const (
	DispositionPending Disposition = "PENDING" // retryable, rescheduled
	DispositionDead    Disposition = "DEAD"    // budget exhausted
	DispositionStale   Disposition = "STALE"   // token lost, untouched
)

// RescheduleDelivery returns a retryable failed lease to PENDING at
// nextAt, or terminalizes it DEAD when the attempts budget is spent.
// Token-conditional like ACK — a stale token changes nothing.
func RescheduleDelivery(ctx context.Context, conn *pgx.Conn,
	id, token uuid.UUID, nextAt time.Time, errCode string,
	maxAttempts int) (Disposition, error) {
	var st string
	err := conn.QueryRow(ctx, `
		UPDATE uptime.notification_outbox
		SET state = CASE WHEN attempts >= $4 THEN 'DEAD' ELSE 'PENDING' END,
		    next_attempt_at = CASE WHEN attempts >= $4
		                           THEN next_attempt_at ELSE $3 END,
		    lease_token=NULL, lease_expires_at=NULL,
		    last_error_code=$5, version=version+1
		WHERE id=$1 AND lease_token=$2 AND state='LEASED'
		RETURNING state`,
		id, token, nextAt, maxAttempts, errCode).Scan(&st)
	if errors.Is(err, pgx.ErrNoRows) {
		return DispositionStale, nil
	}
	if err != nil {
		return "", fmt.Errorf("reschedule: %w", err)
	}
	return Disposition(st), nil
}

// ReclaimExpired sweeps up to cfg.Batch LEASED rows whose lease
// expired: under budget they return PENDING immediately-claimable;
// at budget they terminalize DEAD. An expired lease proves nothing
// about the provider — the row simply re-enters the retry stream.
func ReclaimExpired(ctx context.Context, conn *pgx.Conn,
	cfg LeaseConfig) (int, error) {
	if err := cfg.valid(); err != nil {
		return 0, err
	}
	tag, err := conn.Exec(ctx, `
		UPDATE uptime.notification_outbox
		SET state = CASE WHEN attempts >= $2 THEN 'DEAD' ELSE 'PENDING' END,
		    next_attempt_at = CASE WHEN attempts >= $2
		                           THEN next_attempt_at
		                           ELSE clock_timestamp() END,
		    lease_token=NULL, lease_expires_at=NULL,
		    version=version+1
		WHERE id IN (
		  SELECT id FROM uptime.notification_outbox
		  WHERE state='LEASED' AND lease_expires_at <= clock_timestamp()
		  ORDER BY lease_expires_at, id
		  LIMIT $1
		  FOR UPDATE SKIP LOCKED)`,
		cfg.Batch, cfg.MaxAttempts)
	if err != nil {
		return 0, fmt.Errorf("reclaim: %w", err)
	}
	return int(tag.RowsAffected()), nil
}
