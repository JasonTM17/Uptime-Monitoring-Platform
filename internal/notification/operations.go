package notification

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Operations (C47): administrative dead-letter controls. These are
// INTERNAL service functions — no public route binds them yet;
// Phase 07 adds the authorized/audited caller contract. Every
// mutation preserves event identity: a retry resets the attempt
// window on the SAME row, never a new event; suppression cascades
// the causal stream so a RECOVERY can never stand alone.

var (
	ErrNotDead           = errors.New("delivery is not DEAD")
	ErrNotStreamHead     = errors.New("delivery is not the stream head")
	ErrDeliveryConflict  = errors.New("delivery version changed")
	ErrNotOwned          = errors.New("monitor/channel not owned or not bound")
	ErrChannelIneligible = errors.New("channel is not an eligible verified recipient")
	ErrDuplicateTest     = errors.New("a TEST intent is already outstanding")
	ErrRateLimited       = errors.New("test notification rate limit")
)

// Operations owns administrative delivery mutations on the pool.
type Operations struct {
	pool    *pgxpool.Pool
	timeout time.Duration
}

func NewOperations(pool *pgxpool.Pool, timeout time.Duration) *Operations {
	return &Operations{pool: pool, timeout: timeout}
}

func (o *Operations) ctx(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, o.timeout)
}

// RetryDeadHead resets the attempt window on ONE DEAD stream head:
// same row, same event_key, same channel, same payload — only the
// retry budget restarts. Eligibility: state DEAD, caller's expected
// version matches (optimistic conflict), and no non-terminal
// predecessor — a DEAD row behind another dead row is not the head;
// resolve the head instead. Terminal SENT/SUPPRESSED rows are never
// retryable — their evidence stands.
func (o *Operations) RetryDeadHead(ctx context.Context, id uuid.UUID,
	expectedVersion int64) error {
	ctx, cancel := o.ctx(ctx)
	defer cancel()
	tx, err := o.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	var state string
	var ver int64
	var pred *uuid.UUID
	err = tx.QueryRow(ctx, `
		SELECT state,version,predecessor_id
		FROM uptime.notification_outbox WHERE id=$1 FOR UPDATE`, id).
		Scan(&state, &ver, &pred)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotDead
	}
	if err != nil {
		return err
	}
	if ver != expectedVersion {
		return ErrDeliveryConflict
	}
	if state != "DEAD" {
		return ErrNotDead
	}
	if pred != nil {
		var predState string
		if err := tx.QueryRow(ctx,
			`SELECT state FROM uptime.notification_outbox WHERE id=$1`,
			*pred).Scan(&predState); err != nil {
			return err
		}
		if predState != "SENT" && predState != "SUPPRESSED" {
			return ErrNotStreamHead
		}
	}
	tag, err := tx.Exec(ctx, `
		UPDATE uptime.notification_outbox
		SET state='PENDING', attempts=0, next_attempt_at=clock_timestamp(),
		    lease_token=NULL, lease_expires_at=NULL, last_error_code=NULL,
		    version=version+1
		WHERE id=$1 AND state='DEAD'`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrNotDead
	}
	return tx.Commit(ctx)
}

// SuppressStream cascades the authorized skip across a causal
// stream: the named head plus every descendant whose chain reaches
// it — a RECOVERY is never suppressed alone behind a live DOWN, and
// never left standing when its DOWN is suppressed. Only unsent rows
// (PENDING/DEAD) move; a LEASED send in flight cannot be recalled.
// Returns the number of rows suppressed.
func (o *Operations) SuppressStream(ctx context.Context,
	headID uuid.UUID) (int, error) {
	ctx, cancel := o.ctx(ctx)
	defer cancel()
	tag, err := o.pool.Exec(ctx, `
		WITH RECURSIVE chain AS (
		  SELECT id FROM uptime.notification_outbox WHERE id=$1
		  UNION ALL
		  SELECT o.id FROM uptime.notification_outbox o
		  JOIN chain c ON o.predecessor_id = c.id
		)
		UPDATE uptime.notification_outbox
		SET state='SUPPRESSED', lease_token=NULL, lease_expires_at=NULL,
		    last_error_code='OPERATOR_SUPPRESSED', version=version+1
		WHERE id IN (SELECT id FROM chain)
		  AND state IN ('PENDING','DEAD')`, headID)
	if err != nil {
		return 0, fmt.Errorf("suppress stream: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

// TestRate bounds TEST intents: per-channel cooldown plus a global
// outstanding cap — a test button must not become a send amplifier.
type TestRate struct {
	PerChannelCooldown time.Duration // spec: 1/min per channel
	GlobalOutstanding  int           // spec: bounded global TEST set
}

var DefaultTestRate = TestRate{
	PerChannelCooldown: time.Minute,
	GlobalOutstanding:  50,
}

// QueueTestNotification persists ONE logical TEST intent after the
// full eligibility fence: monitor owned by caller, channel bound to
// that monitor, channel VERIFIED+enabled+live, per-channel cooldown
// and global outstanding cap respected, no outstanding TEST intent
// for the same monitor+channel. Persisted intent returns the row id;
// the dispatcher's normal claim path delivers it — nothing in this
// function touches the network.
func (o *Operations) QueueTestNotification(ctx context.Context,
	ownerID, monitorID, channelID uuid.UUID, rate TestRate) (uuid.UUID, error) {
	ctx, cancel := o.ctx(ctx)
	defer cancel()
	tx, err := o.pool.Begin(ctx)
	if err != nil {
		return uuid.Nil, err
	}
	defer tx.Rollback(ctx)

	// 1) ownership + binding under one read.
	var bound bool
	var monName string
	if err := tx.QueryRow(ctx, `
		SELECT m.name, EXISTS(
		  SELECT 1 FROM uptime.monitor_channels mc
		  WHERE mc.monitor_id=m.id AND mc.channel_id=$3)
		FROM uptime.monitors m
		WHERE m.id=$1 AND m.user_id=$2 AND m.deleted_at IS NULL`,
		monitorID, ownerID, channelID).Scan(&monName, &bound); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return uuid.Nil, ErrNotOwned
		}
		return uuid.Nil, err
	}
	if !bound {
		return uuid.Nil, ErrNotOwned
	}

	// 2) channel eligibility — same Deliverable contract the
	//    dispatcher enforces at send time.
	var status string
	var enabled bool
	var delAt *time.Time
	var ct []byte
	var ver int64
	if err := tx.QueryRow(ctx, `
		SELECT status,enabled,version,destination_ciphertext,deleted_at
		FROM uptime.notification_channels
		WHERE id=$1 AND user_id=$2`, channelID, ownerID).
		Scan(&status, &enabled, &ver, &ct, &delAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return uuid.Nil, ErrNotOwned
		}
		return uuid.Nil, err
	}
	ch := Channel{Status: status, Enabled: enabled, DeletedAt: delAt,
		destinationCiphertext: ct}
	if !ch.Deliverable() {
		return uuid.Nil, ErrChannelIneligible
	}

	// 3) rate: per-channel cooldown + global outstanding TEST cap.
	var recent int
	if err := tx.QueryRow(ctx, `
		SELECT count(*) FROM uptime.notification_outbox
		WHERE channel_id=$1 AND event_kind='TEST'
		  AND created_at > clock_timestamp() - make_interval(secs => $2)`,
		channelID, rate.PerChannelCooldown.Seconds()).
		Scan(&recent); err != nil {
		return uuid.Nil, err
	}
	if recent > 0 {
		return uuid.Nil, ErrRateLimited
	}
	var outstanding int
	if err := tx.QueryRow(ctx, `
		SELECT count(*) FROM uptime.notification_outbox
		WHERE event_kind='TEST' AND state IN ('PENDING','LEASED')`).
		Scan(&outstanding); err != nil {
		return uuid.Nil, err
	}
	if outstanding >= rate.GlobalOutstanding {
		return uuid.Nil, ErrRateLimited
	}

	// 4) the ONE logical intent — event_key dedups concurrent calls.
	payload := fmt.Sprintf(`{"monitor_name":%q,"transition":"TEST"}`,
		monName)
	var id uuid.UUID
	err = tx.QueryRow(ctx, `
		INSERT INTO uptime.notification_outbox
		  (id,user_id,monitor_id,incident_id,channel_id,event_kind,
		   event_key,predecessor_id,channel_version,safe_payload,state)
		VALUES (gen_random_uuid(),$1,$2,NULL,$3,'TEST',$4,NULL,$5,$6,'PENDING')
		ON CONFLICT (event_key) DO NOTHING
		RETURNING id`,
		ownerID, monitorID, channelID,
		"TEST:"+monitorID.String()+":"+channelID.String(), ver, payload).
		Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, ErrDuplicateTest
	}
	if err != nil {
		return uuid.Nil, fmt.Errorf("queue test: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return uuid.Nil, err
	}
	return id, nil
}

// DeliveryRow is the redacted owner-scoped projection — no payload,
// no destination, no secrets: identity, lifecycle state, counters.
type DeliveryRow struct {
	ID            uuid.UUID
	MonitorID     uuid.UUID
	ChannelID     uuid.UUID
	EventKind     string
	State         string
	Attempts      int
	LastErrorCode *string
	CreatedAt     time.Time
	SentAt        *time.Time
	NextAttemptAt time.Time
	Version       int64
}

// ListDeliveries returns the owner's delivery rows, newest first —
// the operator-facing dead-letter view. Owner scope is enforced in
// the WHERE; nothing cross-user can leak through the projection.
func (o *Operations) ListDeliveries(ctx context.Context, ownerID uuid.UUID,
	limit int) ([]DeliveryRow, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	ctx, cancel := o.ctx(ctx)
	defer cancel()
	rows, err := o.pool.Query(ctx, `
		SELECT id,monitor_id,channel_id,event_kind,state,attempts,
		       last_error_code,created_at,sent_at,next_attempt_at,version
		FROM uptime.notification_outbox
		WHERE user_id=$1
		ORDER BY created_at DESC, id
		LIMIT $2`, ownerID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DeliveryRow
	for rows.Next() {
		var r DeliveryRow
		if err := rows.Scan(&r.ID, &r.MonitorID, &r.ChannelID, &r.EventKind,
			&r.State, &r.Attempts, &r.LastErrorCode, &r.CreatedAt,
			&r.SentAt, &r.NextAttemptAt, &r.Version); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
