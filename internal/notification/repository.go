package notification

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

const channelCols = `id,user_id,label,kind,status,destination_ciphertext,` +
	`destination_mask,encryption_key_version,verified_at,verification_receipt,` +
	`enabled,version,deleted_at,created_at,updated_at`

// Repository owns channel persistence on a caller-provided pool.
type Repository struct {
	pool    *pgxpool.Pool
	timeout time.Duration
}

func NewRepository(pool *pgxpool.Pool, queryTimeout time.Duration) *Repository {
	return &Repository{pool: pool, timeout: queryTimeout}
}

func (r *Repository) withTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	if r.timeout <= 0 {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, r.timeout)
}

func mapErr(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrChannelNotFound
	}
	var pge *pgconn.PgError
	if errors.As(err, &pge) {
		return fmt.Errorf("%w: %s", ErrUnavailable, pge.Code)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("%w: deadline", ErrUnavailable)
	}
	return err
}

type actorRow struct {
	Status string
}

// withActorLock takes the owner user row FOR UPDATE — first lock in
// the users → quota_budgets → resource order — and applies the active
// predicate so a raced disable still fails the mutation.
func (r *Repository) withActorLock(ctx context.Context, ownerID uuid.UUID,
	fn func(tx pgx.Tx) error) error {
	ctx, cancel := r.withTimeout(ctx)
	defer cancel()
	// READ COMMITTED is pinned: fn bodies take quota_budgets FOR UPDATE
	// and then count rows committed while the lock was held — under a
	// server REPEATABLE READ default the counts would read a stale
	// pre-lock snapshot and oversubscribe.
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return mapErr(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var a actorRow
	if err := tx.QueryRow(ctx,
		`SELECT status FROM uptime.users WHERE id=$1 FOR UPDATE`,
		ownerID).Scan(&a.Status); err != nil {
		return mapErr(err)
	}
	if a.Status != "ACTIVE" {
		return ErrActorInactive
	}
	if err := fn(tx); err != nil {
		return err
	}
	return mapErr(tx.Commit(ctx))
}

func scanChannel(row pgx.Row) (Channel, error) {
	var c Channel
	err := row.Scan(&c.ID, &c.UserID, &c.Label, &c.Kind, &c.Status,
		&c.destinationCiphertext, &c.DestinationMask, &c.EncryptionKeyVersion,
		&c.VerifiedAt, &c.VerificationReceipt, &c.Enabled, &c.Version,
		&c.DeletedAt, &c.CreatedAt, &c.UpdatedAt)
	return c, err
}

// CreateChannelTx inserts a PENDING_VERIFICATION channel inside the
// caller's actor-locked transaction: quota_budgets FOR UPDATE →
// pending cap (every PENDING row incl. tombstoned pending) →
// retained cap (every row incl. deleted) → INSERT. The row is born
// enabled=false with no destination — verification is operator-only.
func (r *Repository) CreateChannelTx(ctx context.Context, tx pgx.Tx,
	ownerID uuid.UUID, label string, caps Caps) (Channel, error) {
	var budget int
	if err := tx.QueryRow(ctx,
		`SELECT global_monitor_limit FROM uptime.quota_budgets
		 WHERE id=1 FOR UPDATE`).Scan(&budget); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Channel{}, ErrBudgetMissing
		}
		return Channel{}, mapErr(err)
	}
	var pendingOwner, pendingGlobal, retainedOwner, retainedGlobal int
	if err := tx.QueryRow(ctx,
		`SELECT
		   (SELECT count(*) FROM uptime.notification_channels
		     WHERE user_id=$1 AND status='PENDING_VERIFICATION'),
		   (SELECT count(*) FROM uptime.notification_channels
		     WHERE status='PENDING_VERIFICATION'),
		   (SELECT count(*) FROM uptime.notification_channels
		     WHERE user_id=$1),
		   (SELECT count(*) FROM uptime.notification_channels)`,
		ownerID).Scan(&pendingOwner, &pendingGlobal, &retainedOwner, &retainedGlobal); err != nil {
		return Channel{}, mapErr(err)
	}
	switch {
	case pendingOwner >= caps.PendingOwner || pendingGlobal >= caps.PendingGlobal:
		return Channel{}, ErrPendingQuota
	case retainedOwner >= caps.RetainedOwner || retainedGlobal >= caps.RetainedGlobal:
		return Channel{}, ErrRetainedQuota
	}
	c, err := scanChannel(tx.QueryRow(ctx,
		`INSERT INTO uptime.notification_channels (id,user_id,label)
		 VALUES ($1,$2,$3) RETURNING `+channelCols,
		uuid.New(), ownerID, label))
	if err != nil {
		return Channel{}, mapErr(err)
	}
	return c, nil
}

// GetChannel returns the owner's live channel or ErrChannelNotFound.
func (r *Repository) GetChannel(ctx context.Context, ownerID, id uuid.UUID) (Channel, error) {
	ctx, cancel := r.withTimeout(ctx)
	defer cancel()
	c, err := scanChannel(r.pool.QueryRow(ctx,
		`SELECT `+channelCols+` FROM uptime.notification_channels
		 WHERE id=$1 AND user_id=$2 AND deleted_at IS NULL`, id, ownerID))
	if err != nil {
		return Channel{}, mapErr(err)
	}
	return c, nil
}

// ListChannels returns the owner's live channels oldest-first.
func (r *Repository) ListChannels(ctx context.Context, ownerID uuid.UUID, limit int) ([]Channel, error) {
	ctx, cancel := r.withTimeout(ctx)
	defer cancel()
	rows, err := r.pool.Query(ctx,
		`SELECT `+channelCols+` FROM uptime.notification_channels
		 WHERE user_id=$1 AND deleted_at IS NULL
		 ORDER BY created_at, id LIMIT $2`, ownerID, limit)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	out := []Channel{}
	for rows.Next() {
		c, err := scanChannel(rows)
		if err != nil {
			return nil, mapErr(err)
		}
		out = append(out, c)
	}
	return out, mapErr(rows.Err())
}

// mutateChannelTx is the version fence shared by disable/delete:
// channel FOR UPDATE (owner-scoped) → version compare → fn applies.
func (r *Repository) mutateChannelTx(ctx context.Context, tx pgx.Tx, ownerID, id uuid.UUID,
	expectedVersion int64, fn func(tx pgx.Tx, c Channel) error) error {
	c, err := scanChannel(tx.QueryRow(ctx,
		`SELECT `+channelCols+` FROM uptime.notification_channels
		 WHERE id=$1 AND user_id=$2 FOR UPDATE`, id, ownerID))
	if err != nil {
		return mapErr(err)
	}
	if c.DeletedAt != nil {
		return ErrChannelNotFound
	}
	if c.Version != expectedVersion {
		return ErrVersionConflict
	}
	return fn(tx, c)
}

// DisableChannelTx flips the channel to DISABLED+enabled=false under
// the version fence. Historical context (receipt, mask, ciphertext)
// stays — disable is a lifecycle state, not an erasure.
func (r *Repository) DisableChannelTx(ctx context.Context, tx pgx.Tx,
	ownerID, id uuid.UUID, expectedVersion int64) (Channel, error) {
	var out Channel
	err := r.mutateChannelTx(ctx, tx, ownerID, id, expectedVersion,
		func(tx pgx.Tx, c Channel) error {
			// Idempotent: already disabled is a no-op success.
			if c.Status == StatusDisabled && !c.Enabled {
				out = c
				return nil
			}
			u, err := scanChannel(tx.QueryRow(ctx,
				`UPDATE uptime.notification_channels SET
				   status='DISABLED', enabled=false,
				   version=version+1, updated_at=now()
				 WHERE id=$1 AND user_id=$2 RETURNING `+channelCols, id, ownerID))
			if err != nil {
				return mapErr(err)
			}
			out = u
			return nil
		})
	return out, err
}

// SoftDeleteChannelTx tombstones the channel under the version fence.
// The row stays retained for audit/bind history; every subsequent
// read collapses to not-found. Existing monitor_channels rows keep
// pointing at the tombstone — delivery must filter by status+enabled.
func (r *Repository) SoftDeleteChannelTx(ctx context.Context, tx pgx.Tx,
	ownerID, id uuid.UUID, expectedVersion int64) error {
	return r.mutateChannelTx(ctx, tx, ownerID, id, expectedVersion,
		func(tx pgx.Tx, c Channel) error {
			_, err := tx.Exec(ctx,
				`UPDATE uptime.notification_channels SET
				   deleted_at=now(), enabled=false,
				   version=version+1, updated_at=now()
				 WHERE id=$1 AND user_id=$2`, id, ownerID)
			return mapErr(err)
		})
}

// VerifyChannel transitions PENDING → VERIFIED with the operator's
// encrypted destination + receipt, and enables the channel. It is the
// operator CLI path only — no HTTP route reaches it. Self-contained:
// takes the owner lock itself. Status guard makes re-verification
// safe (no silent re-seal over a live VERIFIED row).
func (r *Repository) VerifyChannel(ctx context.Context,
	ownerID, id uuid.UUID, ciphertext []byte, mask string,
	keyVersion int, receipt string) (Channel, error) {
	var out Channel
	err := r.withActorLock(ctx, ownerID, func(tx pgx.Tx) error {
		c, err := scanChannel(tx.QueryRow(ctx,
			`SELECT `+channelCols+` FROM uptime.notification_channels
			 WHERE id=$1 AND user_id=$2 FOR UPDATE`, id, ownerID))
		if err != nil {
			return mapErr(err)
		}
		if c.DeletedAt != nil {
			return ErrChannelNotFound
		}
		if c.Status != StatusPending {
			return fmt.Errorf("channel is %s, not pending verification", c.Status)
		}
		u, err := scanChannel(tx.QueryRow(ctx,
			`UPDATE uptime.notification_channels SET
			   status='VERIFIED', destination_ciphertext=$3,
			   destination_mask=$4, encryption_key_version=$5,
			   verified_at=now(), verification_receipt=$6, enabled=true,
			   version=version+1, updated_at=now()
			 WHERE id=$1 AND user_id=$2 RETURNING `+channelCols,
			id, ownerID, ciphertext, mask, keyVersion, receipt))
		if err != nil {
			return mapErr(err)
		}
		out = u
		return nil
	})
	return out, err
}

// EligibleChannelIDs returns the subset of ids that are owned,
// VERIFIED, enabled, and not deleted — inside the caller's binding
// transaction so the set can't shift between validate and replace.
func EligibleChannelIDs(ctx context.Context, tx pgx.Tx,
	ownerID uuid.UUID, ids []uuid.UUID) (map[uuid.UUID]bool, error) {
	found := map[uuid.UUID]bool{}
	if len(ids) == 0 {
		return found, nil
	}
	rows, err := tx.Query(ctx,
		`SELECT id FROM uptime.notification_channels
		 WHERE user_id=$1 AND id=ANY($2)
		   AND status='VERIFIED' AND enabled AND deleted_at IS NULL`,
		ownerID, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		found[id] = true
	}
	return found, rows.Err()
}
