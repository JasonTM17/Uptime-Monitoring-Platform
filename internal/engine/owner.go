// Package engine is the single-writer monitoring engine: one process
// owns all schedule/reservation writes at a time, fenced by a
// session-scoped advisory lock plus a monotonically increasing epoch.
// Nothing in this package may use a pooled connection for engine
// writes --- the lock lives on the session, so a pooled conn would
// silently fence nothing.
package engine

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ownerLockKey is the singleton advisory-lock identity. It MUST be a
// constant --- two instances holding locks under different keys would
// both believe they own the engine.
const ownerLockKey int64 = 0x757074696d656e67 // "uptimeng"

var (
	ErrOwnerLost = errors.New("engine: owner connection lost")
	ErrNotOwner  = errors.New("engine: not the current owner")
	ErrAcquire   = errors.New("engine: owner acquisition failed")
)

// Owner is the held advisory lock + epoch on a dedicated connection.
// The conn is sacred: only the Writer goroutine may use it.
type Owner struct {
	mu         sync.Mutex // serializes every use of conn
	conn       *pgx.Conn
	instance   uuid.UUID
	epoch      int64
	acquiredAt time.Time
}

// Instance is this process's unique owner identity.
func (o *Owner) Instance() uuid.UUID { return o.instance }

// Epoch is the fencing value stamped on every engine write.
func (o *Owner) Epoch() int64 { return o.epoch }

// AcquiredAt is when the advisory lock was taken.
func (o *Owner) AcquiredAt() time.Time { return o.acquiredAt }

// BumpEpoch increments the singleton epoch and stamps owner identity
// inside one transaction on the lock-holding connection. Exported so
// takeover reconciliation can re-stamp in the same discipline.
func BumpEpoch(ctx context.Context, conn *pgx.Conn, instance uuid.UUID) (int64, time.Time, error) {
	var epoch int64
	var acquiredAt time.Time
	err := conn.QueryRow(ctx, `
		UPDATE uptime.engine_control
		SET epoch=epoch+1, owner_instance=$1, acquired_at=now(), heartbeat_at=now()
		WHERE id=1
		RETURNING epoch, acquired_at`,
		instance).Scan(&epoch, &acquiredAt)
	if err != nil {
		return 0, time.Time{}, fmt.Errorf("%w: bump epoch: %v", ErrAcquire, err)
	}
	return epoch, acquiredAt, nil
}

// AcquireOwner takes the session-scoped advisory lock on the given
// DEDICATED connection (callers must pass a direct pgx.Conn, never a
// pooled borrow), then bumps the epoch inside one transaction. It
// blocks until the lock is held or ctx expires --- lock contention
// means another owner is live and this process must not start.
func AcquireOwner(ctx context.Context, conn *pgx.Conn, instance uuid.UUID) (*Owner, error) {
	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", ownerLockKey); err != nil {
		return nil, fmt.Errorf("%w: advisory lock: %v", ErrAcquire, err)
	}
	epoch, acquiredAt, err := BumpEpoch(ctx, conn, instance)
	if err != nil {
		// Best-effort release --- session close also frees it.
		_, _ = conn.Exec(context.Background(),
			"SELECT pg_advisory_unlock($1)", ownerLockKey)
		return nil, err
	}
	return &Owner{conn: conn, instance: instance, epoch: epoch, acquiredAt: acquiredAt}, nil
}

// Release drops the advisory lock and closes the dedicated
// connection. After Release the Owner is dead --- callers must not
// reuse it; re-acquisition always produces a new epoch.
func (o *Owner) Release(ctx context.Context) error {
	if o.conn == nil {
		return nil
	}
	_, _ = o.conn.Exec(ctx, "SELECT pg_advisory_unlock($1)", ownerLockKey)
	err := o.conn.Close(ctx)
	o.conn = nil
	return err
}
