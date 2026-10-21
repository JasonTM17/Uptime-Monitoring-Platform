package engine

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// OwnerState is the immutable external view of engine ownership ---
// safe to read from any goroutine at any time.
type OwnerState struct {
	Instance   uuid.UUID
	Epoch      int64
	AcquiredAt time.Time
	Alive      bool
}

// Writer is the exclusive user of the owner connection: heartbeats,
// and (in later cards) every schedule/reservation write. If the conn
// dies, Alive flips false and stays false --- there is no reconnect;
// only a fresh AcquireOwner (new epoch) may resume ownership.
type Writer struct {
	owner   *Owner
	hbEvery time.Duration
	alive   atomic.Bool
	done    chan struct{}
	stopped sync.Once
}

func NewWriter(owner *Owner, hbEvery time.Duration) *Writer {
	w := &Writer{owner: owner, hbEvery: hbEvery, done: make(chan struct{})}
	w.alive.Store(true)
	return w
}

// State snapshots the immutable owner view.
func (w *Writer) State() OwnerState {
	o := w.owner
	return OwnerState{
		Instance: o.instance, Epoch: o.epoch,
		AcquiredAt: o.acquiredAt, Alive: w.alive.Load(),
	}
}

// Alive reports whether the owner connection is still believed good.
func (w *Writer) Alive() bool { return w.alive.Load() }

// Done closes when the writer stops.
func (w *Writer) Done() <-chan struct{} { return w.done }

// Run heartbeats on the owner connection until ctx ends or the conn
// dies. All engine writes in later cards flow through Run's goroutine
// via the same conn --- this is the single-writer discipline.
func (w *Writer) Run(ctx context.Context) {
	defer w.stopped.Do(func() { close(w.done) })
	t := time.NewTicker(w.hbEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-w.done:
			return
		case <-t.C:
			if err := w.Heartbeat(ctx); err != nil {
				w.alive.Store(false)
				return
			}
		}
	}
}

// Heartbeat refreshes heartbeat_at on the owner connection --- proof
// the session (and its advisory lock) is still alive. Any failure
// marks the writer dead permanently: a stale owner must not keep
// believing it writes under a fence it no longer holds.
func (w *Writer) Heartbeat(ctx context.Context) error {
	w.owner.mu.Lock()
	defer w.owner.mu.Unlock()
	if w.owner.conn == nil {
		w.alive.Store(false)
		return ErrOwnerLost
	}
	_, err := w.owner.conn.Exec(ctx,
		"UPDATE uptime.engine_control SET heartbeat_at=now() WHERE id=1")
	if err != nil {
		w.alive.Store(false)
		return ErrOwnerLost
	}
	return nil
}

// Exec runs fn with the owner connection --- the ONLY sanctioned way
// for engine code paths (reservations, results, reconciliation) to
// reach the database. Callers receive the lock-holding conn, never a
// pooled borrow.
func (w *Writer) Exec(fn func(ctx context.Context, conn *pgx.Conn) error) error {
	if !w.alive.Load() || w.owner.conn == nil {
		return ErrOwnerLost
	}
	return fn(context.Background(), w.owner.conn)
}

// Stop terminates the writer and releases the owner.
func (w *Writer) Stop(ctx context.Context) {
	w.stopped.Do(func() { close(w.done) })
	_ = w.owner.Release(ctx)
}
