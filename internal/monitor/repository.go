package monitor

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

// Sentinel errors. Handlers map these to envelope codes; repository
// consumers must never discriminate by message text.
var (
	// ErrMonitorNotFound is the single indistinguishable result for
	// missing, foreign-owned, and soft-deleted monitors — the API
	// must not let callers tell them apart (IDOR parity).
	ErrMonitorNotFound    = errors.New("monitor not found")
	ErrGenerationConflict = errors.New("stale monitor generation")
	// ErrQuotaOwner/ErrQuotaGlobal are the live-monitor cap
	// (QUOTA_EXCEEDED): counts every nondeleted row incl. paused.
	ErrQuotaOwner  = errors.New("owner monitor limit reached")
	ErrQuotaGlobal = errors.New("platform monitor admission limit")
	// ErrQuotaRetained is the retained cap
	// (ALLOCATION_LIMIT_REACHED): counts every row incl. tombstones.
	ErrQuotaRetained = errors.New("monitor allocation limit reached")
	ErrBudgetMissing = errors.New("quota budget not initialized")
	ErrActorInactive = errors.New("owner is not active")
	ErrUnavailable   = errors.New("monitor store unavailable")
)

// Health values mirror the CHECK constraint — no other value persists.
const (
	HealthUnknown = "UNKNOWN"
	HealthUp      = "UP"
	HealthDown    = "DOWN"
)

// Caps carries the config-derived allocation ceilings checked inside
// the create transaction (F03). They are plain values, not DB
// authority: only users.monitor_limit and quota_budgets rows are
// runtime-adjustable. Callers pass them from Config.Alloc.
type Caps struct {
	RetainedOwner  int
	RetainedGlobal int
}

// Monitor mirrors one uptime.monitors row. Sequence/generation fences
// and engine fields are read-only here — the API may never set them.
type Monitor struct {
	ID                 uuid.UUID
	UserID             uuid.UUID
	Name               string
	TargetURL          string
	Method             string
	IntervalSeconds    int
	TimeoutSeconds     int
	ExpectedStatus     *int
	IsPaused           bool
	DeletedAt          *time.Time
	Health             string
	FailureStreak      int
	SuccessStreak      int
	Generation         int64
	LastReservedSeq    int64
	LastAppliedSeq     int64
	NextCheckAt        time.Time
	LastCheckedAt      *time.Time
	LastResponseTimeMs *int64
	LastErrorType      *string
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

// WriteFields is the full mutable-field set a mutation applies. The
// service merges patches into concrete values before calling — the
// repository never interprets absent-vs-null semantics.
type WriteFields struct {
	Name            string
	TargetURL       string
	IntervalSeconds int
	TimeoutSeconds  int
	ExpectedStatus  *int
}

// Cursor is the opaque keyset position for owner-scoped listing.
// Rows page newest-first on (created_at, id) DESC, matching the
// monitors_owner_page index scanned backward.
type Cursor struct {
	CreatedAt time.Time
	ID        uuid.UUID
	Valid     bool
}

const monitorCols = `id,user_id,name,target_url,method,interval_seconds,` +
	`timeout_seconds,expected_status,is_paused,deleted_at,health,` +
	`failure_streak,success_streak,generation,last_reserved_sequence,` +
	`last_applied_sequence,next_check_at,last_checked_at,` +
	`last_response_time_ms,last_error_type,created_at,updated_at`

// Repository owns monitor persistence on a caller-provided pool. The
// pool is never closed here — the composition root owns its lifecycle.
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
		return ErrMonitorNotFound
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

// EnsureQuotaBudget seeds the singleton with the configured global
// live cap. ON CONFLICT DO NOTHING keeps an operator-adjusted row
// authoritative — config only supplies the first seed, exactly like
// users.monitor_limit. Creation fails closed while the row is absent.
func (r *Repository) EnsureQuotaBudget(ctx context.Context, globalLimit int) error {
	ctx, cancel := r.withTimeout(ctx)
	defer cancel()
	_, err := r.pool.Exec(ctx,
		`INSERT INTO uptime.quota_budgets (id,global_monitor_limit) VALUES (1,$1)
		 ON CONFLICT (id) DO NOTHING`, globalLimit)
	return mapErr(err)
}

// actorRow is the locked users-row projection every mutation needs:
// status for the actor recheck, monitor_limit for the owner quota.
type actorRow struct {
	Status       string
	MonitorLimit int
}

// withActorLock begins a transaction holding the owner user row
// FOR UPDATE — the mandatory first lock in users → quota_budgets →
// monitors order — and re-reads the actor state under that lock so a
// disable raced ahead of the request principal still fails the
// mutation. fn receives the tx plus the locked row.
func (r *Repository) withActorLock(ctx context.Context, ownerID uuid.UUID,
	fn func(tx pgx.Tx, a actorRow) error) error {
	ctx, cancel := r.withTimeout(ctx)
	defer cancel()
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return mapErr(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var a actorRow
	if err := tx.QueryRow(ctx,
		`SELECT status,monitor_limit FROM uptime.users WHERE id=$1 FOR UPDATE`,
		ownerID).Scan(&a.Status, &a.MonitorLimit); err != nil {
		return mapErr(err)
	}
	if a.Status != "ACTIVE" {
		return ErrActorInactive
	}
	if err := fn(tx, a); err != nil {
		return err
	}
	return mapErr(tx.Commit(ctx))
}

func scanMonitor(row pgx.Row) (Monitor, error) {
	var m Monitor
	err := row.Scan(&m.ID, &m.UserID, &m.Name, &m.TargetURL, &m.Method,
		&m.IntervalSeconds, &m.TimeoutSeconds, &m.ExpectedStatus,
		&m.IsPaused, &m.DeletedAt, &m.Health, &m.FailureStreak,
		&m.SuccessStreak, &m.Generation, &m.LastReservedSeq,
		&m.LastAppliedSeq, &m.NextCheckAt, &m.LastCheckedAt,
		&m.LastResponseTimeMs, &m.LastErrorType,
		&m.CreatedAt, &m.UpdatedAt)
	return m, err
}

// CreateMonitor inserts under the full quota fence:
//
//	users(owner) FOR UPDATE → quota_budgets FOR UPDATE →
//	count live (deleted_at IS NULL, paused included) vs
//	owner/global live caps AND retained (all rows incl. tombstones)
//	vs caps → INSERT.
//
// Counts happen inside the locked transaction, so two concurrent
// creates racing for the final slot serialize — exactly one commits.
// next_check_at = DB now() taken after the locks: creation marks
// eligibility only; the engine still admits via durable budget (F02).
func (r *Repository) CreateMonitor(ctx context.Context, ownerID uuid.UUID,
	in WriteFields, caps Caps) (Monitor, error) {
	var out Monitor
	err := r.withActorLock(ctx, ownerID, func(tx pgx.Tx, a actorRow) error {
		var globalLive int
		if err := tx.QueryRow(ctx,
			`SELECT global_monitor_limit FROM uptime.quota_budgets
			 WHERE id=1 FOR UPDATE`).Scan(&globalLive); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrBudgetMissing
			}
			return mapErr(err)
		}
		var ownerLive, globalLiveN, ownerRetained, globalRetained int
		if err := tx.QueryRow(ctx,
			`SELECT
			   (SELECT count(*) FROM uptime.monitors
			     WHERE user_id=$1 AND deleted_at IS NULL),
			   (SELECT count(*) FROM uptime.monitors
			     WHERE deleted_at IS NULL),
			   (SELECT count(*) FROM uptime.monitors
			     WHERE user_id=$1),
			   (SELECT count(*) FROM uptime.monitors)`,
			ownerID).Scan(&ownerLive, &globalLiveN, &ownerRetained, &globalRetained); err != nil {
			return mapErr(err)
		}
		switch {
		case ownerRetained >= caps.RetainedOwner ||
			globalRetained >= caps.RetainedGlobal:
			return ErrQuotaRetained
		case ownerLive >= a.MonitorLimit:
			return ErrQuotaOwner
		case globalLiveN >= globalLive:
			return ErrQuotaGlobal
		}
		m, err := scanMonitor(tx.QueryRow(ctx,
			`INSERT INTO uptime.monitors
			   (id,user_id,name,target_url,method,interval_seconds,
			    timeout_seconds,expected_status,next_check_at)
			 VALUES ($1,$2,$3,$4,'GET',$5,$6,$7,now())
			 RETURNING `+monitorCols,
			uuid.New(), ownerID, in.Name, in.TargetURL,
			in.IntervalSeconds, in.TimeoutSeconds, in.ExpectedStatus))
		if err != nil {
			return mapErr(err)
		}
		out = m
		return nil
	})
	return out, err
}

// GetMonitor returns the owner's live monitor or ErrMonitorNotFound
// — foreign-owned and soft-deleted rows collapse to the same answer.
func (r *Repository) GetMonitor(ctx context.Context, ownerID, id uuid.UUID) (Monitor, error) {
	ctx, cancel := r.withTimeout(ctx)
	defer cancel()
	m, err := scanMonitor(r.pool.QueryRow(ctx,
		`SELECT `+monitorCols+` FROM uptime.monitors
		 WHERE id=$1 AND user_id=$2 AND deleted_at IS NULL`, id, ownerID))
	if err != nil {
		return Monitor{}, mapErr(err)
	}
	return m, nil
}

// ListMonitors pages the owner's live monitors newest-first. The
// cursor is exclusive: rows strictly older than (CreatedAt,ID) return.
func (r *Repository) ListMonitors(ctx context.Context, ownerID uuid.UUID,
	after Cursor, limit int) ([]Monitor, error) {
	ctx, cancel := r.withTimeout(ctx)
	defer cancel()
	var rows pgx.Rows
	var err error
	if after.Valid {
		rows, err = r.pool.Query(ctx,
			`SELECT `+monitorCols+` FROM uptime.monitors
			 WHERE user_id=$1 AND deleted_at IS NULL
			   AND (created_at,id) < ($3,$4)
			 ORDER BY created_at DESC, id DESC LIMIT $2`,
			ownerID, limit, after.CreatedAt, after.ID)
	} else {
		rows, err = r.pool.Query(ctx,
			`SELECT `+monitorCols+` FROM uptime.monitors
			 WHERE user_id=$1 AND deleted_at IS NULL
			 ORDER BY created_at DESC, id DESC LIMIT $2`,
			ownerID, limit)
	}
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	out := []Monitor{}
	for rows.Next() {
		m, err := scanMonitor(rows)
		if err != nil {
			return nil, mapErr(err)
		}
		out = append(out, m)
	}
	return out, mapErr(rows.Err())
}

// lockedMonitor fetches the monitor FOR UPDATE inside a caller's
// actor-locked transaction. Soft-deleted and foreign rows read as
// not-found — the fence gives no existence oracle.
func lockedMonitor(tx pgx.Tx, ctx context.Context, ownerID, id uuid.UUID) (Monitor, error) {
	m, err := scanMonitor(tx.QueryRow(ctx,
		`SELECT `+monitorCols+` FROM uptime.monitors
		 WHERE id=$1 AND user_id=$2 FOR UPDATE`, id, ownerID))
	if err != nil {
		return Monitor{}, mapErr(err)
	}
	if m.DeletedAt != nil {
		return Monitor{}, ErrMonitorNotFound
	}
	return m, nil
}

// mutateMonitor is the shared generation fence for every lifecycle
// mutation: users FOR UPDATE (via withActorLock) → monitor FOR UPDATE
// → generation compare → fn applies the UPDATE → generation+1 lands
// exactly once in the same statement. A stale expected generation
// returns ErrGenerationConflict with no partial effect.
func (r *Repository) mutateMonitor(ctx context.Context, ownerID, id uuid.UUID,
	expectedGen int64,
	fn func(tx pgx.Tx, m Monitor) (Monitor, error)) (Monitor, error) {
	var out Monitor
	err := r.withActorLock(ctx, ownerID, func(tx pgx.Tx, _ actorRow) error {
		m, err := lockedMonitor(tx, ctx, ownerID, id)
		if err != nil {
			return err
		}
		if m.Generation != expectedGen {
			return ErrGenerationConflict
		}
		m2, err := fn(tx, m)
		if err != nil {
			return err
		}
		out = m2
		return nil
	})
	return out, err
}

// UpdateMonitor applies a concrete write-set under the generation
// fence. The service merged+validated the fields; callers must never
// mass-assign user_id, health, streaks, sequences, or next_check_at —
// those columns are absent from the SET clause by construction.
func (r *Repository) UpdateMonitor(ctx context.Context, ownerID, id uuid.UUID,
	expectedGen int64, in WriteFields) (Monitor, error) {
	return r.mutateMonitor(ctx, ownerID, id, expectedGen,
		func(tx pgx.Tx, m Monitor) (Monitor, error) {
			return scanMonitor(tx.QueryRow(ctx,
				`UPDATE uptime.monitors SET
				   name=$3, target_url=$4, interval_seconds=$5,
				   timeout_seconds=$6, expected_status=$7,
				   generation=generation+1, updated_at=now()
				 WHERE id=$1 AND user_id=$2
				 RETURNING `+monitorCols,
				id, ownerID, in.Name, in.TargetURL, in.IntervalSeconds,
				in.TimeoutSeconds, in.ExpectedStatus))
		})
}

// SetMonitorPaused flips the lifecycle flag under the fence. Pause
// never fabricates DOWN and resume never fabricates UP or a sample —
// health, streaks, and sequence fences pass through untouched. Resume
// sets next_check_at=now(): eligibility only, the durable admission
// budget still gates the actual check (no check-now privilege).
func (r *Repository) SetMonitorPaused(ctx context.Context, ownerID, id uuid.UUID,
	expectedGen int64, paused bool) (Monitor, error) {
	return r.mutateMonitor(ctx, ownerID, id, expectedGen,
		func(tx pgx.Tx, m Monitor) (Monitor, error) {
			var q string
			if paused {
				q = `UPDATE uptime.monitors SET is_paused=true,
				     generation=generation+1, updated_at=now()
				     WHERE id=$1 AND user_id=$2 RETURNING ` + monitorCols
			} else {
				q = `UPDATE uptime.monitors SET is_paused=false,
				     next_check_at=now(),
				     generation=generation+1, updated_at=now()
				     WHERE id=$1 AND user_id=$2 RETURNING ` + monitorCols
			}
			return scanMonitor(tx.QueryRow(ctx, q, id, ownerID))
		})
}

// SoftDeleteMonitor tombstones under the fence. The row stays
// retained (counted toward retained caps, audit history preserved);
// every subsequent read/mutation collapses to ErrMonitorNotFound.
func (r *Repository) SoftDeleteMonitor(ctx context.Context, ownerID, id uuid.UUID,
	expectedGen int64) error {
	_, err := r.mutateMonitor(ctx, ownerID, id, expectedGen,
		func(tx pgx.Tx, m Monitor) (Monitor, error) {
			_, err := tx.Exec(ctx,
				`UPDATE uptime.monitors SET deleted_at=now(),
				   generation=generation+1, updated_at=now()
				 WHERE id=$1 AND user_id=$2`, id, ownerID)
			if err != nil {
				return Monitor{}, mapErr(err)
			}
			return m, nil
		})
	return err
}
