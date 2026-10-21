package monitor

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/incident"
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
	// ErrChannelIneligible covers every bind rejection: foreign-owned,
	// missing, unverified, disabled, or deleted channel. The API never
	// says which — channel existence is not the caller's data.
	ErrChannelIneligible = errors.New("one or more channels not eligible")
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

// CreateMonitorTx is the quota-fenced insert body for a transaction
// whose caller ALREADY holds the owner user row FOR UPDATE — the
// composition root (auth.WithActorLock) supplies the tx so session
// recheck, quota lock, and insert commit or roll back atomically.
// monitorLimit comes from the locked user row.
//
// Lock order inside: quota_budgets FOR UPDATE → count → INSERT. Counts
// serialize under the budget lock, so racing creates for the final
// slot admit exactly one. next_check_at = DB now() taken after locks:
// creation marks eligibility only; durable admission still gates the
// actual check (F02).
func (r *Repository) CreateMonitorTx(ctx context.Context, tx pgx.Tx,
	ownerID uuid.UUID, monitorLimit int, in WriteFields, caps Caps) (Monitor, error) {
	var globalLive int
	if err := tx.QueryRow(ctx,
		`SELECT global_monitor_limit FROM uptime.quota_budgets
		 WHERE id=1 FOR UPDATE`).Scan(&globalLive); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Monitor{}, ErrBudgetMissing
		}
		return Monitor{}, mapErr(err)
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
		return Monitor{}, mapErr(err)
	}
	switch {
	case ownerRetained >= caps.RetainedOwner ||
		globalRetained >= caps.RetainedGlobal:
		return Monitor{}, ErrQuotaRetained
	case ownerLive >= monitorLimit:
		return Monitor{}, ErrQuotaOwner
	case globalLiveN >= globalLive:
		return Monitor{}, ErrQuotaGlobal
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
		return Monitor{}, mapErr(err)
	}
	return m, nil
}

// CreateMonitor is the self-contained variant for non-handler callers
// (tests, CLI): it takes the owner lock itself and applies only the
// user-status predicate — HTTP mutations should instead compose under
// auth.WithActorLock so the session row is fenced in the same commit.
func (r *Repository) CreateMonitor(ctx context.Context, ownerID uuid.UUID,
	in WriteFields, caps Caps) (Monitor, error) {
	var out Monitor
	err := r.withActorLock(ctx, ownerID, func(tx pgx.Tx, a actorRow) error {
		m, err := r.CreateMonitorTx(ctx, tx, ownerID, a.MonitorLimit, in, caps)
		if err != nil {
			return err
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

// ListMonitors pages the owner's live monitors newest-first under the
// bounded filter set. The cursor is exclusive: rows strictly older
// than (CreatedAt,ID) return, matching the monitors_owner_page index
// scanned backward. Callers pass limit+1 when they need has_more.
func (r *Repository) ListMonitors(ctx context.Context, ownerID uuid.UUID,
	after Cursor, filter ListFilter, limit int) ([]Monitor, error) {
	ctx, cancel := r.withTimeout(ctx)
	defer cancel()
	args := []any{ownerID, limit}
	where := `user_id=$1 AND deleted_at IS NULL`
	if filter.Paused != nil {
		args = append(args, *filter.Paused)
		where += fmt.Sprintf(` AND is_paused=$%d`, len(args))
	}
	if filter.Health != "" {
		args = append(args, filter.Health)
		where += fmt.Sprintf(` AND health=$%d`, len(args))
	}
	if filter.Search != "" {
		args = append(args, "%"+escapeLike(filter.Search)+"%")
		where += fmt.Sprintf(` AND name ILIKE $%d ESCAPE '\'`, len(args))
	}
	if after.Valid {
		args = append(args, after.CreatedAt, after.ID)
		where += fmt.Sprintf(` AND (created_at,id) < ($%d,$%d)`, len(args)-1, len(args))
	}
	rows, err := r.pool.Query(ctx,
		`SELECT `+monitorCols+` FROM uptime.monitors WHERE `+where+
			` ORDER BY created_at DESC, id DESC LIMIT $2`, args...)
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

// escapeLike neutralizes ILIKE metacharacters so a search term can
// never widen into a pattern the owner didn't type.
func escapeLike(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return r.Replace(s)
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

// mutateMonitorTx is the shared generation fence for every lifecycle
// mutation inside a caller-held user lock: monitor FOR UPDATE →
// generation compare → fn applies the UPDATE → generation+1 lands
// exactly once in the same statement. A stale expected generation
// returns ErrGenerationConflict with no partial effect.
func (r *Repository) mutateMonitorTx(ctx context.Context, tx pgx.Tx, ownerID, id uuid.UUID,
	expectedGen int64,
	fn func(tx pgx.Tx, m Monitor) (Monitor, error)) (Monitor, error) {
	m, err := lockedMonitor(tx, ctx, ownerID, id)
	if err != nil {
		return Monitor{}, err
	}
	if m.Generation != expectedGen {
		return Monitor{}, ErrGenerationConflict
	}
	return fn(tx, m)
}

// mutateMonitor is the self-contained variant taking the user lock
// itself (status predicate only) — see CreateMonitor's note on why
// HTTP mutations prefer the *Tx forms under auth.WithActorLock.
func (r *Repository) mutateMonitor(ctx context.Context, ownerID, id uuid.UUID,
	expectedGen int64,
	fn func(tx pgx.Tx, m Monitor) (Monitor, error)) (Monitor, error) {
	var out Monitor
	err := r.withActorLock(ctx, ownerID, func(tx pgx.Tx, _ actorRow) error {
		m, err := r.mutateMonitorTx(ctx, tx, ownerID, id, expectedGen, fn)
		if err != nil {
			return err
		}
		out = m
		return nil
	})
	return out, err
}

// UpdateMonitorTx applies a concrete write-set under the generation
// fence inside the caller's transaction. The service merged+validated
// the fields; callers must never mass-assign user_id, health, streaks,
// sequences, or next_check_at — those columns are absent from the SET
// clause by construction.
func (r *Repository) UpdateMonitorTx(ctx context.Context, tx pgx.Tx, ownerID, id uuid.UUID,
	expectedGen int64, in WriteFields) (Monitor, error) {
	return r.mutateMonitorTx(ctx, tx, ownerID, id, expectedGen,
		func(tx pgx.Tx, m Monitor) (Monitor, error) {
			out, err := scanMonitor(tx.QueryRow(ctx,
				`UPDATE uptime.monitors SET
				   name=$3, target_url=$4, interval_seconds=$5,
				   timeout_seconds=$6, expected_status=$7,
				   generation=generation+1, updated_at=now()
				 WHERE id=$1 AND user_id=$2
				 RETURNING `+monitorCols,
				id, ownerID, in.Name, in.TargetURL, in.IntervalSeconds,
				in.TimeoutSeconds, in.ExpectedStatus))
			if err != nil {
				return Monitor{}, err
			}
			// Config change closes any open incident  -  honestly, as
			// CONFIG_CHANGED, never as observed recovery.
			if _, err := (incident.Repository{}).CloseIncident(ctx, tx,
				id, nil, incident.ReasonConfigChanged); err != nil {
				return Monitor{}, err
			}
			return out, nil
		})
}

// SetMonitorPausedTx flips the lifecycle flag under the fence inside
// the caller's transaction. Pause never fabricates DOWN and resume
// never fabricates UP or a sample — health, streaks, and sequence
// fences pass through untouched. Resume sets next_check_at=now():
// eligibility only, the durable admission budget still gates the
// actual check (no check-now privilege).
func (r *Repository) SetMonitorPausedTx(ctx context.Context, tx pgx.Tx, ownerID, id uuid.UUID,
	expectedGen int64, paused bool) (Monitor, error) {
	return r.mutateMonitorTx(ctx, tx, ownerID, id, expectedGen,
		func(tx pgx.Tx, m Monitor) (Monitor, error) {
			// Idempotent command: already in the requested state is a
			// no-op success — no second generation bump, no write. A
			// stale expected_generation still conflicts above.
			if m.IsPaused == paused {
				return m, nil
			}
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
			out, err := scanMonitor(tx.QueryRow(ctx, q, id, ownerID))
			if err != nil {
				return Monitor{}, err
			}
			if paused {
				if _, err := (incident.Repository{}).CloseIncident(ctx, tx,
					id, nil, incident.ReasonConfigChanged); err != nil {
					return Monitor{}, err
				}
			}
			return out, nil
		})
}

// SoftDeleteMonitorTx tombstones under the fence inside the caller's
// transaction. The row stays retained (counted toward retained caps,
// audit history preserved); every subsequent read/mutation collapses
// to ErrMonitorNotFound.
func (r *Repository) SoftDeleteMonitorTx(ctx context.Context, tx pgx.Tx, ownerID, id uuid.UUID,
	expectedGen int64) error {
	_, err := r.mutateMonitorTx(ctx, tx, ownerID, id, expectedGen,
		func(tx pgx.Tx, m Monitor) (Monitor, error) {
			_, err := tx.Exec(ctx,
				`UPDATE uptime.monitors SET deleted_at=now(),
				   generation=generation+1, updated_at=now()
				 WHERE id=$1 AND user_id=$2`, id, ownerID)
			if err != nil {
				return Monitor{}, mapErr(err)
			}
			if _, err := (incident.Repository{}).CloseIncident(ctx, tx,
				id, nil, incident.ReasonDeleted); err != nil {
				return Monitor{}, err
			}
			return m, nil
		})
	return err
}

// UpdateMonitor/SetMonitorPaused/SoftDeleteMonitor are the
// self-contained variants for non-handler callers (tests, CLI): each
// takes the owner lock itself and applies the status predicate only.
func (r *Repository) UpdateMonitor(ctx context.Context, ownerID, id uuid.UUID,
	expectedGen int64, in WriteFields) (Monitor, error) {
	var out Monitor
	err := r.withActorLock(ctx, ownerID, func(tx pgx.Tx, _ actorRow) error {
		m, err := r.UpdateMonitorTx(ctx, tx, ownerID, id, expectedGen, in)
		if err != nil {
			return err
		}
		out = m
		return nil
	})
	return out, err
}

func (r *Repository) SetMonitorPaused(ctx context.Context, ownerID, id uuid.UUID,
	expectedGen int64, paused bool) (Monitor, error) {
	var out Monitor
	err := r.withActorLock(ctx, ownerID, func(tx pgx.Tx, _ actorRow) error {
		m, err := r.SetMonitorPausedTx(ctx, tx, ownerID, id, expectedGen, paused)
		if err != nil {
			return err
		}
		out = m
		return nil
	})
	return out, err
}

func (r *Repository) SoftDeleteMonitor(ctx context.Context, ownerID, id uuid.UUID,
	expectedGen int64) error {
	return r.withActorLock(ctx, ownerID, func(tx pgx.Tx, _ actorRow) error {
		return r.SoftDeleteMonitorTx(ctx, tx, ownerID, id, expectedGen)
	})
}

// ChannelEligibility answers which ids are bindable for this owner,
// evaluated inside the binding transaction so the set can't shift
// between validate and replace. The composition root supplies
// notification.EligibleChannelIDs — monitor stays decoupled from the
// channel package's table.
type ChannelEligibility func(ctx context.Context, tx pgx.Tx,
	ownerID uuid.UUID, ids []uuid.UUID) (map[uuid.UUID]bool, error)

// ReplaceChannelsTx atomically swaps the monitor's binding set under
// the generation fence (RT F11): monitor FOR UPDATE → expected
// generation → validate the FULL owned VERIFIED+enabled set →
// delete+insert + generation++ in one commit. No partial replace:
// one ineligible id fails the whole set, and a stale generation
// conflicts before any row moves. Target health stays untouched.
func (r *Repository) ReplaceChannelsTx(ctx context.Context, tx pgx.Tx,
	ownerID, id uuid.UUID, expectedGen int64, channelIDs []uuid.UUID,
	eligible ChannelEligibility) (Monitor, error) {
	return r.mutateMonitorTx(ctx, tx, ownerID, id, expectedGen,
		func(tx pgx.Tx, m Monitor) (Monitor, error) {
			ok, err := eligible(ctx, tx, ownerID, channelIDs)
			if err != nil {
				return Monitor{}, mapErr(err)
			}
			for _, cid := range channelIDs {
				if !ok[cid] {
					return Monitor{}, ErrChannelIneligible
				}
			}
			if _, err := tx.Exec(ctx,
				`DELETE FROM uptime.monitor_channels
				 WHERE monitor_id=$1 AND user_id=$2`, id, ownerID); err != nil {
				return Monitor{}, mapErr(err)
			}
			for _, cid := range channelIDs {
				if _, err := tx.Exec(ctx,
					`INSERT INTO uptime.monitor_channels
					   (monitor_id,channel_id,user_id) VALUES ($1,$2,$3)`,
					id, cid, ownerID); err != nil {
					return Monitor{}, mapErr(err)
				}
			}
			return scanMonitor(tx.QueryRow(ctx,
				`UPDATE uptime.monitors SET
				   generation=generation+1, updated_at=now()
				 WHERE id=$1 AND user_id=$2 RETURNING `+monitorCols,
				id, ownerID))
		})
}
