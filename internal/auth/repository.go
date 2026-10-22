package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Sentinel errors mapped from storage failures. They never carry SQL,
// argument values, or driver internals.
var (
	ErrNotFound       = errors.New("not found")
	ErrDuplicateEmail = errors.New("email already registered")
	ErrUnavailable    = errors.New("storage unavailable")
)

// User mirrors the uptime.users row. PasswordHash stays server-side —
// public DTOs never include it.
type User struct {
	ID              uuid.UUID
	Email           string
	PasswordHash    string
	DisplayName     string
	Status          string
	MonitorLimit    int
	SecurityVersion int64
	Version         int64
	CreatedAt       time.Time
	UpdatedAt       time.Time
	DisabledAt      *time.Time
}

const (
	UserStatusActive   = "ACTIVE"
	UserStatusDisabled = "DISABLED"
)

// Repository performs parameterized identity queries. It owns no pool —
// the caller wires and closes it.
type Repository struct {
	pool *pgxpool.Pool
	qtim time.Duration
}

func NewRepository(pool *pgxpool.Pool, queryTimeout time.Duration) *Repository {
	return &Repository{pool: pool, qtim: queryTimeout}
}

func (r *Repository) withTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, r.qtim)
}

func mapErr(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	var pge *pgconn.PgError
	if errors.As(err, &pge) {
		// 23505 is ambiguous across tables — discriminate on the
		// constraint name, not the code alone.
		if pge.Code == "23505" && pge.ConstraintName == "users_email_key" {
			return ErrDuplicateEmail
		}
		return fmt.Errorf("%w: %s", ErrUnavailable, pge.Code)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("%w: deadline", ErrUnavailable)
	}
	return err
}

const userCols = `id,email,password_hash,display_name,status,monitor_limit,security_version,version,created_at,updated_at,disabled_at`

func scanUser(row pgx.Row) (User, error) {
	var u User
	err := row.Scan(&u.ID, &u.Email, &u.PasswordHash, &u.DisplayName, &u.Status,
		&u.MonitorLimit, &u.SecurityVersion, &u.Version, &u.CreatedAt, &u.UpdatedAt, &u.DisabledAt)
	return u, err
}

// CreateUser inserts a canonical-email user and returns the stored row.
// Callers supply the already-normalized email, computed password hash,
// and the configured per-user monitor quota — the column is the quota
// authority from this point on (DB DEFAULT is only a migration-era
// fallback, never the policy source).
func (r *Repository) CreateUser(ctx context.Context, email, passwordHash, displayName string, monitorLimit int) (User, error) {
	ctx, cancel := r.withTimeout(ctx)
	defer cancel()
	u, err := scanUser(r.pool.QueryRow(ctx,
		`INSERT INTO uptime.users (id,email,password_hash,display_name,monitor_limit)
		 VALUES ($1,$2,$3,$4,$5) RETURNING `+userCols,
		uuid.New(), email, passwordHash, displayName, monitorLimit))
	if err != nil {
		return User{}, mapErr(err)
	}
	return u, nil
}

// FindUserByEmail returns ErrNotFound (not 500) when no row matches.
func (r *Repository) FindUserByEmail(ctx context.Context, email string) (User, error) {
	ctx, cancel := r.withTimeout(ctx)
	defer cancel()
	u, err := scanUser(r.pool.QueryRow(ctx,
		`SELECT `+userCols+` FROM uptime.users WHERE email=$1`, email))
	if err != nil {
		return User{}, mapErr(err)
	}
	return u, nil
}

func (r *Repository) FindUserByID(ctx context.Context, id uuid.UUID) (User, error) {
	ctx, cancel := r.withTimeout(ctx)
	defer cancel()
	u, err := scanUser(r.pool.QueryRow(ctx,
		`SELECT `+userCols+` FROM uptime.users WHERE id=$1`, id))
	if err != nil {
		return User{}, mapErr(err)
	}
	return u, nil
}

const sessionCols = `id,user_id,security_version,created_at,last_seen_at,expires_at,idle_expires_at,recent_auth_at,revoked_at,device_label`

// qualCols prefixes every comma-separated column with an alias.
func qualCols(alias, cols string) string {
	return alias + "." + strings.ReplaceAll(cols, ",", ","+alias+".")
}

func scanSession(row pgx.Row) (Session, error) {
	var s Session
	err := row.Scan(&s.ID, &s.UserID, &s.SecurityVersion, &s.CreatedAt, &s.LastSeenAt,
		&s.ExpiresAt, &s.IdleExpiresAt, &s.RecentAuthAt, &s.RevokedAt, &s.DeviceLabel)
	return s, err
}

// CreateSession locks the user row FOR UPDATE, stamps the locked
// security_version onto the session, and inserts — so a disable or
// version bump cannot interleave between read and insert. A missing or
// DISABLED user cannot mint sessions.
func (r *Repository) CreateSession(ctx context.Context, userID uuid.UUID, tokenHash []byte,
	expiresAt, idleExpiresAt time.Time, deviceLabel string) (Session, error) {
	ctx, cancel := r.withTimeout(ctx)
	defer cancel()
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return Session{}, mapErr(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var status string
	var secVer int64
	err = tx.QueryRow(ctx,
		`SELECT status,security_version FROM uptime.users WHERE id=$1 FOR UPDATE`,
		userID).Scan(&status, &secVer)
	if err != nil {
		return Session{}, mapErr(err)
	}
	if status != UserStatusActive {
		return Session{}, ErrInvalidSession
	}
	s, err := scanSession(tx.QueryRow(ctx,
		`INSERT INTO uptime.sessions
		 (id,user_id,token_hash,security_version,expires_at,idle_expires_at,device_label)
		 VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING `+sessionCols,
		uuid.New(), userID, tokenHash, secVer, expiresAt, idleExpiresAt, deviceLabel))
	if err != nil {
		return Session{}, mapErr(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Session{}, mapErr(err)
	}
	return s, nil
}

// FindSessionByTokenHash returns the session plus its owner row (status
// and security_version are validated by the caller).
func (r *Repository) FindSessionByTokenHash(ctx context.Context, tokenHash []byte) (Session, User, error) {
	ctx, cancel := r.withTimeout(ctx)
	defer cancel()
	var s Session
	var u User
	err := r.pool.QueryRow(ctx,
		`SELECT `+qualCols("s", sessionCols)+`,`+qualCols("u", userCols)+`
		 FROM uptime.sessions s JOIN uptime.users u ON u.id=s.user_id
		 WHERE s.token_hash=$1`, tokenHash).Scan(
		&s.ID, &s.UserID, &s.SecurityVersion, &s.CreatedAt, &s.LastSeenAt,
		&s.ExpiresAt, &s.IdleExpiresAt, &s.RecentAuthAt, &s.RevokedAt, &s.DeviceLabel,
		&u.ID, &u.Email, &u.PasswordHash, &u.DisplayName, &u.Status,
		&u.MonitorLimit, &u.SecurityVersion, &u.Version, &u.CreatedAt, &u.UpdatedAt, &u.DisabledAt)
	if err != nil {
		return Session{}, User{}, mapErr(err)
	}
	return s, u, nil
}

// TouchSession slides idle_expires_at forward and stamps last_seen.
func (r *Repository) TouchSession(ctx context.Context, id uuid.UUID, seenAt, idleExpiresAt time.Time) error {
	ctx, cancel := r.withTimeout(ctx)
	defer cancel()
	tag, err := r.pool.Exec(ctx,
		`UPDATE uptime.sessions SET last_seen_at=$2,idle_expires_at=$3 WHERE id=$1`,
		id, seenAt, idleExpiresAt)
	if err != nil {
		return mapErr(err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ListSessionsByUser returns a bounded, deterministically-ordered page
// of a user's active sessions (revoked excluded).
func (r *Repository) ListSessionsByUser(ctx context.Context, userID uuid.UUID, limit, offset int) ([]Session, error) {
	ctx, cancel := r.withTimeout(ctx)
	defer cancel()
	rows, err := r.pool.Query(ctx,
		`SELECT `+sessionCols+` FROM uptime.sessions
		 WHERE user_id=$1 AND revoked_at IS NULL
		 ORDER BY created_at,id LIMIT $2 OFFSET $3`, userID, limit, offset)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	var out []Session
	for rows.Next() {
		var s Session
		if err := rows.Scan(&s.ID, &s.UserID, &s.SecurityVersion, &s.CreatedAt,
			&s.LastSeenAt, &s.ExpiresAt, &s.IdleExpiresAt, &s.RecentAuthAt,
			&s.RevokedAt, &s.DeviceLabel); err != nil {
			return nil, mapErr(err)
		}
		out = append(out, s)
	}
	return out, mapErr(rows.Err())
}

// RevokeSessionForUser revokes only when the session belongs to userID —
// foreign IDs are indistinguishable from missing ones (404, not 403).
func (r *Repository) RevokeSessionForUser(ctx context.Context, userID, sessionID uuid.UUID) error {
	ctx, cancel := r.withTimeout(ctx)
	defer cancel()
	tag, err := r.pool.Exec(ctx,
		`UPDATE uptime.sessions SET revoked_at=now()
		 WHERE id=$1 AND user_id=$2 AND revoked_at IS NULL`, sessionID, userID)
	if err != nil {
		return mapErr(err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// WithUserLock runs fn inside a transaction while holding the user row
// FOR UPDATE. The callback receives the tx so callers compose further
// locked writes (quota → monitor insert) atomically under the SAME
// fencing lock — a tx1-recheck/tx2-write split would reopen the
// TOCTOU this barrier exists to close (lock order: users → …).
// Privileged mutations re-read the actor under this lock — a
// middleware-captured principal is only an authentication snapshot,
// never proof of current privileges.
func (r *Repository) WithUserLock(ctx context.Context, userID uuid.UUID,
	fn func(tx pgx.Tx, u User) error) error {
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
	u, err := scanUser(tx.QueryRow(ctx,
		`SELECT `+userCols+` FROM uptime.users WHERE id=$1 FOR UPDATE`, userID))
	if err != nil {
		return mapErr(err)
	}
	if err := fn(tx, u); err != nil {
		return err
	}
	return mapErr(tx.Commit(ctx))
}

// FindSessionForUpdate re-reads the session row FOR UPDATE inside a
// caller-owned transaction. Lock order stays users → sessions, matching
// CreateSession — callers must not hold a session lock before this.
func (r *Repository) FindSessionForUpdate(ctx context.Context, tx pgx.Tx, id uuid.UUID) (Session, error) {
	s, err := scanSession(tx.QueryRow(ctx,
		`SELECT `+sessionCols+` FROM uptime.sessions WHERE id=$1 FOR UPDATE`, id))
	if err != nil {
		return Session{}, mapErr(err)
	}
	return s, nil
}

// RevokeSession stamps revoked_at once (idempotent for callers: a
// missing or already-revoked row is still a successful no-op only when
// the row exists).
func (r *Repository) RevokeSession(ctx context.Context, id uuid.UUID) error {
	ctx, cancel := r.withTimeout(ctx)
	defer cancel()
	tag, err := r.pool.Exec(ctx,
		`UPDATE uptime.sessions SET revoked_at=now() WHERE id=$1 AND revoked_at IS NULL`, id)
	if err != nil {
		return mapErr(err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// MarkRecentAuth stamps recent_auth_at on a live session inside the
// caller's transaction — Reauthenticate uses it after the password
// verify under the actor lock.
func (r *Repository) MarkRecentAuth(ctx context.Context, tx pgx.Tx,
	sessionID uuid.UUID, now time.Time) error {
	tag, err := tx.Exec(ctx, `
		UPDATE uptime.sessions SET recent_auth_at=$2
		WHERE id=$1 AND revoked_at IS NULL`, sessionID, now)
	if err != nil {
		return mapErr(err)
	}
	if tag.RowsAffected() == 0 {
		return ErrInvalidSession
	}
	return nil
}

// RevokeAllSessionsAndBump invalidates every session a user holds and
// bumps the security epoch — one atomic "log out everywhere". The
// caller already holds the user row lock; this composes the two writes
// inside that transaction.
func (r *Repository) RevokeAllSessionsAndBump(ctx context.Context, tx pgx.Tx,
	userID uuid.UUID) (int64, error) {
	if _, err := tx.Exec(ctx, `
		UPDATE uptime.users
		SET security_version=security_version+1, version=version+1,
		    updated_at=now()
		WHERE id=$1`, userID); err != nil {
		return 0, mapErr(err)
	}
	tag, err := tx.Exec(ctx, `
		UPDATE uptime.sessions SET revoked_at=clock_timestamp()
		WHERE user_id=$1 AND revoked_at IS NULL`, userID)
	if err != nil {
		return 0, mapErr(err)
	}
	return tag.RowsAffected(), nil
}
