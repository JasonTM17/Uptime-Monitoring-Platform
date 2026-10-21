package auth

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
		if pge.Code == "23505" {
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
// Callers supply the already-normalized email and computed password hash.
func (r *Repository) CreateUser(ctx context.Context, email, passwordHash, displayName string) (User, error) {
	ctx, cancel := r.withTimeout(ctx)
	defer cancel()
	u, err := scanUser(r.pool.QueryRow(ctx,
		`INSERT INTO uptime.users (id,email,password_hash,display_name)
		 VALUES ($1,$2,$3,$4) RETURNING `+userCols,
		uuid.New(), email, passwordHash, displayName))
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
