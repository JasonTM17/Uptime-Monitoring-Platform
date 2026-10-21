package incident

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// CloseReason enumerates the ONLY terminal causes. RECOVERED is
// emitted exclusively by observed health evidence; CONFIG_CHANGED and
// DELETED close administratively and never produce a recovery event.
type CloseReason string

const (
	ReasonRecovered     CloseReason = "RECOVERED"
	ReasonConfigChanged CloseReason = "CONFIG_CHANGED"
	ReasonDeleted       CloseReason = "DELETED"
)

// Incident mirrors one uptime.incidents row.
type Incident struct {
	ID              uuid.UUID
	MonitorID       uuid.UUID
	OpenedCheckID   uuid.UUID
	ResolvedCheckID *uuid.UUID
	OpenedAt        time.Time
	ResolvedAt      *time.Time
	CloseReason     *CloseReason
	Version         int64
}

var ErrAlreadyOpen = errors.New("incident: monitor already has an open incident")

// Repository composes incident mutations INSIDE the caller's
// transaction — it never begins or commits one itself. Rollback of
// the enclosing finalize removes the incident mutation with it.
type Repository struct{}

// GetActiveIncident returns the open incident for monitorID inside
// the caller's tx, or pgx.ErrNoRows.
func (Repository) GetActiveIncident(ctx context.Context, tx pgx.Tx,
	monitorID uuid.UUID) (*Incident, error) {
	var in Incident
	err := tx.QueryRow(ctx, `
		SELECT id,monitor_id,opened_check_id,resolved_check_id,
		       opened_at,resolved_at,close_reason,version
		FROM uptime.incidents
		WHERE monitor_id=$1 AND resolved_at IS NULL`,
		monitorID).Scan(&in.ID, &in.MonitorID, &in.OpenedCheckID,
		&in.ResolvedCheckID, &in.OpenedAt, &in.ResolvedAt,
		&in.CloseReason, &in.Version)
	if err != nil {
		return nil, err
	}
	return &in, nil
}

// OpenIncident inserts the open incident inside the caller's tx. The
// partial unique index guarantees at most one open per monitor — a
// second concurrent open surfaces as ErrAlreadyOpen, never a second row.
func (Repository) OpenIncident(ctx context.Context, tx pgx.Tx,
	monitorID, openedCheckID uuid.UUID) (*Incident, error) {
	var in Incident
	err := tx.QueryRow(ctx, `
		INSERT INTO uptime.incidents
		  (id,monitor_id,opened_check_id,opened_at)
		VALUES (gen_random_uuid(),$1,$2,clock_timestamp())
		RETURNING id,monitor_id,opened_check_id,opened_at,version`,
		monitorID, openedCheckID).Scan(&in.ID, &in.MonitorID,
		&in.OpenedCheckID, &in.OpenedAt, &in.Version)
	if err != nil {
		if isUniqueViolation(err) {
			return nil, ErrAlreadyOpen
		}
		return nil, fmt.Errorf("open incident: %w", err)
	}
	return &in, nil
}

// CloseIncident resolves the currently-open incident inside the
// caller's tx, stamping the resolver check run and the explicit
// reason. Returns false when nothing was open — callers decide
// whether that's an error.
func (Repository) CloseIncident(ctx context.Context, tx pgx.Tx,
	monitorID uuid.UUID, resolvedCheckID *uuid.UUID, reason CloseReason) (bool, error) {
	tag, err := tx.Exec(ctx, `
		UPDATE uptime.incidents
		SET resolved_at=clock_timestamp(), resolved_check_id=$2,
		    close_reason=$3, version=version+1
		WHERE monitor_id=$1 AND resolved_at IS NULL`,
		monitorID, resolvedCheckID, string(reason))
	if err != nil {
		return false, fmt.Errorf("close incident: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// isUniqueViolation detects SQLSTATE 23505 without importing pgconn
// internals at the call site.
func isUniqueViolation(err error) bool {
	type sqlState interface{ SQLState() string }
	var s sqlState
	return errors.As(err, &s) && s.SQLState() == "23505"
}
