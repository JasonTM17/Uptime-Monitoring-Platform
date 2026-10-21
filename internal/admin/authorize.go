package admin

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Authorization errors map to the contract envelope: revoked actor →
// 401, missing capability → 403, stale epoch/expected-version → 409.
// They are distinct so handlers never collapse a revoked actor into
// a permission failure.
var (
	ErrActorRevoked   = errors.New("actor no longer authorized")
	ErrForbidden      = errors.New("missing required permission")
	ErrStaleEpoch     = errors.New("security version conflict — authorization changed")
	ErrSubjectRevoked = errors.New("target subject is not in a mutable state")
)

// ActorRef carries the minimum stamped state a privileged guard must
// re-verify under lock. It is a snapshot from request authentication —
// never trusted as current authority.
type ActorRef struct {
	UserID          uuid.UUID
	SessionID       uuid.UUID
	SecurityVersion int64 // stamped on the session at login
}

// LockAnchor serializes every privileged mutation — API and CLI
// alike — on the singleton row. Always the FIRST lock: the global
// order is anchor → users (ascending) → quota → monitors →
// incident/outbox.
func LockAnchor(ctx context.Context, tx pgx.Tx) error {
	if _, err := tx.Exec(ctx,
		`SELECT id FROM uptime.security_anchor WHERE id=1 FOR UPDATE`); err != nil {
		return fmt.Errorf("lock security anchor: %w", err)
	}
	return nil
}

// LockUser locks one user row FOR UPDATE inside the guarded
// transaction. Callers handling multiple subjects lock them in
// ascending UUID order via LockUsers.
type LockedUser struct {
	ID              uuid.UUID
	Status          string
	SecurityVersion int64
	Version         int64
}

func LockUser(ctx context.Context, tx pgx.Tx, id uuid.UUID) (LockedUser, error) {
	var u LockedUser
	err := tx.QueryRow(ctx, `
		SELECT id, status, security_version, version
		FROM uptime.users WHERE id=$1 FOR UPDATE`, id).
		Scan(&u.ID, &u.Status, &u.SecurityVersion, &u.Version)
	if errors.Is(err, pgx.ErrNoRows) {
		return LockedUser{}, ErrSubjectRevoked
	}
	return u, err
}

// LockUsers locks several users in ascending ID order — the canonical
// order that keeps concurrent mutations deadlock-free.
func LockUsers(ctx context.Context, tx pgx.Tx, ids ...uuid.UUID) ([]LockedUser, error) {
	sorted := append([]uuid.UUID(nil), ids...)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].String() < sorted[j].String()
	})
	out := make([]LockedUser, 0, len(sorted))
	var prev uuid.UUID
	for _, id := range sorted {
		if len(out) > 0 && id == prev {
			continue // actor may also appear in targets
		}
		prev = id
		u, err := LockUser(ctx, tx, id)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, nil
}

// LoadEffectivePermissions returns the union of all catalog
// permissions granted through the user's role assignments, resolved
// inside the guarded transaction — no cached snapshot is consulted.
func LoadEffectivePermissions(ctx context.Context, tx pgx.Tx, userID uuid.UUID) (map[string]bool, error) {
	// Share-lock the actor's grant rows for the tx duration: a delete
	// landing between this read and our commit is the stale-permission
	// wedge — FOR SHARE makes any removal serialize AFTER this tx, so
	// either the write is honestly first or the removal is.
	if _, err := tx.Exec(ctx, `
		SELECT role_id FROM uptime.user_roles
		WHERE user_id=$1 FOR SHARE`, userID); err != nil {
		return nil, err
	}
	// Same pin on the permission side of the join: a role-permission
	// edit that bypasses the holder-epoch fanout (naive bypass) is a
	// delete on this table — share-locking the actor's effective
	// grant rows closes the same mid-tx window one table deeper.
	if _, err := tx.Exec(ctx, `
		SELECT rp.role_id, rp.permission_id
		FROM uptime.role_permissions rp
		WHERE rp.role_id IN (
		  SELECT role_id FROM uptime.user_roles WHERE user_id=$1)
		FOR SHARE OF rp`, userID); err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, `
		SELECT DISTINCT rp.permission_id
		FROM uptime.user_roles ur
		JOIN uptime.role_permissions rp ON rp.role_id = ur.role_id
		WHERE ur.user_id = $1`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			return nil, err
		}
		out[p] = true
	}
	return out, rows.Err()
}

// Beginner is the transaction seam both *pgx.Conn and *pgxpool.Pool
// satisfy — services stay conn-agnostic so tests can inject a single
// dedicated conn while production wiring uses the shared pool.
type Beginner interface {
	Begin(ctx context.Context) (pgx.Tx, error)
}

// WithPrivilegedTx is the privileged-mutation guard: one transaction
// that serializes on the anchor, re-verifies the actor (ACTIVE user,
// live session, matching security epoch, required permission) under
// the locks that a revoke must wait on, then runs fn and commits.
//
// Linearization point: the actor's user-row lock. A revoke, demote
// or suspend committed before this transaction locks the row is
// observed and denied; one that arrives after waits for the commit —
// ordering never depends on the middleware snapshot.
//
// Callers must not perform network I/O inside fn.
func WithPrivilegedTx(ctx context.Context, conn Beginner,
	actor ActorRef, permission string, now time.Time,
	fn func(tx pgx.Tx, perms map[string]bool) error) error {
	return withPrivilegedTxUsers(ctx, conn, actor, nil, permission, now,
		func(tx pgx.Tx, _ []LockedUser, perms map[string]bool) error {
			return fn(tx, perms)
		})
}

// WithPrivilegedTxUsers is WithPrivilegedTx for mutations that also
// touch subject user rows: every user — actor first in the predicate
// sense — is locked in ascending UUID order inside one transaction.
// fn additionally receives the locked subject rows (actor excluded).
func WithPrivilegedTxUsers(ctx context.Context, conn Beginner,
	actor ActorRef, targets []uuid.UUID, permission string, now time.Time,
	fn func(tx pgx.Tx, subjects []LockedUser, perms map[string]bool) error) error {
	return withPrivilegedTxUsers(ctx, conn, actor, targets, permission, now, fn)
}

// withPrivilegedTxUsers is the shared implementation. Subjects are
// locked together with the actor in ascending order so the global
// lock order (anchor → users asc → …) is never violated.
func withPrivilegedTxUsers(ctx context.Context, conn Beginner,
	actor ActorRef, targets []uuid.UUID, permission string, now time.Time,
	fn func(tx pgx.Tx, subjects []LockedUser, perms map[string]bool) error) error {

	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if err := LockAnchor(ctx, tx); err != nil {
		return err
	}
	ids := append([]uuid.UUID{actor.UserID}, targets...)
	locked, err := LockUsers(ctx, tx, ids...)
	if err != nil {
		return err
	}
	var u LockedUser
	var subjects []LockedUser
	wantSubject := map[uuid.UUID]bool{}
	for _, t := range targets {
		wantSubject[t] = true
	}
	for _, lu := range locked {
		if lu.ID == actor.UserID {
			u = lu
		}
		// The actor may also be a target — self-demotion is the very
		// path the last-superadmin guard exists for.
		if wantSubject[lu.ID] {
			subjects = append(subjects, lu)
		}
	}
	if u.ID != actor.UserID {
		return ErrActorRevoked
	}
	if u.Status != "ACTIVE" || u.SecurityVersion != actor.SecurityVersion {
		return ErrActorRevoked
	}
	// Re-read the session row under the same lock: a per-session
	// revoke does not bump the user epoch, so the user check alone
	// cannot fence it.
	var revokedAt *time.Time
	var expiresAt, idleExpiresAt time.Time
	var owner uuid.UUID
	err = tx.QueryRow(ctx, `
		SELECT user_id, revoked_at, expires_at, idle_expires_at
		FROM uptime.sessions WHERE id=$1 FOR UPDATE`, actor.SessionID).
		Scan(&owner, &revokedAt, &expiresAt, &idleExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrActorRevoked
	}
	if err != nil {
		return err
	}
	if owner != actor.UserID || revokedAt != nil ||
		!now.Before(expiresAt) || !now.Before(idleExpiresAt) {
		return ErrActorRevoked
	}
	perms, err := LoadEffectivePermissions(ctx, tx, actor.UserID)
	if err != nil {
		return err
	}
	if !perms[permission] {
		return ErrForbidden
	}
	if err := fn(tx, subjects, perms); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// AuthorizeRead is the read-path guard: the actor's user row is
// locked and the same session/epoch/permission predicates rechecked,
// but the security anchor is NOT taken — reads must not serialize
// against privileged writes. The fn result is committed unchanged
// (a read fn that mutates is a bug, not a contract).
func AuthorizeRead(ctx context.Context, conn Beginner,
	actor ActorRef, permission string, now time.Time,
	fn func(tx pgx.Tx, perms map[string]bool) error) error {
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	u, err := LockUser(ctx, tx, actor.UserID)
	if err != nil {
		return err
	}
	if u.Status != "ACTIVE" || u.SecurityVersion != actor.SecurityVersion {
		return ErrActorRevoked
	}
	var revokedAt *time.Time
	var expiresAt, idleExpiresAt time.Time
	var owner uuid.UUID
	err = tx.QueryRow(ctx, `
		SELECT user_id, revoked_at, expires_at, idle_expires_at
		FROM uptime.sessions WHERE id=$1 FOR UPDATE`, actor.SessionID).
		Scan(&owner, &revokedAt, &expiresAt, &idleExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrActorRevoked
	}
	if err != nil {
		return err
	}
	if owner != actor.UserID || revokedAt != nil ||
		!now.Before(expiresAt) || !now.Before(idleExpiresAt) {
		return ErrActorRevoked
	}
	perms, err := LoadEffectivePermissions(ctx, tx, actor.UserID)
	if err != nil {
		return err
	}
	if !perms[permission] {
		return ErrForbidden
	}
	if err := fn(tx, perms); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// ValidationError carries bounded field details for 422 responses —
// e.g. the missing_permissions list a custom role needs.
type ValidationError struct {
	Fields map[string]any
}

func (e *ValidationError) Error() string { return "validation failed" }
