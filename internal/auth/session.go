package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Sessions are opaque bearer capabilities: the client holds a 32-byte
// base64url token; the DB stores only its SHA-256 hash, so a leaked
// row never replays. Expiry is server-clock authoritative — absolute
// (default 7d) plus sliding idle (default 24h), capped at absolute.
// last_seen writes coalesce to at most one per minute per session —
// idle_expires_at slides on each coalesced write, so persisted liveness
// may lag true activity by up to ~1 minute (documented granularity).

const (
	sessionTokenBytes = 32
	lastSeenCoalesce  = time.Minute
	maxDeviceRunes    = 120
)

var (
	// ErrInvalidSession covers every rejection reason deliberately —
	// revoked, expired, disabled user, version mismatch all produce the
	// same generic failure (no account-state oracle).
	ErrInvalidSession = errors.New("session is not valid")
	errNoEntropy      = errors.New("could not read randomness")
)

// randSource is injectable so tests can force entropy failure.
var randSource io.Reader = rand.Reader

// Session mirrors one uptime.sessions row. TokenHash stays server-side.
type Session struct {
	ID              uuid.UUID
	UserID          uuid.UUID
	SecurityVersion int64
	CreatedAt       time.Time
	LastSeenAt      time.Time
	ExpiresAt       time.Time
	IdleExpiresAt   time.Time
	RecentAuthAt    *time.Time
	RevokedAt       *time.Time
	DeviceLabel     string
}

// IssuedSession is returned exactly once at creation. Token is the only
// place the plaintext capability exists — never logged, never stored.
type IssuedSession struct {
	Session Session
	Token   string
}

// newSessionToken returns a fresh base64url token (no padding).
func newSessionToken() (string, error) {
	buf := make([]byte, sessionTokenBytes)
	if _, err := io.ReadFull(randSource, buf); err != nil {
		return "", errNoEntropy
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// HashToken decodes a base64url token and returns its SHA-256 digest —
// the only form persisted. Malformed tokens fail closed.
func HashToken(token string) ([]byte, error) {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(raw) != sessionTokenBytes {
		return nil, ErrInvalidSession
	}
	sum := sha256.Sum256(raw)
	return sum[:], nil
}

// SessionStore is the persistence seam for session lifecycle.
// *Repository satisfies it.
type SessionStore interface {
	CreateSession(ctx context.Context, userID uuid.UUID, tokenHash []byte,
		expiresAt, idleExpiresAt time.Time, deviceLabel string) (Session, error)
	FindSessionByTokenHash(ctx context.Context, tokenHash []byte) (Session, User, error)
	TouchSession(ctx context.Context, id uuid.UUID, seenAt, idleExpiresAt time.Time) error
	RevokeSession(ctx context.Context, id uuid.UUID) error
	ListSessionsByUser(ctx context.Context, userID uuid.UUID, limit, offset int) ([]Session, error)
	RevokeSessionForUser(ctx context.Context, userID, sessionID uuid.UUID) error
	WithUserLock(ctx context.Context, userID uuid.UUID, fn func(tx pgx.Tx, u User) error) error
	// FindSessionForUpdate re-reads a session row inside an existing
	// transaction (FOR UPDATE) — WithActorLock uses it so a revoke
	// landing between authenticate and commit cannot slip a mutation
	// through the lock.
	FindSessionForUpdate(ctx context.Context, tx pgx.Tx, id uuid.UUID) (Session, error)
	// MarkRecentAuth stamps the server-side reauthentication time on a
	// live session inside the caller's transaction.
	MarkRecentAuth(ctx context.Context, tx pgx.Tx, sessionID uuid.UUID, now time.Time) error
	// RevokeAllSessionsAndBump ends every session and advances the
	// security epoch atomically — caller holds the user lock.
	RevokeAllSessionsAndBump(ctx context.Context, tx pgx.Tx, userID uuid.UUID) (int64, error)
}

// CreateSession issues a new session for userID. The repository call
// takes the user row FOR UPDATE and stamps the current security_version
// under that lock, so a concurrent disable/version bump cannot be
// observed half-applied.
func (s *Service) CreateSession(ctx context.Context, userID uuid.UUID, deviceLabel string) (IssuedSession, error) {
	if len([]rune(deviceLabel)) > maxDeviceRunes {
		return IssuedSession{}, &FieldError{Fields: map[string]string{
			"device_label": "must be at most 120 characters"}}
	}
	token, err := newSessionToken()
	if err != nil {
		return IssuedSession{}, err
	}
	hash, err := HashToken(token)
	if err != nil {
		return IssuedSession{}, err
	}
	now := s.now()
	sess, err := s.store.CreateSession(ctx, userID, hash,
		now.Add(s.pol.Absolute), now.Add(s.pol.Idle), deviceLabel)
	if err != nil {
		return IssuedSession{}, err
	}
	return IssuedSession{Session: sess, Token: token}, nil
}

// LookupSession validates a bearer token and returns the live session.
// All rejection reasons collapse to ErrInvalidSession.
func (s *Service) LookupSession(ctx context.Context, token string) (Session, error) {
	sess, _, err := s.authenticateToken(ctx, token)
	return sess, err
}

// RevokeSession stamps revoked_at server-side. Client-side cookie
// clearing is the handler's concern; revocation is the authority.
func (s *Service) RevokeSession(ctx context.Context, sessionID uuid.UUID) error {
	return s.store.RevokeSession(ctx, sessionID)
}
