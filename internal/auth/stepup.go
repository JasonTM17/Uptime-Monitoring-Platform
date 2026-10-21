package auth

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// RecentAuthTTL is how long a password reauthentication stays valid
// for sensitive actions. The timestamp is server-side only —
// sessions.recent_auth_at is never trusted from a client.
const RecentAuthTTL = 5 * time.Minute

// ErrReauthRequired means the action needs a fresh password
// verification: the session carries no recent_auth_at inside the TTL.
// Handlers map it to 403 + REAUTH_REQUIRED — it is a state, not an
// authentication failure.
var ErrReauthRequired = errors.New("recent authentication required")

// Reauthenticate verifies the current password and stamps
// recent_auth_at on THIS session only. It grants no permission —
// it only proves the person at the keyboard still knows the password.
// Verification is rate-limited per account, runs the production
// hasher, and treats a wrong password identically to a valid check
// that failed.
func (s *Service) Reauthenticate(ctx context.Context, p Principal, password string) error {
	if ok, wait := s.acctLimiter.allow("reauth:" + p.User.ID.String()); !ok {
		return &RateLimitedError{RetryAfter: wait}
	}
	user, err := s.store.FindUserByID(ctx, p.User.ID)
	if err != nil {
		return err
	}
	ok, err := s.hasher.VerifyPassword(ctx, password, user.PasswordHash)
	if err != nil {
		return err
	}
	if !ok {
		return ErrBadCredentials
	}
	return s.store.WithUserLock(ctx, p.User.ID, func(tx pgx.Tx, _ User) error {
		sess, err := s.store.FindSessionForUpdate(ctx, tx, p.Session.ID)
		if err != nil {
			return err
		}
		if sess.UserID != p.User.ID || sess.RevokedAt != nil {
			return ErrInvalidSession
		}
		return s.store.MarkRecentAuth(ctx, tx, p.Session.ID, s.now())
	})
}

// RevokeAllOwnSessions ends every session the caller owns — the "log
// out everywhere" path. It requires recent authentication inside the
// TTL (the current session row is re-read under the user lock, so a
// reauth racing this call cannot be skipped), bumps the security
// version so every stamped session dies, then revokes each row.
// The caller clears the cookie afterwards; re-login is required.
func (s *Service) RevokeAllOwnSessions(ctx context.Context, p Principal) (int64, error) {
	var revoked int64
	err := s.store.WithUserLock(ctx, p.User.ID, func(tx pgx.Tx, u User) error {
		if err := actorPredicate(u, p); err != nil {
			return err
		}
		sess, err := s.store.FindSessionForUpdate(ctx, tx, p.Session.ID)
		if err != nil {
			return err
		}
		if sess.UserID != u.ID || sess.RevokedAt != nil ||
			!s.now().Before(sess.ExpiresAt) || !s.now().Before(sess.IdleExpiresAt) {
			return ErrInvalidSession
		}
		if sess.RecentAuthAt == nil ||
			s.now().Sub(*sess.RecentAuthAt) > RecentAuthTTL {
			return ErrReauthRequired
		}
		n, err := s.store.RevokeAllSessionsAndBump(ctx, tx, u.ID)
		if err != nil {
			return err
		}
		revoked = n
		return nil
	})
	return revoked, err
}
