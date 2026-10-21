package auth

import (
	"context"
	"net/http"

	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/platform/httpserver"
	"github.com/jackc/pgx/v5"
)

// The principal placed in request context is an authentication
// SNAPSHOT — proof that a session was valid at request start. It is
// never proof of current privileges: mutations that depend on user
// state must call RecheckActor under the user lock.
type ctxKey int

const principalKey ctxKey = 0

// Principal is the authenticated actor snapshot.
type Principal struct {
	User    User
	Session Session
}

// PrincipalFromContext extracts the actor set by RequireSession.
func PrincipalFromContext(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(principalKey).(Principal)
	return p, ok
}

// ContextWithPrincipal injects a principal — the seam for tests and
// trusted internal callers that already authenticated the actor.
func ContextWithPrincipal(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, principalKey, p)
}

// authenticateToken is the shared lookup: hash -> row -> all rejection
// reasons collapse to ErrInvalidSession.
func (s *Service) authenticateToken(ctx context.Context, token string) (Session, User, error) {
	hash, err := HashToken(token)
	if err != nil {
		return Session{}, User{}, err
	}
	sess, owner, err := s.store.FindSessionByTokenHash(ctx, hash)
	if err != nil {
		return Session{}, User{}, ErrInvalidSession
	}
	now := s.now()
	if sess.RevokedAt != nil || owner.Status != UserStatusActive ||
		sess.SecurityVersion != owner.SecurityVersion ||
		!now.Before(sess.ExpiresAt) || !now.Before(sess.IdleExpiresAt) {
		return Session{}, User{}, ErrInvalidSession
	}
	// Sliding idle + coalesced last_seen, single bounded UPDATE.
	if now.Sub(sess.LastSeenAt) >= lastSeenCoalesce {
		newIdle := now.Add(s.pol.Idle)
		if newIdle.After(sess.ExpiresAt) {
			newIdle = sess.ExpiresAt
		}
		if err := s.store.TouchSession(ctx, sess.ID, now, newIdle); err != nil {
			return Session{}, User{}, err
		}
		sess.LastSeenAt, sess.IdleExpiresAt = now, newIdle
	}
	return sess, owner, nil
}

// actorPredicate is the single fencing rule: the user must still be
// ACTIVE and the session's stamped security_version must still match.
// Auth owns this predicate; callers compose their own locked writes
// around it via WithActorLock.
func actorPredicate(u User, p Principal) error {
	if u.Status != UserStatusActive || u.SecurityVersion != p.Session.SecurityVersion {
		return ErrInvalidSession
	}
	return nil
}

// RecheckActor re-reads the USER under FOR UPDATE lock and verifies
// the session's security_version and ACTIVE status still hold. It is
// the ACTOR-level fence only — privileged commits that must also
// exclude a mid-request session revoke use WithActorLock, which
// re-reads the session row under the same lock. The context principal
// is stale the moment it is captured either way.
func (s *Service) RecheckActor(ctx context.Context, p Principal) (User, error) {
	var out User
	err := s.store.WithUserLock(ctx, p.User.ID, func(_ pgx.Tx, u User) error {
		out = u
		return actorPredicate(u, p)
	})
	if err != nil {
		return User{}, err
	}
	return out, nil
}

// WithActorLock runs fn under the user-row FOR UPDATE lock AFTER the
// actor predicate passes, inside the SAME transaction. The session row
// is re-read under lock too — user-level fencing alone would miss a
// per-session revoke (which does not bump security_version) landing
// between authenticate and commit. Callers composing privileged
// mutations (Phase-03 quota → monitor insert) write through tx so the
// recheck genuinely fences the commit — a recheck-then-new-tx split
// would reopen the TOCTOU this closes.
func (s *Service) WithActorLock(ctx context.Context, p Principal,
	fn func(tx pgx.Tx, u User) error) error {
	return s.store.WithUserLock(ctx, p.User.ID, func(tx pgx.Tx, u User) error {
		if err := actorPredicate(u, p); err != nil {
			return err
		}
		sess, err := s.store.FindSessionForUpdate(ctx, tx, p.Session.ID)
		if err != nil {
			return err
		}
		// Bind session→user too: the fence exists precisely to
		// distrust the snapshot, so re-verify ownership, revocation,
		// and both expiries under the lock.
		if sess.UserID != u.ID || sess.RevokedAt != nil ||
			!s.now().Before(sess.ExpiresAt) || !s.now().Before(sess.IdleExpiresAt) {
			return ErrInvalidSession
		}
		return fn(tx, u)
	})
}

// RequireSession is the authentication middleware: reads the session
// cookie, validates it server-side, and injects the principal.
// Rejections are a uniform 401 — no signal about why. It lives on the
// Service so every resource mux (auth, monitors, channels) shares one
// authentication path rather than each wrapping its own.
func (s *Service) RequireSession(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ck, err := r.Cookie(sessionCookieName)
		if err != nil || ck.Value == "" {
			httpserver.WriteError(w, r, http.StatusUnauthorized,
				httpserver.ErrUnauth, "authentication required")
			return
		}
		sess, owner, err := s.authenticateToken(r.Context(), ck.Value)
		if err != nil {
			httpserver.WriteError(w, r, http.StatusUnauthorized,
				httpserver.ErrUnauth, "authentication required")
			return
		}
		p := Principal{User: owner, Session: sess}
		next(w, r.WithContext(context.WithValue(r.Context(), principalKey, p)))
	}
}
