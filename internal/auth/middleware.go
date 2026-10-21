package auth

import (
	"context"
	"net/http"

	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/platform/httpserver"
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

// RecheckActor re-reads the user under FOR UPDATE lock and verifies
// the session's security_version and ACTIVE status still hold. Use
// before every privileged commit — the context principal is stale the
// moment it is captured.
func (s *Service) RecheckActor(ctx context.Context, p Principal) (User, error) {
	var out User
	err := s.store.WithUserLock(ctx, p.User.ID, func(u User) error {
		out = u
		if u.Status != UserStatusActive || u.SecurityVersion != p.Session.SecurityVersion {
			return ErrInvalidSession
		}
		return nil
	})
	if err != nil {
		return User{}, err
	}
	return out, nil
}

// RequireSession is the authentication middleware: reads the session
// cookie, validates it server-side, and injects the principal.
// Rejections are a uniform 401 — no signal about why.
func (h *Handler) RequireSession(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ck, err := r.Cookie(sessionCookieName)
		if err != nil || ck.Value == "" {
			httpserver.WriteError(w, r, http.StatusUnauthorized,
				httpserver.ErrUnauth, "authentication required")
			return
		}
		sess, owner, err := h.svc.authenticateToken(r.Context(), ck.Value)
		if err != nil {
			httpserver.WriteError(w, r, http.StatusUnauthorized,
				httpserver.ErrUnauth, "authentication required")
			return
		}
		p := Principal{User: owner, Session: sess}
		next(w, r.WithContext(context.WithValue(r.Context(), principalKey, p)))
	}
}
