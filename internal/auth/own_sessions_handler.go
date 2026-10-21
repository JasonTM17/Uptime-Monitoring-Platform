package auth

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/platform/httpserver"
)

// Own-session surface: me, logout, and owner-scoped session inventory.
// Every response is a safe DTO — no token hashes, no raw tokens.

const (
	defaultSessionPageSize = 20
	maxSessionPageSize     = 50
)

// ListOwnSessions returns a bounded page of the caller's active
// sessions, newest first.
func (s *Service) ListOwnSessions(ctx context.Context, userID uuid.UUID, limit, offset int) ([]Session, error) {
	return s.store.ListSessionsByUser(ctx, userID, limit, offset)
}

// RevokeOwnSession revokes a session only if owned by userID. A foreign
// or missing ID is indistinguishable: both are ErrNotFound.
func (s *Service) RevokeOwnSession(ctx context.Context, userID, sessionID uuid.UUID) error {
	return s.store.RevokeSessionForUser(ctx, userID, sessionID)
}

// sessionDTO is the wire shape for one session in the inventory.
type sessionDTO struct {
	ID          uuid.UUID `json:"id"`
	DeviceLabel string    `json:"device_label"`
	CreatedAt   time.Time `json:"created_at"`
	LastSeenAt  time.Time `json:"last_seen_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	Current     bool      `json:"current"`
}

func (h *Handler) me(w http.ResponseWriter, r *http.Request) {
	p, ok := PrincipalFromContext(r.Context())
	if !ok {
		httpserver.WriteError(w, r, http.StatusUnauthorized,
			httpserver.ErrUnauth, "authentication required")
		return
	}
	httpserver.WriteJSON(w, r, http.StatusOK, map[string]any{
		"user":               publicUser(p.User),
		"session_expires_at": p.Session.ExpiresAt,
	})
}

// logout revokes the server-side session when it exists and always
// clears the cookie. Missing/invalid sessions still get 200 + cleared
// cookie — logout is idempotent and reveals no account state.
func (h *Handler) logout(w http.ResponseWriter, r *http.Request) {
	if ck, err := r.Cookie(sessionCookieName); err == nil && ck.Value != "" {
		if sess, _, err := h.svc.authenticateToken(r.Context(), ck.Value); err == nil {
			if err := h.svc.RevokeSession(r.Context(), sess.ID); err != nil {
				// Cookie still clears below, but the token stays valid
				// until expiry — surface it in logs, not to the client.
				h.log.Error("logout revoke failed", "session_id", sess.ID, "err", err)
			}
		}
	}
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookieName, Value: "", Path: "/",
		HttpOnly: true, Secure: h.secure,
		SameSite: http.SameSiteLaxMode, MaxAge: -1,
	})
	httpserver.WriteJSON(w, r, http.StatusOK, map[string]string{"status": "logged_out"})
}

// ownSessions returns the caller's bounded session inventory.
func (h *Handler) ownSessions(w http.ResponseWriter, r *http.Request) {
	p, ok := PrincipalFromContext(r.Context())
	if !ok {
		httpserver.WriteError(w, r, http.StatusUnauthorized,
			httpserver.ErrUnauth, "authentication required")
		return
	}
	page, size := 1, defaultSessionPageSize
	if v := r.URL.Query().Get("page"); v != "" {
		// Bounded: (page-1)*size must never overflow to a negative OFFSET.
		if n, err := strconv.Atoi(v); err == nil && n >= 1 && n <= 1<<20 {
			page = n
		}
	}
	if v := r.URL.Query().Get("page_size"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 1 && n <= maxSessionPageSize {
			size = n
		}
	}
	sessions, err := h.svc.ListOwnSessions(r.Context(), p.User.ID, size, (page-1)*size)
	if err != nil {
		h.internalError(w, r, err)
		return
	}
	dtos := make([]sessionDTO, 0, len(sessions))
	for _, s := range sessions {
		dtos = append(dtos, sessionDTO{
			ID: s.ID, DeviceLabel: s.DeviceLabel, CreatedAt: s.CreatedAt,
			LastSeenAt: s.LastSeenAt, ExpiresAt: s.ExpiresAt,
			Current: s.ID == p.Session.ID,
		})
	}
	httpserver.WriteJSON(w, r, http.StatusOK, map[string]any{
		"sessions": dtos, "page": page, "page_size": size,
	})
}

// revokeOwnSession deletes a caller-owned session. Foreign/missing IDs
// are 404; revoking the current session also clears the cookie.
func (h *Handler) revokeOwnSession(w http.ResponseWriter, r *http.Request) {
	p, ok := PrincipalFromContext(r.Context())
	if !ok {
		httpserver.WriteError(w, r, http.StatusUnauthorized,
			httpserver.ErrUnauth, "authentication required")
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpserver.WriteError(w, r, http.StatusNotFound,
			httpserver.ErrNotFound, "session not found")
		return
	}
	if err := h.svc.RevokeOwnSession(r.Context(), p.User.ID, id); err != nil {
		if errors.Is(err, ErrNotFound) {
			httpserver.WriteError(w, r, http.StatusNotFound,
				httpserver.ErrNotFound, "session not found")
			return
		}
		h.internalError(w, r, err)
		return
	}
	if id == p.Session.ID {
		http.SetCookie(w, &http.Cookie{
			Name: sessionCookieName, Value: "", Path: "/",
			HttpOnly: true, Secure: h.secure,
			SameSite: http.SameSiteLaxMode, MaxAge: -1,
		})
	}
	w.WriteHeader(http.StatusNoContent)
}

// reauth verifies the current password and stamps recent_auth_at on
// this session — the step-up receipt for sensitive actions. The body
// carries only {password}; the session cookie supplies identity.
func (h *Handler) reauth(w http.ResponseWriter, r *http.Request) {
	p, ok := PrincipalFromContext(r.Context())
	if !ok {
		httpserver.WriteError(w, r, http.StatusUnauthorized,
			httpserver.ErrUnauth, "authentication required")
		return
	}
	var in struct {
		Password string `json:"password"`
	}
	if apiErr := httpserver.DecodeJSON(w, r, &in, h.maxBody); apiErr != nil {
		httpserver.WriteErrorFields(w, r, apiErr.Status, apiErr.Code, apiErr.Msg, apiErr.Fields)
		return
	}
	err := h.svc.Reauthenticate(r.Context(), p, in.Password)
	switch {
	case err == nil:
		httpserver.WriteJSON(w, r, http.StatusOK, map[string]any{
			"reauthenticated_until": time.Now().Add(RecentAuthTTL).UTC(),
		})
	default:
		var rl *RateLimitedError
		switch {
		case errors.As(err, &rl):
			w.Header().Set("Retry-After",
				strconv.Itoa(int(rl.RetryAfter.Seconds())+1))
			httpserver.WriteError(w, r, http.StatusTooManyRequests,
				httpserver.ErrRateLimited, "too many attempts")
		case errors.Is(err, ErrBadCredentials), errors.Is(err, ErrInvalidSession):
			// Uniform 401 — wrong password and dead session are
			// indistinguishable on the wire.
			httpserver.WriteError(w, r, http.StatusUnauthorized,
				httpserver.ErrUnauth, "invalid credentials")
		default:
			h.internalError(w, r, err)
		}
	}
}

// revokeAllOwnSessions ends every session the caller holds. Requires
// recent authentication; clears the current cookie on success.
func (h *Handler) revokeAllOwnSessions(w http.ResponseWriter, r *http.Request) {
	p, ok := PrincipalFromContext(r.Context())
	if !ok {
		httpserver.WriteError(w, r, http.StatusUnauthorized,
			httpserver.ErrUnauth, "authentication required")
		return
	}
	n, err := h.svc.RevokeAllOwnSessions(r.Context(), p)
	switch {
	case err == nil:
		http.SetCookie(w, &http.Cookie{
			Name: sessionCookieName, Value: "", Path: "/",
			HttpOnly: true, Secure: h.secure,
			SameSite: http.SameSiteLaxMode, MaxAge: -1,
		})
		httpserver.WriteJSON(w, r, http.StatusOK, map[string]any{
			"revoked_count": n,
		})
	case errors.Is(err, ErrReauthRequired):
		httpserver.WriteError(w, r, http.StatusForbidden,
			httpserver.ErrReauth, "recent authentication required")
	case errors.Is(err, ErrInvalidSession):
		httpserver.WriteError(w, r, http.StatusUnauthorized,
			httpserver.ErrUnauth, "authentication required")
	default:
		h.internalError(w, r, err)
	}
}
