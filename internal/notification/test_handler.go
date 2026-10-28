package notification

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/auth"
	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/platform/httpserver"
)

// recentAuthTTL mirrors admin.RecentAuthTTL — the step-up window the
// own-test route enforces before persisting a TEST intent.
const recentAuthTTL = 5 * time.Minute

var errRecentAuthRequired = errors.New("recent authentication required")

// TestHandler exposes the owner-scoped channel test route: POST
// /notification-channels/{id}/test queues ONE TEST intent for a
// monitor the caller owns and the channel is bound to — 202 means
// queued intent, never provider confirmation. Composition:
// RequireSession → CSRF → recent-auth gate → eligibility fence →
// persist. Admin capabilities are a separate surface entirely.
type TestHandler struct {
	ops   *Operations
	auth  AuthGate
	csrf  *auth.CSRFManager
	rate  TestRate
	log   *slog.Logger
	maxIn int64
}

// NewTestHandler wires the own-test route. The actor fence, recent-auth read
// and intent write share the AuthGate transaction.
func NewTestHandler(ops *Operations, gate AuthGate, csrf *auth.CSRFManager, rate TestRate,
	maxBody int64, log *slog.Logger) *TestHandler {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &TestHandler{ops: ops, auth: gate, csrf: csrf,
		rate: rate, log: log, maxIn: maxBody}
}

// Mux returns just the test route — the composition root mounts it
// at the exact /notification-channels/{id}/test pattern, which is
// more specific than the channel subtree mount.
func (h *TestHandler) Mux() *http.ServeMux {
	mux := http.NewServeMux()
	session := h.auth.RequireSession
	guard := func(fn http.HandlerFunc) http.HandlerFunc {
		if h.csrf != nil {
			return h.csrf.RequireCSRF(session(fn))
		}
		return session(fn)
	}
	mux.HandleFunc("POST /notification-channels/{id}/test", guard(h.test))
	for _, m := range []string{"GET", "PUT", "PATCH", "DELETE"} {
		mux.HandleFunc(m+" /notification-channels/{id}/test",
			h.methodNotAllowed("POST"))
	}
	return mux
}

func (h *TestHandler) methodNotAllowed(allow string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Allow", allow)
		httpserver.WriteError(w, r, http.StatusMethodNotAllowed,
			httpserver.ErrMethod, "method not allowed")
	}
}

// testInput is the bounded request — the monitor the TEST targets.
type testInput struct {
	MonitorID uuid.UUID `json:"monitor_id"`
}

// requireRecentAuth verifies the caller's own session carries a
// recent password authentication inside the TTL. WithActorLock already holds
// the user and session locks, keeping this read and the intent in one fence.
func (h *TestHandler) requireRecentAuth(ctx context.Context, tx pgx.Tx,
	sessionID uuid.UUID) error {
	var recent *time.Time
	err := tx.QueryRow(ctx, `
		SELECT recent_auth_at FROM uptime.sessions WHERE id=$1`,
		sessionID).Scan(&recent)
	if err != nil || recent == nil ||
		time.Since(*recent) > recentAuthTTL ||
		recent.After(time.Now().Add(time.Minute)) {
		return errRecentAuthRequired
	}
	return nil
}

func (h *TestHandler) test(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFromContext(r.Context())
	channelID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpserver.WriteError(w, r, http.StatusBadRequest,
			httpserver.ErrBadRequest, "invalid channel id")
		return
	}
	var in testInput
	if apiErr := httpserver.DecodeJSON(w, r, &in, h.maxIn); apiErr != nil {
		httpserver.WriteError(w, r, apiErr.Status, apiErr.Code, apiErr.Msg)
		return
	}
	if in.MonitorID == uuid.Nil {
		httpserver.WriteError(w, r, http.StatusBadRequest,
			httpserver.ErrBadRequest, "monitor_id required")
		return
	}
	var intentID uuid.UUID
	err = h.auth.WithActorLock(r.Context(), p, func(tx pgx.Tx, u auth.User) error {
		if err := h.requireRecentAuth(r.Context(), tx, p.Session.ID); err != nil {
			return err
		}
		var err error
		intentID, err = h.ops.QueueTestNotificationTx(r.Context(), tx,
			u.ID, in.MonitorID, channelID, h.rate)
		return err
	})
	switch {
	case err == nil:
		httpserver.WriteJSON(w, r, http.StatusAccepted, map[string]any{
			"intent_id": intentID.String(), "state": "PENDING",
			"queued": true,
		})
	case errors.Is(err, ErrDuplicateTest):
		// Same window, same pair — the persisted intent stands.
		httpserver.WriteJSON(w, r, http.StatusOK, map[string]any{
			"deduplicated": true, "queued": true,
		})
	case errors.Is(err, ErrRateLimited):
		httpserver.WriteError(w, r, http.StatusTooManyRequests,
			httpserver.ErrRateLimited, "test notification rate limit")
	case errors.Is(err, auth.ErrInvalidSession), errors.Is(err, auth.ErrNotFound):
		httpserver.WriteError(w, r, http.StatusUnauthorized,
			httpserver.ErrUnauth, "authentication required")
	case errors.Is(err, errRecentAuthRequired):
		httpserver.WriteError(w, r, http.StatusForbidden,
			httpserver.ErrReauth, "recent authentication required")
	case errors.Is(err, ErrNotOwned):
		httpserver.WriteError(w, r, http.StatusNotFound,
			httpserver.ErrNotFound, "monitor or channel not found")
	case errors.Is(err, ErrChannelNotBound):
		httpserver.WriteError(w, r, http.StatusConflict,
			httpserver.ErrConflict, "channel is not bound to the monitor")
	case errors.Is(err, ErrChannelIneligible), errors.Is(err, ErrNotDeliverable):
		httpserver.WriteError(w, r, http.StatusConflict,
			httpserver.ErrConflict, "channel is not a verified enabled recipient")
	default:
		h.log.Error("test notification failed", "err", err)
		httpserver.WriteError(w, r, http.StatusInternalServerError,
			httpserver.ErrInternal, "internal error")
	}
}
