package notification

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/auth"
	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/platform/httpserver"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// HandlerConfig wires transport policy into the channel handler.
type HandlerConfig struct {
	MaxJSONBody int64
	CSRF        *auth.CSRFManager
	Logger      *slog.Logger
}

// AuthGate mirrors the monitor seam — *auth.Service satisfies it.
type AuthGate interface {
	RequireSession(next http.HandlerFunc) http.HandlerFunc
	WithActorLock(ctx context.Context, p auth.Principal, fn func(tx pgx.Tx, u auth.User) error) error
}

// Handler exposes owner-scoped notification channels. Browser routes
// manage metadata ONLY: the only writable state a request can reach
// is label/status lifecycle — destination verification is an
// operator-CLI flow by design (no chat id, token, or ciphertext ever
// crosses a browser request).
type Handler struct {
	svc     *Service
	auth    AuthGate
	csrf    *auth.CSRFManager
	maxBody int64
	log     *slog.Logger
}

func NewHandler(svc *Service, gate AuthGate, cfg HandlerConfig) *Handler {
	l := cfg.Logger
	if l == nil {
		l = slog.New(slog.DiscardHandler)
	}
	return &Handler{svc: svc, auth: gate, csrf: cfg.CSRF,
		maxBody: cfg.MaxJSONBody, log: l}
}

// Mux returns the channel route table, mounted under BOTH the bare
// collection and the subtree (no trailing-slash redirect on POST).
func (h *Handler) Mux() *http.ServeMux {
	mux := http.NewServeMux()
	session := h.auth.RequireSession
	guard := func(fn http.HandlerFunc) http.HandlerFunc {
		if h.csrf != nil {
			return h.csrf.RequireCSRF(session(fn))
		}
		return session(fn)
	}
	for _, path := range []string{"/notification-channels", "/notification-channels/{$}"} {
		mux.HandleFunc("POST "+path, guard(h.create))
		mux.HandleFunc("GET "+path, session(h.list))
	}
	mux.HandleFunc("GET /notification-channels/{id}", session(h.get))
	mux.HandleFunc("DELETE /notification-channels/{id}", guard(h.del))
	mux.HandleFunc("POST /notification-channels/{id}/disable", guard(h.disable))

	for _, path := range []string{"/notification-channels", "/notification-channels/{$}"} {
		for _, method := range []string{"PUT", "PATCH", "DELETE"} {
			mux.HandleFunc(method+" "+path, h.methodNotAllowed("GET, POST"))
		}
	}
	for _, method := range []string{"POST", "PUT", "PATCH"} {
		mux.HandleFunc(method+" /notification-channels/{id}", h.methodNotAllowed("GET, DELETE"))
	}
	for _, method := range []string{"GET", "PUT", "PATCH", "DELETE"} {
		mux.HandleFunc(method+" /notification-channels/{id}/disable", h.methodNotAllowed("POST"))
	}
	mux.HandleFunc("/", h.notFound)
	return mux
}

func (h *Handler) notFound(w http.ResponseWriter, r *http.Request) {
	httpserver.WriteError(w, r, http.StatusNotFound,
		httpserver.ErrNotFound, "route not found")
}

func (h *Handler) methodNotAllowed(allow string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Allow", allow)
		httpserver.WriteError(w, r, http.StatusMethodNotAllowed,
			httpserver.ErrMethod, "method not allowed")
	}
}

func (h *Handler) internalError(w http.ResponseWriter, r *http.Request, err error) {
	h.log.Error("channel internal error",
		"request_id", httpserver.RequestIDFromContext(r.Context()),
		"route", r.Pattern, "err", err)
	httpserver.WriteError(w, r, http.StatusInternalServerError,
		httpserver.ErrInternal, "internal error")
}

// channelDTO is the serialized channel — ciphertext and the operator
// verification receipt never leave the service boundary.
type channelDTO struct {
	ID              uuid.UUID  `json:"id"`
	Label           string     `json:"label"`
	Kind            string     `json:"kind"`
	Status          string     `json:"status"`
	Enabled         bool       `json:"enabled"`
	DestinationMask *string    `json:"destination_mask"`
	VerifiedAt      *time.Time `json:"verified_at"`
	Version         int64      `json:"version"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

func toDTO(c Channel) channelDTO {
	return channelDTO{
		ID: c.ID, Label: c.Label, Kind: c.Kind, Status: c.Status,
		Enabled: c.Enabled, DestinationMask: c.DestinationMask,
		VerifiedAt: c.VerifiedAt, Version: c.Version,
		CreatedAt: c.CreatedAt, UpdatedAt: c.UpdatedAt,
	}
}

func (h *Handler) writeChannelError(w http.ResponseWriter, r *http.Request, err error) {
	var fe *FieldError
	switch {
	case errors.As(err, &fe):
		httpserver.WriteErrorFields(w, r, http.StatusUnprocessableEntity,
			httpserver.ErrValidation, "validation failed", fe.Fields)
	case errors.Is(err, ErrChannelNotFound):
		httpserver.WriteError(w, r, http.StatusNotFound,
			httpserver.ErrNotFound, "channel not found")
	case errors.Is(err, ErrVersionConflict):
		httpserver.WriteError(w, r, http.StatusConflict,
			httpserver.ErrConflict, "stale version — re-read and retry")
	case errors.Is(err, ErrPendingQuota):
		httpserver.WriteErrorFields(w, r, http.StatusConflict,
			httpserver.ErrAllocation, "pending channel limit reached",
			map[string]string{"scope": "pending_channels"})
	case errors.Is(err, ErrRetainedQuota):
		httpserver.WriteErrorFields(w, r, http.StatusConflict,
			httpserver.ErrAllocation, "channel allocation limit reached",
			map[string]string{"scope": "channels"})
	case errors.Is(err, ErrBudgetMissing):
		httpserver.WriteError(w, r, http.StatusServiceUnavailable,
			httpserver.ErrUnavailable, "service not initialized")
	case errors.Is(err, ErrActorInactive) || errors.Is(err, auth.ErrInvalidSession):
		httpserver.WriteError(w, r, http.StatusUnauthorized,
			httpserver.ErrUnauth, "authentication required")
	default:
		h.internalError(w, r, err)
	}
}

func owner(r *http.Request) auth.Principal {
	p, _ := auth.PrincipalFromContext(r.Context())
	return p
}

func channelID(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpserver.WriteError(w, r, http.StatusNotFound,
			httpserver.ErrNotFound, "channel not found")
		return uuid.Nil, false
	}
	return id, true
}

func (h *Handler) create(w http.ResponseWriter, r *http.Request) {
	p := owner(r)
	var in CreateInput
	if apiErr := httpserver.DecodeJSON(w, r, &in, h.maxBody); apiErr != nil {
		httpserver.WriteErrorFields(w, r, apiErr.Status, apiErr.Code, apiErr.Msg, apiErr.Fields)
		return
	}
	var c Channel
	err := h.auth.WithActorLock(r.Context(), p, func(tx pgx.Tx, u auth.User) error {
		var cerr error
		c, cerr = h.svc.CreateTx(r.Context(), tx, u.ID, in)
		return cerr
	})
	if err != nil {
		h.writeChannelError(w, r, err)
		return
	}
	w.Header().Set("Location", "/notification-channels/"+c.ID.String())
	httpserver.WriteJSON(w, r, http.StatusCreated, toDTO(c))
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	p := owner(r)
	cs, err := h.svc.List(r.Context(), p.User.ID, 100)
	if err != nil {
		h.writeChannelError(w, r, err)
		return
	}
	items := []channelDTO{}
	for _, c := range cs {
		items = append(items, toDTO(c))
	}
	httpserver.WriteJSON(w, r, http.StatusOK, map[string]any{"items": items})
}

func (h *Handler) get(w http.ResponseWriter, r *http.Request) {
	p := owner(r)
	id, ok := channelID(w, r)
	if !ok {
		return
	}
	c, err := h.svc.Get(r.Context(), p.User.ID, id)
	if err != nil {
		h.writeChannelError(w, r, err)
		return
	}
	httpserver.WriteJSON(w, r, http.StatusOK, toDTO(c))
}

type versionBody struct {
	ExpectedVersion int64 `json:"expected_version"`
}

func (h *Handler) del(w http.ResponseWriter, r *http.Request) {
	p := owner(r)
	id, ok := channelID(w, r)
	if !ok {
		return
	}
	var in versionBody
	if apiErr := httpserver.DecodeJSON(w, r, &in, h.maxBody); apiErr != nil {
		httpserver.WriteErrorFields(w, r, apiErr.Status, apiErr.Code, apiErr.Msg, apiErr.Fields)
		return
	}
	if in.ExpectedVersion < 1 {
		httpserver.WriteErrorFields(w, r, http.StatusUnprocessableEntity,
			httpserver.ErrValidation, "validation failed",
			map[string]string{"expected_version": "required"})
		return
	}
	err := h.auth.WithActorLock(r.Context(), p, func(tx pgx.Tx, u auth.User) error {
		return h.svc.DeleteTx(r.Context(), tx, u.ID, id, in.ExpectedVersion)
	})
	if err != nil {
		h.writeChannelError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) disable(w http.ResponseWriter, r *http.Request) {
	p := owner(r)
	id, ok := channelID(w, r)
	if !ok {
		return
	}
	var in versionBody
	if apiErr := httpserver.DecodeJSON(w, r, &in, h.maxBody); apiErr != nil {
		httpserver.WriteErrorFields(w, r, apiErr.Status, apiErr.Code, apiErr.Msg, apiErr.Fields)
		return
	}
	if in.ExpectedVersion < 1 {
		httpserver.WriteErrorFields(w, r, http.StatusUnprocessableEntity,
			httpserver.ErrValidation, "validation failed",
			map[string]string{"expected_version": "required"})
		return
	}
	var c Channel
	err := h.auth.WithActorLock(r.Context(), p, func(tx pgx.Tx, u auth.User) error {
		var cerr error
		c, cerr = h.svc.DisableTx(r.Context(), tx, u.ID, id, in.ExpectedVersion)
		return cerr
	})
	if err != nil {
		h.writeChannelError(w, r, err)
		return
	}
	httpserver.WriteJSON(w, r, http.StatusOK, toDTO(c))
}
