package monitor

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

// HandlerConfig wires transport policy into the monitor handler.
type HandlerConfig struct {
	MaxJSONBody int64
	CSRF        *auth.CSRFManager // required in production wiring
	Logger      *slog.Logger      // nil-safe
	// ChannelEligibility validates bind sets inside the binding
	// transaction — cmd/api injects notification.EligibleChannelIDs.
	ChannelEligibility ChannelEligibility
}

// AuthGate is the authentication+lock seam the handler needs —
// *auth.Service satisfies it. Session middleware injects the principal;
// WithActorLock fences mutations. Unit tests substitute a fake that
// injects a principal and runs the closure with a nil tx (the fake
// store's Tx methods accept it).
type AuthGate interface {
	RequireSession(next http.HandlerFunc) http.HandlerFunc
	WithActorLock(ctx context.Context, p auth.Principal, fn func(tx pgx.Tx, u auth.User) error) error
}

// Handler exposes owner-scoped monitor resources. Authentication is
// the shared session middleware; every mutation additionally composes
// under WithActorLock, so a session revoked or actor disabled
// between request start and commit still fails the write — the
// context principal is only a snapshot.
type Handler struct {
	svc      *Service
	auth     AuthGate
	csrf     *auth.CSRFManager
	maxBody  int64
	log      *slog.Logger
	eligible ChannelEligibility
}

func NewHandler(svc *Service, gate AuthGate, cfg HandlerConfig) *Handler {
	l := cfg.Logger
	if l == nil {
		l = slog.New(slog.DiscardHandler)
	}
	return &Handler{svc: svc, auth: gate, csrf: cfg.CSRF,
		maxBody: cfg.MaxJSONBody, log: l, eligible: cfg.ChannelEligibility}
}

// Mux returns the monitor route table. The composition root mounts it
// under BOTH "/monitors" and "/monitors/" so the bare collection never
// hits a ServeMux trailing-slash redirect on POST (NOW-3). No-method
// twins + the catch-all keep 404/405 inside the JSON envelope.
func (h *Handler) Mux() *http.ServeMux {
	mux := http.NewServeMux()
	session := h.auth.RequireSession
	guard := func(fn http.HandlerFunc) http.HandlerFunc {
		if h.csrf != nil {
			return h.csrf.RequireCSRF(session(fn))
		}
		return session(fn)
	}
	// {$} anchors the pattern to the exact path — a bare trailing-slash
	// pattern would be a subtree that swallows /monitors/{id} traffic.
	for _, path := range []string{"/monitors", "/monitors/{$}"} {
		mux.HandleFunc("POST "+path, guard(h.create))
		mux.HandleFunc("GET "+path, session(h.list))
	}
	mux.HandleFunc("GET /monitors/{id}", session(h.get))
	mux.HandleFunc("PATCH /monitors/{id}", guard(h.patch))
	mux.HandleFunc("DELETE /monitors/{id}", guard(h.del))
	mux.HandleFunc("POST /monitors/{id}/pause", guard(h.transition(true)))
	mux.HandleFunc("POST /monitors/{id}/resume", guard(h.transition(false)))
	mux.HandleFunc("PUT /monitors/{id}/notification-channels", guard(h.bindChannels))

	// Method twins on exact paths keep 405 inside the envelope.
	for _, path := range []string{"/monitors", "/monitors/{$}"} {
		for _, method := range []string{"PUT", "PATCH", "DELETE"} {
			mux.HandleFunc(method+" "+path, h.methodNotAllowed("GET, POST"))
		}
	}
	for _, method := range []string{"POST", "PUT"} {
		mux.HandleFunc(method+" /monitors/{id}", h.methodNotAllowed("GET, PATCH, DELETE"))
	}
	for _, p := range []string{"/monitors/{id}/pause", "/monitors/{id}/resume"} {
		for _, method := range []string{"GET", "PUT", "PATCH", "DELETE"} {
			mux.HandleFunc(method+" "+p, h.methodNotAllowed("POST"))
		}
	}
	for _, method := range []string{"GET", "POST", "PATCH", "DELETE"} {
		mux.HandleFunc(method+" /monitors/{id}/notification-channels",
			h.methodNotAllowed("PUT"))
	}
	mux.HandleFunc("/", h.notFound)
	return mux
}

func (h *Handler) methodNotAllowed(allow string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Allow", allow)
		httpserver.WriteError(w, r, http.StatusMethodNotAllowed,
			httpserver.ErrMethod, "method not allowed")
	}
}

func (h *Handler) notFound(w http.ResponseWriter, r *http.Request) {
	httpserver.WriteError(w, r, http.StatusNotFound,
		httpserver.ErrNotFound, "route not found")
}

func (h *Handler) internalError(w http.ResponseWriter, r *http.Request, err error) {
	h.log.Error("monitor internal error",
		"request_id", httpserver.RequestIDFromContext(r.Context()),
		"route", r.Pattern, "err", err)
	httpserver.WriteError(w, r, http.StatusInternalServerError,
		httpserver.ErrInternal, "internal error")
}

// monitorDTO is the serialized monitor per the API contract: safe
// config plus engine-owned fields the client may read but never set.
// freshness stays null until check samples exist (engine phases).
type monitorDTO struct {
	ID                 uuid.UUID  `json:"id"`
	Name               string     `json:"name"`
	TargetURL          string     `json:"target_url"`
	Method             string     `json:"method"`
	IntervalSeconds    int        `json:"interval_seconds"`
	TimeoutSeconds     int        `json:"timeout_seconds"`
	ExpectedStatus     *int       `json:"expected_status"`
	IsPaused           bool       `json:"is_paused"`
	Health             string     `json:"health"`
	Generation         int64      `json:"generation"`
	NextCheckAt        time.Time  `json:"next_check_at"`
	LastCheckedAt      *time.Time `json:"last_checked_at"`
	LastResponseTimeMs *int64     `json:"last_response_time_ms"`
	LastErrorType      *string    `json:"last_error_type"`
	Freshness          *string    `json:"freshness"`
	CreatedAt          time.Time  `json:"created_at"`
	UpdatedAt          time.Time  `json:"updated_at"`
}

func toDTO(m Monitor) monitorDTO {
	return monitorDTO{
		ID: m.ID, Name: m.Name, TargetURL: m.TargetURL, Method: m.Method,
		IntervalSeconds: m.IntervalSeconds, TimeoutSeconds: m.TimeoutSeconds,
		ExpectedStatus: m.ExpectedStatus, IsPaused: m.IsPaused,
		Health: m.Health, Generation: m.Generation,
		NextCheckAt: m.NextCheckAt, LastCheckedAt: m.LastCheckedAt,
		LastResponseTimeMs: m.LastResponseTimeMs,
		LastErrorType:      m.LastErrorType,
		CreatedAt:          m.CreatedAt, UpdatedAt: m.UpdatedAt,
	}
}

// writeMonitorError is the single sentinel→envelope mapping. Scope
// discriminators are the contract-safe values from spec-04: they tell
// the client WHICH cap bound without leaking global counts.
func (h *Handler) writeMonitorError(w http.ResponseWriter, r *http.Request, err error) {
	var fe *FieldError
	switch {
	case errors.As(err, &fe):
		httpserver.WriteErrorFields(w, r, http.StatusUnprocessableEntity,
			httpserver.ErrValidation, "validation failed", fe.Fields)
	case errors.Is(err, ErrCursor):
		httpserver.WriteError(w, r, http.StatusBadRequest,
			httpserver.ErrBadRequest, "invalid cursor")
	case errors.Is(err, ErrChannelIneligible):
		httpserver.WriteError(w, r, http.StatusUnprocessableEntity,
			httpserver.ErrValidation, "one or more channels not eligible")
	case errors.Is(err, ErrMonitorNotFound):
		httpserver.WriteError(w, r, http.StatusNotFound,
			httpserver.ErrNotFound, "monitor not found")
	case errors.Is(err, ErrGenerationConflict):
		httpserver.WriteError(w, r, http.StatusConflict,
			httpserver.ErrConflict, "stale generation — re-read and retry")
	case errors.Is(err, ErrQuotaOwner):
		httpserver.WriteErrorFields(w, r, http.StatusConflict,
			httpserver.ErrQuota, "monitor limit reached",
			map[string]string{"scope": "owner_monitor_limit"})
	case errors.Is(err, ErrQuotaGlobal):
		httpserver.WriteErrorFields(w, r, http.StatusConflict,
			httpserver.ErrQuota, "monitor limit reached",
			map[string]string{"scope": "platform_admission"})
	case errors.Is(err, ErrQuotaRetained):
		httpserver.WriteErrorFields(w, r, http.StatusConflict,
			httpserver.ErrAllocation, "monitor allocation limit reached",
			map[string]string{"scope": "monitors"})
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

// owner extracts the session principal — guaranteed present because
// every route runs behind RequireSession.
func owner(r *http.Request) auth.Principal {
	p, _ := auth.PrincipalFromContext(r.Context())
	return p
}

// monitorID parses the path id; a malformed UUID collapses to the
// same 404 as a missing row (no shape oracle).
func monitorID(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpserver.WriteError(w, r, http.StatusNotFound,
			httpserver.ErrNotFound, "monitor not found")
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
	var m Monitor
	err := h.auth.WithActorLock(r.Context(), p, func(tx pgx.Tx, u auth.User) error {
		var cerr error
		m, cerr = h.svc.CreateTx(r.Context(), tx, u.ID, u.MonitorLimit, in)
		return cerr
	})
	if err != nil {
		h.writeMonitorError(w, r, err)
		return
	}
	w.Header().Set("Location", "/monitors/"+m.ID.String())
	httpserver.WriteJSON(w, r, http.StatusCreated, toDTO(m))
}

// listPage is the collection envelope: items plus the keyset resume
// token. next_cursor is null when has_more is false.
type listPage struct {
	Items      []monitorDTO `json:"items"`
	HasMore    bool         `json:"has_more"`
	NextCursor *string      `json:"next_cursor"`
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	p := owner(r)
	pr, err := ParsePageRequest(r.URL.Query())
	if err != nil {
		h.writeMonitorError(w, r, err)
		return
	}
	// limit+1 distinguishes "exactly a page left" from "more pages".
	rows, err := h.svc.List(r.Context(), p.User.ID, pr.After, pr.Filter, pr.Limit+1)
	if err != nil {
		h.writeMonitorError(w, r, err)
		return
	}
	page := listPage{Items: []monitorDTO{}}
	if len(rows) > pr.Limit {
		page.HasMore = true
		rows = rows[:pr.Limit]
	}
	for _, m := range rows {
		page.Items = append(page.Items, toDTO(m))
	}
	if page.HasMore {
		nc := EncodeCursor(rows[len(rows)-1], pr.Filter)
		page.NextCursor = &nc
	}
	httpserver.WriteJSON(w, r, http.StatusOK, page)
}

func (h *Handler) get(w http.ResponseWriter, r *http.Request) {
	p := owner(r)
	id, ok := monitorID(w, r)
	if !ok {
		return
	}
	m, err := h.svc.Get(r.Context(), p.User.ID, id)
	if err != nil {
		h.writeMonitorError(w, r, err)
		return
	}
	httpserver.WriteJSON(w, r, http.StatusOK, toDTO(m))
}

// patchRequest carries the patch fields plus the mandatory optimistic
// fence — expected_generation is a body field per the API contract.
type patchRequest struct {
	PatchInput
	ExpectedGeneration int64 `json:"expected_generation"`
}

type generationBody struct {
	ExpectedGeneration int64 `json:"expected_generation"`
}

func (h *Handler) patch(w http.ResponseWriter, r *http.Request) {
	p := owner(r)
	id, ok := monitorID(w, r)
	if !ok {
		return
	}
	var in patchRequest
	if apiErr := httpserver.DecodeJSON(w, r, &in, h.maxBody); apiErr != nil {
		httpserver.WriteErrorFields(w, r, apiErr.Status, apiErr.Code, apiErr.Msg, apiErr.Fields)
		return
	}
	if in.ExpectedGeneration < 1 {
		httpserver.WriteErrorFields(w, r, http.StatusUnprocessableEntity,
			httpserver.ErrValidation, "validation failed",
			map[string]string{"expected_generation": "required"})
		return
	}
	stored, err := h.svc.Get(r.Context(), p.User.ID, id)
	if err != nil {
		h.writeMonitorError(w, r, err)
		return
	}
	merged, err := MergePatch(stored, in.PatchInput)
	if err != nil {
		h.writeMonitorError(w, r, err)
		return
	}
	var out Monitor
	err = h.auth.WithActorLock(r.Context(), p, func(tx pgx.Tx, u auth.User) error {
		var cerr error
		out, cerr = h.svc.UpdateTx(r.Context(), tx, u.ID, id,
			in.ExpectedGeneration, merged)
		return cerr
	})
	if err != nil {
		h.writeMonitorError(w, r, err)
		return
	}
	httpserver.WriteJSON(w, r, http.StatusOK, toDTO(out))
}

// transition returns the pause/resume handler. The body carries only
// expected_generation — the fence and the idempotent same-state no-op
// live in the repository mutation, so both verbs share one shape.
func (h *Handler) transition(paused bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p := owner(r)
		id, ok := monitorID(w, r)
		if !ok {
			return
		}
		var in generationBody
		if apiErr := httpserver.DecodeJSON(w, r, &in, h.maxBody); apiErr != nil {
			httpserver.WriteErrorFields(w, r, apiErr.Status, apiErr.Code, apiErr.Msg, apiErr.Fields)
			return
		}
		if in.ExpectedGeneration < 1 {
			httpserver.WriteErrorFields(w, r, http.StatusUnprocessableEntity,
				httpserver.ErrValidation, "validation failed",
				map[string]string{"expected_generation": "required"})
			return
		}
		var out Monitor
		var err error
		err = h.auth.WithActorLock(r.Context(), p, func(tx pgx.Tx, u auth.User) error {
			var cerr error
			if paused {
				out, cerr = h.svc.PauseTx(r.Context(), tx, u.ID, id, in.ExpectedGeneration)
			} else {
				out, cerr = h.svc.ResumeTx(r.Context(), tx, u.ID, id, in.ExpectedGeneration)
			}
			return cerr
		})
		if err != nil {
			h.writeMonitorError(w, r, err)
			return
		}
		httpserver.WriteJSON(w, r, http.StatusOK, toDTO(out))
	}
}

// bindBody is the PUT contract: full replacement under the
// generation fence (RT F11). Duplicate ids collapse server-side;
// an empty set is a legitimate unbind.
type bindBody struct {
	ExpectedGeneration int64    `json:"expected_generation"`
	ChannelIDs         []string `json:"channel_ids"`
}

func (h *Handler) bindChannels(w http.ResponseWriter, r *http.Request) {
	p := owner(r)
	id, ok := monitorID(w, r)
	if !ok {
		return
	}
	var in bindBody
	if apiErr := httpserver.DecodeJSON(w, r, &in, h.maxBody); apiErr != nil {
		httpserver.WriteErrorFields(w, r, apiErr.Status, apiErr.Code, apiErr.Msg, apiErr.Fields)
		return
	}
	fields := map[string]string{}
	if in.ExpectedGeneration < 1 {
		fields["expected_generation"] = "required"
	}
	seen := map[uuid.UUID]bool{}
	ids := make([]uuid.UUID, 0, len(in.ChannelIDs))
	for _, raw := range in.ChannelIDs {
		cid, err := uuid.Parse(raw)
		if err != nil {
			fields["channel_ids"] = "must be UUIDs"
			break
		}
		if !seen[cid] {
			seen[cid] = true
			ids = append(ids, cid)
		}
	}
	if len(fields) > 0 {
		httpserver.WriteErrorFields(w, r, http.StatusUnprocessableEntity,
			httpserver.ErrValidation, "validation failed", fields)
		return
	}
	if h.eligible == nil {
		h.internalError(w, r, errors.New("channel eligibility not wired"))
		return
	}
	var out Monitor
	err := h.auth.WithActorLock(r.Context(), p, func(tx pgx.Tx, u auth.User) error {
		var cerr error
		out, cerr = h.svc.BindChannelsTx(r.Context(), tx, u.ID, id,
			in.ExpectedGeneration, ids, h.eligible)
		return cerr
	})
	if err != nil {
		h.writeMonitorError(w, r, err)
		return
	}
	bound := make([]string, 0, len(ids))
	for _, cid := range ids {
		bound = append(bound, cid.String())
	}
	httpserver.WriteJSON(w, r, http.StatusOK, map[string]any{
		"monitor_id":  out.ID,
		"generation":  out.Generation,
		"channel_ids": bound,
	})
}

func (h *Handler) del(w http.ResponseWriter, r *http.Request) {
	p := owner(r)
	id, ok := monitorID(w, r)
	if !ok {
		return
	}
	var in generationBody
	if apiErr := httpserver.DecodeJSON(w, r, &in, h.maxBody); apiErr != nil {
		httpserver.WriteErrorFields(w, r, apiErr.Status, apiErr.Code, apiErr.Msg, apiErr.Fields)
		return
	}
	if in.ExpectedGeneration < 1 {
		httpserver.WriteErrorFields(w, r, http.StatusUnprocessableEntity,
			httpserver.ErrValidation, "validation failed",
			map[string]string{"expected_generation": "required"})
		return
	}
	err := h.auth.WithActorLock(r.Context(), p, func(tx pgx.Tx, u auth.User) error {
		return h.svc.DeleteTx(r.Context(), tx, u.ID, id, in.ExpectedGeneration)
	})
	if err != nil {
		h.writeMonitorError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
