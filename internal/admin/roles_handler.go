package admin

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/auth"
	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/platform/httpserver"
)

// ErrCodeLastSuperAdmin is the contract's 409 code for the
// final-superadmin invariant.
const ErrCodeLastSuperAdmin httpserver.ErrCode = "LAST_SUPERADMIN"

// RoleAuthGate is the session+CSRF seam the admin handler needs —
// *auth.Service supplies RequireSession; tests substitute a fake.
type RoleAuthGate interface {
	RequireSession(next http.HandlerFunc) http.HandlerFunc
}

// RolesHandler exposes the role catalog and bounded role mutations.
// Every mutation composes session → CSRF → step-up → idempotent tx;
// the context principal is only a snapshot — authorization is
// re-derived under the security anchor inside each guarded recipe.
type RolesHandler struct {
	conn     Beginner
	auth     RoleAuthGate
	csrf     *auth.CSRFManager
	maxBody  int64
	log      *slog.Logger
	now      func() time.Time
	ceilings QuotaCeilings
}

// NewRolesHandler wires the role-management route table.
func NewRolesHandler(conn Beginner, gate RoleAuthGate,
	csrf *auth.CSRFManager, maxBody int64, ceilings QuotaCeilings,
	log *slog.Logger) *RolesHandler {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &RolesHandler{conn: conn, auth: gate, csrf: csrf,
		maxBody: maxBody, log: log, now: time.Now, ceilings: ceilings}
}

// Mux returns the admin role-management routes. The composition root
// mounts this under /admin/.
func (h *RolesHandler) Mux() *http.ServeMux {
	mux := http.NewServeMux()
	session := h.auth.RequireSession
	guard := func(fn http.HandlerFunc) http.HandlerFunc {
		if h.csrf != nil {
			return h.csrf.RequireCSRF(session(fn))
		}
		return session(fn)
	}
	for _, path := range []string{"/admin/roles", "/admin/roles/{$}"} {
		mux.HandleFunc("GET "+path, session(h.list))
		mux.HandleFunc("POST "+path, guard(h.create))
		for _, m := range []string{"PUT", "PATCH", "DELETE"} {
			mux.HandleFunc(m+" "+path, h.methodNotAllowed("GET, POST"))
		}
	}
	mux.HandleFunc("PATCH /admin/roles/{id}", guard(h.update))
	for _, m := range []string{"GET", "POST", "PUT", "DELETE"} {
		mux.HandleFunc(m+" /admin/roles/{id}", h.methodNotAllowed("PATCH"))
	}
	mux.HandleFunc("PUT /admin/users/{id}/roles", guard(h.assign))
	for _, m := range []string{"GET", "POST", "PATCH", "DELETE"} {
		mux.HandleFunc(m+" /admin/users/{id}/roles", h.methodNotAllowed("PUT"))
	}
	mux.HandleFunc("POST /admin/users/{id}/suspend", guard(h.suspend))
	mux.HandleFunc("POST /admin/users/{id}/restore", guard(h.restore))
	mux.HandleFunc("POST /admin/users/{id}/revoke-sessions", guard(h.revokeSessions))
	mux.HandleFunc("PATCH /admin/users/{id}/quota", guard(h.setQuota))
	mux.HandleFunc("POST /admin/monitors/{id}/pause", guard(h.pauseMonitor))
	mux.HandleFunc("POST /admin/monitors/{id}/resume", guard(h.resumeMonitor))
	mux.HandleFunc("POST /admin/deliveries/{id}/retry", guard(h.retryDelivery))
	mux.HandleFunc("POST /admin/deliveries/{id}/suppress", guard(h.suppressDelivery))
	for _, m := range []string{"GET", "PUT", "PATCH", "DELETE"} {
		mux.HandleFunc(m+" /admin/monitors/{id}/pause", h.methodNotAllowed("POST"))
		mux.HandleFunc(m+" /admin/monitors/{id}/resume", h.methodNotAllowed("POST"))
		mux.HandleFunc(m+" /admin/deliveries/{id}/retry", h.methodNotAllowed("POST"))
		mux.HandleFunc(m+" /admin/deliveries/{id}/suppress", h.methodNotAllowed("POST"))
	}
	for _, m := range []string{"GET", "PUT", "PATCH", "DELETE"} {
		mux.HandleFunc(m+" /admin/users/{id}/suspend", h.methodNotAllowed("POST"))
		mux.HandleFunc(m+" /admin/users/{id}/restore", h.methodNotAllowed("POST"))
	}
	for _, m := range []string{"GET", "PUT", "PATCH", "DELETE"} {
		mux.HandleFunc(m+" /admin/users/{id}/revoke-sessions", h.methodNotAllowed("POST"))
	}
	for _, m := range []string{"GET", "POST", "PUT", "DELETE"} {
		mux.HandleFunc(m+" /admin/users/{id}/quota", h.methodNotAllowed("PATCH"))
	}
	mux.HandleFunc("/admin/", h.notFound)
	return mux
}

func (h *RolesHandler) methodNotAllowed(allow string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Allow", allow)
		httpserver.WriteError(w, r, http.StatusMethodNotAllowed,
			httpserver.ErrMethod, "method not allowed")
	}
}

func (h *RolesHandler) notFound(w http.ResponseWriter, r *http.Request) {
	httpserver.WriteError(w, r, http.StatusNotFound,
		httpserver.ErrNotFound, "route not found")
}

// actorRef maps the context principal to the admin actor triple —
// user, session and the security epoch captured at auth time. The
// guarded tx re-validates all three under locks.
func actorRef(p auth.Principal) ActorRef {
	return ActorRef{
		UserID:          p.User.ID,
		SessionID:       p.Session.ID,
		SecurityVersion: p.Session.SecurityVersion,
	}
}

func (h *RolesHandler) list(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFromContext(r.Context())
	out, err := ListRoleCatalog(r.Context(), h.conn, actorRef(p), h.now())
	if err != nil {
		h.writeErr(w, r, err)
		return
	}
	httpserver.WriteJSON(w, r, http.StatusOK, out)
}

// readBody enforces the JSON byte cap while preserving the raw bytes
// for the idempotency hash — the same retry must hash identically.
func (h *RolesHandler) readBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, h.maxBody))
	if err != nil {
		httpserver.WriteError(w, r, http.StatusRequestEntityTooLarge,
			httpserver.ErrPayloadLarge, "request body too large")
		return nil, false
	}
	return body, true
}

func (h *RolesHandler) create(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFromContext(r.Context())
	body, ok := h.readBody(w, r)
	if !ok {
		return
	}
	var in CreateRoleInput
	if apiErr := httpserver.DecodeBodyBytes(body, &in); apiErr != nil {
		httpserver.WriteError(w, r, apiErr.Status, apiErr.Code, apiErr.Msg)
		return
	}
	res, err := CreateCustomRole(r.Context(), h.conn, actorRef(p),
		r.Header.Get("Idempotency-Key"), body, in, h.now())
	if err != nil {
		h.writeErr(w, r, err)
		return
	}
	httpserver.WriteJSON(w, r, res.Status, res.Response)
}

func (h *RolesHandler) update(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFromContext(r.Context())
	roleID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpserver.WriteError(w, r, http.StatusBadRequest,
			httpserver.ErrBadRequest, "invalid role id")
		return
	}
	body, ok := h.readBody(w, r)
	if !ok {
		return
	}
	var in UpdateRoleInput
	if apiErr := httpserver.DecodeBodyBytes(body, &in); apiErr != nil {
		httpserver.WriteError(w, r, apiErr.Status, apiErr.Code, apiErr.Msg)
		return
	}
	res, err := UpdateRole(r.Context(), h.conn, actorRef(p), roleID, in,
		r.Header.Get("Idempotency-Key"), body, h.now())
	if err != nil {
		h.writeErr(w, r, err)
		return
	}
	httpserver.WriteJSON(w, r, res.Status, res.Response)
}

func (h *RolesHandler) assign(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFromContext(r.Context())
	target, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpserver.WriteError(w, r, http.StatusBadRequest,
			httpserver.ErrBadRequest, "invalid user id")
		return
	}
	body, ok := h.readBody(w, r)
	if !ok {
		return
	}
	var in AssignRolesInput
	if apiErr := httpserver.DecodeBodyBytes(body, &in); apiErr != nil {
		httpserver.WriteError(w, r, apiErr.Status, apiErr.Code, apiErr.Msg)
		return
	}
	res, err := AssignUserRoles(r.Context(), h.conn, actorRef(p), target, in,
		r.Header.Get("Idempotency-Key"), body, h.now())
	if err != nil {
		h.writeErr(w, r, err)
		return
	}
	httpserver.WriteJSON(w, r, res.Status, res.Response)
}

// accountTransition is the shared suspend/restore transport: parse
// target, read+decode the bounded body, run the guarded recipe.
func (h *RolesHandler) accountTransition(
	fn func(context.Context, Beginner, ActorRef, uuid.UUID,
		SuspendInput, string, []byte, time.Time) (PrivilegedResult, error),
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, _ := auth.PrincipalFromContext(r.Context())
		target, err := uuid.Parse(r.PathValue("id"))
		if err != nil {
			httpserver.WriteError(w, r, http.StatusBadRequest,
				httpserver.ErrBadRequest, "invalid user id")
			return
		}
		body, ok := h.readBody(w, r)
		if !ok {
			return
		}
		var in SuspendInput
		if apiErr := httpserver.DecodeBodyBytes(body, &in); apiErr != nil {
			httpserver.WriteError(w, r, apiErr.Status, apiErr.Code, apiErr.Msg)
			return
		}
		res, err := fn(r.Context(), h.conn, actorRef(p), target, in,
			r.Header.Get("Idempotency-Key"), body, h.now())
		if err != nil {
			h.writeErr(w, r, err)
			return
		}
		httpserver.WriteJSON(w, r, res.Status, res.Response)
	}
}

func (h *RolesHandler) suspend(w http.ResponseWriter, r *http.Request) {
	h.accountTransition(SuspendAccount)(w, r)
}

func (h *RolesHandler) restore(w http.ResponseWriter, r *http.Request) {
	h.accountTransition(RestoreAccount)(w, r)
}

func (h *RolesHandler) revokeSessions(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFromContext(r.Context())
	target, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpserver.WriteError(w, r, http.StatusBadRequest,
			httpserver.ErrBadRequest, "invalid user id")
		return
	}
	body, ok := h.readBody(w, r)
	if !ok {
		return
	}
	var in RevokeSessionsInput
	if apiErr := httpserver.DecodeBodyBytes(body, &in); apiErr != nil {
		httpserver.WriteError(w, r, apiErr.Status, apiErr.Code, apiErr.Msg)
		return
	}
	res, err := RevokeUserSessions(r.Context(), h.conn, actorRef(p), target, in,
		r.Header.Get("Idempotency-Key"), body, h.now())
	if err != nil {
		h.writeErr(w, r, err)
		return
	}
	httpserver.WriteJSON(w, r, res.Status, res.Response)
}

// monitorAction is the shared pause/resume transport.
func (h *RolesHandler) monitorAction(
	fn func(context.Context, Beginner, ActorRef, uuid.UUID,
		MonitorActionInput, string, []byte, time.Time) (PrivilegedResult, error),
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, _ := auth.PrincipalFromContext(r.Context())
		target, err := uuid.Parse(r.PathValue("id"))
		if err != nil {
			httpserver.WriteError(w, r, http.StatusBadRequest,
				httpserver.ErrBadRequest, "invalid monitor id")
			return
		}
		body, ok := h.readBody(w, r)
		if !ok {
			return
		}
		var in MonitorActionInput
		if apiErr := httpserver.DecodeBodyBytes(body, &in); apiErr != nil {
			httpserver.WriteError(w, r, apiErr.Status, apiErr.Code, apiErr.Msg)
			return
		}
		res, err := fn(r.Context(), h.conn, actorRef(p), target, in,
			r.Header.Get("Idempotency-Key"), body, h.now())
		if err != nil {
			h.writeErr(w, r, err)
			return
		}
		httpserver.WriteJSON(w, r, res.Status, res.Response)
	}
}

func (h *RolesHandler) pauseMonitor(w http.ResponseWriter, r *http.Request) {
	h.monitorAction(PauseGlobalMonitor)(w, r)
}

func (h *RolesHandler) resumeMonitor(w http.ResponseWriter, r *http.Request) {
	h.monitorAction(ResumeGlobalMonitor)(w, r)
}

// deliveryAction is the shared retry/suppress transport.
func (h *RolesHandler) deliveryAction(
	fn func(context.Context, Beginner, ActorRef, uuid.UUID,
		DeliveryActionInput, string, []byte, time.Time) (PrivilegedResult, error),
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, _ := auth.PrincipalFromContext(r.Context())
		target, err := uuid.Parse(r.PathValue("id"))
		if err != nil {
			httpserver.WriteError(w, r, http.StatusBadRequest,
				httpserver.ErrBadRequest, "invalid delivery id")
			return
		}
		body, ok := h.readBody(w, r)
		if !ok {
			return
		}
		var in DeliveryActionInput
		if apiErr := httpserver.DecodeBodyBytes(body, &in); apiErr != nil {
			httpserver.WriteError(w, r, apiErr.Status, apiErr.Code, apiErr.Msg)
			return
		}
		res, err := fn(r.Context(), h.conn, actorRef(p), target, in,
			r.Header.Get("Idempotency-Key"), body, h.now())
		if err != nil {
			h.writeErr(w, r, err)
			return
		}
		httpserver.WriteJSON(w, r, res.Status, res.Response)
	}
}

func (h *RolesHandler) retryDelivery(w http.ResponseWriter, r *http.Request) {
	h.deliveryAction(RetryDeliveryChain)(w, r)
}

func (h *RolesHandler) suppressDelivery(w http.ResponseWriter, r *http.Request) {
	h.deliveryAction(SuppressDeliveryChain)(w, r)
}

func (h *RolesHandler) setQuota(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFromContext(r.Context())
	target, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpserver.WriteError(w, r, http.StatusBadRequest,
			httpserver.ErrBadRequest, "invalid user id")
		return
	}
	body, ok := h.readBody(w, r)
	if !ok {
		return
	}
	var in QuotaInput
	if apiErr := httpserver.DecodeBodyBytes(body, &in); apiErr != nil {
		httpserver.WriteError(w, r, apiErr.Status, apiErr.Code, apiErr.Msg)
		return
	}
	res, err := SetUserQuota(r.Context(), h.conn, h.ceilings, actorRef(p),
		target, in, r.Header.Get("Idempotency-Key"), body, h.now())
	if err != nil {
		h.writeErr(w, r, err)
		return
	}
	httpserver.WriteJSON(w, r, res.Status, res.Response)
}

// writeErr maps the admin error lattice onto the shared envelope.
// Codes come straight from the contract: auth failures → 401,
// permission/step-up → 403, version/idempotency/last-superadmin →
// 409, bounded field failures → 422.
func (h *RolesHandler) writeErr(w http.ResponseWriter, r *http.Request, err error) {
	var ve *ValidationError
	switch {
	case errors.As(err, &ve):
		fields := map[string]string{}
		for k, v := range ve.Fields {
			if s, ok := v.(string); ok {
				fields[k] = s
			}
		}
		if missing, ok := ve.Fields["missing_permissions"]; ok {
			if list, ok := missing.([]string); ok && len(list) > 0 {
				fields["missing_permissions"] = list[0] +
					" (+" + itoa(len(list)-1) + " more)"
			}
		}
		httpserver.WriteErrorFields(w, r, http.StatusUnprocessableEntity,
			httpserver.ErrValidation, "validation failed", fields)
	case errors.Is(err, ErrValidation):
		httpserver.WriteError(w, r, http.StatusUnprocessableEntity,
			httpserver.ErrValidation, "validation failed")
	case errors.Is(err, ErrActorRevoked):
		httpserver.WriteError(w, r, http.StatusUnauthorized,
			httpserver.ErrUnauth, "session or actor no longer valid")
	case errors.Is(err, ErrReauthRequired):
		httpserver.WriteError(w, r, http.StatusForbidden,
			httpserver.ErrReauth, "recent authentication required")
	case errors.Is(err, ErrForbidden):
		httpserver.WriteError(w, r, http.StatusForbidden,
			httpserver.ErrForbidden, "insufficient permission")
	case errors.Is(err, ErrLastSuperAdmin):
		httpserver.WriteError(w, r, http.StatusConflict,
			ErrCodeLastSuperAdmin, "the last active superadmin cannot be removed")
	case errors.Is(err, ErrStaleEpoch), errors.Is(err, ErrIdempotencyConflict):
		httpserver.WriteError(w, r, http.StatusConflict,
			httpserver.ErrConflict, "conflicting or stale version")
	case errors.As(err, new(*QuotaConflict)):
		httpserver.WriteError(w, r, http.StatusConflict,
			httpserver.ErrQuota, "quota cap below current usage")
	case errors.Is(err, ErrDeliveryNotHead), errors.Is(err, ErrDeliveryState):
		httpserver.WriteError(w, r, http.StatusConflict,
			httpserver.ErrConflict, "delivery is not retryable or suppressible here")
	case errors.Is(err, ErrSubjectRevoked):
		httpserver.WriteError(w, r, http.StatusNotFound,
			httpserver.ErrNotFound, "subject not found")
	default:
		h.log.Error("admin route failed", "err", err)
		httpserver.WriteError(w, r, http.StatusInternalServerError,
			httpserver.ErrInternal, "internal error")
	}
}

func itoa(n int) string {
	if n <= 0 {
		return "0"
	}
	var buf [8]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
