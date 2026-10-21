package admin

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/google/uuid"

	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/auth"
	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/platform/httpserver"
)

// registerQueries mounts the admin read surface onto the mux — all
// GET, all behind RequireSession, permission enforced inside each
// AuthorizeRead guard. No CSRF needed: these are safe methods.
func (h *RolesHandler) registerQueries(mux *http.ServeMux, session func(http.HandlerFunc) http.HandlerFunc) {
	mux.HandleFunc("GET /admin/overview", session(h.overview))
	mux.HandleFunc("GET /admin/users", session(h.listUsers))
	mux.HandleFunc("GET /admin/users/{$}", session(h.listUsers))
	mux.HandleFunc("GET /admin/users/{id}", session(h.getUser))
	mux.HandleFunc("GET /admin/monitors", session(h.listMonitors))
	mux.HandleFunc("GET /admin/monitors/{$}", session(h.listMonitors))
	mux.HandleFunc("GET /admin/operations", session(h.operations))
	mux.HandleFunc("GET /admin/outbox", session(h.listOutbox))
	mux.HandleFunc("GET /admin/outbox/{$}", session(h.listOutbox))
	mux.HandleFunc("GET /admin/audit-events", session(h.listAudit))
	mux.HandleFunc("GET /admin/audit-events/{$}", session(h.listAudit))
	mux.HandleFunc("GET /admin/audit-events/{id}", session(h.getAudit))
}

func (h *RolesHandler) overview(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFromContext(r.Context())
	out, err := Overview(r.Context(), h.conn, actorRef(p), h.now())
	if err != nil {
		h.writeErr(w, r, err)
		return
	}
	httpserver.WriteJSON(w, r, http.StatusOK, out)
}

// rejectUnknownParams 400s on any query key outside the route's
// declared filter set — an unrecognized filter must never be
// silently ignored (the spec's unknown-filter rule).
func rejectUnknownParams(w http.ResponseWriter, r *http.Request, allowed ...string) bool {
	set := map[string]bool{}
	for _, a := range allowed {
		set[a] = true
	}
	for k := range r.URL.Query() {
		if !set[k] {
			httpserver.WriteError(w, r, http.StatusBadRequest,
				httpserver.ErrBadRequest, "unknown filter: "+k)
			return true
		}
	}
	return false
}

func parseLimit(r *http.Request) int {
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return 0
}

func (h *RolesHandler) listUsers(w http.ResponseWriter, r *http.Request) {
	if rejectUnknownParams(w, r, "q", "status", "role_id", "limit", "cursor") {
		return
	}
	p, _ := auth.PrincipalFromContext(r.Context())
	q := r.URL.Query()
	rows, next, err := ListUsers(r.Context(), h.conn, actorRef(p), UsersFilter{
		Q:      q.Get("q"),
		Status: q.Get("status"),
		RoleID: q.Get("role_id"),
		Limit:  parseLimit(r),
		Cursor: q.Get("cursor"),
	}, h.now())
	if err != nil {
		h.writeErr(w, r, err)
		return
	}
	httpserver.WriteJSON(w, r, http.StatusOK, map[string]any{
		"users": rows, "next_cursor": next,
	})
}

func (h *RolesHandler) getUser(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFromContext(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpserver.WriteError(w, r, http.StatusBadRequest,
			httpserver.ErrBadRequest, "invalid user id")
		return
	}
	out, err := GetUser(r.Context(), h.conn, actorRef(p), id, h.now())
	if err != nil {
		h.writeErr(w, r, err)
		return
	}
	httpserver.WriteJSON(w, r, http.StatusOK, out)
}

func (h *RolesHandler) listMonitors(w http.ResponseWriter, r *http.Request) {
	if rejectUnknownParams(w, r, "owner_id", "paused", "health", "limit", "cursor") {
		return
	}
	p, _ := auth.PrincipalFromContext(r.Context())
	q := r.URL.Query()
	rows, next, err := ListGlobalMonitors(r.Context(), h.conn, actorRef(p),
		MonitorsFilter{
			Owner:  q.Get("owner_id"),
			Paused: q.Get("paused"),
			Health: q.Get("health"),
			Limit:  parseLimit(r),
			Cursor: q.Get("cursor"),
		}, h.now())
	if err != nil {
		h.writeErr(w, r, err)
		return
	}
	httpserver.WriteJSON(w, r, http.StatusOK, map[string]any{
		"monitors": rows, "next_cursor": next,
	})
}

func (h *RolesHandler) operations(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFromContext(r.Context())
	out, err := OperationsSnapshot(r.Context(), h.conn, actorRef(p), h.now())
	if err != nil {
		h.writeErr(w, r, err)
		return
	}
	httpserver.WriteJSON(w, r, http.StatusOK, out)
}

func (h *RolesHandler) listOutbox(w http.ResponseWriter, r *http.Request) {
	if rejectUnknownParams(w, r, "state", "limit", "cursor") {
		return
	}
	p, _ := auth.PrincipalFromContext(r.Context())
	q := r.URL.Query()
	rows, next, err := ListOutbox(r.Context(), h.conn, actorRef(p), OutboxFilter{
		State:  q.Get("state"),
		Limit:  parseLimit(r),
		Cursor: q.Get("cursor"),
	}, h.now())
	if err != nil {
		h.writeErr(w, r, err)
		return
	}
	httpserver.WriteJSON(w, r, http.StatusOK, map[string]any{
		"deliveries": rows, "next_cursor": next,
	})
}

func (h *RolesHandler) listAudit(w http.ResponseWriter, r *http.Request) {
	if rejectUnknownParams(w, r, "action", "actor", "subject", "from", "to", "limit", "cursor") {
		return
	}
	p, _ := auth.PrincipalFromContext(r.Context())
	q := r.URL.Query()
	rows, next, err := ListAuditEvents(r.Context(), h.conn, actorRef(p),
		AuditFilter{
			Action:  q.Get("action"),
			Actor:   q.Get("actor"),
			Subject: q.Get("subject"),
			From:    q.Get("from"),
			To:      q.Get("to"),
			Limit:   parseLimit(r),
			Cursor:  q.Get("cursor"),
		}, h.now())
	if err != nil {
		h.writeErr(w, r, err)
		return
	}
	httpserver.WriteJSON(w, r, http.StatusOK, map[string]any{
		"events": rows, "next_cursor": next,
	})
}

func (h *RolesHandler) getAudit(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFromContext(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpserver.WriteError(w, r, http.StatusBadRequest,
			httpserver.ErrBadRequest, "invalid audit event id")
		return
	}
	out, err := GetAuditEvent(r.Context(), h.conn, actorRef(p), id, h.now())
	if err != nil {
		h.writeErr(w, r, err)
		return
	}
	httpserver.WriteJSON(w, r, http.StatusOK, out)
}

// mapQueryErr extends writeErr for the read-path sentinels —
// ErrCursor→400, ErrUnavailable→503.
func mapQueryErr(err error) (int, httpserver.ErrCode, string) {
	switch {
	case errors.Is(err, ErrCursor):
		return http.StatusBadRequest, httpserver.ErrBadRequest,
			"invalid or mismatched cursor"
	case errors.Is(err, ErrUnavailable):
		return http.StatusServiceUnavailable, httpserver.ErrUnavailable,
			"dependency unavailable"
	}
	return 0, "", ""
}
