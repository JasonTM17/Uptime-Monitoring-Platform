package admin_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/admin"
	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/auth"
)

// fakeGate injects a principal so routes reach the handler — the
// privileged recipes themselves need a real conn and are covered by
// the integration tests.
type fakeGate struct {
	principal auth.Principal
}

func (g fakeGate) RequireSession(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		next(w, r.WithContext(auth.ContextWithPrincipal(r.Context(), g.principal)))
	}
}

func testPrincipal() auth.Principal {
	return auth.Principal{
		User:    auth.User{ID: uuid.New()},
		Session: auth.Session{ID: uuid.New(), SecurityVersion: 1},
	}
}

func TestRolesRouteTable(t *testing.T) {
	gate := fakeGate{principal: testPrincipal()}
	h := admin.NewRolesHandler(nil, gate, nil, 1<<16,
		admin.QuotaCeilings{RetainedOwner: 50, ColumnBound: 10000}, nil)
	mux := h.Mux()

	// Wrong methods get the envelope's 405 + Allow.
	for _, m := range []string{"PUT", "PATCH", "DELETE"} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(m, "/admin/roles", nil))
		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%s /admin/roles: got %d", m, rec.Code)
		}
		if rec.Header().Get("Allow") == "" {
			t.Fatalf("%s /admin/roles: missing Allow", m)
		}
	}

	// Unknown admin subtree is a JSON 404.
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("GET", "/admin/nope", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("GET /admin/nope: got %d", rec.Code)
	}

	// Bad role ID is 400 before any DB work.
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("PATCH",
		"/admin/roles/not-a-uuid", strings.NewReader(`{"reason":"x"}`)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("PATCH bad uuid: got %d", rec.Code)
	}
}

// TestRolesErrorMapping pins the admin error lattice onto HTTP codes.
// errBeginner fails BeginTx with a scripted sentinel — enough to drive
// the handler's writeErr lattice through the real mux without a DB.
type errBeginner struct{ err error }

func (e errBeginner) BeginTx(_ context.Context, _ pgx.TxOptions) (pgx.Tx, error) {
	return nil, e.err
}

// TestRolesErrorMapping exercises the REAL writeErr table: each route
// reaches SuspendAccount, the scripted BeginTx failure propagates
// verbatim, and the handler maps it. An out-of-sync mapping fails here
// instead of passing against a stale in-test mirror.
func TestRolesErrorMapping(t *testing.T) {
	target := uuid.New()
	cases := []struct {
		name     string
		err      error
		wantCode int
	}{
		{"actor revoked", admin.ErrActorRevoked, http.StatusUnauthorized},
		{"forbidden", admin.ErrForbidden, http.StatusForbidden},
		{"reauth", admin.ErrReauthRequired, http.StatusForbidden},
		{"last superadmin", admin.ErrLastSuperAdmin, http.StatusConflict},
		{"stale epoch", admin.ErrStaleEpoch, http.StatusConflict},
		{"idempotency conflict", admin.ErrIdempotencyConflict, http.StatusConflict},
		{"quota conflict", &admin.QuotaConflict{Usage: 3, Requested: 1}, http.StatusConflict},
		{"delivery not head", admin.ErrDeliveryNotHead, http.StatusConflict},
		{"delivery state", admin.ErrDeliveryState, http.StatusConflict},
		{"subject revoked", admin.ErrSubjectRevoked, http.StatusNotFound},
		{"validation", &admin.ValidationError{Fields: map[string]any{
			"missing_permissions": []string{"users:read"}}}, http.StatusUnprocessableEntity},
		{"unmapped", errors.New("boom"), http.StatusInternalServerError},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := admin.NewRolesHandler(errBeginner{c.err},
				fakeGate{testPrincipal()}, nil, 1<<10,
				admin.QuotaCeilings{}, nil)
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost,
				"/admin/users/"+target.String()+"/suspend",
				strings.NewReader(`{"expected_version":1,"reason":"audit"}`))
			req.Header.Set("Idempotency-Key", "idem-1")
			h.Mux().ServeHTTP(rec, req)
			if rec.Code != c.wantCode {
				t.Fatalf("%s -> %d want %d (%s)",
					c.err, rec.Code, c.wantCode, rec.Body.String())
			}
		})
	}

	t.Run("missing idempotency key is 422 before any conn touch", func(t *testing.T) {
		h := admin.NewRolesHandler(errBeginner{nil},
			fakeGate{testPrincipal()}, nil, 1<<10,
			admin.QuotaCeilings{}, nil)
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost,
			"/admin/users/"+target.String()+"/suspend",
			strings.NewReader(`{"expected_version":1,"reason":"audit"}`))
		h.Mux().ServeHTTP(rec, req)
		if rec.Code != http.StatusUnprocessableEntity {
			t.Fatalf("missing idem key -> %d (%s)", rec.Code, rec.Body.String())
		}
	})
}

// TestAssignRolesJSONShape pins the request contract fields — a drift
// here silently breaks API consumers.
func TestAssignRolesJSONShape(t *testing.T) {
	var in admin.AssignRolesInput
	err := json.Unmarshal([]byte(
		`{"role_ids":["00000000-0000-4000-8000-000000000001"],`+
			`"expected_version":3,"reason":"ticket-1"}`), &in)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if in.ExpectedVersion != 3 || in.Reason != "ticket-1" ||
		len(in.RoleIDs) != 1 {
		t.Fatalf("unexpected decode: %+v", in)
	}
}
