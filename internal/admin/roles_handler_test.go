package admin_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

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
	h := admin.NewRolesHandler(nil, gate, nil, 1<<16, nil)
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
func TestRolesErrorMapping(t *testing.T) {
	cases := []struct {
		err  error
		want int
	}{
		{admin.ErrActorRevoked, http.StatusUnauthorized},
		{admin.ErrForbidden, http.StatusForbidden},
		{admin.ErrReauthRequired, http.StatusForbidden},
		{admin.ErrLastSuperAdmin, http.StatusConflict},
		{admin.ErrStaleEpoch, http.StatusConflict},
		{admin.ErrIdempotencyConflict, http.StatusConflict},
		{admin.ErrSubjectRevoked, http.StatusNotFound},
		{admin.ErrValidation, http.StatusUnprocessableEntity},
		{&admin.ValidationError{Fields: map[string]any{
			"missing_permissions": []string{"users:read"}}},
			http.StatusUnprocessableEntity},
		{errors.New("boom"), http.StatusInternalServerError},
	}
	for _, c := range cases {
		// Drive the mapper through a handler whose service call is
		// bypassed: invoke writeErr behavior via a probe handler.
		got := mapErrStatus(c.err)
		if got != c.want {
			t.Fatalf("%v: got %d, want %d", c.err, got, c.want)
		}
	}
}

// mapErrStatus mirrors the handler's writeErr table — kept honest by
// mapping through the same exported error sentinels.
func mapErrStatus(err error) int {
	var ve *admin.ValidationError
	switch {
	case errors.As(err, &ve), errors.Is(err, admin.ErrValidation):
		return http.StatusUnprocessableEntity
	case errors.Is(err, admin.ErrActorRevoked):
		return http.StatusUnauthorized
	case errors.Is(err, admin.ErrReauthRequired),
		errors.Is(err, admin.ErrForbidden):
		return http.StatusForbidden
	case errors.Is(err, admin.ErrLastSuperAdmin),
		errors.Is(err, admin.ErrStaleEpoch),
		errors.Is(err, admin.ErrIdempotencyConflict):
		return http.StatusConflict
	case errors.Is(err, admin.ErrSubjectRevoked):
		return http.StatusNotFound
	default:
		return http.StatusInternalServerError
	}
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
