package admin_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/admin"
)

// Transport-level coverage for the admin mux: validation branches
// that run before the privileged recipe — unknown filters, bad path
// ids, body cap, malformed JSON, method handling, and the catch-all.
// Positive/permission behavior is proven by the integration suite.

func adminMux(t *testing.T, conn admin.Beginner) *admin.RolesHandler {
	t.Helper()
	return admin.NewRolesHandler(conn,
		fakeGate{testPrincipal()}, nil, 1<<10,
		admin.QuotaCeilings{}, nil)
}

func TestAdminTransportValidation(t *testing.T) {
	mux := adminMux(t, errBeginner{nil}).Mux()

	t.Run("unknown filter is 400 on every list route", func(t *testing.T) {
		for _, path := range []string{
			"/admin/users", "/admin/monitors",
			"/admin/outbox", "/admin/audit-events",
		} {
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet,
				path+"?bogus=1", nil))
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("%s: %d %s", path, rec.Code, rec.Body.String())
			}
		}
	})

	t.Run("bad path uuid is 400, not a panic", func(t *testing.T) {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet,
			"/admin/users/not-a-uuid", nil))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("getUser bad id: %d", rec.Code)
		}
		rec = httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost,
			"/admin/users/not-a-uuid/suspend",
			strings.NewReader(`{"expected_version":1,"reason":"x"}`)))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("suspend bad id: %d", rec.Code)
		}
	})

	t.Run("body over cap is 413", func(t *testing.T) {
		big := strings.Repeat("x", 1<<10+1)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost,
			"/admin/users/"+uuid.NewString()+"/suspend",
			strings.NewReader(big)))
		if rec.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("over-cap body: %d %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("malformed json is rejected", func(t *testing.T) {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost,
			"/admin/users/"+uuid.NewString()+"/suspend",
			strings.NewReader(`{"expected_version":`)))
		if rec.Code != http.StatusBadRequest &&
			rec.Code != http.StatusUnprocessableEntity {
			t.Fatalf("malformed json: %d %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("method not allowed is 405", func(t *testing.T) {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPut,
			"/admin/monitors/"+uuid.NewString()+"/pause", nil))
		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("PUT pause: %d", rec.Code)
		}
	})

	t.Run("unknown admin subtree is 404", func(t *testing.T) {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet,
			"/admin/bogus", nil))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("catch-all: %d", rec.Code)
		}
	})
}
