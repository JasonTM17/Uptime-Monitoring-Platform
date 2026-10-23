//go:build integration

package admin_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/admin"
	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/auth"
)

// Positive-path HTTP coverage over the real DB: the query surface
// had service-level integration coverage but no transport evidence —
// these subtests drive the mounted mux end to end, so permission
// wiring, envelopes, and 404/403 mapping are all real.

func adminMuxFor(t *testing.T, conn *pgx.Conn, actor admin.ActorRef) *httptest.Server {
	t.Helper()
	gate := fakeGate{principal: auth.Principal{
		User: auth.User{ID: actor.UserID},
		Session: auth.Session{ID: actor.SessionID,
			SecurityVersion: actor.SecurityVersion},
	}}
	h := admin.NewRolesHandler(conn, gate, nil, 1<<20,
		admin.QuotaCeilings{}, nil)
	return httptest.NewServer(h.Mux())
}

func adminGet(t *testing.T, srv *httptest.Server, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	srv.Config.Handler.ServeHTTP(rec,
		httptest.NewRequest(http.MethodGet, path, nil))
	return rec
}

func TestAdminQueryTransport(t *testing.T) {
	conn := connect(t)
	sec, cleanup := actorWithRole(t, conn, "qt-sec", secAdminPreset)
	defer cleanup()
	viewer, vcleanup := actorWithRole(t, conn, "qt-view", viewerPreset)
	defer vcleanup()

	srv := adminMuxFor(t, conn, sec)
	defer srv.Close()

	t.Run("overview serves the platform projection", func(t *testing.T) {
		rec := adminGet(t, srv, "/admin/overview")
		if rec.Code != http.StatusOK {
			t.Fatalf("overview: %d %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("roles catalog lists the presets", func(t *testing.T) {
		rec := adminGet(t, srv, "/admin/roles")
		if rec.Code != http.StatusOK {
			t.Fatalf("roles: %d %s", rec.Code, rec.Body.String())
		}
		var env struct {
			Data struct {
				Roles []struct {
					Code string `json:"code"`
				} `json:"roles"`
			} `json:"data"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(env.Data.Roles) < 5 {
			t.Fatalf("catalog: %+v", env.Data)
		}
	})

	t.Run("users list + single-get + missing subject", func(t *testing.T) {
		rec := adminGet(t, srv, "/admin/users")
		if rec.Code != http.StatusOK {
			t.Fatalf("users: %d %s", rec.Code, rec.Body.String())
		}
		var env struct {
			Data struct {
				Users []struct {
					ID string `json:"id"`
				} `json:"users"`
			} `json:"data"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(env.Data.Users) == 0 {
			t.Fatal("users list empty — fixture users exist")
		}

		rec = adminGet(t, srv, "/admin/users/"+viewer.UserID.String())
		if rec.Code != http.StatusOK {
			t.Fatalf("getUser: %d %s", rec.Code, rec.Body.String())
		}
		rec = adminGet(t, srv, "/admin/users/"+uuid.NewString())
		if rec.Code != http.StatusNotFound {
			t.Fatalf("missing user: %d", rec.Code)
		}
	})

	t.Run("audit list + detail + missing id", func(t *testing.T) {
		rec := adminGet(t, srv, "/admin/audit-events")
		if rec.Code != http.StatusOK {
			t.Fatalf("audit list: %d %s", rec.Code, rec.Body.String())
		}
		rec = adminGet(t, srv, "/admin/audit-events/"+uuid.NewString())
		if rec.Code != http.StatusNotFound {
			t.Fatalf("missing event: %d", rec.Code)
		}
	})

	t.Run("monitors + operations lists serve envelopes", func(t *testing.T) {
		for _, path := range []string{"/admin/monitors", "/admin/operations"} {
			rec := adminGet(t, srv, path)
			if rec.Code != http.StatusOK {
				t.Fatalf("%s: %d %s", path, rec.Code, rec.Body.String())
			}
		}
	})

	t.Run("outbox needs deliveries:read — operator, not secadmin", func(t *testing.T) {
		// SEC_ADMIN lacks deliveries:read by design; the deny is the
		// contract, then the OPERATOR read proves the positive path.
		rec := adminGet(t, srv, "/admin/outbox")
		if rec.Code != http.StatusForbidden {
			t.Fatalf("secadmin outbox must be denied: %d", rec.Code)
		}
		op, ocleanup := actorWithRole(t, conn, "qt-op", operatorPreset)
		defer ocleanup()
		osrv := adminMuxFor(t, conn, op)
		defer osrv.Close()
		rec = adminGet(t, osrv, "/admin/outbox")
		if rec.Code != http.StatusOK {
			t.Fatalf("operator outbox: %d %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("viewer is denied the users surface", func(t *testing.T) {
		vsrv := adminMuxFor(t, conn, viewer)
		defer vsrv.Close()
		rec := adminGet(t, vsrv, "/admin/users")
		if rec.Code != http.StatusForbidden {
			t.Fatalf("viewer users: %d %s", rec.Code, rec.Body.String())
		}
		// platform:read is allowed — the boundary is real.
		rec = adminGet(t, vsrv, "/admin/overview")
		if rec.Code != http.StatusOK {
			t.Fatalf("viewer overview: %d %s", rec.Code, rec.Body.String())
		}
	})
}
