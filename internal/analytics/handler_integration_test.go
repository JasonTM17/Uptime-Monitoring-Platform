//go:build integration

package analytics

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/auth"
)

// handlerFixture wires the real analytics handler over the real
// repository — the HTTP transport (validation lattice, envelope,
// ownership) is what this file adds beyond service-level coverage.
type handlerFixture struct {
	srv   *httptest.Server
	owner uuid.UUID
	other uuid.UUID
}

type gateFunc func(http.HandlerFunc) http.HandlerFunc

func (g gateFunc) RequireSession(next http.HandlerFunc) http.HandlerFunc {
	return g(next)
}

func principalGate(uid uuid.UUID) gateFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			p := auth.Principal{User: auth.User{ID: uid}}
			next(w, r.WithContext(auth.ContextWithPrincipal(r.Context(), p)))
		}
	}
}

// unauthGate lets the route run but injects no principal — the
// handler's own principal() check must write the 401.
func unauthGate() gateFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			next(w, r)
		}
	}
}

func newHandlerFixture(t *testing.T, gate SessionGate) *handlerFixture {
	t.Helper()
	pool := apool(t)
	repo := NewRepository(pool, 15*time.Second)
	svc := NewService(repo, ServiceConfig{
		RawRetentionHours: 720, HourlyRetentionDays: 30, Profile: "local"})
	h := NewHandler(svc, gate, nil)
	return &handlerFixture{srv: httptest.NewServer(h.Mux())}
}

func (f *handlerFixture) get(t *testing.T, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	f.srv.Config.Handler.ServeHTTP(rec, req)
	return rec
}

func TestAnalyticsTransport(t *testing.T) {
	conn := aconn(t)
	cleanAnalytics(t, conn)
	fx := mkMonitor(t, conn)
	otherFx := mkMonitor(t, conn)

	h := newHandlerFixture(t, principalGate(fx.userID))
	defer h.srv.Close()

	t.Run("unauthenticated principal is 401", func(t *testing.T) {
		anon := newHandlerFixture(t, unauthGate())
		defer anon.srv.Close()
		rec := httptest.NewRecorder()
		// Drive the anonymous mux, not the authed one.
		anon.srv.Config.Handler.ServeHTTP(rec,
			httptest.NewRequest(http.MethodGet, "/dashboard/summary", nil))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("no principal: %d", rec.Code)
		}
	})

	t.Run("malformed monitor id is 404", func(t *testing.T) {
		for _, suffix := range []string{"checks", "incidents", "stats"} {
			rec := h.get(t, "/monitors/not-a-uuid/"+suffix)
			if rec.Code != http.StatusNotFound {
				t.Fatalf("%s: %d", suffix, rec.Code)
			}
		}
	})

	t.Run("checks rejects bad range and cursor, serves envelope", func(t *testing.T) {
		rec := h.get(t, "/monitors/"+fx.monID.String()+
			"/checks?from=not-a-time")
		if rec.Code != http.StatusUnprocessableEntity {
			t.Fatalf("bad from: %d %s", rec.Code, rec.Body.String())
		}
		rec = h.get(t, "/monitors/"+fx.monID.String()+
			"/checks?to=also-bad")
		if rec.Code != http.StatusUnprocessableEntity {
			t.Fatalf("bad to: %d %s", rec.Code, rec.Body.String())
		}
		rec = h.get(t, "/monitors/"+fx.monID.String()+"/checks")
		if rec.Code != http.StatusOK {
			t.Fatalf("happy checks: %d %s", rec.Code, rec.Body.String())
		}
		var env struct {
			Checks []any `json:"checks"`
			Page   struct {
				HasMore bool `json:"has_more"`
			} `json:"page"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
			t.Fatalf("envelope: %v", err)
		}
	})

	t.Run("incidents rejects bad state, serves envelope", func(t *testing.T) {
		rec := h.get(t, "/monitors/"+fx.monID.String()+
			"/incidents?state=bogus")
		if rec.Code != http.StatusUnprocessableEntity {
			t.Fatalf("bad state: %d %s", rec.Code, rec.Body.String())
		}
		rec = h.get(t, "/monitors/"+fx.monID.String()+"/incidents")
		if rec.Code != http.StatusOK {
			t.Fatalf("happy incidents: %d %s", rec.Code, rec.Body.String())
		}
		var env struct {
			Incidents []any `json:"incidents"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
			t.Fatalf("envelope: %v", err)
		}
	})

	t.Run("stats rejects bad window, serves projection", func(t *testing.T) {
		rec := h.get(t, "/monitors/"+fx.monID.String()+"/stats?window=13h")
		if rec.Code != http.StatusUnprocessableEntity {
			t.Fatalf("bad window: %d %s", rec.Code, rec.Body.String())
		}
		for _, w := range []string{"24h", "7d", "30d"} {
			rec = h.get(t, "/monitors/"+fx.monID.String()+"/stats?window="+w)
			if rec.Code != http.StatusOK {
				t.Fatalf("window %s: %d %s", w, rec.Code, rec.Body.String())
			}
		}
	})

	t.Run("foreign monitor reads as 404 on every surface", func(t *testing.T) {
		for _, suffix := range []string{"checks", "incidents", "stats"} {
			rec := h.get(t, "/monitors/"+otherFx.monID.String()+"/"+suffix)
			if rec.Code != http.StatusNotFound {
				t.Fatalf("foreign %s: %d %s", suffix, rec.Code, rec.Body.String())
			}
		}
	})

	t.Run("dashboard summary serves owner projection", func(t *testing.T) {
		rec := h.get(t, "/dashboard/summary")
		if rec.Code != http.StatusOK {
			t.Fatalf("summary: %d %s", rec.Code, rec.Body.String())
		}
		var env struct {
			Data struct {
				Monitors        int   `json:"monitors"`
				RecentIncidents []any `json:"recent_incidents"`
			} `json:"data"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
			t.Fatalf("envelope: %v", err)
		}
		if env.Data.Monitors != 1 {
			t.Fatalf("summary monitors=%v, want 1", env.Data.Monitors)
		}
	})

	t.Run("unknown route is 404", func(t *testing.T) {
		rec := h.get(t, "/monitors/"+fx.monID.String()+"/bogus")
		if rec.Code != http.StatusNotFound {
			t.Fatalf("catch-all: %d", rec.Code)
		}
	})
}
