package monitor

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/auth"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// fakeGate substitutes the auth service: RequireSession injects a
// fixed principal when the probe header is set, WithActorLock just
// runs the callback (the fake store's Tx methods accept a nil tx).
type fakeGate struct {
	actor    uuid.UUID
	monLimit int
}

func (g *fakeGate) RequireSession(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Test-Auth") != "1" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		next(w, r.WithContext(auth.ContextWithPrincipal(r.Context(),
			auth.Principal{User: auth.User{ID: g.actor}})))
	}
}

func (g *fakeGate) WithActorLock(ctx context.Context, p auth.Principal,
	fn func(tx pgx.Tx, u auth.User) error) error {
	return fn(nil, auth.User{ID: p.User.ID, MonitorLimit: g.monLimit})
}

type handlerFixture struct {
	mux   *http.ServeMux
	store *fakeStore
	actor uuid.UUID
	other uuid.UUID
}

func newHandlerFixture() *handlerFixture {
	fs := newFakeStore()
	svc := NewService(fs, fs, Caps{RetainedOwner: 100, RetainedGlobal: 200})
	f := &handlerFixture{store: fs, actor: uuid.New(), other: uuid.New()}
	h := NewHandler(svc, &fakeGate{actor: f.actor, monLimit: 100},
		HandlerConfig{MaxJSONBody: 32 << 10})
	f.mux = h.Mux()
	return f
}

func (f *handlerFixture) do(method, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("X-Test-Auth", "1")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	f.mux.ServeHTTP(rec, req)
	return rec
}

func (f *handlerFixture) create(t *testing.T) monitorDTO {
	t.Helper()
	rec := f.do("POST", "/monitors", `{"name":"api","target_url":"https://example.com/health","interval_seconds":60,"timeout_seconds":5}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create %d %s", rec.Code, rec.Body.String())
	}
	var env struct {
		Data monitorDTO `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return env.Data
}

func TestMonitorHandlers(t *testing.T) {
	f := newHandlerFixture()

	t.Run("create returns 201 + Location + owned DTO", func(t *testing.T) {
		rec := f.do("POST", "/monitors", `{"name":"api","target_url":"https://example.com/health","interval_seconds":60,"timeout_seconds":5}`)
		if rec.Code != http.StatusCreated {
			t.Fatalf("%d %s", rec.Code, rec.Body.String())
		}
		loc := rec.Header().Get("Location")
		if !strings.HasPrefix(loc, "/monitors/") {
			t.Fatalf("bad Location %q", loc)
		}
		var env struct {
			Data monitorDTO `json:"data"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
			t.Fatal(err)
		}
		m := env.Data
		if m.Health != HealthUnknown || m.Generation != 1 || m.IsPaused ||
			m.Freshness != nil || m.Method != "GET" {
			t.Fatalf("bad DTO %+v", m)
		}
	})

	t.Run("create on trailing-slash collection works too", func(t *testing.T) {
		rec := f.do("POST", "/monitors/", `{"name":"b","target_url":"https://example.com/h","interval_seconds":60,"timeout_seconds":5}`)
		if rec.Code != http.StatusCreated {
			t.Fatalf("%d %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("invalid body -> 422 with field map, nothing stored", func(t *testing.T) {
		before := len(f.store.monitors)
		rec := f.do("POST", "/monitors", `{"name":"","target_url":"ftp://x","interval_seconds":1,"timeout_seconds":99}`)
		if rec.Code != http.StatusUnprocessableEntity {
			t.Fatalf("%d %s", rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "VALIDATION_ERROR") {
			t.Fatalf("no validation code: %s", rec.Body.String())
		}
		if len(f.store.monitors) != before {
			t.Fatal("invalid create stored a row")
		}
	})

	t.Run("unauthenticated -> 401", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/monitors/"+uuid.NewString(), nil)
		rec := httptest.NewRecorder()
		f.mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("%d", rec.Code)
		}
	})

	t.Run("get returns stored DTO", func(t *testing.T) {
		m := f.create(t)
		rec := f.do("GET", "/monitors/"+m.ID.String(), "")
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), m.ID.String()) {
			t.Fatalf("%d %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("missing and malformed id both 404", func(t *testing.T) {
		if rec := f.do("GET", "/monitors/"+uuid.NewString(), ""); rec.Code != http.StatusNotFound {
			t.Fatalf("missing %d", rec.Code)
		}
		if rec := f.do("GET", "/monitors/not-a-uuid", ""); rec.Code != http.StatusNotFound {
			t.Fatalf("malformed %d", rec.Code)
		}
	})

	t.Run("patch bumps generation, stale gen conflicts", func(t *testing.T) {
		m := f.create(t)
		rec := f.do("PATCH", "/monitors/"+m.ID.String(),
			`{"expected_generation":1,"name":"renamed"}`)
		if rec.Code != http.StatusOK {
			t.Fatalf("patch %d %s", rec.Code, rec.Body.String())
		}
		var env struct {
			Data monitorDTO `json:"data"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil || env.Data.Generation != 2 || env.Data.Name != "renamed" {
			t.Fatalf("bad patch %+v", env.Data)
		}
		// Replay with the now-stale generation.
		rec = f.do("PATCH", "/monitors/"+m.ID.String(),
			`{"expected_generation":1,"name":"again"}`)
		if rec.Code != http.StatusConflict {
			t.Fatalf("stale patch %d %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("patch without generation -> 422", func(t *testing.T) {
		m := f.create(t)
		rec := f.do("PATCH", "/monitors/"+m.ID.String(), `{"name":"x"}`)
		if rec.Code != http.StatusUnprocessableEntity {
			t.Fatalf("%d %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("delete 204 then reads/mutations as 404", func(t *testing.T) {
		m := f.create(t)
		rec := f.do("DELETE", "/monitors/"+m.ID.String(), `{"expected_generation":1}`)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("delete %d %s", rec.Code, rec.Body.String())
		}
		if rec := f.do("GET", "/monitors/"+m.ID.String(), ""); rec.Code != http.StatusNotFound {
			t.Fatalf("post-delete get %d", rec.Code)
		}
		// Repeated delete stays 404 — tombstone never resurrects.
		if rec := f.do("DELETE", "/monitors/"+m.ID.String(), `{"expected_generation":1}`); rec.Code != http.StatusNotFound {
			t.Fatalf("re-delete %d", rec.Code)
		}
	})

	t.Run("delete without generation body -> 422", func(t *testing.T) {
		m := f.create(t)
		rec := f.do("DELETE", "/monitors/"+m.ID.String(), `{}`)
		if rec.Code != http.StatusUnprocessableEntity {
			t.Fatalf("%d", rec.Code)
		}
	})

	t.Run("method not allowed stays in envelope", func(t *testing.T) {
		rec := f.do("PUT", "/monitors/"+uuid.NewString(), `{}`)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%d", rec.Code)
		}
		if rec.Header().Get("Allow") == "" || !strings.Contains(rec.Body.String(), "METHOD_NOT_ALLOWED") {
			t.Fatalf("bad 405 %s", rec.Body.String())
		}
	})

	t.Run("unknown subroute stays in envelope", func(t *testing.T) {
		rec := f.do("GET", "/monitors/"+uuid.NewString()+"/extra", "")
		if rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), "NOT_FOUND") {
			t.Fatalf("%d %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("quota errors map to contract codes", func(t *testing.T) {
		fs := newFakeStore()
		fs.err = ErrQuotaOwner
		svc := NewService(fs, fs, Caps{})
		h := NewHandler(svc, &fakeGate{actor: uuid.New(), monLimit: 1},
			HandlerConfig{MaxJSONBody: 32 << 10})
		mux := h.Mux()
		req := httptest.NewRequest("POST", "/monitors",
			strings.NewReader(`{"name":"a","target_url":"https://example.com","interval_seconds":60,"timeout_seconds":5}`))
		req.Header.Set("X-Test-Auth", "1")
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "QUOTA_EXCEEDED") ||
			!strings.Contains(rec.Body.String(), "owner_monitor_limit") {
			t.Fatalf("%d %s", rec.Code, rec.Body.String())
		}
	})
}
