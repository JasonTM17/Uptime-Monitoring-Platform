package httpserver

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"log/slog"

	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/config"
)

func testConfig() config.Config {
	env := map[string]string{
		"DATABASE_URL":           "postgres://u:p@127.0.0.1/u",
		"ENGINE_DATABASE_URL":    "postgres://u:p@127.0.0.1/u",
		"MIGRATION_DATABASE_URL": "postgres://u:p@127.0.0.1/u",
	}
	c, err := config.Load(func(k string) (string, bool) { v, ok := env[k]; return v, ok })
	if err != nil {
		panic(err)
	}
	return c
}

func quietLogger() *slog.Logger { return slog.New(slog.DiscardHandler) }

func TestHealth(t *testing.T) {
	t.Parallel()

	t.Run("live returns 200 without touching the ready probe", func(t *testing.T) {
		t.Parallel()
		called := false
		s := New(testConfig(), quietLogger(), func(context.Context) error {
			called = true
			return errors.New("dependency down")
		})
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health/live", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("live status = %d", rec.Code)
		}
		if called {
			t.Fatal("liveness must not consult the readiness probe")
		}
	})

	t.Run("ready reflects probe failure and success", func(t *testing.T) {
		t.Parallel()
		var probeErr error = errors.New("db unreachable")
		s := New(testConfig(), quietLogger(), func(context.Context) error { return probeErr })

		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health/ready", nil))
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("ready with failing probe = %d", rec.Code)
		}
		// Internal diagnostic must not be echoed to clients.
		if body := rec.Body.String(); body == "" || body == "db unreachable" {
			t.Fatalf("ready body leaked diagnostic: %q", body)
		}

		probeErr = nil
		rec = httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health/ready", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("ready with healthy probe = %d", rec.Code)
		}
	})

	t.Run("nil probe is trivially ready", func(t *testing.T) {
		t.Parallel()
		s := New(testConfig(), quietLogger(), nil)
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health/ready", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("ready = %d", rec.Code)
		}
	})
}

func TestListenFailure(t *testing.T) {
	t.Parallel()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	cfg := testConfig()
	cfg.HTTP.Host = "127.0.0.1"
	cfg.HTTP.Port = ln.Addr().(*net.TCPAddr).Port

	s := New(cfg, quietLogger(), nil)
	if err := s.Run(context.Background()); err == nil {
		t.Fatal("expected listen failure on occupied port")
	}
}

func TestShutdown(t *testing.T) {
	t.Parallel()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := New(testConfig(), quietLogger(), nil)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx, ln) }()

	// In-flight request that ends shortly after cancellation.
	go func() {
		resp, err := http.Get("http://" + ln.Addr().String() + "/health/live")
		if err == nil {
			resp.Body.Close()
		}
	}()
	time.Sleep(50 * time.Millisecond)

	start := time.Now()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("shutdown did not complete within deadline")
	}
	if elapsed := time.Since(start); elapsed > testConfig().HTTP.ShutdownTimeout+time.Second {
		t.Fatalf("shutdown exceeded deadline: %s", elapsed)
	}
}
