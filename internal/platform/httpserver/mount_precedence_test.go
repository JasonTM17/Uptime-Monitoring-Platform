package httpserver

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// Mount precedence mirrors the production composition root
// (cmd/api/main.go): literal {id} subtrees like /monitors/{id}/checks
// must outrank the broader /monitors/ subtree mount, and the
// /notification-channels/{id}/test literal must outrank its subtree.
// A regression here silently 404s history/stats routes in production
// while every per-package mux test still passes.

func named(name string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Handler", name)
		w.WriteHeader(http.StatusOK)
	})
}

func routedTo(t *testing.T, h http.Handler, path string) string {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec.Header().Get("X-Handler")
}

func TestMountPrecedence(t *testing.T) {
	// Same pattern shapes as the production mount table.
	s := New(testConfig(), quietLogger(), nil,
		Mount{Pattern: "/monitors", Handler: named("monitors")},
		Mount{Pattern: "/monitors/", Handler: named("monitors")},
		Mount{Pattern: "/notification-channels/", Handler: named("channels")},
		Mount{Pattern: "/notification-channels/{id}/test",
			Handler: named("test-send")},
		Mount{Pattern: "/monitors/{id}/checks", Handler: named("analytics")},
		Mount{Pattern: "/monitors/{id}/incidents", Handler: named("analytics")},
		Mount{Pattern: "/monitors/{id}/stats", Handler: named("analytics")},
	)
	h := s.Handler()

	mid := "11111111-1111-1111-8111-111111111111"
	cases := []struct {
		path, want string
	}{
		{"/monitors", "monitors"},
		{"/monitors/" + mid, "monitors"},
		{"/monitors/" + mid + "/checks", "analytics"},
		{"/monitors/" + mid + "/incidents", "analytics"},
		{"/monitors/" + mid + "/stats", "analytics"},
		{"/notification-channels/" + mid + "/test", "test-send"},
		{"/notification-channels/" + mid, "channels"},
	}
	for _, c := range cases {
		if got := routedTo(t, h, c.path); got != c.want {
			t.Fatalf("GET %s -> %s, want %s", c.path, got, c.want)
		}
	}
}
