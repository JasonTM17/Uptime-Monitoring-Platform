package httpserver

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCorrelation(t *testing.T) {
	t.Parallel()
	mw := RequestID(64)

	t.Run("generates an id when header absent", func(t *testing.T) {
		t.Parallel()
		var seen string
		h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			seen = RequestIDFromContext(r.Context())
			w.WriteHeader(http.StatusNoContent)
		}))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
		if seen == "" || rec.Header().Get("X-Request-Id") != seen {
			t.Fatalf("missing/invalid correlation: ctx=%q header=%q", seen, rec.Header().Get("X-Request-Id"))
		}
	})

	t.Run("honors a valid client id", func(t *testing.T) {
		t.Parallel()
		var seen string
		h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			seen = RequestIDFromContext(r.Context())
		}))
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("X-Request-Id", "cli-id_123.ok")
		h.ServeHTTP(httptest.NewRecorder(), req)
		if seen != "cli-id_123.ok" {
			t.Fatalf("id = %q", seen)
		}
	})

	t.Run("rejects overlong or unsafe client ids", func(t *testing.T) {
		t.Parallel()
		var seen string
		h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			seen = RequestIDFromContext(r.Context())
		}))
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("X-Request-Id", strings.Repeat("a", 65))
		h.ServeHTTP(httptest.NewRecorder(), req)
		if seen == strings.Repeat("a", 65) || seen == "" {
			t.Fatalf("overlong id was trusted: %q", seen)
		}
		req.Header.Set("X-Request-Id", "bad\ninjection")
		h.ServeHTTP(httptest.NewRecorder(), req)
		if seen == "bad\ninjection" {
			t.Fatal("unsafe id was trusted")
		}
	})

	t.Run("ids differ across requests", func(t *testing.T) {
		t.Parallel()
		var a, b string
		h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if a == "" {
				a = RequestIDFromContext(r.Context())
			} else {
				b = RequestIDFromContext(r.Context())
			}
		}))
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
		if a == "" || a == b {
			t.Fatalf("ids not unique: %q %q", a, b)
		}
	})
}

func TestEnvelope(t *testing.T) {
	t.Parallel()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	WriteError(rec, req, http.StatusUnprocessableEntity, ErrUnprocessable, "name is taken")
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d", rec.Code)
	}
	var env map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatal(err)
	}
	errObj, ok := env["error"].(map[string]any)
	if !ok || errObj["code"] != "UNPROCESSABLE_ENTITY" || errObj["message"] != "name is taken" {
		t.Fatalf("envelope = %v", env)
	}
	if _, present := env["request_id"]; !present {
		t.Fatal("request_id key must always be present in error envelope")
	}
}

func TestRedaction(t *testing.T) {
	t.Parallel()
	log := slog.New(slog.NewJSONHandler(io.Discard, nil))
	h := Recover(log)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("pq: password=hunter2 connection reset")
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("panic status = %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "hunter2") || strings.Contains(rec.Body.String(), "pq:") {
		t.Fatalf("panic detail leaked: %s", rec.Body.String())
	}
}

func TestNoStore(t *testing.T) {
	t.Parallel()
	h := NoStore(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("cache-control = %q", rec.Header().Get("Cache-Control"))
	}
}
