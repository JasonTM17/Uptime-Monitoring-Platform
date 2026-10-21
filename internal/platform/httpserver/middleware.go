package httpserver

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net/http"
	"regexp"
	"time"
)

type ctxKey int

const ctxRequestID ctxKey = iota

var requestIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

// RequestIDFromContext returns the correlation id for this request.
func RequestIDFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(ctxRequestID).(string); ok {
		return v
	}
	return ""
}

// RequestID honors a client X-Request-Id only when it matches the bounded
// charset/length; otherwise a fresh id is generated — untrusted ids are
// never echoed back unvalidated. The id lands in the response header,
// the error envelope, the access log, and the request context.
func RequestID(maxLen int) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := r.Header.Get("X-Request-Id")
			if len(id) == 0 || len(id) > maxLen || !requestIDPattern.MatchString(id) {
				id = newRequestID()
			}
			w.Header().Set("X-Request-Id", id)
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxRequestID, id)))
		})
	}
}

func newRequestID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// statusWriter captures status and bytes for the access log.
type statusWriter struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	n, err := w.ResponseWriter.Write(b)
	w.bytes += n
	return n, err
}

func (w *statusWriter) code() int {
	if w.status == 0 {
		return http.StatusOK
	}
	return w.status
}

// Unwrap exposes the underlying writer so middleware below can still
// reach Flusher/Hijacker implementations for future streaming routes.
func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// Flush forwards to the underlying writer when it supports flushing.
func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// AccessLog emits one line per request with the route PATTERN (never the
// raw URI or query), method, status, bytes, duration, and request id.
// Untrusted request content — query strings, bodies, credentials — is
// never logged.
func AccessLog(log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sw := &statusWriter{ResponseWriter: w}
			start := time.Now()
			next.ServeHTTP(sw, r)
			route := r.Pattern
			if route == "" {
				route = "unmatched"
			}
			log.Info("http request",
				"request_id", RequestIDFromContext(r.Context()),
				"method", r.Method,
				"route", route,
				"status", sw.code(),
				"bytes", sw.bytes,
				"duration_ms", time.Since(start).Milliseconds(),
			)
		})
	}
}

// Recover converts a panic into a generic 500. The panic value is logged
// server-side only; nothing internal reaches the response body.
func Recover(log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if rec := recover(); rec != nil {
					log.Error("handler panic",
						"request_id", RequestIDFromContext(r.Context()),
						"panic", rec,
					)
					WriteError(w, r, http.StatusInternalServerError, ErrInternal, "internal error")
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

// NoStore marks responses non-cacheable. Applied to this API surface;
// static/frontend assets (phase 08, served elsewhere) must opt out.
func NoStore(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}
