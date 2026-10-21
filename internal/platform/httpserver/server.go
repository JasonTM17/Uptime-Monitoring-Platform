// Package httpserver runs the public HTTP surface: lifecycle, health
// endpoints, timeouts, and (from C07) the shared JSON envelope middleware.
package httpserver

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/config"
)

// ReadyProbe reports whether the service can serve real traffic. A nil
// probe means "trivially ready": honest today because no dependency (pgx
// pool) is wired yet — readiness is NOT database-verified until C10
// injects the real ping.
type ReadyProbe func(ctx context.Context) error

// Server owns the HTTP listener lifecycle.
type Server struct {
	cfg    config.Config
	log    *slog.Logger
	ready  ReadyProbe
	server *http.Server
}

// Mount attaches a sub-handler under a mux subtree pattern such as
// "/auth/". Domain packages register their routes inside their own
// mux; the server only mounts the subtree — the router seam stays
// single-source inside the domain package.
type Mount struct {
	Pattern string
	Handler http.Handler
}

// New builds a Server. ready may be nil (see ReadyProbe). mounts are
// registered before the catch-all 404.
func New(cfg config.Config, log *slog.Logger, ready ReadyProbe, mounts ...Mount) *Server {
	s := &Server{cfg: cfg, log: log, ready: ready}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health/live", s.handleLive)
	mux.HandleFunc("GET /health/ready", s.handleReady)
	for _, m := range mounts {
		mux.Handle(m.Pattern, m.Handler)
	}
	// No-method twins make wrong-method requests return the JSON envelope
	// with Allow instead of the mux's plaintext default.
	mux.HandleFunc("/health/live", methodNotAllowed)
	mux.HandleFunc("/health/ready", methodNotAllowed)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		WriteError(w, r, http.StatusNotFound, ErrNotFound, "route not found")
	})
	handler := RequestID(cfg.HTTP.RequestIDMaxLen)(
		AccessLog(log)(
			Recover(log)(
				NoStore(mux))))
	s.server = &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: cfg.HTTP.ReadHeaderTimeout,
		ReadTimeout:       cfg.HTTP.ReadTimeout,
		WriteTimeout:      cfg.HTTP.WriteTimeout,
		IdleTimeout:       cfg.HTTP.IdleTimeout,
	}
	return s
}

// Handler exposes the mux for tests that do not need a real listener.
func (s *Server) Handler() http.Handler { return s.server.Handler }

// Run binds cfg.HTTP and serves until ctx is cancelled or the listener
// fails. Listen errors surface immediately; shutdown is bounded by
// ShutdownTimeout with a Close fallback.
func (s *Server) Run(ctx context.Context) error {
	addr := net.JoinHostPort(s.cfg.HTTP.Host, fmt.Sprint(s.cfg.HTTP.Port))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}
	return s.Serve(ctx, ln)
}

// Serve accepts connections on ln until ctx is cancelled, then shuts down
// within the configured deadline. It lets tests bind an ephemeral port.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	errCh := make(chan error, 1)
	go func() { errCh <- s.server.Serve(ln) }()
	s.log.Info("http listening", "addr", ln.Addr().String())

	select {
	case <-ctx.Done():
		sctx, cancel := context.WithTimeout(context.Background(), s.cfg.HTTP.ShutdownTimeout)
		defer cancel()
		err := s.server.Shutdown(sctx)
		if err != nil {
			s.log.Error("graceful shutdown failed; closing", "err", err)
			_ = s.server.Close()
		}
		serveErr := <-errCh
		if err != nil {
			return fmt.Errorf("shutdown: %w", err)
		}
		if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			return fmt.Errorf("serve: %w", serveErr)
		}
		return nil
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("serve: %w", err)
	}
}

// handleLive reports process liveness. It never touches the database or
// any dependency — a dead dependency must not mark the process dead.
func (s *Server) handleLive(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

// methodNotAllowed returns the JSON envelope with Allow, replacing the
// mux's plaintext 405 for registered paths.
func methodNotAllowed(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Allow", http.MethodGet)
	WriteError(w, r, http.StatusMethodNotAllowed, ErrMethod, "method not allowed")
}

// handleReady reports dependency readiness through the injected probe.
func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	if s.ready == nil {
		s.writeHealth(w, http.StatusOK, "ready")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	if err := s.ready(ctx); err != nil {
		s.writeHealth(w, http.StatusServiceUnavailable, "unavailable")
		return
	}
	s.writeHealth(w, http.StatusOK, "ready")
}

func (s *Server) writeHealth(w http.ResponseWriter, code int, status string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, _ = fmt.Fprintf(w, `{"status":%q}`, status)
}
