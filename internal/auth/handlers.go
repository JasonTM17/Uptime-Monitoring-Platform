package auth

import (
	"errors"
	"net/http"
	"net/netip"
	"strconv"
	"time"

	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/platform/httpserver"
)

// sessionCookieName is the local-profile cookie (no __Host- prefix —
// local serves plain HTTP; hosted profile sets Secure + tighter policy).
const sessionCookieName = "uptime_session"

// HandlerConfig wires transport policy into the auth handler.
type HandlerConfig struct {
	MaxJSONBody    int64
	TrustedProxies []netip.Prefix // empty = trust no proxy (default)
	CookieSecure   bool           // hosted HTTPS only; local stays false
	CSRF           *CSRFManager   // required in production wiring
}

// Handler exposes auth use cases over HTTP. Mux() is the router seam:
// routes are registered in one place here so cards add handlers without
// editing the server. The mux is NOT mounted publicly until the CSRF
// gate (C15) lands — cmd/api leaves it unwired.
type Handler struct {
	svc     *Service
	maxBody int64
	trusted []netip.Prefix
	secure  bool
	csrf    *CSRFManager
}

func NewHandler(svc *Service, cfg HandlerConfig) *Handler {
	return &Handler{svc: svc, maxBody: cfg.MaxJSONBody,
		trusted: cfg.TrustedProxies, secure: cfg.CookieSecure, csrf: cfg.CSRF}
}

// Mux returns the auth route table. Every auth route lives here so the
// registration seam stays single-source for route/method parity. When a
// CSRF manager is wired, every mutation is wrapped in the pre-auth
// challenge check — this is the gate that lets the mux go public.
func (h *Handler) Mux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /auth/csrf", h.csrfChallenge)
	if h.csrf != nil {
		mux.HandleFunc("POST /auth/register", h.csrf.RequireCSRF(h.register))
		mux.HandleFunc("POST /auth/login", h.csrf.RequireCSRF(h.login))
		return mux
	}
	mux.HandleFunc("POST /auth/register", h.register)
	mux.HandleFunc("POST /auth/login", h.login)
	return mux
}

// csrfChallenge issues a fresh signed challenge: readable cookie plus
// the token in the body. No session is required — this is the pre-auth
// login-CSRF defense.
func (h *Handler) csrfChallenge(w http.ResponseWriter, r *http.Request) {
	if h.csrf == nil {
		httpserver.WriteError(w, r, http.StatusNotFound,
			httpserver.ErrNotFound, "route not found")
		return
	}
	token, err := h.csrf.Issue(w)
	if err != nil {
		httpserver.WriteError(w, r, http.StatusInternalServerError,
			httpserver.ErrInternal, "internal error")
		return
	}
	httpserver.WriteJSON(w, r, http.StatusOK, map[string]string{"csrf_token": token})
}

// writeCSRFError renders the uniform 403 rejection.
func writeCSRFError(w http.ResponseWriter, r *http.Request) {
	httpserver.WriteError(w, r, http.StatusForbidden,
		httpserver.ErrCSRF, "csrf check failed")
}

// sessionCookie serializes the bearer token for the browser. Plaintext
// appears only here — HttpOnly blocks script access; SameSite=Lax plus
// the CSRF gate (C15) bound ambient use.
func (h *Handler) sessionCookie(token string, expires time.Time) *http.Cookie {
	return &http.Cookie{
		Name: sessionCookieName, Value: token, Path: "/",
		HttpOnly: true, Secure: h.secure,
		SameSite: http.SameSiteLaxMode, Expires: expires,
	}
}

func (h *Handler) register(w http.ResponseWriter, r *http.Request) {
	var in RegisterInput
	if apiErr := httpserver.DecodeJSON(w, r, &in, h.maxBody); apiErr != nil {
		httpserver.WriteErrorFields(w, r, apiErr.Status, apiErr.Code, apiErr.Msg, apiErr.Fields)
		return
	}
	u, err := h.svc.Register(r.Context(), in)
	switch {
	case err == nil:
		httpserver.WriteJSON(w, r, http.StatusCreated, u)
	default:
		var fe *FieldError
		switch {
		case errors.As(err, &fe):
			httpserver.WriteErrorFields(w, r, http.StatusUnprocessableEntity,
				httpserver.ErrValidation, "validation failed", fe.Fields)
		case errors.Is(err, ErrEmailTaken):
			// Anti-enumeration: fixed message, no hint whether the
			// existing account is active/disabled.
			httpserver.WriteError(w, r, http.StatusConflict,
				httpserver.ErrConflict, "registration could not be completed")
		default:
			httpserver.WriteError(w, r, http.StatusInternalServerError,
				httpserver.ErrInternal, "internal error")
		}
	}
}

func (h *Handler) login(w http.ResponseWriter, r *http.Request) {
	var in LoginInput
	if apiErr := httpserver.DecodeJSON(w, r, &in, h.maxBody); apiErr != nil {
		httpserver.WriteErrorFields(w, r, apiErr.Status, apiErr.Code, apiErr.Msg, apiErr.Fields)
		return
	}
	iss, user, err := h.svc.Login(r.Context(), in, ClientIP(r, h.trusted))
	switch {
	case err == nil:
		http.SetCookie(w, h.sessionCookie(iss.Token, iss.Session.ExpiresAt))
		httpserver.WriteJSON(w, r, http.StatusOK, map[string]any{
			"user":               user,
			"session_expires_at": iss.Session.ExpiresAt,
		})
	default:
		var rl *RateLimitedError
		switch {
		case errors.As(err, &rl):
			w.Header().Set("Retry-After",
				strconv.Itoa(int(rl.RetryAfter.Seconds())+1))
			httpserver.WriteError(w, r, http.StatusTooManyRequests,
				httpserver.ErrRateLimited, "too many attempts")
		case errors.Is(err, ErrBadCredentials):
			// Uniform 401 — unknown, disabled, and wrong password are
			// indistinguishable on the wire.
			httpserver.WriteError(w, r, http.StatusUnauthorized,
				httpserver.ErrUnauth, "invalid credentials")
		default:
			httpserver.WriteError(w, r, http.StatusInternalServerError,
				httpserver.ErrInternal, "internal error")
		}
	}
}
