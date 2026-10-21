package auth

import (
	"errors"
	"net/http"

	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/platform/httpserver"
)

// Handler exposes auth use cases over HTTP. Mux() is the router seam:
// routes are registered in one place here so cards add handlers without
// editing the server. The mux is NOT mounted publicly until the CSRF
// gate (C15) lands — cmd/api leaves it unwired.
type Handler struct {
	svc     *Service
	maxBody int64
}

func NewHandler(svc *Service, maxJSONBody int64) *Handler {
	return &Handler{svc: svc, maxBody: maxJSONBody}
}

// Mux returns the auth route table. Every auth route lives here so the
// registration seam stays single-source for route/method parity.
func (h *Handler) Mux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /auth/register", h.register)
	return mux
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
