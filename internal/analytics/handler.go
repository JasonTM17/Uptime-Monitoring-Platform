package analytics

import (
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/auth"
	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/platform/httpserver"
	"github.com/google/uuid"
)

// SessionGate is the authentication seam — *auth.Service satisfies
// it. Reads compose under RequireSession only: history is read-only,
// no actor lock and no mutation path.
type SessionGate interface {
	RequireSession(next http.HandlerFunc) http.HandlerFunc
}

// Handler exposes owner-scoped history, statistics, and dashboard
// reads. Every route is GET-only, session-gated, and owner-scoped —
// a foreign monitor id is indistinguishable from a missing one.
type Handler struct {
	svc  *Service
	auth SessionGate
	log  *slog.Logger
}

func NewHandler(svc *Service, gate SessionGate, log *slog.Logger) *Handler {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Handler{svc: svc, auth: gate, log: log}
}

// Mux returns the analytics route table. The composition root mounts
// the specific "/monitors/{id}/..." patterns — Go's mux prefers them
// over the broader "/monitors/" subtree — plus "/dashboard/".
func (h *Handler) Mux() *http.ServeMux {
	mux := http.NewServeMux()
	session := h.auth.RequireSession
	mux.HandleFunc("GET /monitors/{id}/checks", session(h.checks))
	mux.HandleFunc("GET /monitors/{id}/incidents", session(h.incidents))
	mux.HandleFunc("GET /monitors/{id}/stats", session(h.stats))
	mux.HandleFunc("GET /dashboard/summary", session(h.dashboard))
	mux.HandleFunc("/", h.notFound)
	return mux
}

func (h *Handler) notFound(w http.ResponseWriter, r *http.Request) {
	httpserver.WriteError(w, r, http.StatusNotFound,
		httpserver.ErrNotFound, "route not found")
}

func (h *Handler) internalError(w http.ResponseWriter,
	r *http.Request, err error) {
	h.log.Error("analytics internal error",
		"request_id", httpserver.RequestIDFromContext(r.Context()),
		"route", r.Pattern, "err", err)
	httpserver.WriteError(w, r, http.StatusInternalServerError,
		httpserver.ErrInternal, "internal error")
}

func principal(w http.ResponseWriter, r *http.Request) (auth.Principal, bool) {
	p, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		httpserver.WriteError(w, r, http.StatusUnauthorized,
			httpserver.ErrUnauth, "authentication required")
	}
	return p, ok
}

func parseMonID(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpserver.WriteError(w, r, http.StatusNotFound,
			httpserver.ErrNotFound, "monitor not found")
		return uuid.Nil, false
	}
	return id, true
}

// checkDTO is one history row — run lifecycle plus accepted outcome;
// slot_at is the nominal slot, observed_at the actual timestamp.
type checkDTO struct {
	RunID      uuid.UUID  `json:"run_id"`
	SlotAt     time.Time  `json:"slot_at"`
	StartedAt  *time.Time `json:"started_at"`
	FinishedAt *time.Time `json:"finished_at"`
	Status     string     `json:"status"`
	Outcome    *string    `json:"outcome"`
	Eligible   *bool      `json:"eligible"`
	Success    *bool      `json:"success"`
	HTTPStatus *int       `json:"http_status"`
	DurationMs *int64     `json:"duration_ms"`
	ObservedAt *time.Time `json:"observed_at"`
}

func (h *Handler) checks(w http.ResponseWriter, r *http.Request) {
	p, ok := principal(w, r)
	if !ok {
		return
	}
	monID, ok := parseMonID(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	from, to := nowUTC().Add(-24*time.Hour), nowUTC()
	var fErr = map[string]string{}
	if v := q.Get("from"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			fErr["from"] = "RFC3339 timestamp required"
		} else {
			from = t.UTC()
		}
	}
	if v := q.Get("to"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			fErr["to"] = "RFC3339 timestamp required"
		} else {
			to = t.UTC()
		}
	}
	limit := parseLimit(q.Get("limit"), 50, 100)
	if len(fErr) > 0 {
		httpserver.WriteErrorFields(w, r, http.StatusUnprocessableEntity,
			httpserver.ErrValidation, "invalid input", fErr)
		return
	}
	page, err := h.svc.ListChecks(r.Context(), p.User.ID, monID,
		from, to, q.Get("cursor"), limit)
	switch {
	case errors.Is(err, ErrMonitorNotFound):
		httpserver.WriteError(w, r, http.StatusNotFound,
			httpserver.ErrNotFound, "monitor not found")
	case errors.Is(err, ErrCursor):
		httpserver.WriteError(w, r, http.StatusBadRequest,
			httpserver.ErrValidation, "invalid cursor")
	case errors.Is(err, ErrWindow):
		httpserver.WriteError(w, r, http.StatusUnprocessableEntity,
			httpserver.ErrValidation, "invalid range")
	case err != nil:
		h.internalError(w, r, err)
	default:
		dtos := make([]checkDTO, len(page.Checks))
		for i, c := range page.Checks {
			dtos[i] = checkDTO{
				RunID: c.RunID, SlotAt: c.SlotAt,
				StartedAt: c.StartedAt, FinishedAt: c.FinishedAt,
				Status: c.Status, Outcome: c.Outcome,
				Eligible: c.Eligible, Success: c.Success,
				HTTPStatus: c.HTTPStatus, DurationMs: c.DurationMs,
				ObservedAt: c.ObservedAt,
			}
		}
		httpserver.WriteJSON(w, r, http.StatusOK, map[string]any{
			"checks": dtos,
			"page": map[string]any{
				"next_cursor": page.NextCursor,
				"has_more":    page.HasMore,
			},
		})
	}
}

type incidentDTO struct {
	ID              uuid.UUID  `json:"id"`
	OpenedAt        time.Time  `json:"opened_at"`
	ResolvedAt      *time.Time `json:"resolved_at"`
	CloseReason     *string    `json:"close_reason"`
	OpenedCheckID   uuid.UUID  `json:"opened_check_id"`
	ResolvedCheckID *uuid.UUID `json:"resolved_check_id"`
}

func (h *Handler) incidents(w http.ResponseWriter, r *http.Request) {
	p, ok := principal(w, r)
	if !ok {
		return
	}
	monID, ok := parseMonID(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	page, err := h.svc.ListIncidents(r.Context(), p.User.ID, monID,
		q.Get("state"), q.Get("cursor"),
		parseLimit(q.Get("limit"), 50, 100))
	switch {
	case errors.Is(err, ErrMonitorNotFound):
		httpserver.WriteError(w, r, http.StatusNotFound,
			httpserver.ErrNotFound, "monitor not found")
	case errors.Is(err, ErrCursor):
		httpserver.WriteError(w, r, http.StatusBadRequest,
			httpserver.ErrValidation, "invalid cursor")
	case errors.Is(err, ErrWindow):
		httpserver.WriteError(w, r, http.StatusUnprocessableEntity,
			httpserver.ErrValidation, "invalid state")
	case err != nil:
		h.internalError(w, r, err)
	default:
		dtos := make([]incidentDTO, len(page.Incidents))
		for i, v := range page.Incidents {
			dtos[i] = incidentDTO{
				ID: v.ID, OpenedAt: v.OpenedAt,
				ResolvedAt: v.ResolvedAt, CloseReason: v.CloseReason,
				OpenedCheckID:   v.OpenedCheckID,
				ResolvedCheckID: v.ResolvedCheckID,
			}
		}
		httpserver.WriteJSON(w, r, http.StatusOK, map[string]any{
			"incidents": dtos,
			"page": map[string]any{
				"next_cursor": page.NextCursor,
				"has_more":    page.HasMore,
			},
		})
	}
}

// statsDTO is the full contract payload — window bounds are the
// REQUEST, data bounds the REPRESENTED interval; they are separate
// fields on purpose.
type statsDTO struct {
	WindowStart         time.Time   `json:"window_start"`
	WindowEnd           time.Time   `json:"window_end"`
	DataStart           *time.Time  `json:"data_start"`
	DataEnd             *time.Time  `json:"data_end"`
	ValidSamples        int64       `json:"valid_samples"`
	Successes           int64       `json:"successes"`
	Failures            int64       `json:"failures"`
	ExcludedSamples     int64       `json:"excluded_samples"`
	ExpectedSamples     int64       `json:"expected_samples"`
	MissedSamples       int64       `json:"missed_samples"`
	PendingSamples      int64       `json:"pending_samples"`
	Coverage            *float64    `json:"coverage"`
	SampleUptime        *float64    `json:"sample_uptime"`
	MeanDurationMs      *float64    `json:"avg_duration_ms"`
	RawRetentionHours   int         `json:"raw_retention_hours"`
	HourlyRetentionDays int         `json:"hourly_retention_days"`
	RawAvailableFrom    *time.Time  `json:"raw_available_from"`
	Resolution          string      `json:"resolution"`
	IsPartial           bool        `json:"is_partial"`
	Series              []bucketDTO `json:"series"`
}

type bucketDTO struct {
	BucketStart   time.Time `json:"bucket_start"`
	ValidSamples  int64     `json:"valid_samples"`
	Successes     int64     `json:"successes"`
	Failures      int64     `json:"failures"`
	Excluded      int64     `json:"excluded_samples"`
	SampleUptime  *float64  `json:"sample_uptime"`
	AvgDurationMs *float64  `json:"avg_duration_ms"`
}

func (h *Handler) stats(w http.ResponseWriter, r *http.Request) {
	p, ok := principal(w, r)
	if !ok {
		return
	}
	monID, ok := parseMonID(w, r)
	if !ok {
		return
	}
	now := nowUTC()
	var dur time.Duration
	switch q := r.URL.Query().Get("window"); q {
	case "", "24h":
		dur = 24 * time.Hour
	case "7d":
		dur = 7 * 24 * time.Hour
	case "30d":
		dur = 30 * 24 * time.Hour
	default:
		httpserver.WriteErrorFields(w, r, http.StatusUnprocessableEntity,
			httpserver.ErrValidation, "invalid input",
			map[string]string{"window": "must be 24h, 7d, or 30d"})
		return
	}
	res, err := h.svc.Statistics(r.Context(), p.User.ID, monID,
		now.Add(-dur), now, now)
	switch {
	case errors.Is(err, ErrMonitorNotFound):
		httpserver.WriteError(w, r, http.StatusNotFound,
			httpserver.ErrNotFound, "monitor not found")
	case errors.Is(err, ErrWindow):
		httpserver.WriteError(w, r, http.StatusUnprocessableEntity,
			httpserver.ErrValidation, "invalid window")
	case err != nil:
		h.internalError(w, r, err)
	default:
		series := make([]bucketDTO, len(res.Series))
		for i, b := range res.Series {
			series[i] = bucketDTO{
				BucketStart:   b.BucketStart,
				ValidSamples:  b.Counts.Valid,
				Successes:     b.Counts.Successes,
				Failures:      b.Counts.Failures,
				Excluded:      b.Counts.Excluded,
				SampleUptime:  SampleUptime(b.Counts),
				AvgDurationMs: MeanDurationMs(b.Counts),
			}
		}
		httpserver.WriteJSON(w, r, http.StatusOK, statsDTO{
			WindowStart: res.WindowStart, WindowEnd: res.WindowEnd,
			DataStart: res.DataStart, DataEnd: res.DataEnd,
			ValidSamples:        res.Counts.Valid,
			Successes:           res.Counts.Successes,
			Failures:            res.Counts.Failures,
			ExcludedSamples:     res.Counts.Excluded,
			ExpectedSamples:     res.Expected,
			MissedSamples:       res.Missed,
			PendingSamples:      res.Pending,
			Coverage:            res.Coverage,
			SampleUptime:        res.SampleUptime,
			MeanDurationMs:      res.MeanDurationMs,
			RawRetentionHours:   res.RawRetentionHours,
			HourlyRetentionDays: res.HourlyRetentionDays,
			RawAvailableFrom:    res.RawAvailableFrom,
			Resolution:          res.Resolution,
			IsPartial:           res.IsPartial,
			Series:              series,
		})
	}
}

type recentIncidentDTO struct {
	ID          uuid.UUID  `json:"id"`
	MonitorID   uuid.UUID  `json:"monitor_id"`
	MonitorName string     `json:"monitor_name"`
	OpenedAt    time.Time  `json:"opened_at"`
	ResolvedAt  *time.Time `json:"resolved_at"`
	CloseReason *string    `json:"close_reason"`
}

func (h *Handler) dashboard(w http.ResponseWriter, r *http.Request) {
	p, ok := principal(w, r)
	if !ok {
		return
	}
	d, err := h.svc.Dashboard(r.Context(), p.User.ID, nowUTC())
	if err != nil {
		h.internalError(w, r, err)
		return
	}
	recent := make([]recentIncidentDTO, len(d.RecentIncidents))
	for i, v := range d.RecentIncidents {
		recent[i] = recentIncidentDTO{
			ID: v.ID, MonitorID: v.MonitorID,
			MonitorName: v.MonitorName, OpenedAt: v.OpenedAt,
			ResolvedAt: v.ResolvedAt, CloseReason: v.CloseReason,
		}
	}
	httpserver.WriteJSON(w, r, http.StatusOK, map[string]any{
		"monitors":          d.Monitors,
		"active":            d.Active,
		"paused":            d.Paused,
		"up":                d.Up,
		"down":              d.Down,
		"open_incidents":    d.OpenIncidents,
		"sample_uptime_24h": d.SampleUptime24h,
		"recent_incidents":  recent,
		"quota":             d.Quota,
		"as_of":             d.AsOf,
	})
}

func parseLimit(v string, def, max int) int {
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 || n > max {
		return def
	}
	return n
}

func nowUTC() time.Time { return time.Now().UTC() }
