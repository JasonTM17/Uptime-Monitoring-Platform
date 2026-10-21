// Package observability exposes bounded runtime signals: a finite
// metric catalog (counters + gauges) and dependency-aware health
// composition. Cardinality is compile-time bounded — every label
// domain is a fixed table, never a runtime string. No monitor ID,
// owner ID, URL, email, DSN, or token may appear in any output.
package observability

import (
	"context"
	"crypto/subtle"
	"fmt"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/checker"
	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/engine"
)

// Finite label domains. An enum value outside its table lands in the
// "other" bucket — an upgraded dependency can never mint a new series.
var (
	denialLabels  = [...]string{"queue_full", "owner_window", "global_window"}
	outcomeLabels = [...]string{
		"success", "unexpected_status", "dns_error", "connect_error",
		"tls_error", "timeout", "policy_blocked", "canceled",
		"internal_error",
	}
	finalizeLabels = [...]string{"committed", "stale", "duplicate"}
	// OutboxStates mirrors the state CHECK in migrations/005_outbox.
	// Order is the wire order for series and the gauge array index.
	OutboxStates = [...]string{"PENDING", "LEASED", "SENT", "DEAD", "SUPPRESSED"}
)

const (
	labelOther = "other"
	// numDenial/numOutcome/numFinalize count the fixed buckets plus
	// one trailing "other" catch-all.
	numDenial   = len(denialLabels) + 1
	numOutcome  = len(outcomeLabels) + 1
	numFinalize = len(finalizeLabels) + 1 // + "error" occupies slot 3
)

// finalizeErrorSlot replaces "other" for the finalize family: a
// failed finalize is the actionable series, so it gets a real name.
const finalizeErrorSlot = numFinalize - 1

// Metrics is the bounded collector. Counters are atomics incremented
// by the engine at each decision point; gauges are pulled from
// injected sources at render time so a scrape never fans out into
// engine internals beyond an atomic read.
type Metrics struct {
	admissions   atomic.Int64
	denials      [numDenial]atomic.Int64
	observations [numOutcome]atomic.Int64
	finalize     [numFinalize]atomic.Int64
	ownerLoss    atomic.Int64

	gauges func() engine.EngineGauges // nil-safe: absent => zeros
	outbox *OutboxGauges              // nil-safe: absent => age -1
}

// NewMetrics builds the collector. engineGauges may be nil (renders
// zeros); outbox may be nil (renders snapshot_age -1 = no source).
func NewMetrics(gauges func() engine.EngineGauges, outbox *OutboxGauges) *Metrics {
	return &Metrics{gauges: gauges, outbox: outbox}
}

// BindSources attaches gauge readers after construction — the
// composition root needs the collector before the engine exists,
// so counters start instrumented while gauges bind post-start.
// Not goroutine-hot: call once during wiring, before serving.
func (m *Metrics) BindSources(gauges func() engine.EngineGauges, outbox *OutboxGauges) {
	m.gauges = gauges
	m.outbox = outbox
}

var _ engine.Counters = (*Metrics)(nil)

func (m *Metrics) RecordAdmissions(n int64) { m.admissions.Add(n) }

func (m *Metrics) RecordDenial(d engine.DenialCause) {
	i := numDenial - 1
	if d >= 0 && int(d) < len(denialLabels) {
		i = int(d)
	}
	m.denials[i].Add(1)
}

func (m *Metrics) RecordObservation(o checker.Outcome) {
	i := numOutcome - 1
	if o >= 0 && int(o) < len(outcomeLabels) {
		i = int(o)
	}
	m.observations[i].Add(1)
}

func (m *Metrics) RecordFinalize(f engine.FinalizeOutcome, ok bool) {
	if !ok {
		m.finalize[finalizeErrorSlot].Add(1)
		return
	}
	i := finalizeErrorSlot // defensive: unknown outcome can't mint a label
	if f >= 0 && int(f) < len(finalizeLabels) {
		i = int(f)
	}
	m.finalize[i].Add(1)
}

func (m *Metrics) RecordOwnerLoss() { m.ownerLoss.Add(1) }

// Render writes the Prometheus text exposition. It is idempotent —
// rendering never mutates counters, so a collector scrape cannot
// inflate what it reports.
func (m *Metrics) Render(w io.Writer, now time.Time) error {
	bw := func(format string, a ...any) {
		fmt.Fprintf(w, format, a...)
	}
	bw("# TYPE uptime_engine_admissions_total counter\n")
	bw("uptime_engine_admissions_total %d\n", m.admissions.Load())
	bw("# TYPE uptime_engine_admission_denials_total counter\n")
	for i := range m.denials {
		c := m.denials[i].Load()
		bw("uptime_engine_admission_denials_total{reason=%q} %d\n",
			denialLabel(i), c)
	}
	bw("# TYPE uptime_engine_observations_total counter\n")
	for i := range m.observations {
		c := m.observations[i].Load()
		bw("uptime_engine_observations_total{outcome=%q} %d\n",
			outcomeLabel(i), c)
	}
	bw("# TYPE uptime_engine_finalize_total counter\n")
	for i := range m.finalize {
		c := m.finalize[i].Load()
		bw("uptime_engine_finalize_total{result=%q} %d\n",
			finalizeLabel(i), c)
	}
	bw("# TYPE uptime_engine_owner_loss_total counter\n")
	bw("uptime_engine_owner_loss_total %d\n", m.ownerLoss.Load())

	var g engine.EngineGauges
	if m.gauges != nil {
		g = m.gauges()
	}
	bw("# TYPE uptime_engine_queue_depth gauge\n")
	bw("uptime_engine_queue_depth %d\n", g.QueueDepth)
	bw("# TYPE uptime_engine_workers gauge\n")
	bw("uptime_engine_workers %d\n", g.Workers)
	bw("# TYPE uptime_engine_workers_busy gauge\n")
	bw("uptime_engine_workers_busy %d\n", g.WorkersBusy)
	bw("# TYPE uptime_engine_owner_alive gauge\n")
	alive := int64(0)
	if g.OwnerAlive {
		alive = 1
	}
	bw("uptime_engine_owner_alive %d\n", alive)

	counts, age := outboxSnapshot(m.outbox, now)
	bw("# TYPE uptime_outbox_deliveries gauge\n")
	for i, s := range OutboxStates {
		bw("uptime_outbox_deliveries{state=%q} %d\n", s, counts[i])
	}
	bw("# TYPE uptime_outbox_snapshot_age_seconds gauge\n")
	bw("uptime_outbox_snapshot_age_seconds %d\n", age)
	return nil
}

// Handler serves GET /metrics. Authorization (bearer token when
// configured) is applied by the caller's middleware — the handler
// itself holds no secrets.
func (m *Metrics) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		w.Header().Set("Cache-Control", "no-store")
		_ = m.Render(w, time.Now())
	})
}

// RequireBearer gates a metrics surface behind a static token.
// Constant-time compare; the token is never logged or rendered.
// An empty token is a wiring bug — fail closed.
func RequireBearer(token string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := r.Header.Get("Authorization")
		want := "Bearer " + token
		if token == "" || subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
			w.Header().Set("Cache-Control", "no-store")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func denialLabel(i int) string {
	if i < len(denialLabels) {
		return denialLabels[i]
	}
	return labelOther
}

func outcomeLabel(i int) string {
	if i < len(outcomeLabels) {
		return outcomeLabels[i]
	}
	return labelOther
}

func finalizeLabel(i int) string {
	if i == finalizeErrorSlot {
		return "error"
	}
	if i < len(finalizeLabels) {
		return finalizeLabels[i]
	}
	return labelOther
}

// OutboxGauges is a TTL-cached read of notification_outbox state
// counts. The cache bounds DB cost to one grouped query per TTL
// regardless of scrape rate, and the exported snapshot age makes a
// stale or missing read honest instead of a false zero.
type OutboxGauges struct {
	src     func(ctx context.Context) ([len(OutboxStates)]int64, error)
	ttl     time.Duration
	timeout time.Duration

	mu          sync.Mutex
	counts      [len(OutboxStates)]int64
	refreshedAt time.Time
	have        bool
	lastErr     error
}

// NewOutboxGauges wraps a state-count query. ttl bounds refresh
// frequency (>=1s); timeout bounds each probe (>=100ms).
func NewOutboxGauges(src func(ctx context.Context) ([len(OutboxStates)]int64, error),
	ttl, timeout time.Duration) *OutboxGauges {
	if ttl < time.Second {
		ttl = time.Second
	}
	if timeout < 100*time.Millisecond {
		timeout = 100 * time.Millisecond
	}
	return &OutboxGauges{src: src, ttl: ttl, timeout: timeout}
}

// LastErr reports the most recent refresh failure (diagnostics).
func (o *OutboxGauges) LastErr() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.lastErr
}

// snapshot returns the counts plus snapshot age in seconds: -1 when
// no successful refresh has ever happened — a read must not
// masquerade as five healthy zeros.
func (o *OutboxGauges) snapshot(now time.Time) ([len(OutboxStates)]int64, int64) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if !o.have || now.Sub(o.refreshedAt) >= o.ttl {
		o.refresh(now)
	}
	if !o.have {
		return o.counts, -1
	}
	return o.counts, int64(now.Sub(o.refreshedAt).Seconds())
}

func (o *OutboxGauges) refresh(now time.Time) {
	if o.src == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), o.timeout)
	defer cancel()
	counts, err := o.src(ctx)
	if err != nil {
		o.lastErr = err
		return // keep the last good snapshot; age keeps counting
	}
	o.counts = counts
	o.refreshedAt = now
	o.have = true
	o.lastErr = nil
}

func outboxSnapshot(o *OutboxGauges, now time.Time) ([len(OutboxStates)]int64, int64) {
	if o == nil {
		return [len(OutboxStates)]int64{}, -1
	}
	return o.snapshot(now)
}
