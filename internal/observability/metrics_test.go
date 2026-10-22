package observability

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/checker"
	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/engine"
)

func testGauges() engine.EngineGauges {
	return engine.EngineGauges{
		QueueDepth: 7, WorkersBusy: 3, Workers: 10, OwnerAlive: true,
	}
}

// TestMetricCardinality proves the catalog is closed: feeding every
// enum value plus out-of-range values still renders only the finite
// series set, no label carries identity, and re-rendering does not
// mutate the counters it reports.
func TestMetricCardinality(t *testing.T) {
	var dbCalls int
	outbox := NewOutboxGauges(
		func(ctx context.Context) ([5]int64, error) {
			dbCalls++
			return [5]int64{3, 1, 40, 2, 5}, nil
		}, time.Minute, time.Second)

	m := NewMetrics(testGauges, outbox)
	m.RecordAdmissions(11)
	for d := engine.DenialQueueFull; d <= engine.DenialGlobalWindow; d++ {
		m.RecordDenial(d)
	}
	m.RecordDenial(engine.DenialCause(99)) // out-of-range -> "other"
	for o := checker.OutcomeSuccess; o <= checker.OutcomeInternalError; o++ {
		m.RecordObservation(o)
	}
	m.RecordObservation(checker.Outcome(255)) // out-of-range -> "other"
	m.RecordFinalize(engine.FinalizeCommitted, true)
	m.RecordFinalize(engine.FinalizeStale, true)
	m.RecordFinalize(engine.FinalizeDuplicate, true)
	m.RecordFinalize(engine.FinalizeCommitted, false) // error slot
	m.RecordOwnerLoss()
	m.RecordOwnerLoss() // counter counts calls; writer dedupes upstream

	render := func() string {
		var b strings.Builder
		if err := m.Render(&b, time.Now()); err != nil {
			t.Fatal(err)
		}
		return b.String()
	}
	out := render()

	// Every emitted series name must belong to the catalog.
	wantNames := map[string]bool{
		"uptime_engine_admissions_total":        true,
		"uptime_engine_admission_denials_total": true,
		"uptime_engine_observations_total":      true,
		"uptime_engine_finalize_total":          true,
		"uptime_engine_owner_loss_total":        true,
		"uptime_engine_queue_depth":             true,
		"uptime_engine_workers":                 true,
		"uptime_engine_workers_busy":            true,
		"uptime_engine_goroutines":              true,
		"uptime_engine_owner_alive":             true,
		"uptime_outbox_deliveries":              true,
		"uptime_outbox_snapshot_age_seconds":    true,
	}
	series := 0
	for _, line := range strings.Split(out, "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		series++
		name := line
		if i := strings.IndexAny(name, "{ "); i >= 0 {
			name = name[:i]
		}
		if !wantNames[name] {
			t.Fatalf("uncataloged series emitted: %q", line)
		}
	}
	// Hard ceiling: counters (1+4+10+4+1) + gauges (4) + outbox (5+1).
	if series > 31 {
		t.Fatalf("series bound exceeded: %d", series)
	}

	// Label values must come from the finite tables only.
	labelRe := regexp.MustCompile(`\{(reason|outcome|result|state)="([^"]+)"\}`)
	allowed := map[string]bool{
		"queue_full": true, "owner_window": true, "global_window": true,
		"success": true, "unexpected_status": true, "dns_error": true,
		"connect_error": true, "tls_error": true, "timeout": true,
		"policy_blocked": true, "canceled": true, "internal_error": true,
		"committed": true, "stale": true, "duplicate": true, "error": true,
		"PENDING": true, "LEASED": true, "SENT": true, "DEAD": true,
		"SUPPRESSED": true, "other": true,
	}
	for _, mm := range labelRe.FindAllStringSubmatch(out, -1) {
		if !allowed[mm[2]] {
			t.Fatalf("label value outside finite domain: %q", mm[0])
		}
	}

	// Identity/secret hygiene: no URLs, emails, DSNs, uuids, tokens.
	for _, bad := range []string{
		"http://", "https://", "postgres", "@", "token", "secret", "dsn",
	} {
		if strings.Contains(strings.ToLower(out), bad) {
			t.Fatalf("exposition leaks %q", bad)
		}
	}
	if regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}`).MatchString(out) {
		t.Fatal("exposition contains a uuid-shaped value")
	}

	// Values landed where expected.
	for _, want := range []string{
		"uptime_engine_admissions_total 11",
		`uptime_engine_admission_denials_total{reason="queue_full"} 1`,
		`uptime_engine_observations_total{outcome="timeout"} 1`,
		`uptime_engine_observations_total{outcome="other"} 1`,
		`uptime_engine_finalize_total{result="error"} 1`,
		`uptime_engine_admission_denials_total{reason="other"} 1`,
		"uptime_engine_owner_loss_total 2",
		"uptime_engine_queue_depth 7",
		"uptime_engine_workers_busy 3",
		"uptime_engine_workers 10",
		"uptime_engine_owner_alive 1",
		`uptime_outbox_deliveries{state="PENDING"} 3`,
		`uptime_outbox_deliveries{state="DEAD"} 2`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing series %q in:\n%s", want, out)
		}
	}

	// Render is idempotent: a second scrape reports identical values.
	if render() != out {
		t.Fatal("render mutated reported state")
	}
	// TTL bound: both renders shared at most one refresh.
	if dbCalls > 1 {
		t.Fatalf("outbox refreshed per render: %d calls", dbCalls)
	}
}

// TestRenderWithoutSources proves a nil-source collector still emits
// honest values: zero engine gauges, -1 outbox age (no snapshot yet).
func TestRenderWithoutSources(t *testing.T) {
	m := NewMetrics(nil, nil)
	var b strings.Builder
	if err := m.Render(&b, time.Now()); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	if !strings.Contains(out, "uptime_outbox_snapshot_age_seconds -1") {
		t.Fatal("missing-source outbox must report age -1, not zero")
	}
	if !strings.Contains(out, `uptime_outbox_deliveries{state="PENDING"} 0`) {
		t.Fatal("missing-source outbox counts must be zero")
	}
}

// TestOutboxSnapshotFreshness: a failed refresh keeps the last good
// counts while age keeps growing — never a false fresh zero.
func TestOutboxSnapshotFreshness(t *testing.T) {
	now := time.Now()
	var calls int
	fail := false
	src := func(ctx context.Context) ([5]int64, error) {
		calls++
		if fail {
			return [5]int64{}, errors.New("db down")
		}
		return [5]int64{9, 0, 0, 0, 0}, nil
	}
	o := NewOutboxGauges(src, 10*time.Second, time.Second)
	m := NewMetrics(nil, o)

	render := func(at time.Time) string {
		var b strings.Builder
		if err := m.Render(&b, at); err != nil {
			t.Fatal(err)
		}
		return b.String()
	}

	out := render(now)
	if !strings.Contains(out, `uptime_outbox_deliveries{state="PENDING"} 9`) {
		t.Fatal("initial snapshot missing")
	}
	fail = true
	out = render(now.Add(30 * time.Second)) // past TTL -> refresh fails
	if !strings.Contains(out, `uptime_outbox_deliveries{state="PENDING"} 9`) {
		t.Fatal("failed refresh clobbered last-good counts")
	}
	if !strings.Contains(out, "uptime_outbox_snapshot_age_seconds 30") {
		t.Fatalf("stale age not reported: %s", out)
	}
	if calls != 2 {
		t.Fatalf("expected exactly 2 refreshes, got %d", calls)
	}
}

// TestHandler verifies GET-only and content type without a server.
func TestHandler(t *testing.T) {
	m := NewMetrics(testGauges, nil)
	h := m.Handler()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != 200 {
		t.Fatalf("GET /metrics -> %d", rec.Code)
	}
	if !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/plain") {
		t.Fatalf("content-type %q", rec.Header().Get("Content-Type"))
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/metrics", nil))
	if rec.Code != 405 {
		t.Fatalf("POST /metrics -> %d, want 405", rec.Code)
	}
}
