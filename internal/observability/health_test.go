package observability

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// TestHealthOwnerLoss: a dead engine probe fails readiness while
// liveness is untouched — owner loss must not kill the process.
func TestHealthOwnerLoss(t *testing.T) {
	var dbCalls int
	h := NewHealth(
		Probe{Name: "database", Check: func(ctx context.Context) error {
			dbCalls++
			return nil
		}},
		Probe{Name: "engine", Check: func(ctx context.Context) error {
			return errors.New("owner connection lost")
		}},
	)
	if err := h.Live(context.Background()); err != nil {
		t.Fatalf("live must not depend on probes: %v", err)
	}
	err := h.Ready(context.Background())
	if err == nil {
		t.Fatal("ready must fail when the engine probe fails")
	}
	if !strings.Contains(err.Error(), "engine") {
		t.Fatalf("ready error must name the failed probe: %v", err)
	}
	if dbCalls != 1 {
		t.Fatalf("ready ran %d db probes, want 1", dbCalls)
	}

	// Healthy engine -> ready passes.
	h = NewHealth(
		Probe{Name: "database", Check: func(ctx context.Context) error { return nil }},
		Probe{Name: "engine", Check: func(ctx context.Context) error { return nil }},
	)
	if err := h.Ready(context.Background()); err != nil {
		t.Fatalf("ready with all probes green: %v", err)
	}
}

// TestLiveDoesNotTouchDatabase proves liveness is dependency-free:
// a counting fake DB must observe zero calls.
func TestLiveDoesNotTouchDatabase(t *testing.T) {
	var dbCalls int
	fakeDB := func(ctx context.Context) error { dbCalls++; return nil }
	h := NewHealth(Probe{Name: "database", Check: fakeDB})
	for i := 0; i < 5; i++ {
		if err := h.Live(context.Background()); err != nil {
			t.Fatalf("live: %v", err)
		}
	}
	if dbCalls != 0 {
		t.Fatalf("live touched the database %d times", dbCalls)
	}
}

// TestReadyAggregates: every probe runs once per call and all
// failures join — a dead DB must not hide a dead engine.
func TestReadyAggregates(t *testing.T) {
	h := NewHealth(
		Probe{Name: "database", Check: func(ctx context.Context) error {
			return errors.New("down")
		}},
		Probe{Name: "engine", Check: func(ctx context.Context) error {
			return errors.New("lost")
		}},
	)
	err := h.Ready(context.Background())
	if err == nil {
		t.Fatal("ready must fail")
	}
	for _, name := range []string{"database", "engine"} {
		if !strings.Contains(err.Error(), name) {
			t.Fatalf("ready error missing probe %q: %v", name, err)
		}
	}
}
