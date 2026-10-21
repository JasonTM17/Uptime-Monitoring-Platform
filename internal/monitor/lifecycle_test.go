package monitor

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
)

// TestLifecyclePolicy locks the transition contract at the service
// seam: state stays orthogonal to health, same-state transitions are
// no-ops, and the generation fence rejects stale callers.
func TestLifecyclePolicy(t *testing.T) {
	ctx := context.Background()
	owner := uuid.New()

	seed := func() (*fakeStore, Monitor) {
		fs := newFakeStore()
		m, _ := fs.CreateMonitor(ctx, owner, validFields, Caps{})
		return fs, m
	}

	t.Run("pause bumps generation once, repeat is a no-op", func(t *testing.T) {
		fs, m := seed()
		svc := NewService(fs, fs, Caps{})
		p, err := svc.Pause(ctx, owner, m.ID, m.Generation)
		if err != nil || !p.IsPaused || p.Generation != 2 {
			t.Fatalf("pause: %v %+v", err, p)
		}
		// Same-state repeat with the CURRENT generation: success, no
		// second bump — idempotent command semantics.
		p2, err := svc.Pause(ctx, owner, m.ID, p.Generation)
		if err != nil || p2.Generation != 2 {
			t.Fatalf("repeat pause mutated: %v %+v", err, p2)
		}
	})

	t.Run("pause never fabricates health", func(t *testing.T) {
		fs, m := seed()
		svc := NewService(fs, fs, Caps{})
		p, _ := svc.Pause(ctx, owner, m.ID, m.Generation)
		if p.Health != HealthUnknown || p.FailureStreak != 0 {
			t.Fatalf("pause wrote health %+v", p)
		}
	})

	t.Run("stale generation conflicts on both verbs", func(t *testing.T) {
		fs, m := seed()
		svc := NewService(fs, fs, Caps{})
		if _, err := svc.Pause(ctx, owner, m.ID, 99); !errors.Is(err, ErrGenerationConflict) {
			t.Fatalf("stale pause: %v", err)
		}
		if _, err := svc.Resume(ctx, owner, m.ID, 99); !errors.Is(err, ErrGenerationConflict) {
			t.Fatalf("stale resume: %v", err)
		}
	})

	t.Run("resume after pause restores eligibility only", func(t *testing.T) {
		fs, m := seed()
		svc := NewService(fs, fs, Caps{})
		p, _ := svc.Pause(ctx, owner, m.ID, m.Generation)
		r, err := svc.Resume(ctx, owner, m.ID, p.Generation)
		if err != nil || r.IsPaused || r.Health != HealthUnknown || r.Generation != 3 {
			t.Fatalf("resume: %v %+v", err, r)
		}
	})
}
