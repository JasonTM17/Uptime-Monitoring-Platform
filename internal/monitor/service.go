package monitor

import (
	"context"
	"strings"

	"github.com/google/uuid"
)

// Store is the service-facing persistence seam. *Repository satisfies
// it; unit tests substitute fakes without a database.
type Store interface {
	CreateMonitor(ctx context.Context, ownerID uuid.UUID, in WriteFields, caps Caps) (Monitor, error)
	GetMonitor(ctx context.Context, ownerID, id uuid.UUID) (Monitor, error)
	ListMonitors(ctx context.Context, ownerID uuid.UUID, after Cursor, limit int) ([]Monitor, error)
	UpdateMonitor(ctx context.Context, ownerID, id uuid.UUID, expectedGen int64, in WriteFields) (Monitor, error)
	SetMonitorPaused(ctx context.Context, ownerID, id uuid.UUID, expectedGen int64, paused bool) (Monitor, error)
	SoftDeleteMonitor(ctx context.Context, ownerID, id uuid.UUID, expectedGen int64) error
}

// Service orchestrates validation + persistence. It holds the
// configured retained caps (Config.Alloc) — live caps stay inside the
// locked transaction (users.monitor_limit, quota_budgets row).
type Service struct {
	store Store
	caps  Caps
}

func NewService(store Store, caps Caps) *Service {
	return &Service{store: store, caps: caps}
}

// Create validates the body then enters the quota-fenced insert.
// The name is trimmed before persist — the validator already checked
// the trimmed form, so storage and the 120-rune bound stay aligned.
func (s *Service) Create(ctx context.Context, ownerID uuid.UUID, in CreateInput) (Monitor, error) {
	if err := ValidateCreate(in); err != nil {
		return Monitor{}, err
	}
	return s.store.CreateMonitor(ctx, ownerID, WriteFields{
		Name:            strings.TrimSpace(in.Name),
		TargetURL:       in.TargetURL,
		IntervalSeconds: in.IntervalSeconds,
		TimeoutSeconds:  in.TimeoutSeconds,
		ExpectedStatus:  in.ExpectedStatus,
	}, s.caps)
}

// Patch merges the explicit field set onto the stored row, re-checks
// the merged relation (timeout<interval can only be judged against
// final values), then commits under the generation fence. Absent
// fields keep stored values; explicit null clears expected_status.
func (s *Service) Patch(ctx context.Context, ownerID, id uuid.UUID,
	expectedGen int64, in PatchInput) (Monitor, error) {
	if err := ValidatePatch(in); err != nil {
		return Monitor{}, err
	}
	m, err := s.store.GetMonitor(ctx, ownerID, id)
	if err != nil {
		return Monitor{}, err
	}
	merged := WriteFields{
		Name:            m.Name,
		TargetURL:       m.TargetURL,
		IntervalSeconds: m.IntervalSeconds,
		TimeoutSeconds:  m.TimeoutSeconds,
		ExpectedStatus:  m.ExpectedStatus,
	}
	if in.Name.Set {
		merged.Name = strings.TrimSpace(in.Name.V)
	}
	if in.TargetURL.Set {
		merged.TargetURL = in.TargetURL.V
	}
	if in.IntervalSeconds.Set {
		merged.IntervalSeconds = in.IntervalSeconds.V
	}
	if in.TimeoutSeconds.Set {
		merged.TimeoutSeconds = in.TimeoutSeconds.V
	}
	if in.ExpectedStatus.Set {
		if in.ExpectedStatus.Null {
			merged.ExpectedStatus = nil
		} else {
			v := in.ExpectedStatus.V
			merged.ExpectedStatus = &v
		}
	}
	// The merged relation is a row-level invariant, not a per-field
	// one: an interval patch may invalidate a previously valid timeout.
	if merged.TimeoutSeconds >= merged.IntervalSeconds {
		return Monitor{}, fe(map[string]string{
			"timeout_seconds": "must be less than interval_seconds",
		})
	}
	return s.store.UpdateMonitor(ctx, ownerID, id, expectedGen, merged)
}

// Pause/Resume/Delete carry the expected generation through to the
// fence — the service adds no semantics of its own so the row's
// optimistic-concurrency contract stays the single authority.
func (s *Service) Pause(ctx context.Context, ownerID, id uuid.UUID, gen int64) (Monitor, error) {
	return s.store.SetMonitorPaused(ctx, ownerID, id, gen, true)
}

func (s *Service) Resume(ctx context.Context, ownerID, id uuid.UUID, gen int64) (Monitor, error) {
	return s.store.SetMonitorPaused(ctx, ownerID, id, gen, false)
}

func (s *Service) Delete(ctx context.Context, ownerID, id uuid.UUID, gen int64) error {
	return s.store.SoftDeleteMonitor(ctx, ownerID, id, gen)
}

func (s *Service) Get(ctx context.Context, ownerID, id uuid.UUID) (Monitor, error) {
	return s.store.GetMonitor(ctx, ownerID, id)
}

func (s *Service) List(ctx context.Context, ownerID uuid.UUID, after Cursor, limit int) ([]Monitor, error) {
	return s.store.ListMonitors(ctx, ownerID, after, limit)
}
