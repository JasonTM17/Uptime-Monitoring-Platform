package monitor

import (
	"context"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Store is the service-facing persistence seam for self-contained
// operations (each takes its own locks). *Repository satisfies it;
// unit tests substitute fakes without a database.
type Store interface {
	CreateMonitor(ctx context.Context, ownerID uuid.UUID, in WriteFields, caps Caps) (Monitor, error)
	GetMonitor(ctx context.Context, ownerID, id uuid.UUID) (Monitor, error)
	ListMonitors(ctx context.Context, ownerID uuid.UUID, after Cursor, filter ListFilter, limit int) ([]Monitor, error)
	UpdateMonitor(ctx context.Context, ownerID, id uuid.UUID, expectedGen int64, in WriteFields) (Monitor, error)
	SetMonitorPaused(ctx context.Context, ownerID, id uuid.UUID, expectedGen int64, paused bool) (Monitor, error)
	SoftDeleteMonitor(ctx context.Context, ownerID, id uuid.UUID, expectedGen int64) error
}

// TxStore is the mutation seam for callers that already hold the
// owner user-row lock inside their own transaction — the HTTP
// composition runs these under auth.WithActorLock so session recheck,
// quota fence, and write commit or roll back atomically.
type TxStore interface {
	CreateMonitorTx(ctx context.Context, tx pgx.Tx, ownerID uuid.UUID, monitorLimit int, in WriteFields, caps Caps) (Monitor, error)
	UpdateMonitorTx(ctx context.Context, tx pgx.Tx, ownerID, id uuid.UUID, expectedGen int64, in WriteFields) (Monitor, error)
	SetMonitorPausedTx(ctx context.Context, tx pgx.Tx, ownerID, id uuid.UUID, expectedGen int64, paused bool) (Monitor, error)
	SoftDeleteMonitorTx(ctx context.Context, tx pgx.Tx, ownerID, id uuid.UUID, expectedGen int64) error
}

// Service orchestrates validation + persistence. It holds the
// configured retained caps (Config.Alloc) — live caps stay inside the
// locked transaction (users.monitor_limit, quota_budgets row).
type Service struct {
	store Store
	tx    TxStore
	caps  Caps
}

// NewService takes the same concrete store for both seams — the
// repository implements Store and TxStore.
func NewService(store Store, tx TxStore, caps Caps) *Service {
	return &Service{store: store, tx: tx, caps: caps}
}

func writeFields(name, url string, interval, timeout int, expected *int) WriteFields {
	return WriteFields{Name: name, TargetURL: url,
		IntervalSeconds: interval, TimeoutSeconds: timeout,
		ExpectedStatus: expected}
}

// Create validates the body then enters the quota-fenced insert
// (self-contained variant — see CreateTx for the HTTP path).
// The name is trimmed before persist — the validator already checked
// the trimmed form, so storage and the 120-rune bound stay aligned.
func (s *Service) Create(ctx context.Context, ownerID uuid.UUID, in CreateInput) (Monitor, error) {
	if err := ValidateCreate(in); err != nil {
		return Monitor{}, err
	}
	return s.store.CreateMonitor(ctx, ownerID, writeFields(
		strings.TrimSpace(in.Name), in.TargetURL,
		in.IntervalSeconds, in.TimeoutSeconds, in.ExpectedStatus), s.caps)
}

// CreateTx is the handler-path variant: validation, then the fenced
// insert inside the caller's actor-locked transaction. monitorLimit
// comes from the locked users row — never from request state.
func (s *Service) CreateTx(ctx context.Context, tx pgx.Tx, ownerID uuid.UUID,
	monitorLimit int, in CreateInput) (Monitor, error) {
	if err := ValidateCreate(in); err != nil {
		return Monitor{}, err
	}
	return s.tx.CreateMonitorTx(ctx, tx, ownerID, monitorLimit, writeFields(
		strings.TrimSpace(in.Name), in.TargetURL,
		in.IntervalSeconds, in.TimeoutSeconds, in.ExpectedStatus), s.caps)
}

// MergePatch validates the patch and merges its explicit field set
// onto stored: absent fields keep stored values, explicit null clears
// expected_status. The merged timeout<interval relation is re-checked
// — unreachable under current bounds but kept as a guard if they relax.
func MergePatch(m Monitor, in PatchInput) (WriteFields, error) {
	if err := ValidatePatch(in); err != nil {
		return WriteFields{}, err
	}
	merged := writeFields(m.Name, m.TargetURL, m.IntervalSeconds,
		m.TimeoutSeconds, m.ExpectedStatus)
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
	if merged.TimeoutSeconds >= merged.IntervalSeconds {
		return WriteFields{}, fe(map[string]string{
			"timeout_seconds": "must be less than interval_seconds",
		})
	}
	return merged, nil
}

// Patch is the self-contained variant: unlocked read → merge →
// fenced update. The generation fence inside UpdateMonitor catches
// any row change raced in between.
func (s *Service) Patch(ctx context.Context, ownerID, id uuid.UUID,
	expectedGen int64, in PatchInput) (Monitor, error) {
	m, err := s.store.GetMonitor(ctx, ownerID, id)
	if err != nil {
		return Monitor{}, err
	}
	merged, err := MergePatch(m, in)
	if err != nil {
		return Monitor{}, err
	}
	return s.store.UpdateMonitor(ctx, ownerID, id, expectedGen, merged)
}

// UpdateTx commits an already-merged write-set inside the caller's
// actor-locked transaction (handler path).
func (s *Service) UpdateTx(ctx context.Context, tx pgx.Tx, ownerID, id uuid.UUID,
	expectedGen int64, merged WriteFields) (Monitor, error) {
	return s.tx.UpdateMonitorTx(ctx, tx, ownerID, id, expectedGen, merged)
}

// Pause/Resume/Delete carry the expected generation through to the
// fence — the service adds no semantics of its own so the row's
// optimistic-concurrency contract stays the single authority. The Tx
// variants run inside the caller's actor-locked transaction.
func (s *Service) Pause(ctx context.Context, ownerID, id uuid.UUID, gen int64) (Monitor, error) {
	return s.store.SetMonitorPaused(ctx, ownerID, id, gen, true)
}

func (s *Service) Resume(ctx context.Context, ownerID, id uuid.UUID, gen int64) (Monitor, error) {
	return s.store.SetMonitorPaused(ctx, ownerID, id, gen, false)
}

func (s *Service) Delete(ctx context.Context, ownerID, id uuid.UUID, gen int64) error {
	return s.store.SoftDeleteMonitor(ctx, ownerID, id, gen)
}

func (s *Service) SetPausedTx(ctx context.Context, tx pgx.Tx, ownerID, id uuid.UUID, gen int64, paused bool) (Monitor, error) {
	return s.tx.SetMonitorPausedTx(ctx, tx, ownerID, id, gen, paused)
}

func (s *Service) DeleteTx(ctx context.Context, tx pgx.Tx, ownerID, id uuid.UUID, gen int64) error {
	return s.tx.SoftDeleteMonitorTx(ctx, tx, ownerID, id, gen)
}

func (s *Service) Get(ctx context.Context, ownerID, id uuid.UUID) (Monitor, error) {
	return s.store.GetMonitor(ctx, ownerID, id)
}

func (s *Service) List(ctx context.Context, ownerID uuid.UUID, after Cursor, filter ListFilter, limit int) ([]Monitor, error) {
	return s.store.ListMonitors(ctx, ownerID, after, filter, limit)
}
