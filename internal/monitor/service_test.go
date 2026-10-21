package monitor

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type fakeStore struct {
	monitors map[uuid.UUID]Monitor
	created  WriteFields
	gotGen   int64
	gotCaps  Caps
	err      error
}

func newFakeStore() *fakeStore { return &fakeStore{monitors: map[uuid.UUID]Monitor{}} }

func (f *fakeStore) CreateMonitor(_ context.Context, ownerID uuid.UUID, in WriteFields, caps Caps) (Monitor, error) {
	if f.err != nil {
		return Monitor{}, f.err
	}
	m := Monitor{ID: uuid.New(), UserID: ownerID, Name: in.Name,
		TargetURL: in.TargetURL, Method: "GET",
		IntervalSeconds: in.IntervalSeconds, TimeoutSeconds: in.TimeoutSeconds,
		ExpectedStatus: in.ExpectedStatus, Health: HealthUnknown,
		Generation: 1, NextCheckAt: time.Now(), CreatedAt: time.Now(), UpdatedAt: time.Now()}
	f.monitors[m.ID] = m
	f.created, f.gotCaps = in, caps
	return m, nil
}

func (f *fakeStore) GetMonitor(_ context.Context, ownerID, id uuid.UUID) (Monitor, error) {
	if m, ok := f.monitors[id]; ok && m.UserID == ownerID && m.DeletedAt == nil {
		return m, nil
	}
	return Monitor{}, ErrMonitorNotFound
}

func (f *fakeStore) ListMonitors(_ context.Context, ownerID uuid.UUID, _ Cursor, _ ListFilter, _ int) ([]Monitor, error) {
	return nil, nil
}

func (f *fakeStore) UpdateMonitor(_ context.Context, ownerID, id uuid.UUID, gen int64, in WriteFields) (Monitor, error) {
	m, ok := f.monitors[id]
	if !ok || m.UserID != ownerID || m.DeletedAt != nil {
		return Monitor{}, ErrMonitorNotFound
	}
	if m.Generation != gen {
		return Monitor{}, ErrGenerationConflict
	}
	m.Name, m.TargetURL = in.Name, in.TargetURL
	m.IntervalSeconds, m.TimeoutSeconds = in.IntervalSeconds, in.TimeoutSeconds
	m.ExpectedStatus = in.ExpectedStatus
	m.Generation++
	f.monitors[id] = m
	f.gotGen = gen
	return m, nil
}

func (f *fakeStore) SetMonitorPaused(_ context.Context, ownerID, id uuid.UUID, gen int64, paused bool) (Monitor, error) {
	m, ok := f.monitors[id]
	if !ok || m.UserID != ownerID || m.DeletedAt != nil {
		return Monitor{}, ErrMonitorNotFound
	}
	if m.Generation != gen {
		return Monitor{}, ErrGenerationConflict
	}
	if m.IsPaused == paused {
		f.monitors[id] = m // idempotent: no generation bump
		f.gotGen = gen
		return m, nil
	}
	m.IsPaused, m.Generation = paused, m.Generation+1
	f.monitors[id] = m
	f.gotGen = gen
	return m, nil
}

func (f *fakeStore) SoftDeleteMonitor(_ context.Context, ownerID, id uuid.UUID, gen int64) error {
	m, ok := f.monitors[id]
	if !ok || m.UserID != ownerID || m.DeletedAt != nil {
		return ErrMonitorNotFound
	}
	if m.Generation != gen {
		return ErrGenerationConflict
	}
	now := time.Now()
	m.DeletedAt = &now
	f.monitors[id] = m
	f.gotGen = gen
	return nil
}

// TxStore seam for the fake: delegate to the in-memory ops — unit
// tests exercise merge/validation logic, not real transactions.
func (f *fakeStore) CreateMonitorTx(ctx context.Context, _ pgx.Tx, ownerID uuid.UUID, _ int, in WriteFields, caps Caps) (Monitor, error) {
	return f.CreateMonitor(ctx, ownerID, in, caps)
}
func (f *fakeStore) UpdateMonitorTx(ctx context.Context, _ pgx.Tx, ownerID, id uuid.UUID, gen int64, in WriteFields) (Monitor, error) {
	return f.UpdateMonitor(ctx, ownerID, id, gen, in)
}
func (f *fakeStore) SetMonitorPausedTx(ctx context.Context, _ pgx.Tx, ownerID, id uuid.UUID, gen int64, paused bool) (Monitor, error) {
	return f.SetMonitorPaused(ctx, ownerID, id, gen, paused)
}
func (f *fakeStore) SoftDeleteMonitorTx(ctx context.Context, _ pgx.Tx, ownerID, id uuid.UUID, gen int64) error {
	return f.SoftDeleteMonitor(ctx, ownerID, id, gen)
}

var validFields = WriteFields{
	Name: "api", TargetURL: "https://example.com/health",
	IntervalSeconds: 60, TimeoutSeconds: 5,
}

func TestServiceCreate(t *testing.T) {
	ctx := context.Background()
	owner := uuid.New()

	t.Run("valid input reaches store with trimmed name and caps", func(t *testing.T) {
		fs := newFakeStore()
		svc := NewService(fs, fs, Caps{RetainedOwner: 100, RetainedGlobal: 200})
		m, err := svc.Create(ctx, owner, CreateInput{
			Name: "  api  ", TargetURL: "https://example.com/health",
			IntervalSeconds: 60, TimeoutSeconds: 5})
		if err != nil {
			t.Fatalf("create: %v", err)
		}
		if fs.created.Name != "api" || m.Health != HealthUnknown || m.Generation != 1 {
			t.Fatalf("bad persist %+v", m)
		}
		if fs.gotCaps.RetainedOwner != 100 || fs.gotCaps.RetainedGlobal != 200 {
			t.Fatalf("caps not forwarded: %+v", fs.gotCaps)
		}
	})

	t.Run("invalid input never reaches store", func(t *testing.T) {
		fs := newFakeStore()
		svc := NewService(fs, fs, Caps{RetainedOwner: 100, RetainedGlobal: 200})
		_, err := svc.Create(ctx, owner, CreateInput{
			Name: "", TargetURL: "ftp://x", IntervalSeconds: 10, TimeoutSeconds: 60})
		var feErr *FieldError
		if !errors.As(err, &feErr) {
			t.Fatalf("want FieldError, got %v", err)
		}
		if len(fs.monitors) != 0 {
			t.Fatal("invalid input was persisted")
		}
	})
}

func TestServicePatch(t *testing.T) {
	ctx := context.Background()
	owner := uuid.New()
	seed := func() (*fakeStore, Monitor) {
		fs := newFakeStore()
		m, _ := fs.CreateMonitor(ctx, owner, validFields, Caps{})
		return fs, m
	}

	t.Run("absent fields keep stored values", func(t *testing.T) {
		fs, m := seed()
		svc := NewService(fs, fs, Caps{})
		p := PatchInput{}
		p.IntervalSeconds.Set, p.IntervalSeconds.V = true, 120
		up, err := svc.Patch(ctx, owner, m.ID, 1, p)
		if err != nil {
			t.Fatalf("patch: %v", err)
		}
		if up.IntervalSeconds != 120 || up.TimeoutSeconds != 5 || up.Name != "api" {
			t.Fatalf("merge lost fields %+v", up)
		}
	})

	t.Run("explicit null clears expected_status", func(t *testing.T) {
		fs := newFakeStore()
		es := 201
		wf := validFields
		wf.ExpectedStatus = &es
		m, _ := fs.CreateMonitor(ctx, owner, wf, Caps{})
		svc := NewService(fs, fs, Caps{})
		p := PatchInput{}
		p.ExpectedStatus.Set, p.ExpectedStatus.Null = true, true
		up, err := svc.Patch(ctx, owner, m.ID, 1, p)
		if err != nil {
			t.Fatalf("patch: %v", err)
		}
		if up.ExpectedStatus != nil {
			t.Fatalf("null did not clear expected_status: %v", *up.ExpectedStatus)
		}
	})

	t.Run("out-of-bounds patch rejected before store", func(t *testing.T) {
		fs, m := seed()
		svc := NewService(fs, fs, Caps{})
		p := PatchInput{}
		p.IntervalSeconds.Set, p.IntervalSeconds.V = true, 10
		if _, err := svc.Patch(ctx, owner, m.ID, 1, p); err == nil {
			t.Fatal("expected validation rejection")
		}
		if fs.gotGen != 0 {
			t.Fatal("invalid patch reached store")
		}
		// Note: the merged timeout<interval relation re-check in
		// Service.Patch is unreachable under current bounds
		// (interval≥60 > timeout≤10) — kept as a guard if bounds relax.
	})

	t.Run("stale generation surfaces conflict", func(t *testing.T) {
		fs, m := seed()
		svc := NewService(fs, fs, Caps{})
		p := PatchInput{}
		p.Name.Set, p.Name.V = true, "renamed"
		_, err := svc.Patch(ctx, owner, m.ID, 99, p)
		if !errors.Is(err, ErrGenerationConflict) {
			t.Fatalf("want conflict, got %v", err)
		}
	})
}
