package engine

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
)

func drain(p *WorkerPool) func() {
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			case <-p.Results():
			}
		}
	}()
	return func() { close(stop) }
}

type fakeClock struct{ t time.Time }

func (f *fakeClock) Now() time.Time { return f.t }

func dueFor(owner uuid.UUID, n int) []DueMonitor {
	out := make([]DueMonitor, n)
	for i := range out {
		out[i] = DueMonitor{
			MonitorID: uuid.New(), OwnerID: owner,
			TargetURL: "https://x.test", TimeoutSeconds: 2,
			IntervalSeconds: 60, NextCheckAt: time.Now(),
		}
	}
	return out
}

func schedForTest(pool *WorkerPool, due []DueMonitor, calls *int32) *Scheduler {
	s := NewScheduler(nil, pool, 1, AdmissionCaps{100, 100}, 50)
	var mu sync.Mutex
	active := map[uuid.UUID]bool{}
	s.SetDueSource(func(context.Context) ([]DueMonitor, error) {
		mu.Lock()
		defer mu.Unlock()
		var out []DueMonitor
		for _, d := range due {
			if !active[d.MonitorID] {
				out = append(out, d)
			}
		}
		return out, nil
	})
	s.SetReserver(func(ctx context.Context, d DueMonitor) (*Reservation, error) {
		mu.Lock()
		active[d.MonitorID] = true
		mu.Unlock()
		if calls != nil {
			atomic.AddInt32(calls, 1)
		}
		return &Reservation{
			RunID: uuid.New(), MonitorID: d.MonitorID, OwnerID: d.OwnerID,
			SegmentID: uuid.New(), Sequence: 1, Epoch: 1, SlotAt: time.Now(),
		}, nil
	})
	return s
}

// One owner with many due monitors must NOT be fairness-capped ---
// work-conserving admission drains the queue with the full pool.
func TestSingleOwnerUtilizesPool(t *testing.T) {
	pool := NewWorkerPool(10, 20, &fakeChecker{})
	pool.Start(context.Background())
	// Drain results --- the real finalizer (C41) owns this channel; a
	// full results queue is legitimate backpressure on the workers.
	stopDrain := drain(pool)
	defer func() { pool.CloseJobs(); pool.Wait(); stopDrain() }()

	owner := uuid.New()
	s := schedForTest(pool, dueFor(owner, 100), nil)
	// Tick until the backlog drains: each tick fills whatever queue
	// space workers freed since the last - the bound only caps
	// runaway, not per-tick throughput.
	total := 0
	for i := 0; i < 500 && total < 100; i++ {
		n, err := s.Tick(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		total += n
	}
	if total != 100 {
		t.Fatalf("single owner capped: admitted %d/100", total)
	}
}

// Multi-owner round-robin: one-per-owner per round, deterministic,
// last-served rotates to the back.
func TestOwnerRoundRobin(t *testing.T) {
	a, b, c := uuid.New(), uuid.New(), uuid.New()
	// Sort order for determinism.
	owners := []uuid.UUID{a, b, c}
	for i := 0; i < len(owners); i++ {
		for j := i + 1; j < len(owners); j++ {
			if owners[j].String() < owners[i].String() {
				owners[i], owners[j] = owners[j], owners[i]
			}
		}
	}
	var due []DueMonitor
	due = append(due, dueFor(owners[0], 3)...)
	due = append(due, dueFor(owners[1], 3)...)
	due = append(due, dueFor(owners[2], 2)...)
	// Interleave input to prove ordering isn't input-dependent.
	for i, j := 0, len(due)-1; i < j; i, j = i+1, j-1 {
		due[i], due[j] = due[j], due[i]
	}

	got := RoundRobinOwners(due, uuid.Nil)
	if len(got) != 8 {
		t.Fatalf("lost candidates: %d", len(got))
	}
	// First three must be one of each owner (round 0).
	seen := map[uuid.UUID]int{}
	for i := 0; i < 3; i++ {
		seen[got[i].OwnerID]++
	}
	if len(seen) != 3 {
		t.Fatalf("round-0 not fair: %v", seen)
	}

	// Rotation: serving owners[0] puts owners[1] first next tick.
	got = RoundRobinOwners(due, owners[0])
	if got[0].OwnerID != owners[1] {
		t.Fatalf("denied/served owner not rotated: got %v first", got[0].OwnerID)
	}
}

// A full queue stops admission --- due stays in the DB (reserver is
// never even called), nothing lost, no storm.
func TestFullQueueRetainsDue(t *testing.T) {
	pool := NewWorkerPool(1, 2, &fakeChecker{block: make(chan struct{})})
	// Workers not started: queue fills and stays full.
	var calls int32
	due := dueFor(uuid.New(), 50)
	s := schedForTest(pool, due, &calls)

	n, err := s.Tick(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("admitted %d with queue cap 2", n)
	}
	if calls != 2 {
		t.Fatalf("reserved beyond capacity: %d", calls)
	}
	// Second tick: queue still full --- zero new reservations.
	n, _ = s.Tick(context.Background())
	if n != 0 || calls != 2 {
		t.Fatalf("full queue leaked reservations: n=%d calls=%d", n, calls)
	}
}

// A clock jump coalesces overdue monitors into ONE bounded batch ---
// no catch-up amplification beyond queue capacity.
func TestClockJumpCoalesces(t *testing.T) {
	clk := &fakeClock{t: time.Now()}
	pool := NewWorkerPool(2, 4, &fakeChecker{})
	var calls int32
	due := dueFor(uuid.New(), 1000) // huge overdue backlog after jump
	s := schedForTest(pool, due, &calls)
	clk.t = clk.t.Add(24 * time.Hour) // the jump
	// Workers deliberately not started: the queue fills and stays
	// full, so the admission bound is deterministic (<= queue cap).
	n, err := s.Tick(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if n > 4 || calls > 4 {
		t.Fatalf("catch-up storm: n=%d calls=%d", n, calls)
	}
	// A second tick in the same full-queue state admits nothing more.
	n2, _ := s.Tick(context.Background())
	if n2 != 0 || calls > 4 {
		t.Fatalf("second tick stormed: n=%d calls=%d", n2, calls)
	}
}
