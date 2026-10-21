package engine

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/checker"
	"github.com/google/uuid"
)

// stubCounters records every seam call for assertions.
type stubCounters struct {
	mu       sync.Mutex
	admitted int64
	denials  map[DenialCause]int64
	obs      map[checker.Outcome]int64
	finalize map[bool]int64
	owner    int64
}

func newStub() *stubCounters {
	return &stubCounters{
		denials:  map[DenialCause]int64{},
		obs:      map[checker.Outcome]int64{},
		finalize: map[bool]int64{},
	}
}

func (s *stubCounters) RecordAdmissions(n int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.admitted += n
}
func (s *stubCounters) RecordDenial(d DenialCause) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.denials[d]++
}
func (s *stubCounters) RecordObservation(o checker.Outcome) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.obs[o]++
}
func (s *stubCounters) RecordFinalize(_ FinalizeOutcome, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.finalize[ok]++
}
func (s *stubCounters) RecordOwnerLoss() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.owner++
}

// Tick records one admission per committed+enqueued run, and the
// matching denial cause when the bounded budgets refuse.
func TestTickRecordsAdmissionsAndDenials(t *testing.T) {
	pool := NewWorkerPool(2, 10, &fakeChecker{})
	stub := newStub()
	s := schedForTest(pool, dueFor(uuid.New(), 3), nil)
	s.SetCounters(stub)

	// Don't start the pool: jobs stay queued, nothing drains.
	n, err := s.Tick(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Fatalf("admitted %d, want 3", n)
	}
	if stub.admitted != 3 {
		t.Fatalf("admissions recorded %d, want 3", stub.admitted)
	}

	// Global window denial stops the tick and is counted once.
	s2 := schedForTest(pool, dueFor(uuid.New(), 1), nil)
	s2.SetCounters(stub)
	s2.SetReserver(func(context.Context, DueMonitor) (*Reservation, error) {
		return nil, ErrAdmissionFull
	})
	if _, err := s2.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if stub.denials[DenialGlobalWindow] != 1 {
		t.Fatalf("global denials %d, want 1", stub.denials[DenialGlobalWindow])
	}

	// Owner window denial is counted and the tick continues.
	s3 := schedForTest(pool, dueFor(uuid.New(), 1), nil)
	s3.SetCounters(stub)
	s3.SetReserver(func(context.Context, DueMonitor) (*Reservation, error) {
		return nil, ErrOwnerAdmissionFull
	})
	if _, err := s3.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if stub.denials[DenialOwnerWindow] != 1 {
		t.Fatalf("owner denials %d, want 1", stub.denials[DenialOwnerWindow])
	}
	pool.CloseJobs()
	pool.Wait()
}

// A saturated queue denies before reserving — counted as queue_full.
func TestQueueFullDenialCounted(t *testing.T) {
	pool := NewWorkerPool(1, 1, &fakeChecker{}) // capacity 1
	stub := newStub()
	// Fill the one slot manually.
	if !pool.TrySubmit(Job{RunID: uuid.New()}) {
		t.Fatal("precondition: pool should accept one job")
	}
	s := schedForTest(pool, dueFor(uuid.New(), 1), nil)
	s.SetCounters(stub)
	n, err := s.Tick(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("admitted %d on full queue", n)
	}
	if stub.denials[DenialQueueFull] != 1 {
		t.Fatalf("queue denials %d, want 1", stub.denials[DenialQueueFull])
	}
	if stub.admitted != 0 {
		t.Fatalf("admissions %d on full queue", stub.admitted)
	}
	pool.CloseJobs()
	pool.Wait()
}

// The pool records each finished attempt's outcome and keeps the
// busy gauge balanced around the call.
func TestWorkerRecordsObservations(t *testing.T) {
	stub := newStub()
	pool := NewWorkerPool(1, 4, &fakeChecker{})
	pool.SetCounters(stub)
	pool.Start(context.Background())
	stopDrain := drain(pool)
	defer func() { pool.CloseJobs(); pool.Wait(); stopDrain() }()

	for i := 0; i < 3; i++ {
		if !pool.TrySubmit(Job{
			RunID: uuid.New(), MonitorID: uuid.New(),
			Target: checker.Target{TimeoutSeconds: 1},
		}) {
			t.Fatal("submit failed")
		}
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		stub.mu.Lock()
		total := int64(0)
		for _, n := range stub.obs {
			total += n
		}
		stub.mu.Unlock()
		if total == 3 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	stub.mu.Lock()
	defer stub.mu.Unlock()
	total := int64(0)
	for _, n := range stub.obs {
		total += n
	}
	if total != 3 {
		t.Fatalf("observations recorded %d, want 3", total)
	}
	if pool.BusyWorkers() != 0 {
		t.Fatalf("busy gauge leaked: %d", pool.BusyWorkers())
	}
}
