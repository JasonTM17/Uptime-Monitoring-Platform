package engine

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/checker"
	"github.com/google/uuid"
)

func okObs(t checker.Target) checker.Observation {
	status := 200
	lat := int64(1)
	o, _ := checker.NewObservation(t, checker.OutcomeSuccess, &status, &lat, time.Now())
	return o
}

type fakeChecker struct {
	mu      sync.Mutex
	peaked  int32
	cur     int32
	delay   time.Duration
	calls   int32
	panic   bool
	block   chan struct{}      // non-nil: Check blocks until closed or ctx done
	targets map[uuid.UUID]bool // MonitorIDs that reached Check
}

func (f *fakeChecker) Check(ctx context.Context, t checker.Target) checker.Observation {
	atomic.AddInt32(&f.calls, 1)
	f.mu.Lock()
	if f.targets == nil {
		f.targets = map[uuid.UUID]bool{}
	}
	f.targets[t.MonitorID] = true
	f.mu.Unlock()
	c := atomic.AddInt32(&f.cur, 1)
	for {
		m := atomic.LoadInt32(&f.peaked)
		if c <= m || atomic.CompareAndSwapInt32(&f.peaked, m, c) {
			break
		}
	}
	defer atomic.AddInt32(&f.cur, -1)
	if f.block != nil {
		select {
		case <-f.block:
		case <-ctx.Done():
			o, _ := checker.NewObservation(t, checker.OutcomeCanceled, nil, nil, time.Now())
			return o
		}
	}
	if f.delay > 0 {
		time.Sleep(f.delay)
	}
	if f.panic {
		panic("checker blew up")
	}
	return okObs(t)
}

func mkJob() Job {
	return Job{
		RunID: uuid.New(), MonitorID: uuid.New(), OwnerID: uuid.New(),
		SegmentID: uuid.New(), Sequence: 1, Epoch: 1, SlotAt: time.Now(),
		Target: checker.Target{
			MonitorID: uuid.New(), URL: "https://x.test", TimeoutSeconds: 2,
		},
	}
}

// Peak concurrency never exceeds configured workers; results are
// bounded and identity survives the pool.
func TestWorkerBounds(t *testing.T) {
	f := &fakeChecker{delay: 30 * time.Millisecond}
	p := NewWorkerPool(4, 8, f)
	ctx := context.Background()
	p.Start(ctx)

	const n = 20
	go func() {
		for i := 0; i < n; i++ {
			p.Submit(ctx, mkJob())
		}
		p.CloseJobs()
	}()
	got := 0
	for got < n {
		select {
		case r := <-p.Results():
			got++
			if r.Job.RunID == uuid.Nil || r.Observation.MonitorID == uuid.Nil {
				t.Fatal("identity not preserved through pool")
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("starved: %d/%d results", got, n)
		}
	}
	p.Wait()
	if f.peaked > 4 {
		t.Fatalf("concurrency exceeded workers: %d > 4", f.peaked)
	}
}

// Parent cancellation makes workers exit without send-on-closed or
// leaks — Wait must complete.
func TestWorkerCancellation(t *testing.T) {
	f := &fakeChecker{delay: 50 * time.Millisecond}
	p := NewWorkerPool(3, 4, f)
	ctx, cancel := context.WithCancel(context.Background())
	p.Start(ctx)
	for i := 0; i < 4; i++ {
		p.Submit(ctx, mkJob())
	}
	cancel()
	done := make(chan struct{})
	go func() { p.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("workers leaked after cancellation")
	}
}

// A full results channel backpressures the worker without loss when
// the consumer drains.
func TestResultBackpressure(t *testing.T) {
	f := &fakeChecker{}
	p := NewWorkerPool(2, 2, f)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p.Start(ctx)

	const n = 8
	go func() {
		for i := 0; i < n; i++ {
			p.Submit(ctx, mkJob())
		}
		p.CloseJobs()
	}()
	time.Sleep(100 * time.Millisecond) // let results fill
	got := 0
	for got < n {
		select {
		case <-p.Results():
			got++
		case <-time.After(3 * time.Second):
			t.Fatalf("results lost under backpressure: %d/%d", got, n)
		}
	}
	p.Wait()
}

// A panicking checker must not kill the worker or lose the
// reservation — the job becomes an excluded INTERNAL_ERROR result.
func TestWorkerPanicBoundary(t *testing.T) {
	f := &fakeChecker{panic: true}
	p := NewWorkerPool(1, 2, f)
	ctx := context.Background()
	p.Start(ctx)
	p.Submit(ctx, mkJob())
	select {
	case r := <-p.Results():
		if r.Observation.Outcome != checker.OutcomeInternalError {
			t.Fatalf("panic outcome: %v", r.Observation.Outcome)
		}
		if r.Observation.Outcome.IsEligible() {
			t.Fatal("panicked check produced eligible evidence")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("panic swallowed the job entirely")
	}
	// Worker still alive for the next job.
	f.panic = false
	p.Submit(ctx, mkJob())
	select {
	case r := <-p.Results():
		if r.Observation.Outcome != checker.OutcomeSuccess {
			t.Fatalf("worker dead after panic: %v", r.Observation.Outcome)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("worker did not recover")
	}
	p.CloseJobs()
	p.Wait()
}

// F01: queue wait does not consume the target budget — a 2s-timeout
// job queued ~150ms still gets its full check window.
func TestQueuedJobTargetBudget(t *testing.T) {
	f := &fakeChecker{delay: 60 * time.Millisecond}
	p := NewWorkerPool(1, 4, f)
	ctx := context.Background()
	p.Start(ctx)

	slow := mkJob()
	slow.Target.TimeoutSeconds = 1
	p.Submit(ctx, mkJob()) // occupies the single worker ~60ms
	p.Submit(ctx, slow)    // sits in queue behind it
	deadline := time.Now().Add(4 * time.Second)
	var sawSlow bool
	for !sawSlow && time.Now().Before(deadline) {
		select {
		case r := <-p.Results():
			if r.Job.RunID == slow.RunID {
				sawSlow = true
				if r.Observation.Outcome != checker.OutcomeSuccess {
					t.Fatalf("queued job lost its budget: %v", r.Observation.Outcome)
				}
			}
		case <-time.After(time.Second):
		}
	}
	if !sawSlow {
		t.Fatal("queued job never ran")
	}
	p.CloseJobs()
	p.Wait()
}

// A job whose engine ctx is canceled before the attempt does zero
// I/O — no observation, reservation stays recoverable.
func TestPreAttemptCancellation(t *testing.T) {
	f := &fakeChecker{block: make(chan struct{}), calls: 0}
	p := NewWorkerPool(1, 4, f)
	ctx, cancel := context.WithCancel(context.Background())
	p.Start(ctx)

	p.Submit(ctx, mkJob()) // blocks the single worker
	queued := mkJob()
	p.Submit(ctx, queued) // sits in queue
	cancel()              // kill engine ctx while job queued
	close(f.block)
	p.CloseJobs()

	done := make(chan struct{})
	go func() { p.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("worker leaked")
	}
	// Drain whatever escaped — but the queued job must never have
	// reached the checker.
	for {
		select {
		case r := <-p.Results():
			if r.Job.RunID == queued.RunID {
				t.Fatal("canceled-queued job produced an observation")
			}
		default:
			f.mu.Lock()
			hit := f.targets[queued.Target.MonitorID]
			f.mu.Unlock()
			if hit {
				t.Fatal("canceled-queued job reached the checker")
			}
			return
		}
	}
}
