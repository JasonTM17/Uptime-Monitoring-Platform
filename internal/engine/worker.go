package engine

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/checker"
	"github.com/google/uuid"
)

// Job is the immutable unit handed to a worker: the committed
// reservation identity plus the target snapshot. It carries a
// TargetTimeout, NOT a deadline computed at enqueue time — a job that
// waits in the queue still gets its full check budget (F01).
type Job struct {
	RunID      uuid.UUID
	MonitorID  uuid.UUID
	OwnerID    uuid.UUID
	SegmentID  uuid.UUID
	Sequence   int64
	Epoch      int64
	Generation int64
	SlotAt     time.Time
	Target     checker.Target
}

// Result preserves the job identity with the checker's observation —
// the finalizer commits it to check_results in C41.
type Result struct {
	Job         Job
	Observation checker.Observation
}

// Checker is the injected outbound-check boundary — the pool holds no
// HTTP or DB state itself.
type Checker interface {
	Check(ctx context.Context, t checker.Target) checker.Observation
}

// WorkerPool is a fixed set of consumers over two bounded channels.
// The coordinator is the SOLE job producer and the sole closer of
// jobs; workers never close shared channels.
type WorkerPool struct {
	jobs    chan Job
	results chan Result
	checker Checker
	workers int
	wg      sync.WaitGroup
	started sync.Once
	mu      sync.RWMutex
	closed  bool

	busy    atomic.Int64 // in-flight check attempts (gauge)
	metrics Counters     // nil-tolerant instrumentation seam
}

func NewWorkerPool(workers, queueSize int, ch Checker) *WorkerPool {
	return &WorkerPool{
		jobs:    make(chan Job, queueSize),
		results: make(chan Result, queueSize),
		checker: ch,
		workers: workers,
	}
}

// Submit enqueues a job, honoring cancellation and queue backpressure.
// Only the coordinator may call it; returns false when ctx ended first.
func (p *WorkerPool) Submit(ctx context.Context, j Job) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.closed {
		return false
	}
	select {
	case p.jobs <- j:
		return true
	case <-ctx.Done():
		return false
	}
}

// TrySubmit enqueues without blocking; false means the queue was full
// or the pool is closed. The send and the close are serialized on
// p.mu  -  a submit racing shutdown returns false, it cannot panic.
func (p *WorkerPool) TrySubmit(j Job) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.closed {
		return false
	}
	select {
	case p.jobs <- j:
		return true
	default:
		return false
	}
}

// Capacity reports free queue slots. Only meaningful while the
// coordinator is the sole producer (consumers can only free space).
func (p *WorkerPool) Capacity() int { return cap(p.jobs) - len(p.jobs) }

// QueueDepth reports jobs buffered but not yet picked up.
func (p *WorkerPool) QueueDepth() int { return len(p.jobs) }

// BusyWorkers reports in-flight check attempts.
func (p *WorkerPool) BusyWorkers() int64 { return p.busy.Load() }

// WorkerCount reports the configured worker set size.
func (p *WorkerPool) WorkerCount() int { return p.workers }

// SetCounters attaches the metrics seam. Nil disables instrumentation.
func (p *WorkerPool) SetCounters(c Counters) { p.metrics = c }

// Results exposes the bounded result stream for the finalizer.
func (p *WorkerPool) Results() <-chan Result { return p.results }

// Start launches the worker goroutines. Idempotent.
func (p *WorkerPool) Start(ctx context.Context) {
	p.started.Do(func() {
		for i := 0; i < p.workers; i++ {
			p.wg.Add(1)
			go p.runWorker(ctx)
		}
	})
}

// Wait blocks until all workers exit — called after jobs is closed
// and drained, or ctx ended. No compensation goroutines are spawned.
func (p *WorkerPool) Wait() { p.wg.Wait() }

// CloseJobs is the coordinator's shutdown signal: close the input
// after the last Submit, then Wait for the in-flight set to finish.
// Idempotent  -  the mutex also serializes against in-flight TrySubmit,
// so no send can land on the closed channel.
func (p *WorkerPool) CloseJobs() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.closed {
		close(p.jobs)
		p.closed = true
	}
}

func (p *WorkerPool) runWorker(ctx context.Context) {
	defer p.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case job, ok := <-p.jobs:
			if !ok {
				return
			}
			// Pre-attempt cancellation: zero-I/O — no observation is
			// emitted and the reservation stays INTERRUPTED-recoverable.
			// A canceled job never masquerades as an eligible TIMEOUT.
			select {
			case <-ctx.Done():
				continue
			default:
			}
			p.busy.Add(1)
			obs := p.execute(ctx, job)
			p.busy.Add(-1)
			if p.metrics != nil {
				p.metrics.RecordObservation(obs.Outcome)
			}
			res := Result{Job: job, Observation: obs}
			select {
			case p.results <- res:
			case <-ctx.Done():
				// Lifecycle canceled: drop, do NOT report success. The
				// RESERVED row remains for takeover reconciliation.
				return
			}
		}
	}
}

// execute runs the check under a fresh per-job timeout created right
// before the call (F01: queue wait is collector lag, not target time)
// and converts a checker panic into a bounded INTERNAL_ERROR so the
// reservation can still be finalized as an excluded observation.
func (p *WorkerPool) execute(ctx context.Context, job Job) (obs checker.Observation) {
	defer func() {
		if r := recover(); r != nil {
			var err error
			obs, err = checker.NewObservation(job.Target,
				checker.OutcomeInternalError, nil, nil, time.Now())
			if err != nil {
				// Never fabricate a zero-value (Success) observation.
				obs = checker.Observation{
					MonitorID: job.Target.MonitorID,
					Outcome:   checker.OutcomeInternalError,
					CheckedAt: time.Now(),
				}
			}
		}
	}()
	cctx, cancel := context.WithTimeout(ctx,
		time.Duration(job.Target.TimeoutSeconds)*time.Second)
	defer cancel()
	return p.checker.Check(cctx, job.Target)
}
