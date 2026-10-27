package notification

import (
	"context"
	"errors"
	"math/rand/v2"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestAuditRateLimitThenFirstTransientSend(t *testing.T) {
	store := newFakeStore()
	clock := &fakeClock{now: time.Now()}
	sender := &fakeSender{script: func(int) (Delivery, error) { return Delivery{}, errors.New("temporary") }}
	d := testDispatcher(store, sender, clock)
	d.limit = NewLimiter(1, 1, clock)
	c := mkClaim("DOWN", 1)
	c.CreatedAt = clock.now
	if !d.limit.Allow(c.ChannelID) {
		t.Fatal("could not consume initial limiter token")
	}
	for n := 1; n <= 7; n++ {
		c.Attempts = n
		c.RateLimitRefusals = n - 1
		if err := d.process(context.Background(), c); err != nil {
			t.Fatal(err)
		}
	}
	if len(sender.calls) != 0 || store.resched[c.ID] != 7 {
		t.Fatal("expected seven unsent rate-limit reschedules")
	}
	clock.Advance(time.Second)
	c.Attempts = 8
	c.RateLimitRefusals = 7
	var scheduled time.Time
	reschedule := d.reschedFn
	d.reschedFn = func(ctx context.Context, id, token uuid.UUID, next time.Time, code string, max int) (Disposition, error) {
		scheduled = next
		return reschedule(ctx, id, token, next, code, max)
	}
	if err := d.process(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	if len(sender.calls) != 1 {
		t.Fatalf("expected one send, got %d", len(sender.calls))
	}
	if code := store.dead[c.ID]; code != "" {
		t.Fatalf("first transient send was dead-lettered: %s", code)
	}
	if store.resched[c.ID] != 8 {
		t.Fatalf("expected retry after seven refusals, got %d reschedules", store.resched[c.ID])
	}
	if delay := scheduled.Sub(clock.now); delay < 4500*time.Millisecond || delay > 5500*time.Millisecond {
		t.Fatalf("first-send backoff = %v", delay)
	}
}

func TestAuditExternalProviderRateLimitThenTransientSend(t *testing.T) {
	store := newFakeStore()
	clock := &fakeClock{now: time.Now()}
	sender := &fakeSender{script: func(call int) (Delivery, error) {
		if call <= 7 {
			return Delivery{RetryAfter: 7 * time.Second}, ratelimitf("telegram: rate limited (retry_after=7s)")
		}
		return Delivery{}, errors.New("temporary failure")
	}}
	d := testDispatcher(store, sender, clock)
	c := mkClaim("DOWN", 1)
	c.CreatedAt = clock.now

	var scheduled time.Time
	var lastCode string
	var lastMax int
	reschedule := d.reschedFn
	d.reschedFn = func(ctx context.Context, id, token uuid.UUID, next time.Time, code string, max int) (Disposition, error) {
		scheduled = next
		lastCode = code
		lastMax = max
		return reschedule(ctx, id, token, next, code, max)
	}

	for n := 1; n <= 7; n++ {
		c.Attempts = n
		c.RateLimitRefusals = n - 1
		if err := d.process(context.Background(), c); err != nil {
			t.Fatal(err)
		}
		if lastCode != "RATE_LIMITED" {
			t.Fatalf("call %d: expected RATE_LIMITED, got %s", n, lastCode)
		}
		if lastMax != d.cfg.Retry.MaxAttempts*8 {
			t.Fatalf("call %d: expected maxAttempts %d, got %d", n, d.cfg.Retry.MaxAttempts*8, lastMax)
		}
		if delay := scheduled.Sub(clock.now); delay < 6000*time.Millisecond || delay > 8000*time.Millisecond {
			t.Fatalf("call %d: expected rate-limit backoff around 7s, got %v", n, delay)
		}
		if store.dead[c.ID] != "" {
			t.Fatalf("call %d was dead-lettered: %s", n, store.dead[c.ID])
		}
	}
	if len(sender.calls) != 7 || store.resched[c.ID] != 7 {
		t.Fatalf("expected seven sent rate-limit reschedules, got sends=%d resched=%d",
			len(sender.calls), store.resched[c.ID])
	}

	// 8th call: transient send failure after 7 rate-limit refusals.
	c.Attempts = 8
	c.RateLimitRefusals = 7
	if err := d.process(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	if len(sender.calls) != 8 {
		t.Fatalf("expected eight sends, got %d", len(sender.calls))
	}
	if code := store.dead[c.ID]; code != "" {
		t.Fatalf("first transient send was dead-lettered: %s", code)
	}
	if lastCode != "RETRYABLE" {
		t.Fatalf("expected RETRYABLE for transient error, got %s", lastCode)
	}
	if lastMax != d.cfg.Retry.MaxAttempts {
		t.Fatalf("expected maxAttempts %d, got %d", d.cfg.Retry.MaxAttempts, lastMax)
	}
	if store.resched[c.ID] != 8 {
		t.Fatalf("expected 8 reschedules, got %d", store.resched[c.ID])
	}
	if delay := scheduled.Sub(clock.now); delay < 4500*time.Millisecond || delay > 5500*time.Millisecond {
		t.Fatalf("first transient failure backoff = %v", delay)
	}

	// Continue transient failures until 8 transient attempts are reached.
	for n := 9; n <= 14; n++ {
		c.Attempts = n
		c.RateLimitRefusals = 7
		if err := d.process(context.Background(), c); err != nil {
			t.Fatal(err)
		}
		if store.dead[c.ID] != "" {
			t.Fatalf("transient failure %d dead-lettered prematurely", n-7)
		}
	}
	// 8th transient failure (total attempts = 15, refusals = 7, transient = 8):
	c.Attempts = 15
	c.RateLimitRefusals = 7
	if err := d.process(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	if store.dead[c.ID] != "RETRY_EXHAUSTED" {
		t.Fatalf("expected RETRY_EXHAUSTED after 8 transient attempts, got dead=%q resched=%d",
			store.dead[c.ID], store.resched[c.ID])
	}
}

func TestAuditInternalLimiterMaxAgeExhaustion(t *testing.T) {
	store := newFakeStore()
	clock := &fakeClock{now: time.Now()}
	sender := &fakeSender{}
	d := testDispatcher(store, sender, clock)
	d.limit = NewLimiter(1, 1, clock)
	c := mkClaim("DOWN", 1)
	c.CreatedAt = clock.now.Add(-25 * time.Hour) // exceeds MaxAge (24h)

	// Consume limiter token so next Allow returns false.
	if !d.limit.Allow(c.ChannelID) {
		t.Fatal("could not consume initial limiter token")
	}

	if err := d.process(context.Background(), c); err != nil {
		t.Fatal(err)
	}

	if store.dead[c.ID] != "RETRY_EXHAUSTED" {
		t.Fatalf("expected RETRY_EXHAUSTED for expired claim under limiter refusal, got dead=%q resched=%d",
			store.dead[c.ID], store.resched[c.ID])
	}
	if store.resched[c.ID] != 0 {
		t.Fatalf("expired claim was rescheduled %d times", store.resched[c.ID])
	}
	if len(sender.calls) != 0 {
		t.Fatalf("expected 0 sends, got %d", len(sender.calls))
	}
}

func TestAuditExternalProviderRateLimitMaxAgeExhaustion(t *testing.T) {
	store := newFakeStore()
	clock := &fakeClock{now: time.Now()}
	sender := &fakeSender{script: func(int) (Delivery, error) {
		return Delivery{RetryAfter: 10 * time.Second}, ratelimitf("telegram: rate limited (retry_after=10s)")
	}}
	d := testDispatcher(store, sender, clock)
	c := mkClaim("DOWN", 1)
	c.CreatedAt = clock.now.Add(-25 * time.Hour) // exceeds MaxAge (24h)

	if err := d.process(context.Background(), c); err != nil {
		t.Fatal(err)
	}

	if store.dead[c.ID] != "RETRY_EXHAUSTED" {
		t.Fatalf("expected RETRY_EXHAUSTED for expired claim under provider rate limit, got dead=%q resched=%d",
			store.dead[c.ID], store.resched[c.ID])
	}
	if store.resched[c.ID] != 0 {
		t.Fatalf("expired claim was rescheduled %d times", store.resched[c.ID])
	}
	if len(sender.calls) != 1 {
		t.Fatalf("expected 1 send, got %d", len(sender.calls))
	}
}

func TestAuditComputeRetryJitterBounds(t *testing.T) {
	p := DefaultRetryPolicy // MinDelay=5s, MaxDelay=15m

	// 1. Exact deterministic exponential when r == nil:
	expectedDelays := []time.Duration{
		5 * time.Second,   // attempt 1
		10 * time.Second,  // attempt 2
		20 * time.Second,  // attempt 3
		40 * time.Second,  // attempt 4
		80 * time.Second,  // attempt 5
		160 * time.Second, // attempt 6
		320 * time.Second, // attempt 7
		640 * time.Second, // attempt 8
		15 * time.Minute,  // attempt 9 (clamped to 900s)
		15 * time.Minute,  // attempt 10
	}
	for i, want := range expectedDelays {
		got := ComputeRetry(i+1, 0, p, nil)
		if got != want {
			t.Fatalf("attempt %d: got %v, want %v", i+1, got, want)
		}
	}

	// Provider retryAfter honored within ceiling:
	if got := ComputeRetry(1, 10*time.Minute, p, nil); got != 10*time.Minute {
		t.Fatalf("retryAfter 10m: got %v, want 10m", got)
	}
	if got := ComputeRetry(1, 30*time.Minute, p, nil); got != 15*time.Minute {
		t.Fatalf("retryAfter 30m: got %v, want 15m (clamped)", got)
	}

	// 2. Caller-seeded RNG produces jitter strictly within [0.9*base, 1.1*base]:
	r := rand.New(rand.NewPCG(42, 99))
	for a := 1; a <= 10; a++ {
		base := ComputeRetry(a, 0, p, nil)
		minBound := time.Duration(float64(base) * 0.899)
		maxBound := time.Duration(float64(base) * 1.101)
		for trial := 0; trial < 100; trial++ {
			d := ComputeRetry(a, 0, p, r)
			if d < time.Second {
				t.Fatalf("attempt %d trial %d: delay %v below 1s floor", a, trial, d)
			}
			if d < minBound || d > maxBound {
				t.Fatalf("attempt %d trial %d: delay %v outside [%v, %v] (base=%v)",
					a, trial, d, minBound, maxBound, base)
			}
		}
	}
}
