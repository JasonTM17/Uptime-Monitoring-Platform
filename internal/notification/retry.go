package notification

import (
	"errors"
	"math/rand/v2"
	"time"
)

// Retry policy (C46): bounded attempts, bounded delay, bounded age —
// an outage must amplify nothing. The schedule is exponential with a
// deterministic jitter so thundering herds of expired leases never
// re-fire in lockstep, and the provider's own retry_after is honored
// but clamped to the same ceiling.

var ErrRetryConfig = errors.New("invalid retry policy")

// RetryPolicy bounds every retry decision.
type RetryPolicy struct {
	MinDelay    time.Duration // floor of the backoff curve (spec: 5s)
	MaxDelay    time.Duration // ceiling — retry_after can never exceed it (spec: 15m)
	MaxAttempts int           // total attempts before DEAD (spec: 8)
	MaxAge      time.Duration // overall event age budget (spec: 24h)
}

// DefaultRetryPolicy is the spec's bounded schedule.
var DefaultRetryPolicy = RetryPolicy{
	MinDelay:    5 * time.Second,
	MaxDelay:    15 * time.Minute,
	MaxAttempts: 8,
	MaxAge:      24 * time.Hour,
}

func (p RetryPolicy) valid() error {
	if p.MinDelay <= 0 || p.MaxDelay < p.MinDelay ||
		p.MaxAttempts <= 0 || p.MaxAge <= 0 {
		return ErrRetryConfig
	}
	return nil
}

// ComputeRetry returns the next_attempt delay for attempt n (1-based:
// the attempt that just failed). Exponential min*2^(n-1) capped at
// max; the provider's retryAfter floor is honored but never above
// max; ±10% jitter spreads reclaim storms deterministically under a
// caller-seeded rand (tests pin the seed, production seeds per run).
func ComputeRetry(attempt int, retryAfter time.Duration,
	p RetryPolicy, r *rand.Rand) time.Duration {
	d := p.MinDelay
	for i := 1; i < attempt && d < p.MaxDelay; i++ {
		if d > p.MaxDelay/2 {
			d = p.MaxDelay
			break
		}
		d *= 2
	}
	if retryAfter > d {
		d = retryAfter // honor the provider's floor
	}
	if d > p.MaxDelay {
		d = p.MaxDelay // but never above our ceiling
	}
	if r != nil {
		// ±10% deterministic jitter.
		j := float64(d) * 0.1
		d += time.Duration(r.Float64()*2*j - j)
	}
	if d < time.Second {
		d = time.Second
	}
	return d
}

// Exhausted reports whether the event has spent its attempts budget
// or outlived its age budget — either routes to DEAD.
func Exhausted(attempts int, createdAt, now time.Time, p RetryPolicy) bool {
	return attempts >= p.MaxAttempts || now.Sub(createdAt) > p.MaxAge
}
