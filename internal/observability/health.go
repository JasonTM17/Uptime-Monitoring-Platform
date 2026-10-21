package observability

import (
	"context"
	"errors"
	"fmt"
)

// Probe is one named readiness dependency. Names are the bounded
// component catalog — "database", "engine", "janitor", "dispatcher" —
// never URLs, DSNs, or runtime strings.
type Probe struct {
	Name  string
	Check func(ctx context.Context) error
}

// Health composes liveness and readiness. Liveness is intentionally
// probe-free: a dead dependency must not report the process dead —
// orchestrators restart on live-fail and would flap a DB-loss into a
// crash loop.
type Health struct {
	ready []Probe
}

// NewHealth builds the composer from the ordered readiness probes.
// An empty probe set means "trivially ready" — the process has no
// dependencies to satisfy.
func NewHealth(ready ...Probe) *Health {
	return &Health{ready: ready}
}

// Live never touches a dependency. It exists so tests can assert the
// invariant directly and the composition root can pass it as the
// liveness probe.
func (h *Health) Live(context.Context) error { return nil }

// Ready runs every readiness probe in order and fails on the first
// error, wrapped with the probe's component name. The HTTP surface
// reports only status — the name stays in logs, out of the body.
func (h *Health) Ready(ctx context.Context) error {
	var errs []error
	for _, p := range h.ready {
		if p.Check == nil {
			continue
		}
		if err := p.Check(ctx); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", p.Name, err))
		}
	}
	return errors.Join(errs...)
}
