// Package checker performs bounded, policy-checked outbound HTTP
// observations of monitor targets. It owns the whole boundary between
// "we tried to reach the target" and "here is typed evidence": DNS
// validation, pinned dialing, TLS verification, body/deadline bounds
// and outcome classification. It knows nothing about schedulers,
// databases, or notifications — an Observation is its only product.
package checker

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

// Outcome is the ONLY classification of a check attempt. Eligible
// outcomes are target-health evidence; excluded outcomes are
// collector-side events that must never move a failure streak or a
// monitor's health.
type Outcome int

const (
	// Target-side evidence — these say something true about the
	// destination and are eligible streak/health inputs.
	OutcomeSuccess          Outcome = iota // expected status observed
	OutcomeUnexpectedStatus                // HTTP answered, wrong status
	OutcomeDNSError                        // resolution failed (NXDOMAIN, SERVFAIL)
	OutcomeConnectError                    // TCP/TLS transport refused or dropped
	OutcomeTLSError                        // certificate/handshake verification failed
	OutcomeTimeout                         // our deadline expired before evidence

	// Collector-side exclusions — never DOWN evidence.
	OutcomePolicyBlocked // destination rejected by OUR policy, not the target
	OutcomeCanceled      // caller abandoned the attempt
	OutcomeInternalError // our bug/infra (pool, allocation, protocol violation)
)

// IsEligible reports whether the outcome is target-health evidence.
// Policy blocks, cancellations, and internal faults are collector
// events — a monitor must not go DOWN because WE refused or crashed.
func (o Outcome) IsEligible() bool { return o <= OutcomeTimeout }

// Target is the immutable check specification handed to the engine.
// Everything here is operator-approved monitor config — no runtime
// overrides, no network exceptions.
type Target struct {
	MonitorID      uuid.UUID
	URL            string // validated at create (C19 syntax gate)
	ExpectedStatus *int   // nil => 2xx counts as healthy
	TimeoutSeconds int    // total attempt budget, 1..10
}

// Observation is the immutable result of one Check. Contract:
//   - Success:            Status non-nil, ErrorClass nil, Latency non-nil.
//   - UnexpectedStatus:   Status non-nil, ErrorClass nil (a status IS
//     the evidence), Latency non-nil.
//   - Eligible failures:  Status nil, ErrorClass non-nil, Latency
//     non-nil (time-to-failure is evidence too).
//   - Exclusions:         Status nil, ErrorClass non-nil, Latency may
//     be nil (canceled work measures nothing).
//
// No raw error strings and no response body ever cross this type —
// an Observation is safe to persist and safe to show an owner.
type Observation struct {
	MonitorID  uuid.UUID
	Outcome    Outcome
	Status     *int
	ErrorClass *Outcome // non-nil for everything except the two status outcomes
	LatencyMs  *int64
	CheckedAt  time.Time // UTC wall clock — when the attempt finished
}

// NewObservation is the only constructor — it enforces the field
// invariants so a contradictory observation can't be built.
func NewObservation(t Target, outcome Outcome, status *int,
	latencyMs *int64, checkedAt time.Time) (Observation, error) {
	o := Observation{
		MonitorID: t.MonitorID, Outcome: outcome,
		Status: status, LatencyMs: latencyMs,
		CheckedAt: checkedAt.UTC(),
	}
	switch outcome {
	case OutcomeSuccess:
		if status == nil || *status < 100 || *status > 599 {
			return Observation{}, errors.New("success requires an HTTP status")
		}
	case OutcomeUnexpectedStatus:
		if status == nil {
			return Observation{}, errors.New("unexpected-status requires an HTTP status")
		}
	case OutcomePolicyBlocked, OutcomeCanceled, OutcomeInternalError:
		if status != nil {
			return Observation{}, errors.New("excluded outcome must not carry a status")
		}
	default: // eligible failures
		if status != nil {
			return Observation{}, errors.New("failure outcome must not carry a status")
		}
	}
	if outcome != OutcomeSuccess && outcome != OutcomeUnexpectedStatus {
		cls := outcome
		o.ErrorClass = &cls
	}
	return o, nil
}
