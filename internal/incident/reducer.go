// Package incident owns the pure health state machine: eligible
// check evidence moves a monitor between UNKNOWN/UP/DOWN across fixed
// thresholds; excluded observations never count as target evidence.
// Persistence happens elsewhere (C39/C41) - nothing here touches a
// clock, a database, or the network.
package incident

import "github.com/JasonTM17/Uptime-Monitoring-Platform/internal/checker"

// Health is the monitor's computed liveness, independent of pause or
// data freshness.
type Health int

const (
	HealthUnknown Health = iota
	HealthUp
	HealthDown
)

func (h Health) String() string {
	switch h {
	case HealthUp:
		return "UP"
	case HealthDown:
		return "DOWN"
	}
	return "UNKNOWN"
}

// Fixed validated policy: three consecutive eligible failures open an
// incident; two consecutive eligible successes recover one.
const (
	FailThreshold    = 3
	RecoverThreshold = 2
)

// State is the reducer's complete input: health plus the two streak
// counters. Streaks measure CONSECUTIVE eligible evidence only.
type State struct {
	Health        Health
	FailureStreak int
	SuccessStreak int
}

// Effect is the intent emitted for the writer to persist - never an
// action the reducer takes itself.
type Effect int

const (
	EffectNone Effect = iota
	// EffectIncidentOpened - health crossed into DOWN.
	EffectIncidentOpened
	// EffectRecovered - health returned UP from DOWN.
	EffectRecovered
)

func (e Effect) String() string {
	switch e {
	case EffectIncidentOpened:
		return "incident_opened"
	case EffectRecovered:
		return "recovered"
	}
	return "none"
}

// Transition reports what one observation changed.
type Transition struct {
	Prev, Next Health
	Effect     Effect
}

// Reduce applies one observation to a state. Rules:
//   - Excluded outcomes (policy/cancel/internal) reset BOTH streaks
//     and leave health+incident untouched - they are not evidence of
//     target failure AND not evidence of recovery.
//   - An eligible success clears the failure streak; a first success
//     from UNKNOWN establishes UP with no incident effect; two
//     consecutive successes while DOWN recover to UP.
//   - An eligible failure (incl. unexpected status) clears the
//     success streak; the third consecutive failure from UP or
//     UNKNOWN drops to DOWN and emits the incident intent.
//   - Already-DOWN monitors emit no repeated transition.
func Reduce(s State, o checker.Observation) (State, Transition) {
	tr := Transition{Prev: s.Health, Next: s.Health}
	if !o.Outcome.IsEligible() {
		s.FailureStreak = 0
		s.SuccessStreak = 0
		return s, tr
	}
	if o.Outcome == checker.OutcomeSuccess {
		s.FailureStreak = 0
		s.SuccessStreak++
		switch {
		case s.Health == HealthDown && s.SuccessStreak >= RecoverThreshold:
			s.Health = HealthUp
			s.SuccessStreak = 0
			tr.Next, tr.Effect = HealthUp, EffectRecovered
		case s.Health == HealthUnknown:
			s.Health = HealthUp
			tr.Next = HealthUp // initial establishment, not a recovery
		}
		// Saturate at the threshold: a streak only ever proves
		// "N consecutive"  -  more evidence changes nothing, and the
		// schema CHECK bounds the column at the threshold.
		if s.SuccessStreak > RecoverThreshold {
			s.SuccessStreak = RecoverThreshold
		}
		return s, tr
	}
	// Eligible failure.
	s.SuccessStreak = 0
	s.FailureStreak++
	if s.FailureStreak >= FailThreshold && s.Health != HealthDown {
		s.Health = HealthDown
		s.FailureStreak = 0
		tr.Next, tr.Effect = HealthDown, EffectIncidentOpened
	}
	if s.FailureStreak > FailThreshold {
		s.FailureStreak = FailThreshold
	}
	return s, tr
}
