package incident

import (
	"testing"
	"time"

	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/checker"
	"github.com/google/uuid"
)

func obs(t *testing.T, outcome checker.Outcome) checker.Observation {
	t.Helper()
	tgt := checker.Target{MonitorID: uuid.New(), URL: "https://x", TimeoutSeconds: 2}
	var st *int
	var lat *int64
	if outcome == checker.OutcomeSuccess || outcome == checker.OutcomeUnexpectedStatus {
		code := 200
		if outcome == checker.OutcomeUnexpectedStatus {
			code = 500
		}
		st = &code
	}
	if outcome.IsEligible() {
		ms := int64(5)
		lat = &ms
	}
	o, err := checker.NewObservation(tgt, outcome, st, lat, time.Now())
	if err != nil {
		t.Fatalf("obs %v: %v", outcome, err)
	}
	return o
}

// Full transition matrix: only exact threshold crossings produce a
// health change or incident effect.
func TestThresholdTransitions(t *testing.T) {
	success := checker.OutcomeSuccess
	fail := checker.OutcomeConnectError

	cases := []struct {
		name  string
		start State
		in    checker.Outcome
		want  State
		eff   Effect
	}{
		{"unknown+success->UP", State{}, success,
			State{Health: HealthUp, SuccessStreak: 1}, EffectNone},
		{"unknown+fail1 stays", State{}, fail,
			State{Health: HealthUnknown, FailureStreak: 1}, EffectNone},
		{"unknown+fail3->DOWN", State{HealthUnknown, 2, 0}, fail,
			State{Health: HealthDown}, EffectIncidentOpened},
		{"up+fail1 stays UP", State{HealthUp, 0, 4}, fail,
			State{Health: HealthUp, FailureStreak: 1}, EffectNone},
		{"up+fail3->DOWN", State{HealthUp, 2, 0}, fail,
			State{Health: HealthDown}, EffectIncidentOpened},
		{"down+success1 waits", State{HealthDown, 0, 0}, success,
			State{Health: HealthDown, SuccessStreak: 1}, EffectNone},
		{"down+success2->UP", State{HealthDown, 0, 1}, success,
			State{Health: HealthUp}, EffectRecovered},
		{"down+fail saturates at threshold", State{HealthDown, 5, 0}, fail,
			State{Health: HealthDown, FailureStreak: 3}, EffectNone},
		{"unexpected status is failure", State{HealthUp, 2, 0},
			checker.OutcomeUnexpectedStatus,
			State{Health: HealthDown}, EffectIncidentOpened},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, tr := Reduce(c.start, obs(t, c.in))
			if got != c.want || tr.Effect != c.eff {
				t.Fatalf("Reduce(%+v, %v) = %+v eff=%v, want %+v eff=%v",
					c.start, c.in, got, tr.Effect, c.want, c.eff)
			}
		})
	}
}

// A multi-step oscillation replay: fail streak needs an unbroken run,
// DOWN never re-transitions, recovery needs two straight successes.
func TestOscillationReplay(t *testing.T) {
	s := State{}
	fail, ok, skip := checker.OutcomeTimeout, checker.OutcomeSuccess,
		checker.OutcomePolicyBlocked

	step := func(o checker.Outcome) Effect {
		var tr Transition
		s, tr = Reduce(s, obs(t, o))
		return tr.Effect
	}
	step(fail) // 1
	step(fail) // 2
	step(ok)   // success resets failure streak
	step(fail) // 1 again
	step(fail) // 2
	if e := step(fail); e != EffectIncidentOpened {
		t.Fatalf("3rd consecutive fail effect: %v", e)
	}
	if s.Health != HealthDown {
		t.Fatal("not DOWN after 3 consecutive fails")
	}
	if e := step(fail); e != EffectNone {
		t.Fatal("repeated DOWN transition emitted")
	}
	step(skip) // exclusion: resets recovery progress below
	if e := step(ok); e != EffectNone {
		t.Fatal("single success after exclusion falsely recovered")
	}
	if e := step(ok); e != EffectRecovered {
		t.Fatalf("2nd straight success should recover: %v", e)
	}
	if s.Health != HealthUp {
		t.Fatal("not UP after recovery")
	}
}

// Exclusions zero both streaks and never touch health - a DOWN
// monitor stays DOWN, an UP monitor stays UP.
func TestExcludedResetsStreaks(t *testing.T) {
	for _, ex := range []checker.Outcome{
		checker.OutcomePolicyBlocked, checker.OutcomeCanceled,
		checker.OutcomeInternalError,
	} {
		s := State{Health: HealthDown, FailureStreak: 2, SuccessStreak: 1}
		got, tr := Reduce(s, obs(t, ex))
		if got.Health != HealthDown || got.FailureStreak != 0 || got.SuccessStreak != 0 {
			t.Fatalf("exclusion %v mutated state: %+v", ex, got)
		}
		if tr.Effect != EffectNone {
			t.Fatalf("exclusion %v emitted effect", ex)
		}
	}
}

// Same input stream -> identical states, and the input State is not
// mutated by Reduce.
func TestReducerDeterminism(t *testing.T) {
	seq := []checker.Outcome{
		checker.OutcomeSuccess, checker.OutcomeConnectError,
		checker.OutcomeConnectError, checker.OutcomeConnectError,
		checker.OutcomeSuccess, checker.OutcomeSuccess,
	}
	run := func() State {
		s := State{Health: HealthUp, FailureStreak: 1}
		for _, o := range seq {
			s, _ = Reduce(s, obs(t, o))
		}
		return s
	}
	a, b := run(), run()
	if a != b {
		t.Fatal("nondeterministic reduce")
	}
	in := State{Health: HealthDown, FailureStreak: 4, SuccessStreak: 2}
	Reduce(in, obs(t, checker.OutcomeSuccess))
	if in != (State{HealthDown, 4, 2}) {
		t.Fatal("Reduce mutated its input")
	}
}
