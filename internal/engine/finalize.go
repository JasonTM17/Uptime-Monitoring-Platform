package engine

import (
	"context"
	"errors"
	"fmt"

	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/checker"
	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/incident"
	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/notification"
	"github.com/jackc/pgx/v5"
)

// FinalizeOutcome reports what the atomic finalize decided.
type FinalizeOutcome int

const (
	FinalizeCommitted FinalizeOutcome = iota // result persisted, state applied
	FinalizeStale                            // run marked STALE, no health effect
	FinalizeDuplicate                        // replay — nothing changed
)

var ErrCommitAmbiguous = errors.New("engine: commit outcome unknown; revalidate before retry")

// FinalizeInput is a worker result plus the reservation identity it
// must prove — validated under the same locks the reservation took.
type FinalizeInput struct {
	Identity    FinalizeIdentity
	Observation checker.Observation
}

// FinalizeObservation commits one worker result atomically on the
// OWNER connection. One transaction contains, in order:
//  1. identity revalidation under owner -> monitor -> run locks,
//  2. the check_results row (unique per run — replay cannot double),
//  3. pure reducer applied to the row-locked monitor state,
//  4. incident open/close + ordered outbox intents,
//  5. terminal run disposition.
//
// The schedule is NOT touched — C34 already advanced it. A rollback
// revokes every piece; a stale/duplicate result changes nothing but
// the run disposition. No network I/O happens inside the transaction.
func (w *Writer) FinalizeObservation(ctx context.Context, in FinalizeInput) (FinalizeOutcome, error) {
	var outcome FinalizeOutcome
	err := w.Exec(ctx, func(ctx context.Context, conn *pgx.Conn) error {
		tx, err := conn.BeginTx(ctx, pgx.TxOptions{})
		if err != nil {
			return err
		}
		defer tx.Rollback(ctx)

		verdict, err := ValidateResultIdentity(ctx, tx, w.owner.epoch, in.Identity)
		if err != nil {
			return err
		}
		switch verdict {
		case IdentityDuplicate:
			outcome = FinalizeDuplicate
			return tx.Commit(ctx)
		case IdentityStale:
			if _, err := MarkStaleRun(ctx, tx, in.Identity.RunID,
				"STALE", "identity_fenced"); err != nil {
				return err
			}
			outcome = FinalizeStale
			return tx.Commit(ctx)
		}

		// 2) Result row — identity-mapped fields only; the nine-outcome
		// enum and eligible/success parity are DB-enforced.
		obs := in.Observation
		var httpStatus *int
		var duration int64
		var success *bool
		if obs.Status != nil {
			httpStatus = obs.Status
		}
		if obs.LatencyMs != nil {
			duration = *obs.LatencyMs
		}
		if obs.Outcome.IsEligible() {
			s := obs.Outcome == checker.OutcomeSuccess
			success = &s
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO uptime.check_results
			  (check_id,monitor_id,outcome,eligible,success,http_status,
			   duration_ms,observed_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
			in.Identity.RunID, in.Identity.MonitorID, outcomeName(obs.Outcome),
			obs.Outcome.IsEligible(), success, httpStatus, duration,
			obs.CheckedAt); err != nil {
			return fmt.Errorf("insert result: %w", err)
		}

		// 3) Reducer on the locked monitor row — streaks and health move
		// only via eligible evidence; exclusions reset streaks, not health.
		var health, monName string
		var fs, ss int
		if err := tx.QueryRow(ctx, `
			SELECT health, failure_streak, success_streak, name
			FROM uptime.monitors WHERE id=$1`, in.Identity.MonitorID).
			Scan(&health, &fs, &ss, &monName); err != nil {
			return err
		}
		state := incident.State{
			Health:        parseHealth(health),
			FailureStreak: fs, SuccessStreak: ss,
		}
		next, tr := incident.Reduce(state, obs)
		var errType *string
		if obs.Outcome.IsEligible() && obs.Outcome != checker.OutcomeSuccess {
			n := outcomeName(obs.Outcome)
			errType = &n
		}
		if _, err := tx.Exec(ctx, `
			UPDATE uptime.monitors
			SET health=$2, failure_streak=$3, success_streak=$4,
			    last_checked_at=$5, last_response_time_ms=$6,
			    last_error_type=$7
			WHERE id=$1`,
			in.Identity.MonitorID, next.Health.String(), next.FailureStreak,
			next.SuccessStreak, obs.CheckedAt, durationOrNil(obs.LatencyMs),
			errType); err != nil {
			return err
		}

		// 4) Incident + outbox intents for real transitions only.
		repo := incident.Repository{}
		switch tr.Effect {
		case incident.EffectIncidentOpened:
			inc, err := repo.OpenIncident(ctx, tx, in.Identity.MonitorID, in.Identity.RunID)
			if err != nil {
				return err
			}
			if _, err := notification.AppendTransitionDeliveries(ctx, tx,
				notification.TransitionInput{
					UserID: in.Identity.OwnerID, MonitorID: in.Identity.MonitorID,
					MonitorName: monName,
					IncidentID:  inc.ID, Kind: notification.EventDown,
					ObservedAt: obs.CheckedAt,
				}); err != nil {
				return err
			}
		case incident.EffectRecovered:
			// The reducer believes an incident is open; a config or
			// delete closure may have already resolved it. Missing
			// active incident is NOT a finalize failure  -  skip the
			// close and the recovery intent rather than wedge the run.
			active, err := repo.GetActiveIncident(ctx, tx, in.Identity.MonitorID)
			if errors.Is(err, pgx.ErrNoRows) {
				break
			}
			if err != nil {
				return err
			}
			if _, err := repo.CloseIncident(ctx, tx, in.Identity.MonitorID,
				&in.Identity.RunID, incident.ReasonRecovered); err != nil {
				return err
			}
			if _, err := notification.AppendTransitionDeliveries(ctx, tx,
				notification.TransitionInput{
					UserID: in.Identity.OwnerID, MonitorID: in.Identity.MonitorID,
					MonitorName: monName,
					IncidentID:  active.ID, Kind: notification.EventRecovery,
					ObservedAt: obs.CheckedAt,
				}); err != nil {
				return err
			}
		}

		// 5) Terminal disposition: eligible evidence completes the run;
		// collector/policy exclusions mark it EXCLUDED with the reason.
		runStatus, reason := "COMPLETED", ""
		if !obs.Outcome.IsEligible() {
			runStatus, reason = "EXCLUDED", outcomeName(obs.Outcome)
		}
		if _, err := tx.Exec(ctx, `
			UPDATE uptime.check_runs
			SET status=$2, finished_at=clock_timestamp(), terminal_reason=$3
			WHERE id=$1`, in.Identity.RunID, runStatus, nullIfEmpty(reason)); err != nil {
			return err
		}

		outcome = FinalizeCommitted
		return tx.Commit(ctx)
	})
	return outcome, err
}

func outcomeName(o checker.Outcome) string {
	switch o {
	case checker.OutcomeSuccess:
		return "SUCCESS"
	case checker.OutcomeUnexpectedStatus:
		return "UNEXPECTED_STATUS"
	case checker.OutcomeDNSError:
		return "DNS_ERROR"
	case checker.OutcomeConnectError:
		return "CONNECT_ERROR"
	case checker.OutcomeTLSError:
		return "TLS_ERROR"
	case checker.OutcomeTimeout:
		return "TIMEOUT"
	case checker.OutcomePolicyBlocked:
		return "POLICY_BLOCKED"
	case checker.OutcomeCanceled:
		return "CANCELLED"
	}
	return "INTERNAL_ERROR"
}

func parseHealth(s string) incident.Health {
	switch s {
	case "UP":
		return incident.HealthUp
	case "DOWN":
		return incident.HealthDown
	}
	return incident.HealthUnknown
}

func durationOrNil(ms *int64) *int64 { return ms }
func nullIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
