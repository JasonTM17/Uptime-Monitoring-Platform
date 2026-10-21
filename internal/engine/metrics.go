package engine

import "github.com/JasonTM17/Uptime-Monitoring-Platform/internal/checker"

// DenialCause classifies a bounded admission refusal. The set is
// finite by design — metrics labels must never carry monitor, owner,
// or target identity.
type DenialCause int

const (
	DenialQueueFull    DenialCause = iota // bounded job queue saturated
	DenialOwnerWindow                     // one owner's rolling-60s window full
	DenialGlobalWindow                    // global rolling-60s window full
)

// Counters is the engine's metrics seam, implemented by
// observability.Metrics at the composition root. A nil Counters
// means uninstrumented — every call site must tolerate nil so tests
// and alternate compositions need no stub.
type Counters interface {
	// RecordAdmissions counts runs committed+enqueued by the
	// scheduler in one tick.
	RecordAdmissions(n int64)
	// RecordDenial counts a bounded admission refusal by cause.
	RecordDenial(d DenialCause)
	// RecordObservation counts one finished check attempt by its
	// checker outcome — eligible and excluded outcomes alike.
	RecordObservation(o checker.Outcome)
	// RecordFinalize counts a finalize pass; ok=false means the
	// durable outcome was ambiguous (ErrCommitAmbiguous included) —
	// the run stays recoverable, the counter marks the fault.
	RecordFinalize(f FinalizeOutcome, ok bool)
	// RecordOwnerLoss counts the alive->dead transition of the
	// owner connection. Fires once per ownership lifetime.
	RecordOwnerLoss()
}
