# Engine lifecycle

How a monitor observation travels from schedule to durable state, and
what survives each failure boundary. PostgreSQL is the only authority;
in-memory queues coordinate lifecycle but decide nothing durable.

## Ownership

- Exactly one engine instance owns the schedule at a time, enforced by
  a PostgreSQL session advisory lock on a dedicated connection.
- Each acquisition bumps `uptime.engine_control.epoch`. Every run row
  is stamped with the epoch that reserved it; results delivered under
  a superseded epoch are fenced as STALE.
- Losing the owner connection (crash, `pg_terminate_backend`) drops
  the lock and poisons the writer. A contender takes over on a fresh
  connection with a strictly larger epoch — an old owner can never
  write again.

## Pipeline

```
SelectDue (bounded, next_check_at <= now, no active run, not paused/deleted)
  -> ReserveRun (tx: lock user -> quota -> monitor; one active run;
                 sequence++, next_check_at advances IN THE SAME COMMIT)
  -> enqueue Job (bounded queue; capacity checked BEFORE reserving)
  -> worker attempt (fresh context.WithTimeout created AT the attempt;
                     queue wait never consumes the target budget)
  -> FinalizeObservation (tx on the owner conn: revalidate identity
                 -> insert result -> pure reducer -> monitor state ->
                 incident -> outbox intents -> run terminal, one commit)
```

## Failure boundaries (proven by deterministic schedules)

| Fault | Outcome |
| --- | --- |
| Crash after reservation commit, before attempt | Run reconciled to `INTERRUPTED` at takeover; schedule NOT rewound; no fabricated result/incident/outbox; next reservation continues the sequence — no catch-up replay. |
| Result arrives after engine takeover | Epoch fence: run `STALE`, zero durable effect. |
| Result arrives after pause/edit/delete/owner-disable | Generation/tombstone/owner fence: run `STALE`, monitor state and schedule untouched. |
| Lifecycle/configuration mutation while an incident is open | Close it in the same transaction as CONFIG_CHANGED or DELETED, never as observed recovery. Editing a DOWN monitor or resuming it after pause resets stale DOWN/streaks to UNKNOWN so new failures can establish another incident. Non-DOWN streaks are preserved; pause alone does not fabricate a health observation. See [mutation regressions](../internal/monitor/mutations_integration_test.go). |
| Queue full | Due monitors stay in the database; nothing is reserved, nothing is lost. Retained work is admitted when capacity returns, exactly once. |
| Job waits in queue longer than its timeout | Attempt still gets its full configured budget — queue delay cannot produce a failure outcome, an incident, or an outbox intent. A genuinely slow target still produces an eligible `TIMEOUT`. |
| Cancel before attempt | Zero network I/O, no observation; the reservation stays `RESERVED` and recoverable. |
| Finalize fails or commit is ambiguous (conn dies mid-finalize) | Nothing partial persists. The coordinator makes one best-effort `STALE` mark — a no-op if the commit actually landed, otherwise it frees the monitor's one-active slot so a finalize defect can never wedge the monitor. The failure is recorded on `Engine.LastErr()`. |
| Result replay | Unique `check_id` plus terminal disposition fence: duplicate changes nothing. |

Known residual: if a finalize error AND its best-effort `STALE`
mark both fail while the writer stays alive (e.g., a persistent
external row-lock outliving `lock_timeout`), the run stays `RESERVED`
for the rest of the epoch; the next owner's `ReconcileInterrupted`
still reaps it. Liveness was chosen over a retry loop on the
best-effort path. Similarly, an owner that fails to acquire within
the bounded try-lock window leaves the process serving traffic with
no engine — start-time overlap is an operations concern, not a state
risk.

## Invariants

- One active (`RESERVED`/`RUNNING`) run per monitor — partial unique
  index, enforced by the database.
- Schedule advances exactly once, inside the reservation commit.
  Finalize never touches `next_check_at`.
- Eligible evidence only (success/status/DNS/connect/TLS/timeout)
  moves health and streaks. Collector-side exclusions reset streaks
  but never move health or open incidents.
- No network I/O inside a database transaction; no Telegram/network
  delivery inside finalize; the dispatcher consumes committed outbox intents.
- Lock order everywhere: owner user row -> quota/monitor -> run. A
  mutation and a finalize serialize on those rows; whichever commits
  first wins, the loser is fenced.

## Ordered shutdown

`Engine.Shutdown(ctx)` runs a fixed, deadline-bounded sequence
(`internal/engine/shutdown.go`), wired in `cmd/api` after the HTTP
drain:

1. **Readiness false + stop admission** — always first; `/health/ready`
   reports unavailable before any drain begins.
2. **Scheduler loop exits, then jobs closes** — the tick goroutine is
   the sole job producer; `CloseJobs` only happens after it has fully
   exited, so nothing can enqueue into a closed channel.
3. **Bounded worker drain, then cancel** — in-flight attempts finish
   within the deadline; a forced deadline cancels the worker context.
   A worker that ignores cancellation is abandoned after a last-resort
   grace — its send drops on the dead context (the results channel is
   never closed, so no send-on-closed is possible).
4. **Result drain within budget** — the coordinator waits the worker
   WaitGroup before result consumption ends; buffered leftovers
   finalize inside the remaining budget, or their reservations simply
   stay `RESERVED` for the next owner's reconciliation. Uncommitted
   work never becomes target DOWN.
5. **Heartbeat stops, lock releases, conn closes** — last, after every
   write settles: `Owner.Release` holds the same mutex as `Writer.Exec`,
   so the advisory lock can never drop while a write is in flight.
   Release uses a fresh bounded context — cleanup must run even when
   the caller's deadline is spent.

Shutdown is idempotent (`sync.Once`): concurrent and repeated signals
observe one outcome.

## Evidence

Deterministic schedules live in `recovery_integration_test.go`,
`mutation_schedule_test.go`, and `shutdown_integration_test.go`
(crash, dual-owner, queue-full, queue delay, cancel-before-attempt,
every mutation barrier, and ordered/forced/idempotent shutdown),
gated by `go test -tags=integration ./internal/engine -count=1`
against the disposable `postgres-test` database.
