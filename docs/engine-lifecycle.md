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
| Queue full | Due monitors stay in the database; nothing is reserved, nothing is lost. Retained work is admitted when capacity returns, exactly once. |
| Job waits in queue longer than its timeout | Attempt still gets its full configured budget — queue delay cannot produce a failure outcome, an incident, or an outbox intent. A genuinely slow target still produces an eligible `TIMEOUT`. |
| Cancel before attempt | Zero network I/O, no observation; the reservation stays `RESERVED` and recoverable. |
| Commit ambiguity (conn dies mid-finalize) | Nothing partial persists; the run stays `RESERVED` and a revalidation/retry commits exactly once. |
| Result replay | Unique `check_id` plus terminal disposition fence: duplicate changes nothing. |

## Invariants

- One active (`RESERVED`/`RUNNING`) run per monitor — partial unique
  index, enforced by the database.
- Schedule advances exactly once, inside the reservation commit.
  Finalize never touches `next_check_at`.
- Eligible evidence only (success/status/DNS/connect/TLS/timeout)
  moves health and streaks. Collector-side exclusions reset streaks
  but never move health or open incidents.
- No network I/O inside a database transaction; no Telegram/network
  delivery inside finalize (outbox intents only — Phase 06 dispatches).
- Lock order everywhere: owner user row -> quota/monitor -> run. A
  mutation and a finalize serialize on those rows; whichever commits
  first wins, the loser is fenced.

## Evidence

Deterministic schedules live in `recovery_integration_test.go` and
`mutation_schedule_test.go` (crash, dual-owner, queue-full, queue
delay, cancel-before-attempt, and every mutation barrier), gated by
`go test -tags=integration ./internal/engine -count=1` against the
disposable `postgres-test` database.
