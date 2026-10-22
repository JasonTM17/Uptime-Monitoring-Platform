# Capacity & recovery measurement (the capacity run)

Measures the engine's bounded behavior under the frozen local protocol.
Everything in a report's `measured` section comes from the composed
disposable stack (`compose.test.yaml`); `model` holds arithmetic
projections only and is never evidence for scale claims.

## Frozen protocol

| Knob | Value | Where it lives |
| --- | --- | --- |
| Monitors | 100, one owner | seeded via real `POST /monitors` (owner limit 100) |
| Interval | 60 s (schema floor) | monitor `interval_seconds` |
| Workers | 10 | `ENGINE_WORKERS` local default |
| Job queue | 20 | `ENGINE_QUEUE_SIZE` local default |
| Scheduler tick | 1 s | `CAP_TICK_MS=1000` → `TESTAPP_TICK_MS` (release parity with `cmd/api`) |
| Admission | 100 starts / 60 s, owner and global | `*_PER_60S` local defaults |
| Check timeout | 10 s | monitor `timeout_seconds` (schema max) |
| Distributions | fast (`<10 ms` 200s) then timeout-heavy (hangs → 10 s timeouts) | fixture `up`/`timeout` modes |

`ReserveRun` pins PostgreSQL isolation to `READ COMMITTED`: owner and global
quota locks serialize competing admissions, and the later count statements
must see reservations committed while they waited. Inheriting a
`REPEATABLE READ` server default can leave the counts on an older snapshot and
oversubscribe the rolling window. `TestConcurrentGlobalAdmissionCapUsesFreshPostLockSnapshot`
holds the budget lock until both reservations are queued to exercise this case.

The same pin covers every actor-locked admission transaction that performs
`quota_budgets FOR UPDATE` then counts sibling rows: `auth.WithUserLock`
(monitor create), `monitor.Repository.withActorLock`, and
`notification.Repository.withActorLock` (channel create). Each begins its
transaction at `READ COMMITTED` so post-lock counts cannot freeze on a
pre-lock snapshot under a changed server default.

Total budget defaults to 1800 s: ~35% fast, ~35% timeout-heavy, ~30%
fault injections. `--duration-seconds` rescales the two steady phases;
faults have fixed minimum windows.

## Run

```bash
node scripts/measure-capacity.mjs --profile local \
  --duration-seconds 1800 --output artifacts/capacity-local.json
```

Outputs: `capacity-local.json` (report) + `capacity-local-samples.csv`
(5 s scrapes). `--fast-seconds`/`--heavy-seconds` override phase
windows for smoke runs; `--keep true` leaves the stack up.

The script owns the whole lifecycle: `down -v`, build-reuse, migrate,
seed 100 monitors through the real API, run phases, inject faults,
collect, write the report, `down -v`. Nothing touches the dev stack.

## What is measured

- **Queue age** = `check_runs.reserved_at - slot_at` (admission
  lateness). The schema's `started_at` is never written — the engine
  goes RESERVED→COMPLETED — so start-time lateness cannot be split
  further without a production change; the report labels the basis.
  A second metric, **completion lateness** = `finished_at - slot_at`,
  covers admission wait + queue wait + execution, separate from…
- **Network duration** = `check_results.duration_ms` — same
  percentiles, per outcome.
- **Starts & backlog**: runs reserved per window, `queue_depth`
  samples, admission-denial counters (`queue_full`, `owner_window`,
  `global_window`), open-run ceiling.
- **Resources**: `docker stats` CPU%/RSS for `app` and `db`,
  `uptime_engine_goroutines` from `/metrics` every 5 s.
- **Storage**: per-table rows, `pg_total_relation_size`,
  `pg_indexes_size`, `pg_database_size` — pending/retained bytes and
  index bytes are reported, not just row counts.

## Fault injections (bounded)

| Fault | Mechanism | Asserted evidence |
| --- | --- | --- |
| Full queue | all 100 monitors `next_check_at=now()` under timeouts | queue max ≤ 20, open runs ≤ 30, denials counted |
| DB disconnect | `compose pause db` 12 s | engine behavior + `owner_loss` delta recorded honestly |
| Crash after reserve | `SIGKILL app` under timeout load | epoch increments, orphans → `INTERRUPTED/engine_takeover`, zero fabricated results, post-restart starts ≤ 200 (2× the 60 s admission cap ⇒ no catch-up storm) |
| Shutdown deadline | `docker stop -t 3` under load | exit code + drain recorded |
| Churn denial | `POST /monitors` #101 over owner limit | quota refusal status recorded |

## Invariants (verdict inputs)

`workers_busy ≤ 10` · `queue_depth ≤ 20` · zero duplicate slot rows ·
≤ 1 open run per monitor · ≤ 1 open incident per monitor ·
`finalize_total{result="stale"}` reported · post-crash starts bounded
by the admission window.

## Honest limits

- One host, one run. Docker Desktop CPU/RSS sampling is coarse.
- Timeout-heavy **must** show lateness — 100 × 10 s checks / 10
  workers ≈ 100 s of work per 60 s cycle. A report claiming zero
  missed coverage here is wrong by construction; the p99 queue age
  is the honest number.
- `model.projections` for 1 000 / 10 000 monitors are linear
  arithmetic on the measured p50 check duration. They are flagged
  `NOT measured` and are not evidence for those scales — admission
  caps would gate real admission far below 10k anyway.
- No overall disk-growth cap is claimed: `schedule_segments` retains
  lifecycle history; storage numbers are point-in-time.

## Invariant tests (deterministic lane)

```bash
go test -tags=integration ./internal/engine -count=1 -run \
  'TestCapacityBounds|TestSingleOwnerUsesAvailableWorkers|TestReservationCrashRecovery|TestOwnerLossStopsWrites'
```

These prove the same bounds deterministically against a disposable
PostgreSQL; the measurement script proves them on the composed stack
with real HTTP, real docker stats, and real clock time.
