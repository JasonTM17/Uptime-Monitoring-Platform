# Local operations: health and metrics

Runtime signals added in Phase 09 (C77). Everything here is bounded:
metric labels come from fixed tables, gauges are atomic reads or
TTL-cached, and a scrape can never fan out into unbounded DB work.

## Endpoints

| Endpoint | Auth | Touches DB | Meaning |
| --- | --- | --- | --- |
| `GET /health/live` | none | never | process is alive |
| `GET /health/ready` | none | yes (bounded pings) | every dependency + engine ownership is good |
| `GET /metrics` | bearer when `METRICS_TOKEN` set | at most one grouped outbox query per `METRICS_GAUGE_REFRESH` | bounded metric exposition |

- Liveness **never** queries the database. A dead DB returns
  `ready=503` while `live=200` — orchestrators restart on live-fail,
  so conflating them would flap a dependency outage into a crash loop.
- Readiness is the composition of named probes: `database`, `engine`
  (owner lock + writer liveness), `janitor` (rollup/retention loop
  conn), `dispatcher` (delivery loop conn when enabled). Any failure
  returns `503 {"status":"unavailable"}`; the failed probe name stays
  in server logs, not the response body.
- `200` on `/health/ready` is readiness *at that instant*, not proof
  the engine is checking targets — use the metrics below plus the
  admin operations surface for engine-freshness evidence.

## Metrics catalog (finite)

Counters (monotonic):

| Series | Labels | Records |
| --- | --- | --- |
| `uptime_engine_admissions_total` | — | runs reserved+enqueued per tick |
| `uptime_engine_admission_denials_total` | `reason`: `queue_full`, `owner_window`, `global_window`, `other` | bounded admission refusals |
| `uptime_engine_observations_total` | `outcome`: the 9 checker outcomes + `other` | finished check attempts, eligible and excluded alike |
| `uptime_engine_finalize_total` | `result`: `committed`, `stale`, `duplicate`, `error` | coordinator finalize outcomes |
| `uptime_engine_owner_loss_total` | — | owner-conn alive→dead transitions (≤1 per ownership) |

Gauges (scrape-time):

| Series | Labels | Source |
| --- | --- | --- |
| `uptime_engine_queue_depth` | — | buffered jobs channel length |
| `uptime_engine_workers` | — | configured worker count |
| `uptime_engine_workers_busy` | — | in-flight check attempts |
| `uptime_engine_owner_alive` | — | writer liveness flag (0/1) |
| `uptime_outbox_deliveries` | `state`: `PENDING`, `LEASED`, `SENT`, `DEAD`, `SUPPRESSED` | TTL-cached `GROUP BY state` |
| `uptime_outbox_snapshot_age_seconds` | — | seconds since last good outbox read; `-1` = never refreshed |

Cardinality is closed: out-of-domain enum values land in `other`,
never a new label. No monitor ID, owner ID, URL, email, or secret
appears in any series — that is test-enforced, not aspirational.

## Interpretation notes

- **Owner loss**: `owner_alive` drops to 0 and
  `owner_loss_total` increments exactly once. Readiness then fails on
  the `engine` probe. There is no reconnect — only a restart acquires
  a fresh epoch.
- **Denials are expected behavior**, not errors: `owner_window` means
  one owner's rolling-60s budget is saturated (fairness working);
  `global_window` means platform-wide saturation; `queue_full` means
  the bounded job channel is at capacity — due monitors stay in the
  DB for the next tick, nothing is lost.
- **Outbox freshness is explicit**: `uptime_outbox_snapshot_age_seconds`
  is `-1` when no DB read has succeeded yet, and grows past
  `METRICS_GAUGE_REFRESH` while refresh fails — a stale or missing
  count never masquerades as a healthy zero. `DEAD` counts are the
  dead-letter signal the operations screen triages.
- **`finalize{result="error"}`** counts ambiguous commits: the run
  stays recoverable (STALE/reconciliation), the counter marks the
  fault for follow-up — it is not silently swallowed.
- Metrics show the engine *did* something; they do not prove a
  specific target is UP. Per-monitor truth lives in check results
  and the monitor dashboard, not in aggregate counters.

## Configuration

| Env | Default | Notes |
| --- | --- | --- |
| `METRICS_ENABLED` | local: `true`, hosted: `false` | mounts `GET /metrics` |
| `METRICS_TOKEN` | unset | when set, `Authorization: Bearer <token>` required; **required** for hosted+enabled or config load fails |
| `METRICS_GAUGE_REFRESH` | `15s` | min 1s, max 5m — bounds outbox query cost |
| `METRICS_GAUGE_TIMEOUT` | `2s` | per-probe bound, must be <= refresh |

Local scrape example:

```sh
curl -s http://127.0.0.1:8080/metrics
curl -s http://127.0.0.1:8080/health/ready
curl -s -H "Authorization: Bearer $METRICS_TOKEN" http://127.0.0.1:8080/metrics
```
