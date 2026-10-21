# Sampled statistics and denominators

How the API computes availability numbers without ever fabricating
an SLA. Everything here is **sampled** statistics — a ratio over
observations that actually ran — never a time-weighted uptime
guarantee.

## The partition identity

For a represented half-open interval `W_data = [data_start, data_end)`:

```
expected = valid + excluded + missed + pending     (always, non-negative)
coverage = valid / expected                       (null when expected = 0)
sample_uptime = successes / valid                 (null when valid = 0)
```

- **expected** — nominal slots owed by the schedule: `starts_at +
  k*interval_seconds` over every `schedule_segments` row intersecting
  `W_data`. Segments close on pause/suspend/delete/edit, so ineligible
  time never enters the denominator. The current interval is never
  stretched over history — each segment contributes its own grid.
- **valid** — accepted eligible observations (successes + failures).
- **excluded** — accepted non-evidence (POLICY_BLOCKED, CANCELLED,
  INTERNAL_ERROR). Exclusions are real rows; they are never
  fabricated to balance the count.
- **pending** — nominal slots with a RESERVED/RUNNING run and no
  accepted result yet.
- **missed** — the complement: unreserved slots, terminal
  INTERRUPTED/STALE runs with no result. A late result rejected by
  the generation fence is missed forever — the slot was owed and
  the evidence never arrived.

Because missed is a complement, `expected = valid + excluded +
missed + pending` holds by construction. The denominator survives
raw purge: **schedule_segments are never purged** — they are the
durable evidence the schedule existed.

## Raw + hourly merge (no double count)

Raw results roll into `hourly_stats` buckets keyed by the run's
nominal `slot_at` hour (UTC). A result is marked `rolled_up_at`
inside the same transaction that increments the bucket — replay is
impossible. Retention only purges rolled pairs (the rollup barrier).

At query time the merge is disjoint by construction:

- hourly contributes **complete buckets only** — buckets whose whole
  hour lies inside `W_data`;
- raw contributes rows whose slot is inside `W_data` **and** whose
  counts are not already inside a covered bucket (unrolled rows, or
  rolled rows in a partial boundary bucket that was not used).

## Requested vs represented window

`window_start/end` echo the request. `data_start/end` are what the
data can actually represent:

- `data_start = max(window_start, earliest representable instant)`,
  where representable instants come from retained raw slots,
  surviving hourly buckets, and segment starts (all-missed evidence).
- The oldest raw hour is suspect: purged and never-scheduled slots
  are indistinguishable there. If its bucket exists and fewer runs
  survive than the schedule owed, the represented start snaps to the
  next UTC hour — the API truncates instead of guessing.
- Nothing representable: null bounds, zero counts, null ratios,
  empty series, `is_partial=true`. A truncated interval is
  `is_partial=true`.

`raw_available_from`, `resolution` (raw / hourly / mixed / none),
`raw_retention_hours`, and `hourly_retention_days` are surfaced so a
client can explain *why* a window is partial.

## What MVP does not compute

- No P50/P95 — sums and counts cannot reconstruct quantiles; only
  `avg_duration_ms` over eligible samples is emitted.
- No chart gap bridging — series entries exist only where data does;
  missing hours stay missing.
- No cross-monitor ratio averaging — summary uptime is the weighted
  ratio of summed counts, never the mean of per-monitor percentages.
