# Retention runbook

Bounded maintenance for raw evidence and aggregates. Retention is
about *application semantics* — which rows stop being represented —
not disk reclamation. A DELETE does not shrink the database file;
VACUUM/storage behavior is a database concern outside this contract.

## Lanes and horizons

| Lane | Local | Hosted-free | What leaves |
|---|---|---|---|
| Raw runs+results | 30d | 24h | terminal, rolled, unanchored pairs |
| Hourly aggregates | 30d | 30d | `hourly_stats` buckets |
| Terminal outbox | 30d | 30d | SENT/SUPPRESSED intents |

`RunRetention(ctx, pool, cfg, now)` sweeps all three lanes in bounded
batches (`cfg.Batch` rows per commit, optional `BatchDelay`). Each
batch is its own transaction — cancel, crash, or restart resumes
from durable commits; there is no scan position to lose.

## The rollup barrier (load-bearing)

A raw run+result pair is purge-eligible only when **every** result
on the run has `rolled_up_at` set. Retention can never remove a
sample that was not yet counted into `hourly_stats` — this is the
invariant that keeps denominators identical before and after purge.
If `hourly_stats` looks stale, investigate the rollup, never force
the purge.

## What is protected

- **Unrolled results** — the rollup barrier above.
- **Active runs** — `finished_at IS NULL` rows are excluded by
  construction (reserved/running work).
- **Incident anchors** — a run referenced as `opened_check_id` or
  `resolved_check_id` outlives raw retention while the incident's
  evidence chain exists, including notification intents on that
  incident (DEAD heads need causal context).
- **Schedule segments** — never purged; the expected-slot
  denominator depends on them.
- **DEAD outbox rows** — dead-letter evidence stays.
- **Audit rows** — outside retention scope entirely (180d, operator
  export flow — not implemented in this sweep).

## Failure semantics

Retention failure degrades **retention health**, never target
health: a stuck sweep leaves data longer, it cannot corrupt counts.
`RunRetention` returns the partial report accumulated before the
error so operators can see which lane stalled.

## Operator checks

```sql
-- unrolled backlog (must trend to 0; retention cannot purge these)
SELECT count(*) FROM uptime.check_results WHERE rolled_up_at IS NULL;

-- oldest retained raw vs the horizon
SELECT min(slot_at) FROM uptime.check_runs WHERE finished_at IS NOT NULL;

-- purge candidates beyond the raw horizon
SELECT count(*) FROM uptime.check_runs
 WHERE finished_at < now() - interval '30 days';
```

A growing unrolled backlog means the rollup is broken — fix that
first; retention will simply retain more, which is safe.
