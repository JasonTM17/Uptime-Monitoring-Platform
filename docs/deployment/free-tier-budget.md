# Free-tier budget — hosted deployment preflight

Status: **BUDGET WORKSHEET** — research/read-only; no resources
provisioned. Facts re-verified against official docs on 2026-10-22
(citations inline); they are point-in-time, not guarantees — recheck at
deploy time.

## Hosted profile (contract)

10 monitors × 60 s interval on the hosted deployment. Local profile
(100 monitors) remains the capacity reference — the local capacity run measured it; the
hosted profile is a *smaller* workload, never projected beyond what
the capacity run measured per-request.

| Quantity | Value | Source |
| --- | --- | --- |
| checks/day | 10 × 1440 = **14,400** | 60 s interval |
| checks/month | **432,000** | 30-day |
| raw retention | 24 h | retention contract |
| hourly rollup | 30 days | analytics contract |
| steady-state raw rows | ~14.4 k | 24 h window |
| hourly points/month | 10 × 720 = **7,200** | rollup |
| measured DB footprint (local capacity run, 100 monitors incl. indexes) | **11.2 MB** | `artifacts/capacity-local.json` |
| measured check-run row cost | ~0.3–0.8 KB incl. indexes | capacity run: 11.2 MB ÷ ~15 k retained rows, conservative bound |
| hosted raw+rollup storage | **≤ 15 MB** | 14.4 k raw + 7.2 k hourly + incidents/outbox/audit/segments |

## Provider budget matrix

| Provider | Role | Free quota (2026-10-22) | Hosted need | Verdict |
| --- | --- | --- | --- | --- |
| Vercel Hobby | static SPA + `/api` rewrite → Render | 100 GB Fast Data Transfer; personal scope; pause on overage ([vercel.com/docs/plans](https://vercel.com/docs/plans)) | ~10 MB build + user traffic, no server functions | FITS — cron NOT usable: Hobby cron = **once/day** granularity ([cron-jobs/usage](https://vercel.com/docs/cron-jobs/usage-and-pricing)); the 60 s engine scheduler must live on Render, not Vercel |
| Render Free web service | Go API + engine + dispatcher (one process) | **750 instance-hours/month**; 15 min idle → spin down, ~1 min cold start; ephemeral FS; TLS + custom domain included; rollbacks to 2 previous deploys ([render.com/docs/free](https://render.com/docs/free)) | 1 service × 744 h/month = **~99 % of quota** (6 h headroom) | FITS — tight; a second always-on service (migrate/cron) would break the budget, so migrate must run as a release/deploy step, not a second service |
| Supabase Free | PostgreSQL (persistent) | 500 MB DB; 5 GB egress; shared CPU/500 MB RAM; pause after **1 week** inactivity; ≤ 2 active projects; **no automatic backups** ([supabase.com/pricing](https://supabase.com/pricing), [free-project-pausing](https://supabase.com/docs/guides/platform/free-project-pausing)) | ≤ 15 MB data; engine queries 24/7 keep it active | FITS — no backups is the real gap: rely on the the restore drill `pg_dump` drill for manual snapshots; document honestly |
| External keepalive (e.g. BetterStack/UptimeRobot free) | 5 min GET on `/health/live` | provider-dependent | every 5 min ≪ 15 min idle window | REQUIRED for uptime; endpoint is DB-free so keepalive never touches the DB budget |

### Explicitly rejected

- **Render Free Postgres** — free instance **expires after 30 days**
  ([render.com/docs/free](https://render.com/docs/free)); unsuitable
  as the permanent store. Supabase chosen instead.
- **Vercel Cron as monitor scheduler** — once/day minimum interval on
  Hobby; the engine's 60 s tick belongs inside the Render process.
- **Second Render service** (separate migrate/cron worker) — would
  exceed the 750 h shared pool; migrate runs at deploy only.

## Traffic/egress separation (plan F02/F03)

- Checker HTTP traffic (monitor targets) leaves from **Render**, not
  Supabase — never counted against the 5 GB DB egress.
- Supabase egress = SQL result traffic only: ~432 k tiny result sets/
  month + admin reads — ≪ 5 GB.
- Vercel transfer = static assets + proxied API JSON — ≪ 100 GB.

## Keepalive semantics — what it does and does not guarantee

- `/health/live` is **DB-free** by design → keepalive pings don't
  consume DB/egress budget and can't mask DB outages (`/health/ready`
  remains the DB-bound probe).
- Keepalive keeps the Render service *awake* so the engine tick runs;
  it does **not** guarantee zero restarts, SLA uptime, or that the
  service is immune to platform restarts. Cold-start ≈ 1 min; the
  engine's owner-lock takeover + interrupted-run reconciliation (capacity run)
  makes restart behavior correct, not invisible.
- Supabase anti-pause is satisfied *naturally* by engine queries —
  no artificial keepalive-to-DB traffic needed; if the app sleeps
  >7 days a manual dashboard resume restores within the 1-year window.

## Failure/edge review (card E)

- **All-target-timeout**: 10 timeouts at 60 s occupy ≤10 workers of
  the hosted pool — bounded by the measured admission math; no quota impact.
- **Notification storm**: outbox is DB-bounded + dispatcher-limited;
  worst case adds small rows, not egress spikes.
- **31-day month**: 744 h ≤ 750 h still holds; Feb is safer.
- **Extra Render services**: none planned; any always-on second
  service is a budget violation — flag before adding.
- **Paused DB**: 1-week-inactivity pause cannot trigger while the
  engine runs; restore = dashboard resume + the restore drill reconciliation.
- **No backup entitlement**: manual `pg_dump` per
  `docs/runbooks/backup-restore.md`; accept data-loss window = last
  manual dump — recorded as residual risk, not waived.

## Blockers / account entitlements (UNKNOWN until checked)

| Item | State |
| --- | --- |
| Vercel account exists + Hobby plan | UNKNOWN — needs user account |
| Render account + free web service | UNKNOWN — needs user account |
| Supabase org/project (free) | UNKNOWN — needs user account |
| Keepalive provider account | UNKNOWN — needs user choice |
| GitHub repo visibility (deploy source) | PASS — `JasonTM17/Uptime-Monitoring-Platform` PUBLIC (re-verified 2026-10-22) |

No provisioning, billing, or account mutation is performed by this
card. If any provider is unavailable, local acceptance stands and the
release target is NOT silently changed — that is a user decision.
