# Supabase Free PostgreSQL — hosted deployment notes

Provision (manual, free): create one project in the org; record
`project_ref`, region, and the two connection strings. Secrets live
only in the provider store — never committed.

## Connection contract

| Role | String | Mode | Why |
| --- | --- | --- | --- |
| `DATABASE_URL` | app pool | session or transaction pooler OK for app reads/writes | pooled HTTP workload |
| `ENGINE_DATABASE_URL` | engine owner lock | **direct session (port 5432), NOT transaction pooler** | the advisory owner-lock + dedicated `*pgx.Conn` requires session semantics; transaction mode releases the backend between statements and silently breaks lock ownership (C80 fencing) |
| `MIGRATION_DATABASE_URL` | `golang-migrate` run | direct session, **TLS required** (`sslmode=require`) | migrations at deploy time only; never auto-migrated at app start |

All strings: `postgres://postgres.[project-ref]:<password>@aws-0-<region>.pooler.supabase.com:5432/postgres?sslmode=require`
for direct session, or port `6543` for transaction pooler (app DSN
only, never the engine DSN).

## Least-privilege

Default `postgres` role is superuser — acceptable for the free-tier
demo but recorded as residual risk. If a least-privilege app role is
created, it needs full DML on app tables and must NOT own the engine
advisory lock differently (lock is session-scoped, role-agnostic).

## Budget (docs/deployment/free-tier-budget.md)

- 500 MB DB → hosted profile steady-state ≤ 15 MB.
- 5 GB egress → SQL traffic only; checker target HTTP leaves from
  Render.
- Pause after 1 week of inactivity → natural engine traffic prevents;
  manual dashboard resume restores within the 1-year window.
- **No automatic backups on free** → manual `pg_dump` per
  `docs/runbooks/backup-restore.md`; accepted residual risk = last
  manual dump.

## Migration receipt

After each deploy: run `migrate -database $MIGRATION_DATABASE_URL up`
from a trusted host (not inside the distroless image — it has no
migrate binary) and record `{version, dirty, applied_at_utc}` into
`artifacts/hosted-candidate.json` under `migration`.
