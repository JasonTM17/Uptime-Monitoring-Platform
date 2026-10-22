# Render Free web service — hosted deployment notes

Single `web` service from `render.yaml`: the distroless image
(`uptime-api`) runs API + engine + dispatcher in one process — the
modular monolith keeps engine ownership/session-lock semantics intact.

## Constraints honoured

- **Digest deploy** — `image.url` carries `@sha256:<manifest-list
  digest>` substituted from `artifacts/release/image-manifest.json`;
  mutable tags (incl. `:latest`) violate the contract.
- **750 h/month** — one always-on service ≈ 744 h; a second service
  or worker would break the budget → migrate runs as a deploy-time
  step from a trusted host (the image has no migrate binary; Render's
  `preDeployCommand` can't run inside distroless anyway).
- **15 min idle → spin down**, ~1 min cold start — an external
  keepalive pings `GET /health/live` every 5 min. `/health/live` is
  DB-free so keepalive consumes no DB budget; `/health/ready` stays
  the DB-bound probe. Engine owner-loss/restart correctness is already
  proven (C80); cold starts are tolerated, not hidden.
- **Ephemeral FS** — app is stateless (postgres is the only state).

## Env contract

`render.yaml` lists names only. Secret values (`DATABASE_URL`,
`ENGINE_DATABASE_URL`, `MIGRATION_DATABASE_URL`, `CSRF_SIGNING_KEY`,
later `CHANNEL_*` when notifications enable) go to the Render env UI.

- `APP_ENV=hosted` → Secure cookies + hosted defaults + fail-closed
  `TRUSTED_ORIGINS`.
- `TRUSTED_ORIGINS=https://<vercel-app>.vercel.app` — exact origin, the
  only browser origin that may carry credentials.
- `TRUSTED_PROXIES=<Render LB CIDRs>` — required under hosted or all
  logins rate-limit against one shared proxy bucket; obtain the actual
  egress/proxy ranges for the service region at provision time and
  record them in `hosted-candidate.json`.

## Engine/session semantics

`ENGINE_DATABASE_URL` → **Supabase direct session (5432)**, never the
transaction pooler — advisory lock + dedicated `*pgx.Conn` need
session semantics (see `docs/deployment/supabase.md`).

## Rollback

Render free rollbacks cover the 2 most recent deploys. Rollback = set
`image.url` to the retained previous compatible digest (C87 receipt)
and redeploy — schema compatibility is the gate, never a `down`
migration.
