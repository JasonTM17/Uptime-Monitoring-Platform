# Runbook: local and test databases

Two PostgreSQL 17.11 services exist:

- `postgres` — persistent **local** data on a named volume, network `local`,
  loopback port `POSTGRES_PORT` (default 5432).
- `postgres-test` — **disposable** test data on tmpfs, isolated network
  `test`, loopback port `TEST_POSTGRES_PORT` (default 5433). Its data vanishes
  when the container stops; that is intentional.

Migration is a separate job (`migrate`, `migrate-test`), never an
application startup side effect.

## First-time setup

PowerShell and Linux/macOS:

```sh
cp .env.example .env   # then edit values
docker compose up -d postgres
docker compose ps
```

Wait until `postgres` reports `healthy`. `depends_on` with
`condition: service_healthy` gates the migration job — a running process is
not proof of readiness; `pg_isready` is.

## Run migrations (separate job)

```sh
docker compose --profile tools run --rm migrate up        # local
docker compose --profile test run --rm migrate-test up    # test DB
docker compose --profile tools run --rm migrate version   # inspect
```

Destructive directions (`down`, `drop`) are refused unless
`MIGRATE_TARGET=test` and `MIGRATE_ALLOW_DESTRUCTIVE=true`; the local
database cannot be migrated down through this job.

## Test profile

```sh
docker compose --profile test up -d postgres-test   # start disposable DB
docker compose --profile test run --rm migrate-test up
docker compose --profile test run --rm go-test      # Linux go test -race ./...
docker compose --profile test down                  # stop + destroy tmpfs data
```

`go-test` runs the suite inside Linux (real `-race` coverage); the source
tree mounts read-only and module/build caches use named volumes.

## Rules that keep local data safe

- Never run `docker compose down -v` or `docker volume rm` against the local
  stack — that destroys the learning database. Plain `down` keeps `pgdata`.
- PostgreSQL binds to `127.0.0.1` only; do not republish it on all interfaces.
- Do not print `docker compose config` output publicly — it interpolates the
  DSN with your real password.
- Test services never mount the local volume and never reuse local
  credentials; if you need to nuke the test DB, `compose --profile test down`
  is always safe.
