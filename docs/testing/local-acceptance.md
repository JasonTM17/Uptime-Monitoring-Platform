# Local acceptance harness (the local acceptance harness)

Deterministic, disposable end-to-end proof for the composed platform:
real PostgreSQL, real API, real engine, real delivery pipeline, and a
real browser lane — with three controlled seams injected at the test
composition root. Nothing in the production image or destination
policy changes.

## Run

```sh
node scripts/accept-local.mjs --profile local --output artifacts/local-acceptance.json
# individual lanes:
node scripts/accept-local.mjs --profile local --gate backend  --output artifacts/local-backend.json
node scripts/accept-local.mjs --profile local --gate browser  --output artifacts/local-browser.json
node scripts/accept-local.mjs --profile local --gate restore  --output artifacts/local-restore.json
```

`--gate` defaults to `all`. Exit code is nonzero when any executed
gate fails; skipped/absent gates never appear as PASS.

## Topology (`compose.test.yaml`, project `uptime-accept`)

Two networks with disjoint roles:

| network | kind | contents |
|---|---|---|
| `publicnet` | `internal: true`, squatted public `93.184.216.0/24` | `target` under network-scoped alias `target-public`; `app` |
| `control`   | normal NAT bridge | `db`, `migrate`, `app`, `target`; the only published ports |

- `target` runs `cmd/fixture`: `/check` on :80 (only reachable on
  `publicnet`, like a real public target) and `/control` on :9080
  (published to host `127.0.0.1:19080` for the driver — internal
  networks cannot serve published ports, so the bind lands on
  `control` unambiguously).
- `app` runs `cmd/testapp` on both networks: control for the DB and
  its published API port (`127.0.0.1:18080`), publicnet so the
  embedded docker DNS resolves `target-public`.
- `db` is tmpfs postgres:17.11 with disposable credentials;
  `migrate` reuses `scripts/migrate-entrypoint.sh`.
- `harness` is a build-only service that produces the shared
  `uptime-accept-harness:local` image (`Dockerfile.test`).

The `.fixture` hostname convention: `cmd/testapp`'s
`fixtureResolver` strips the suffix and resolves the bare service
name — for `target-public` that answer can only be the publicnet
address, because network-scoped aliases never leak the control IP.
Every dial still passes the unchanged `checker` transport policy
(public global-unicast only); there is no allow-private flag.

Why a squatted public /24: the destination policy correctly denies
every lab-friendly prefix — TEST-NET-1/2/3, 198.18.0.0/15
benchmarking, ULA, documentation ranges — as special-purpose. The
only way a fixture can carry a dialable "public" address is to own
one inside an unreachable network. `93.184.216.0/24` is arbitrary;
`internal: true` guarantees the squat can never collide with the
real range holder.

## Injected seams (test composition only)

| seam | mechanism | production untouched? |
|---|---|---|
| resolver | `fixtureResolver` strips `.fixture`, docker DNS answers | policy + checker code identical |
| sender | `recordingSender` implements `notification.Sender`, served at `GET /__test__/deliveries` | lease/ACK/retry pipeline identical |
| cadence | `TESTAPP_TICK_MS=250` shortens the scheduler tick | interval_seconds, thresholds, admission budgets unchanged |

`cmd/testapp` and `cmd/fixture` are excluded from the release build
context (`.dockerignore`) and never enter the release image; they
compile only through `Dockerfile.test`.

## Seeding

- USER identities register through `POST /auth/register` and log in
  through `POST /auth/login` — no default public passwords; each run
  generates random credentials written to `accept-seeded.json`
  (artifacts are gitignored).
- The SUPER_ADMIN is granted via `admin bootstrap` / `admin recover`
  inside the app container — the operator local-authority path, not
  an HTTP backdoor.
- Channels are created via `POST /notification-channels` and verified
  via `channel verify` (destination on stdin) — the only supported
  verification flow.

## Scenarios (backend gate)

| scenario | key assertions |
|---|---|
| `LifecycleIncidentRecovery` | baseline UP; 3 forced checks via pause/resume (due-now, admission-gated) hit FailThreshold exactly — no early incident; incident opens, health DOWN; outbox PENDING→SENT (admin API); `<name> is DOWN` recorded; recovery on the natural 60s cadence closes with `RECOVERED` + delivery |
| `AdminRoleRevocation` | admin `revoke-sessions` → live session 401s; audit event records actor/action/subject |
| `OwnerIsolation` | foreign monitor GET/PATCH/incidents are 404; owner list contains no foreign rows |
| `LogoutIdentityRace` | logout kills the session server-side; a same-context re-login sees only the new identity's rows |

Why recovery waits: pause, resume, and config updates all close an
open incident as `CONFIG_CHANGED` — they cannot fabricate a recovery.
The harness therefore forces the three failure checks (each
pause+resume is a legitimate due-now under the durable admission
budget) but lets the two recovery successes arrive on the real
interval (~120s). That is product latency, not a guessed sleep.

## Browser gate

`scripts/accept-local.mjs --gate browser` starts the composition,
seeds fresh identities (incl. a `recover`-granted admin), writes
`accept-seeded.json`, then runs:

```sh
npm --prefix web run test:e2e -- --project=chromium \
  --grep 'LifecycleIncidentRecovery|AdminRoleRevocation|OwnerIsolation|LogoutIdentityRace'
```

with `E2E_API_TARGET=http://localhost:18080` so the vite dev proxy
reaches the testapp, plus `ACCEPT_*` envs the spec requires. The spec
skips when env is absent (plain `npm run test:e2e` keeps working);
the driver counts a skipped lane as NOT_RUN evidence, not a pass.
Journeys are UI-real: login form, monitor create form, dashboard,
incidents page, admin users/audit pages — with API-level fixture
stepping between UI observations.

## Restore gate

`pg_dump -Fc` of the acceptance database → `pg_restore` into a
**fresh** `accept_restore` database in the same disposable container
→ schema-version + row-count verification across users, sessions,
monitors, incidents, outbox, audit. This is the mechanism-level
rehearsal; the full restored-identity verification matrix is the restore drill.

## Teardown

`docker compose -p uptime-accept -f compose.test.yaml down -v
--remove-orphans` — removes containers, networks, and volumes this
project owns. The dev stack (`uptime-platform`), named dev volumes
(`pgdata`, `go-*-cache`), and docker client config are never touched.
The dump archive persists at `artifacts/accept-restore.dump` for
inspection.

## Reports

`--output` receives a scrubbed JSON report: gate statuses, per-step
PASS/FAIL, monitor/incident ids (uuid evidence), row counts, and
limitations. Credentials, destination material, DSNs, and cookies
never enter the report; emails are per-run `@accept.test` values.
