# Local acceptance — Phase 09 (C82)

Candidate: local release candidate for the uptime monitoring platform.
This document records what was proven, against which exact snapshot, by
which evidence — and what is explicitly **not** proven.

## Candidate identity

| Identity | Value |
| --- | --- |
| Source SHA | `723588c` (`git rev-parse HEAD` at freeze) |
| Source diff cleanliness | `git diff --check`: clean on all tracked source; violations only inside `plans/` bookkeeping docs (uncommitted per plan convention) |
| Dirty paths at freeze | `plans/261021-1505-uptime-platform-master/**` card-status bookkeeping only; no source dirty paths |
| Release image | `uptime-platform:local` digest `sha256:5e5788ac8185411b83f23c01299f65f5895242e22ddeacc320c06c1fdedcf8a7` (linux/amd64, distroless, non-root, `cmd/api` only) |
| Test harness image | `uptime-accept-harness:local` digest `sha256:298e7dcc4089e86385ced25fc7d445a256937f4d49ca54093aaa00bbb9413794` (contains `testapp`/`fixture`/`admin`/`channel` binaries — never the release image) |
| Database | PostgreSQL 17.11 (`postgres:17.11`, pg_dump/pg_restore 17.11) |
| Go toolchain | `golang:1.27.3` container (host toolchain AV-blocked; all Go gates ran in-container, `-race` enabled — Linux runtime recorded) |
| Web toolchain | Node v24.12.0, npm, `tsc --noEmit`, vite 7.3.7, Playwright (desktop chromium + 390px projects) |
| Composition | `compose.yaml` (local app+db), `compose.test.yaml` (`uptime-accept` project: `control` NAT bridge + `publicnet` internal-only bridge `93.184.216.0/24`) |

## Gate results (this candidate)

| Gate | Command | Result |
| --- | --- | --- |
| Static | `go vet ./...` | PASS |
| Unit | `go test ./...` | PASS (all packages `ok`) |
| Race | `go test -race ./...` | PASS |
| Integration (CI lane) | `go test -count=1 -race -p 1 -tags=integration ./internal/auth ./internal/engine ./internal/incident ./internal/monitor ./internal/notification ./internal/admin` | PASS — 6/6 packages on fresh schema |
| Integration (out-of-lane) | `go test -tags=integration ./internal/analytics` / `./internal/testsupport` | PASS each, run standalone on a freshly migrated disposable schema |
| Web static | `npm --prefix web run typecheck`, `npm --prefix web run api:check` | PASS (generated types match OpenAPI contract) |
| Web unit | `npm --prefix web run test` | PASS — 59/59 vitest |
| Web build | `npm --prefix web run build` | PASS (vite production bundle) |
| Local acceptance | `node scripts/accept-local.mjs --profile local --gate all --output artifacts/acceptance/local.json` | PASS — backend 19/19, browser 8/8 (both viewports), restore 3/3 |
| Compose validity | `docker compose config --quiet`, `docker compose -f compose.test.yaml config --quiet` | PASS |
| Release-image smoke | `docker compose --profile app --profile tools up -d postgres migrate app`; `/health/ready` 200 → register→login→`/auth/me` round-trip | PASS — distroless non-root binary (UID 65532), image digest `sha256:5e5788ac…` |
| Capacity protocol | `node scripts/measure-capacity.mjs --duration-seconds 1800` (C80, `artifacts/capacity-local.json`) | PASS — verdict PASS, wall 1481s; reused per C82 budget (no production-code change since; C81 delta is test/tooling only) |
| Restore drill | `node scripts/restore-drill.mjs --target fresh --output artifacts/restore/report.json` | PASS — 8/8 steps, RPO 0 (quiesced dump), measured RTO ≈20s on the disposable world |

### Shared-database property of `./...` integration

The literal `go test -tags=integration ./...` does **not** pass as a
single invocation: all suites share one disposable database (CI documents
this — `-p 1`, and even serialized packages leave state that suites
authored for a fresh world reject: FK-order teardowns, admission-window
charge pollution, quiescence requirements for restore tests). The
authoritative CI lane plus per-package standalone runs above cover every
integration test file. Recorded as harness design property, not product
defect; unifying it is a test-infrastructure redesign out of C82 scope.

## Requirement trace (required local evidence)

| Required area | Current evidence |
| --- | --- |
| Auth / sessions / CSRF / rate-limit | `internal/auth` integration lane (`-race`) + accept-local backend seed/login/logout-kills-identity steps + browser Login journey |
| IDOR / owner isolation | backend gate: foreign GET/list/history/mutation → 404, post-swap session exposes only bob's data (0 rows); `internal/monitor` + admin lanes |
| RBAC / revoke / suspend / last-superadmin | `internal/admin` lane (`-race`); browser AdminRoleRevocation (step-up reauth → revoke → session dead → notice); backend gate revoked-session 401 + audit events |
| SSRF / rebinding / TLS | `internal/checker` suite (`-race`); accept composition exercises the **unchanged production destination policy** against a global-unicast-looking internal-only subnet |
| Race / shutdown / restart / fencing | `go test -race` green; engine `TestOwnerLossStopsWrites`, `TestReservationCrashRecovery`, C80 fault block (SIGKILL epoch takeover, 0 fabricated results, no catch-up storm); C78 SIGTERM smoke (0.6s) |
| Outbox atomicity / ordering / ambiguity | `internal/notification` lane (`-race`); backend gate DOWN→RECOVERY ordered deliveries; restore drill reclaimed-lease → SENT |
| Rollup / retention / denominators | `internal/analytics` standalone PASS (stale-window, denominator, purge, rollup-merge tests) |
| Browser responsive / keyboard / cache isolation | browser gate 8/8 on chromium **and** chromium-390; vitest session/logout race coverage; OwnerIsolation both viewports |
| Restore rehearsal | `artifacts/restore/report.json` — counts/FKs/manifest/schema-head + session revocation + key rotation v1→v2 + outbox reconcile before enable |
| Metrics / health / readiness | `internal/observability` unit + live scrape smoke (C77), goroutine/workers/queue/owner gauges in capacity report |
| Build context privacy | `scripts/check-build-context.mjs` gate (C78) ran before any build; release image history inspected — no private canary |

## Repairs applied during this gate (bounded)

1. `internal/monitor/repository_integration_test.go` — `fieldSeq` package
   var raced by concurrent racers under `-race`; made `atomic.Int64`.
2. `internal/auth/registration_integration_test.go` — hash-pool saturation
   retry budget 8→40 attempts; saturation is designed backpressure, the
   test's window was too thin under race instrumentation on this host.

Both are test-only repairs; no production code changed. The affected
packages were re-run under `-race` and pass; the full CI lane was re-run
after repairs and is green (recorded above).

## Independent review

- **Kongming** (architecture/authority, read-only):
  **PROCEED_WITH_RESIDUAL_RISK**. Two medium findings repaired during
  this gate; the rest recorded as residual risk below or deferred.
- **Wukong** (adversarial falsification of the owner-loss fencing
  claim, read-only): **VERIFIED-HELD** (evidence grade E2 — mechanism +
  test inspection; integration suite not re-executed by the reviewer).
  Single-conn lock+write lifetime, mutex-serialized `Exec`, epoch
  revalidation under row locks — no falsification found. Residual: the
  fence is a wiring convention, not enforced inside the SQL primitive
  (a future caller could pass a non-owner conn).

### Review-driven repairs applied in this gate

| Finding | Repair |
| --- | --- |
| K-F1: isolation claim overstated (app dual-homed; real egress possible via control NAT) | `compose.test.yaml` header rewritten — `internal: true` scoped to publicnet; explicit instruction that all monitor targets stay `*.fixture`-scoped |
| K-F2: release binary never exercised by composed evidence | Live smoke added below — release image booted via compose `app` profile: `/health/ready` 200, register→login→`/auth/me` round-trip on the distroless non-root binary (UID 65532, rev `d7929f8`) |
| K-F4: never-fail `ok:true` fields in capacity report | `faults.db_disconnect` and `inv.stale_finalize_total` marked `gate:false` telemetry with explanation; tautological `orphans>=0` clause removed from `crash_after_reserve` |
| K-F5: browser gate count-blind (grep subset could pass) | gate now captures playwright stdout and requires `passed == 8` (4 journeys × 2 viewport projects) in addition to exit 0 |
| K-F6: `BLOCKED_PREFIXES` lacked `cmd/testapp`,`cmd/fixture` | added — context gate now independently refuses harness sources even if `.dockerignore` regresses (re-verified: PASS 168 files) |
| K-F7: `report.limitations` always `[]` | populated with the real six limitations (sender never fails, testapp-not-release, dual-homing, readiness gap, unauthenticated test surfaces, faster heartbeat) |
| K-F3: readiness green for configured-but-failed components | **deferred** — probe-semantics change is production code; recorded as known gap in limitations |
| W-R1: fencing by convention not enforced in primitive | **deferred** — candidate hardening is an in-tx `pg_try_advisory_lock` re-check inside `ReserveRun`; recorded, not applied (would re-open C80 evidence) |
| K-F9/W-R4: "artifacts missing" | false — `artifacts/*.json` exist on disk but are gitignored; reviewer read view could not see them |

Review identities and findings are recorded verbatim in
`plans/261021-1505-uptime-platform-master/reports/` alongside this file's
commit; a stale review is refreshed whenever a repair touches its scope.

## Explicitly NOT_RUN / not proven

- **Hosted/cloud deployment, registry push, CI execution** — NOT_RUN; the
  workflow file existing is not evidence it ran. Phase 10/11 gates own it.
- **Live Telegram/provider send** — NOT_RUN by design; all deliveries end
  at the recording sender (`/__test__/deliveries`).
- **Literal `./...` single-invocation integration** — FAILS by shared-DB
  design (see above); coverage is via the CI lane + standalone packages.
- **30-minute soak** reused from C80 (`capacity-local.json`) — the
  candidate adds no production-code change since that artifact; per C82
  budget it is not re-run for tooling-only deltas.
- **Capacity projections for 1k/10k monitors** — recorded in the capacity
  report as modelled, NOT measured.
- **RTO/RPO** are measured on this disposable dataset/environment only —
  not a hosted guarantee.
- **Arm64/multi-platform image** — linux/amd64 only; no native/QEMU smoke.
- **Optional TOTP** — not implemented and not claimed.

## Residual risks accepted

- One host, one soak run; coarse `docker stats` sampling for CPU/RSS.
- Engine has no `RUNNING`/`started_at` state — saturation evidence uses
  observed worker concurrency + admission/completion timestamp proxies
  (documented in `docs/testing/capacity.md`).
- `plans/` bookkeeping files carry whitespace noise flagged by
  `git diff --check`; source tree is clean.
