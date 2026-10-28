# Product requirements and scope traceability

The platform monitors public HTTP(S) endpoints for individual owners. It records
sampled availability, incidents and verified Telegram notification intents,
with a permission-scoped admin console. The stack is a Go net/http modular
monolith with PostgreSQL and a React/Vite dashboard.

This page owns scope. [Business rules](business-rules.md) owns domain decisions,
the [user guide](user-guide.md) owns the user journey, and [OpenAPI](api/openapi.yaml)
owns HTTP shapes. Requirements point to current owners rather than historical phases.

## Reading status correctly

- **Implemented**: behavior and associated automated checks exist in the repo;
  this does not claim every environment has passed them.
- **Operator/process**: a controlled procedure or engineering obligation.
- **Unverified**: a protocol/guide exists, but the corresponding hosted,
  provider or capacity evidence has not been established publicly.
- **Future**: outside the local release. OpenAPI operations marked x-future are
  drafts and must not be treated as callable endpoints.

Use [testing](testing.md) to select checks; inspect the exact source revision of
a CI run before claiming PASS. The [release record](releases/v0.1.0-evidence.md)
applies only to its named image/source, not every later main commit.

## Requirement map

| Req | Requirement | State and executable / documentation owner |
| --- | --- | --- |
| R01 | Register/login/logout, identity, hashing, revocable sessions | Implemented: [auth](../internal/auth/handlers.go), [identity integration](../internal/auth/identity_integration_test.go), [own sessions](../internal/auth/own_sessions_integration_test.go). No self-service password reset or profile editing. |
| R02 | Ownership isolation for monitors/history/incidents/channels | Implemented: [monitor isolation](../internal/monitor/mutations_integration_test.go), [history](../internal/analytics/api_integration_test.go), [channels](../internal/notification/channels_integration_test.go). |
| R03 | Monitor CRUD/pause/resume, quotas, pagination, bounded requests/errors | Implemented: [handlers](../internal/monitor/handlers.go), [validation](../internal/monitor/validation_test.go), [mutations](../internal/monitor/mutations_integration_test.go), [pagination](../internal/monitor/pagination_integration_test.go). |
| R04 | Bounded public HTTP GET, default 2xx or explicit expected status | Implemented: [checker](../internal/checker/http_checker.go), [outcome tests](../internal/checker/outcomes_test.go). |
| R05 | SSRF policy at actual dial, redirects and rebinding | Implemented: [boundary](security/ssrf-boundary.md), [rebinding tests](../internal/checker/rebinding_test.go), [destination fixtures](../internal/checker/destination_policy_test.go). |
| R06 | Single-owner scheduler, bounded workers/queue, durable admission | Implemented: [lifecycle](engine-lifecycle.md), [ownership](../internal/engine/owner_integration_test.go), [scheduler](../internal/engine/scheduler_integration_test.go). |
| R07 | Evidence thresholds; pause/freshness separate from health | Implemented: [decision table](business-rules.md#observations-and-incident-decisions), [reducer](../internal/incident/reducer_test.go), [lifecycle mutations](../internal/monitor/mutations_integration_test.go). |
| R08 | Atomic result/state/incident/outbox, idempotency, stale-write fences | Implemented: [finalization](../internal/engine/finalize.go), [tests](../internal/engine/finalize_integration_test.go), [fencing](../internal/engine/fencing_integration_test.go). |
| R09 | Verified Telegram, outbox, retry, causal ordering, dead-letter controls | Implemented: [delivery](runbooks/notification-delivery.md), [claims/retry](../internal/notification/lease_integration_test.go), [ambiguity](../internal/notification/ambiguity_integration_test.go). Verification is operator-only; real recipient delivery needs provider evidence. |
| R10 | History/stats, transparent coverage/windows, rollups and retention | Implemented: [statistics](architecture/statistics.md), [API oracles](../internal/analytics/api_integration_test.go), [denominators](../internal/analytics/denominators_integration_test.go), [retention](../internal/analytics/retention_integration_test.go). |
| R11 | User dashboard, monitors, charts, incidents, channels and settings | Implemented: [frontend routes](../web/src/app/App.tsx), [frontend testing](testing/frontend.md), [monitor E2E](../web/e2e/user-monitor.spec.ts). |
| R12 | Admin accounts, sessions, quotas, roles, global monitors and operations | Implemented: [RBAC](security/rbac-matrix.md), [accounts](../internal/admin/accounts_integration_test.go), [roles](../internal/admin/roles_integration_test.go). |
| R13 | Least privilege, audit, step-up, race safety and last-admin protection | Implemented: [race contract](testing/admin-security.md), [race tests](../internal/admin/security_races_integration_test.go), [last-admin tests](../internal/admin/superadmin_integration_test.go). DBA authority is outside application immutability. |
| R14 | Permission-scoped admin UI, pulse and audit inventory | Implemented: [routes](../web/src/app/App.tsx), [RBAC E2E](../web/e2e/admin-rbac.spec.ts), [operations E2E](../web/e2e/admin-operations.spec.ts). Menu visibility never replaces server authorization. |
| R15 | Local Compose, migrations, fixtures, deterministic acceptance | Operator/process: [database](runbooks/local-database.md), [toolchain](toolchain.md), [acceptance](testing/local-acceptance.md). Platform claims require an actual run there. |
| R16 | Unit/integration/browser/security/race/recovery checks | Implemented checks: [testing](testing.md), [CI definition](../.github/workflows/ci.yml). A workflow file is not a passing run. |
| R17 | Structured logs, correlation, health and bounded metrics | Implemented: [operations](runbooks/local-operations.md), [HTTP server](../internal/platform/httpserver/server.go), [metrics](../internal/engine/metrics.go). |
| R18 | Local acceptance before hosted release | Operator/process: [harness](testing/local-acceptance.md), [evidence scope](releases/local-acceptance.md). Controlled fixtures are not real-provider evidence. |
| R19 | Free hosted frontend/API/database and external monitoring | Unverified: [Render](deployment/render.md), [Vercel](deployment/vercel.md), [Supabase](deployment/supabase.md), [budget](deployment/free-tier-budget.md). These are candidate guides, not proof of a running service. |
| R20 | GitHub/repository overview, API, database, architecture decisions, runbooks, media and release evidence | Coverage mapped below: [index](README.md), [system decisions](architecture/system-design.md), [database](architecture/database.md), [UI decisions](design/design-decisions.md), [media](media/manifest.json), [release](releases/v0.1.0-evidence.md). External metadata and media remain checkpoint evidence, not automatic current-source proof. |
| R21 | Per-change scope, steps, tests, verification, mistakes, review and definition of done | Engineering obligation: [contributing](../CONTRIBUTING.md), [testing](testing.md), scoped PR/Git history. Each delivery must report applicable evidence and limitations; this is not a claim that every historical commit has a complete receipt. |
| R22 | Fifteen deliverables, architecture review answers, twenty failure cases and capacity at 100/1,000/10,000 monitors | Deliverable coverage below; [architecture answers and twenty scenarios](architecture/system-design.md), [capacity protocol](testing/capacity.md). Large-scale results remain unverified unless accompanied by a measured run; arithmetic projections are labeled separately. |
| R23 | Distributed scheduler, Redis/Kafka, multi-region, K8s, public status, email/webhook, tracing | Future; outside the local release. Draft contracts do not imply support. |
| R24 | Build once, scan/attest, distribute one image on Docker Hub + GHCR | Verified for the named artifact only: [policy](releases/container-policy.md), [digest/source](releases/v0.1.0-evidence.md). A future build needs fresh acceptance. |

## Fifteen-deliverable coverage

These are coverage references, not a blanket acceptance verdict. A protocol,
procedure or historical release record cannot fill a missing runtime receipt.

| Deliverable | Current owner | Coverage / remaining boundary |
| --- | --- | --- |
| D01 Executive overview | [Root README](../README.md) and this scope brief | Present. |
| D02 Requirements | This page and [business rules](business-rules.md) | Implemented/operator/unverified/future distinguished. |
| D03 Architecture and decisions | [System design](architecture/system-design.md) and [engine](engine-lifecycle.md) | Rationale and review answers present; distributed deployment is future. |
| D04 Database design | [Database](architecture/database.md) and [migrations](../migrations/) | Schema and invariant owners present; real rollout/rollback needs operator evidence. |
| D05 REST/OpenAPI | [API contract](api/openapi.yaml) | Implemented routes separated from future drafts; contract gate owns parity. |
| D06 Monitoring engine | [Lifecycle](engine-lifecycle.md) | Ownership, reservation, finalization, failure and shutdown contract. |
| D07 States/incidents | [Business decisions](business-rules.md#observations-and-incident-decisions) | Threshold, exclusion and administrative-closure rules with regressions. |
| D08 Security | [Trust boundaries](architecture/system-design.md#trust-boundaries), [SSRF](security/ssrf-boundary.md), [RBAC](security/rbac-matrix.md) | Controls and residual authority boundaries documented; no global production-security claim. |
| D09 Alerting | [Notification runbook](runbooks/notification-delivery.md) | Durable retry/causal/recovery contract; real Telegram delivery needs provider evidence. |
| D10 Testing | [Testing](testing.md) and [frontend](testing/frontend.md) | Executable checks and proof boundaries; check exact commit/run before claiming PASS. |
| D11 DevOps | [Database](runbooks/local-database.md), [CI](../.github/workflows/ci.yml), [deployment](README.md#operations) | Local procedures present; hosted rollout remains unverified. |
| D12 Detailed scoped changes | [Contributing](../CONTRIBUTING.md) and PR/Git history | Per-delivery process obligation; historical completeness is not assumed. |
| D13 Learning route | [Learning/review route](architecture/system-design.md#learning-and-review-route) | User journey → domain rules → API/schema → engine/delivery/statistics → explicit test oracles. |
| D14 Risks/trade-offs | [Architecture questions and twenty failures](architecture/system-design.md), [capacity](testing/capacity.md) | Analysis/protocol present; measured scale evidence is separate. |
| D15 Release readiness | [Acceptance](releases/local-acceptance.md), [release evidence](releases/v0.1.0-evidence.md), [media](media/manifest.json) | Existing image has its own source identity; current-source or hosted acceptance cannot be inferred from it. |

## Operating constraints

Advanced administration belongs to the implemented scope. Distributed scheduling
and additional notification providers remain future work. Browser users cannot
write Telegram credentials or destinations; an operator verifies the recipient.

Sampling gaps remain visible; no profile may bypass outbound policy.
Profiles/defaults belong to [configuration](../internal/config/config.go) and
[.env.example](../.env.example). Live per-user quota is server-controlled.

Hosted rollout follows local acceptance and requires operator decisions for
provider accounts, secrets, key backup, restore and external checks. Paid
services and automatic upgrades are outside the current scope. Use
[capacity](testing/capacity.md) before raising quotas and
[backup/restore](runbooks/backup-restore.md) before operating durable data.

The repo is [MIT licensed](../LICENSE). Publication proves distribution of a
named artifact, not hosted operation, real-recipient delivery or inclusion of
later source changes.
