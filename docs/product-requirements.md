# Product requirements and scope traceability

This document is the self-contained scope brief for the application. It states
what the platform must do, what it must not do, and where each requirement is
verified. It intentionally does not reproduce or link the project's private
planning artifacts; requirement IDs below are the stable public references.

Status: accepted scope, implementation in progress. Statements below are
requirements and design commitments, not claims that behavior already exists.

## Product summary

A self-hosted uptime monitoring platform for individuals. Users register public
HTTP(S) monitors, inspect availability samples and honest coverage, follow
incidents, and receive verified Telegram alert/recovery notifications. Platform
administrators hold explicit permissions for accounts, sessions, quotas,
operational health, roles, and audit history.

Stack commitment: Go (`net/http` + chi, pgx, PostgreSQL) modular monolith,
React/Vite/TypeScript/Tailwind dashboard. Local-first: cloud deployment happens
only after the local acceptance gate passes.

## Must scope

- R01–R22 and R24 are required for the full scope. Advanced Admin is required
  scope; it overrides the earlier advanced-RBAC non-goal and is never
  silently demoted to stretch work.
- R19 (free cloud deployment) executes only after R18 (local acceptance).
- R23 (distributed scheduler, Redis/Kafka, multi-region, Kubernetes, public
  status page, email/webhook, OpenTelemetry) stays future roadmap and does not
  block the local release.

## Non-goals

- No paid services, no automatic upgrades, no spending without an explicit
  user decision.
- No public writable demo with admin privileges before anti-abuse and
  permission gates exist.
- No claims of uptime percentages, CI runs, container publication, or hosted
  URLs before the corresponding evidence exists.
- No weakening of security or Admin scope to meet a date; the forecast moves
  instead.

## Requirement traceability (R → phase → gate)

| Req | Requirement (summary) | Producing phase | Verified at |
|---|---|---|---|
| R01 | Register/login/logout/me, revocable sessions, password hashing | Phase 02 | Phase 02 exit gate |
| R02 | Ownership isolation for monitors/history/incidents/channels; IDOR negatives | Phases 02–03 | Phase 02/03 exit gates |
| R03 | Monitor CRUD/pause/resume, quotas, pagination, request limits, error contract | Phase 03 | Phase 03 exit gate |
| R04 | Public HTTP GET checker, 2xx default + validated expected policy, bounded | Phase 04 | Phase 04 exit gate |
| R05 | SSRF protection at actual dial (DNS/IP/rebinding/proxy/no bypass) | Phase 04 | Phase 04 exit gate |
| R06 | Single-owner scheduler, bounded workers/queue, durable schedule, fairness | Phase 05 | Phase 05 exit gate |
| R07 | State machine thresholds; PAUSED separate from scheduling; no false DOWN | Phase 05 | Phase 05 exit gate |
| R08 | Atomic result/state/incident/outbox; idempotency; stale-write fences | Phases 05–06 | Phase 05/06 exit gates |
| R09 | Telegram channels, transactional outbox, retry/dead state, honest ordering | Phase 06 | Phase 06 exit gate |
| R10 | History/stats 24h/7d/30d, transparent denominators, missing data, retention | Phase 06 | Phase 06 exit gate |
| R11 | Professional FE: auth/dashboard/monitor detail/charts/incidents/settings | Phase 08 | Phase 08 exit gate |
| R12 | Advanced Admin: multi-level RBAC, global ops dashboard, account/session/quota | Phase 07 | Phase 07 exit gate |
| R13 | Privileged actions: audit, least privilege, race tests, last-super-admin | Phase 07 | Phase 07 exit gate |
| R14 | Admin UI: users/roles/monitors/engine pulse/audit, permission-denied flows | Phase 08 | Phase 08 exit gate |
| R15 | Docker Compose on Windows/Linux, migrations/seed, deterministic local demo | Phases 01, 09 | Phase 01/09 exit gates |
| R16 | Unit/integration/browser/security/race/recovery tests; early CI; budgets | Phase 01 + all | Phase 01 baseline + per-phase gates |
| R17 | Structured logs/correlation/metrics/health; no secrets or high-cardinality | Phases 01, 09 | Phase 01/09 exit gates |
| R18 | Local acceptance before any cloud work | Phase 09 | Hard gate before Phases 10–11 |
| R19 | Free deployment: Vercel FE + Render Go + free PostgreSQL, external uptime | Phase 11 | Phase 11 gate, after R18 |
| R20 | GitHub About/README/API/ERD/ADRs/runbooks/screenshots/GIF/release evidence | Phase 11 | Phase 11 exit gate |
| R21 | Per-commit contract (scope/steps/tests/verification/mistakes/review/DoD) | All phases | Every commit review |
| R22 | 15 deliverables, architecture review answers, 20 failures, capacity 100/1k/10k | Phases 09–11 | Phase 09/11 exit gates |
| R23 | Distributed scheduler/Redis/multi-region/K8s/email/webhook/OTel | Future roadmap | Not gated in this release |
| R24 | Build once, scan/attest, publish same artifact to Docker Hub + GHCR | Phase 10 | Phase 10 gate, after R18 |

## 15 deliverables

| Deliverable | Produced by |
|---|---|
| D01 Executive overview | Root README + this document |
| D02 Requirements | This document + traceability table above |
| D03 Architecture | docs architecture/ADR surfaces (Phase 09+) |
| D04 Database design | docs database surfaces + migrations (Phase 09+) |
| D05 REST/OpenAPI | Published OpenAPI contract (Phases 03, 09) |
| D06 Monitoring engine design | Engine docs + code (Phases 05, 09) |
| D07 State/incidents | State model docs + tests (Phases 05–06) |
| D08 Security | Threat model, RBAC matrix, security tests (Phases 04, 07, 09) |
| D09 Alerting | Outbox/Telegram delivery docs + evidence (Phase 06) |
| D10 Testing | Test plan, budgets, and gate receipts (Phase 01 + all) |
| D11 DevOps | Compose/CI/runbooks/hosting notes (Phases 01, 09–11) |
| D12 Detailed commits | Scoped conventional commits per card |
| D13 Learning roadmap | Per-commit knowledge checks and explanations |
| D14 Risks/trade-offs | Failure/capacity analysis (Phase 09+) |
| D15 Release readiness | Acceptance matrix, media, About, release bundle (Phase 11) |

## Two profiles, one correctness rule

| Attribute | Local lab | Hosted free demo (after local gate) |
|---|---|---|
| Design capacity target | 100 non-deleted monitors, >=60s interval | Starts at 10; server-side quota enforced |
| Raw retention | 30 days (disk permitting) | 24h raw + 30d hourly rollups |
| Concurrency | 10 workers target, capped queue | Reduced to measured baseline |
| Public access | Full registration in learning environment | Invite-only proposed |
| Security | Production policy for checker | Same policy; server-side secrets only |

These are configuration profiles, not two codebases. No profile may relax the
URL/internal-network policy. Quotas increase only after measurement.

## Time forecast and open decisions

Full scope estimate: 252–337 hours plus ~20% contingency (roughly 302–404
hours). At 10–15 hours/week that is approximately 20–41 weeks. The initial
12–16 week target is a progress-review checkpoint, not a promise; weeks 4/8/12
re-forecast from actual hours.

Open decisions owned by the user at their checkpoints: free domain/provider
accounts, license selection (MIT proposed), Telegram recipient and key backup,
external uptime keepalive choice, and any future public-history or publication
authorization.
