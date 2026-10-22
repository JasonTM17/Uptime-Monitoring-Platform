# Uptime Monitoring Platform

A personal Go backend engineering project built around secure uptime checks, incident alerting, advanced administration, and a polished React dashboard.

**Status: local acceptance complete; external distribution pending.** The full product runs locally against the composed harness with evidence-backed gates. Container publication and hosted deployment are blocked on owner-side prerequisites (license choice, registry accounts/credentials, publication authority).

## Start here

- [Product requirements and scope traceability](docs/product-requirements.md): Must/non-goal scope, R01–R24 to phase and gate mapping.
- [Documentation index](docs/README.md): toolchain, runbooks, testing and operations docs.
- [Toolchain pins](docs/toolchain.md) and the [local database runbook](docs/runbooks/local-database.md).

A private, detailed implementation roadmap (11 phases, 93 focused commits)
lives in this workspace's local planning directory and is intentionally not
linked or published from public documentation.

## Planned product

Users manage public HTTP(S) monitors, inspect sampled availability and coverage, follow incidents, and receive verified Telegram notifications. Platform administrators have explicit permissions for accounts, sessions, quotas, operational health, roles and audit history.

The backend uses Go, PostgreSQL, bounded scheduling/workers, connection-bound SSRF protection and transactional incident/outbox updates. The frontend uses React and TypeScript, with a Stitch design handoff, responsive User/Admin screens and accessible data views.

Development and acceptance happen locally first. Container distribution to Docker Hub and GitHub Container Registry follows the local gate. Vercel, Render and a free PostgreSQL provider are the planned hosting targets, subject to current free-tier and runtime checks.

## Screenshots and demo

Captured from the real application running in the local deterministic
harness (`compose.test.yaml`): synthetic demo accounts, an isolated
fixture target, and the production-shaped UI — no mockups.

- Dashboard, monitor detail, and the new-monitor editor:
  [desktop](docs/media/screenshots/dashboard-desktop.png) ·
  [monitor detail](docs/media/screenshots/monitor-detail-desktop.png) ·
  [mobile editor](docs/media/screenshots/monitor-editor-mobile.png) ·
  [mobile dashboard](docs/media/screenshots/dashboard-mobile.png)
- Admin console — overview, user inventory, roles matrix, audit history:
  [overview](docs/media/screenshots/admin-overview-desktop.png) ·
  [users](docs/media/screenshots/admin-users-desktop.png) ·
  [roles](docs/media/screenshots/admin-roles-desktop.png) ·
  [audit](docs/media/screenshots/admin-audit-desktop.png) ·
  [mobile admin](docs/media/screenshots/admin-mobile.png) ·
  [empty/a11y state](docs/media/screenshots/states-and-accessibility.png)
- Recorded flows:
  [monitor incident → recovery](docs/media/monitor-incident-recovery.gif) ·
  [admin action → audit](docs/media/admin-role-and-audit.gif)
  ([transcripts](docs/media/), [provenance manifest](docs/media/manifest.json))

## Evidence and release

Runtime, CI, benchmark and local acceptance evidence exists under the
verification harness; container publication and hosted deployment remain
pending owner-side prerequisites (license, registry accounts/credentials,
publication authority). No hosted or published result is claimed.

The initial learning target is 12–16 weeks at 10–15 hours per week. The expanded full scope is estimated separately in the plan; advanced Admin and security are retained as required work.

License and public release metadata will be selected by the repository owner at the release checkpoint.
