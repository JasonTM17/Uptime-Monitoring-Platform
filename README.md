# Uptime Monitoring Platform

[![CI](https://github.com/JasonTM17/Uptime-Monitoring-Platform/actions/workflows/ci.yml/badge.svg)](https://github.com/JasonTM17/Uptime-Monitoring-Platform/actions/workflows/ci.yml)
[![Go 1.27](https://img.shields.io/badge/go-1.27-00ADD8?logo=go&logoColor=white)](docs/toolchain.md)
[![PostgreSQL 17](https://img.shields.io/badge/postgresql-17-336791?logo=postgresql&logoColor=white)](docs/toolchain.md)
[![React + TypeScript](https://img.shields.io/badge/react-typescript-61DAFB?logo=react&logoColor=white)](web/)

A personal Go backend engineering project built around secure uptime checks, incident alerting, advanced administration, and a polished React dashboard.

Release requirements and verified distribution records are maintained separately in the release documentation linked below.

## Start here

- [Product requirements and scope](docs/product-requirements.md): user-facing requirements and non-goals.
- [Documentation index](docs/README.md): toolchain, runbooks, testing and operations docs.
- [Toolchain pins](docs/toolchain.md) and the [local database runbook](docs/runbooks/local-database.md).
- [Container release policy](docs/releases/container-policy.md) and [release evidence](docs/releases/v0.1.0-evidence.md).

## Repository layout

| Path | Responsibility |
|---|---|
| `cmd/` | API application entry point |
| `internal/` | Backend domains, services, persistence, and adapters |
| `web/` | React and TypeScript dashboard |
| `migrations/` | PostgreSQL schema migrations |
| `docs/` | Product, API, architecture, testing, security, and operations documentation |
| `scripts/` | Local checks, acceptance tooling, and release automation |
| `tools/` | API contract and repository support tools |

## Product overview

Users manage public HTTP(S) monitors, inspect sampled availability and coverage, follow incidents, and receive verified Telegram notifications. Platform administrators have explicit permissions for accounts, sessions, quotas, operational health, roles and audit history.

The backend uses Go, PostgreSQL, bounded scheduling/workers, connection-bound SSRF protection and transactional incident/outbox updates. The frontend uses React and TypeScript, with a Stitch design handoff, responsive User/Admin screens and accessible data views.

Use the guides in [`docs/`](docs/README.md) for setup, testing, and operations. Container distribution requirements are defined in the release policy; registry identities are recorded only after verification.

## Screenshots and demo

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

## Release and license

The project is licensed under [MIT](LICENSE). See the [container release policy](docs/releases/container-policy.md) for distribution requirements and the [release evidence page](docs/releases/v0.1.0-evidence.md) for verified registry identities. Hosted deployment guides cover [Render](docs/deployment/render.md), [Vercel](docs/deployment/vercel.md), and [Supabase](docs/deployment/supabase.md).
