# Uptime Monitoring Platform

A personal Go backend engineering project planned around secure uptime checks, incident alerting, advanced administration, and a polished React dashboard.

**Status: early implementation — foundation phase.** The application is under active development and has not been deployed. Feature descriptions below are planned scope; only what has verifiable evidence is claimed.

## Start here

- [Product requirements and scope traceability](docs/product-requirements.md): Must/non-goal scope, R01–R24 to phase and gate mapping.
- [Master implementation plan](plans/261021-1505-uptime-platform-master/plan.md): 11 phases and 93 focused learning commits.
- [Documentation index](docs/README.md): database, API, security, UI/UX, verification and operations.
- [Mentor workflow in Vietnamese](plans/261021-1505-uptime-platform-master/specs/12-learning-mentor-commits.md): one commit at a time, with exercises, review and knowledge checks.
- [Current planning/execution ledger](plans/261021-1505-uptime-platform-master/reports/execution-ledger.md).

## Planned product

Users manage public HTTP(S) monitors, inspect sampled availability and coverage, follow incidents, and receive verified Telegram notifications. Platform administrators have explicit permissions for accounts, sessions, quotas, operational health, roles and audit history.

The backend uses Go, PostgreSQL, bounded scheduling/workers, connection-bound SSRF protection and transactional incident/outbox updates. The frontend uses React and TypeScript, with a Stitch design handoff, responsive User/Admin screens and accessible data views.

Development and acceptance happen locally first. Container distribution to Docker Hub and GitHub Container Registry follows the local gate. Vercel, Render and a free PostgreSQL provider are the planned hosting targets, subject to current free-tier and runtime checks.

## Evidence and release

No runtime, CI, benchmark, screenshot, GIF, container publication or hosted result is claimed yet. The plan specifies how those artifacts will be captured and verified before the final repository presentation and GitHub About update.

The initial learning target is 12–16 weeks at 10–15 hours per week. The expanded full scope is estimated separately in the plan; advanced Admin and security are retained as required work.

License and public release metadata will be selected by the repository owner at the release checkpoint.
