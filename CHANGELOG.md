# Changelog

All notable changes to this project are documented here. Dates are UTC.

## [0.1.0-rc.1] — 2026-10-26 — release candidate

The first complete candidate: the full product runs against the composed
harness with evidence-backed gates. The MIT license is committed. The
container image is published to Docker Hub; GHCR publication is pushed
and is public (not yet linked to the repository). Hosted deployment
is not included. Registry digests are recorded in
`docs/releases/v0.1.0-evidence.md`.

### Implemented

- **Identity & sessions** — registration, login, opaque server-side
  sessions with revocation, CSRF double-submit, rate limiting, re-auth
  for privileged operations.
- **Monitor APIs** — owned CRUD with generation-checked mutations,
  notification-channel binding, pause/resume, owner-scoped queries.
- **SSRF-safe checker** — DNS resolution classification (blocked
  private/reserved ranges), validated-dial transport, no redirect
  following, bounded body read, sanitized error enums.
- **Monitoring engine** — bounded scheduler and worker pool,
  durable run reservations, single-writer owner fencing via advisory
  lock + dedicated connection, backpressure admission, interrupted-run
  reconciliation, graceful SIGTERM drain.
- **Incidents & delivery** — threshold-based incident lifecycle,
  transactional outbox, lease-based dispatcher with retry/dead states,
  Telegram channel with operator-verified destinations.
- **Statistics** — sampled uptime/coverage, hourly aggregation,
  honest partial-window labeling, retention with raw purge.
- **Admin backend** — RBAC permission catalog with bounded custom
  roles, append-only audit history, administrative recovery, account
  suspend/restore, session/quota administration, operational monitor
  actions, health/query APIs, privilege-epoch revocation.
- **React UI** — authenticated shell; dashboard; monitor list/detail
  with charts; incidents; channels; settings/sessions; admin overview,
  users, roles, monitors, operations, outbox, audit; responsive and
  accessibility-verified states.
- **Observability** — version/revision metadata, Prometheus metrics,
  health/readiness endpoints, goroutine/worker/queue/owner gauges.
- **Tooling** — deterministic compose harness, acceptance driver,
  capacity measurement, restore drill, release-image builder/verifier,
  publication planner, hosted-candidate trust verifier, portfolio
  media capture, docs privacy/release checks.

### Verified evidence (local)

- `go test` unit + `-race` suites: PASS.
- Integration suites (per-package lanes): PASS.
- Browser acceptance: 8 journeys × desktop+mobile viewports: PASS.
- 30-minute capacity protocol (100 monitors): PASS, honest overload
  signature recorded.
- Restore drill: seed → dump → restore → reconcile → verify: PASS.
- Release image: one-build distroless artifact with SBOM/provenance
  attestations, Trivy + govulncheck scans (no critical/high),
  self-contained smoke, OCI digest-chain verification: PASS.
- Privacy gate over public docs/media: PASS.

### Release and deployment status

- The release image is public on Docker Hub and GHCR. Both registries resolve
  to the same OCI index digest; see
  [release evidence](docs/releases/v0.1.0-evidence.md) for the full digest.
- GHCR visibility, repository association, and anonymous pulls are verified;
  the evidence page records the matching digest and verification details.
- Hosted deployment on Vercel, Render, or Supabase is **NOT_RUN**.
