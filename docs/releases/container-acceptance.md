# Container distribution acceptance gate

Status: **MECHANISM COMPLETE / PUBLISHED + ANONYMOUSLY VERIFIED ON BOTH REGISTRIES — GHCR repository association outstanding** (updated 2026-10-26)

This document is the distribution-acceptance receipt for Phase 10. It
records what is proven locally and exactly which checks remain blocked
by unresolved prerequisites — nothing here is claimed as published.

## Verified mechanism (local, evidence-backed)

| Check | Evidence |
| --- | --- |
| One-build artifact | Single `buildx` invocation → daemon image + OCI-layout archive; daemon `Id` asserted `==` manifest-list digest `sha256:ef68a0c7…` (same build, not assumed) |
| Attestation-preserving transport | OCI archive carries index → manifest list → {image manifest `30b89e2c…`, attestation `a0bacfea…`}; `docker save` rejected as parity path |
| OCI digest-chain verification | `verify-container-release.mjs --stage local` recomputes every blob hash: index→list→image+attestation→config→all 13 layers — PASS |
| Context privacy gate | Deny-by-default receipt `00c5d9d2cc175fde…` ran before the builder received the context |
| Vulnerability scan | `aquasec/trivy:0.76.0` (pinned; DB `updatedAt=2026-10-22T01:15:55Z` schema 2): **CRITICAL=0, HIGH=0** on OS + Go binary |
| Source/binary scan | `govulncheck v1.1.4` binary mode: 1 advisory `GO-2026-5932` (openpgp unmaintained) — counter-evidence: 0 openpgp packages in `cmd/api` import closure, 0 openpgp strings in shipped binary; recorded as advisory, not waived silently. Source mode NOT_RUN: x/tools SSA panics on this toolchain's AST (limitation recorded) |
| Runtime smoke | Disposable `postgres:17.11` + `migrate/migrate:v4.20.1` + app on scratch network; `/health/ready` 200; SIGTERM stop 0.49s; UID `65532:65532`; read-only/cap-drop/no-new-privileges mirrored |
| In-image canary | 0 host-path strings (`C:\`, `/home/`, `/root/`, `Users\Admin`) — `-trimpath` effective |
| Publish mechanism | `publish-release-image.mjs`: remote-contract gate refuses pre-prerequisite manifests; creds via ephemeral authfile (never argv/logs); tags `[version, sha-<12>]` never `latest`; PARTIAL on one-registry success; receipts per registry |
| Anonymous-pull mechanism | `--anonymous` stage: fresh empty `docker --config <tmp>` (scrubbed after), digest-form pulls `<ref>@<index_digest>` from verified receipts, disposable pg+migrate+app smoke on pulled content, every resolved command recorded. Proven against a public image: `docker --config <empty> pull postgres:17.11@sha256:b8faeff…` — credential-free digest pull works |
| Remote readback mechanism | `--stage remote`: `gh api` package existence/association/visibility + `imagetools` digest parity (GHCR); anonymous `hub.docker.com` REST (Docker Hub) |

## Honestly FAILing gates (not waived)

Live remote run `verification-anon.json` — verdict **FAIL** with real
API calls behind each:

1. `manifest-contract` — `license_status: pending-user-decision`
   (remote publish requires `resolved:<spdx>`); Docker Hub namespace
   `pending-user-namespace`.
2. `ghcr-package` — `gh api users/JasonTM17/packages` returned 30 real
   packages on the account; `uptime-monitoring-platform` genuinely
   absent (readback path proven, not a silent error).
3. `dockerhub-package` — namespace unresolved (the container policy prerequisite).
4. `receipts-present` — no publication receipts; the the publication workflow trusted run
   has not executed.

## Prerequisites — resolved (2026-10-26)

- **License**: MIT is committed (`LICENSE`); release manifests report
  `resolved:MIT` (see `container-policy.md`).
- **Docker Hub**: owner-confirmed destination
  `nguyenson1710/uptime-monitoring-platform`; `DOCKERHUB_USERNAME` and
  `DOCKERHUB_NAMESPACE` are repository variables and `DOCKERHUB_TOKEN` a
  repository secret.
- **User authority**: external publication was explicitly authorized.
- **Remaining gap**: the GHCR package is public and anonymous digest
  pulls + ready-200 smokes pass on both registries, but the package→
  repository association is still `null`. The image carries the
  `org.opencontainers.image.source` label; GitHub package settings
  showed no connect-repository control, so the link may need a
  `GITHUB_TOKEN`-driven publish from the repository workflow.

## What remains after prerequisites

1. `gh workflow run container-release.yml --ref <reviewed tag>` —
   one trusted run publishes the verified artifact to both registries.
2. `--stage remote` readback flips to PASS when package association,
   visibility, and digest parity are observed (the package readback).
3. `--anonymous` stage flips to PASS when both digest pulls + smoke
   succeed under the empty config, including the rollback-digest step
   once ≥1 retained prior digest exists.
4. `:latest` may only be tagged after a dual-registry PASS.
