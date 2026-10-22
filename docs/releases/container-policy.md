# Container distribution policy (C83)

Status: contract frozen at local-acceptance `2503232`; publication gates
(C85+) consume this document. Nothing below is a claim that publication
happened — it defines what must be true before it may.

## 1. Registry identities

| Registry | Image reference | Entitlement at checkpoint (2026-10-22) |
| --- | --- | --- |
| GHCR | `ghcr.io/jasontm17/uptime-monitoring-platform` | READY — account `JasonTM17`, repo `JasonTM17/Uptime-Monitoring-Platform` PUBLIC, token scopes `write:packages`, `delete:packages`, `workflow`, `repo` |
| Docker Hub | `<namespace>/uptime-monitoring-platform` | **BLOCKED — user action required.** `hub.docker.com/v2/users/{JasonTM17,jasontm17}` → 404: no account under the GitHub username. The namespace is read from the real account, never inferred. User must create/choose the account and provide `DOCKERHUB_USERNAME` (variable) + `DOCKERHUB_TOKEN` (secret). |

GitHub Packages source association uses the OCI
`org.opencontainers.image.source` label → `JasonTM17/Uptime-Monitoring-Platform`.
A public source repo does not imply a public GHCR package — package
visibility is verified separately (C86).

## 2. License prerequisite

The repository currently has **no LICENSE** (`licenseInfo: null`). A
public release without a license grants no rights to consumers; the
release step is blocked until the owner chooses one (a permissive license
such as MIT is the natural default for this learning portfolio — the
choice itself is the owner's). `org.opencontainers.image.licenses` is
populated only after that decision.

## 3. Tag and identity contract

- Immutable identity is the **digest** (`image@sha256:…`), never a tag.
- Release tags: exact semver `v<semver>` (candidate `v0.1.0-rc.1` first)
  plus `sha-<short-sha>` trace tag.
- `latest` is published only when BOTH registries succeed on the same
  digest; never on a partial result, never as rollback identity.
- One build produces the artifact consumed by both registries — no
  per-registry rebuild. Remote identities are compared by index/config/
  layer digests per platform.
- Baseline platform `linux/amd64` only; arm64 requires its own
  build+smoke evidence before it is claimed.

Required OCI labels (all set at build, never from secrets):
`source` (GitHub repo URL), `revision` (exact source SHA), `version`,
`created`, `title`, `description`, `licenses` (after license choice),
`url`. No local paths, usernames, or credentials in labels/args/history.

## 4. Pre-publish gates (order enforced)

1. Local acceptance PASS at the exact source SHA (C82 evidence).
2. Effective build-context privacy gate (`check-build-context.mjs`)
   before any builder receives the context — receipt binds source +
   Dockerfile + filter + context hashes.
3. One-build artifact: `scripts/build-release-image.mjs` → OCI archive +
   manifest (schema in §7).
4. SBOM + BuildKit provenance (`mode=max` capability-permitting), same
   subject digest; vulnerability scan with pinned tool + recorded DB
   timestamp. High/critical findings are waived only via recorded
   exception (CVE + impact + owner + expiry) — never silently.
5. Image smoke: non-root UID, read-only rootfs, SIGTERM deadline,
   CA-chain outbound, `/health/live` DB-free, `/health/ready` post-migrate.
6. Only then: authenticated publish, remote inspect, package
   association/visibility (C86), fresh **anonymous** pull + run in a
   disposable world (C87).

## 5. CI trust boundary (C85 contract)

- Trigger: protected release tag or manual dispatch on a reviewed ref.
  `pull_request` (especially forks) never receives publish secrets.
- Default `permissions: contents: read`. The GHCR publish job adds
  `packages: write`; the Docker Hub job uses `DOCKERHUB_TOKEN` secret +
  `DOCKERHUB_USERNAME` variable. No broad PAT if `GITHUB_TOKEN` suffices.
- Actions pinned by full commit SHA (mutable major tags are not pins).
- `concurrency` serializes per image+release; in-flight publishes are
  not cancelled mid-write.
- Partial failure: `PARTIAL` is recorded, retry reuses the same digest —
  the same tag never points at different bytes. Docs/`latest` follow
  full dual success only.
- No private plans/reviews/raw context manifest in CI artifacts, logs,
  cache, provenance, or uploaded context. Public-history preparation is
  a separate owner-authorized prerequisite — never an autonomous
  rewrite/push.

## 6. Required secrets (names only — presence check, never values)

| Name | Kind | Purpose |
| --- | --- | --- |
| `GITHUB_TOKEN` | built-in | GHCR `packages: write` (job-scoped) |
| `DOCKERHUB_USERNAME` | Actions variable | Hub namespace identity |
| `DOCKERHUB_TOKEN` | Actions secret | Hub publish, repository-scoped PAT |

Missing required secret → workflow fails **before** any mutation.

## 7. Registry manifest schema (evidence artifact)

`artifacts/release/image-manifest.json` — produced by the C84 build
wrapper, consumed by verifier + publisher:

```json
{
  "format": "uptime-release-manifest-v1",
  "version": "v0.1.0-rc.1",
  "source_sha": "<full git SHA>",
  "source_dirty": false,
  "built_at": "<UTC ISO>",
  "platform": "linux/amd64",
  "image": {
    "reference": "uptime-platform:v0.1.0-rc.1",
    "index_digest": "sha256:…",
    "config_digest": "sha256:…",
    "layer_digests": ["sha256:…"],
    "archive": "artifacts/release/uptime-platform-v0.1.0-rc.1.oci",
    "archive_sha256": "…"
  },
  "base": {"image": "…", "digest": "sha256:…"},
  "labels": {"org.opencontainers.image.revision": "<source_sha>"},
  "sbom": {"format": "spdx-json", "path": "…", "subject_digest": "sha256:…"},
  "provenance": {"mode": "max", "path": "…", "subject_digest": "sha256:…"},
  "scan": {"tool": "…", "tool_version": "…", "db_timestamp": "…",
           "critical": 0, "high": 0, "exceptions": []},
  "context_receipt": "artifacts/build/context-manifest.json",
  "registries": {
    "ghcr": "ghcr.io/jasontm17/uptime-monitoring-platform",
    "dockerhub": "<pending — user namespace>"
  }
}
```

## 8. Retention / rollback

Keep current + 2 previous release digests per registry where free quota
allows. Deletion only of unreferenced pre-release images, allowlisted,
after read-back — never bulk package deletes. Rollback identity is a
digest, not a tag.

## 9. Receipts and reporting

Every external step writes a public-safe receipt: UTC, actor identity,
registry URL, tag→digest resolution, conclusion. No tokens, cookies, or
`Authorization` headers are recorded anywhere.
