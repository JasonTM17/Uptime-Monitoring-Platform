# Container distribution policy

This document defines the gates and identities required for container distribution. It does not claim that publication or hosted deployment has happened. Local build, test, and credential evidence is kept out of this public policy.

## 1. Registry identities

| Registry | Image reference | Publication contract |
| --- | --- | --- |
| GHCR | `ghcr.io/jasontm17/uptime-monitoring-platform` | Publish with job-scoped `packages: write`; verify package visibility and source association after publication. |
| Docker Hub | `<owner>/<repository>` | Requires explicit owner confirmation. Configure `DOCKERHUB_USERNAME` and the full-image-reference `DOCKERHUB_NAMESPACE` as repository variables plus `DOCKERHUB_TOKEN` as a repository secret. Never infer a destination from the GitHub account or a public profile. |

GitHub Packages source association uses the OCI
`org.opencontainers.image.source` label → `JasonTM17/Uptime-Monitoring-Platform`.
A public source repo does not imply a public GHCR package — package
visibility is verified separately (the package readback).

## 2. License status

The repository includes an MIT `LICENSE`. The release manifest must report `resolved:MIT`, and the OCI license label must match the committed license. The verifier blocks remote publication if the committed license cannot be resolved.

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
`created`, `title`, `description`, `licenses` (`MIT`), and `url`. No local
paths, usernames, or credentials in labels/args/history.

## 4. Pre-publish gates (order enforced)

1. Local acceptance PASS at the exact source SHA (the local acceptance gate evidence).
2. Effective build-context privacy gate (`check-build-context.mjs`)
   before any builder receives the context — receipt binds source +
   Dockerfile + filter + context hashes.
3. One-build artifact: `scripts/build-release-image.mjs` → OCI archive +
   manifest (schema in §7). The builder rejects dirty release inputs and
   archives the recorded Git commit once; the image build and Go scanner
   consume the same captured archive bytes. Migrations use the extracted
   snapshot, whose context hash is rechecked before and after migration; smoke
   probe compilation also consumes the captured archive bytes.
   The verifier replays the committed source through the context gate and
   compares it with a minimized `context-proof.json` containing only source
   SHA and context hash; the raw file inventory stays local.
4. SBOM + BuildKit provenance (`mode=max` capability-permitting), same
   subject digest; vulnerability scan with pinned tool + recorded DB
   timestamp. High/critical findings are waived only via recorded
   exception (CVE + impact + owner + expiry) — never silently.
   Go reachability uses pinned `govulncheck v1.1.4` binary mode on a
   symbol-preserving companion built from the same source SHA, version, and
   platform as the stripped runtime image, using the same digest-pinned Go
   builder image as the runtime build. The release artifact retains the
   companion binary. Local and remote verification recompute its SHA-256 and
   confirm the embedded source SHA and version. The manifest binds that
   digest to the runtime image and context hash; missing artifacts, a wrong
   tool version, mismatched evidence, or nonzero scanner exit fails the gate.
   Module-only advisory output remains visible in the scanner summary.
5. Image smoke: non-root UID, read-only rootfs, all Linux capabilities
   dropped, `no-new-privileges`, and SIGTERM deadline. After migration,
   `/health/ready` must return 200. Then stop the disposable PostgreSQL
   service and prove `/health/ready` fails while `/health/live` remains
   200. Finally run a read-only HTTPS GET to
   `https://github.com/JasonTM17/Uptime-Monitoring-Platform` from inside
   the exact app image; require a verified certificate chain and a 2xx/3xx
   response. This specifically tests the final image's system CA bundle,
   DNS, and outbound path. If that public endpoint or outbound network is
   unavailable, record the gate as failed/not-run; do not infer success
   from a host-side TLS check. The manifest records each result and the
   SHA-256 of the smoke helper and build script.
6. Only then: authenticated publish, remote inspect, package
   association/visibility (the package readback), fresh **anonymous** pull + run in a
   disposable world (the distribution acceptance).

## 5. CI trust boundary (the publication workflow contract)

- Trigger: protected release tag or manual dispatch on a reviewed ref.
  `pull_request` (especially forks) never receives publish secrets.
- Default `permissions: contents: read`. The GHCR publish job adds
  `packages: write` and uses `github.actor` with built-in `GITHUB_TOKEN`;
  the Docker Hub job uses `DOCKERHUB_TOKEN` secret plus the
  `DOCKERHUB_USERNAME` and full-image-reference `DOCKERHUB_NAMESPACE`
  variables. No repository `GHCR_USER` or `GHCR_TOKEN` secret is needed.
- Actions pinned by full commit SHA (mutable major tags are not pins).
- The `release-artifact` allowlist contains only the manifest, OCI archive,
  SBOM, provenance, retained `govulncheck-target`, and minimized
  `context-proof.json`; it excludes the raw context inventory and local
  verifier/build receipts.
- `concurrency` serializes per image+release; in-flight publishes are
  not cancelled mid-write.
- Partial failure: `PARTIAL` is recorded, retry reuses the same digest —
  the same tag never points at different bytes. Docs/`latest` follow
  full dual success only.
- No internal plan/review/raw context manifest in CI artifacts, logs,
  cache, provenance, or uploaded context. Public-history preparation is
  a separate owner-authorized prerequisite — never an autonomous
  rewrite/push.

## 6. Required settings (names only — presence check, never values)

| Name | Kind | Purpose |
| --- | --- | --- |
| `GITHUB_TOKEN` | built-in | GHCR `packages: write` (job-scoped) |
| `DOCKERHUB_USERNAME` | Actions variable | Hub login identity |
| `DOCKERHUB_NAMESPACE` | Actions variable | Exact `<owner>/<repository>` image reference |
| `DOCKERHUB_TOKEN` | Actions secret | Hub publish, repository-scoped PAT |

Missing required Docker Hub setting → workflow fails **before** build or registry mutation. The GHCR token comes from built-in `GITHUB_TOKEN` with job-scoped `packages: write`.

## 7. Registry manifest schema (evidence artifact)

`artifacts/release/image-manifest.json` — produced by the release build
wrapper and consumed by the verifier and publisher:

```json
{
  "format": "uptime-release-manifest-v1",
  "version": "v0.1.0-rc.1",
  "source_sha": "<full git SHA>",
  "source_dirty": false,
  "build_context_sha256": "sha256:…",
  "built_at": "<UTC ISO>",
  "platform": "linux/amd64",
  "image": {
    "reference": "uptime-platform:v0.1.0-rc.1",
    "index_digest": "sha256:…",
    "image_manifest_digest": "sha256:…",
    "config_digest": "sha256:…",
    "attestation_digest": "sha256:…",
    "layer_digests": ["sha256:…"],
    "archive": "artifacts/release/uptime-platform-v0.1.0-rc.1.oci.tar",
    "archive_sha256": "sha256:…"
  },
  "base": {"image": "…", "digest": "sha256:…"},
  "labels": {
    "org.opencontainers.image.source": "https://github.com/JasonTM17/Uptime-Monitoring-Platform",
    "org.opencontainers.image.revision": "<source_sha>",
    "org.opencontainers.image.version": "v0.1.0-rc.1",
    "org.opencontainers.image.created": "<UTC ISO>",
    "org.opencontainers.image.title": "uptime-platform-api",
    "org.opencontainers.image.description": "local-first uptime monitoring platform (release candidate)",
    "org.opencontainers.image.licenses": "MIT",
    "org.opencontainers.image.url": "https://github.com/JasonTM17/Uptime-Monitoring-Platform"
  },
  "license_status": "resolved:MIT",
  "sbom": {"format": "spdx-json", "path": "sbom.spdx.json",
           "subject_digest": "sha256:…"},
  "provenance": {"mode": "sidecar-json", "path": "provenance.json",
                 "subject_digest": "sha256:…"},
  "scan": {"image_scanner": {"tool": "…", "tool_version": "…",
           "db_timestamp": "…", "critical": 0, "high": 0,
           "findings": [], "exceptions": []},
            "source_scanner": {"tool": "govulncheck", "tool_version": "v1.1.4",
              "mode": "binary", "exit_code": 0,
             "target": {"kind": "source-matched-symbol-preserving-companion",
               "source_sha": "…", "version": "…", "platform": "linux/amd64",
               "build_context_sha256": "sha256:…",
                "runtime_image_digest": "sha256:…", "artifact": "govulncheck-target",
                "sha256": "sha256:…"},
             "findings_tail": "<scanner summary>"}},
  "smoke": {"ready_probe_200": true, "live_db_free": true,
            "ca_chain_outbound": true, "migrated_db": true,
            "nonroot_user": "65532:65532", "read_only_rootfs": true,
            "capabilities_dropped": true, "no_new_privileges": true,
            "sigterm_stop_s": 0.5,
            "build_script_sha256": "sha256:…",
            "tls_probe_sha256": "sha256:…"},
  "context_receipt_sha256": "sha256:<context-proof.json hash>",
  "registries": {
    "ghcr": "ghcr.io/jasontm17/uptime-monitoring-platform",
    "dockerhub": "pending-user-namespace"
  },
  "publishable": false
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
