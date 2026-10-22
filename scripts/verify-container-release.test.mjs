// C84 verifier contract tests — every reject case in the card's E
// section maps to a fixture below. Run: node --test scripts/verify-container-release.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { validateManifest } from "./verify-container-release.mjs";

const SHA = "a".repeat(64);
const base = () => ({
  format: "uptime-release-manifest-v1",
  version: "v0.1.0-rc.1",
  source_sha: "b".repeat(40),
  source_dirty: false,
  built_at: "2026-10-22T00:00:00Z",
  platform: "linux/amd64",
  image: {
    reference: "uptime-platform:v0.1.0-rc.1",
    index_digest: `sha256:${SHA}`,
    image_manifest_digest: `sha256:${SHA}`,
    config_digest: `sha256:${SHA}`,
    attestation_digest: `sha256:${SHA}`,
    layer_digests: [`sha256:${SHA}`],
    archive: "artifacts/release/x.oci.tar",
    archive_sha256: `sha256:${SHA}`,
  },
  base: { image: "gcr.io/distroless/static-debian12:nonroot", digest: `sha256:${SHA}` },
  labels: {
    "org.opencontainers.image.source": "https://github.com/JasonTM17/Uptime-Monitoring-Platform",
    "org.opencontainers.image.revision": "b".repeat(40),
    "org.opencontainers.image.version": "v0.1.0-rc.1",
  },
  license_status: "resolved:MIT",
  sbom: { format: "spdx-json", path: "sbom.spdx.json", subject_digest: `sha256:${SHA}` },
  provenance: { mode: "sidecar-json", path: "provenance.json", subject_digest: `sha256:${SHA}` },
  scan: { image_scanner: { tool: "trivy", tool_version: "0.76.0",
    db_timestamp: "2026-10-22", critical: 0, high: 0, exceptions: [] } },
  smoke: { ready_probe_200: true, sigterm_stop_s: 0.5, migrated_db: true, nonroot_user: "65532:65532" },
  context_receipt: "artifacts/build/context-manifest.json",
  registries: { ghcr: "ghcr.io/jasontm17/uptime-monitoring-platform",
    dockerhub: "jasontm17/uptime-monitoring-platform" },
  publishable: true,
});

const rejects = (mut, stage) => { const m = base(); mut(m); return validateManifest(m, { stage }); };

test("TestRejectSubjectMismatch", () => {
  const errs = rejects((m) => { m.sbom.subject_digest = `sha256:${"c".repeat(64)}`; });
  assert.ok(errs.some((e) => /subject/.test(e)), errs.join("|"));
});

test("TestRejectMissingPlatform", () => {
  const errs = rejects((m) => { m.platform = "linux/arm64"; });
  assert.ok(errs.some((e) => /platform/.test(e)), errs.join("|"));
});

test("TestRejectCriticalFinding", () => {
  const errs = rejects((m) => { m.scan.image_scanner.critical = 2; });
  assert.ok(errs.some((e) => /CRITICAL/.test(e)), errs.join("|"));
});

test("TestRejectCriticalWaivedProperly", () => {
  const errs = rejects((m) => {
    m.scan.image_scanner.critical = 1;
    m.scan.image_scanner.exceptions = [{ cve: "CVE-2026-0001", owner: "ops", expiry: "2027-01-01" }];
  });
  assert.ok(!errs.some((e) => /CRITICAL/.test(e)), errs.join("|"));
});

test("TestRejectSecretBuildArg", () => {
  const errs = rejects((m) => { m.build_args = { TELEGRAM_BOT_TOKEN: "x".repeat(30) }; });
  assert.ok(errs.some((e) => /secret/.test(e)), errs.join("|"));
});

test("TestRejectMalformedNamespace", () => {
  const errs = rejects((m) => { m.registries.ghcr = "ghcr.io/JasonTM17/UPTIME!!"; });
  assert.ok(errs.some((e) => /ghcr/.test(e)), errs.join("|"));
});

test("TestRejectWrongSourceLabel", () => {
  const errs = rejects((m) => { m.labels["org.opencontainers.image.source"] = "local"; });
  assert.ok(errs.some((e) => /source label/.test(e)), errs.join("|"));
});

test("TestRejectFloatingOnlyTag", () => {
  const errs = rejects((m) => { m.image.reference = "uptime-platform:latest"; });
  assert.ok(errs.some((e) => /latest/.test(e)), errs.join("|"));
});

test("TestRejectMissingSourceSHA", () => {
  const errs = rejects((m) => { m.source_sha = ""; });
  assert.ok(errs.some((e) => /source_sha/.test(e)), errs.join("|"));
});

test("TestRejectMissingLicense", () => {
  const errs = rejects((m) => { delete m.license_status; });
  assert.ok(errs.some((e) => /license/.test(e)), errs.join("|"));
});

test("TestRejectPendingLicenseRemote", () => {
  const errs = rejects((m) => { m.license_status = "pending-user-decision"; }, "remote");
  assert.ok(errs.some((e) => /license/.test(e)), errs.join("|"));
});

test("TestAcceptValidLocal", () => {
  const m = base();
  m.license_status = "pending-user-decision"; // local candidate may be pending
  const errs = validateManifest(m, { stage: "local" });
  assert.deepEqual(errs, [], errs.join("|"));
});
