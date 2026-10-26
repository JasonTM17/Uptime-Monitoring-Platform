// C84 verifier contract tests — every reject case in the card's E
// section maps to a fixture below. Run: node --test scripts/verify-container-release.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { isAbsolute, join, relative, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs, validateContextProof, validateManifest,
  validateScannerTargetArtifact, verifySourceContext } from "./verify-container-release.mjs";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const SCRIPT = fileURLToPath(new URL("./verify-container-release.mjs", import.meta.url));
const CONTEXT_CHECKER = resolve(ROOT, "scripts/check-build-context.mjs");

const SHA = "a".repeat(64);
const SOURCE_SHA = "b".repeat(40);
const CONTEXT_HASH = `sha256:${SHA}`;
const TARGET_BYTES = Buffer.from(`version=v0.1.0-rc.1 revision=${SOURCE_SHA}`);
const TARGET_SHA = `sha256:${createHash("sha256").update(TARGET_BYTES).digest("hex")}`;
const CONTEXT_PROOF_BYTES = Buffer.from(JSON.stringify({
  format: "uptime-context-proof-v1",
  source_sha: SOURCE_SHA,
  build_context_sha256: CONTEXT_HASH,
}, null, 2) + "\n");
const CONTEXT_PROOF_SHA = `sha256:${createHash("sha256").update(CONTEXT_PROOF_BYTES).digest("hex")}`;
const base = () => ({
  format: "uptime-release-manifest-v1",
  version: "v0.1.0-rc.1",
  source_sha: SOURCE_SHA,
  source_dirty: false,
  build_context_sha256: CONTEXT_HASH,
  context_receipt_sha256: CONTEXT_PROOF_SHA,
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
    "org.opencontainers.image.revision": SOURCE_SHA,
    "org.opencontainers.image.version": "v0.1.0-rc.1",
    "org.opencontainers.image.licenses": "MIT",
  },
  license_status: "resolved:MIT",
  sbom: { format: "spdx-json", path: "sbom.spdx.json", subject_digest: `sha256:${SHA}` },
  provenance: { mode: "sidecar-json", path: "provenance.json", subject_digest: `sha256:${SHA}` },
  scan: {
    image_scanner: { tool: "trivy", tool_version: "0.76.0",
      db_timestamp: "2026-10-22", critical: 0, high: 0, findings: [], exceptions: [] },
    source_scanner: {
      tool: "govulncheck",
      tool_version: "v1.1.4",
      mode: "binary",
      exit_code: 0,
      target: {
        kind: "source-matched-symbol-preserving-companion",
        source_sha: SOURCE_SHA,
        version: "v0.1.0-rc.1",
        platform: "linux/amd64",
        build_context_sha256: CONTEXT_HASH,
        runtime_image_digest: `sha256:${SHA}`,
        artifact: "govulncheck-target",
        sha256: TARGET_SHA,
      },
      findings_tail: "No vulnerabilities found.",
    },
  },
  smoke: {
    ready_probe_200: true,
    live_db_free: true,
    ca_chain_outbound: true,
    sigterm_stop_s: 0.5,
    migrated_db: true,
    nonroot_user: "65532:65532",
    read_only_rootfs: true,
    capabilities_dropped: true,
    no_new_privileges: true,
    build_script_sha256: `sha256:${SHA}`,
    tls_probe_sha256: `sha256:${SHA}`,
  },
  context_receipt_sha256: CONTEXT_PROOF_SHA,
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
  const errs = rejects((m) => {
    m.scan.image_scanner.critical = 1;
    m.scan.image_scanner.findings = [{ cve: "CVE-2026-0001", severity: "CRITICAL" }];
  });
  assert.ok(errs.some((e) => /unwaived CRITICAL/.test(e)), errs.join("|"));
});

test("TestRejectHighFinding", () => {
  const errs = rejects((m) => {
    m.scan.image_scanner.high = 1;
    m.scan.image_scanner.findings = [{ cve: "CVE-2026-0002", severity: "HIGH" }];
  });
  assert.ok(errs.some((e) => /unwaived HIGH/.test(e)), errs.join("|"));
});

test("TestRejectCriticalWaivedProperly", () => {
  const errs = rejects((m) => {
    m.scan.image_scanner.critical = 1;
    m.scan.image_scanner.findings = [{ cve: "CVE-2026-0001", severity: "CRITICAL" }];
    m.scan.image_scanner.exceptions = [{ cve: "CVE-2026-0001", impact: "Unreachable code path",
      owner: "ops", expiry: "2027-01-01" }];
  });
  assert.ok(!errs.some((e) => /CRITICAL/.test(e)), errs.join("|"));
});

test("TestRejectIncompleteFindingException", () => {
  const errs = rejects((m) => {
    m.scan.image_scanner.high = 1;
    m.scan.image_scanner.findings = [{ cve: "CVE-2026-0003", severity: "HIGH" }];
    m.scan.image_scanner.exceptions = [{ cve: "CVE-2026-0003", owner: "ops", expiry: "2027-01-01" }];
  });
  assert.ok(errs.some((e) => /unwaived HIGH/.test(e)), errs.join("|"));
});

test("TestRejectExpiredFindingException", () => {
  const errs = rejects((m) => {
    m.scan.image_scanner.high = 1;
    m.scan.image_scanner.findings = [{ cve: "CVE-2026-0004", severity: "HIGH" }];
    m.scan.image_scanner.exceptions = [{ cve: "CVE-2026-0004", impact: "Accepted temporarily",
      owner: "ops", expiry: "2026-01-01" }];
  });
  assert.ok(errs.some((e) => /unwaived HIGH/.test(e)), errs.join("|"));
});

test("TestRejectScanCountMismatch", () => {
  const errs = rejects((m) => {
    m.scan.image_scanner.high = 0;
    m.scan.image_scanner.findings = [{ cve: "CVE-2026-0005", severity: "HIGH" }];
  });
  assert.ok(errs.some((e) => /count .* != recorded findings/.test(e)), errs.join("|"));
});

test("TestRejectNonzeroGoVulncheckExit", () => {
  const errs = rejects((m) => { m.scan.source_scanner.exit_code = 3; });
  assert.ok(errs.some((e) => /govulncheck.*exit_code.*0/.test(e)), errs.join("|"));
});

test("TestRejectUnpinnedGoVulncheckVersion", () => {
  const errs = rejects((m) => { m.scan.source_scanner.tool_version = "made-up-version"; });
  assert.ok(errs.some((e) => /tool_version must be v1\.1\.4/.test(e)), errs.join("|"));
});

test("TestRejectMissingGoVulncheckTargetDigest", () => {
  const errs = rejects((m) => { delete m.scan.source_scanner.target.sha256; });
  assert.ok(errs.some((e) => /govulncheck target.*sha256/.test(e)), errs.join("|"));
});

test("TestRejectGoVulncheckTargetSourceMismatch", () => {
  const errs = rejects((m) => { m.scan.source_scanner.target.source_sha = "c".repeat(40); });
  assert.ok(errs.some((e) => /govulncheck target source_sha/.test(e)), errs.join("|"));
});

test("TestRejectGoVulncheckTargetImageMismatch", () => {
  const errs = rejects((m) => { m.scan.source_scanner.target.runtime_image_digest = `sha256:${"c".repeat(64)}`; });
  assert.ok(errs.some((e) => /govulncheck target runtime_image_digest/.test(e)), errs.join("|"));
});

test("TestRejectMissingGoVulncheckEvidence", () => {
  const errs = rejects((m) => { delete m.scan.source_scanner; });
  assert.ok(errs.some((e) => /source_scanner.tool must be govulncheck/.test(e)), errs.join("|"));
});

test("TestRejectDirtySourceSnapshot", () => {
  const errs = rejects((m) => { m.source_dirty = true; });
  assert.ok(errs.some((e) => /source_dirty must be false/.test(e)), errs.join("|"));
});

test("TestRejectMissingBuildContextDigest", () => {
  const errs = rejects((m) => { delete m.build_context_sha256; });
  assert.ok(errs.some((e) => /build_context_sha256 missing/.test(e)), errs.join("|"));
});

test("TestRejectGoVulncheckContextMismatch", () => {
  const errs = rejects((m) => { m.scan.source_scanner.target.build_context_sha256 = `sha256:${"c".repeat(64)}`; });
  assert.ok(errs.some((e) => /govulncheck target build_context_sha256/.test(e)), errs.join("|"));
});

test("TestRejectUnsafeGoVulncheckArtifactPath", () => {
  const errs = rejects((m) => { m.scan.source_scanner.target.artifact = "../outside"; });
  assert.ok(errs.some((e) => /artifact must be the retained/.test(e)), errs.join("|"));
});

test("TestVerifyRetainedGoVulncheckTargetHashAndIdentity", () => {
  const m = base();
  assert.deepEqual(validateScannerTargetArtifact(m, TARGET_BYTES), []);
  assert.deepEqual(validateScannerTargetArtifact(m, null), [
    "govulncheck target artifact is missing",
  ]);
  assert.deepEqual(validateScannerTargetArtifact(m, Buffer.from("tampered")), [
    "govulncheck target artifact sha256 mismatch",
    "govulncheck target artifact does not embed source_sha",
    "govulncheck target artifact does not embed version",
  ]);
});

test("TestVerifyMinimizedContextProofHashAndIdentity", () => {
  const m = base();
  assert.deepEqual(validateContextProof(m, CONTEXT_PROOF_BYTES), []);
  assert.ok(validateContextProof(m, Buffer.from("tampered")).some((e) =>
    /context proof sha256 mismatch/.test(e)));
  const wrongSource = Buffer.from(JSON.stringify({ format: "uptime-context-proof-v1",
    source_sha: "c".repeat(40), build_context_sha256: CONTEXT_HASH }));
  m.context_receipt_sha256 = `sha256:${createHash("sha256").update(wrongSource).digest("hex")}`;
  assert.ok(validateContextProof(m, wrongSource).some((e) => /source_sha mismatch/.test(e)));
  const expanded = Buffer.from(JSON.stringify({ format: "uptime-context-proof-v1",
    source_sha: SOURCE_SHA, build_context_sha256: CONTEXT_HASH, extra: "metadata" }));
  m.context_receipt_sha256 = `sha256:${createHash("sha256").update(expanded).digest("hex")}`;
  assert.ok(validateContextProof(m, expanded).some((e) => /unsupported fields/.test(e)));
});

test("TestGhcrPackageReadbackIsNotListBound", () => {
  const source = readFileSync(SCRIPT, "utf8");
  assert.doesNotMatch(source, /users\/JasonTM17\/packages\?package_type/);
  assert.match(source, /user\/packages\/container\/uptime-monitoring-platform/);
});

test("TestTarPathPortableForWindowsGnuTar", () => {
  const source = readFileSync(SCRIPT, "utf8");
  assert.match(source, /tarPath\(sourceRoot\)/);
  assert.doesNotMatch(source, /"-C", sourceRoot\]/);
});

test("TestReplayBuildContextFromExactSourceCommit", async () => {
  const tempRoot = mkdtempSync(join(tmpdir(), "uptime-context-source-test-"));
  try {
    const repo = join(tempRoot, "repo");
    mkdirSync(join(repo, "scripts"), { recursive: true });
    mkdirSync(join(repo, "cmd"), { recursive: true });
    mkdirSync(join(repo, "internal"), { recursive: true });
    writeFileSync(join(repo, "scripts/check-build-context.mjs"),
      readFileSync(CONTEXT_CHECKER, "utf8"));
    writeFileSync(join(repo, "Dockerfile"), "FROM scratch\n");
    writeFileSync(join(repo, ".dockerignore"),
      ".git/\nplans/\n.secrets/\nnode_modules/\n.env*\n");
    writeFileSync(join(repo, "go.mod"), "module example.test/context\n");
    writeFileSync(join(repo, "go.sum"), "");
    writeFileSync(join(repo, "cmd/main.go"), "package main\n");
    writeFileSync(join(repo, "internal/marker.go"), "package internal\n");
    assert.equal(spawnSync("git", ["init", "-q"], { cwd: repo, encoding: "utf8" }).status, 0);
    assert.equal(spawnSync("git", ["add", "--all"], { cwd: repo, encoding: "utf8" }).status, 0);
    const commit = spawnSync("git", ["-c", "user.name=Context Test", "-c",
      "user.email=context-test@example.invalid", "commit", "--quiet", "-m", "context fixture"],
    { cwd: repo, encoding: "utf8" });
    assert.equal(commit.status, 0, commit.stderr);
    const revision = spawnSync("git", ["rev-parse", "HEAD"], { cwd: repo, encoding: "utf8" });
    assert.equal(revision.status, 0, revision.stderr);
    const sourceSha = revision.stdout.trim();
    const expectedSource = join(tempRoot, "expected-source");
    const receipt = join(tempRoot, "context-manifest.json");
    mkdirSync(expectedSource);
    const archived = spawnSync("git", ["archive", "--format=tar", sourceSha],
      { cwd: repo, maxBuffer: 64 * 1024 * 1024 });
    assert.equal(archived.status, 0, archived.stderr);
    // Pipe the archive through stdin like the verifier does — GNU tar reads
    // a drive-letter "-f" path as host:file remote syntax.
    const extracted = spawnSync("tar", ["-xf", "-", "-C", expectedSource],
      { cwd: repo, input: archived.stdout, encoding: "utf8" });
    assert.equal(extracted.status, 0, extracted.stderr);
    const checked = spawnSync(process.execPath, [join(expectedSource, "scripts/check-build-context.mjs"),
      "--context", expectedSource, "--dockerfile", "Dockerfile", "--verify-sentinels",
      "--output", receipt], { cwd: repo, encoding: "utf8" });
    assert.equal(checked.status, 0, `${checked.stdout}\n${checked.stderr}`);
    const manifest = JSON.parse(readFileSync(receipt, "utf8"));
    assert.equal(await verifySourceContext({ source_sha: sourceSha,
      build_context_sha256: `sha256:${manifest.contextHash}` }, repo), true);
    assert.equal(await verifySourceContext({ source_sha: sourceSha,
      build_context_sha256: `sha256:${"0".repeat(64)}` }, repo), false);
  } finally {
    const base = resolve(tmpdir());
    const target = resolve(tempRoot);
    const rel = relative(base, target);
    assert.ok(rel && rel !== "." && !rel.startsWith("..") && !isAbsolute(rel),
      "temporary context fixture must remain below the OS temp directory");
    rmSync(target, { recursive: true, force: true });
  }
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

test("TestRejectMissingContextReceiptDigest", () => {
  const errs = rejects((m) => { delete m.context_receipt_sha256; });
  assert.ok(errs.some((e) => /context_receipt_sha256 missing\/malformed/.test(e)), errs.join("|"));
});

test("TestRejectMissingLicense", () => {
  const errs = rejects((m) => { delete m.license_status; });
  assert.ok(errs.some((e) => /license/.test(e)), errs.join("|"));
});

test("TestRejectMismatchedLicenseLabel", () => {
  const errs = rejects((m) => { m.labels["org.opencontainers.image.licenses"] = "Apache-2.0"; });
  assert.ok(errs.some((e) => /license label/.test(e)), errs.join("|"));
});

test("TestRejectEmptyResolvedLicenseRemote", () => {
  const errs = rejects((m) => { m.license_status = "resolved:"; }, "remote");
  assert.ok(errs.some((e) => /nonempty resolved:<spdx>/.test(e)), errs.join("|"));
});

test("rejects OCI config labels that disagree with the manifest", () => {
  const dir = mkdtempSync(join(ROOT, ".verifier-oci-label-test-"));
  const layout = join(dir, "layout");
  const archive = join(dir, "image.oci.tar");
  const manifestPath = join(dir, "manifest.json");
  const output = join(dir, "verification.json");
  const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");
  const writeBlob = (digest, bytes) => {
    const blobPath = join(layout, "blobs", "sha256", digest.slice("sha256:".length));
    mkdirSync(dirname(blobPath), { recursive: true });
    writeFileSync(blobPath, bytes);
  };

  try {
    const m = base();
    const layerBytes = Buffer.from("oci-layer-fixture");
    const layerDigest = `sha256:${hash(layerBytes)}`;
    const configBytes = Buffer.from(JSON.stringify({
      architecture: "amd64",
      os: "linux",
      config: { User: "65532:65532", Labels: {
        ...m.labels,
        "org.opencontainers.image.licenses": "Apache-2.0",
      } },
      rootfs: { type: "layers", diff_ids: [] },
    }));
    const configDigest = `sha256:${hash(configBytes)}`;
    const imageManifestBytes = Buffer.from(JSON.stringify({
      schemaVersion: 2,
      mediaType: "application/vnd.oci.image.manifest.v1+json",
      config: { mediaType: "application/vnd.oci.image.config.v1+json",
        digest: configDigest, size: configBytes.length },
      layers: [{ mediaType: "application/vnd.oci.image.layer.v1.tar",
        digest: layerDigest, size: layerBytes.length }],
    }));
    const imageDigest = `sha256:${hash(imageManifestBytes)}`;
    const attestationBytes = Buffer.from(JSON.stringify({ subject: { digest: imageDigest } }));
    const attestationDigest = `sha256:${hash(attestationBytes)}`;
    const listBytes = Buffer.from(JSON.stringify({
      schemaVersion: 2,
      manifests: [
        { mediaType: "application/vnd.oci.image.manifest.v1+json",
          digest: imageDigest, size: imageManifestBytes.length,
          platform: { architecture: "amd64", os: "linux" } },
        { mediaType: "application/vnd.oci.image.manifest.v1+json",
          digest: attestationDigest, size: attestationBytes.length,
          annotations: { "vnd.docker.reference.type": "attestation-manifest" } },
      ],
    }));
    const listDigest = `sha256:${hash(listBytes)}`;
    const indexBytes = Buffer.from(JSON.stringify({
      schemaVersion: 2,
      manifests: [{ mediaType: "application/vnd.oci.image.index.v1+json",
        digest: listDigest, size: listBytes.length }],
    }));
    mkdirSync(layout, { recursive: true });
    writeFileSync(join(layout, "index.json"), indexBytes);
    writeBlob(listDigest, listBytes);
    writeBlob(imageDigest, imageManifestBytes);
    writeBlob(attestationDigest, attestationBytes);
    writeBlob(configDigest, configBytes);
    writeBlob(layerDigest, layerBytes);

    const archiveRelative = relative(ROOT, archive).replaceAll("\\", "/");
    const packed = spawnSync("tar", ["-cf", archiveRelative, "-C", layout, "index.json", "blobs"], {
      cwd: ROOT,
      encoding: "utf8",
    });
    assert.ifError(packed.error);
    assert.equal(packed.status, 0, packed.stderr);

    m.image.index_digest = listDigest;
    m.image.image_manifest_digest = imageDigest;
    m.image.config_digest = configDigest;
    m.image.attestation_digest = attestationDigest;
    m.image.layer_digests = [layerDigest];
    m.image.archive = archiveRelative;
    m.image.archive_sha256 = `sha256:${hash(readFileSync(archive))}`;
    m.scan.source_scanner.target.runtime_image_digest = listDigest;
    m.sbom.subject_digest = listDigest;
    m.provenance.subject_digest = listDigest;
    writeFileSync(manifestPath, JSON.stringify(m));

    const child = spawnSync(process.execPath, [SCRIPT,
      "--manifest", manifestPath, "--output", output, "--stage", "local"], {
      cwd: ROOT,
      encoding: "utf8",
    });
    assert.ifError(child.error);
    assert.equal(child.status, 1, child.stdout);
    const receipt = JSON.parse(readFileSync(output, "utf8"));
    assert.equal(receipt.checks.find((check) => check.name === "manifest-contract").ok, true);
    assert.equal(receipt.checks.find((check) => check.name === "archive-integrity").ok, true);
    const chain = receipt.checks.find((check) => check.name === "oci-chain");
    assert.equal(chain.ok, false);
    assert.match(chain.detail, /OCI config labels != manifest labels/);
  } finally {
    const relDir = relative(ROOT, resolve(dir));
    assert.ok(relDir && relDir !== "." && !relDir.startsWith("..") && !isAbsolute(relDir),
      "temporary OCI fixture must remain below the repository root");
    rmSync(dir, { recursive: true, force: true });
  }
});

test("TestRejectMissingDBFreeLiveness", () => {
  const errs = rejects((m) => { m.smoke.live_db_free = false; });
  assert.ok(errs.some((e) => /live_db_free/.test(e)), errs.join("|"));
});

test("TestRejectMissingCAChain", () => {
  const errs = rejects((m) => { delete m.smoke.ca_chain_outbound; });
  assert.ok(errs.some((e) => /ca_chain_outbound/.test(e)), errs.join("|"));
});

test("TestRejectMissingRuntimeHardening", () => {
  const errs = rejects((m) => { m.smoke.read_only_rootfs = false; });
  assert.ok(errs.some((e) => /read_only_rootfs/.test(e)), errs.join("|"));
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

test("bare anonymous flag does not consume the following option", () => {
  assert.deepEqual(parseArgs(["--anonymous", "--manifest", "manifest.json"]), {
    anonymous: "true",
    manifest: "manifest.json",
  });
});

test("anonymous flag accepts explicit true and false values", () => {
  assert.deepEqual(parseArgs(["--anonymous", "true"]), { anonymous: "true" });
  assert.deepEqual(parseArgs(["--anonymous", "false"]), { anonymous: "false" });
});

test("bare anonymous flag executes the gate and writes its failure receipt", () => {
  const dir = mkdtempSync(join(tmpdir(), "uptime-anonymous-verifier-"));
  const manifest = join(dir, "manifest.json");
  const output = join(dir, "verification.json");
  try {
    writeFileSync(manifest, JSON.stringify({ image: { archive: "missing.oci.tar" } }));
    const child = spawnSync(process.execPath, [SCRIPT,
      "--manifest", manifest, "--output", output, "--stage", "local", "--anonymous"], {
      cwd: ROOT,
      encoding: "utf8",
    });
    assert.ifError(child.error);
    assert.equal(child.status, 1, child.stdout);

    const receipt = JSON.parse(readFileSync(output, "utf8"));
    assert.equal(receipt.verdict, "FAIL");
    assert.deepEqual(receipt.anonymous.commands, []);
    assert.equal(receipt.anonymous.docker_config, "<task-temp, scrubbed>");
    const receiptsCheck = receipt.checks.find((check) => check.name === "receipts-present");
    assert.deepEqual(receiptsCheck, {
      name: "receipts-present",
      ok: false,
      detail: "no publication receipts — C85 not run",
    });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
