// C84 — release-candidate verifier.
//
//   node scripts/verify-container-release.mjs --manifest <path> \
//     --output <path> [--stage local|remote] [--anonymous]
//
// local  — schema/label/digest/license/scan checks + docker load
//          roundtrip parity against the recorded archive.
// remote — (C86/C87) registry readback + anonymous pull; refuses to
//          run while the manifest has unresolved prerequisites.
//
// Reject contract (each maps to a test fixture):
//   malformed namespace, wrong source label, floating-only tag,
//   missing sourceSHA/license, unwaived CRITICAL finding,
//   secret-looking build arg/provenance, subject mismatch,
//   missing platform, corrupt archive.
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, writeFileSync, readFileSync, existsSync, mkdtempSync, rmSync } from "node:fs";
import { resolve, dirname, join } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const GHCR_REF = "ghcr.io/jasontm17/uptime-monitoring-platform";
const REPO_URL = "https://github.com/JasonTM17/Uptime-Monitoring-Platform";
const DIGEST_RE = /^sha256:[0-9a-f]{64}$/;
const GOVULNCHECK_VERSION = "v1.1.4";
const rel = (p) => p.replace(ROOT + "\\", "").replace(ROOT + "/", "").replaceAll("\\", "/");
// GNU tar (Git's tar on Windows) octal-decodes backslash escapes in args
// like -C "D:\...\3abc"; forward slashes are portable across tar builds.
const tarPath = (p) => p.replaceAll("\\", "/");
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

export function validateManifest(m, { stage = "local" } = {}) {
  const errs = [];
  const need = (c, msg) => { if (!c) errs.push(msg); };

  need(m && typeof m === "object", "manifest is not an object");
  if (!m || typeof m !== "object") return errs;
  need(m.format === "uptime-release-manifest-v1",
    `format ${m.format} != uptime-release-manifest-v1`);
  need(/^v\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$/.test(m.version ?? ""),
    `version '${m.version}' is not semver-shaped`);
  need(/^[0-9a-f]{40}$/.test(m.source_sha ?? ""),
    `source_sha missing/malformed: '${m.source_sha}'`);
  need(m.source_dirty === false, "source_dirty must be false for an exact-source release");
  need(DIGEST_RE.test(m.context_receipt_sha256 ?? ""),
    "context_receipt_sha256 missing/malformed");
  need(DIGEST_RE.test(m.build_context_sha256 ?? ""),
    "build_context_sha256 missing/malformed");
  need(m.platform === "linux/amd64",
    `platform '${m.platform}' — baseline contract is linux/amd64 only`);
  const resolvedLicense = /^resolved:([A-Za-z0-9.+-]+)$/.exec(m.license_status ?? "")?.[1];
  need(typeof m.license_status === "string" &&
    (m.license_status === "pending-user-decision" || resolvedLicense),
    "license_status missing/malformed — expected resolved:<spdx> or pending-user-decision");
  if (stage === "remote")
    need(!!resolvedLicense,
      `license_status '${m.license_status}' — remote publish requires a nonempty resolved:<spdx>`);

  const img = m.image ?? {};
  need(typeof img.reference === "string" && img.reference.includes(":"),
    "image.reference missing tag");
  if (typeof img.reference === "string" && img.reference.endsWith(":latest"))
    errs.push("floating ':latest' reference is not a release identity");
  need(DIGEST_RE.test(img.index_digest ?? ""),
    "no index digest — the manifest-list digest is the pushable identity");
  need(DIGEST_RE.test(img.image_manifest_digest ?? ""),
    "image_manifest_digest missing/malformed");
  need(DIGEST_RE.test(img.config_digest ?? ""), "config_digest missing/malformed");
  need(DIGEST_RE.test(img.attestation_digest ?? ""),
    "attestation_digest missing — transport must preserve provenance");
  need(Array.isArray(img.layer_digests) && img.layer_digests.length > 0 &&
    img.layer_digests.every((d) => DIGEST_RE.test(d)),
    "layer_digests missing/malformed");
  need(DIGEST_RE.test(img.archive_sha256 ?? ""), "archive_sha256 missing/malformed");

  const labels = m.labels ?? {};
  need(labels["org.opencontainers.image.source"] === REPO_URL,
    `source label '${labels["org.opencontainers.image.source"]}' != ${REPO_URL}`);
  need(labels["org.opencontainers.image.revision"] === m.source_sha,
    "revision label != source_sha");
  need(labels["org.opencontainers.image.version"] === m.version,
    "version label != manifest version");
  if (resolvedLicense)
    need(labels["org.opencontainers.image.licenses"] === resolvedLicense,
      `license label '${labels["org.opencontainers.image.licenses"]}' != ${resolvedLicense}`);

  for (const k of ["sbom", "provenance"]) {
    const s = m[k] ?? {};
    need(DIGEST_RE.test(s.subject_digest ?? ""),
      `${k} subject_digest missing/malformed`);
  }
  const subj = m.sbom?.subject_digest;
  if (subj && m.provenance?.subject_digest && subj !== m.provenance.subject_digest)
    errs.push("sbom/provenance subject digests disagree");
  const imgDigest = img.index_digest; // pushable manifest-list identity
  if (subj && imgDigest && subj !== imgDigest)
    errs.push(`sbom subject ${subj} != image digest ${imgDigest}`);

  const scan = m.scan?.image_scanner ?? {};
  const sourceScan = m.scan?.source_scanner ?? {};
  need(sourceScan.tool === "govulncheck", "source_scanner.tool must be govulncheck");
  need(sourceScan.tool_version === GOVULNCHECK_VERSION,
    `source_scanner.tool_version must be ${GOVULNCHECK_VERSION}`);
  need(sourceScan.mode === "binary", "source_scanner.mode must be binary");
  need(sourceScan.exit_code === 0,
    `govulncheck exit_code must be 0, got ${sourceScan.exit_code ?? "missing"}`);
  const scanTarget = sourceScan.target ?? {};
  need(scanTarget.kind === "source-matched-symbol-preserving-companion",
    "govulncheck target kind must be source-matched-symbol-preserving-companion");
  need(scanTarget.source_sha === m.source_sha,
    "govulncheck target source_sha != manifest source_sha");
  need(scanTarget.version === m.version,
    "govulncheck target version != manifest version");
  need(scanTarget.platform === m.platform,
    "govulncheck target platform != manifest platform");
  need(scanTarget.build_context_sha256 === m.build_context_sha256,
    "govulncheck target build_context_sha256 != manifest build_context_sha256");
  need(scanTarget.runtime_image_digest === img.index_digest,
    "govulncheck target runtime_image_digest != image index_digest");
  need(DIGEST_RE.test(scanTarget.sha256 ?? ""),
    "govulncheck target sha256 missing/malformed");
  need(scanTarget.artifact === "govulncheck-target",
    "govulncheck target artifact must be the retained govulncheck-target file");
  need(typeof sourceScan.findings_tail === "string" && !!sourceScan.findings_tail.trim(),
    "source_scanner.findings_tail missing");

  const findings = scan.findings;
  need(Array.isArray(findings), "image_scanner.findings must record scanned vulnerability identities");
  if (Array.isArray(findings)) {
    const critical = findings.filter((x) => x.severity === "CRITICAL");
    const high = findings.filter((x) => x.severity === "HIGH");
    need(scan.critical === critical.length,
      `CRITICAL count ${scan.critical} != recorded findings ${critical.length}`);
    need(scan.high === high.length,
      `HIGH count ${scan.high} != recorded findings ${high.length}`);
    const exceptions = Array.isArray(scan.exceptions) ? scan.exceptions : [];
    const validException = (x) => {
      if (!/^CVE-\d{4}-\d{4,}$/i.test(x?.cve ?? "") ||
        typeof x.impact !== "string" || !x.impact.trim() ||
        typeof x.owner !== "string" || !x.owner.trim() ||
        !/^\d{4}-\d{2}-\d{2}$/.test(x.expiry ?? "")) return false;
      const endOfExpiry = Date.parse(`${x.expiry}T23:59:59Z`);
      return Number.isFinite(endOfExpiry) && endOfExpiry >= Date.now() &&
        new Date(endOfExpiry).toISOString().slice(0, 10) === x.expiry;
    };
    const waived = (finding) => exceptions.some((x) =>
      x?.cve?.toUpperCase() === finding.cve?.toUpperCase() && validException(x));
    for (const finding of [...critical, ...high])
      need(waived(finding), `unwaived ${finding.severity} finding: ${finding.cve ?? "identity missing"}`);
  }
  const smoke = m.smoke ?? {};
  need(smoke.ready_probe_200 === true, "smoke.ready_probe_200 must be true after migration");
  need(smoke.live_db_free === true, "smoke.live_db_free must be true during a database outage");
  need(smoke.ca_chain_outbound === true, "smoke.ca_chain_outbound must prove verified HTTPS egress");
  need(smoke.migrated_db === true, "smoke.migrated_db must be true");
  need(smoke.read_only_rootfs === true, "smoke.read_only_rootfs must be true");
  need(smoke.capabilities_dropped === true, "smoke.capabilities_dropped must be true");
  need(smoke.no_new_privileges === true, "smoke.no_new_privileges must be true");
  need(typeof smoke.nonroot_user === "string" && !!smoke.nonroot_user.trim() &&
    !/^(?:0|root)(?::(?:0|root))?$/i.test(smoke.nonroot_user.trim()),
    "smoke.nonroot_user must identify a non-root runtime user");
  need(Number.isFinite(smoke.sigterm_stop_s) && smoke.sigterm_stop_s >= 0 && smoke.sigterm_stop_s <= 15,
    `smoke.sigterm_stop_s '${smoke.sigterm_stop_s}' is missing or exceeds the 15s deadline`);
  need(/^sha256:[0-9a-f]{64}$/.test(smoke.build_script_sha256 ?? ""),
    "smoke.build_script_sha256 missing/malformed");
  need(/^sha256:[0-9a-f]{64}$/.test(smoke.tls_probe_sha256 ?? ""),
    "smoke.tls_probe_sha256 missing/malformed");
  const seenKeys = JSON.stringify([m.build_args, m.provenance, m.env, labels]);
  for (const mm of seenKeys.matchAll(/"([^"]*(?:token|secret|password|passwd|private[-_]?key|credential|api[-_]?key)[^"]*)"\s*:/gi))
    errs.push(`secret-named field in metadata: '${mm[1]}'`);

  const regs = m.registries ?? {};
  need(regs.ghcr === GHCR_REF, `ghcr ref '${regs.ghcr}' != ${GHCR_REF}`);
  if (regs.ghcr && !/^ghcr\.io\/[a-z0-9-]+\/[a-z0-9._-]+$/.test(regs.ghcr))
    errs.push(`malformed ghcr namespace '${regs.ghcr}'`);
  if (stage === "remote")
    need(regs.dockerhub && regs.dockerhub !== "pending-user-namespace",
      "remote stage with unresolved dockerhub namespace");
  return errs;
}

export function validateScannerTargetArtifact(m, bytes) {
  const target = m?.scan?.source_scanner?.target ?? {};
  const errs = [];
  if (!Buffer.isBuffer(bytes)) return ["govulncheck target artifact is missing"];
  if (`sha256:${sha256(bytes)}` !== target.sha256)
    errs.push("govulncheck target artifact sha256 mismatch");
  if (!bytes.includes(Buffer.from(m?.source_sha ?? "")))
    errs.push("govulncheck target artifact does not embed source_sha");
  if (!bytes.includes(Buffer.from(m?.version ?? "")))
    errs.push("govulncheck target artifact does not embed version");
  return errs;
}

export function validateContextProof(m, bytes) {
  if (!Buffer.isBuffer(bytes)) return ["context proof artifact is missing"];
  if (`sha256:${sha256(bytes)}` !== m?.context_receipt_sha256)
    return ["context proof sha256 mismatch"];
  let proof;
  try { proof = JSON.parse(bytes.toString("utf8")); }
  catch { return ["context proof is malformed"]; }
  const errs = [];
  const proofKeys = Object.keys(proof).sort();
  if (JSON.stringify(proofKeys) !== JSON.stringify([
    "build_context_sha256", "format", "source_sha",
  ])) errs.push("context proof contains unsupported fields");
  if (proof.format !== "uptime-context-proof-v1") errs.push("context proof format mismatch");
  if (proof.source_sha !== m.source_sha) errs.push("context proof source_sha mismatch");
  if (proof.build_context_sha256 !== m.build_context_sha256)
    errs.push("context proof build_context_sha256 mismatch");
  return errs;
}

export async function verifySourceContext(m, repoRoot = ROOT) {
  const tempRoot = mkdtempSync(join(tmpdir(), "uptime-context-verify-"));
  let step = "archive";
  try {
    const sourceRoot = join(tempRoot, "source");
    const receipt = join(tempRoot, "context-manifest.json");
    mkdirSync(sourceRoot);
    // Replay one captured Git archive stream so extraction cannot observe a
    // different temporary tar file than the recorded source SHA.
    const sourceArchiveBytes = await run(["git", "archive", "--format=tar", m.source_sha],
      { quiet: true, buffer: true, cwd: repoRoot });
    step = "extract";
    await run(["tar", "-xf", "-", "-C", tarPath(sourceRoot)],
      { input: sourceArchiveBytes, quiet: true });
    step = "context-check";
    await run(["node", resolve(sourceRoot, "scripts/check-build-context.mjs"),
      "--context", sourceRoot, "--dockerfile", "Dockerfile", "--verify-sentinels",
      "--output", receipt], { quiet: true });
    step = "receipt-read";
    const context = JSON.parse(readFileSync(receipt, "utf8"));
    return context.contextHash === m.build_context_sha256.replace(/^sha256:/, "");
  } catch (e) {
    const code = / -> (\d+)(?::|$)/.exec(e?.message ?? "")?.[1];
    console.error(`source-context replay ${step} failed${code ? ` (exit ${code})` : ""}`);
    return false;
  } finally {
    rmSync(tempRoot, { recursive: true, force: true });
  }
}

function run(argv, { quiet, buffer, cwd = ROOT, input } = {}) {
  return new Promise((res, rej) => {
    const p = spawn(argv[0], argv.slice(1), { cwd, stdio: ["pipe", "pipe", "pipe"] });
    const chunks = [];
    let err = "";
    p.stdout.on("data", (d) => chunks.push(d));
    p.stderr.on("data", (d) => { err += d; if (!quiet) process.stderr.write(d); });
    // EPIPE/EOF only mean the child closed stdin early; let close surface
    // the real exit code and stderr instead of masking it as "write EOF".
    p.stdin.on("error", (e) => { if (e.code !== "EPIPE" && e.code !== "EOF") rej(e); });
    p.stdin.end(input);
    p.on("close", (c) => {
      const buf = Buffer.concat(chunks);
      c === 0 ? res(buffer ? buf : buf.toString("utf8"))
        : rej(new Error(`${argv.join(" ")} -> ${c}`));
    });
  });
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const mpath = resolve(args.manifest ?? die2("--manifest required"));
  const output = resolve(args.output ?? die2("--output required"));
  const stage = args.stage ?? "local";
  if (!["local", "remote"].includes(stage)) die2(`--stage ${stage}`);
  mkdirSync(dirname(output), { recursive: true });

  const m = JSON.parse(readFileSync(mpath, "utf8"));
  const result = { manifest: mpath, stage, generated_at: new Date().toISOString(),
    checks: [], verdict: "PASS" };
  const check = (name, ok, detail) => {
    result.checks.push({ name, ok: !!ok, detail });
    if (!ok) result.verdict = "FAIL";
  };

  const errs = validateManifest(m, { stage });
  check("manifest-contract", errs.length === 0, errs.join(" | ") || "schema/labels/digests/scan OK");

  const targetArtifactPath = join(dirname(mpath), "govulncheck-target");
  let targetArtifact = null;
  try { if (existsSync(targetArtifactPath)) targetArtifact = readFileSync(targetArtifactPath); }
  catch { targetArtifact = null; }
  const targetErrs = validateScannerTargetArtifact(m, targetArtifact);
  check("scanner-target-integrity", targetErrs.length === 0,
    targetErrs.join(" | ") || "retained scanner binary hash and embedded identity match");

  const contextProofPath = join(dirname(mpath), "context-proof.json");
  let contextProofBytes = null;
  try { if (existsSync(contextProofPath)) contextProofBytes = readFileSync(contextProofPath); }
  catch { contextProofBytes = null; }
  const proofErrs = validateContextProof(m, contextProofBytes);
  const replayOK = proofErrs.length === 0 && await verifySourceContext(m);
  check("source-context-binding", replayOK,
    replayOK ? "minimized proof and source-SHA context replay match" :
      (proofErrs.join(" | ") || "source-SHA context replay mismatch"));

  if (stage === "local") {
    // Archive on disk + recorded sha256 matches.
    const arch = resolve(ROOT, m.image?.archive ?? "");
    const want = (m.image?.archive_sha256 ?? "").replace(/^sha256:/, "");
    const archOK = existsSync(arch) && !!want &&
      createHash("sha256").update(readFileSync(arch)).digest("hex") === want;
    check("archive-integrity", archOK, archOK ? "archive sha256 matches" : "archive missing or sha mismatch");

    // Capability test: recompute the OCI digest chain inside the
    // archive — index -> manifest list -> {image manifest, attestation}
    // -> config + layer blobs. Every recorded digest must hash-match a
    // blob on disk; the attestation's subject must be the image
    // manifest. This is the parity claim; docker save/load is not.
    if (archOK) {
      try {
        const cat = async (name, buffer) => ({ out: await run(["tar", "-xOf", rel(arch), name], { quiet: true, buffer }) });
        const hexOK = (digest, bytes) =>
          digest.replace(/^sha256:/, "") === createHash("sha256").update(bytes).digest("hex");
        const idxBytes = (await cat("index.json")).out;
        const idx = JSON.parse(idxBytes);
        const problems = [];
        if (idx.manifests?.[0]?.digest !== m.image.index_digest)
          problems.push("index.json child != index_digest");
        const listBytes = (await cat(`blobs/${m.image.index_digest.replace(":", "/")}`)).out;
        if (!hexOK(m.image.index_digest, Buffer.from(listBytes, "utf8"))) problems.push("manifest-list blob hash mismatch");
        const list = JSON.parse(listBytes);
        const imgD = list.manifests?.find((x) => x.platform?.architecture === "amd64"
          && x.platform?.os === "linux" && !x.annotations?.["vnd.docker.reference.type"]);
        const attD = list.manifests?.find((x) =>
          x.annotations?.["vnd.docker.reference.type"] === "attestation-manifest");
        if (imgD?.digest !== m.image.image_manifest_digest) problems.push("image manifest digest mismatch/absent");
        if (attD?.digest !== m.image.attestation_digest) problems.push("attestation manifest digest mismatch/absent");
        const imgBytes = (await cat(`blobs/${imgD.digest.replace(":", "/")}`)).out;
        if (!hexOK(imgD.digest, Buffer.from(imgBytes, "utf8"))) problems.push("image manifest blob hash mismatch");
        const imgM = JSON.parse(imgBytes);
        if (imgM.config?.digest !== m.image.config_digest) problems.push("config digest mismatch");
        const cfgBytes = (await cat(`blobs/${m.image.config_digest.replace(":", "/")}`)).out;
        if (!hexOK(m.image.config_digest, Buffer.from(cfgBytes, "utf8"))) problems.push("config blob hash mismatch");
        const config = JSON.parse(cfgBytes);
        const sortedEntries = (value) => Object.entries(value ?? {}).sort(([a], [b]) => a.localeCompare(b));
        if (JSON.stringify(sortedEntries(config.config?.Labels)) !==
            JSON.stringify(sortedEntries(m.labels)))
          problems.push("OCI config labels != manifest labels");
        const manifestLayers = (imgM.layers ?? []).map((l) => l.digest);
        if (JSON.stringify(manifestLayers) !== JSON.stringify(m.image.layer_digests))
          problems.push("recorded layer_digests != image manifest layers");
        for (const d of manifestLayers) {
          const b = (await cat(`blobs/${d.replace(":", "/")}`, true)).out;
          if (!hexOK(d, b)) { problems.push(`layer blob ${d.slice(0, 19)} hash mismatch`); break; }
        }
        const attBytes = (await cat(`blobs/${attD.digest.replace(":", "/")}`)).out;
        const att = JSON.parse(attBytes);
        const attSubject = att.subject?.digest ?? att.subject?.[0]?.digest;
        if (attSubject !== imgD.digest)
          problems.push(`attestation subject ${attSubject} != image manifest`);
        check("oci-chain", problems.length === 0,
          problems.length ? problems.join(" | ") : "index->list->image+attestation->config+layers all hash-verified");
      } catch (e) { check("oci-chain", false, `chain walk: ${e.message.slice(0, 160)}`); }
    }
  }

  if (stage === "remote") {
    // C86 readback: package existence/association/visibility + remote
    // digest parity. Metadata only — anonymous pull/run is C87.
    const ver = m.version;
    // --- GHCR: gh api package readback (authenticated, read-only) ---
    try {
      const pkgs = JSON.parse(await run(["gh", "api",
        "users/JasonTM17/packages?package_type=container&per_page=100"], { quiet: true }));
      const pkg = pkgs.find((p) => p.name === "uptime-monitoring-platform");
      if (!pkg) {
        check("ghcr-package", false, "package ghcr.io/jasontm17/uptime-monitoring-platform not found — nothing published");
      } else {
        const detail = JSON.parse(await run(["gh", "api",
          `user/packages/container/${pkg.name}`], { quiet: true }).catch(() => "{}"));
        const assoc = detail.repository?.full_name ?? pkg.repository?.full_name ?? null;
        const vis = detail.visibility ?? pkg.visibility ?? "unknown";
        check("ghcr-package", true, `exists; visibility=${vis}`);
        check("ghcr-association", assoc === "JasonTM17/Uptime-Monitoring-Platform",
          `repository link: ${assoc}`);
        check("ghcr-visibility", vis === "public", `visibility=${vis} (contract requires public)`);
        // Remote digest parity via imagetools (no pull).
        try {
          const insp = await run(["docker", "buildx", "imagetools", "inspect",
            `${GHCR_REF}:${ver}`], { quiet: true });
          const d = /Digest:\s*(sha256:[0-9a-f]{64})/.exec(insp)?.[1];
          check("ghcr-digest-parity", d === m.image.index_digest,
            d ? `remote ${d.slice(0, 19)}… vs recorded ${m.image.index_digest.slice(0, 19)}…`
              : "no digest in inspect output");
        } catch (e) { check("ghcr-digest-parity", false, `inspect: ${e.message.slice(0, 120)}`); }
      }
    } catch (e) { check("ghcr-package", false, `gh api: ${e.message.slice(0, 120)}`); }
    // --- Docker Hub: anonymous REST readback ---
    const dhNs = m.registries?.dockerhub;
    if (!dhNs || dhNs === "pending-user-namespace") {
      check("dockerhub-package", false, "namespace unresolved (C83 prerequisite)");
    } else {
      try {
        const r = await fetch(`https://hub.docker.com/v2/repositories/${dhNs}`).then((x) => x.json());
        const repoName = dhNs.split("/").pop();
        check("dockerhub-package", r.name === repoName, `repo ${r.name ?? "not found"}`);
        check("dockerhub-visibility", r.is_private === false, `is_private=${r.is_private}`);
        const t = await fetch(`https://hub.docker.com/v2/repositories/${dhNs}/tags/${ver}`)
          .then((x) => x.json()).catch(() => null);
        const dDig = t?.digest ?? t?.images?.[0]?.digest;
        check("dockerhub-digest-parity", dDig === m.image.index_digest,
          dDig ? `remote ${dDig.slice(0, 19)}…` : `tag ${ver} not found`);
      } catch (e) { check("dockerhub-package", false, `hub api: ${e.message.slice(0, 120)}`); }
    }
  }

  if (args.anonymous === "true") {
    // C87: fresh empty Docker config — cached auths/images cannot be
    // the oracle. Pulls are BY DIGEST from publication receipts.
    const { mkdtempSync, rmSync } = await import("node:fs");
    const { tmpdir } = await import("node:os");
    const { join } = await import("node:path");
    const cfg = mkdtempSync(join(tmpdir(), "uptime-anon-"));
    writeFileSync(join(cfg, "config.json"), "{}");
    result.anonymous = { docker_config: cfg, commands: [] };
    const cmd = (argv) => { result.anonymous.commands.push(argv.join(" "));
      return run(argv, { quiet: true }); };

    const recPath = args.receipts ? resolve(args.receipts) : null;
    let receipts = [];
    try { receipts = recPath ? JSON.parse(readFileSync(recPath, "utf8")).receipts ?? [] : []; }
    catch { receipts = []; }
    check("receipts-present", receipts.some((r) => r.verified),
      receipts.length ? `${receipts.filter((r) => r.verified).length}/${receipts.length} verified receipts` : "no publication receipts — C85 not run");

    for (const r of receipts.filter((x) => x.verified)) {
      const ref = `${r.reference}@${m.image.index_digest}`;
      try {
        await cmd(["docker", "--config", cfg, "pull", ref]);
        const ins = JSON.parse(await cmd(["docker", "--config", cfg,
          "image", "inspect", ref]));
        check(`anon-pull-${r.registry}`, ins?.[0]?.Id === m.image.index_digest ||
          ins?.[0]?.RepoDigests?.some((d) => d.endsWith(m.image.index_digest)),
          `pulled ${r.registry} Id=${ins?.[0]?.Id?.slice(0, 19)}…`);
        // disposable smoke: ready probe on pulled content
        const smokeOK = await anonSmoke(cmd, ins[0].Id, cfg).catch(() => false);
        check(`anon-run-${r.registry}`, smokeOK, smokeOK ? "pulled image ready-200" : "smoke failed");
      } catch (e) {
        check(`anon-pull-${r.registry}`, false, e.message.slice(0, 140));
      }
    }
    result.anonymous.docker_config = "<task-temp, scrubbed>";
    rmSync(cfg, { recursive: true, force: true });
  }

  writeFileSync(output, JSON.stringify(result, null, 2));
  console.log(`verdict ${result.verdict} — ${result.checks.map((c) => `${c.name}:${c.ok ? "ok" : "FAIL"}`).join(", ")}`);
  process.exit(result.verdict === "PASS" ? 0 : 1);
}

export function parseArgs(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i++) {
    const flag = argv[i];
    if (!flag.startsWith("--")) die2(`unexpected argument '${flag}'`);
    const key = flag.slice(2);
    if (key === "anonymous") {
      const next = argv[i + 1];
      args[key] = next === "true" || next === "false" ? argv[++i] : "true";
      continue;
    }
    const value = argv[++i];
    if (!value || value.startsWith("--")) die2(`--${key} requires a value`);
    args[key] = value;
  }
  return args;
}
function die2(msg) { throw new Error(`verify-release: ${msg}`); }

// C87 anonymous smoke: pulled image + disposable pg on a scratch net.
// All docker calls ride the same fresh --config (a truly credential-free
// session); `cmd` records every resolved command into the receipt.
async function anonSmoke(cmd, imageId, cfg) {
  const tag = Date.now();
  const net = `anon-net-${tag}`, pg = `anon-pg-${tag}`, app = `anon-app-${tag}`;
  const dsn = `postgres://smoke:smoke-dummy@${pg}:5432/smoke?sslmode=disable`;
  const kill = (n) => cmd(["docker", "--config", cfg, "rm", "-f", n]).catch(() => {});
  try {
    await cmd(["docker", "--config", cfg, "network", "create", net]);
    await cmd(["docker", "--config", cfg, "run", "-d", "--rm", "--name", pg, "--network", net,
      "-e", "POSTGRES_USER=smoke", "-e", "POSTGRES_PASSWORD=smoke-dummy",
      "-e", "POSTGRES_DB=smoke", "postgres:17.11"]);
    for (let i = 0; i < 30; i++) {
      const ok = await run(["docker", "exec", pg, "pg_isready", "-U", "smoke", "-d", "smoke"],
        { quiet: true }).then(() => true).catch(() => false);
      if (ok) break;
      await new Promise((r) => setTimeout(r, 1000));
    }
    await cmd(["docker", "--config", cfg, "run", "--rm", "--network", net,
      "-v", `${resolve(ROOT, "migrations")}:/migrations:ro`,
      "migrate/migrate:v4.20.1", "-path", "/migrations", "-database", dsn, "up"]);
    await cmd(["docker", "--config", cfg, "run", "-d", "--rm", "--name", app, "--network", net,
      "-p", "127.0.0.1:18098:8080",
      "-e", "APP_ENV=local", "-e", "HTTP_HOST=0.0.0.0", "-e", "HTTP_PORT=8080",
      "-e", `DATABASE_URL=${dsn}`, "-e", `ENGINE_DATABASE_URL=${dsn}`,
      "-e", `MIGRATION_DATABASE_URL=${dsn}`, "-e", "NOTIFICATIONS_ENABLED=false",
      imageId]);
    for (let i = 0; i < 40; i++) {
      const r = await fetch("http://localhost:18098/health/ready").catch(() => null);
      if (r?.status === 200) return true;
      await new Promise((r) => setTimeout(r, 1000));
    }
    return false;
  } finally {
    await kill(app); await kill(pg);
    await cmd(["docker", "--config", cfg, "network", "rm", net]).catch(() => {});
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url))
  main().catch((e) => { console.error(e.message ?? e); process.exit(1); });
