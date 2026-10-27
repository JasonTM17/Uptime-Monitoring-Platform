// C85 — dual-registry publisher for the C84-verified OCI artifact.
//
//   node scripts/publish-release-image.mjs --manifest <path> \
//     --output <receipt-path> --dest ghcr|dockerhub|all [--dry-run]
//
// Copies the ONE verified OCI archive (index + attestation preserved)
// to each destination via a pinned skopeo image — never rebuilds.
// Readback inspects the remote digest; receipts record per-registry
// pushed/remote digests and UTC. Exactly one success = PARTIAL.
// Credentials ride an authfile mount, never process args or logs.
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, writeFileSync, readFileSync, rmSync, mkdtempSync } from "node:fs";
import { resolve, dirname, join } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { validateManifest } from "./verify-container-release.mjs";
import { TRUSTED_REGISTRY_REFS } from "./container-release-contract.mjs";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const SKOPEO_IMAGE = "quay.io/skopeo/stable:v1.19.0@sha256:77e6c8901f6976bdfa87b8b14c40b96de754794c492d8ed295f77fba1454a4ab";
const rel = (p) => p.replace(ROOT + "\\", "").replace(ROOT + "/", "").replaceAll("\\", "/");

export const REGISTRIES = {
  ghcr: { host: "ghcr.io", ref: TRUSTED_REGISTRY_REFS.ghcr,
    user_env: "GHCR_USER", tok_env: "GHCR_TOKEN" },
  dockerhub: { host: "docker.io", ref: TRUSTED_REGISTRY_REFS.dockerhub,
    user_env: "DOCKERHUB_USERNAME", tok_env: "DOCKERHUB_TOKEN" },
};

export function assertTrustedRegistryTargets(manifest) {
  const mismatches = Object.entries(TRUSTED_REGISTRY_REFS)
    .filter(([registry, expected]) => manifest?.registries?.[registry] !== expected)
    .map(([registry]) => registry);
  if (mismatches.length)
    throw new Error(`release manifest registry target mismatch: ${mismatches.join(", ")}`);
  return true;
}

export function planTags(m) {
  return [m.version, `sha-${m.source_sha.slice(0, 12)}`];
}

export function summarizeVerdict(receipts) {
  const ok = receipts.filter((r) => r.verified).length;
  const dry = receipts.filter((r) => r.dry_run).length;
  if (dry === receipts.length && receipts.length > 0) return "NOT_RUN";
  if (ok === receipts.length && receipts.length > 0) return "PASS";
  if (ok > 0) return "PARTIAL";
  return "FAIL";
}

export function isMissingRegistryTag(error) {
  const detail = `${error?.stderr ?? ""}\n${error?.message ?? ""}`;
  return /manifest unknown|no such manifest|manifest[^\n]*not found|tag[^\n]*not found/i.test(detail);
}

export async function preflightReleaseTags(tags, expectedDigest, inspectTag) {
  if (!Array.isArray(tags) || tags.length === 0 ||
      !/^sha256:[0-9a-f]{64}$/.test(expectedDigest ?? ""))
    throw new Error("release-tag preflight input is malformed");
  const states = [];
  for (const tag of tags) {
    let currentDigest;
    try { currentDigest = await inspectTag(tag); }
    catch (error) {
      if (!isMissingRegistryTag(error))
        throw new Error(`cannot safely inspect release tag ${tag}; no mutation attempted`);
      states.push({ tag, state: "absent" });
      continue;
    }
    if (currentDigest !== expectedDigest)
      throw new Error(`release tag ${tag} exists with a different digest; no mutation attempted`);
    states.push({ tag, state: "same-digest" });
  }
  return states;
}

function run(argv, { quiet, env } = {}) {
  return new Promise((res, rej) => {
    const p = spawn(argv[0], argv.slice(1), { cwd: ROOT, env: { ...process.env, ...env },
      stdio: ["ignore", "pipe", "pipe"] });
    let out = "", err = "";
    p.stdout.on("data", (d) => out += d);
    p.stderr.on("data", (d) => { err += d; if (!quiet) process.stderr.write(d); });
    p.on("close", (c) => {
      if (c === 0) return res(out);
      const error = new Error(`${argv.join(" ")} -> ${c}: ${err.trim().split("\n").slice(-1)[0]}`);
      error.stderr = err;
      error.exitCode = c;
      rej(error);
    });
  });
}

export async function verifyReleaseArtifactBeforePublish(manifestPath, runVerifier = run) {
  const tempRoot = mkdtempSync(join(tmpdir(), "uptime-publish-verify-"));
  const reportPath = join(tempRoot, "verification.json");
  try {
    await runVerifier([process.execPath, resolve(ROOT, "scripts/verify-container-release.mjs"),
      "--manifest", resolve(manifestPath), "--output", reportPath, "--stage", "local"],
    { quiet: true });
    const report = JSON.parse(readFileSync(reportPath, "utf8"));
    if (report.verdict !== "PASS") throw new Error("local verifier did not pass");
  } catch (error) {
    const code = / -> (\d+)(?::|$)/.exec(error?.message ?? "")?.[1];
    throw new Error(`release artifact failed pre-publish verification${code ? ` (exit ${code})` : ""}`);
  } finally {
    rmSync(tempRoot, { recursive: true, force: true });
  }
}

export async function publishAfterArtifactVerification(manifestPath, publish, verify = verifyReleaseArtifactBeforePublish) {
  await verify(manifestPath);
  return publish();
}

export async function publishAfterFinalReleaseCheck(checkRelease, publish) {
  await checkRelease();
  return publish();
}

async function assertTrustedPublisherEvent(manifestPath) {
  if (process.env.REQUIRE_TRUSTED_RELEASE_EVENT !== "true") return;
  const required = ["UPSTREAM_WORKFLOW_RUN", "CURRENT_REPOSITORY", "DEFAULT_BRANCH", "GITHUB_REF", "GH_TOKEN"];
  if (required.some((name) => !process.env[name]))
    throw new Error("trusted release event context is incomplete; no mutation attempted");
  await run([process.execPath, resolve(ROOT, "scripts/validate-container-publish-event.mjs"),
    resolve(manifestPath)], { quiet: true });
}

async function publishOne(m, registry, ref, { dryRun, authDir, finalReleaseCheck }) {
  const receipt = { registry, reference: ref, tags: planTags(m),
    subject_digest: m.image.index_digest, pushed: [], reused: [], remote_digests: {},
    remote_digest: null, verified: false, dry_run: !!dryRun, utc: new Date().toISOString() };
  const archDir = dirname(resolve(ROOT, m.image.archive));
  const archFile = resolve(ROOT, m.image.archive).split(/[\\/]/).pop();
  const mounts = ["-v", `${archDir}:/a:ro`, "-v", `${authDir}:/auth:ro`];
  if (dryRun) { receipt.detail = "dry-run: no copy performed"; return receipt; }
  const inspect = async (tag) => {
    const raw = await run(["docker", "run", "--rm", ...mounts, SKOPEO_IMAGE,
      "inspect", "--authfile", "/auth/auth.json", "--raw", `docker://${ref}:${tag}`],
    { quiet: true });
    return `sha256:${createHash("sha256").update(raw, "utf8").digest("hex")}`;
  };
  const states = await preflightReleaseTags(receipt.tags, m.image.index_digest, inspect);
  for (const { tag, state } of states) {
    if (state === "same-digest") { receipt.reused.push(tag); continue; }
    const copy = () => run(["docker", "run", "--rm", ...mounts, SKOPEO_IMAGE,
      "copy", "--all", "--dest-authfile", "/auth/auth.json",
      `oci-archive:/a/${archFile}:${tag}`, `docker://${ref}:${tag}`], { quiet: true });
    await publishAfterFinalReleaseCheck(finalReleaseCheck ?? (async () => {}), copy);
    receipt.pushed.push(tag);
  }
  for (const tag of receipt.tags) receipt.remote_digests[tag] = await inspect(tag);
  receipt.remote_digest = receipt.remote_digests[receipt.tags[0]];
  receipt.verified = receipt.tags.every((tag) =>
    receipt.remote_digests[tag] === m.image.index_digest);
  return receipt;
}

async function main() {
  const args = {};
  for (let i = 2; i < process.argv.length; i += 2)
    args[process.argv[i].replace(/^--/, "")] = process.argv[i + 1];
  const mpath = resolve(args.manifest ?? die("--manifest required"));
  const output = resolve(args.output ?? die("--output required"));
  const dest = args.dest ?? "all";
  const dryRun = args["dry-run"] === "true" || args["dry-run"] === undefined && false;
  if (!["ghcr", "dockerhub", "all"].includes(dest)) die(`--dest ${dest}`);
  const selectedDestinations = dest === "all" ? Object.keys(REGISTRIES) : [dest];
  if (args["override-ref"] && selectedDestinations.some((registry) =>
    args["override-ref"] !== REGISTRIES[registry].ref))
    die("release target override does not match every selected trusted registry");
  mkdirSync(dirname(output), { recursive: true });

  const m = JSON.parse(readFileSync(mpath, "utf8"));
  try { assertTrustedRegistryTargets(m); }
  catch (error) {
    writeFileSync(output, JSON.stringify({ verdict: "FAIL", blocked: [error.message] }, null, 2));
    console.error(error.message);
    process.exit(1);
  }
  const errs = validateManifest(m, { stage: "remote" });
  if (errs.length) { writeFileSync(output, JSON.stringify({ verdict: "FAIL", blocked: errs }, null, 2));
    console.error(`manifest fails remote contract: ${errs.join(" | ")}`); process.exit(1); }

  if (args["preflight-only"] === "true") {
    await verifyReleaseArtifactBeforePublish(mpath);
    const destinations = selectedDestinations;
    const checked = [];
    await assertTrustedPublisherEvent(mpath);
    for (const d of destinations) {
      const spec = REGISTRIES[d];
      const ref = spec.ref;
      if (args["override-ref"] && args["override-ref"] !== ref)
        throw new Error(`release target override rejected for ${d}; no mutation attempted`);
      const user = process.env[spec.user_env], tok = process.env[spec.tok_env];
      if (!ref || ref === "pending-user-namespace" || !user || !tok)
        throw new Error(`release-tag preflight blocked for ${d}; target or credentials are unavailable`);
      const authDir = resolve(dirname(output), `.auth-${d}`);
      mkdirSync(authDir, { recursive: true });
      try {
        writeFileSync(resolve(authDir, "auth.json"), JSON.stringify({ auths: {
          [spec.host]: { auth: Buffer.from(`${user}:${tok}`).toString("base64") } } }));
        const mounts = ["-v", `${authDir}:/auth:ro`];
        const states = await preflightReleaseTags(planTags(m), m.image.index_digest, async (tag) => {
          const raw = await run(["docker", "run", "--rm", ...mounts, SKOPEO_IMAGE,
            "inspect", "--authfile", "/auth/auth.json", "--raw", `docker://${ref}:${tag}`],
          { quiet: true });
          return `sha256:${createHash("sha256").update(raw, "utf8").digest("hex")}`;
        });
        checked.push({ registry: d, reference: ref, tags: states });
      } finally {
        rmSync(authDir, { recursive: true, force: true });
      }
    }
    writeFileSync(output, JSON.stringify({ verdict: "PASS", mutation: false,
      subject_digest: m.image.index_digest, checked, utc: new Date().toISOString() }, null, 2));
    console.log("release-tag preflight PASS — no registry mutation attempted");
    return;
  }

  const receipts = await publishAfterArtifactVerification(mpath, async () => {
    await assertTrustedPublisherEvent(mpath);
    const dests = selectedDestinations;
    const result = [];
    for (const d of dests) {
      const spec = REGISTRIES[d];
      const ref = spec.ref;
      if (args["override-ref"] && args["override-ref"] !== ref)
        throw new Error(`release target override rejected for ${d}; no mutation attempted`);
      const user = process.env[spec.user_env], tok = process.env[spec.tok_env];
      if ((!user || !tok) && !dryRun) {
        result.push({ registry: d, reference: ref, verified: false, dry_run: false,
          error: `missing ${spec.user_env}/${spec.tok_env} — no mutation attempted`,
          utc: new Date().toISOString() });
        continue;
      }
      const authDir = resolve(dirname(output), `.auth-${d}`);
      mkdirSync(authDir, { recursive: true });
      try {
        if (!dryRun)
          writeFileSync(resolve(authDir, "auth.json"), JSON.stringify({ auths: {
            [spec.host]: { auth: Buffer.from(`${user}:${tok}`).toString("base64") } } }));
        result.push(await publishOne(m, d, ref, { dryRun, authDir,
          finalReleaseCheck: () => assertTrustedPublisherEvent(mpath) }));
      } catch (e) {
        result.push({ registry: d, reference: ref, verified: false, dry_run: !!dryRun,
          error: e.message.slice(0, 300), utc: new Date().toISOString() });
      } finally {
        rmSync(authDir, { recursive: true, force: true }); // never persist creds
      }
    }
    return result;
  });

  const result = { manifest: rel(mpath), subject_digest: m.image.index_digest,
    generated_at: new Date().toISOString(), receipts,
    verdict: summarizeVerdict(receipts) };
  writeFileSync(output, JSON.stringify(result, null, 2));
  console.log(`verdict ${result.verdict} — ${receipts.map((r) =>
    `${r.registry}:${r.verified ? "verified" : r.dry_run ? "dry" : "FAIL"}`).join(", ")}`);
  process.exit(result.verdict === "PASS" ? 0 : result.verdict === "PARTIAL" ? 2 : 1);
}
function die(msg) { throw new Error(`publish-release: ${msg}`); }

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url))
  main().catch((e) => { console.error(e.message ?? e); process.exit(1); });
