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

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const SKOPEO_IMAGE = "quay.io/skopeo/stable:v1.19.0@sha256:77e6c8901f6976bdfa87b8b14c40b96de754794c492d8ed295f77fba1454a4ab";
const rel = (p) => p.replace(ROOT + "\\", "").replace(ROOT + "/", "").replaceAll("\\", "/");

export const REGISTRIES = {
  ghcr: { host: "ghcr.io", user_env: "GHCR_USER", tok_env: "GHCR_TOKEN" },
  dockerhub: { host: "docker.io", user_env: "DOCKERHUB_USERNAME", tok_env: "DOCKERHUB_TOKEN" },
};

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

function run(argv, { quiet, env } = {}) {
  return new Promise((res, rej) => {
    const p = spawn(argv[0], argv.slice(1), { cwd: ROOT, env: { ...process.env, ...env },
      stdio: ["ignore", "pipe", "pipe"] });
    let out = "", err = "";
    p.stdout.on("data", (d) => out += d);
    p.stderr.on("data", (d) => { err += d; if (!quiet) process.stderr.write(d); });
    p.on("close", (c) => c === 0 ? res(out) : rej(new Error(`${argv.join(" ")} -> ${c}: ${err.split("\n").pop()}`)));
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

async function publishOne(m, registry, ref, { dryRun, authDir }) {
  const receipt = { registry, reference: ref, tags: planTags(m),
    subject_digest: m.image.index_digest, pushed: [], remote_digest: null,
    verified: false, dry_run: !!dryRun, utc: new Date().toISOString() };
  const archDir = dirname(resolve(ROOT, m.image.archive));
  const archFile = resolve(ROOT, m.image.archive).split(/[\\/]/).pop();
  const mounts = ["-v", `${archDir}:/a:ro`, "-v", `${authDir}:/auth:ro`];
  if (dryRun) { receipt.detail = "dry-run: no copy performed"; return receipt; }
  for (const tag of receipt.tags) {
    await run(["docker", "run", "--rm", ...mounts, SKOPEO_IMAGE,
      "copy", "--all", "--dest-authfile", "/auth/auth.json",
      `oci-archive:/a/${archFile}:${tag}`, `docker://${ref}:${tag}`], { quiet: true });
    receipt.pushed.push(tag);
  }
  // Read back the remote index and hash the raw document — the digest
  // must equal the recorded manifest-list digest (no tag trust).
  const raw = await run(["docker", "run", "--rm", ...mounts, SKOPEO_IMAGE,
    "inspect", "--authfile", "/auth/auth.json", "--raw",
    `docker://${ref}:${receipt.tags[0]}`], { quiet: true });
  receipt.remote_digest = `sha256:${createHash("sha256").update(raw, "utf8").digest("hex")}`;
  receipt.verified = receipt.remote_digest === m.image.index_digest;
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
  mkdirSync(dirname(output), { recursive: true });

  const m = JSON.parse(readFileSync(mpath, "utf8"));
  const errs = validateManifest(m, { stage: "remote" });
  if (errs.length) { writeFileSync(output, JSON.stringify({ verdict: "FAIL", blocked: errs }, null, 2));
    console.error(`manifest fails remote contract: ${errs.join(" | ")}`); process.exit(1); }

  const receipts = await publishAfterArtifactVerification(mpath, async () => {
    const dests = dest === "all" ? Object.keys(REGISTRIES) : [dest];
    const result = [];
    for (const d of dests) {
      const spec = REGISTRIES[d];
      const ref = args["override-ref"] ?? m.registries?.[d];
      if (!ref || ref === "pending-user-namespace") {
        result.push({ registry: d, reference: ref ?? null, verified: false,
          dry_run: false, error: "namespace unresolved", utc: new Date().toISOString() });
        continue;
      }
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
        result.push(await publishOne(m, d, ref, { dryRun, authDir }));
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
