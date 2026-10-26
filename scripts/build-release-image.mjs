// C84 — one-build release image wrapper.
//
// Produces the single artifact consumed by every registry publish:
//   context privacy gate -> docker build -> docker save archive ->
//   pinned trivy scan + SPDX SBOM -> govulncheck -> smoke -> manifest.
//
// The manifest (docs/releases/container-policy.md §7) is the only
// identity the verifier and publisher trust. `docker save` emits a
// docker-archive: config/layer digests survive `docker load` intact
// (the verifier capability-tests that roundtrip); it does NOT carry
// OCI referrers/attestation sidecars — our SBOM/provenance travel as
// subject-bound artifact files instead and are re-attached by the
// publish path (skopeo/buildx imagetools), which C85 capability-tests.
//
//   node scripts/build-release-image.mjs --version v0.1.0-rc.1 \
//     --output artifacts/release/image-manifest.json
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, writeFileSync, readFileSync, existsSync, statSync, readdirSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const REPO_URL = "https://github.com/JasonTM17/Uptime-Monitoring-Platform";
const TRIVY_IMAGE = "aquasec/trivy:0.76.0"; // pinned: released 2026-10-14, >7d
const GOVULNCHECK_VERSION = "v1.1.4";
const GOVULNCHECK = `golang.org/x/vuln/cmd/govulncheck@${GOVULNCHECK_VERSION}`;
const GO_IMAGE = "golang:1.27.3";
const RELEASE_INPUT_PATHS = [
  "Dockerfile", ".dockerignore", "Dockerfile.dockerignore", "LICENSE",
  "go.mod", "go.sum", "cmd", "internal", "migrations",
  ".github/workflows/container-release.yml", "docs/releases/container-policy.md",
  "scripts/build-release-image.mjs", "scripts/check-build-context.mjs",
  "scripts/check-build-context.test.mjs",
  "scripts/release_smoke_probe.go", "scripts/verify-container-release.mjs",
  "scripts/publish-release-image.mjs", "scripts/publish-release-image.test.mjs",
  "scripts/verify-container-release.test.mjs",
];

function die(msg) { throw new Error(`build-release: ${msg}`); }

export function sanitizeGovulncheckFailure(error) {
  const message = typeof error?.message === "string" ? error.message : "";
  const exit = / -> (\d+)(?::|$)/.exec(message)?.[1];
  const exitCode = exit === undefined ? null : Number(exit);
  return {
    exitCode,
    findingsTail: exitCode === null
      ? "tool error: govulncheck binary scan invocation failed"
      : `tool error: govulncheck binary scan exited ${exitCode}`,
  };
}

export function assertGovulncheckClean(exitCode, targetDigest, toolVersion) {
  if (exitCode !== 0)
    die(`govulncheck binary scan exited ${exitCode ?? "unknown"}`);
  if (toolVersion !== GOVULNCHECK_VERSION)
    die(`govulncheck version mismatch: expected ${GOVULNCHECK_VERSION}, got ${toolVersion ?? "unknown"}`);
  if (!DIGEST_RE.test(targetDigest ?? ""))
    die("govulncheck symbol-preserving target digest missing or malformed");
}

export function assertReleaseInputsClean(dirtyOutput) {
  if (typeof dirtyOutput === "string" && dirtyOutput.trim())
    die("release inputs must be committed at the recorded source SHA");
}

export function isArtifactPublishable(licenseInfo, dockerhubNs) {
  return /^resolved:[A-Za-z0-9.+-]+$/.test(licenseInfo ?? "") &&
    dockerhubNs !== "pending-user-namespace";
}

// The manifest records what the committed LICENSE file actually says,
// not what we hope. verify-container-release.mjs requires
// `resolved:<spdx>` for the remote stage; anything unresolvable stays
// pending and keeps publication blocked.
function licenseStatus(root) {
  const p = resolve(root, "LICENSE");
  if (!existsSync(p)) return "pending-user-decision";
  const first = readFileSync(p, "utf8")
    .split("\n").map((l) => l.trim()).find(Boolean) ?? "";
  if (/^MIT License$/i.test(first)) return "resolved:MIT";
  if (/^Apache License$/i.test(first)) return "resolved:Apache-2.0";
  return "pending-user-decision";
}

function run(argv, { input, env, quiet, buffer } = {}) {
  return new Promise((res, rej) => {
    const p = spawn(argv[0], argv.slice(1), {
      cwd: ROOT, env: { ...process.env, ...env },
      stdio: ["pipe", "pipe", "pipe"],
    });
    let out = "", err = "";
    const chunks = [];
    p.stdout.on("data", (d) => {
      if (buffer) chunks.push(d);
      else { const s = d.toString(); out += s; if (!quiet) process.stdout.write(s); }
    });
    p.stderr.on("data", (d) => { const s = d.toString(); err += s; if (!quiet) process.stderr.write(s); });
    p.stdin.on("error", (e) => { if (e.code !== "EPIPE") rej(e); });
    p.stdin.end(input);
    p.on("close", (c) => c === 0 ? res({ out: buffer ? Buffer.concat(chunks) : out, err })
      : rej(new Error(`${argv.join(" ")} -> ${c}: ${err.split("\n").pop() || out.split("\n").pop()}`)));
  });
}

const sha256 = (buf) => createHash("sha256").update(buf).digest("hex");
const DIGEST_RE = /^sha256:[0-9a-f]{64}$/;
const rel = (p) => p.replace(ROOT + "\\", "").replace(ROOT + "/", "").replaceAll("\\", "/");

async function main() {
  const args = {};
  for (let i = 2; i < process.argv.length; i += 2)
    args[process.argv[i].replace(/^--/, "")] = process.argv[i + 1];
  const version = args.version ?? die("--version required");
  const output = resolve(args.output ?? die("--output required"));
  // Docker Hub destination is an owner-provided fact, never a default.
  // Unresolved stays in the manifest as the literal pending marker, which
  // verify-container-release.mjs --stage remote refuses (R24 dual-registry).
  const dockerhubNs = args["dockerhub-namespace"] ?? process.env.DOCKERHUB_NAMESPACE
    ?? "pending-user-namespace";
  if (dockerhubNs !== "pending-user-namespace" &&
      !/^[a-z0-9_-]+\/[a-z0-9._-]{1,100}$/.test(dockerhubNs))
    die(`--dockerhub-namespace '${dockerhubNs}' is not <user>/<repo>`);
  if (!/^v\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$/.test(version))
    die(`version '${version}' is not semver-shaped (v<semver>)`);
  mkdirSync(dirname(output), { recursive: true });
  const outDir = dirname(output);
  if (readdirSync(outDir).length)
    die("release output directory must be empty; use a fresh source-SHA-scoped directory");

  // ---------- 0. exact source snapshot + context gate ----------
  const sourceSha = (await run(["git", "rev-parse", "HEAD"], { quiet: true })).out.trim();
  const dirtyOut = (await run(["git", "status", "--porcelain", "--untracked-files=all",
    "--", ...RELEASE_INPUT_PATHS], { quiet: true })).out.trim();
  const sourceDirty = dirtyOut.length > 0;
  assertReleaseInputsClean(dirtyOut);

  const sourceArchive = resolve(outDir, "release-source.tar");
  const sourceRoot = resolve(outDir, "release-source");
  if (existsSync(sourceArchive) || existsSync(sourceRoot))
    die("source snapshot output already exists; use a fresh SHA-scoped output directory");
  mkdirSync(sourceRoot);
  // Capture Git's tar stream once. Extraction, BuildKit, the scanner, and
  // the smoke helper all consume these same immutable in-memory bytes.
  const sourceArchiveBytes = (await run(["git", "archive", "--format=tar", sourceSha],
    { quiet: true, buffer: true })).out;
  writeFileSync(sourceArchive, sourceArchiveBytes);
  await run(["tar", "-xf", "-", "-C", sourceRoot],
    { input: sourceArchiveBytes, quiet: true });

  const licenseInfo = licenseStatus(sourceRoot);
  const licenseId = /^resolved:(.+)$/.exec(licenseInfo)?.[1];
  const ctxReceipt = resolve(outDir, "context-manifest.json");
  console.log("[build] context privacy gate");
  const contextGate = resolve(sourceRoot, "scripts/check-build-context.mjs");
  await run(["node", contextGate, "--context", sourceRoot,
    "--dockerfile", "Dockerfile", "--verify-sentinels", "--output", ctxReceipt]);
  const contextManifest = JSON.parse(readFileSync(ctxReceipt, "utf8"));
  const buildContextSha = contextManifest.contextHash;
  if (!/^[0-9a-f]{64}$/.test(buildContextSha ?? ""))
    die("build-context receipt has no valid contextHash");
  const contextProofPath = resolve(outDir, "context-proof.json");
  const contextProof = { format: "uptime-context-proof-v1", source_sha: sourceSha,
    build_context_sha256: `sha256:${buildContextSha}` };
  writeFileSync(contextProofPath, JSON.stringify(contextProof, null, 2) + "\n");
  const ctxReceiptSha = `sha256:${sha256(readFileSync(contextProofPath))}`;
  const verifyContextSnapshot = async (name) => {
    const head = (await run(["git", "rev-parse", "HEAD"], { quiet: true })).out.trim();
    if (head !== sourceSha)
      die(`source HEAD moved during release build (${name})`);
    const snapshotPath = resolve(outDir, `context-snapshot-${name}.json`);
    await run(["node", contextGate, "--context", sourceRoot,
      "--dockerfile", "Dockerfile", "--verify-sentinels", "--output", snapshotPath],
    { quiet: true });
    const currentHash = JSON.parse(readFileSync(snapshotPath, "utf8")).contextHash;
    if (currentHash !== buildContextSha)
      die(`build context changed after the committed snapshot (${name})`);
  };

  // ---------- 1. one build, two exports ----------
  // A single buildx invocation emits (a) the daemon image used by
  // scan/smoke and (b) an OCI-layout archive that preserves the image
  // index AND the buildkit attestation manifest. docker save would
  // drop the attestation — the OCI archive is the publish transport.
  const ref = `uptime-platform:${version}`;
  const shaRef = `uptime-platform:sha-${sourceSha.slice(0, 12)}`;
  const created = new Date().toISOString();
  const archPath = resolve(outDir, `uptime-platform-${version}.oci.tar`);
  console.log(`[build] buildx build ${ref} @ ${sourceSha.slice(0, 12)} (daemon + OCI)`);
  await run(["docker", "buildx", "build", "--pull", "--platform", "linux/amd64",
    "--provenance=true",
    "--build-arg", `VERSION=${version}`,
    "--build-arg", `REVISION=${sourceSha}`,
    "--label", `org.opencontainers.image.source=${REPO_URL}`,
    "--label", `org.opencontainers.image.created=${created}`,
    "--label", "org.opencontainers.image.title=uptime-platform-api",
    "--label", "org.opencontainers.image.description=local-first uptime monitoring platform (release candidate)",
    "--label", `org.opencontainers.image.url=${REPO_URL}`,
    ...(licenseId ? ["--label", `org.opencontainers.image.licenses=${licenseId}`] : []),
    "-t", ref, "-t", shaRef,
    "-o", "type=docker", "-o", `type=oci,dest=${archPath}`, "-"],
  { input: sourceArchiveBytes });
  await verifyContextSnapshot("after-image-build");

  // ---------- 2. identity readback (daemon + OCI chain) ----------
  const insp = JSON.parse((await run(["docker", "image", "inspect", ref],
    { quiet: true })).out)[0];
  if (!insp.Config.User || insp.Config.User === "" || insp.Config.User === "0" || insp.Config.User === "root")
    die(`image runs as root/empty user: '${insp.Config.User}'`);
  if (insp.Config.Entrypoint?.[0] !== "/usr/local/bin/uptime-api")
    die(`entrypoint is not direct exec: ${JSON.stringify(insp.Config.Entrypoint)}`);
  const labels = insp.Config.Labels ?? {};

  // Walk the OCI archive: index -> manifest list -> image manifest +
  // attestation manifest. tar entries are pax/ustar; read via bsdtar.
  const tarCat = (name) => run(["tar", "-xOf", rel(archPath), name], { quiet: true })
    .then((r) => r.out); // relative path: bsdtar treats 'D:' as remote
  const ociIndex = JSON.parse(await tarCat("index.json"));
  const listDigest = ociIndex.manifests?.[0]?.digest;
  if (!DIGEST_RE.test(listDigest ?? "")) die("OCI index missing manifest-list digest");
  const ociList = JSON.parse(await tarCat(`blobs/${listDigest.replace(":", "/")}`));
  const imgDesc = ociList.manifests?.find((m) => m.platform?.architecture === "amd64"
    && m.platform?.os === "linux" && !m.annotations?.["vnd.docker.reference.type"]);
  const attDesc = ociList.manifests?.find((m) =>
    m.annotations?.["vnd.docker.reference.type"] === "attestation-manifest");
  if (!attDesc) die("OCI manifest list has no attestation manifest (--provenance failed?)");
  if (!imgDesc) die("OCI manifest list missing linux/amd64 image manifest");
  const ociImg = JSON.parse(await tarCat(`blobs/${imgDesc.digest.replace(":", "/")}`));
  const configDigest = ociImg.config?.digest;
  const layers = (ociImg.layers ?? []).map((l) => l.digest);
  // Same-build binding: the daemon-side image id must equal the
  // manifest-list digest (containerd store keys on the index).
  const daemonId = insp.Id;
  if (daemonId !== listDigest)
    die(`daemon Id ${daemonId} != OCI manifest-list ${listDigest} — outputs diverged`);
  const archSha = `sha256:${sha256(readFileSync(archPath))}`;

  // ---------- 4. scan + SBOM (pinned trivy image) ----------
  console.log(`[build] trivy scan (${TRIVY_IMAGE})`);
  const scanJson = resolve(outDir, "trivy-report.json");
  const sbomPath = resolve(outDir, "sbom.spdx.json");
  const trivyBase = ["docker", "run", "--rm",
    "-v", "/var/run/docker.sock:/var/run/docker.sock",
    "-v", "uptime-trivy-db:/root/.cache/trivy",
    "-v", `${outDir}:/out`, TRIVY_IMAGE];
  const scan = await run([...trivyBase, "image", "--format", "json",
    "--severity", "CRITICAL,HIGH", "-o", `/out/trivy-report.json`, ref]);
  // DB identity from the persisted trivy metadata, not log parsing.
  let dbTs = "unparsed";
  try {
    const meta = JSON.parse((await run(["docker", "run", "--rm",
      "--entrypoint", "sh", "-v", "uptime-trivy-db:/c", TRIVY_IMAGE,
      "-c", "cat /c/db/metadata.json"], { quiet: true })).out);
    dbTs = `updatedAt=${meta.UpdatedAt} schema=${meta.Version}`;
  } catch { dbTs = `unparsed (run: ${scan.err.split("\n").find((l) => /vulndb/i.test(l))?.trim() ?? "none"})`; }
  const report = JSON.parse(readFileSync(scanJson, "utf8"));
  const vulns = (report.Results ?? []).flatMap((r) => r.Vulnerabilities ?? []);
  const crit = vulns.filter((v) => v.Severity === "CRITICAL").length;
  const high = vulns.filter((v) => v.Severity === "HIGH").length;
  await run([...trivyBase, "image", "--format", "spdx-json",
    "-o", "/out/sbom.spdx.json", ref], { quiet: true });

  // ---------- 5. govulncheck (pinned, container lane) ----------
  // The runtime binary is stripped with -s -w, which removes symbols the
  // govulncheck binary analyzer needs for reachability. Build a companion
  // from the same committed source/version/platform without stripping, then
  // bind its digest and identity to this image in the release manifest.
  // Source mode remains unavailable because the pinned analyzer's SSA parser
  // panics on this toolchain's AST.
  console.log(`[build] govulncheck ${GOVULNCHECK} (symbol-preserving binary mode)`);
  let goFindings = "unparsed", goExit = null, goBinaryDigest = null, goToolVersion = null;
  const scanTargetPath = resolve(outDir, "govulncheck-target");
  try {
    await verifyContextSnapshot("before-source-scan");
    const scanCmd = `mkdir -p /src && tar -xf - -C /src; extract_ec=$?; ` +
      `if [ "$extract_ec" -ne 0 ]; then echo EXIT:$extract_ec; ` +
      `echo 'tool error: committed source archive extraction failed'; else ` +
      `cd /src && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -buildvcs=false ` +
      `-ldflags="-X main.version=${version} -X main.revision=${sourceSha}" ` +
      `-o /out/govulncheck-target ./cmd/api >/tmp/gobuild.txt 2>&1; build_ec=$?; ` +
      `if [ "$build_ec" -ne 0 ]; then echo EXIT:$build_ec; ` +
      `echo 'tool error: same-source scanner binary build failed'; tail -15 /tmp/gobuild.txt; else ` +
      `go install ${GOVULNCHECK} >/tmp/govuln-install.txt 2>&1; install_ec=$?; ` +
      `if [ "$install_ec" -ne 0 ]; then echo EXIT:$install_ec; ` +
      `echo 'tool error: govulncheck installation failed'; tail -15 /tmp/govuln-install.txt; else ` +
      `govulncheck -version >/tmp/govc-version.txt 2>&1; version_ec=$?; ` +
      `if [ "$version_ec" -ne 0 ]; then echo EXIT:$version_ec; ` +
      `echo 'tool error: govulncheck version check failed'; tail -5 /tmp/govc-version.txt; else ` +
      `tool_version=$(grep -Eo 'v[0-9]+\\.[0-9]+\\.[0-9]+' /tmp/govc-version.txt | head -1); ` +
      `echo GOVULNCHECK_VERSION:$tool_version; ` +
      `if [ "$tool_version" != "${GOVULNCHECK_VERSION}" ]; then echo EXIT:90; ` +
      `echo 'tool error: govulncheck version does not match the pinned release'; else ` +
      `govulncheck -mode binary -format text /out/govulncheck-target >/tmp/govc.txt 2>&1; ec=$?; ` +
      `echo EXIT:$ec; tail -15 /tmp/govc.txt; fi; fi; fi; fi; fi`;
    const gv = await run(["docker", "run", "--rm", "-i",
      "-v", `${outDir}:/out`, "-w", "/", GO_IMAGE, "sh", "-c", scanCmd],
      { input: sourceArchiveBytes, quiet: true });
    const lines = gv.out.trim().split("\n");
    const exit = /^EXIT:(\d+)$/.exec(lines.find((line) => line.startsWith("EXIT:")) ?? "")?.[1];
    goExit = exit === undefined ? null : Number(exit);
    goToolVersion = lines.find((line) => line.startsWith("GOVULNCHECK_VERSION:"))
      ?.slice("GOVULNCHECK_VERSION:".length).trim() || null;
    if (existsSync(scanTargetPath))
      goBinaryDigest = `sha256:${sha256(readFileSync(scanTargetPath))}`;
    goFindings = lines.filter((line) => !line.startsWith("EXIT:") &&
      !line.startsWith("GOVULNCHECK_VERSION:")).join("\n").slice(-600);
  } catch (e) {
    const failure = sanitizeGovulncheckFailure(e);
    goExit = failure.exitCode;
    goFindings = failure.findingsTail;
  }
  assertGovulncheckClean(goExit, goBinaryDigest, goToolVersion);
  await verifyContextSnapshot("after-source-scan");

  // ---------- 6. smoke: real migrated DB + runtime contract ----------
  // The API exits when the DB is unreachable at startup, so the smoke
  // brings its own disposable postgres + migrate on a scratch network.
  // Dummy database creds only; one read-only HTTPS GET validates the
  // final image's system CA bundle and outbound path.
  console.log("[build] image smoke (scratch pg + migrate + app)");
  const tag = Date.now();
  const net = `rel-smoke-net-${tag}`, pg = `rel-smoke-pg-${tag}`, app = `rel-smoke-app-${tag}`;
  const dsn = `postgres://smoke:smoke-dummy@${pg}:5432/smoke?sslmode=disable`;
  const probePath = resolve(outDir, "release-smoke-probe");
  const smokeBuildCmd = "mkdir -p /src && tar -xf - -C /src && cd /src && " +
    "go build -trimpath -buildvcs=false -o /out/release-smoke-probe ./scripts/release_smoke_probe.go";
  await run(["docker", "run", "--rm", "-i", "-e", "CGO_ENABLED=0", "-e", "GOOS=linux", "-e", "GOARCH=amd64",
    "-v", `${outDir}:/out`, "-w", "/", GO_IMAGE, "sh", "-c", smokeBuildCmd],
  { input: sourceArchiveBytes, quiet: true });
  const tlsProbeSha = `sha256:${createHash("sha256").update(readFileSync(probePath)).digest("hex")}`;
  const committedBuildScript = (await run(["git", "show",
    `${sourceSha}:scripts/build-release-image.mjs`], { quiet: true })).out;
  const buildScriptSha = `sha256:${sha256(Buffer.from(committedBuildScript, "utf8"))}`;
  const smoke = { ready200: false, liveDbFree: false, caChainOutbound: false,
    migratedDb: false, readOnlyRootfs: false, capabilitiesDropped: false,
    noNewPrivileges: false, sigterm_s: null };
  const kill = (n) => run(["docker", "rm", "-f", n], { quiet: true }).catch(() => {});
  try {
    await run(["docker", "network", "create", net], { quiet: true });
    await run(["docker", "run", "-d", "--rm", "--name", pg, "--network", net,
      "-e", "POSTGRES_USER=smoke", "-e", "POSTGRES_PASSWORD=smoke-dummy",
      "-e", "POSTGRES_DB=smoke", "postgres:17.11"], { quiet: true });
    for (let i = 0; i < 30; i++) {
      const ok = await run(["docker", "exec", pg, "pg_isready", "-U", "smoke", "-d", "smoke"],
        { quiet: true }).then(() => true).catch(() => false);
      if (ok) break;
      await new Promise((r) => setTimeout(r, 1000));
    }
    await verifyContextSnapshot("before-migrations");
    await run(["docker", "run", "--rm", "--network", net,
      "-v", `${resolve(sourceRoot, "migrations")}:/migrations:ro`,
      "migrate/migrate:v4.20.1",
      "-path", "/migrations", "-database", dsn, "up"], { quiet: true });
    smoke.migratedDb = true;
    await verifyContextSnapshot("after-migrations");
    await run(["docker", "run", "-d", "--rm", "--name", app, "--network", net,
      "-p", "127.0.0.1:18099:8080",
      "--read-only", "--tmpfs", "/tmp:size=8m,uid=65532,gid=65532",
      "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
      "-e", "APP_ENV=local", "-e", "HTTP_HOST=0.0.0.0", "-e", "HTTP_PORT=8080",
      "-e", `DATABASE_URL=${dsn}`, "-e", `ENGINE_DATABASE_URL=${dsn}`,
      "-e", `MIGRATION_DATABASE_URL=${dsn}`, "-e", "NOTIFICATIONS_ENABLED=false",
      ref], { quiet: true }).catch((e) => die(`smoke run: ${e.message}`));
    const runInspect = JSON.parse((await run(["docker", "inspect", app], { quiet: true })).out)[0];
    smoke.readOnlyRootfs = runInspect.HostConfig.ReadonlyRootfs === true;
    smoke.capabilitiesDropped = runInspect.HostConfig.CapDrop?.includes("ALL") ?? false;
    smoke.noNewPrivileges = runInspect.HostConfig.SecurityOpt?.includes("no-new-privileges:true") ?? false;
    if (!smoke.readOnlyRootfs || !smoke.capabilitiesDropped || !smoke.noNewPrivileges)
      die("smoke container is missing read-only rootfs, cap-drop ALL, or no-new-privileges");
    for (let i = 0; i < 40 && !smoke.ready200; i++) {
      const r = await fetch("http://localhost:18099/health/ready").catch(() => null);
      if (r?.status === 200) smoke.ready200 = true;
      else await new Promise((r) => setTimeout(r, 1000));
    }
    if (smoke.ready200) {
      // Run a static probe in the final image with its default non-root
      // user and system CA bundle. The probe is mounted read-only because
      // the release image has a read-only root filesystem.
      const probeSource = probePath.replaceAll("\\", "/");
      await run(["docker", "run", "--rm", "--network", net, "--read-only",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
        "--mount", `type=bind,source=${probeSource},target=/usr/local/bin/release-smoke-probe,readonly`,
        "--entrypoint", "/usr/local/bin/release-smoke-probe", ref, REPO_URL], { quiet: true });
      smoke.caChainOutbound = true;

      // Stop PostgreSQL and require readiness to fail while liveness
      // continues to return 200. This proves the route is DB-free at runtime.
      await run(["docker", "stop", "-t", "5", pg], { quiet: true });
      for (let i = 0; i < 20 && !smoke.liveDbFree; i++) {
        const [live, ready] = await Promise.all([
          fetch("http://localhost:18099/health/live").catch(() => null),
          fetch("http://localhost:18099/health/ready").catch(() => null),
        ]);
        if (live?.status === 200 && ready?.status !== 200) smoke.liveDbFree = true;
        else await new Promise((r) => setTimeout(r, 1000));
      }

      const t0 = Date.now();
      await run(["docker", "stop", "-t", "20", app], { quiet: true });
      smoke.sigterm_s = +((Date.now() - t0) / 1000).toFixed(2);
    }
  } finally {
    await kill(app); await kill(pg);
    await run(["docker", "network", "rm", net], { quiet: true }).catch(() => {});
  }
  if (!smoke.ready200) die("smoke: /health/ready never answered 200");
  if (!smoke.liveDbFree) die("smoke: /health/live did not remain 200 with PostgreSQL stopped and readiness failing");
  if (!smoke.caChainOutbound) die("smoke: final image did not verify the outbound HTTPS certificate chain");
  if (smoke.sigterm_s > 15) die(`smoke: SIGTERM stop ${smoke.sigterm_s}s exceeds contract`);

  // ---------- 7. provenance (subject-bound sidecar) ----------
  // Subject = the manifest-list digest: the identity a registry tag
  // will resolve to after push. Same subject for SBOM + provenance.
  const subject = listDigest;
  const provPath = resolve(outDir, "provenance.json");
  const provenance = {
    _type: "https://in-toto.io/Statement/v1",
    subject: [{ name: ref, digest: { sha256: subject.replace(/^sha256:/, "") } }],
    predicateType: "https://slsa.dev/provenance/v1",
    predicate: {
      buildDefinition: {
        buildType: "https://devin.local/dockerfile-build/v1",
        externalParameters: { dockerfile: "Dockerfile", platform: "linux/amd64",
          version, revision: sourceSha, context_receipt_sha256: ctxReceiptSha,
          build_script_sha256: buildScriptSha, tls_probe_sha256: tlsProbeSha,
          smoke_contract: "docs/releases/container-policy.md#4-pre-publish-gates" },
      },
      runDetails: { builder: { id: `docker ${(await run(["docker", "version", "--format", "{{.Server.Version}}"], { quiet: true })).out.trim()}` },
        metadata: { startedOn: created, finishedOn: new Date().toISOString() } },
    },
  };
  writeFileSync(provPath, JSON.stringify(provenance, null, 2));

  // ---------- 8. manifest ----------
  const manifest = {
    format: "uptime-release-manifest-v1",
    version, source_sha: sourceSha, source_dirty: sourceDirty,
    built_at: created, platform: "linux/amd64",
    build_context_sha256: `sha256:${buildContextSha}`,
    image: {
      reference: ref,
      index_digest: listDigest,
      image_manifest_digest: imgDesc.digest,
      config_digest: configDigest,
      layer_digests: layers,
      attestation_digest: attDesc.digest,
      archive: rel(archPath),
      archive_sha256: archSha,
      transport: "oci-layout",
      transport_notes:
        "OCI-layout archive from the same buildx invocation that loaded " +
        "the daemon image; index->manifest-list->{image,attestation} " +
        "digest chain is re-verified by verify-container-release.mjs. " +
        "Publish via skopeo/imagetools from this archive preserves " +
        "attestations; docker save/load does not and is not the parity path.",
    },
    base: { image: "gcr.io/distroless/static-debian12:nonroot",
      digest: "sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab" },
    labels,
    license_status: licenseInfo,
    sbom: { format: "spdx-json", path: rel(sbomPath),
      subject_digest: subject },
    provenance: { mode: "sidecar-json", path: rel(provPath),
      subject_digest: subject },
    scan: {
      image_scanner: { tool: "trivy", tool_version: "0.76.0",
        image: TRIVY_IMAGE, db_timestamp: dbTs,
        critical: crit, high: high,
        findings: vulns.map((v) => ({ cve: v.VulnerabilityID,
          severity: v.Severity, package: v.PkgName,
          installed_version: v.InstalledVersion, fixed_version: v.FixedVersion ?? null })),
        exceptions: [] },
      source_scanner: { tool: "govulncheck", tool_version: goToolVersion,
        mode: "binary", exit_code: goExit,
        target: { kind: "source-matched-symbol-preserving-companion",
          source_sha: sourceSha, version, platform: "linux/amd64",
          build_context_sha256: `sha256:${buildContextSha}`,
          runtime_image_digest: subject, artifact: "govulncheck-target",
          sha256: goBinaryDigest },
        limitation: "source mode unavailable because x/tools SSA panics on this toolchain's AST; binary mode scans a same-source/version/platform companion with Go symbols preserved, while the runtime image remains stripped",
        findings_tail: goFindings },
    },
    smoke: {
      ready_probe_200: smoke.ready200,
      live_db_free: smoke.liveDbFree,
      ca_chain_outbound: smoke.caChainOutbound,
      sigterm_stop_s: smoke.sigterm_s,
      migrated_db: smoke.migratedDb,
      nonroot_user: insp.Config.User,
      read_only_rootfs: smoke.readOnlyRootfs,
      capabilities_dropped: smoke.capabilitiesDropped,
      no_new_privileges: smoke.noNewPrivileges,
      build_script_sha256: buildScriptSha,
      tls_probe_sha256: tlsProbeSha,
    },
    context_receipt_sha256: ctxReceiptSha,
    registries: {
      ghcr: "ghcr.io/jasontm17/uptime-monitoring-platform",
      dockerhub: dockerhubNs,
    },
    publishable: isArtifactPublishable(licenseInfo, dockerhubNs),
    // publishable = artifact-level prereqs met (license resolved + namespace
    // recorded). It is NOT publish authority: an actual push still requires
    // the owner's explicit instruction and registry credentials.
  };
  writeFileSync(output, JSON.stringify(manifest, null, 2));
  console.log(`[build] manifest: ${output}`);
  console.log(`[build] crit=${crit} high=${high} subject=${subject.slice(0, 19)}… ` +
    `archive=${(statSync(archPath).size / 1048576).toFixed(1)}MiB smoke_sigterm=${smoke.sigterm_s}s`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url))
  main().catch((e) => { console.error(e.message ?? e); process.exit(1); });
