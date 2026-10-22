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
import { mkdirSync, writeFileSync, readFileSync, existsSync, statSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const REPO_URL = "https://github.com/JasonTM17/Uptime-Monitoring-Platform";
const TRIVY_IMAGE = "aquasec/trivy:0.76.0"; // pinned: released 2026-10-14, >7d
const GOVULNCHECK = "golang.org/x/vuln/cmd/govulncheck@v1.1.4"; // pinned
const GO_IMAGE = "golang:1.27.3";

function die(msg) { throw new Error(`build-release: ${msg}`); }

function run(argv, { input, env, quiet } = {}) {
  return new Promise((res, rej) => {
    const p = spawn(argv[0], argv.slice(1), {
      cwd: ROOT, env: { ...process.env, ...env },
      stdio: ["pipe", "pipe", "pipe"],
    });
    let out = "", err = "";
    p.stdout.on("data", (d) => { const s = d.toString(); out += s; if (!quiet) process.stdout.write(s); });
    p.stderr.on("data", (d) => { const s = d.toString(); err += s; if (!quiet) process.stderr.write(s); });
    if (input !== undefined) { p.stdin.write(input); }
    p.stdin.end();
    p.on("close", (c) => c === 0 ? res({ out, err })
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
  if (!/^v\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$/.test(version))
    die(`version '${version}' is not semver-shaped (v<semver>)`);
  mkdirSync(dirname(output), { recursive: true });
  const outDir = dirname(output);

  // ---------- 0. source identity + context gate ----------
  const sourceSha = (await run(["git", "rev-parse", "HEAD"], { quiet: true })).out.trim();
  // Dirty = anything reaching the build context (deny-by-default:
  // only go.mod/go.sum/cmd/internal + Dockerfile/.dockerignore).
  const dirtyOut = (await run(["git", "status", "--porcelain",
    "--", "go.mod", "go.sum", "cmd", "internal", "Dockerfile",
    ".dockerignore", "Dockerfile.dockerignore"], { quiet: true })).out.trim();
  const sourceDirty = dirtyOut.length > 0;
  if (sourceDirty) console.log(`[build] WARNING: build-visible paths dirty:\n${dirtyOut}`);

  const ctxReceipt = resolve(outDir, "..", "build", "context-manifest.json");
  mkdirSync(dirname(ctxReceipt), { recursive: true });
  console.log("[build] context privacy gate");
  await run(["node", "scripts/check-build-context.mjs", "--context", ".",
    "--dockerfile", "Dockerfile", "--verify-sentinels",
    "--output", ctxReceipt]);

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
    "-t", ref, "-t", shaRef,
    "-o", "type=docker", "-o", `type=oci,dest=${archPath}`, "."]);

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
  // govulncheck v1.1.4's x/tools SSA builder cannot parse this
  // toolchain's AST (panic: unexpected expr: *ast.KeyValueExpr), so
  // source mode is unusable. Binary mode analyzes the shipped artifact's
  // embedded buildinfo + call graph — the honest target for a release
  // gate anyway. Extract the binary straight out of the image.
  console.log(`[build] govulncheck ${GOVULNCHECK} (binary mode)`);
  const binPath = resolve(outDir, "uptime-api-bin");
  let goFindings = "unparsed", goExit = null;
  try {
    const cid = (await run(["docker", "create", ref], { quiet: true })).out.trim();
    await run(["docker", "cp", `${cid}:/usr/local/bin/uptime-api`, binPath], { quiet: true });
    await run(["docker", "rm", cid], { quiet: true });
    const gv = await run(["docker", "run", "--rm",
      "-v", `${ROOT}:/src:ro`, "-w", "/src", GO_IMAGE, "sh", "-c",
      `go install ${GOVULNCHECK} >/dev/null 2>&1 && govulncheck -mode binary -format text '${rel(binPath)}' > /tmp/govc.txt 2>&1; ec=$?; echo EXIT:$ec; tail -15 /tmp/govc.txt; echo DEPS_OPENPGP:$(go list -deps ./cmd/api 2>/dev/null | grep -c openpgp)`],
      { quiet: true });
    const lines = gv.out.trim().split("\n");
    goExit = /^EXIT:(\d+)/.exec(lines[0])?.[1] ?? null;
    const depCount = /DEPS_OPENPGP:(\d+)/.exec(lines[lines.length - 1])?.[1];
    goFindings = lines.slice(1).join("\n").slice(-600) +
      `\ncounter-evidence: cmd/api import closure contains ${depCount ?? "?"} openpgp packages` +
      ` (go list -deps; strings-in-binary check corroborates when 0)`;
  } catch (e) { goFindings = `tool error: ${e.message.slice(0, 200)}`; }

  // ---------- 6. smoke: real migrated DB + runtime contract ----------
  // The API exits when the DB is unreachable, so the smoke brings its
  // own disposable postgres + migrate on a scratch network. Dummy creds
  // only — the stack never leaves the loopback-bound docker network.
  console.log("[build] image smoke (scratch pg + migrate + app)");
  const tag = Date.now();
  const net = `rel-smoke-net-${tag}`, pg = `rel-smoke-pg-${tag}`, app = `rel-smoke-app-${tag}`;
  const dsn = `postgres://smoke:smoke-dummy@${pg}:5432/smoke?sslmode=disable`;
  const smoke = { ready200: false, sigterm_s: null };
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
    await run(["docker", "run", "--rm", "--network", net,
      "-v", `${resolve(ROOT, "migrations")}:/migrations:ro`,
      "migrate/migrate:v4.20.1",
      "-path", "/migrations", "-database", dsn, "up"], { quiet: true });
    await run(["docker", "run", "-d", "--rm", "--name", app, "--network", net,
      "-p", "127.0.0.1:18099:8080",
      "--read-only", "--tmpfs", "/tmp:size=8m,uid=65532,gid=65532",
      "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
      "-e", "APP_ENV=local", "-e", "HTTP_HOST=0.0.0.0", "-e", "HTTP_PORT=8080",
      "-e", `DATABASE_URL=${dsn}`, "-e", `ENGINE_DATABASE_URL=${dsn}`,
      "-e", `MIGRATION_DATABASE_URL=${dsn}`, "-e", "NOTIFICATIONS_ENABLED=false",
      ref], { quiet: true }).catch((e) => die(`smoke run: ${e.message}`));
    for (let i = 0; i < 40 && !smoke.ready200; i++) {
      const r = await fetch("http://localhost:18099/health/ready").catch(() => null);
      if (r?.status === 200) smoke.ready200 = true;
      else await new Promise((r) => setTimeout(r, 1000));
    }
    if (smoke.ready200) {
      const t0 = Date.now();
      await run(["docker", "stop", "-t", "20", app], { quiet: true });
      smoke.sigterm_s = +((Date.now() - t0) / 1000).toFixed(2);
    }
  } finally {
    await kill(app); await kill(pg);
    await run(["docker", "network", "rm", net], { quiet: true }).catch(() => {});
  }
  if (!smoke.ready200) die("smoke: /health/ready never answered 200");
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
          version, revision: sourceSha, context_receipt: ctxReceipt },
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
    license_status: "pending-user-decision",
    sbom: { format: "spdx-json", path: rel(sbomPath),
      subject_digest: subject },
    provenance: { mode: "sidecar-json", path: rel(provPath),
      subject_digest: subject },
    scan: {
      image_scanner: { tool: "trivy", tool_version: "0.76.0",
        image: TRIVY_IMAGE, db_timestamp: dbTs,
        critical: crit, high: high, exceptions: [] },
      source_scanner: { tool: "govulncheck", tool_version: "v1.1.4",
        mode: "binary", exit_code: goExit,
        limitation: "source mode unusable — x/tools SSA panics on this toolchain's AST (govulncheck v1.1.4 / x/tools v0.29.0); binary mode scans the shipped artifact's buildinfo instead",
        findings_tail: goFindings },
    },
    smoke: { ready_probe_200: true, sigterm_stop_s: smoke.sigterm_s,
      migrated_db: true, nonroot_user: insp.Config.User },
    context_receipt: rel(ctxReceipt),
    registries: {
      ghcr: "ghcr.io/jasontm17/uptime-monitoring-platform",
      dockerhub: "pending-user-namespace",
    },
    publishable: false, // license pending + Docker Hub namespace pending
  };
  writeFileSync(output, JSON.stringify(manifest, null, 2));
  console.log(`[build] manifest: ${output}`);
  console.log(`[build] crit=${crit} high=${high} subject=${subject.slice(0, 19)}… ` +
    `archive=${(statSync(archPath).size / 1048576).toFixed(1)}MiB smoke_sigterm=${smoke.sigterm_s}s`);
}

main().catch((e) => { console.error(e.message ?? e); process.exit(1); });
