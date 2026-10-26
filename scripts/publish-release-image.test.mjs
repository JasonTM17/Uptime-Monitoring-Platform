// C85 publish contract tests — verdict logic + workflow trust-boundary
// static analysis. Run: node --test scripts/publish-release-image.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { summarizeVerdict, planTags, REGISTRIES, publishAfterArtifactVerification,
  verifyReleaseArtifactBeforePublish } from "./publish-release-image.mjs";
import { assertGovulncheckClean, assertReleaseInputsClean, isArtifactPublishable,
  sanitizeGovulncheckFailure } from "./build-release-image.mjs";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const wf = readFileSync(resolve(ROOT, ".github/workflows/container-release.yml"), "utf8");
const builder = readFileSync(resolve(ROOT, "scripts/build-release-image.mjs"), "utf8");
const publisher = readFileSync(resolve(ROOT, "scripts/publish-release-image.mjs"), "utf8");

const m = { version: "v0.1.0", source_sha: "a".repeat(40),
  image: { index_digest: `sha256:${"b".repeat(64)}` } };

test("planTags = version + source sha tag, never latest", () => {
  assert.deepEqual(planTags(m), ["v0.1.0", `sha-${"a".repeat(12)}`]);
  assert.ok(!planTags(m).includes("latest"));
});

test("summarizeVerdict: both verified = PASS", () => {
  assert.equal(summarizeVerdict([{ verified: true }, { verified: true }]), "PASS");
});

test("summarizeVerdict: one verified = PARTIAL", () => {
  assert.equal(summarizeVerdict([{ verified: true }, { verified: false }]), "PARTIAL");
});

test("summarizeVerdict: none verified = FAIL", () => {
  assert.equal(summarizeVerdict([{ verified: false }, { verified: false }]), "FAIL");
});

test("summarizeVerdict: all dry-run = NOT_RUN", () => {
  assert.equal(summarizeVerdict([{ dry_run: true }, { dry_run: true }]), "NOT_RUN");
});

test("workflow has no pull_request/fork trigger", () => {
  const triggers = wf.match(/^on:[\s\S]*?(?=^\w)/m)?.[0] ?? "";
  assert.ok(!/pull_request/.test(triggers), "pull_request trigger present");
  assert.ok(!/pull_request_target/.test(triggers), "pull_request_target present");
  assert.ok(/tags:\s*\["v\*"\]/.test(wf), "release-tag trigger missing");
});

test("workflow secrets never ride a PR context", () => {
  // secrets.* may only appear under env: inside publish jobs — assert
  // the file never references secrets in an if: condition on PR events.
  assert.ok(!/github\.event_name == 'pull_request'[\s\S]*secrets\./.test(wf));
  assert.ok(/GHCR_TOKEN: \$\{\{ secrets\.GITHUB_TOKEN \}\}/.test(wf));
  assert.ok(/DOCKERHUB_TOKEN: \$\{\{ secrets\.DOCKERHUB_TOKEN \}\}/.test(wf));
});

test("every uses: is pinned to a full 40-hex SHA", () => {
  const uses = [...wf.matchAll(/uses: ([^\s#]+)/g)].map((x) => x[1]);
  assert.ok(uses.length >= 4, "expected >=4 pinned actions");
  for (const u of uses)
    assert.match(u, /@[0-9a-f]{40}$/, `unpinned/mutable action: ${u}`);
});

test("release is serialized, never cancelled mid-publish", () => {
  assert.ok(/concurrency:[\s\S]*group: container-release/.test(wf));
  assert.ok(/cancel-in-progress: false/.test(wf));
});

test("least-privilege permissions: default read, packages only on ghcr job", () => {
  assert.ok(/^permissions:\n  contents: read$/m.test(wf));
  const ghcr = wf.match(/publish-ghcr:[\s\S]*?(?=^  \w)/m)?.[0] ?? "";
  assert.ok(/packages: write/.test(ghcr), "ghcr job missing packages: write");
  const dh = wf.match(/publish-dockerhub:[\s\S]*?(?=^  \w)/m)?.[0] ?? "";
  assert.ok(!/packages: write/.test(dh), "dockerhub job has unneeded packages: write");
});

test("registries map uses documented secret names only", () => {
  assert.equal(REGISTRIES.ghcr.tok_env, "GHCR_TOKEN");
  assert.equal(REGISTRIES.dockerhub.user_env, "DOCKERHUB_USERNAME");
  assert.equal(REGISTRIES.dockerhub.tok_env, "DOCKERHUB_TOKEN");
});

test("build job requires and passes the configured Docker Hub image reference", () => {
  const buildJob = wf.match(/^  build-verify:[\s\S]*?(?=^  publish-ghcr:)/m)?.[0] ?? "";
  const step = buildJob.match(/- name: build \+ attest \+ scan[\s\S]*?--output artifacts\/release\/image-manifest\.json/)?.[0] ?? "";
  assert.match(step, /DOCKERHUB_NAMESPACE: \$\{\{ vars\.DOCKERHUB_NAMESPACE \}\}/);
  assert.match(step, /test -n "\$DOCKERHUB_NAMESPACE"[^\n]*exit 3/);
  const guardIndex = step.indexOf("test -n \"$DOCKERHUB_NAMESPACE\"");
  const builderIndex = step.indexOf("node scripts/build-release-image.mjs");
  assert.ok(guardIndex >= 0 && builderIndex > guardIndex, "namespace guard must precede the build");
  assert.match(step, /--dockerhub-namespace "\$DOCKERHUB_NAMESPACE"/);
});

test("Docker Hub prerequisites gate the build and both publish jobs", () => {
  const prerequisites = wf.match(/^  release-prerequisites:[\s\S]*?(?=^  build-verify:)/m)?.[0] ?? "";
  const buildJob = wf.match(/^  build-verify:[\s\S]*?(?=^  publish-ghcr:)/m)?.[0] ?? "";
  const ghcrJob = wf.match(/^  publish-ghcr:[\s\S]*?(?=^  publish-dockerhub:)/m)?.[0] ?? "";
  const dockerHubJob = wf.match(/^  publish-dockerhub:[\s\S]*?(?=^  release-summary:)/m)?.[0] ?? "";
  assert.match(prerequisites, /DOCKERHUB_USERNAME: \$\{\{ vars\.DOCKERHUB_USERNAME \}\}/);
  assert.match(prerequisites, /DOCKERHUB_TOKEN: \$\{\{ secrets\.DOCKERHUB_TOKEN \}\}/);
  assert.match(prerequisites, /DOCKERHUB_NAMESPACE: \$\{\{ vars\.DOCKERHUB_NAMESPACE \}\}/);
  assert.match(prerequisites, /test -n "\$DOCKERHUB_USERNAME"/);
  assert.match(prerequisites, /test -n "\$DOCKERHUB_TOKEN"/);
  assert.match(prerequisites, /test -n "\$DOCKERHUB_NAMESPACE"/);
  assert.match(prerequisites, /DOCKERHUB_NAMESPACE malformed/);
  assert.match(buildJob, /needs: release-prerequisites/);
  assert.match(ghcrJob, /needs: build-verify/);
  assert.match(dockerHubJob, /needs: build-verify/);
});

test("Docker Hub username is a variable and its token remains secret-only", () => {
  const job = wf.match(/^  publish-dockerhub:[\s\S]*?(?=^  release-summary:)/m)?.[0] ?? "";
  assert.match(job, /DOCKERHUB_USERNAME: \$\{\{ vars\.DOCKERHUB_USERNAME \}\}/);
  assert.match(job, /DOCKERHUB_TOKEN: \$\{\{ secrets\.DOCKERHUB_TOKEN \}\}/);
  assert.doesNotMatch(job, /DOCKERHUB_USERNAME: \$\{\{ secrets\./);
  assert.doesNotMatch(job, /--override-ref/);
});

test("publisher jobs check out the exact workflow source before the artifact", () => {
  const jobs = [
    wf.match(/^  publish-ghcr:[\s\S]*?(?=^  publish-dockerhub:)/m)?.[0] ?? "",
    wf.match(/^  publish-dockerhub:[\s\S]*?(?=^  release-summary:)/m)?.[0] ?? "",
  ];
  for (const job of jobs) {
    const checkout = job.indexOf("actions/checkout@");
    const exactSha = job.indexOf("ref: ${{ github.sha }}");
    const artifact = job.indexOf("actions/download-artifact@");
    const publisher = job.indexOf("node scripts/publish-release-image.mjs");
    assert.ok(checkout >= 0 && exactSha > checkout && artifact > exactSha,
      "publisher must checkout github.sha before downloading the artifact");
    assert.ok(publisher > artifact, "publisher CLI should run after artifact download");
  }
});

test("publisher runs the local artifact verifier before any registry copy", () => {
  const main = publisher.slice(publisher.indexOf("async function main()"));
  const gate = main.indexOf("publishAfterArtifactVerification(mpath");
  const copy = main.indexOf("publishOne(m, d, ref");
  assert.ok(gate >= 0 && copy > gate, "local verifier must guard the registry-copy loop");
  assert.match(publisher, /"--stage", "local"/);
});

test("failed artifact verification prevents the publisher operation from starting", async () => {
  const events = [];
  await assert.rejects(publishAfterArtifactVerification("image-manifest.json", async () => {
    events.push("registry-copy");
  }, async () => {
    events.push("verification");
    throw new Error("tampered artifact rejected");
  }), /tampered artifact rejected/);
  assert.deepEqual(events, ["verification"]);
});

test("pre-publish verifier requires a PASS receipt from local-stage validation", async () => {
  let verifierArgs;
  await assert.rejects(verifyReleaseArtifactBeforePublish("image-manifest.json", async (argv) => {
    verifierArgs = argv;
    const report = argv[argv.indexOf("--output") + 1];
    writeFileSync(report, JSON.stringify({ verdict: "FAIL" }));
  }), /failed pre-publish verification/);
  assert.ok(verifierArgs.includes(resolve(ROOT, "scripts/verify-container-release.mjs")));
  assert.deepEqual(verifierArgs.slice(-2), ["--stage", "local"]);
});

test("release artifact upload contains only the reviewed publication payload", () => {
  const paths = wf.match(/name: release-artifact\n\s+path:\s*\|?\s*\n([\s\S]*?)\n\s+if-no-files-found:/)?.[1]
    ?.split(/\r?\n/).map((line) => line.trim()).filter(Boolean) ?? [];
  assert.deepEqual(paths, [
    "artifacts/release/image-manifest.json",
    "artifacts/release/uptime-platform-*.oci.tar",
    "artifacts/release/sbom.spdx.json",
    "artifacts/release/provenance.json",
    "artifacts/release/govulncheck-target",
    "artifacts/release/context-proof.json",
  ]);
  assert.doesNotMatch(paths.join("\n"), /context-manifest\.json|release-source/);
  assert.doesNotMatch(wf, /name: release-artifact\n\s+path:\s*artifacts\/release\/?(?:\r?\n|$)/);
});

test("distributed manifest and provenance record only the context receipt hash", () => {
  assert.match(builder, /const ctxReceiptSha = `sha256:\$\{sha256\(readFileSync\(contextProofPath\)\)\}`/);
  assert.equal((builder.match(/context_receipt_sha256: ctxReceiptSha/g) ?? []).length, 2);
  assert.doesNotMatch(builder, /context_receipt:\s*(?:ctxReceipt|rel\(ctxReceipt\))/);
});

test("govulncheck failures retain exit status without exposing workspace paths", () => {
  const failure = sanitizeGovulncheckFailure(new Error(String.raw`docker run -v D:\Users\Admin\Uptime Monitoring Platform:/src -> 1: stderr included D:\Users\Admin\private`));
  assert.deepEqual(failure, {
    exitCode: 1,
    findingsTail: "tool error: govulncheck binary scan exited 1",
  });
  assert.doesNotMatch(JSON.stringify(failure), /D:\\|\/home\/|\/Users\//);
});

test("govulncheck gate requires a clean exit and a bound companion digest", () => {
  const digest = `sha256:${"a".repeat(64)}`;
  assert.doesNotThrow(() => assertGovulncheckClean(0, digest, "v1.1.4"));
  assert.throws(() => assertGovulncheckClean(3, digest, "v1.1.4"), /govulncheck binary scan exited 3/);
  assert.throws(() => assertGovulncheckClean(0, "", "v1.1.4"), /symbol-preserving target digest/);
  assert.throws(() => assertGovulncheckClean(0, digest, "v99.0.0"), /version mismatch/);
});

test("release build and scanners consume the captured Git archive bytes", () => {
  assert.match(builder, /cd \/src && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build/);
  assert.match(builder, /docker", "run", "--rm", "-i"[\s\S]*input: sourceArchiveBytes, quiet: true/);
  assert.equal((builder.match(/\{ input: sourceArchiveBytes(?:, quiet: true)? \}/g) ?? []).length, 4);
});

test("release builder rejects dirty inputs before creating a source-SHA image", () => {
  assert.doesNotThrow(() => assertReleaseInputsClean(""));
  assert.throws(() => assertReleaseInputsClean(" M cmd/api/main.go"),
    /release inputs must be committed at the recorded source SHA/);
});

test("builder hands tar a portable context path, not a backslash Windows path", () => {
  assert.match(builder, /tarPath\(sourceRoot\)/);
  assert.doesNotMatch(builder, /"-C", sourceRoot\]/);
  assert.match(builder, /replaceAll\("\\\\", "\/"\)/);
});

test("release builder rechecks HEAD and context hash around mutable steps", () => {
  const snapshot = builder.match(
    /const verifyContextSnapshot = async \(name\) => \{([\s\S]*?)\n  \};/)?.[1] ?? "";
  assert.match(snapshot, /rev-parse", "HEAD"/);
  assert.match(snapshot, /!== sourceSha/);
  assert.match(snapshot, /contextHash/);
});

test("artifact publishability requires both resolved license and Docker Hub destination", () => {
  assert.equal(isArtifactPublishable("resolved:MIT", "owner/repository"), true);
  assert.equal(isArtifactPublishable("pending-user-decision", "owner/repository"), false);
  assert.equal(isArtifactPublishable("resolved:", "owner/repository"), false);
  assert.equal(isArtifactPublishable("resolved:MIT", "pending-user-namespace"), false);
});
