// C85 publish contract tests — verdict logic + workflow trust-boundary
// static analysis. Run: node --test scripts/publish-release-image.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { summarizeVerdict, planTags, REGISTRIES, publishAfterArtifactVerification,
  verifyReleaseArtifactBeforePublish, preflightReleaseTags, assertTrustedRegistryTargets,
  publishAfterFinalReleaseCheck } from "./publish-release-image.mjs";
import { TRUSTED_REGISTRY_REFS } from "./container-release-contract.mjs";
import { BUILD_WORKFLOW_PATH, validateContainerPublishEvent }
  from "./validate-container-publish-event.mjs";
import { assertGovulncheckClean, assertReleaseInputsClean, isArtifactPublishable,
  sanitizeGovulncheckFailure } from "./build-release-image.mjs";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const wf = readFileSync(resolve(ROOT, ".github/workflows/container-build.yml"), "utf8");
const publisherWf = readFileSync(resolve(ROOT, ".github/workflows/container-publish.yml"), "utf8");
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

test("release-tag preflight refuses a different digest and accepts only explicit not-found", async () => {
  const digest = `sha256:${"b".repeat(64)}`;
  await assert.rejects(preflightReleaseTags(["v1.2.3", "sha-a"], digest,
    async (tag) => tag === "v1.2.3" ? `sha256:${"c".repeat(64)}` : digest),
  /different digest; no mutation attempted/);
  const absent = await preflightReleaseTags(["v1.2.3"], digest, async () => {
    const error = new Error("registry inspect failed");
    error.stderr = "manifest unknown";
    throw error;
  });
  assert.deepEqual(absent, [{ tag: "v1.2.3", state: "absent" }]);
  await assert.rejects(preflightReleaseTags(["v1.2.3"], digest, async () => {
    const error = new Error("registry inspect failed");
    error.stderr = "unauthorized";
    throw error;
  }), /cannot safely inspect.*no mutation attempted/);
});

test("secretless builder has no pull request, tag, or push trigger", () => {
  const triggers = wf.match(/^on:[\s\S]*?(?=^\w)/m)?.[0] ?? "";
  assert.match(triggers, /workflow_dispatch:/);
  assert.doesNotMatch(triggers, /pull_request|pull_request_target|push:/);
});

test("build workflow has no registry credentials or package-write authority", () => {
  assert.doesNotMatch(wf, /secrets\.|packages:\s*write|DOCKERHUB_TOKEN/);
  assert.match(publisherWf, /GHCR_TOKEN: \$\{\{ secrets\.GITHUB_TOKEN \}\}/);
  assert.match(publisherWf, /DOCKERHUB_TOKEN: \$\{\{ secrets\.DOCKERHUB_TOKEN \}\}/);
});

test("every workflow action is pinned to a full 40-hex SHA", () => {
  for (const workflow of [wf, publisherWf]) {
    const uses = [...workflow.matchAll(/uses: ([^\s#]+)/g)].map((x) => x[1]);
    assert.ok(uses.length > 0, "expected pinned actions");
    for (const u of uses)
      assert.match(u, /@[0-9a-f]{40}$/, `unpinned/mutable action: ${u}`);
  }
});

test("build and publisher workflows cannot cancel an in-flight release", () => {
  assert.match(wf, /cancel-in-progress: false/);
  assert.match(publisherWf, /group: container-publish[\s\S]*cancel-in-progress: false/);
});

test("least-privilege permissions: builder is read-only, packages only on ghcr job", () => {
  assert.ok(/^permissions:\n  contents: read$/m.test(wf));
  assert.ok(/^permissions:\n  contents: read$/m.test(publisherWf));
  const ghcr = publisherWf.match(/^  publish-ghcr:[\s\S]*?(?=^  publish-dockerhub:)/m)?.[0] ?? "";
  assert.ok(/packages: write/.test(ghcr), "ghcr job missing packages: write");
  const dh = publisherWf.match(/^  publish-dockerhub:[\s\S]*?(?=^\s*$)/m)?.[0] ?? "";
  assert.ok(!/packages: write/.test(dh), "dockerhub job has unneeded packages: write");
});

test("registries map uses documented secret names only", () => {
  assert.equal(REGISTRIES.ghcr.tok_env, "GHCR_TOKEN");
  assert.equal(REGISTRIES.dockerhub.user_env, "DOCKERHUB_USERNAME");
  assert.equal(REGISTRIES.dockerhub.tok_env, "DOCKERHUB_TOKEN");
});

test("publisher target refs are bound to the owner-approved repositories", () => {
  assert.equal(REGISTRIES.ghcr.ref, TRUSTED_REGISTRY_REFS.ghcr);
  assert.equal(REGISTRIES.dockerhub.ref, TRUSTED_REGISTRY_REFS.dockerhub);
  assert.equal(assertTrustedRegistryTargets({ registries: TRUSTED_REGISTRY_REFS }), true);
});

test("a manifest destination edit is rejected before registry inspect or copy", () => {
  const events = [];
  const manifest = { registries: { ...TRUSTED_REGISTRY_REFS,
    dockerhub: "attacker/other-repository" } };
  assert.throws(() => {
    assertTrustedRegistryTargets(manifest);
    events.push("inspect", "copy");
  }, /registry target mismatch: dockerhub/);
  assert.deepEqual(events, []);
  const main = publisher.slice(publisher.indexOf("async function main()"));
  assert.ok(main.indexOf("assertTrustedRegistryTargets(m);") <
    main.indexOf("preflightReleaseTags("),
  "manifest destinations must be rejected before any registry inspection");
});

test("a post-approval release-tag drift blocks the mutation callback", async () => {
  const events = [];
  const sha = "a".repeat(40);
  await assert.rejects(publishAfterFinalReleaseCheck(async () => {
    events.push("revalidate-tag");
    const errors = validateContainerPublishEvent({
      event: { id: 42, workflow_id: 13, conclusion: "success", head_branch: "main",
        head_sha: sha, head_repository: { full_name: "JasonTM17/Uptime-Monitoring-Platform" } },
      manifest: { version: "v1.2.3", source_sha: sha },
      repository: "JasonTM17/Uptime-Monitoring-Platform", defaultBranch: "main",
      trustedRef: "refs/heads/main", workflowPath: BUILD_WORKFLOW_PATH,
      tagSha: "c".repeat(40), ciRuns: [{ head_sha: sha, conclusion: "success" }],
    });
    if (errors.length) throw new Error(`release tag no longer matches source: ${errors.join("; ")}`);
  }, async () => events.push("registry-copy")), /release tag no longer matches source/);
  assert.deepEqual(events, ["revalidate-tag"]);
  assert.match(publisher, /publishAfterFinalReleaseCheck\(finalReleaseCheck/);
});

test("build job requires and passes the owner-confirmed Docker Hub reference", () => {
  const buildJob = wf.match(/^  build-verify:[\s\S]*/m)?.[0] ?? "";
  const step = buildJob.match(/- name: build, attest, and scan[\s\S]*?--output artifacts\/release\/image-manifest\.json/)?.[0] ?? "";
  const guard = buildJob.match(/- name: validate release ref and Docker Hub target[\s\S]*?- name: build, attest, and scan/)?.[0] ?? "";
  assert.match(guard, /DOCKERHUB_NAMESPACE: \$\{\{ vars\.DOCKERHUB_NAMESPACE \}\}/);
  assert.match(guard, /test "\$DOCKERHUB_NAMESPACE" = "nguyenson1710\/uptime-monitoring-platform"/);
  const guardIndex = buildJob.indexOf("validate release ref and Docker Hub target");
  const builderIndex = buildJob.indexOf("node scripts/build-release-image.mjs");
  assert.ok(guardIndex >= 0 && builderIndex >= 0, "namespace and release-tag guard must precede build");
  assert.ok(builderIndex > guardIndex, "release preflight must run before the build");
  assert.match(step, /--dockerhub-namespace "\$DOCKERHUB_NAMESPACE"/);
});

test("protected registry credentials and tags are checked before either publisher", () => {
  const prerequisites = publisherWf.match(/^  preflight-tags:[\s\S]*?(?=^  publish-ghcr:)/m)?.[0] ?? "";
  const ghcrJob = publisherWf.match(/^  publish-ghcr:[\s\S]*?(?=^  publish-dockerhub:)/m)?.[0] ?? "";
  const dockerHubJob = publisherWf.match(/^  publish-dockerhub:[\s\S]*/m)?.[0] ?? "";
  assert.match(prerequisites, /DOCKERHUB_USERNAME: \$\{\{ vars\.DOCKERHUB_USERNAME \}\}/);
  assert.match(prerequisites, /DOCKERHUB_TOKEN: \$\{\{ secrets\.DOCKERHUB_TOKEN \}\}/);
  assert.match(prerequisites, /DOCKERHUB_NAMESPACE: \$\{\{ vars\.DOCKERHUB_NAMESPACE \}\}/);
  assert.match(prerequisites, /environment: container-release/);
  assert.match(prerequisites, /test -n "\$DOCKERHUB_TOKEN"/);
  assert.match(prerequisites, /--dest all --preflight-only true/);
  assert.match(ghcrJob, /needs: \[validate-release, preflight-tags\]/);
  assert.match(dockerHubJob, /needs: \[validate-release, preflight-tags\]/);
});

test("Docker Hub username is a variable and its token remains secret-only", () => {
  const job = publisherWf.match(/^  publish-dockerhub:[\s\S]*/m)?.[0] ?? "";
  assert.match(job, /DOCKERHUB_USERNAME: \$\{\{ vars\.DOCKERHUB_USERNAME \}\}/);
  assert.match(job, /DOCKERHUB_TOKEN: \$\{\{ secrets\.DOCKERHUB_TOKEN \}\}/);
  assert.match(job, /environment: container-release/);
  assert.doesNotMatch(job, /DOCKERHUB_USERNAME: \$\{\{ secrets\./);
  assert.doesNotMatch(job, /--override-ref/);
});

test("publisher reads the OCI tar via the archive transport, not a layout directory", () => {
  assert.match(publisher, /oci-archive:\/a\/\$\{archFile\}:\$\{tag\}/);
  assert.doesNotMatch(publisher, /`oci:\/a\/\$\{archFile\}`/);
});

test("publisher jobs check out default-branch code before downloading the build artifact", () => {
  const jobs = [
    publisherWf.match(/^  validate-release:[\s\S]*?(?=^  preflight-tags:)/m)?.[0] ?? "",
    publisherWf.match(/^  preflight-tags:[\s\S]*?(?=^  publish-ghcr:)/m)?.[0] ?? "",
    publisherWf.match(/^  publish-ghcr:[\s\S]*?(?=^  publish-dockerhub:)/m)?.[0] ?? "",
    publisherWf.match(/^  publish-dockerhub:[\s\S]*/m)?.[0] ?? "",
  ];
  for (const job of jobs) {
    const checkout = job.indexOf("actions/checkout@");
    const exactSha = job.indexOf("ref: ${{ github.sha }}");
    const artifact = job.indexOf("actions/download-artifact@");
    assert.ok(checkout >= 0 && exactSha > checkout && artifact > exactSha,
      "trusted jobs must checkout github.sha before downloading the upstream artifact");
    assert.match(job.slice(artifact), /run-id: \$\{\{ github\.event\.workflow_run\.id \}\}/);
  }
  assert.doesNotMatch(publisherWf, /ref: \$\{\{ github\.event\.workflow_run\.head_sha \}\}/);
});

test("publisher runs the local artifact verifier before any registry copy", () => {
  const main = publisher.slice(publisher.indexOf("async function main()"));
  const gate = main.indexOf("publishAfterArtifactVerification(mpath");
  const copy = main.indexOf("publishOne(m, d, ref");
  assert.ok(gate >= 0 && copy > gate, "local verifier must guard the registry-copy loop");
  assert.match(publisher, /"--stage", "local"/);
  assert.ok(publisher.indexOf("preflightReleaseTags(receipt.tags") < publisher.indexOf('"copy", "--all"'),
    "existing release tags must be checked before copy");
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
