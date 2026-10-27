import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { BUILD_WORKFLOW_PATH, validateContainerPublishEvent }
  from "./validate-container-publish-event.mjs";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const SHA = "a".repeat(40);
const REPO = "JasonTM17/Uptime-Monitoring-Platform";
const valid = () => ({
  event: { id: 42, workflow_id: 13, conclusion: "success", head_branch: "main",
    head_sha: SHA, head_repository: { full_name: REPO } },
  manifest: { version: "v1.2.3-rc.1", source_sha: SHA },
  repository: REPO, defaultBranch: "main", trustedRef: "refs/heads/main",
  workflowPath: BUILD_WORKFLOW_PATH, tagSha: SHA,
  ciRuns: [{ head_sha: SHA, conclusion: "success" }],
});

test("accepts only the trusted exact-source, green-CI publication event", () => {
  assert.deepEqual(validateContainerPublishEvent(valid()), []);
});

test("rejects feature branches, failed workflows, wrong workflow paths, and source drift", () => {
  for (const change of [
    (input) => { input.event.head_branch = "feature/untrusted"; },
    (input) => { input.event.conclusion = "failure"; },
    (input) => { input.workflowPath = ".github/workflows/other.yml"; },
    (input) => { input.manifest.source_sha = "b".repeat(40); },
    (input) => { input.tagSha = "c".repeat(40); },
    (input) => { input.ciRuns = []; },
    (input) => { input.event.head_repository.full_name = "attacker/fork"; },
    (input) => { input.trustedRef = "refs/heads/feature/untrusted"; },
  ]) {
    const input = valid();
    change(input);
    assert.notDeepEqual(validateContainerPublishEvent(input), [], "invalid event was accepted");
  }
});

test("trusted workflow downloads a single run-bound artifact and does not checkout build source", () => {
  const workflow = readFileSync(resolve(ROOT, ".github/workflows/container-publish.yml"), "utf8");
  assert.match(workflow, /workflow_run:[\s\S]*workflows:\s*\["container-build"\]/);
  assert.match(workflow, /run-id: \$\{\{ github\.event\.workflow_run\.id \}\}/);
  assert.match(workflow, /ref: \$\{\{ github\.sha \}\}/);
  assert.doesNotMatch(workflow, /ref: \$\{\{ github\.event\.workflow_run\.head_sha \}\}/);
  assert.match(workflow, /validate-container-publish-event\.mjs/);
  assert.match(workflow, /node scripts\/verify-container-release\.mjs[\s\S]*--stage local/);
  assert.match(workflow, /verify-container-release\.mjs[\s\S]*--stage local/);
  assert.ok(workflow.indexOf("--stage local") < workflow.indexOf("node scripts/publish-release-image.mjs"));
});

test("every protected credential job revalidates tag and CI after approval", () => {
  const workflow = readFileSync(resolve(ROOT, ".github/workflows/container-publish.yml"), "utf8");
  const jobs = [
    workflow.match(/^  preflight-tags:[\s\S]*?(?=^  publish-ghcr:)/m)?.[0] ?? "",
    workflow.match(/^  publish-ghcr:[\s\S]*?(?=^  publish-dockerhub:)/m)?.[0] ?? "",
    workflow.match(/^  publish-dockerhub:[\s\S]*/m)?.[0] ?? "",
  ];
  for (const job of jobs) {
    const environment = job.indexOf("environment:");
    const validate = job.indexOf("name: revalidate source, release tag, and CI after environment approval");
    const validateCommand = job.indexOf("node scripts/validate-container-publish-event.mjs", validate);
    const publish = job.indexOf("node scripts/publish-release-image.mjs");
    assert.ok(environment >= 0 && validate > environment && validateCommand > validate,
      "revalidation must run inside the protected environment after its approval gate");
    if (job.includes("publish-release-image.mjs"))
      assert.ok(validateCommand < publish, "tag revalidation must precede the publisher CLI");
    assert.match(job.slice(validate), /UPSTREAM_WORKFLOW_RUN: \$\{\{ toJSON\(github\.event\.workflow_run\) \}\}/);
  }
  for (const job of jobs.slice(1))
    assert.match(job, /REQUIRE_TRUSTED_RELEASE_EVENT: "true"/,
      "the trusted publisher must repeat the event check before every copy");
});

test("secretless builder has no registry authority and publishes only the narrow release artifact", () => {
  const workflow = readFileSync(resolve(ROOT, ".github/workflows/container-build.yml"), "utf8");
  assert.match(workflow, /^permissions:\n  contents: read$/m);
  assert.doesNotMatch(workflow, /packages:\s*write|secrets\.|DOCKERHUB_TOKEN/);
  assert.match(workflow, /GITHUB_REF[\s\S]*refs\/heads\/main/);
  assert.match(workflow, /git rev-parse[\s\S]*RELEASE_VERSION/);
  assert.match(workflow, /name: release-artifact/);
  assert.match(workflow, /artifacts\/release\/govulncheck-target/);
  assert.doesNotMatch(workflow, /context-manifest\.json|release-source/);
});

test("only GHCR receives package write and Docker Hub token comes from a protected environment", () => {
  const workflow = readFileSync(resolve(ROOT, ".github/workflows/container-publish.yml"), "utf8");
  const ghcr = workflow.match(/^  publish-ghcr:[\s\S]*?(?=^  publish-dockerhub:)/m)?.[0] ?? "";
  const dockerHub = workflow.match(/^  publish-dockerhub:[\s\S]*/m)?.[0] ?? "";
  assert.match(ghcr, /packages: write/);
  assert.match(ghcr, /environment: ghcr-release/);
  assert.match(dockerHub, /environment: container-release/);
  assert.match(dockerHub, /DOCKERHUB_TOKEN: \$\{\{ secrets\.DOCKERHUB_TOKEN \}\}/);
  assert.doesNotMatch(dockerHub, /packages: write/);
  assert.doesNotMatch(ghcr, /DOCKERHUB_TOKEN/);
});

test("all third-party workflow actions are pinned to full commit SHAs", () => {
  for (const filename of ["container-build.yml", "container-publish.yml"]) {
    const workflow = readFileSync(resolve(ROOT, ".github/workflows", filename), "utf8");
    const uses = [...workflow.matchAll(/uses: ([^\s#]+)/g)].map((match) => match[1]);
    assert.ok(uses.length > 0, `${filename} has no pinned actions`);
    for (const action of uses) assert.match(action, /@[0-9a-f]{40}$/);
  }
});
