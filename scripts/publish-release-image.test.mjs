// C85 publish contract tests — verdict logic + workflow trust-boundary
// static analysis. Run: node --test scripts/publish-release-image.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { summarizeVerdict, planTags, REGISTRIES } from "./publish-release-image.mjs";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const wf = readFileSync(resolve(ROOT, ".github/workflows/container-release.yml"), "utf8");

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
