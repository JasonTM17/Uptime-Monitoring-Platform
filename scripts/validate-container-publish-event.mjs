// Trusted preflight for the privileged workflow_run publisher.
// The build artifact is data only; this program runs from the default branch.
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { validateManifest } from "./verify-container-release.mjs";

export const BUILD_WORKFLOW_PATH = ".github/workflows/container-build.yml";
const RELEASE_VERSION = /^v\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$/;
const SOURCE_SHA = /^[0-9a-f]{40}$/;

export function validateContainerPublishEvent({
  event, manifest, repository, defaultBranch, trustedRef, workflowPath,
  tagSha, ciRuns,
}) {
  const errors = [];
  const require = (ok, message) => { if (!ok) errors.push(message); };
  const repo = String(repository ?? "").toLowerCase();
  const sha = event?.head_sha;

  require(event?.conclusion === "success", "build workflow did not succeed");
  require(defaultBranch === "main" && event?.head_branch === defaultBranch &&
    trustedRef === `refs/heads/${defaultBranch}`,
  "publisher requires a successful build and trusted publisher code on main");
  require(repo === "jasontm17/uptime-monitoring-platform" &&
    String(event?.head_repository?.full_name ?? "").toLowerCase() === repo,
  "build run repository does not match the trusted repository");
  require(Number.isSafeInteger(Number(event?.id)) && Number(event.id) > 0 &&
    Number.isSafeInteger(Number(event?.workflow_id)) && Number(event.workflow_id) > 0,
  "build run identity is missing or malformed");
  require(workflowPath === BUILD_WORKFLOW_PATH,
    "upstream workflow path is not the secretless container build workflow");
  require(SOURCE_SHA.test(sha ?? "") && manifest?.source_sha === sha,
    "artifact source SHA does not match the upstream workflow run");
  require(RELEASE_VERSION.test(manifest?.version ?? ""),
    "artifact release version is malformed");
  require(tagSha === sha, "release tag does not point to the exact build source SHA");

  const greenCi = Array.isArray(ciRuns) && ciRuns.some((run) =>
    run?.head_sha === sha && run?.conclusion === "success");
  require(greenCi, "the exact source SHA has no successful CI run");

  return errors;
}

function run(command, args) {
  const result = spawnSync(command, args, { encoding: "utf8", windowsHide: true });
  if (result.error || result.status !== 0) throw new Error("trusted release preflight lookup failed");
  return result.stdout.trim();
}

function ghJson(path) {
  try { return JSON.parse(run("gh", ["api", path])); }
  catch { return null; }
}

function readTagCommit(version) {
  if (!RELEASE_VERSION.test(version)) return null;
  const ref = `refs/tags/${version}`;
  try {
    // Force-refresh only this local tag ref so a moved remote tag cannot be
    // hidden by the checkout's previously fetched copy.
    run("git", ["fetch", "--no-tags", "--force", "origin", `+${ref}:${ref}`]);
    return run("git", ["rev-parse", `${ref}^{commit}`]);
  } catch { return null; }
}

function main() {
  const manifestPath = process.argv[2];
  if (!manifestPath) throw new Error("--manifest path is required");
  const event = JSON.parse(process.env.UPSTREAM_WORKFLOW_RUN ?? "{}");
  const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
  const manifestErrors = validateManifest(manifest, { stage: "remote" });
  if (manifestErrors.length) throw new Error(`artifact manifest rejected: ${manifestErrors.join(" | ")}`);

  const repository = process.env.CURRENT_REPOSITORY ?? "";
  const runId = String(event.id ?? "");
  const workflowId = String(event.workflow_id ?? "");
  const sha = String(event.head_sha ?? "");
  if (!/^\d+$/.test(runId) || !/^\d+$/.test(workflowId) || !SOURCE_SHA.test(sha))
    throw new Error("upstream workflow run identity is malformed");

  const workflow = ghJson(`repos/${repository}/actions/workflows/${workflowId}`);
  const ci = ghJson(`repos/${repository}/actions/workflows/ci.yml/runs?head_sha=${sha}&status=completed&per_page=100`);
  const tagSha = readTagCommit(manifest.version);
  const errors = validateContainerPublishEvent({
    event, manifest, repository,
    defaultBranch: process.env.DEFAULT_BRANCH,
    trustedRef: process.env.GITHUB_REF,
    workflowPath: workflow?.path,
    tagSha,
    ciRuns: ci?.workflow_runs,
  });
  if (errors.length) {
    console.error(`trusted publisher blocked: ${errors.join("; ")}`);
    process.exitCode = 1;
    return;
  }
  console.log(`trusted publisher preflight PASS for ${manifest.version} at ${sha}`);
}

if (process.argv[1]?.endsWith("validate-container-publish-event.mjs")) {
  try { main(); }
  catch (error) {
    console.error(error.message ?? "trusted publisher preflight failed");
    process.exitCode = 1;
  }
}
