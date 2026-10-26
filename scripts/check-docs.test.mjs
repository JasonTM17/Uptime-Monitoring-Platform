import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, isAbsolute, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const CHECKER = join(ROOT, "scripts/check-docs.mjs");

function scanReadme(text) {
  const fixtureRoot = mkdtempSync(join(tmpdir(), "uptime-docs-privacy-"));
  try {
    const publicRoot = join(fixtureRoot, "public");
    const readme = join(fixtureRoot, "README.md");
    mkdirSync(publicRoot);
    writeFileSync(readme, text, "utf8");
    return spawnSync(process.execPath, [CHECKER,
      "--public-root", publicRoot,
      "--readme", readme,
      "--privacy"], { cwd: ROOT, encoding: "utf8" });
  } finally {
    const tempRoot = resolve(tmpdir());
    const fixturePath = resolve(fixtureRoot);
    const fixtureRelative = relative(tempRoot, fixturePath);
    assert.ok(fixtureRelative && fixtureRelative !== "."
      && !fixtureRelative.startsWith("..") && !isAbsolute(fixtureRelative),
    "temporary privacy fixture must remain below the OS temp directory");
    rmSync(fixturePath, { recursive: true, force: true });
  }
}

test("rejects a private roadmap summary in English", () => {
  const result = scanReadme(
    "A private, detailed implementation roadmap (2 phases, 3 focused commits) is stored locally.");
  assert.ifError(result.error);
  assert.equal(result.status, 1, result.stdout);
  assert.match(result.stdout, /private roadmap summary/i);
  assert.doesNotMatch(result.stdout, /2 phases|3 focused commits/);
});

test("rejects a private plan summary with slash-separated counts", () => {
  const result = scanReadme("Bộ plan chi tiết (2 phases/3 commits) là tài liệu nội bộ.");
  assert.ifError(result.error);
  assert.equal(result.status, 1, result.stdout);
  assert.match(result.stdout, /private roadmap summary/i);
  assert.doesNotMatch(result.stdout, /2 phases|3 commits/);
});

test("rejects a private roadmap summary wrapped across Markdown lines", () => {
  const result = scanReadme("A private roadmap\n(2 phases,\n3 commits) remains local.");
  assert.ifError(result.error);
  assert.equal(result.status, 1, result.stdout);
  assert.match(result.stdout, /private roadmap summary/i);
  assert.doesNotMatch(result.stdout, /2 phases|3 commits/);
});

test("allows phase and commit counts without a private-plan reference", () => {
  const result = scanReadme("Release notes cover 2 phases and 3 commits.");
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stdout);
  assert.match(result.stdout, /verdict PASS/);
});
