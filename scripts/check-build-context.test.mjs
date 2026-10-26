import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, isAbsolute, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const CHECKER = join(ROOT, "scripts/check-build-context.mjs");

test("accepts an absolute build-context path on Windows and POSIX", () => {
  const tempRoot = mkdtempSync(join(tmpdir(), "uptime-context-"));
  try {
    const context = join(tempRoot, "source snapshot");
    mkdirSync(join(context, "cmd"), { recursive: true });
    mkdirSync(join(context, "internal"), { recursive: true });
    writeFileSync(join(context, "Dockerfile"), "FROM scratch\n");
    writeFileSync(join(context, ".dockerignore"),
      "plans/\n.secrets/\nnode_modules/\n.env*\n");
    writeFileSync(join(context, "go.mod"), "module example.test/context\n");
    writeFileSync(join(context, "go.sum"), "");
    writeFileSync(join(context, "cmd", "main.go"), "package main\n");
    writeFileSync(join(context, "internal", "marker.go"), "package internal\n");

    const result = spawnSync(process.execPath, [CHECKER,
      "--context", context,
      "--dockerfile", "Dockerfile",
      "--verify-sentinels"], { cwd: ROOT, encoding: "utf8" });

    assert.ifError(result.error);
    assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
    assert.match(result.stdout, /PASS:/);
  } finally {
    const base = resolve(tmpdir());
    const target = resolve(tempRoot);
    const rel = relative(base, target);
    assert.ok(rel && rel !== "." && !rel.startsWith("..") && !isAbsolute(rel),
      "temporary context fixture must remain below the OS temp directory");
    rmSync(target, { recursive: true, force: true });
  }
});
