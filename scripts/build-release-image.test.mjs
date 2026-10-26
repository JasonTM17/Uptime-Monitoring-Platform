import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const dockerfile = readFileSync(new URL("../Dockerfile", import.meta.url), "utf8");
const buildScript = readFileSync(new URL("./build-release-image.mjs", import.meta.url), "utf8");

test("source companion scanner uses the exact digest-pinned runtime Go builder", () => {
  const runtimeBuilder = dockerfile.match(/^FROM\s+(\S+)\s+AS\s+build\s*$/im)?.[1];
  const scannerBuilder = buildScript.match(/^const GO_IMAGE = "([^"]+)";$/m)?.[1];

  assert.ok(runtimeBuilder, "Dockerfile must declare its Go builder stage");
  assert.match(runtimeBuilder, /@sha256:[0-9a-f]{64}$/, "runtime Go builder must be digest pinned");
  assert.equal(scannerBuilder, runtimeBuilder, "scanner companion must use the runtime Go builder image");
});
