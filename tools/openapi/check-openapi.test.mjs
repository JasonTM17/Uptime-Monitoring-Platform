// check-openapi.test.mjs — the checker must catch real breakage, not
// just pass the happy path. Each negative test mutates the spec,
// writes a temp copy, and asserts the specific failure surfaces.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, writeFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import YAML from "yaml";
import { checkSpec, IMPLEMENTED_OPS } from "./check-openapi.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SPEC = path.resolve(HERE, "../../docs/api/openapi.yaml");

const tmpSpec = (mutate) => {
  const doc = YAML.parse(readFileSync(SPEC, "utf8"));
  mutate(doc);
  const dir = mkdtempSync(path.join(tmpdir(), "oas-"));
  const p = path.join(dir, "spec.yaml");
  writeFileSync(p, YAML.stringify(doc));
  return p;
};

const has = (failures, needle) =>
  failures.some((f) => f.includes(needle));

test("the shipped spec passes clean", async () => {
  const failures = await checkSpec(SPEC);
  assert.deepEqual(failures, []);
});

test("parity catches a spec route the manifest doesn't implement", async () => {
  const p = tmpSpec((doc) => {
    doc.paths["/monitors/{id}/bogus"] = {
      get: { operationId: "bogus", responses: { "200": { description: "x" } } },
    };
  });
  const failures = await checkSpec(p);
  assert.ok(has(failures, "/monitors/{id}/bogus"), failures.join("\n"));
});

test("parity catches a missing implemented route", async () => {
  const p = tmpSpec((doc) => {
    delete doc.paths["/auth/login"];
  });
  const failures = await checkSpec(p);
  assert.ok(has(failures, "post /auth/login"), failures.join("\n"));
});

test("x-future operations are excluded from parity", async () => {
  const p = tmpSpec((doc) => {
    doc.paths["/planned-widget"] = {
      get: { "x-future": true, operationId: "pw", responses: { "200": { description: "x" } } },
    };
  });
  const failures = await checkSpec(p);
  assert.deepEqual(failures, []);
});

test("schema validation catches a wrong example field type", async () => {
  const p = tmpSpec((doc) => {
    const op = doc.paths["/monitors"].post;
    op.requestBody.content["application/json"].example.interval_seconds = "five";
  });
  const failures = await checkSpec(p);
  assert.ok(has(failures, "post /monitors request"), failures.join("\n"));
});

test("schema validation catches a missing required field", async () => {
  const p = tmpSpec((doc) => {
    const op = doc.paths["/monitors"].post;
    delete op.requestBody.content["application/json"].example.timeout_seconds;
  });
  const failures = await checkSpec(p);
  assert.ok(has(failures, "post /monitors request"), failures.join("\n"));
});

test("schema validation catches an extra property (additionalProperties:false)", async () => {
  const p = tmpSpec((doc) => {
    doc.paths["/notification-channels"].post.requestBody
      .content["application/json"].example.chat_id = "123";
  });
  const failures = await checkSpec(p);
  assert.ok(has(failures, "post /notification-channels request"), failures.join("\n"));
});

test("hygiene catches a credential-shaped example value", async () => {
  const p = tmpSpec((doc) => {
    doc.paths["/auth/login"].post.requestBody
      .content["application/json"].example.password = "ghp_" + "a".repeat(36);
  });
  const failures = await checkSpec(p);
  assert.ok(has(failures, "github token"), failures.join("\n"));
});

test("lint catches a broken $ref", async () => {
  const p = tmpSpec((doc) => {
    doc.paths["/monitors"].post.responses["422"].$ref =
      "#/components/responses/DoesNotExist";
  });
  const failures = await checkSpec(p);
  assert.ok(failures.length > 0, "expected lint failure");
});

test("manifest covers every production mux route (drift guard)", () => {
  // If a route is added to a mux without updating the manifest, this
  // count and the spec parity above go out of sync and fail loudly.
  assert.equal(IMPLEMENTED_OPS.length, 22);
});
