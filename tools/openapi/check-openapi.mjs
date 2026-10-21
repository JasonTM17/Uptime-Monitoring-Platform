// check-openapi.mjs — contract gate for docs/api/openapi.yaml.
//
//   1. SPEC LINT   — swagger-parser validates OpenAPI structure and
//                    dereferences every $ref (a broken ref is a fail).
//   2. ROUTE PARITY — the implemented-route manifest must match the
//                    spec's non-future operations exactly. Documenting
//                    an unwritten route (or forgetting a shipped one)
//                    fails here.
//   3. EXAMPLES    — every request/response example validates against
//                    its operation's schema (ajv, draft 2020-12).
//   4. HYGIENE     — examples must not contain credential-looking
//                    values (provider tokens, PEM blocks, bot tokens).
//
// Exit 0 = clean. Exit 1 prints each failure. `node --test` covers
// the negative cases (validator must actually catch them).

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import YAML from "yaml";
import SwaggerParser from "@apidevtools/swagger-parser";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";

// IMPLEMENTED — routes that exist in cmd/api + handler muxes today.
// Anything tagged x-future is a contract draft, not a claim.
export const IMPLEMENTED_OPS = [
  ["get", "/health/live"],
  ["get", "/health/ready"],
  ["get", "/auth/csrf"],
  ["post", "/auth/register"],
  ["post", "/auth/login"],
  ["post", "/auth/logout"],
  ["get", "/auth/me"],
  ["get", "/auth/sessions"],
  ["delete", "/auth/sessions/{id}"],
  ["post", "/monitors"],
  ["get", "/monitors"],
  ["get", "/monitors/{id}"],
  ["patch", "/monitors/{id}"],
  ["delete", "/monitors/{id}"],
  ["post", "/monitors/{id}/pause"],
  ["post", "/monitors/{id}/resume"],
  ["put", "/monitors/{id}/notification-channels"],
  ["post", "/notification-channels"],
  ["get", "/notification-channels"],
  ["get", "/notification-channels/{id}"],
  ["delete", "/notification-channels/{id}"],
  ["post", "/notification-channels/{id}/disable"],
];

const SECRET_PATTERNS = [
  [/AKIA[0-9A-Z]{16}/, "aws access key"],
  [/xox[baprs]-[A-Za-z0-9-]{10,}/, "slack token"],
  [/ghp_[A-Za-z0-9]{36}/, "github token"],
  [/sk_(live|test)_[A-Za-z0-9]{16,}/, "stripe key"],
  [/\d{8,10}:[A-Za-z0-9_-]{35}/, "telegram bot token"],
  [/-----BEGIN [A-Z ]*PRIVATE KEY/, "pem private key"],
  [/eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/, "jwt"],
];

const HERE = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_SPEC = path.resolve(HERE, "../../docs/api/openapi.yaml");

const METHODS = ["get", "put", "post", "delete", "patch", "options", "head", "trace"];

export async function checkSpec(specPath = DEFAULT_SPEC, ops = IMPLEMENTED_OPS) {
  const failures = [];
  const raw = readFileSync(specPath, "utf8");
  const doc = YAML.parse(raw, { strict: false });
  if (!doc || typeof doc !== "object") {
    return ["spec does not parse as a YAML document"];
  }
  if (doc.openapi !== "3.1.1") {
    failures.push(`openapi version is ${JSON.stringify(doc.openapi)}, expected 3.1.1`);
  }

  // 1. structural lint — dereference fully first so $refs resolve.
  let api;
  try {
    api = await SwaggerParser.validate(JSON.parse(JSON.stringify(doc)), {
      dereference: { circular: false },
    });
  } catch (err) {
    failures.push(`spec lint: ${err.message}`);
    return failures; // nothing else is meaningful without a valid spec
  }

  // 2. route parity
  const specOps = [];
  for (const [p, item] of Object.entries(api.paths ?? {})) {
    for (const m of METHODS) {
      const op = item?.[m];
      if (op && op["x-future"] !== true) specOps.push([m, p]);
    }
  }
  const key = ([m, p]) => `${m} ${p}`;
  const want = new Set(ops.map(key));
  const got = new Set(specOps.map(key));
  for (const k of want) {
    if (!got.has(k)) failures.push(`implemented route missing from spec: ${k}`);
  }
  for (const k of got) {
    if (!want.has(k)) {
      failures.push(`spec documents ${k} without x-future — either implement it or mark it planned`);
    }
  }

  // 3. examples validate against operation schemas
  const ajv = new Ajv2020({ strict: false, allErrors: true });
  addFormats(ajv);
  const examplesOf = (media) => {
    const out = [];
    if (media?.example !== undefined) out.push(media.example);
    for (const ex of Object.values(media?.examples ?? {})) {
      if (ex?.value !== undefined) out.push(ex.value);
    }
    return out;
  };
  const validatePayload = (schema, payload, where) => {
    if (!schema) return;
    try {
      const fn = ajv.compile(schema);
      if (!fn(payload)) {
        failures.push(`${where}: example fails schema — ${ajv.errorsText(fn.errors)}`);
      }
    } catch (err) {
      failures.push(`${where}: schema not compilable — ${err.message}`);
    }
  };
  for (const [p, item] of Object.entries(api.paths ?? {})) {
    for (const m of METHODS) {
      const op = item?.[m];
      if (!op || op["x-future"] === true) continue;
      const where = `${m} ${p}`;
      const reqMedia = op.requestBody?.content?.["application/json"];
      for (const ex of examplesOf(reqMedia)) {
        validatePayload(reqMedia.schema, ex, `${where} request`);
      }
      for (const [status, resp] of Object.entries(op.responses ?? {})) {
        const media = resp?.content?.["application/json"];
        for (const ex of examplesOf(media)) {
          validatePayload(media.schema, ex, `${where} ${status}`);
        }
      }
    }
  }

  // 4. hygiene — walk every example-ish string for credential shapes.
  const walk = (node, trail) => {
    if (typeof node === "string") {
      for (const [re, what] of SECRET_PATTERNS) {
        if (re.test(node)) failures.push(`${trail}: example contains ${what}-shaped value`);
      }
    } else if (Array.isArray(node)) {
      node.forEach((v, i) => walk(v, `${trail}[${i}]`));
    } else if (node && typeof node === "object") {
      for (const [k, v] of Object.entries(node)) walk(v, trail ? `${trail}.${k}` : k);
    }
  };
  for (const [p, item] of Object.entries(api.paths ?? {})) {
    for (const m of METHODS) {
      const op = item?.[m];
      if (!op) continue;
      walk(op.requestBody, `${m} ${p} request`);
      walk(op.responses, `${m} ${p} responses`);
    }
  }

  return failures;
}

const isMain = process.argv[1] &&
  path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  const specArg = process.argv[2] ? path.resolve(process.argv[2]) : DEFAULT_SPEC;
  const failures = await checkSpec(specArg);
  if (failures.length === 0) {
    console.log(`openapi check OK — ${IMPLEMENTED_OPS.length} implemented routes in parity, examples valid`);
  } else {
    for (const f of failures) console.error(`FAIL ${f}`);
    process.exit(1);
  }
}
