// Parity gate: regenerate schema.d.ts from the canonical OpenAPI
// contract and fail on any diff — hand-edited types can never cover a
// producer-side contract change.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import openapiTS, { astToString } from "openapi-typescript";

const spec = new URL("../../docs/api/openapi.yaml", import.meta.url);
const committed = fileURLToPath(new URL("../src/lib/api/schema.d.ts", import.meta.url));

const generated = astToString(await openapiTS(spec));
// The CLI prepends a do-not-edit banner the programmatic API omits —
// compare bodies only.
const current = readFileSync(committed, "utf8").replace(
  /^\/\*\*[\s\S]*?\*\/\s*/,
  "",
);

if (current !== generated) {
  console.error(
    "api:check FAIL — src/lib/api/schema.d.ts differs from docs/api/openapi.yaml.\n" +
      "Run `npm run api:generate` and review the diff.",
  );
  process.exit(1);
}
console.log("api:check PASS — generated types match the OpenAPI contract");
