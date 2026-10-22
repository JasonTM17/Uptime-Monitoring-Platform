// C89 — hosted-deployment verifier.
//
//   node scripts/verify-hosted.mjs --manifest artifacts/hosted-candidate.json \
//     --gate trust|runtime|all --output <path>
//
// trust   — static contract checks on the candidate manifest (no
//           network): digest deploy, exact origins, bounded proxy
//           trust, TLS DSNs, session-mode engine conn, migrate-at-
//           deploy, no secret values, single-service budget.
// runtime — live readback once deployed: health probes, version
//           revision parity, cookie/secure flags. NOT_RUN when URLs
//           are absent.
import { writeFileSync, readFileSync, mkdirSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import net from "node:net";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const DIGEST_RE = /^sha256:[0-9a-f]{64}$/;
const ORIGIN_RE = /^https:\/\/[a-z0-9.-]+(?::\d+)?$/i;
const SENSITIVE_RE = /(token|secret|password|passwd|private[-_]?key|credential|api[-_]?key|[-_]?key$|signing[-_]?key)/i;

export function validateTrust(c) {
  const errs = [];
  const need = (ok, msg) => { if (!ok) errs.push(msg); };
  need(c && typeof c === "object", "candidate is not an object");
  if (!c || typeof c !== "object") return errs;

  need(c.format === "hosted-candidate-v1", `format ${c.format}`);
  need(/^[0-9a-f]{40}$/.test(c.source_sha ?? ""), "source_sha missing/malformed");

  // Digest deploy — never a mutable tag.
  const img = c.image?.ref ?? "";
  need(/@sha256:[0-9a-f]{64}$/.test(img),
    `image ref must pin @sha256: digest — got '${img || "none"}'`);
  need(!/:latest(@|$)/.test(img), "latest tag is not a deploy identity");

  // Same-origin contract: exact https origins, never wildcard.
  const origins = c.env?.TRUSTED_ORIGINS ?? [];
  need(Array.isArray(origins) && origins.length > 0, "TRUSTED_ORIGINS empty — hosted fails closed");
  for (const o of origins ?? []) {
    need(ORIGIN_RE.test(o), `TRUSTED_ORIGINS entry not an exact https origin: '${o}'`);
    need(!o.includes("*"), `wildcard origin '${o}' forbidden`);
  }

  // Bounded proxy trust: required for limiter correctness, never 0.0.0.0/0.
  const proxies = c.env?.TRUSTED_PROXIES ?? [];
  need(Array.isArray(proxies) && proxies.length > 0,
    "TRUSTED_PROXIES empty — all logins would share one rate bucket");
  for (const p of proxies ?? []) {
    const [host, len] = String(p).split("/");
    const validCidr = host && len !== undefined && net.isIP(host) !== 0 &&
      Number.isInteger(+len) && +len >= 0 && +len <= (net.isIP(host) === 6 ? 128 : 32);
    need(validCidr, `invalid TRUSTED_PROXIES CIDR '${p}'`);
    if (validCidr && +len === 0)
      errs.push(`trust-all proxy CIDR '${p}' forbidden`);
  }

  need(c.env?.APP_ENV === "hosted", `APP_ENV '${c.env?.APP_ENV}' — Secure cookies require hosted`);

  // DSNs: TLS enforced; engine session-mode only (pooler breaks the
  // advisory owner-lock). Values must be secret NAMES, not literals.
  for (const k of ["DATABASE_URL", "ENGINE_DATABASE_URL", "MIGRATION_DATABASE_URL"]) {
    const v = c.env?.[k];
    need(v !== undefined, `${k} missing`);
    if (typeof v !== "string") continue;
    if (/^postgres(?:ql)?:\/\//.test(v)) {
      errs.push(`${k} carries a literal DSN — env values must be secret refs/names, never committed URLs`);
      if (!/sslmode=(require|verify-ca|verify-full)/.test(v))
        errs.push(`${k} DSN lacks sslmode=require+ TLS`);
    }
  }
  const engPort = c.engine_conn?.port ?? null;
  need(engPort === 5432,
    `engine connection must be Supabase session mode :5432 (got ${engPort}) — transaction pooler :6543 breaks owner-lock`);

  // Migrate at deploy only — no startup auto-migration inside the app.
  need(c.migration?.strategy === "deploy-step",
    `migration.strategy '${c.migration?.strategy}' — must be deploy-step, not startup`);

  // One-service hours budget.
  const services = c.services ?? [];
  need(services.length === 1 && services[0]?.type === "web",
    `expected exactly 1 web service — got ${JSON.stringify(services.map((s) => s.type))}`);
  need(services[0]?.health_check === "/health/live",
    `health_check '${services[0]?.health_check}' — must be DB-free /health/live`);

  // No secret VALUES anywhere in the candidate.
  const flat = JSON.stringify(c.env ?? {});
  for (const mm of flat.matchAll(/"([^"]+)"\s*:\s*"([^"]{20,})"/g))
    if (SENSITIVE_RE.test(mm[1]) && !/^(env:|sref:|\$\{)/.test(mm[2]))
      errs.push(`possible secret value in env.${mm[1]}`);

  return errs;
}

async function runtimeChecks(c, result, check) {
  const api = c.endpoints?.api_base;
  const web = c.endpoints?.web_origin;
  result.runtime = { probed_at: new Date().toISOString(), urls: {} };
  if (!api && !web) { check("runtime-urls", false, "no endpoints.api_base/web_origin — deploy not performed (NOT_RUN)"); return; }

  if (api) {
    try {
      const live = await fetch(`${api}/health/live`);
      const ready = await fetch(`${api}/health/ready`);
      result.runtime.urls.live = live.status; result.runtime.urls.ready = ready.status;
      check("api-live", live.status === 200, `/health/live ${live.status}`);
      check("api-ready", ready.status === 200, `/health/ready ${ready.status}`);
      const body = await live.json().catch(() => ({}));
      if (body.revision)
        check("api-revision", body.revision === c.source_sha,
          `revision ${body.revision} vs ${c.source_sha}`);
    } catch (e) { check("api-live", false, e.message.slice(0, 120)); }
  }
  if (web) {
    try {
      const r = await fetch(web, { redirect: "manual" });
      result.runtime.urls.web = r.status;
      check("web-serves", r.status === 200, `GET ${web} -> ${r.status}`);
      const proxy = await fetch(`${web}/api/health/live`).catch(() => null);
      check("api-proxy", proxy?.status === 200, `/api/health/live -> ${proxy?.status}`);
    } catch (e) { check("web-serves", false, e.message.slice(0, 120)); }
  }
}

async function main() {
  const args = {};
  for (let i = 2; i < process.argv.length; i += 2)
    args[process.argv[i].replace(/^--/, "")] = process.argv[i + 1];
  const mpath = resolve(args.manifest ?? die("--manifest required"));
  const output = resolve(args.output ?? die("--output required"));
  const gate = args.gate ?? "all";
  if (!["trust", "runtime", "all"].includes(gate)) die(`--gate ${gate}`);
  mkdirSync(dirname(output), { recursive: true });

  const c = JSON.parse(readFileSync(mpath, "utf8"));
  const result = { manifest: mpath.replace(ROOT + "\\", "").replaceAll("\\", "/"),
    gate, generated_at: new Date().toISOString(), checks: [], verdict: "PASS" };
  const check = (name, ok, detail) => {
    result.checks.push({ name, ok: !!ok, detail });
    if (!ok) result.verdict = "FAIL";
  };

  if (gate === "trust" || gate === "all") {
    const errs = validateTrust(c);
    check("trust-contract", errs.length === 0, errs.join(" | ") || "digest/origins/proxies/TLS/session/migrate/budget OK");
  }
  if (gate === "runtime" || gate === "all")
    await runtimeChecks(c, result, check);

  writeFileSync(output, JSON.stringify(result, null, 2));
  console.log(`verdict ${result.verdict} — ${result.checks.map((x) => `${x.name}:${x.ok ? "ok" : "FAIL"}`).join(", ")}`);
  process.exit(result.verdict === "PASS" ? 0 : 1);
}
function die(msg) { throw new Error(`verify-hosted: ${msg}`); }

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url))
  main().catch((e) => { console.error(e.message ?? e); process.exit(1); });
