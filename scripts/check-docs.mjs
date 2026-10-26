// C92/C93 — documentation checks.
//
//   node scripts/check-docs.mjs --public-root docs --readme README.md --privacy
//   node scripts/check-docs.mjs --release docs/releases/<evidence>.md
//
// --privacy: scan tracked public-facing docs/media for private-marker
//   leaks before any external metadata/publication step. Rejects links
//   or text referencing private plan/report/attachment paths, host paths,
//   and literal credential shapes. Public-safe positives must pass.
import { readdirSync, readFileSync, statSync, existsSync } from "node:fs";
import { resolve, dirname, join, extname } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const args = {};
for (let i = 2; i < process.argv.length; i++) {
  const a = process.argv[i];
  if (a.startsWith("--")) args[a.slice(2)] = process.argv[i + 1] && !process.argv[i + 1].startsWith("--") ? process.argv[++i] : true;
}

// Private markers: the review-approved blocklist for anything that can
// reach public docs/media/metadata.
const PRIVATE_MARKERS = [
  { re: /(^|[^\w])(plans|private|\.private)\//i, what: "private plan/report path" },
  { re: /docs\/(private|internal)\//i, what: "private docs path" },
  { re: /\b(?:plans?|roadmap)\b[\s\S]{0,100}\b\d+\s+phases?\s*(?:,|\/|and|&)\s*\d+\s+(?:focused\s+)?commits?\b/i,
    what: "private roadmap summary", redact: true },
  { re: /execution-ledger/i, what: "private execution ledger" },
  { re: /(C:\\Users|\/home\/[a-z]|\/Users\/[a-z]|D:\\)/i, what: "host-local path" },
  { re: /spec1[0-9]|phase-0[0-9]-|phase-1[0-9]-/i, what: "internal plan spec/card ref" },
  { re: /(wukong|kongming)\b/i, what: "internal review-agent name" },
  { re: /\bC[89][0-9]\b|\bC[0-7][0-9]\b/i, what: "internal card id" },
];
const CRED_SHAPES = [
  { re: /(password|passwd|secret|token|api[_-]?key|bearer)["' ]*[:=]["' ]*[A-Za-z0-9+/=_-]{12,}/i, what: "credential-shaped literal" },
  { re: /-----BEGIN [A-Z ]*PRIVATE KEY-----/, what: "private key material" },
  { re: /postgres(ql)?:\/\/[^\s"'`:]+:[^\s"'`@]+@/i, what: "DSN with embedded credential" },
];

function* walk(dir) {
  for (const e of readdirSync(dir)) {
    const p = join(dir, e);
    const s = statSync(p);
    if (s.isDirectory()) {
      if (["private", "internal", ".private", "node_modules", ".git"].includes(e)) continue;
      yield* walk(p);
    } else yield p;
  }
}

async function privacy() {
  const pubRoot = resolve(ROOT, args["public-root"] ?? "docs");
  const readme = resolve(ROOT, args.readme ?? "README.md");
  const files = [...walk(pubRoot)].filter((p) =>
    [".md", ".json", ".yml", ".yaml", ".html", ".txt"].includes(extname(p)));
  if (existsSync(readme)) files.push(readme);
  files.push(resolve(ROOT, "render.yaml"));
  const findings = [];
  for (const f of files) {
    if (!existsSync(f)) continue;
    const text = readFileSync(f, "utf8");
    const rel = f.replace(ROOT, "").replaceAll("\\", "/").slice(1);
    for (const { re, what, redact } of [...PRIVATE_MARKERS, ...CRED_SHAPES]) {
      const m = text.match(re);
      if (m) findings.push({ file: rel, what,
        sample: redact ? "[redacted]" : (m[0] ?? "").slice(0, 60) });
    }
  }
  // media privacy: binary files can't be text-scanned; enforce the
  // manifest provenance contract instead (artifact exists + hash binds).
  const manifestPath = resolve(ROOT, "docs/media/manifest.json");
  if (existsSync(manifestPath)) {
    const man = JSON.parse(readFileSync(manifestPath, "utf8"));
    for (const a of man.artifacts ?? []) {
      const p = resolve(ROOT, a.file);
      if (!existsSync(p)) {
        findings.push({ file: "docs/media/manifest.json", what: "manifest artifact missing on disk", sample: a.file });
        continue;
      }
      const h = `sha256:${createHash("sha256").update(readFileSync(p)).digest("hex")}`;
      if (h !== a.sha256)
        findings.push({ file: "docs/media/manifest.json", what: "artifact hash mismatch (stale media)", sample: a.file });
      if (!a.runtime_sha && !man.runtime_sha)
        findings.push({ file: "docs/media/manifest.json", what: "missing runtime provenance", sample: a.file });
    }
  }
  console.log(`privacy scan: ${files.length} files`);
  if (findings.length) {
    for (const f of findings) console.log(`  FAIL ${f.file}: ${f.what} (${f.sample})`);
    console.log(`verdict FAIL — ${findings.length} finding(s)`);
    process.exit(1);
  }
  console.log("verdict PASS — no private markers in public docs/media");
}

function release() {
  const doc = resolve(ROOT, args.release);
  if (!existsSync(doc)) { console.log(`FAIL: ${args.release} missing`); process.exit(1); }
  const text = readFileSync(doc, "utf8");
  const required = ["source_sha", "image", "acceptance", "media", "registry", "hosted", "limitations"];
  const missing = required.filter((k) => !text.toLowerCase().includes(k));
  if (missing.length) { console.log(`FAIL: missing sections ${missing.join(",")}`); process.exit(1); }
  // every linked tracked path must exist
  const links = [...text.matchAll(/\]\(([^)\s]+)\)/g)].map((m) => m[1])
    .filter((l) => !l.startsWith("http") && !l.startsWith("#"));
  let bad = 0;
  for (const l of links) {
    const p = resolve(dirname(doc), decodeURIComponent(l.split("#")[0]));
    if (!existsSync(p)) { console.log(`  FAIL dead link: ${l}`); bad++; }
  }
  if (bad) process.exit(1);
  console.log(`release doc ${args.release}: sections OK, ${links.length} links resolve`);
}

if (args.privacy !== undefined) await privacy();
else if (args.release) release();
else { console.log("usage: check-docs.mjs --privacy | --release <doc>"); process.exit(1); }
