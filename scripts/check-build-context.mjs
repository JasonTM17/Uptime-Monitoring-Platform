#!/usr/bin/env node
// check-build-context.mjs — pre-upload build-context gate (F13).
//
// `docker build` uploads the ENTIRE ignore-filtered context to the
// daemon before the Dockerfile is read — a .dockerignore mistake is
// a secret leak to the builder. This script resolves the effective
// file set BuildKit would send, refuses the upload when any blocked
// namespace survives filtering, optionally proves inert sentinel
// fixtures are excluded, and emits a hashed manifest receipt that
// later build receipts can cite.
//
// Usage:
//   node scripts/check-build-context.mjs --context . \
//     --dockerfile Dockerfile [--verify-sentinels] \
//     [--output artifacts/build/context-manifest.json]
//
// Exit 0 = context is safe to upload. Exit 1 = blocked or invalid.
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync, mkdirSync, readdirSync,
         statSync, existsSync, unlinkSync } from 'node:fs';
import { join, relative, resolve, sep, posix } from 'node:path';
import { argv, exit, cwd } from 'node:process';

// --- args -----------------------------------------------------------------
const args = { context: '.', dockerfile: 'Dockerfile', output: null,
               verifySentinels: false };
for (let i = 2; i < argv.length; i++) {
  switch (argv[i]) {
    case '--context': args.context = argv[++i]; break;
    case '--dockerfile': args.dockerfile = argv[++i]; break;
    case '--output': args.output = argv[++i]; break;
    case '--verify-sentinels': args.verifySentinels = true; break;
    default:
      console.error(`unknown arg: ${argv[i]}`); exit(2);
  }
}
const contextDir = resolve(cwd(), args.context);
if (!existsSync(join(contextDir, args.dockerfile))) {
  console.error(`FAIL: ${args.dockerfile} not found under ${args.context}`);
  exit(1);
}

// --- ignore resolution ------------------------------------------------------
// Precedence mirrors BuildKit: <dockerfile>.dockerignore wins when
// present, else .dockerignore in the context root.
const namedIgnore = join(contextDir, `${args.dockerfile}.dockerignore`);
const rootIgnore = join(contextDir, '.dockerignore');
const ignoreSource = existsSync(namedIgnore) ? namedIgnore
                   : existsSync(rootIgnore)   ? rootIgnore : null;
const patterns = [];
if (ignoreSource) {
  for (const raw of readFileSync(ignoreSource, 'utf8').split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const negated = line.startsWith('!');
    patterns.push({ negated, pat: negated ? line.slice(1).trim() : line });
  }
}

// dockerignore glob -> regex. All patterns anchor at the context
// root: `*` and `?` never cross '/', `**` crosses everything. A
// trailing '/' marks a directory pattern (prunes its subtree).
function toRegex(p) {
  let s = p.replace(/\\/g, '/');
  if (s.startsWith('/')) s = s.slice(1);
  const dirOnly = s.endsWith('/');
  if (dirOnly) s = s.slice(0, -1);
  let re = '';
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (c === '*') {
      if (s[i + 1] === '*') {
        re += '.*'; i++;
        if (s[i + 1] === '/') i++; // '**/' -> optional leading dirs
      } else re += '[^/]*';
    } else if (c === '?') re += '[^/]';
    else re += c.replace(/[.+^${}()|[\]\\]/g, '\\$&');
  }
  return { re: new RegExp(`^${re}$`), dirOnly };
}
const compiled = patterns.map(p => ({ ...p, ...toRegex(p.pat) }));

// Last match wins; a pattern matching any ANCESTOR dir also matches
// (directory pruning). Negations re-include; a path with no match is
// included — we err toward "included" so the block check stays
// conservative rather than falsely reassuring.
function excluded(relPath) {
  const parts = relPath.split('/');
  let result = false;
  for (const { re, dirOnly, negated } of compiled) {
    for (let depth = parts.length; depth >= 1; depth--) {
      const cand = parts.slice(0, depth).join('/');
      if (dirOnly && depth === parts.length) continue; // dir pattern
                                                      // can't match file
      if (re.test(cand)) { result = !negated; break; }
    }
  }
  return result;
}

// --- walk ------------------------------------------------------------------
function walk(dir, base, out) {
  for (const ent of readdirSync(dir, { withFileTypes: true })) {
    const rel = base ? `${base}/${ent.name}` : ent.name;
    if (ent.isDirectory()) walk(join(dir, ent.name), rel, out);
    else if (ent.isFile() || ent.isSymbolicLink()) out.push(rel);
  }
}
const all = [];
walk(contextDir, '', all);
const included = all.filter(p => !excluded(p));

// --- blocked namespaces ------------------------------------------------------
// Namespace prefixes that must never reach a builder. Checked
// against the INCLUDED set — an ignore rule that accidentally lets
// one through is the exact bug this gate exists to catch.
const BLOCKED_PREFIXES = [
  'plans', 'private', '.private', 'docs/private', 'docs/internal',
  '.secrets', '.git', '.codex', '.claude', '.agents', '.devin',
  '.cursor', '.gemini', '.grok', '.omp', '.opencode', '.dsh',
  'node_modules', 'artifacts', 'coverage', 'tmp',
  // Harness binaries must never enter the release build context —
  // .dockerignore also excludes them, but this gate refuses the
  // context independently if that exclusion ever regresses.
  'cmd/testapp', 'cmd/fixture',
];
const BLOCKED_FILES = new Set(['.env', 'docker-compose.override.yml']);
const blockedRe = new RegExp(
  `(^|/)\\.env(\\.|$)|(^|/)[^/]*\\.(pem|key|p12|pfx)$` +
  `|(^|/)id_(rsa|ed25519|ecdsa)(\\.pub)?$|(^|/)known_hosts$`);
const envOk = /\.(example|sample|template)$/;

function verdicts(list) {
  const hits = [];
  for (const rel of list) {
    const top = rel.split('/')[0];
    const two = rel.split('/').slice(0, 2).join('/');
    if (BLOCKED_PREFIXES.includes(top) || BLOCKED_PREFIXES.includes(two)) {
      hits.push(rel); continue;
    }
    if (BLOCKED_FILES.has(rel)) { hits.push(rel); continue; }
    if (blockedRe.test(rel) && !envOk.test(rel)) hits.push(rel);
  }
  return hits;
}

// --- sentinels ---------------------------------------------------------------
// Inert negative fixtures: dropped into blocked namespaces, they must
// NOT resolve into the included set. Positive fixtures prove required
// inputs DO resolve. Cleaned up unconditionally.
const NEG_SENTINELS = [
  'plans/.ctx-sentinel-c78', '.env.ctx-sentinel',
  '.secrets/.ctx-sentinel-c78', 'node_modules/.ctx-sentinel-c78',
];
// Dockerfile itself is NOT required in the context — the client
// reads it directly; only compile inputs must resolve as included.
const POS_REQUIRED = ['go.mod', 'go.sum'];
const POS_PREFIXES = ['cmd/', 'internal/'];
const created = [];
try {
  if (args.verifySentinels) {
    for (const rel of NEG_SENTINELS) {
      const abs = join(contextDir, rel);
      try {
        mkdirSync(join(abs, '..'), { recursive: true });
        writeFileSync(abs, 'inert build-context sentinel — safe to delete\n');
        created.push(abs);
      } catch { /* dir absent is fine — sentinel moot */ }
    }
  }
  // Re-walk when sentinels were planted so they are resolved too.
  const effective = args.verifySentinels && created.length
    ? (() => { const l = []; walk(contextDir, '', l);
               return l.filter(p => !excluded(p)); })()
    : included;

  const leaked = [];
  if (args.verifySentinels) {
    for (const rel of NEG_SENTINELS) {
      const relPos = rel.split(sep).join(posix.sep);
      if (effective.includes(relPos)) leaked.push(relPos);
    }
    for (const rel of POS_REQUIRED) {
      if (!effective.includes(rel)) leaked.push(`REQUIRED-MISSING:${rel}`);
    }
    for (const pre of POS_PREFIXES) {
      if (!effective.some(f => f.startsWith(pre))) {
        leaked.push(`REQUIRED-MISSING:${pre}*`);
      }
    }
  }
  const hits = verdicts(effective);
  const ok = hits.length === 0 && leaked.length === 0;

  // --- manifest receipt ------------------------------------------------------
  const files = effective.sort().map(rel => {
    const abs = join(contextDir, rel);
    let sha = null, bytes = 0;
    try {
      const buf = readFileSync(abs);
      sha = createHash('sha256').update(buf).digest('hex');
      bytes = statSync(abs).size;
    } catch { /* raced delete — record without hash */ }
    return { path: rel.split(sep).join(posix.sep), sha256: sha, bytes };
  });
  const manifest = {
    gate: 'check-build-context',
    generatedAt: new Date().toISOString(),
    context: relative(cwd(), contextDir) || '.',
    dockerfile: args.dockerfile,
    ignoreSource: ignoreSource
      ? relative(cwd(), ignoreSource).split(sep).join(posix.sep) : null,
    patternsApplied: patterns.length,
    fileCount: files.length,
    totalBytes: files.reduce((a, f) => a + f.bytes, 0),
    contextHash: createHash('sha256')
      .update(files.map(f => `${f.path}:${f.sha256}`).join('\n'))
      .digest('hex'),
    blockedPrefixes: BLOCKED_PREFIXES,
    hits, sentinelLeaks: leaked,
    verdict: ok ? 'PASS' : 'FAIL',
    files,
  };
  if (args.output) {
    mkdirSync(join(args.output, '..'), { recursive: true });
    writeFileSync(args.output, JSON.stringify(manifest, null, 2) + '\n');
  }
  if (!ok) {
    for (const h of hits) console.error(`BLOCKED-IN-CONTEXT: ${h}`);
    for (const l of leaked) console.error(`SENTINEL/REQUIRED FAIL: ${l}`);
    console.error(`FAIL: context unsafe — ${hits.length} blocked, ` +
      `${leaked.length} sentinel violations`);
    exit(1);
  }
  console.log(`PASS: ${files.length} files, ` +
    `${(manifest.totalBytes / 1024 / 1024).toFixed(1)}MiB, ` +
    `contextHash ${manifest.contextHash.slice(0, 16)}…`);
} finally {
  for (const abs of created) { try { unlinkSync(abs); } catch {} }
}
