#!/usr/bin/env node
// Scoped secret gate for staged changes.
//
//   node scripts/check-staged-secrets.mjs            scan staged diff
//   node scripts/check-staged-secrets.mjs --self-test  run fixture assertions
//
// Contract:
//   - Staged files are enumerated with `git diff --cached --name-only -z`
//     (NUL-safe, execFile, no shell interpolation).
//   - Staged SENSITIVE FILENAMES (.env, *.pem, *.key, ...) are refused
//     outright: .gitignore only blocks untracked files and `git add -f`
//     bypasses it.
//   - Only ADDED lines of the staged diff are scanned.
//   - Findings print file:line + rule name with the match masked; a match
//     value is never printed in full.
//   - Example/template/fixture paths are exempt; they carry placeholders.
//   - Exit 0 clean, 2 on findings or refusals.

import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const RULES = [
  { name: 'telegram-bot-token', re: /\b\d{8,10}:[A-Za-z0-9_-]{35}\b/ },
  { name: 'postgres-dsn-with-password', re: /postgres(?:ql)?:\/\/[^\s:/]+:[^\s@/]+@/ },
  { name: 'pem-private-key', re: /-----BEGIN (?:RSA |EC |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY/ },
  { name: 'generic-assigned-secret', re: /(?:api[_-]?key|secret|token|pass(?:word|phrase))\s*[:=]\s*['"]?[A-Za-z0-9+/=_-]{16,}/i },
];

const SENSITIVE_PATHS = [
  /(^|\/)\.env(\.[^/]*)?$/,        // .env, .env.local, .env.production, ...
  /\.env$/i,                       // prod.env, staging.env, ...
  /(^|\/)\.secrets?\//, /(^|\/)secrets\//, /(^|\/)credentials\//,
  /(^|\/)\.pgpass$/, /(^|\/)\.pg_service\.conf$/, /(^|\/)\.netrc$/,
  /\.(pem|key|p12|pfx|jks|keystore)$/i,
];

const EXEMPT_PATHS = [
  /\.(example|sample|template|dist)$/,
  /(^|\/)scripts\/testdata\//,
  /(^|\/)\.env\.example$/,
  /(^|\/)\.env\.[^/]+\.example$/,
];

function isSensitivePath(p) {
  if (EXEMPT_PATHS.some((re) => re.test(p))) return false;
  return SENSITIVE_PATHS.some((re) => re.test(p));
}

function mask(value) {
  const v = value.trim();
  if (v.length <= 6) return '…';
  return v.slice(0, 2) + '…' + v.slice(-2);
}

// scanText returns [{rule, line, masked}] for added lines of one file's diff.
function scanText(lines) {
  const findings = [];
  lines.forEach((text, i) => {
    for (const { name, re } of RULES) {
      const m = text.match(re);
      if (m) findings.push({ rule: name, line: i + 1, masked: mask(m[0]) });
    }
  });
  return findings;
}

function stagedPaths() {
  const out = execFileSync('git', ['diff', '--cached', '--name-only', '-z'], {
    encoding: 'utf8',
  });
  return out.split('\0').filter(Boolean);
}

function addedLines() {
  // Returns map path -> [added line strings].
  const diff = execFileSync('git', ['diff', '--cached', '--unified=0', '--no-color'], {
    encoding: 'utf8', maxBuffer: 64 * 1024 * 1024,
  });
  const byFile = new Map();
  let cur = null;
  for (const line of diff.split('\n')) {
    if (line.startsWith('+++ b/')) {
      cur = line.slice(6);
      if (!byFile.has(cur)) byFile.set(cur, []);
    } else if (line.startsWith('+') && cur && !line.startsWith('+++')) {
      byFile.get(cur).push(line.slice(1));
    }
  }
  return byFile;
}

function runScan() {
  let failed = false;

  for (const p of stagedPaths()) {
    if (isSensitivePath(p)) {
      console.log(`REFUSED ${p}: sensitive filename must not be staged`);
      failed = true;
    }
  }

  const perFile = addedLines();
  for (const [path, lines] of perFile) {
    if (EXEMPT_PATHS.some((re) => re.test(path))) continue;
    for (const f of scanText(lines)) {
      console.log(`${path}:${f.line} ${f.rule} match=${f.masked}`);
      failed = true;
    }
  }
  return failed;
}

function selfTest() {
  const root = join(fileURLToPath(import.meta.url), '..', 'testdata', 'fixtures');
  const fixture = readFileSync(join(root, 'leaky.txt'), 'utf8').split('\n');
  const sentinel = '123456789:';
  const found = scanText(fixture);
  const rulesHit = new Set(found.map((f) => f.rule));
  const checks = [
    ['detects telegram token', rulesHit.has('telegram-bot-token')],
    ['detects postgres dsn', rulesHit.has('postgres-dsn-with-password')],
    ['detects pem key', rulesHit.has('pem-private-key')],
    ['masks telegram sentinel', !found.some((f) => f.masked.includes(sentinel))],
    ['refuses .env', isSensitivePath('.env')],
    ['refuses .env.local', isSensitivePath('.env.local')],
    ['refuses nested key file', isSensitivePath('certs/id.pem')],
    ['allows .env.example', !isSensitivePath('.env.example')],
    ['allows fixture dir', !isSensitivePath('scripts/testdata/fixtures/leaky.txt')],
    ['refuses a real secrets dir', isSensitivePath('deploy/secrets/api.env')],
    ['clean fixture passes', scanText(['const x = 1;', 'no secrets here']).length === 0],
  ];
  let ok = true;
  for (const [label, pass] of checks) {
    console.log(`${pass ? 'PASS' : 'FAIL'} ${label}`);
    if (!pass) ok = false;
  }
  if (!ok) process.exit(2);
  console.log('self-test: all assertions passed');
}

if (process.argv.includes('--self-test')) {
  selfTest();
} else {
  process.exit(runScan() ? 2 : 0);
}
