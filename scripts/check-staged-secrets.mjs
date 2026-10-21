#!/usr/bin/env node
// Scoped secret gate for staged changes.
//
//   node scripts/check-staged-secrets.mjs            scan staged blobs
//   node scripts/check-staged-secrets.mjs --self-test  run fixture assertions
//
// Contract:
//   - Staged paths are enumerated with `git diff --cached --name-status -z`
//     (NUL-safe, execFile, no shell interpolation).
//   - Each staged path is scanned as the STAGED BLOB (`git show :path`), so
//     the gate does not depend on diff prefixes, quoting, attributes, or
//     context-line rules — those classes of bypass cannot exist here.
//   - Staged SENSITIVE FILENAMES (.env, prod.env, *.pem, credentials,
//     id_rsa, ...) are refused outright: .gitignore only blocks untracked
//     files and `git add -f` bypasses it.
//   - Example-suffixed paths (*.example|sample|template|dist) are NOT
//     refused by name (they are legit to commit) but their content is
//     still scanned — an example file holding a real secret is a leak.
//   - scripts/testdata/ is fully exempt: it holds inert scanner fixtures.
//   - Placeholder-shaped values (${VAR}, replace-me, <yours>, ...) do not
//     count as secrets.
//   - Findings print file:line + rule name with the match fully masked.
//   - Binary blobs and staged deletions are skipped (documented scope).
//   - Exit 0 clean, 2 on findings or refusals. Unhandled errors exit
//     non-zero (fail closed).

import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const RULES = [
  { name: 'telegram-bot-token', re: /\b\d{6,12}:[A-Za-z0-9_-]{35}\b/ },
  {
    name: 'dsn-with-password',
    re: /\b(?:postgres(?:ql)?|mysql2?|mariadb|mongodb(?:\+srv)?|rediss?|amqps?):\/\/[^\s:/]+:[^\s@/]{3,}@/,
  },
  { name: 'pem-private-key', re: /-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----/ },
  { name: 'aws-access-key-id', re: /\bAKIA[0-9A-Z]{16}\b/ },
  { name: 'github-token', re: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b|\bgithub_pat_[A-Za-z0-9_]{20,}\b/ },
  { name: 'api-token', re: /\bsk-[A-Za-z0-9_-]{20,}\b/ },
  { name: 'jwt', re: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\b/ },
  {
    name: 'generic-assigned-secret',
    re: /(?:api[-_]?key|access[-_]?key|secret|token|pass(?:word|phrase|wd)?|pwd|credential|private[-_]?key)[-._a-z0-9]*\s*[:=]\s*['"]?[^\s'"]{12,}/i,
  },
];

// Refused as staged filenames regardless of content.
const NAME_REFUSAL = [
  /(^|\/)\.env(\.[^/]*)?$/i, // .env, .env.local, .env.production, ...
  /(^|\/)\.envrc$/i,
  /\.env(\.bak|\.backup|\.old|\.save|\.swp)?$/i, // prod.env, app.env.bak, ...
  /(^|\/)\.secrets?\//, /(^|\/)secrets?\//i, /(^|\/)credentials?\//i,
  /(^|\/)\.aws\/credentials$/i,
  /(^|\/)credentials$/i,
  /(^|\/)\.pgpass$/i, /(^|\/)\.pg_service\.conf$/i, /(^|\/)\.netrc$/i,
  /(^|\/)\.npmrc$/i,
  /(^|\/)(id_rsa|id_dsa|id_ecdsa|id_ed25519)$/i,
  /\.(pem|key|p12|pfx|jks|keystore|ovpn)$/i,
];

// These suffixes legitimately live in the repo (placeholders). They are
// exempt from NAME refusal but never from content scanning.
const NAME_EXEMPT = [/\.(example|sample|template|dist)$/i, /(^|\/)scripts\/testdata\//];

// Content inside these paths is never scanned (inert fixtures live here,
// including this file's own self-test literals).
const CONTENT_EXEMPT = [
  /(^|\/)scripts\/testdata\//,
  /(^|\/)scripts\/check-staged-secrets\.mjs$/,
];

// A match that contains a placeholder marker is not a secret.
const PLACEHOLDER = /\$\{|\$\(|replace[-_]?me|change[-_]?me|changeme|example|placeholder|dummy|your[-_]|<[^>]*>/i;

function isSensitivePath(p) {
  if (NAME_EXEMPT.some((re) => re.test(p))) return false;
  return NAME_REFUSAL.some((re) => re.test(p));
}

function isContentExempt(p) {
  return CONTENT_EXEMPT.some((re) => re.test(p));
}

const MASKED = '**masked**';

// scanText returns [{rule, line, masked}] for the given content lines.
function scanText(lines) {
  const findings = [];
  lines.forEach((text, i) => {
    for (const { name, re } of RULES) {
      const m = text.match(re);
      if (m && !PLACEHOLDER.test(m[0])) {
        findings.push({ rule: name, line: i + 1, masked: MASKED });
      }
    }
  });
  return findings;
}

function stagedPaths() {
  const out = execFileSync(
    'git',
    ['diff', '--cached', '--name-status', '-z', '--diff-filter=ACMR'],
    { encoding: 'utf8' },
  );
  const tokens = out.split('\0').filter(Boolean);
  const paths = [];
  let i = 0;
  while (i < tokens.length) {
    const status = tokens[i];
    if (status[0] === 'R' || status[0] === 'C') {
      paths.push(tokens[i + 2]);
      i += 3;
    } else {
      paths.push(tokens[i + 1]);
      i += 2;
    }
  }
  return paths;
}

function stagedBlobText(path) {
  const buf = execFileSync('git', ['show', ':' + path], { maxBuffer: 64 * 1024 * 1024 });
  if (buf.includes(0)) return null; // binary blob: documented skip
  return buf.toString('utf8').split('\n');
}

function runScan() {
  let failed = false;

  const paths = stagedPaths();
  for (const p of paths) {
    if (isSensitivePath(p)) {
      console.log(`REFUSED ${p}: sensitive filename must not be staged`);
      failed = true;
    }
  }

  for (const p of paths) {
    if (isContentExempt(p)) continue;
    let lines;
    try {
      lines = stagedBlobText(p);
    } catch {
      continue; // staged deletion or unreadable gitlink
    }
    if (lines === null) continue;
    for (const f of scanText(lines)) {
      console.log(`${p}:${f.line} ${f.rule} match=${f.masked}`);
      failed = true;
    }
  }
  return failed;
}

function selfTest() {
  const root = join(fileURLToPath(import.meta.url), '..', 'testdata', 'fixtures');
  const fixture = readFileSync(join(root, 'leaky.txt'), 'utf8').split('\n');
  const clean = readFileSync(join(root, 'clean.txt'), 'utf8').split('\n');
  const found = scanText(fixture);
  const rulesHit = new Set(found.map((f) => f.rule));
  const checks = [
    ['detects telegram token', rulesHit.has('telegram-bot-token')],
    ['detects postgres dsn', rulesHit.has('dsn-with-password')],
    ['detects pem key', rulesHit.has('pem-private-key')],
    ['detects generic api_key', rulesHit.has('generic-assigned-secret')],
    ['masks every match fully', found.every((f) => f.masked === MASKED)],
    ['detects SECRET_KEY compound', scanText(['SECRET_KEY=S3cur3Value123456']).length > 0],
    ['detects aws-style secret', scanText(['aws_secret_access_key = wJalrXUtnFEMIK7MDENGbPxRfiCYk7d3mPqR']).length > 0],
    ['skips aws documented example', scanText(['aws_secret_access_key = wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY']).length === 0],
    ['detects short password', scanText(['DB_PASS=Sup3rSecret123']).length > 0],
    ['detects mysql dsn', scanText(['dsn=mysql://u:passw0rd@h/db']).length > 0],
    ['detects DSA pem', scanText(['-----BEGIN DSA PRIVATE KEY-----']).length > 0],
    ['detects github token', scanText(['ghp_' + 'a'.repeat(36)]).length > 0],
    ['detects jwt', scanText(['eyJhbGciOiJIUzI1NiIs.eyJzdWIiOiIxMjM0NTY3O.SflKxwRJSMeKKF2QT4fwpMe']).length > 0],
    ['skips placeholder dsn', scanText(['DATABASE_URL=postgres://u:replace-me-password@127.0.0.1/db']).length === 0],
    ['skips ${VAR} interpolation', scanText(['url: postgres://${U}:${P}@h/d']).length === 0],
    ['refuses .env', isSensitivePath('.env')],
    ['refuses .env.local', isSensitivePath('.env.local')],
    ['refuses prod.env', isSensitivePath('prod.env')],
    ['refuses prod.env.bak', isSensitivePath('prod.env.bak')],
    ['refuses nested key file', isSensitivePath('certs/id.pem')],
    ['refuses aws credentials file', isSensitivePath('.aws/credentials')],
    ['refuses credentials filename', isSensitivePath('deploy/credentials')],
    ['refuses secrets dir', isSensitivePath('deploy/secrets/api.txt')],
    ['refuses id_ed25519', isSensitivePath('ssh/id_ed25519')],
    ['refuses .npmrc', isSensitivePath('.npmrc')],
    ['allows .env.example name but still scans', !isSensitivePath('.env.example') && !isContentExempt('.env.example')],
    ['allows .env.production.example name but still scans', !isSensitivePath('.env.production.example') && !isContentExempt('.env.production.example')],
    ['allows fixture dir fully', !isSensitivePath('scripts/testdata/fixtures/leaky.txt') && isContentExempt('scripts/testdata/fixtures/leaky.txt')],
    ['skips own source (self-test literals)', isContentExempt('scripts/check-staged-secrets.mjs')],
    ['clean fixture passes', scanText(clean).length === 0],
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
