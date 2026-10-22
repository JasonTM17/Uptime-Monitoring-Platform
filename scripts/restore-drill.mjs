#!/usr/bin/env node
// restore-drill.mjs — C81 restore rehearsal against the disposable
// compose.test.yaml stack. Operator path: quiesce app -> pg_dump ->
// manifest receipt -> fresh disposable database -> pg_restore ->
// pre-enable reconcile (expired leases + global session revocation) ->
// repoint app at the restored DB -> evidence + measured RPO/RTO.
//
// The drill dataset is seeded deterministically (API for identity/
// channel ciphertext, SQL for the incident/outbox fixture) — restore
// semantics are under test, not the create paths.
//
// Nothing destructive touches the source: the dump is read-only,
// restore lands in a NEW database, and `down -v` disposes everything.
//
// Usage:
//   node scripts/restore-drill.mjs --target fresh \
//     --output artifacts/restore/report.json

import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, writeFileSync, readFileSync, readdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import os from "node:os";
import { execSync } from "node:child_process";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const COMPOSE = ["compose", "-f", "compose.test.yaml"];
const API = "http://localhost:18080";
const RESTORE_DB = "restore_drill";
const KEY_V1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
const KEY_V2 = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=";

const args = {};
for (let i = 2; i < process.argv.length; i += 2) {
  args[process.argv[i].replace(/^--/, "")] = process.argv[i + 1];
}
if (args.target !== "fresh") die("only --target fresh exists (disposable target)");
const output = args.output ?? "artifacts/restore/report.json";

function die(msg) { throw new Error(`restore-drill: ${msg}`); }
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const nowISO = () => new Date().toISOString();
const steps = [];
const step = (name, ok, evidence) => { steps.push({ name, ok, evidence }); console.log(`${ok ? "PASS" : "FAIL"}  ${name} — ${evidence}`); };

function run(cmd, argv, env = {}) {
  return new Promise((res, rej) => {
    const p = spawn(cmd, argv, { cwd: root, env: { ...process.env, ...env } });
    let out = "", err = "";
    p.stdout.on("data", (d) => (out += d));
    p.stderr.on("data", (d) => (err += d));
    p.on("close", (c) => (c === 0 ? res(out) : rej(new Error(`${cmd} ${argv.join(" ")} -> ${c}: ${err.slice(-400)}`))));
  });
}
const compose = (...a) => run("docker", [...COMPOSE, ...a]);
function runInput(cmd, argv, input) {
  return new Promise((res, rej) => {
    const p = spawn(cmd, argv, { cwd: root, env: process.env });
    let out = "", err = "";
    p.stdout.on("data", (d) => (out += d));
    p.stderr.on("data", (d) => (err += d));
    p.on("close", (c) => (c === 0 ? res(out) : rej(new Error(`${argv.join(" ")} -> ${c}: ${err.slice(-400)}`))));
    p.stdin.write(input);
    p.stdin.end();
  });
}
const psqlOn = (db, sql) =>
  compose("exec", "-T", "db", "psql", "-U", "accept", "-d", db, "-Atc", sql);
const psql = (sql) => psqlOn("accept", sql);

async function waitFor(url, what, timeoutMs = 90000) {
  const dl = Date.now() + timeoutMs;
  for (;;) {
    try { const r = await fetch(url); if (r.ok) return; } catch {}
    if (Date.now() > dl) die(`${what} not ready within ${timeoutMs}ms`);
    await sleep(1000);
  }
}

// ---------- API client (same cookie-jar convention as accept-local) ----------
class Client {
  #csrf = ""; #cookies = new Map();
  get cookie() {
    return [...this.#cookies].map(([k, v]) => `${k}=${v}`).join("; ");
  }
  async req(method, path, body, headers = {}) {
    const h = { accept: "application/json", ...headers };
    if (this.#cookies.size) h.cookie = this.cookie;
    if (body !== undefined) {
      h["content-type"] = "application/json";
      h["x-csrf-token"] = this.#csrf;
      h.origin = API;
    }
    const r = await fetch(API + path, { method, headers: h,
      body: body === undefined ? undefined : JSON.stringify(body), redirect: "manual" });
    for (const c of r.headers.getSetCookie?.() ?? []) {
      const [kv] = c.split(";");
      const i = kv.indexOf("=");
      this.#cookies.set(kv.slice(0, i).trim(), kv.slice(i + 1));
    }
    let j = null; try { j = await r.json(); } catch {}
    return { status: r.status, json: j };
  }
  async init() {
    const r = await this.req("GET", "/auth/csrf");
    this.#csrf = r.json?.data?.csrf_token;
    if (!this.#csrf) die("csrf bootstrap failed");
  }
}

// ---------- manifest (mirrors testsupport.ValidateManifest) ----------
const DRILL_FORMAT = "uptime-restore-v1";
function validateManifest(m, wantSchema) {
  if (m.format !== DRILL_FORMAT) die(`manifest format ${m.format}`);
  if (m.schema_version !== wantSchema)
    die(`manifest schema ${m.schema_version} != head ${wantSchema}`);
  if (!m.source_db || !m.created_at || (m.dump_sha256 ?? "").length !== 64)
    die("manifest missing required fields");
}
const sha256 = (buf) => createHash("sha256").update(buf).digest("hex");
const sqlNum = async (db, q) => Number((await psqlOn(db, q)).trim() || 0);
const sqlVal = async (q) => (await psql(q)).trim().split(String.fromCharCode(10))[0];

const TABLES = ["users", "sessions", "quota_budgets", "monitors",
  "notification_channels", "monitor_channels", "engine_control",
  "schedule_segments", "check_runs", "check_results", "incidents",
  "notification_outbox", "hourly_stats", "permissions", "roles",
  "role_permissions", "user_roles", "security_anchor",
  "audit_events", "admin_idempotency"];

// ---------- main ----------
const report = {
  meta: {
    tool: "scripts/restore-drill.mjs", target: "fresh", generated_at: nowISO(),
    git_sha: execSync("git rev-parse --short HEAD").toString().trim(),
    machine: `${os.type()} ${os.release()} ${os.arch()}, ${os.cpus().length} cpus`,
    composition: "compose.test.yaml (disposable accept world)",
    note: "local measurement only — RPO/RTO here are NOT hosted guarantees",
  },
  timings: {}, receipt: {}, verdict: "PENDING", steps,
};

try {
  // ---------- clean stack, seed the drill world ----------
  console.log("down -v / build / up disposable accept world");
  await compose("down", "-v").catch(() => {});
  await compose("build", "harness");
  await compose("up", "-d", "--wait", "db");
  await compose("up", "migrate");
  await compose("up", "-d", "app", "target");
  await waitFor(`${API}/health/ready`, "app ready");

  const client = new Client();
  await client.init();
  const email = `drill-${Date.now()}@accept.test`;
  const password = "drill-dummy-password-1";
  let r = await client.req("POST", "/auth/register",
    { email, password, display_name: "restore drill" });
  if (r.status >= 300) die(`register -> ${r.status}`);
  r = await client.req("POST", "/auth/login", { email, password });
  if (r.status >= 300) die(`login -> ${r.status}`);
  const oldCookie = client.cookie; // the pre-restore authority
  const meR = await client.req("GET", "/auth/me");
  const userID = meR.json?.data?.user?.id;
  if (!userID) die("/auth/me missing user id");

  r = await client.req("POST", "/monitors", {
    name: "drill-mon", target_url: "http://target-public.fixture/check",
    interval_seconds: 60, timeout_seconds: 5, expected_status: 200 });
  const monID = r.json.data.id;
  // Channel: create pending via API (label only — the destination is
  // never in the request body), verify via operator CLI on stdin.
  r = await client.req("POST", "/notification-channels", { label: "drill-chan" });
  if (r.status >= 300) die(`channel -> ${r.status} ${JSON.stringify(r.json)}`);
  const chanID = r.json.data.id;
  await runInput("docker",
    [...COMPOSE, "exec", "-T", "app", "/harness-bin/channel", "verify",
      "-channel", chanID, "-owner", userID, "-receipt", "drill-verify"],
    "drill-chat-001\n");
  const chanState = (await psql(
    `SELECT status||'|'||coalesce(encryption_key_version::text,'null') FROM uptime.notification_channels WHERE id='${chanID}'`)).trim();

  // Deterministic incident + outbox fixture via SQL (drill dataset,
  // not API evidence): completed run w/ result (recent charge),
  // interrupted run (must stay sample-free), open incident, causal
  // outbox chain (PENDING down + expired-LEASED recovery).
  // The API-created monitor already owns a current segment and the
  // live engine may already have checked it — take the real segment,
  // generation, and epoch, and use high synthetic sequences.
  const [segID, segGen] = (await sqlVal(
    `SELECT id||'|'||generation FROM uptime.schedule_segments WHERE monitor_id='${monID}' AND ends_at IS NULL`)).split("|");
  const epoch = await sqlVal(`SELECT epoch FROM uptime.engine_control WHERE id=1`);
  const runDone = await sqlVal(
    `INSERT INTO uptime.check_runs(id,monitor_id,segment_id,slot_at,generation,sequence,engine_epoch,status,finished_at)
     VALUES (gen_random_uuid(),'${monID}','${segID}',now()-interval '5 min',${segGen},900,${epoch},'COMPLETED',now()-interval '5 min') RETURNING id`);
  await psql(
    `INSERT INTO uptime.check_results(check_id,monitor_id,outcome,eligible,success,duration_ms,observed_at)
     VALUES ('${runDone}','${monID}','SUCCESS',true,true,42,now()-interval '5 min')`);
  const runInt = await sqlVal(
    `INSERT INTO uptime.check_runs(id,monitor_id,segment_id,slot_at,generation,sequence,engine_epoch,status,finished_at,terminal_reason)
     VALUES (gen_random_uuid(),'${monID}','${segID}',now()-interval '4 min',${segGen},901,${epoch},'INTERRUPTED',now()-interval '4 min','engine_takeover') RETURNING id`);
  const incID = await sqlVal(
    `INSERT INTO uptime.incidents(id,monitor_id,opened_check_id,opened_at)
     VALUES (gen_random_uuid(),'${monID}','${runDone}',now()-interval '3 min') RETURNING id`);
  // The DOWN head seeds SENT — it delivered before the snapshot.
  // (PENDING here would race the live pre-dump dispatcher: it could
  // send in the old app's recording buffer, which the repoint then
  // discards, making the post-restore recording count racy.)
  const boxDown = await sqlVal(
    `INSERT INTO uptime.notification_outbox(id,user_id,monitor_id,incident_id,channel_id,event_kind,event_key,channel_version,safe_payload,state)
     VALUES (gen_random_uuid(),'${userID}','${monID}','${incID}','${chanID}','DOWN','drill-down-${Date.now()}',2,'{}','SENT') RETURNING id`);
  await psql(
    `INSERT INTO uptime.notification_outbox(id,user_id,monitor_id,incident_id,channel_id,event_kind,event_key,predecessor_id,channel_version,safe_payload,state,lease_token,lease_expires_at)
     VALUES (gen_random_uuid(),'${userID}','${monID}','${incID}','${chanID}','RECOVERY','drill-rec-${Date.now()}','${boxDown}',2,'{}','LEASED',gen_random_uuid(),now()-interval '1 min')`);
  step("seed", true, `user+session+monitor+channel(${chanState})+incident/outbox fixture`);

  // Baseline: the pre-restore session really authenticates.
  const me = await fetch(`${API}/auth/me`, { headers: { cookie: oldCookie } });
  if (me.status !== 200) die(`pre-dump session not valid: ${me.status}`);

  // ---------- quiesce, dump, manifest ----------
  await compose("stop", "app"); // engine + dispatcher disabled
  const countsSrc = {};
  for (const tbl of TABLES) {
    countsSrc[tbl] = await sqlNum("accept", `SELECT count(*) FROM uptime.${tbl}`);
  }
  const schemaHead = await sqlNum("accept", `SELECT max(version) FROM schema_migrations`);
  const migHead = readdirSync(resolve(root, "migrations")).filter((f) => f.endsWith(".up.sql")).length;

  const t0 = Date.now();
  await compose("exec", "-T", "db", "pg_dump", "-U", "accept", "-Fc", "-f", "/tmp/drill.pgc", "accept");
  report.timings.dump_s = +((Date.now() - t0) / 1000).toFixed(2);
  mkdirSync(dirname(resolve(output)), { recursive: true });
  const dumpPath = resolve(output).replace(/\.json$/, ".pgc");
  await run("docker", ["cp", "uptime-accept-db-1:/tmp/drill.pgc", dumpPath]);
  const dumpBuf = readFileSync(dumpPath);
  const pgDumpVersion = (await compose("exec", "-T", "db", "pg_dump", "--version")).trim();

  const manifest = {
    format: DRILL_FORMAT, schema_version: schemaHead, created_at: nowISO(),
    source_db: "accept", pg_dump_version: pgDumpVersion,
    dump_sha256: sha256(dumpBuf), tables: TABLES.length,
  };
  validateManifest(manifest, migHead);
  // Corrupt receipts must refuse — exercise the validator negatively.
  try {
    validateManifest({ ...manifest, schema_version: schemaHead + 1 }, migHead);
    die("wrong-version manifest accepted");
  } catch (e) { if (!/schema/.test(e.message)) throw e; }
  writeFileSync(resolve(output).replace(/\.json$/, "-manifest.json"), JSON.stringify(manifest, null, 2));
  report.receipt.manifest = manifest;
  step("dump+manifest", true,
    `${(dumpBuf.length / 1024).toFixed(0)}KiB pgcustom, schema v${schemaHead}, ${report.timings.dump_s}s`);

  // ---------- fresh target, restore, reconcile BEFORE enable ----------
  await psqlOn("postgres", `DROP DATABASE IF EXISTS ${RESTORE_DB}`);
  await psqlOn("postgres", `CREATE DATABASE ${RESTORE_DB}`);
  await run("docker", ["cp", dumpPath, "uptime-accept-db-1:/tmp/drill.pgc"]);
  const t1 = Date.now();
  await compose("exec", "-T", "db", "pg_restore", "-U", "accept", "-d", RESTORE_DB, "/tmp/drill.pgc");
  report.timings.restore_s = +((Date.now() - t1) / 1000).toFixed(2);

  // Pre-enable reconcile: expired leases -> PENDING; every restored
  // session loses authority via the global security_version bump.
  const reclaimed = Number((await psqlOn(RESTORE_DB,
    `WITH u AS (UPDATE uptime.notification_outbox SET state='PENDING',
       lease_token=NULL, lease_expires_at=NULL, version=version+1
     WHERE state='LEASED' AND lease_expires_at < now() RETURNING 1)
     SELECT count(*) FROM u`)).trim() || 0);
  await psqlOn(RESTORE_DB, `UPDATE uptime.users SET security_version=security_version+1`);
  const fabInt = await sqlNum(RESTORE_DB,
    `SELECT count(*) FROM uptime.check_results WHERE check_id='${runInt}'`);
  step("restore+reconcile", fabInt === 0 && reclaimed === 1,
    `pg_restore ${report.timings.restore_s}s, reclaimed=${reclaimed}, sessions revoked, interrupted run samples=${fabInt}`);

  // ---------- repoint app at the restored DB (dual-read ring, v2 writes) ----------
  const repointEnv = {
    CAP_DB_NAME: RESTORE_DB,
    CAP_READ_KEYRING: `1=${KEY_V1},2=${KEY_V2}`,
    CAP_WRITE_KEY_VERSION: "2",
  };
  await run("docker", [...COMPOSE, "up", "-d", "app"], repointEnv);
  await waitFor(`${API}/health/ready`, "restored app ready");

  const oldSess = await fetch(`${API}/auth/me`, { headers: { cookie: oldCookie } });
  step("old-session-revoked", oldSess.status === 401,
    `restored world's app rejects pre-restore session: ${oldSess.status}`);

  const c2 = new Client();
  await c2.init();
  r = await c2.req("POST", "/auth/login", { email, password });
  step("new-authority-login", r.status === 200, `re-login into restored world -> ${r.status}`);

  // New writes under the rotated ring seal at v2 — sealing happens
  // at verify, so the post-restore channel is created AND verified
  // through the operator CLI inside the repointed app container.
  r = await c2.req("POST", "/notification-channels", { label: "drill-chan-2" });
  const newChan = r.json.data.id;
  await runInput("docker",
    [...COMPOSE, "exec", "-T", "app", "/harness-bin/channel", "verify",
      "-channel", newChan, "-owner", userID, "-receipt", "drill-verify-2"],
    "drill-chat-002\n");
  const kv2 = await sqlNum(RESTORE_DB,
    `SELECT encryption_key_version FROM uptime.notification_channels WHERE id='${newChan}'`);
  step("new-writes-v2", kv2 === 2, `post-restore channel sealed under key_version=${kv2}`);

  // Dispatcher reconciles the restored outbox — the reclaimed child
  // goes SENT through the recording sender (never a live provider).
  // The buffer is per-app-instance, so only post-repoint sends are
  // recorded: head(SENT at seed) + child(sent post-restore) = 1 new
  // recording, 2 SENT rows total for the drill user.
  let sent = 0;
  const dl0 = Date.now();
  while (Date.now() - dl0 < 30000) {
    sent = await sqlNum(RESTORE_DB,
      `SELECT count(*) FROM uptime.notification_outbox WHERE state='SENT' AND user_id='${userID}'`);
    if (sent >= 2) break;
    await sleep(1500);
  }
  const recDeliveries = (await (await fetch(`${API}/__test__/deliveries`)).json()).deliveries ?? [];
  step("outbox-delivered-recorded", sent >= 2 && recDeliveries.length >= 1,
    `SENT=${sent} recorded=${recDeliveries.length} post-repoint sends (recording sink, no live send)`);

  // ---------- receipt: identity + integrity ----------
  const countsDst = {};
  let drift = [];
  for (const tbl of TABLES) {
    countsDst[tbl] = await sqlNum(RESTORE_DB, `SELECT count(*) FROM uptime.${tbl}`);
    // counts grow legitimately post-enable (sessions, channels, outbox
    // state churn) — the receipt compares the SEEDED set, so compare
    // only tables the drill froze, and note the delta elsewhere.
    if (countsDst[tbl] < countsSrc[tbl]) drift.push(`${tbl}:${countsSrc[tbl]}->${countsDst[tbl]}`);
  }
  const orphans = await sqlNum(RESTORE_DB,
    `SELECT count(*) FROM uptime.notification_outbox o LEFT JOIN uptime.notification_outbox p
       ON o.predecessor_id=p.id WHERE o.predecessor_id IS NOT NULL AND p.id IS NULL`)
    + await sqlNum(RESTORE_DB,
    `SELECT count(*) FROM uptime.sessions s WHERE NOT EXISTS (SELECT 1 FROM uptime.users u WHERE u.id=s.user_id)`);
  const charge = await sqlNum(RESTORE_DB,
    `SELECT count(*) FROM uptime.check_results WHERE check_id='${runDone}' AND duration_ms=42`);
  const pred = await sqlNum(RESTORE_DB,
    `SELECT count(*) FROM uptime.notification_outbox WHERE predecessor_id='${boxDown}'`);
  step("receipt", drift.length === 0 && orphans === 0 && charge === 1 && pred === 1,
    `drift=[${drift.join(",")}] orphans=${orphans} charge=${charge} predecessor=${pred}`);

  report.receipt.counts_source = countsSrc;
  report.receipt.counts_restored = countsDst;
  report.receipt.fk_orphans = orphans;
  report.receipt.interrupted_run_samples = fabInt;
  report.receipt.deliveries_recorded = recDeliveries.length;
  report.timings.total_s = +((Date.now() - t0) / 1000).toFixed(2);
  report.receipt.rpo = "0 (quiesced snapshot — dump taken with app stopped)";
  report.receipt.rto_measured_s = report.timings.total_s;
  report.verdict = steps.every((s) => s.ok) ? "PASS" : "FAIL";
  writeFileSync(resolve(output), JSON.stringify(report, null, 2));
  console.log(`\nverdict ${report.verdict} — wrote ${output}`);
} catch (e) {
  console.error(e.message);
  report.verdict = "FAIL";
  report.err = e.message;
  try { writeFileSync(resolve(output), JSON.stringify(report, null, 2)); } catch {}
  process.exitCode = 2;
} finally {
  if (args.keep !== "true") await compose("down", "-v").catch(() => {});
}
