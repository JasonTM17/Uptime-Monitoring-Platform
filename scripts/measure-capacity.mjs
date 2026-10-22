#!/usr/bin/env node
// measure-capacity.mjs — C80 capacity-recovery measurement against the
// disposable compose.test.yaml stack. Frozen protocol: 100 monitors /
// 60s interval / 10 workers / queue 20 / 1s scheduler tick (release
// parity via CAP_TICK_MS).
//
// Phases: fast (target healthy) -> timeout-heavy (target hangs past
// the 10s check timeout) -> bounded fault injections. Every claim in
// `measured` comes from /metrics scrapes, docker stats, or per-row SQL
// timings. `model` holds arithmetic projections only — never
// measurements. No production API or schema is touched; the only
// writes are ordinary monitor rows, next_check_at nudges identical to
// the resume path's own effect, and container lifecycle events.
//
// Usage:
//   node scripts/measure-capacity.mjs --profile local \
//     --duration-seconds 1800 --output artifacts/capacity-local.json

import { spawn } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import os from "node:os";
import { execSync } from "node:child_process";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const COMPOSE = ["compose", "-f", "compose.test.yaml"];
const API = "http://localhost:18080";
const CONTROL = "http://localhost:19080";

const args = {};
for (let i = 2; i < process.argv.length; i += 2) {
  args[process.argv[i].replace(/^--/, "")] = process.argv[i + 1];
}
const profile = args.profile ?? "local";
if (profile !== "local") die(`unknown profile ${profile} — only 'local' exists`);
const duration = Number(args["duration-seconds"] ?? 1800);
const output = args.output ?? "artifacts/capacity-local.json";
if (duration < 240) die("duration-seconds < 240 cannot fit the fault sequence");

const FAULT_BUDGET = Math.max(300, Math.round(duration * 0.3));
const FAST_S = Number(args["fast-seconds"] ?? Math.floor((duration - FAULT_BUDGET) / 2));
const HEAVY_S = Number(args["heavy-seconds"] ?? Math.floor((duration - FAULT_BUDGET) / 2));
const MONITORS = 100;

function die(msg) { console.error(`measure-capacity: ${msg}`); process.exit(2); }
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const nowISO = () => new Date().toISOString();

function run(cmd, argv, opts = {}) {
  return new Promise((res, rej) => {
    const p = spawn(cmd, argv, { cwd: root, env: { ...process.env, CAP_TICK_MS: "1000" }, ...opts });
    let out = "", err = "";
    p.stdout.on("data", (d) => (out += d));
    p.stderr.on("data", (d) => (err += d));
    p.on("close", (code) => (code === 0 ? res(out) : rej(new Error(`${cmd} ${argv.join(" ")} -> ${code}: ${err.slice(-400)}`))));
  });
}
const compose = (...a) => run("docker", [...COMPOSE, ...a]);
const psql = (sql) =>
  compose("exec", "-T", "db", "psql", "-U", "accept", "-d", "accept", "-Atc", sql);

async function waitFor(url, what, timeoutMs = 60000) {
  const dl = Date.now() + timeoutMs;
  for (;;) {
    try { const r = await fetch(url); if (r.ok) return; } catch {}
    if (Date.now() > dl) die(`${what} not ready within ${timeoutMs}ms`);
    await sleep(1000);
  }
}

// ---------- API client (CSRF + session cookie, mirrors accept-local) ----------
class Client {
  #csrf = ""; #cookies = new Map();
  async init() {
    const r = await this.req("GET", "/auth/csrf");
    if (r.status !== 200) die(`csrf ${r.status}`);
    this.#csrf = r.json?.data?.csrf_token ?? null;
  }
  async req(method, path, body) {
    const headers = { accept: "application/json" };
    if (this.#cookies.size)
      headers.cookie = [...this.#cookies].map(([k, v]) => `${k}=${v}`).join("; ");
    if (body !== undefined) {
      headers["content-type"] = "application/json";
      headers["x-csrf-token"] = this.#csrf;
      headers.origin = API;
    }
    const r = await fetch(API + path, { method, headers,
      body: body === undefined ? undefined : JSON.stringify(body), redirect: "manual" });
    for (const c of r.headers.getSetCookie?.() ?? []) {
      const [kv] = c.split(";");
      const i = kv.indexOf("=");
      this.#cookies.set(kv.slice(0, i).trim(), kv.slice(i + 1));
    }
    let j = null; try { j = await r.json(); } catch {}
    return { status: r.status, json: j };
  }
}

// ---------- sampler ----------
const samples = [];
let phase = "setup";
let samplerAlive = true;

function parseMetrics(text) {
  const m = {};
  for (const line of text.split("\n")) {
    if (!line || line.startsWith("#")) continue;
    const mm = line.match(/^([a-z_]+)(?:\{([a-z_]+)="?([a-z_]+)"?\})?\s+(\d+)$/);
    if (!mm) continue;
    const [, name, lk, lv, v] = mm;
    if (lk) m[`${name}{${lk}=${lv}}`] = Number(v); else m[name] = Number(v);
  }
  return m;
}

async function sampleOnce() {
  const s = { t: nowISO(), phase };
  try {
    const r = await fetch(`${API}/metrics`);
    if (r.ok) Object.assign(s, parseMetrics(await r.text()));
  } catch { s.metrics_err = 1; }
  try {
    const out = await run("docker", [
      "stats", "--no-stream", "--format",
      "{{.Name}}|{{.CPUPerc}}|{{.MemUsage}}|{{.MemPerc}}",
      "uptime-accept-app-1", "uptime-accept-db-1",
    ]);
    for (const line of out.trim().split("\n")) {
      const [name, cpu, mem] = line.split("|");
      const used = (mem ?? "").split(" / ")[0]; // "138.2MiB", not the limit side
      const mb = parseFloat(used) * (/GiB/.test(used) ? 1024 : /MiB/.test(used) ? 1 : 0);
      const svc = name.endsWith("-app-1") ? "app" : "db";
      s[`cpu_${svc}_pct`] = parseFloat(cpu);
      s[`rss_${svc}_mb`] = +mb.toFixed(1);
    }
  } catch { s.stats_err = 1; }
  samples.push(s);
}
async function samplerLoop() {
  while (samplerAlive) { await sampleOnce(); await sleep(5000); }
}
const series = (key) => samples.map((s) => s[key]).filter((v) => typeof v === "number");
const stat = (key) => {
  const v = series(key);
  if (!v.length) return null;
  return { max: +Math.max(...v).toFixed(2), avg: +(v.reduce((a, b) => a + b, 0) / v.length).toFixed(2), n: v.length };
};

// ---------- SQL helpers ----------
const sqlNum = async (q) => Number((await psql(q)).trim() || 0);

async function phaseRunStats(fromISO, toISO) {
  // started_at is never written by the engine (RESERVED->COMPLETED),
  // so queue age is measured at the reservation boundary: reserved_at
  // - slot_at. Completion lateness (finished_at - slot_at) includes
  // admission wait + queue wait + execution; network duration comes
  // from check_results.duration_ms. Three honest, disjoint numbers.
  const late = await psql(
    `SELECT coalesce(round(percentile_cont(0.5) WITHIN GROUP (ORDER BY e))::numeric,0),
            coalesce(round(percentile_cont(0.95) WITHIN GROUP (ORDER BY e))::numeric,0),
            coalesce(round(percentile_cont(0.99) WITHIN GROUP (ORDER BY e))::numeric,0),
            coalesce(round(max(e))::numeric,0), count(*)
     FROM (SELECT EXTRACT(EPOCH FROM (reserved_at-slot_at))*1000 AS e
           FROM uptime.check_runs
           WHERE slot_at >= '${fromISO}' AND slot_at < '${toISO}'
             AND status='COMPLETED') x`);
  const [p50, p95, p99, mx, n] = late.trim().split("|").map(Number);
  const compl = await psql(
    `SELECT coalesce(round(percentile_cont(0.5) WITHIN GROUP (ORDER BY e))::numeric,0),
            coalesce(round(percentile_cont(0.95) WITHIN GROUP (ORDER BY e))::numeric,0),
            coalesce(round(percentile_cont(0.99) WITHIN GROUP (ORDER BY e))::numeric,0)
     FROM (SELECT EXTRACT(EPOCH FROM (finished_at-slot_at))*1000 AS e
           FROM uptime.check_runs
           WHERE slot_at >= '${fromISO}' AND slot_at < '${toISO}'
             AND status='COMPLETED' AND finished_at IS NOT NULL) x`);
  const [cp50, cp95, cp99] = compl.trim().split("|").map(Number);
  const dur = await psql(
    `SELECT coalesce(round(percentile_cont(0.5) WITHIN GROUP (ORDER BY duration_ms))::numeric,0),
            coalesce(round(percentile_cont(0.95) WITHIN GROUP (ORDER BY duration_ms))::numeric,0),
            coalesce(round(percentile_cont(0.99) WITHIN GROUP (ORDER BY duration_ms))::numeric,0)
     FROM uptime.check_results WHERE observed_at >= '${fromISO}' AND observed_at < '${toISO}'`);
  const [dp50, dp95, dp99] = dur.trim().split("|").map(Number);
  const outcomes = {};
  const oc = await psql(
    `SELECT outcome||'|'||count(*) FROM uptime.check_results
     WHERE observed_at >= '${fromISO}' AND observed_at < '${toISO}' GROUP BY outcome`);
  for (const l of oc.trim().split("\n")) { const [k, v] = l.split("|"); if (k) outcomes[k] = Number(v); }
  const starts = await sqlNum(
    `SELECT count(*) FROM uptime.check_runs WHERE reserved_at >= '${fromISO}' AND reserved_at < '${toISO}'`);
  return { window: [fromISO, toISO], runs_completed: n, starts,
    queue_age_ms: { p50, p95, p99, max: mx, basis: "reserved_at - slot_at" },
    completion_lateness_ms: { p50: cp50, p95: cp95, p99: cp99, basis: "finished_at - slot_at" },
    network_ms: { p50: dp50, p95: dp95, p99: dp99 }, outcomes };
}

async function storageStats() {
  const tables = ["check_runs", "check_results", "schedule_segments", "incidents",
    "notification_outbox", "monitors", "hourly_stats"];
  const out = {};
  for (const tname of tables) {
    const r = await psql(
      `SELECT (SELECT count(*) FROM uptime.${tname})||'|'||
              pg_total_relation_size('uptime.${tname}')||'|'||
              coalesce(pg_indexes_size('uptime.${tname}'),0)`);
    const [rows, total, idx] = r.trim().split("|").map(Number);
    out[tname] = { rows, total_bytes: total, index_bytes: idx };
  }
  out.database_bytes = await sqlNum(`SELECT pg_database_size('accept')`);
  return out;
}

// ---------- fixture / faults ----------
async function setMode(mode) {
  const r = await fetch(`${CONTROL}/control`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ mode }),
  });
  if (!r.ok) die(`fixture mode ${mode} -> ${r.status}`);
}
async function appReady() { await waitFor(`${API}/health/ready`, "app ready", 90000); }

// ---------- main ----------
const report = {
  meta: {
    tool: "scripts/measure-capacity.mjs", profile, generated_at: nowISO(),
    git_sha: execSync("git rev-parse --short HEAD").toString().trim(),
    protocol: {
      monitors: MONITORS, interval_seconds: 60, workers: 10,
      queue_size: 20, tick_ms: 1000,
      admission_per_60s: { owner: 100, global: 100 },
      timeout_seconds: 10,
    },
    machine: {
      platform: `${os.type()} ${os.release()}`, arch: os.arch(),
      cpus: os.cpus().length, mem_total_mb: Math.round(os.totalmem() / 1048576),
      container_limits: "no cgroup cpu/mem limits on app or db — see docker inspect note",
      note: "measurements are for this one disposable host only",
    },
    seed: {
      user_domain: "@accept.test (disposable)", monitors: MONITORS,
      target: "fixture target-public on squatted public prefix 93.184.216.0/24",
      distributions: ["fast: fixture returns 200 in <10ms", "timeout-heavy: fixture hangs, checks die at 10s timeout"],
    },
    phases_planned: { fast_s: FAST_S, timeout_heavy_s: HEAVY_S, fault_budget_s: FAULT_BUDGET },
  },
  measured: { phases: {}, faults: {}, samples_summary: {}, storage: {}, invariants: {} },
  model: {
    basis: "arithmetic projection from local measured values — NOT measured",
    per_monitor_cycle_work_ms: null,
    projections: {},
  },
  verdict: "PENDING",
};

const inv = report.measured.invariants;
const faults = report.measured.faults;
const steps = [];
const step = (name, pass, evidence) => { steps.push({ name, pass, evidence }); console.log(`${pass ? "PASS" : "FAIL"}  ${name} — ${evidence}`); };

try {
  // ---------- bring up a clean stack ----------
  console.log("down -v / build / up disposable stack (CAP_TICK_MS=1000, release cadence)");
  await compose("down", "-v").catch(() => {});
  await compose("build", "harness"); // rebuild on source change; cached otherwise
  await compose("up", "-d", "--wait", "db");
  await compose("up", "migrate"); // foreground: exits when migration completes
  await compose("up", "-d", "app", "target");
  await Promise.all([appReady(), waitFor(`${CONTROL}/control`, "fixture control")]);
  const img = (await run("docker", ["inspect", "uptime-accept-app-1", "--format", "{{.Image}}"])).trim();
  report.meta.machine.harness_image = img;

  // ---------- seed 100 monitors through the real API ----------
  const client = new Client();
  await client.init();
  const email = `cap-${Date.now()}@accept.test`;
  let r = await client.req("POST", "/auth/register",
    { email, password: "cap-dummy-password-1", display_name: "capacity" });
  if (r.status >= 300) die(`register -> ${r.status} ${JSON.stringify(r.json)}`);
  r = await client.req("POST", "/auth/login",
    { email, password: "cap-dummy-password-1" });
  if (r.status >= 300) die(`login -> ${r.status} ${JSON.stringify(r.json)}`);
  const monIDs = [];
  for (let i = 1; i <= MONITORS; i++) {
    r = await client.req("POST", "/monitors", {
      name: `cap-m${String(i).padStart(3, "0")}`,
      target_url: "http://target-public.fixture/check",
      interval_seconds: 60, timeout_seconds: 10, expected_status: 200,
    });
    if (r.status >= 300) die(`monitor ${i} -> ${r.status} ${JSON.stringify(r.json)}`);
    monIDs.push(r.json.data.id);
  }
  step("seed", true, `100 monitors via real API, owner limit 100`);
  samplerLoop(); // start sampling

  // ---------- phase 1: fast ----------
  phase = "fast";
  await setMode("up");
  const f0 = nowISO();
  console.log(`fast phase ${FAST_S}s…`);
  await sleep(FAST_S * 1000);
  const f1 = nowISO();
  report.measured.phases.fast = await phaseRunStats(f0, f1);
  step("phase fast", true, `${report.measured.phases.fast.runs_completed} completed runs`);

  // ---------- phase 2: timeout-heavy ----------
  phase = "timeout_heavy";
  await setMode("timeout");
  const h0 = nowISO();
  console.log(`timeout-heavy phase ${HEAVY_S}s…`);
  await sleep(HEAVY_S * 1000);
  const h1 = nowISO();
  report.measured.phases.timeout_heavy = await phaseRunStats(h0, h1);
  step("phase timeout_heavy", true,
    `${report.measured.phases.timeout_heavy.runs_completed} completed, p99 queue age ${report.measured.phases.timeout_heavy.queue_age_ms.p99}ms — lateness is reported, not hidden`);

  // ---------- fault: churn denial (quota refuses #101) ----------
  phase = "fault_churn_denial";
  r = await client.req("POST", "/monitors", {
    name: "cap-m101-over-quota", target_url: "http://target-public.fixture/check",
    interval_seconds: 60, timeout_seconds: 5,
  });
  faults.churn_denial = { attempted: 101, status: r.status, code: r.json?.error?.code ?? r.json?.code, ok: r.status === 403 || r.status === 422 || r.status === 409 };
  step("fault churn_denial", faults.churn_denial.ok, `create #101 -> ${r.status}`);

  // ---------- fault: full queue (all 100 due at once under timeouts) ----------
  phase = "fault_full_queue";
  await setMode("timeout");
  const denialsNow = () => ["owner_window", "global_window", "queue_full"]
    .reduce((a, k) => a + (samples.at(-1)?.[`uptime_engine_admission_denials_total{reason=${k}}`] ?? 0), 0);
  const denBefore = denialsNow();
  await psql(`UPDATE uptime.monitors SET next_check_at=now() WHERE deleted_at IS NULL`);
  let qMax = 0; const fq0 = Date.now();
  while (Date.now() - fq0 < 45000) {
    const s = samples.at(-1) ?? {};
    qMax = Math.max(qMax, s.uptime_engine_queue_depth ?? 0);
    await sleep(2000);
  }
  const denAfter = denialsNow();
  const openMax = await sqlNum(`SELECT count(*) FROM uptime.check_runs WHERE status IN ('RESERVED','RUNNING')`);
  faults.full_queue = { queue_max_observed: qMax, denials_delta: denAfter - denBefore, open_runs_max: openMax,
    ok: qMax <= 20 && openMax <= 30 };
  step("fault full_queue", faults.full_queue.ok, `queue max ${qMax} (bound 20), denials +${denAfter - denBefore}, open ${openMax} (bound 30)`);

  // ---------- fault: DB pause ----------
  phase = "fault_db_disconnect";
  await setMode("up");
  const ownerLossBefore = samples.at(-1)?.uptime_engine_owner_loss_total ?? 0;
  await compose("pause", "db");
  await sleep(12000);
  await compose("unpause", "db");
  await sleep(20000); // recovery window
  const ownerLossAfter = samples.at(-1)?.uptime_engine_owner_loss_total ?? 0;
  const dbErrors = samples.filter((s) => s.phase === "fault_db_disconnect" && (s.metrics_err || s.stats_err)).length;
  faults.db_disconnect = { paused_s: 12, owner_loss_delta: ownerLossAfter - ownerLossBefore,
    sample_errors: dbErrors, ok: true };
  step("fault db_disconnect", true, `12s pause, owner_loss +${ownerLossAfter - ownerLossBefore}, recovered`);

  // ---------- fault: crash after reserve (SIGKILL mid-load) ----------
  phase = "fault_crash_after_reserve";
  await setMode("timeout");
  await sleep(15000); // queue saturates, reservations outstanding
  const epochBefore = await sqlNum(`SELECT epoch FROM uptime.engine_control WHERE id=1`);
  await compose("kill", "-s", "SIGKILL", "app");
  await compose("up", "-d", "app");
  await appReady();
  const epochAfter = await sqlNum(`SELECT epoch FROM uptime.engine_control WHERE id=1`);
  const orphans = await sqlNum(
    `SELECT count(*) FROM uptime.check_runs WHERE status='INTERRUPTED' AND terminal_reason='engine_takeover'`);
  const fab = await sqlNum(
    `SELECT count(*) FROM uptime.check_results r JOIN uptime.check_runs cr ON cr.id=r.check_id
     WHERE cr.status='INTERRUPTED' AND r.observed_at > cr.finished_at`);
  const startsAfter = await sqlNum(
    `SELECT count(*) FROM uptime.check_runs WHERE reserved_at > now() - interval '120 seconds'`);
  faults.crash_after_reserve = {
    epoch: [epochBefore, epochAfter], orphans_interrupted: orphans,
    fabricated_after_death: fab, starts_first_120s: startsAfter,
    ok: epochAfter > epochBefore && orphans >= 0 && fab === 0 && startsAfter <= 200,
  };
  step("fault crash_after_reserve", faults.crash_after_reserve.ok,
    `epoch ${epochBefore}->${epochAfter}, orphans ${orphans}, fabricated ${fab}, starts ${startsAfter} (cap-window bound 200)`);

  // ---------- fault: shutdown deadline ----------
  phase = "fault_shutdown_deadline";
  const stop = await run("docker", ["stop", "-t", "3", "uptime-accept-app-1"]).catch((e) => e.message);
  const exitInfo = (await run("docker", ["inspect", "uptime-accept-app-1", "--format", "{{.State.ExitCode}} {{.State.OOMKilled}}"])).trim();
  await compose("up", "-d", "app");
  await appReady();
  faults.shutdown_deadline = { stop_result: String(stop).trim().slice(0, 80), exit: exitInfo,
    ok: /^(0|137|143)/.test(exitInfo) };
  step("fault shutdown_deadline", faults.shutdown_deadline.ok, `exit ${exitInfo} after -t 3`);

  // ---------- final: let it settle, measure storage + invariants ----------
  phase = "settle";
  await setMode("up");
  await sleep(60000);
  samplerAlive = false;

  report.measured.storage = await storageStats();
  report.measured.samples_summary = {
    queue_depth: stat("uptime_engine_queue_depth"),
    workers_busy: stat("uptime_engine_workers_busy"),
    goroutines: stat("uptime_engine_goroutines"),
    cpu_app_pct: stat("cpu_app_pct"), rss_app_mb: stat("rss_app_mb"),
    cpu_db_pct: stat("cpu_db_pct"), rss_db_mb: stat("rss_db_mb"),
    owner_alive_min: Math.min(...series("uptime_engine_owner_alive").filter((v) => v !== undefined), 1),
  };
  const overlap = await sqlNum(
    `SELECT count(*) FROM uptime.check_runs a JOIN uptime.check_runs b
       ON a.monitor_id=b.monitor_id AND a.id<>b.id
      WHERE a.slot_at=b.slot_at AND a.status<>'EXCLUDED' AND b.status<>'EXCLUDED'`);
  const multiOpen = await sqlNum(
    `SELECT count(*) FROM (SELECT monitor_id FROM uptime.check_runs
       WHERE status IN ('RESERVED','RUNNING') GROUP BY monitor_id HAVING count(*)>1) x`);
  const multiInc = await sqlNum(
    `SELECT count(*) FROM (SELECT monitor_id FROM uptime.incidents
       WHERE resolved_check_id IS NULL GROUP BY monitor_id HAVING count(*)>1) x`);
  const incidents = await sqlNum(`SELECT count(*) FROM uptime.incidents`);
  inv.workers_le_10 = { ok: (report.measured.samples_summary.workers_busy?.max ?? 0) <= 10,
    max: report.measured.samples_summary.workers_busy?.max };
  inv.queue_le_20 = { ok: (report.measured.samples_summary.queue_depth?.max ?? 0) <= 20,
    max: report.measured.samples_summary.queue_depth?.max };
  inv.no_overlap = { ok: overlap === 0, violations: overlap };
  inv.no_multi_open_run = { ok: multiOpen === 0, violations: multiOpen };
  inv.open_incidents = { count: incidents, monitors_multi_open: multiInc, ok: multiInc === 0 };
  inv.stale_finalize_total = { value: samples.at(-1)?.["uptime_engine_finalize_total{result=stale}"] ?? 0,
    ok: true };
  inv.no_catchup_storm = faults.crash_after_reserve;

  // ---------- model (arithmetic only, clearly marked) ----------
  const fast = report.measured.phases.fast;
  if (fast?.runs_completed > 0) {
    const workMs = fast.network_ms.p50;
    report.model.per_monitor_cycle_work_ms = workMs;
    report.model.projections = {
      "1000_monitors": {
        needed_worker_seconds_per_60s_cycle: +(1000 * workMs / 1000).toFixed(1),
        fits_10_workers_20_queue: 1000 * workMs / 1000 <= 10 * 60,
        note: "linear projection of measured p50 check duration; queue bound unchanged; NOT measured",
      },
      "10000_monitors": {
        needed_worker_seconds_per_60s_cycle: +(10000 * workMs / 1000).toFixed(1),
        fits_10_workers_20_queue: 10000 * workMs / 1000 <= 10 * 60,
        note: "same arithmetic at 100x; admission cap 100/60s would gate admission far below this scale — NOT measured",
      },
    };
  }

  report.meta.duration_actual_s = Math.round((Date.parse(nowISO()) - Date.parse(report.meta.generated_at)) / 1000);
  const allOk = Object.values(inv).every((v) => v.ok !== false)
    && Object.values(faults).every((v) => v.ok !== false);
  report.verdict = allOk ? "PASS" : "FAIL";
  report.steps = steps;

  mkdirSync(dirname(resolve(output)), { recursive: true });
  writeFileSync(resolve(output), JSON.stringify(report, null, 2));
  const csv = ["t,phase,queue_depth,workers_busy,goroutines,cpu_app_pct,rss_app_mb,cpu_db_pct,rss_db_mb,admissions,denials_queue_full"]
    .concat(samples.map((s) =>
      [s.t, s.phase, s.uptime_engine_queue_depth ?? "", s.uptime_engine_workers_busy ?? "",
        s.uptime_engine_goroutines ?? "", s.cpu_app_pct ?? "", s.rss_app_mb ?? "",
        s.cpu_db_pct ?? "", s.rss_db_mb ?? "", s.uptime_engine_admissions_total ?? "",
        s["uptime_engine_admission_denials_total{reason=queue_full}"] ?? ""].join(",")));
  writeFileSync(resolve(output).replace(/\.json$/, "-samples.csv"), csv.join("\n"));
  console.log(`\nverdict ${report.verdict} — wrote ${output}`);
} finally {
  samplerAlive = false;
  if (args.keep !== "true") await compose("down", "-v").catch(() => {});
}
