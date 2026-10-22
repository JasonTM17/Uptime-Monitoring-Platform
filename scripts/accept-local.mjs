#!/usr/bin/env node
// C79 deterministic local acceptance driver.
//
//   node scripts/accept-local.mjs --profile local --output <path>
//     [--gate backend|browser|restore|all]   (default: all)
//
// Brings up the disposable composition in compose.test.yaml (isolated
// public-subnet target network + control network), seeds identities
// through the REAL API and operator CLIs, runs the four acceptance
// scenarios, optionally drives the real browser lane, and writes a
// scrubbed JSON report. Teardown removes only resources this
// composition owns (project-scoped `down -v`); it never touches
// unrelated volumes or docker configuration.

import { execFile, spawn } from "node:child_process";
import { promisify } from "node:util";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash, randomBytes, randomUUID } from "node:crypto";

const run = promisify(execFile);
const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

const API = "http://localhost:18080";
const CONTROL = "http://localhost:19080";
const COMPOSE = ["compose", "-p", "uptime-accept", "-f", "compose.test.yaml"];

// ---------- helpers ----------

const sh = (args, opts = {}) =>
  run("docker", [...COMPOSE, ...args],
    { cwd: ROOT, maxBuffer: 64 * 1024 * 1024, ...opts });

const shInput = (args, input) =>
  new Promise((res, rej) => {
    const p = spawn("docker", [...COMPOSE, ...args], {
      cwd: ROOT, stdio: ["pipe", "pipe", "pipe"],
    });
    let out = "", err = "";
    p.stdout.on("data", (d) => (out += d));
    p.stderr.on("data", (d) => (err += d));
    p.on("close", (code) =>
      code === 0 ? res({ stdout: out, stderr: err })
                 : rej(new Error(`docker ${args.join(" ")} -> ${code}: ${err}`)));
    p.stdin.write(input);
    p.stdin.end();
  });

async function poll(fn, { until, timeoutMs = 30000, every = 400, what }) {
  const deadline = Date.now() + timeoutMs;
  let last;
  for (;;) {
    try {
      last = await fn();
      if (until(last)) return last;
    } catch (e) {
      last = e;
    }
    if (Date.now() > deadline)
      throw new Error(`timeout waiting for ${what} (last=${JSON.stringify(last)})`);
    await new Promise((r) => setTimeout(r, every));
  }
}

const digest = (s) => createHash("sha256").update(s).digest("hex").slice(0, 12);

class Api {
  constructor(label, base = API) {
    this.label = label;
    this.base = base;
    this.cookies = new Map();
    this.csrf = null;
  }
  cookieHeader() {
    return [...this.cookies].map(([k, v]) => `${k}=${v}`).join("; ");
  }
  async req(method, path, body, extraHeaders) {
    const headers = { accept: "application/json", ...(extraHeaders ?? {}) };
    if (this.cookies.size) headers.cookie = this.cookieHeader();
    if (body !== undefined) {
      headers["content-type"] = "application/json";
      headers["x-csrf-token"] = this.csrf ?? "";
      headers.origin = this.base;
    }
    const res = await fetch(this.base + path, {
      method, headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      redirect: "manual",
    });
    for (const c of res.headers.getSetCookie?.() ?? []) {
      const [kv] = c.split(";");
      const i = kv.indexOf("=");
      this.cookies.set(kv.slice(0, i).trim(), kv.slice(i + 1));
    }
    const text = await res.text();
    let json = null;
    try { json = JSON.parse(text); } catch {}
    return { status: res.status, json, text };
  }
  async csrfBootstrap() {
    const r = await this.req("GET", "/auth/csrf");
    this.csrf = r.json?.data?.csrf_token ?? null;
    return this.csrf;
  }
  async register(email, password, name) {
    if (!this.csrf) await this.csrfBootstrap();
    return this.req("POST", "/auth/register", {
      email, password, display_name: name,
    });
  }
  async login(email, password) {
    if (!this.csrf) await this.csrfBootstrap();
    return this.req("POST", "/auth/login", { email, password });
  }
  async logout() { return this.req("POST", "/auth/logout", {}); }
  async me() { return (await this.req("GET", "/auth/me")).json?.data?.user; }
  async reauth(password) {
    return this.req("POST", "/auth/reauth", { password });
  }
}

async function setMode(mode) {
  const res = await fetch(`${CONTROL}/control`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ mode }),
  });
  if (!res.ok) throw new Error(`fixture control -> ${res.status}`);
}

const step = (results, name, status, detail) => {
  results.push({ name, status, detail });
  console.log(`  [${status}] ${name}${detail ? ` — ${detail}` : ""}`);
};

// ---------- seed ----------

async function seed() {
  const mkPass = () => "Acc3pt!" + randomBytes(12).toString("base64url");
  const users = {
    alice: { email: `alice.${digest(Date.now() + "a")}@accept.test`, password: mkPass() },
    bob: { email: `bob.${digest(Date.now() + "b")}@accept.test`, password: mkPass() },
    admin: { email: `admin.${digest(Date.now() + "d")}@accept.test`, password: mkPass() },
  };
  const clients = {};
  for (const [k, u] of Object.entries(users)) {
    const c = new Api(k);
    const reg = await c.register(u.email, u.password, k);
    if (reg.status !== 201 && reg.status !== 200)
      throw new Error(`register ${k} -> ${reg.status}: ${reg.text}`);
    u.id = undefined; // filled after login below
    clients[k] = c;
  }
  // SUPER_ADMIN grant BEFORE the admin's first session: the grant is
  // anchored by the operator CLI (controlled local-authority path),
  // and a session minted afterwards can never carry a stale pre-grant
  // principal snapshot.
  await sh(["exec", "-T", "app", "/harness-bin/admin", "bootstrap",
    "-email", users.admin.email, "-reason", "acceptance-seed"]);
  for (const [k, u] of Object.entries(users)) {
    const c = clients[k];
    const lg = await c.login(u.email, u.password);
    if (lg.status !== 200)
      throw new Error(`login ${k} -> ${lg.status}: ${lg.text}`);
    u.id = (await c.me())?.id;
  }
  return { users, clients };
}

async function seedMonitor(clients) {
  const alice = clients.alice;
  // Channel: create pending via API, verify via operator CLI (stdin
  // destination — the only supported verification path).
  const ch = await alice.req("POST", "/notification-channels",
    { label: "accept-chan" });
  if (ch.status !== 201) throw new Error(`channel create -> ${ch.status}`);
  const chanId = ch.json.data.id;
  await shInput(
    ["exec", "-T", "app", "/harness-bin/channel", "verify",
      "-channel", chanId, "-owner", (await alice.me()).id,
      "-receipt", "acceptance-seed"],
    "accept-test-chat-001\n");

  const mon = await alice.req("POST", "/monitors", {
    name: "accept-target",
    target_url: "http://target-public.fixture/check",
    interval_seconds: 60,
    timeout_seconds: 5,
    expected_status: 200,
  });
  if (mon.status !== 201) throw new Error(`monitor create -> ${mon.status}: ${mon.text}`);
  const m = mon.json.data;
  const bind = await alice.req("PUT",
    `/monitors/${m.id}/notification-channels`,
    { expected_generation: m.generation, channel_ids: [chanId] });
  if (bind.status !== 200) throw new Error(`bind -> ${bind.status}: ${bind.text}`);
  return { monitorId: m.id, channelId: chanId };
}

// Force exactly one check: pause+resume resets next_check_at=now();
// then wait for the check to LAND (last_checked_at advances) before
// returning — no guessed sleeps.
async function forceCheck(api, monitorId) {
  const before = (await api.req("GET", `/monitors/${monitorId}`)).json.data;
  const p = await api.req("POST", `/monitors/${monitorId}/pause`,
    { expected_generation: before.generation });
  if (p.status !== 200) throw new Error(`pause -> ${p.status}: ${p.text}`);
  const paused = p.json.data;
  const r = await api.req("POST", `/monitors/${monitorId}/resume`,
    { expected_generation: paused.generation });
  if (r.status !== 200) throw new Error(`resume -> ${r.status}: ${r.text}`);
  return poll(
    async () => (await api.req("GET", `/monitors/${monitorId}`)).json.data,
    {
      until: (m) =>
        m.last_checked_at && m.last_checked_at !== (before.last_checked_at ?? null),
      timeoutMs: 15000, what: "forced check to land",
    });
}

// ---------- scenarios ----------

async function scenarioLifecycle({ clients }, ev) {
  const alice = clients.alice;
  const admin = clients.admin;
  const { monitorId } = await seedMonitor(clients);
  const deliveries = async () =>
    (await (await fetch(`${API}/__test__/deliveries`)).json()).deliveries ?? [];

  step(ev, "seed monitor+channel via real API/CLI", "PASS", monitorId);

  // Baseline: fixture up → first check establishes UP (UNKNOWN→UP).
  await setMode("up");
  await poll(
    async () => (await alice.req("GET", `/monitors/${monitorId}`)).json.data,
    { until: (m) => m.health === "UP", timeoutMs: 20000, what: "health UP" });
  step(ev, "baseline UP established by engine", "PASS");

  // Failure streak: force three checks under mode=down. After each,
  // the monitor detail confirms the check landed. Incident must NOT
  // exist before the threshold — assert honest intermediate state.
  await setMode("down");
  for (let i = 1; i <= 3; i++) {
    await forceCheck(alice, monitorId);
    const inc = await alice.req("GET",
      `/monitors/${monitorId}/incidents?state=open`);
    const n = inc.json?.data?.incidents?.length ?? 0;
    if (i < 3 && n !== 0)
      throw new Error(`incident opened early at failure ${i}`);
  }
  step(ev, "failure threshold held (no incident before 3)", "PASS");

  const open = await poll(
    async () => (await alice.req("GET",
      `/monitors/${monitorId}/incidents?state=open`)).json?.data?.incidents ?? [],
    { until: (l) => l.length === 1, timeoutMs: 15000, what: "open incident" });
  step(ev, "incident opened at threshold", "PASS", open[0].id);

  const mon = (await alice.req("GET", `/monitors/${monitorId}`)).json.data;
  if (mon.health !== "DOWN")
    throw new Error(`expected health DOWN, got ${mon.health}`);
  step(ev, "health reduced to DOWN", "PASS");

  // Delivery: recording sender captured the DOWN intent; admin
  // outbox view confirms a SENT row — real API evidence, not DB peek.
  const sent = await poll(deliveries, {
    until: (d) => d.some((x) => x.text === "accept-target is DOWN"),
    timeoutMs: 15000, what: "DOWN delivery recorded",
  });
  step(ev, "DOWN notification delivered via pipeline", "PASS",
    sent.filter((d) => d.text.includes("DOWN")).length + " delivery(s)");

  const outbox = await poll(
    async () => (await admin.req("GET",
      `/admin/outbox?limit=50`)).json?.data?.deliveries ?? [],
    { until: (rows) => rows.some((r) => r.monitor_id === monitorId && r.state === "SENT"),
      timeoutMs: 10000, what: "admin outbox SENT row" });
  step(ev, "admin outbox shows SENT for monitor", "PASS");

  // Recovery rides the real 60s cadence: pause/update would close
  // the incident as CONFIG_CHANGED, so we wait for two natural
  // successful checks (RecoverThreshold=2). ~120s is honest product
  // latency, not a guessed sleep.
  await setMode("up");
  const recovered = await poll(
    async () => (await alice.req("GET",
      `/monitors/${monitorId}/incidents?state=resolved`)).json?.data?.incidents ?? [],
    {
      until: (l) => l.some((i) => i.id === open[0].id && i.close_reason === "RECOVERED"),
      timeoutMs: 150_000, every: 2000, what: "natural recovery",
    });
  step(ev, "incident recovered via natural cadence", "PASS",
    `close_reason=${recovered[0].close_reason}`);

  await poll(deliveries, {
    until: (d) => d.some((x) => x.text === "accept-target is RECOVERY"),
    timeoutMs: 15000, what: "RECOVERY delivery recorded",
  });
  step(ev, "RECOVERY notification delivered", "PASS");
  return { monitorId };
}

async function scenarioAdminRevocation({ clients, users }, ev) {
  const admin = clients.admin;
  const bob = new Api("bob-fresh");
  const lg = await bob.login(users.bob.email, users.bob.password);
  if (lg.status !== 200) throw new Error("bob login failed");

  // Step-up: privileged mutations require recent auth (5-min window)
  // — stamp it like the UI's reauth dialog does.
  const ra = await admin.reauth(users.admin.password);
  if (ra.status !== 200) throw new Error(`reauth -> ${ra.status}`);
  // Privileged mutations fence on the subject's current version —
  // read it through the admin detail surface first.
  const detail = await admin.req("GET", `/admin/users/${users.bob.id}`);
  const ver = detail.json?.data?.version;
  if (!ver) throw new Error(`admin user detail -> ${detail.status}`);
  const revoke = await admin.req("POST",
    `/admin/users/${users.bob.id}/revoke-sessions`,
    { expected_version: ver, reason: "acceptance revocation" },
    { "idempotency-key": randomUUID() });
  if (revoke.status !== 200 && revoke.status !== 204)
    throw new Error(`revoke-sessions -> ${revoke.status}: ${revoke.text}`);
  step(ev, "admin revoked user sessions", "PASS");

  const denied = await bob.req("GET", "/monitors");
  if (denied.status !== 401)
    throw new Error(`revoked session still valid: ${denied.status}`);
  step(ev, "revoked session rejected (401)", "PASS");

  const audit = await poll(
    async () => (await admin.req("GET",
      `/admin/audit-events?limit=50`)).json?.data?.events ?? [],
    {
      until: (rows) => rows.some((r) =>
        JSON.stringify(r).includes(users.bob.id) &&
        /revoke|session/i.test(JSON.stringify(r))),
      timeoutMs: 10000, what: "audit row for revocation",
    });
  step(ev, "audit trail recorded the privileged action", "PASS",
    audit.length + " recent events scanned");
}

async function scenarioOwnerIsolation({ clients, users }, ev) {
  const alice = clients.alice;
  const bob = clients.bob;
  // The revocation scenario killed bob's sessions — his account is
  // intact, so a fresh login restores his lane.
  const relog = await bob.login(users.bob.email, users.bob.password);
  if (relog.status !== 200) throw new Error("bob re-login failed");
  // Alice's monitor from the lifecycle seed must be invisible to Bob.
  const listA = await alice.req("GET", "/monitors");
  const mA = (listA.json?.data?.items ?? [])[0];
  if (!mA) throw new Error("no monitor on alice");

  const get404 = await bob.req("GET", `/monitors/${mA.id}`);
  if (get404.status !== 404)
    throw new Error(`foreign monitor readable: ${get404.status}`);
  step(ev, "foreign monitor GET is 404", "PASS");

  const listB = await bob.req("GET", "/monitors");
  if ((listB.json?.data?.items ?? []).some((m) => m.id === mA.id))
    throw new Error("foreign monitor leaked into list");
  step(ev, "owner list contains no foreign rows", "PASS");

  const inc = await bob.req("GET", `/monitors/${mA.id}/incidents`);
  if (inc.status !== 404)
    throw new Error(`foreign incidents readable: ${inc.status}`);
  step(ev, "foreign history surfaces are 404", "PASS");

  const patch = await bob.req("PATCH", `/monitors/${mA.id}`,
    { expected_generation: mA.generation, name: "hijack" });
  if (patch.status !== 404)
    throw new Error(`foreign monitor mutable: ${patch.status}`);
  step(ev, "foreign monitor mutation is 404", "PASS");
}

async function scenarioLogoutRace({ clients, users }, ev) {
  const ctx = new Api("race");
  const lg = await ctx.login(users.alice.email, users.alice.password);
  if (lg.status !== 200) throw new Error("alice login failed");
  const out = await ctx.logout();
  if (out.status !== 200 && out.status !== 204)
    throw new Error(`logout -> ${out.status}: ${out.text}`);
  const me = await ctx.req("GET", "/auth/me");
  if (me.status !== 401)
    throw new Error(`post-logout identity alive: ${me.status}`);
  step(ev, "logout kills identity server-side", "PASS");

  const lgB = await ctx.login(users.bob.email, users.bob.password);
  if (lgB.status !== 200) throw new Error("bob re-login failed");
  const list = await ctx.req("GET", "/monitors");
  const items = list.json?.data?.items ?? [];
  const mine = (await clients.alice.req("GET", "/monitors")).json?.data?.items ?? [];
  if (items.some((m) => mine.some((a) => a.id === m.id)))
    throw new Error("alice's rows visible under bob's identity");
  step(ev, "post-swap session exposes only bob's data", "PASS",
    `${items.length} rows`);
}

// ---------- gates ----------

async function gateBackend() {
  const results = [];
  const ev = (name, status, detail) => step(results, name, status, detail);
  const seeded = await seed();
  ev("identities seeded via API + operator CLI", "PASS",
    `users=${Object.keys(seeded.users).length}`);
  let monitorId;
  try {
    ({ monitorId } = await scenarioLifecycle(seeded, results));
    await scenarioAdminRevocation(seeded, results);
    await scenarioOwnerIsolation(seeded, results);
    await scenarioLogoutRace(seeded, results);
    return { status: "PASS", steps: results, monitorId };
  } catch (e) {
    step(results, "scenario aborted", "FAIL", String(e.message ?? e));
    return { status: "FAIL", steps: results, error: String(e.message ?? e) };
  }
}

async function gateBrowser(seedFile) {
  const env = {
    ...process.env,
    CI: "1",
    E2E_API_TARGET: API,
    ACCEPT_API_URL: API,
    ACCEPT_CONTROL_URL: CONTROL,
    ACCEPT_SEED_FILE: seedFile,
  };
  // Spawn node + playwright cli.js directly: Windows refuses .cmd
  // spawns without a shell (EINVAL), and a shell would re-parse the
  // | in the grep pattern. No --project filter: both configured
  // viewports (desktop chromium + 390px) must prove the journeys.
  // --workers=1 serializes the matrix — the lifecycle tests share one
  // seeded world (fixture mode, identities) and would cross-talk in
  // parallel.
  const proc = spawn(
    process.execPath,
    [resolve(ROOT, "web", "node_modules", "playwright", "cli.js"),
     "test", "--workers=1",
     "--grep", "LifecycleIncidentRecovery|AdminRoleRevocation|OwnerIsolation|LogoutIdentityRace"],
    { cwd: resolve(ROOT, "web"), env, stdio: "inherit" });
  const code = await new Promise((r) => proc.on("close", r));
  return {
    status: code === 0 ? "PASS" : "FAIL",
    detail: `playwright exit ${code}`,
  };
}

async function gateRestore() {
  // Mechanism-level rehearsal: dump the acceptance DB, restore into
  // a FRESH database in the same disposable container, verify schema
  // version + representative row counts. Deep identity/session/audit
  // cross-checks are the C81 card's scope.
  const r = { status: "PASS", steps: [] };
  const note = (n, s, d) => step(r.steps, n, s, d);
  // -Fc output is binary: buffer encoding, not utf8.
  const dump = await run("docker", [...COMPOSE, "exec", "-T", "db",
    "pg_dump", "-U", "accept", "-d", "accept", "-Fc"],
    { cwd: ROOT, encoding: "buffer", maxBuffer: 256 * 1024 * 1024 });
  const dumpPath = resolve(ROOT, "artifacts", "accept-restore.dump");
  mkdirSync(dirname(dumpPath), { recursive: true });
  writeFileSync(dumpPath, dump.stdout);
  note("pg_dump produced custom-format archive", "PASS",
    `${dump.stdout.length} bytes`);

  await sh(["exec", "-T", "db", "psql", "-U", "accept", "-d", "postgres",
    "-c", "DROP DATABASE IF EXISTS accept_restore"]);
  await sh(["exec", "-T", "db", "psql", "-U", "accept", "-d", "postgres",
    "-c", "CREATE DATABASE accept_restore"]);
  // Stream the archive back in — restore must not read host files.
  await shInput(["exec", "-T", "db", "pg_restore", "-U", "accept",
    "-d", "accept_restore", "--no-owner", "--no-privileges"],
    dump.stdout);
  note("restored into fresh database accept_restore", "PASS");

  const q = async (sql) =>
    (await sh(["exec", "-T", "db", "psql", "-U", "accept", "-d",
      "accept_restore", "-Atc", sql])).stdout.trim();
  const counts = {};
  for (const t of ["users", "monitors", "incidents", "notification_outbox",
    "audit_events", "sessions"]) {
    counts[t] = Number(await q(`SELECT count(*) FROM uptime.${t}`));
  }
  const ver = await q(`SELECT version FROM public.schema_migrations`);
  note("row counts + schema version verified post-restore", "PASS",
    `version=${ver} ${JSON.stringify(counts)}`);
  if (Number(ver) < 1) throw new Error("schema_migrations empty post-restore");
  if (counts.users < 3 || counts.monitors < 1)
    throw new Error(`restored data incomplete: ${JSON.stringify(counts)}`);
  return r;
}

// ---------- main ----------

async function main() {
  const args = process.argv.slice(2);
  const opt = {};
  for (let i = 0; i < args.length; i += 2)
    opt[args[i].replace(/^--/, "")] = args[i + 1];
  const profile = opt.profile ?? "local";
  const gate = opt.gate ?? "all";
  const output = opt.output ?? resolve(ROOT, "artifacts", "local-acceptance.json");
  if (profile !== "local")
    throw new Error(`unknown profile ${profile} (only 'local' exists)`);
  mkdirSync(dirname(output), { recursive: true });

  const report = {
    generated_at: new Date().toISOString(),
    profile, gate,
    composition: "compose.test.yaml / project uptime-accept",
    gates: {},
    limitations: [],
  };

  console.log(`[accept] profile=${profile} gate=${gate}`);
  console.log("[accept] building harness image");
  await sh(["build", "harness"]);
  console.log("[accept] starting composition");
  // Deterministic fresh state: any leftover project resources (tmpfs
  // DB data is volatile anyway, but limiter/process state is not)
  // come down first. Scope is this project only.
  await sh(["down", "-v", "--remove-orphans"]).catch(() => {});
  // depends_on conditions order db(healthy) -> migrate(completed) ->
  // app -> target; my own polls below confirm real readiness.
  await sh(["up", "-d", "app", "target"]);

  // Readiness: app ready endpoint + fixture control plane.
  await poll(async () => (await fetch(`${API}/health/ready`)).status,
    { until: (s) => s === 200, timeoutMs: 60000, what: "app /health/ready" });
  await poll(async () => (await fetch(`${CONTROL}/control`)).status,
    { until: (s) => s === 200, timeoutMs: 15000, what: "fixture control" });
  console.log("[accept] composition ready");

  const seedFile = resolve(dirname(output), "accept-seeded.json");
  try {
    if (gate === "backend" || gate === "all") {
      console.log("[gate backend] API-level scenarios");
      report.gates.backend = await gateBackend();
    }
    if (gate === "browser" || gate === "all") {
      console.log("[gate browser] real-browser lane");
      // Seed file for the playwright lane: regenerate passwords so the
      // browser tests own fresh identities independent of the backend
      // gate's run.
      const seedUsers = {
        alice: `alice.${digest("pw-a" + Date.now())}@accept.test`,
        bob: `bob.${digest("pw-b" + Date.now())}@accept.test`,
        admin: `admin.${digest("pw-d" + Date.now())}@accept.test`,
        passwords: {},
      };
      const mkPass = () => "Acc3pt!" + randomBytes(12).toString("base64url");
      for (const k of ["alice", "bob", "admin"]) {
        const p = mkPass();
        seedUsers.passwords[k] = p;
        const c = new Api("seed-" + k);
        const reg = await c.register(seedUsers[k], p, "e2e-" + k);
        if (reg.status !== 201 && reg.status !== 200)
          throw new Error(`browser seed register ${k} -> ${reg.status}`);
        const lg = await c.login(seedUsers[k], p);
        if (lg.status !== 200)
          throw new Error(`browser seed login ${k} -> ${lg.status}`);
        seedUsers[k + "_id"] = (await c.me())?.id ?? null;
      }
      // recover (not bootstrap): grants SUPER_ADMIN even when the
      // backend gate already holds the first grant; it also revokes
      // the seed user's sessions — harmless, the spec logs in fresh.
      await sh(["exec", "-T", "app", "/harness-bin/admin", "recover",
        "-email", seedUsers.admin, "-reason", "acceptance-e2e-seed"]);
      writeFileSync(seedFile, JSON.stringify(seedUsers, null, 2));
      report.gates.browser = await gateBrowser(seedFile);
    }
    if (gate === "restore" || gate === "all") {
      console.log("[gate restore] fresh-database rehearsal");
      report.gates.restore = await gateRestore();
    }
  } finally {
    console.log("[accept] teardown (project-scoped down -v)");
    await sh(["down", "-v", "--remove-orphans"]).catch(() => {});
  }

  const statuses = Object.entries(report.gates).map(([k, g]) => `${k}=${g.status}`);
  report.status = report.gates && Object.values(report.gates).every((g) => g.status === "PASS")
    ? "PASS" : "FAIL";
  writeFileSync(output, JSON.stringify(report, null, 2));
  console.log(`[accept] ${report.status} (${statuses.join(", ")})`);
  console.log(`[accept] report: ${output}`);
  process.exit(report.status === "PASS" ? 0 : 1);
}

main().catch(async (e) => {
  console.error("[accept] fatal:", e.message ?? e);
  try { await sh(["down", "-v", "--remove-orphans"]); } catch {}
  process.exit(2);
});
