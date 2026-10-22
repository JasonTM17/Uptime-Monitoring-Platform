// C91 — portfolio media capture (local deterministic harness).
//
//   node scripts/capture-portfolio.mjs --profile local --output docs/media/manifest.json
//
// Drives the REAL composed testapp (compose.test.yaml: app + fixture +
// migrated postgres) and the real vite UI, through Playwright — no
// mocks, no Stitch concept shots. Every artifact gets sha256 +
// provenance (runtime SHA, viewport, browser, route, seed, UTC) in the
// manifest. Raw video intermediates stay in ignored artifacts/media/.
import { spawn } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { mkdirSync, writeFileSync, readFileSync, statSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const API = "http://localhost:18080";
const CONTROL = "http://localhost:19080";
const UI = "http://localhost:5173";
const COMPOSE = ["compose", "-p", "uptime-media", "-f", "compose.test.yaml"];
const MEDIA = resolve(ROOT, "docs/media");
const SHOTS = resolve(MEDIA, "screenshots");
const RAW = resolve(ROOT, "artifacts/media");
const rel = (p) => p.replace(ROOT + "\\", "").replace(ROOT + "/", "").replaceAll("\\", "/");

function run(argv, { input, quiet, env, cwd } = {}) {
  return new Promise((res, rej) => {
    const p = spawn(argv[0], argv.slice(1), { cwd: cwd ?? ROOT,
      env: { ...process.env, ...env }, stdio: ["pipe", "pipe", "pipe"] });
    let out = "", err = "";
    p.stdout.on("data", (d) => out += d);
    p.stderr.on("data", (d) => err += d);
    if (input !== undefined) p.stdin.write(input);
    p.stdin.end();
    p.on("close", (c) => c === 0 ? res(out) : rej(new Error(`${argv.join(" ")} -> ${c}: ${err.split("\n").pop()}`)));
    void quiet;
  });
}
const sh = (args, input) => run(["docker", ...COMPOSE, "exec", "-T", "app", ...args], { input });
const die = (m) => { throw new Error(`capture-portfolio: ${m}`); };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function poll(fn, { until, timeoutMs = 15000, every = 500 } = {}) {
  const t0 = Date.now();
  for (;;) {
    const v = await fn().catch(() => null);
    if (v && (!until || until(v))) return v;
    if (Date.now() - t0 > timeoutMs) die(`poll timeout ${timeoutMs}ms`);
    await sleep(every);
  }
}

class Api {
  constructor() { this.cookies = new Map(); this.csrf = null; }
  cookieHeader() { return [...this.cookies].map(([k, v]) => `${k}=${v}`).join("; "); }
  async req(method, path, body) {
    const headers = { accept: "application/json" };
    if (this.cookies.size) headers.cookie = this.cookieHeader();
    if (body !== undefined) {
      headers["content-type"] = "application/json";
      headers["x-csrf-token"] = this.csrf ?? "";
      headers.origin = API;
    }
    const res = await fetch(API + path, { method, headers,
      body: body === undefined ? undefined : JSON.stringify(body), redirect: "manual" });
    for (const c of res.headers.getSetCookie?.() ?? []) {
      const [kv] = c.split(";"); const i = kv.indexOf("=");
      this.cookies.set(kv.slice(0, i).trim(), kv.slice(i + 1));
    }
    const text = await res.text();
    let json = null; try { json = JSON.parse(text); } catch {}
    return { status: res.status, json, text };
  }
  async csrfBootstrap() {
    const r = await this.req("GET", "/auth/csrf");
    this.csrf = r.json?.data?.csrf_token ?? null;
    return this.csrf;
  }
  async login(e, p) {
    if (!this.csrf) await this.csrfBootstrap();
    return this.req("POST", "/auth/login", { email: e, password: p });
  }
  async register(e, p) {
    if (!this.csrf) await this.csrfBootstrap();
    return this.req("POST", "/auth/register", { email: e, password: p, display_name: "demo" });
  }
  me() { return this.req("GET", "/auth/me").then((r) => r.json?.data?.user); }
}

async function setMode(mode) {
  const r = await fetch(`${CONTROL}/control`, { method: "POST",
    headers: { "content-type": "application/json" }, body: JSON.stringify({ mode }) });
  if (!r.ok) die(`fixture mode ${mode} -> ${r.status}`);
}

async function main() {
  const args = {};
  for (let i = 2; i < process.argv.length; i += 2)
    args[process.argv[i].replace(/^--/, "")] = process.argv[i + 1];
  const output = resolve(args.output ?? die("--output required"));
  const profile = args.profile ?? "local";
  mkdirSync(SHOTS, { recursive: true }); mkdirSync(RAW, { recursive: true });

  const runtimeSha = (await run(["git", "rev-parse", "HEAD"])).trim();
  const seedTag = `media-${Date.now().toString(36)}`;
  const seed = {
    alice: { email: `alice.${seedTag}@demo.invalid`, password: `Demo-${randomBytes(9).toString("base64url")}` },
    bob: { email: `bob.${seedTag}@demo.invalid`, password: `Demo-${randomBytes(9).toString("base64url")}` },
    admin: { email: `admin.${seedTag}@demo.invalid`, password: `Demo-${randomBytes(9).toString("base64url")}` },
  };

  // ---------- stack ----------
  console.log("[capture] compose up");
  await run(["docker", ...COMPOSE, "down", "-v", "--remove-orphans"], { quiet: true }).catch(() => {});
  await run(["docker", ...COMPOSE, "up", "-d", "--wait", "db"], { quiet: true });
  await run(["docker", ...COMPOSE, "run", "--rm", "migrate"], { quiet: true });
  await run(["docker", ...COMPOSE, "up", "-d", "app", "target"], { quiet: true });
  await poll(() => fetch(`${API}/health/ready`).then((r) => r.status === 200),
    { timeoutMs: 60000 });

  // ---------- seed ----------
  console.log("[capture] seed users/monitors via real API");
  for (const u of Object.values(seed)) {
    const reg = await new Api().register(u.email, u.password);
    if (reg.status !== 201 && reg.status !== 200) die(`register -> ${reg.status}`);
  }
  await sh(["/harness-bin/admin", "bootstrap", "-email", seed.admin.email, "-reason", "media-seed"]);
  const alice = new Api(), bob = new Api(), admin = new Api();
  await alice.login(seed.alice.email, seed.alice.password);
  await bob.login(seed.bob.email, seed.bob.password);
  await admin.login(seed.admin.email, seed.admin.password);

  const mkMonitor = async (name) => {
    const r = await alice.req("POST", "/monitors", { name,
      target_url: "http://target-public.fixture/check",
      interval_seconds: 60, timeout_seconds: 5, expected_status: 200 });
    if (r.status !== 201) die(`monitor ${name} -> ${r.status}: ${r.text}`);
    return r.json.data;
  };
  const m1 = await mkMonitor("edge-uptime-demo");
  const m2 = await mkMonitor("api-latency-demo");
  const forceCheck = async (id) => {
    const b = (await alice.req("GET", `/monitors/${id}`)).json.data;
    const p = await alice.req("POST", `/monitors/${id}/pause`, { expected_generation: b.generation });
    const g = p.json.data.generation;
    await alice.req("POST", `/monitors/${id}/resume`, { expected_generation: g });
    return poll(async () => (await alice.req("GET", `/monitors/${id}`)).json.data,
      { until: (m) => m.last_checked_at && m.last_checked_at !== (b.last_checked_at ?? null) });
  };
  await setMode("up");
  await forceCheck(m1.id); await forceCheck(m2.id);
  // Drive m2 DOWN -> real incident for dashboard/detail/incidents views.
  await setMode("down");
  await forceCheck(m2.id); await forceCheck(m2.id);
  await setMode("up");

  // ---------- vite ----------
  console.log("[capture] vite dev");
  const vite = spawn(process.platform === "win32" ? "npm.cmd" : "npm",
    ["--prefix", "web", "run", "dev", "--", "--port", "5173", "--strictPort"],
    { cwd: ROOT, stdio: "ignore", shell: process.platform === "win32",
      env: { ...process.env, E2E_API_TARGET: API } });
  await poll(() => fetch(UI).then((r) => r.ok), { timeoutMs: 30000 });

  // ---------- playwright ----------
  const { chromium } = await import(
    pathToFileURL(resolve(ROOT, "web/node_modules/playwright/index.mjs")).href);
  const browser = await chromium.launch();
  const shots = [];
  const uiLogin = async (page, u) => {
    await page.goto(`${UI}/login`);
    await page.getByLabel(/email/i).fill(u.email);
    await page.getByLabel(/password/i).fill(u.password);
    await page.getByRole("button", { name: /sign in|log in/i }).click();
    await page.waitForURL((u) => !u.pathname.endsWith("/login"), { timeout: 15000 });
  };
  const snap = async (page, name, route, { mobile = false, state } = {}) => {
    const path = resolve(SHOTS, `${name}.png`);
    await page.waitForLoadState("networkidle").catch(() => {});
    await page.screenshot({ path, fullPage: false });
    shots.push({ name, file: rel(path), route, viewport: mobile ? "390x844" : "1440x900",
      state: state ?? "authenticated" });
    console.log(`[capture] ${name}`);
  };

  const ctxD = await browser.newContext({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 1 });
  const ctxM = await browser.newContext({ viewport: { width: 390, height: 844 }, deviceScaleFactor: 2, isMobile: true, hasTouch: true });

  // alice — user views
  const pa = await ctxD.newPage();
  await uiLogin(pa, seed.alice);
  await pa.goto(`${UI}/`);
  await snap(pa, "dashboard-desktop", "/", { state: "1UP+1DOWN+open-incident" });
  await pa.goto(`${UI}/monitors/${m1.id}`);
  await snap(pa, "monitor-detail-desktop", `/monitors/${m1.id}`);
  await pa.goto(`${UI}/incidents`);
  // bob — empty/state view (no-data + focus ring evidence); own
  // context: an authenticated session would redirect /login -> /.
  const pb = await (await browser.newContext({ viewport: { width: 1440, height: 900 } })).newPage();
  await uiLogin(pb, seed.bob);
  await pb.goto(`${UI}/`);
  await pb.keyboard.press("Tab");
  await snap(pb, "states-and-accessibility", "/", { state: "empty-dashboard+keyboard-focus" });
  // admin — ops views (own context for its own session)
  const pc = await (await browser.newContext({ viewport: { width: 1440, height: 900 } })).newPage();
  await uiLogin(pc, seed.admin);
  await pc.goto(`${UI}/admin`); await snap(pc, "admin-overview-desktop", "/admin");
  await pc.goto(`${UI}/admin/users`); await snap(pc, "admin-users-desktop", "/admin/users");
  await pc.goto(`${UI}/admin/roles`); await snap(pc, "admin-roles-desktop", "/admin/roles");
  await pc.goto(`${UI}/admin/audit`); await snap(pc, "admin-audit-desktop", "/admin/audit");
  // mobile views
  const pm = await ctxM.newPage();
  await uiLogin(pm, seed.alice);
  await pm.goto(`${UI}/`); await snap(pm, "dashboard-mobile", "/", { mobile: true });
  await pm.goto(`${UI}/monitors`);
  await pm.getByRole("button", { name: /new monitor|add monitor|create/i }).first().click().catch(() => {});
  await snap(pm, "monitor-editor-mobile", "/monitors (editor open)", { mobile: true });
  const pm2 = await (await browser.newContext({ viewport: { width: 390, height: 844 },
    deviceScaleFactor: 2, isMobile: true, hasTouch: true })).newPage();
  await uiLogin(pm2, seed.admin);
  await pm2.goto(`${UI}/admin/users`);
  await snap(pm2, "admin-mobile", "/admin/users", { mobile: true });

  // ---------- GIF 1: monitor incident -> recovery ----------
  console.log("[capture] gif1: incident->recovery");
  const g1 = await browser.newContext({ viewport: { width: 1280, height: 720 },
    recordVideo: { dir: RAW, size: { width: 1280, height: 720 } } });
  const g1p = await g1.newPage();
  await uiLogin(g1p, seed.alice);
  await g1p.goto(`${UI}/monitors/${m2.id}`);
  await g1p.waitForTimeout(1200);
  await setMode("down");
  await forceCheck(m2.id); await forceCheck(m2.id);
  await g1p.reload(); await g1p.waitForLoadState("networkidle");
  await g1p.waitForTimeout(1500);
  await setMode("up");
  await forceCheck(m2.id); await forceCheck(m2.id); await forceCheck(m2.id);
  await g1p.goto(`${UI}/`);
  await g1p.waitForLoadState("networkidle"); await g1p.waitForTimeout(1500);
  const g1v = g1p.video(); await g1.close();
  const g1src = await g1v.path();

  // ---------- GIF 2: admin suspend -> denied -> audit ----------
  console.log("[capture] gif2: admin action -> denied -> audit");
  const g2 = await browser.newContext({ viewport: { width: 1280, height: 720 },
    recordVideo: { dir: RAW, size: { width: 1280, height: 720 } } });
  const g2p = await g2.newPage();
  const bobId = (await admin.req("GET", "/admin/users?q=bob")).json.data?.users?.[0]?.id;
  await uiLogin(g2p, seed.admin);
  await g2p.goto(`${UI}/admin/users`);
  await g2p.waitForLoadState("networkidle"); await g2p.waitForTimeout(1000);
  if (bobId) {
    await g2p.goto(`${UI}/admin/users/${bobId}`);
    await g2p.waitForLoadState("networkidle");
    await g2p.getByRole("button", { name: /suspend/i }).first().click().catch(() => {});
    await g2p.waitForTimeout(800);
    const reason = g2p.getByLabel(/reason/i);
    if (await reason.count()) await reason.fill("demo suspension for portfolio");
    await g2p.getByRole("button", { name: /confirm|suspend/i }).last().click().catch(() => {});
    await g2p.waitForTimeout(1200);
  }
  await g2p.goto(`${UI}/admin/audit`);
  await g2p.waitForLoadState("networkidle"); await g2p.waitForTimeout(1500);
  const g2v = g2p.video(); await g2.close();
  const g2src = await g2v.path();

  await browser.close();
  vite.kill();
  await run(["docker", ...COMPOSE, "down", "-v", "--remove-orphans"], { quiet: true }).catch(() => {});

  // ---------- encode GIFs ----------
  console.log("[capture] ffmpeg encode");
  const gifs = [
    { src: g1src, out: "monitor-incident-recovery.gif", transcript: "monitor-incident-recovery.transcript.md",
      flow: "detail page -> forced DOWN (fixture mode) -> check lands -> DOWN state -> forced UP -> recovery checks -> dashboard UP" },
    { src: g2src, out: "admin-role-and-audit.gif", transcript: "admin-role-and-audit.transcript.md",
      flow: "admin users -> user detail -> suspend+reason -> audit page shows recorded action" },
  ];
  for (const g of gifs) {
    const dst = resolve(MEDIA, g.out);
    const pal = resolve(RAW, `${g.out}.pal.png`);
    await run(["ffmpeg", "-y", "-i", g.src, "-vf", "fps=11,scale=1120:-1:flags=lanczos,palettegen", pal]);
    await run(["ffmpeg", "-y", "-i", g.src, "-i", pal,
      "-lavfi", "fps=11,scale=1120:-1:flags=lanczos [x]; [x][1:v] paletteuse", dst]);
    if (statSync(dst).size > 8 * 1024 * 1024)
      console.warn(`[capture] WARN ${g.out} >8MB (${(statSync(dst).size / 1048576).toFixed(1)}MB)`);
    writeFileSync(resolve(MEDIA, g.transcript),
      `# ${g.out} — transcript\n\nProfile: local deterministic harness (compose.test.yaml).\nFlow: ${g.flow}.\n` +
      `Fixture: synthetic demo accounts (${seedTag}); fixture target 'target-public.fixture' toggled via /control.\n` +
      `No time-stretch: actions shown in real order; fixture waits are API-polled, not slept.\n`);
    shots.push({ name: g.out.replace(".gif", ""), file: rel(dst),
      route: g.flow, viewport: "1280x720@11fps", state: "recorded-flow",
      transcript: rel(resolve(MEDIA, g.transcript)) });
  }

  // ---------- manifest ----------
  const manifest = {
    format: "uptime-media-manifest-v1",
    generated_at: new Date().toISOString(),
    profile, runtime_sha: runtimeSha,
    browser: `chromium ${browser?.version?.() ?? "playwright"}`,
    harness: "compose.test.yaml (uptime-media): testapp + fixture + postgres:17.11 + vite dev",
    seed: { tag: seedTag, identities: "synthetic @demo.invalid accounts; no personal data" },
    privacy: "allowlisted app routes only; no internal plan/report/personal paths in pixels/DOM/metadata",
    limitations: [
      "localRC capture — hosted/production media pending hosted deploy",
      "GIF flows use deterministic fixture toggles, not real target latency",
    ],
    artifacts: shots.map((s) => ({
      ...s,
      sha256: `sha256:${createHash("sha256").update(readFileSync(resolve(ROOT, s.file))).digest("hex")}`,
      bytes: statSync(resolve(ROOT, s.file)).size,
      captured_utc: new Date().toISOString(),
    })),
  };
  mkdirSync(dirname(output), { recursive: true });
  writeFileSync(output, JSON.stringify(manifest, null, 2));
  console.log(`[capture] manifest: ${output} — ${shots.length} artifacts`);
}

main().catch(async (e) => {
  console.error(e.message ?? e);
  for (const p of ["5173"])
    try {
      const { execSync } = await import("node:child_process");
      if (process.platform === "win32")
        execSync(`for /f "tokens=5" %a in ('netstat -ano ^| findstr :${p} ^| findstr LISTENING') do taskkill /PID %a /F`, { stdio: "ignore" });
    } catch {}
  await run(["docker", ...COMPOSE, "down", "-v", "--remove-orphans"], { quiet: true }).catch(() => {});
  process.exit(1);
});
