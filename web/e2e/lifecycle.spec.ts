import { test, expect, request, type APIRequestContext } from "@playwright/test";
import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

// C79 browser lane: real UI journeys against the composed testapp
// (compose.test.yaml). Driven exclusively by scripts/accept-local.mjs,
// which seeds identities and passes these envs:
//   ACCEPT_API_URL      testapp base (default http://localhost:18080)
//   ACCEPT_CONTROL_URL  fixture mode control (default :19080)
//   ACCEPT_SEED_FILE    JSON with seeded emails + passwords
// Running this spec outside the harness skips cleanly — the
// acceptance driver treats skipped tests as NOT_RUN, never PASS.

const API = process.env.ACCEPT_API_URL;
const CONTROL = process.env.ACCEPT_CONTROL_URL ?? "http://localhost:19080";
const SEED_FILE = process.env.ACCEPT_SEED_FILE;

const COMPOSE = ["compose", "-p", "uptime-accept", "-f", "compose.test.yaml"];
const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");

function execApp(args: string[], input?: string): Promise<string> {
  return new Promise((res, rej) => {
    const p = spawn("docker", [...COMPOSE, "exec", "-T", "app", ...args], {
      cwd: REPO_ROOT, stdio: ["pipe", "pipe", "pipe"],
    });
    let out = "", err = "";
    p.stdout.on("data", (d) => (out += d));
    p.stderr.on("data", (d) => (err += d));
    p.on("close", (code) =>
      code === 0 ? res(out) : rej(new Error(`exec ${args[0]} -> ${code}: ${err}`)));
    if (input !== undefined) p.stdin.write(input);
    p.stdin.end();
  });
}

async function setMode(mode: "up" | "down" | "timeout") {
  const res = await fetch(`${CONTROL}/control`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ mode }),
  });
  if (!res.ok) throw new Error(`fixture control -> ${res.status}`);
}

// API-level client (seeding + deterministic check stepping). The UI
// journey itself always goes through the browser.
async function apiLogin(email: string, password: string): Promise<{
  ctx: APIRequestContext;
  csrf: string;
}> {
  const ctx = await request.newContext({ baseURL: API });
  const c = await ctx.get("/auth/csrf");
  const csrf = (await c.json()).data.csrf_token as string;
  const res = await ctx.post("/auth/login", {
    headers: { "x-csrf-token": csrf, origin: API! },
    data: { email, password },
  });
  if (res.status() !== 200) throw new Error(`login ${email} -> ${res.status()}`);
  return { ctx, csrf };
}

const mut = (csrf: string) => ({
  headers: { "x-csrf-token": csrf, origin: API! },
});

// One real check, forced: pause+resume sets next_check_at=now(); the
// poll confirms the check landed before returning.
async function forceCheck(ctx: APIRequestContext, csrf: string, id: string) {
  const before = await (await ctx.get(`/monitors/${id}`)).json();
  const prev = before.data.last_checked_at ?? null;
  const p = await ctx.post(`/monitors/${id}/pause`, {
    ...mut(csrf),
    data: { expected_generation: before.data.generation },
  });
  if (p.status() !== 200) throw new Error(`pause -> ${p.status()}`);
  const paused = await p.json();
  const r = await ctx.post(`/monitors/${id}/resume`, {
    ...mut(csrf),
    data: { expected_generation: paused.data.generation },
  });
  if (r.status() !== 200) throw new Error(`resume -> ${r.status()}`);
  await expect
    .poll(async () => {
      const m = await (await ctx.get(`/monitors/${id}`)).json();
      return m.data.last_checked_at;
    }, { timeout: 20_000, intervals: [300, 500, 1000] })
    .not.toBe(prev);
}

async function uiLogin(
  page: import("@playwright/test").Page,
  email: string,
  password: string,
) {
  await page.goto("/login");
  await page.getByLabel("Email").fill(email);
  await page.getByLabel("Password").fill(password);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page).toHaveURL(/\/$/);
}

const seeds = SEED_FILE
  ? (JSON.parse(readFileSync(SEED_FILE, "utf8")) as {
      alice: string; bob: string; admin: string;
      passwords: { [k: string]: string };
      alice_id?: string; bob_id?: string; admin_id?: string;
    })
  : null;

// noUncheckedIndexedAccess makes record reads `string | undefined`;
// a missing seed password is a harness defect — fail loudly.
function pw(name: string): string {
  const v = seeds?.passwords[name];
  if (!v) throw new Error(`seed password missing: ${name}`);
  return v;
}

// Both viewport projects share one seeded world; earlier-project rows
// persist, so fixture names must be unique per project AND non-prefix
// ("dsk"/"mob" — neither contains the other — so substring selectors
// can never cross-match a sibling project's rows).
function tag(): string {
  return test.info().project.name === "chromium" ? "dsk" : "mob";
}

test.skip(!API || !seeds, "acceptance env not set — run via scripts/accept-local.mjs");

test.describe("C79 lifecycle acceptance (real composed stack)", () => {
  test("LifecycleIncidentRecovery", async ({ page }) => {
    test.setTimeout(300_000);
    const { ctx, csrf } = await apiLogin(seeds!.alice, pw("alice"));
    const monName = `e2e-accept-target-${tag()}`;

    // Channel: pending via API, verified via operator CLI — the only
    // supported verification path.
    const ch = await ctx.post("/notification-channels", {
      ...mut(csrf), data: { label: "e2e-accept-chan" },
    });
    expect(ch.status()).toBe(201);
    const chanId = (await ch.json()).data.id;
    const me = await (await ctx.get("/auth/me")).json();
    await execApp(
      ["/harness-bin/channel", "verify", "-channel", chanId,
        "-owner", me.data.user.id, "-receipt", "e2e-acceptance"],
      "accept-e2e-chat\n");

    // Monitor: created through the REAL UI form.
    await uiLogin(page, seeds!.alice, pw("alice"));
    await page.goto("/monitors");
    await page.getByLabel("Name").fill(monName);
    await page.getByLabel("Target URL").fill("http://target-public.fixture/check");
    await page.getByLabel("Interval (s)").fill("60");
    await page.getByLabel("Timeout (s)").fill("5");
    await page.getByRole("button", { name: /create/i }).click();
    await expect(page).toHaveURL(/\/monitors\//);
    const monitorId = page.url().split("/monitors/")[1];
    if (!monitorId) throw new Error("monitor create did not route to detail");

    // Bind the verified channel via API (UI binding is C70-covered).
    const mon = await (await ctx.get(`/monitors/${monitorId}`)).json();
    const bind = await ctx.put(`/monitors/${monitorId}/notification-channels`, {
      ...mut(csrf),
      data: { expected_generation: mon.data.generation, channel_ids: [chanId] },
    });
    expect(bind.status()).toBe(200);

    // Baseline UP through real engine + UI badge. The detail page
    // polls on the product's 20s cadence — windows cover one full
    // interval plus check latency.
    await setMode("up");
    await expect(page.getByText(/^UP$/).first()).toBeVisible({ timeout: 45_000 });

    // 3 forced failures — threshold semantics are the product's.
    await setMode("down");
    for (let i = 0; i < 3; i++) await forceCheck(ctx, csrf, monitorId);
    await expect(page.getByText(/^DOWN$/).first()).toBeVisible({ timeout: 45_000 });

    await page.goto("/incidents");
    await expect(page.getByText("currently open")).toBeVisible();
    await expect(
      page.getByRole("link", { name: monName, exact: true }),
    ).toBeVisible();

    const deliveries = async () =>
      (await (await fetch(`${API}/__test__/deliveries`)).json()).deliveries as
        { text: string }[];
    await expect
      .poll(async () => (await deliveries()).some((d) => d.text === monName + " is DOWN"))
      .toBe(true);

    // Recovery rides the real 60s cadence (pause/update would close
    // the incident as CONFIG_CHANGED — not evidence of recovery).
    await setMode("up");
    await expect
      .poll(
        async () => {
          const inc = await (
            await ctx.get(`/monitors/${monitorId}/incidents?state=resolved`)
          ).json();
          return (inc.data.incidents ?? []).some(
            (i: { close_reason?: string }) => i.close_reason === "RECOVERED",
          );
        },
        { timeout: 200_000, intervals: [2000, 5000, 5000] },
      )
      .toBe(true);
    await expect
      .poll(async () => (await deliveries()).some((d) => d.text === monName + " is RECOVERY"))
      .toBe(true);

    await page.goto("/incidents");
    await expect(page.getByText("currently open")).toBeVisible();
    await expect(page.locator("strong", { hasText: "0" })).toBeVisible();
    await ctx.dispose();
  });

  test("AdminRoleRevocation", async ({ page, browser }) => {
    test.setTimeout(120_000);
    const bobApi = await apiLogin(seeds!.bob, pw("bob"));

    // Admin UI: revoke bob's sessions through the real dialog.
    await uiLogin(page, seeds!.admin, pw("admin"));
    await page.goto(`/admin/users/${seeds!.bob_id}`);
    // The action's dialog TITLE is "Revoke all sessions"; the page
    // button itself is labeled "Revoke sessions…".
    await page.getByRole("button", { name: /revoke sessions/i }).click();
    const dialog = page.getByRole("dialog", { name: "Revoke all sessions" });
    await dialog.getByLabel(/Reason/).fill("e2e acceptance revocation");
    await dialog.getByRole("button", { name: "Revoke sessions" }).click();
    // The first submit resolves async to either "closed" (recent auth
    // held) or a SECOND dialog ("Confirm it's you") — a point-in-time
    // isVisible() races the 403 and misses the step-up, so poll until
    // the outcome is decided.
    const reauth = page.getByRole("dialog", { name: /confirm it.s you/i });
    await expect
      .poll(
        async () =>
          (await reauth.isVisible()) ? "reauth" : (await dialog.isVisible()) ? "open" : "closed",
        { timeout: 15_000 },
      )
      .not.toBe("open");
    if (await reauth.isVisible()) {
      await reauth.getByLabel("Password").fill(pw("admin"));
      await reauth.getByRole("button", { name: "Continue" }).click();
      await expect(reauth).not.toBeVisible();
      await dialog.getByRole("button", { name: "Revoke sessions" }).click();
    }
    // Success = dialog closes AND the status notice reports the count.
    // (Matching bare /revoked/ would hit the dialog's own summary text
    // while the mutation is still in flight.)
    await expect(dialog).not.toBeVisible({ timeout: 15_000 });
    await expect(
      page.getByRole("status").filter({ hasText: /session\(s\) revoked/ }),
    ).toBeVisible();

    // Bob's live session must now be rejected.
    const denied = await bobApi.ctx.get("/monitors");
    expect(denied.status()).toBe(401);

    // Audit history shows the privileged action.
    await page.goto("/admin/audit");
    await expect(page.getByRole("table")).toContainText(/revoke/i);

    // Bob's browser session is dead too — a second UI context sees
    // the login redirect, not stale data.
    const bctx = await browser.newContext();
    const bpage = await bctx.newPage();
    await uiLogin(bpage, seeds!.bob, pw("bob")); // fresh login works (account itself is fine)
    await bpage.goto("/");
    await expect(bpage).not.toHaveURL(/login/);
    await bctx.close();
    await bobApi.ctx.dispose();
  });

  test("OwnerIsolation", async ({ page }) => {
    test.setTimeout(90_000);
    const { ctx, csrf } = await apiLogin(seeds!.alice, pw("alice"));
    const isoName = `alice-isolated-target-${tag()}`;
    const mon = await ctx.post("/monitors", {
      ...mut(csrf),
      data: {
        name: isoName,
        target_url: "http://target-public.fixture/check",
        interval_seconds: 60,
        timeout_seconds: 5,
        expected_status: 200,
      },
    });
    expect(mon.status()).toBe(201);
    const mid = (await mon.json()).data.id;
    await ctx.dispose();

    // Bob's UI session: direct navigation to alice's monitor must
    // land on the not-found state, never the data.
    await uiLogin(page, seeds!.bob, pw("bob"));
    await page.goto(`/monitors/${mid}`);
    await expect(page.getByText(/not found|404/i).first()).toBeVisible({
      timeout: 15_000,
    });
    await expect(page.getByText(/alice-isolated-target/)).toHaveCount(0);

    await page.goto("/");
    await expect(
      page.getByRole("link", { name: isoName, exact: true }),
    ).toHaveCount(0);
  });

  test("LogoutIdentityRace", async ({ page }) => {
    test.setTimeout(60_000);
    const { ctx, csrf } = await apiLogin(seeds!.alice, pw("alice"));
    const raceName = `race-marker-monitor-${tag()}`;
    const mon = await ctx.post("/monitors", {
      ...mut(csrf),
      data: {
        name: raceName,
        target_url: "http://target-public.fixture/check",
        interval_seconds: 60,
        timeout_seconds: 5,
        expected_status: 200,
      },
    });
    expect(mon.status()).toBe(201);
    await ctx.dispose();

    // Alice UI session → sees her marker → signs out → identity gone.
    await uiLogin(page, seeds!.alice, pw("alice"));
    await expect(
      page.getByRole("link", { name: raceName, exact: true }),
    ).toBeVisible({ timeout: 15_000 });
    await page.getByRole("button", { name: "Sign out" }).click();
    await expect(page).toHaveURL(/login/);

    // Bob signs in on the SAME browser: identity-scoped cache means
    // zero of alice's rows may surface.
    await page.getByLabel("Email").fill(seeds!.bob);
    await page.getByLabel("Password").fill(pw("bob"));
    await page.getByRole("button", { name: "Sign in" }).click();
    await expect(page).toHaveURL(/\/$/);
    await expect(page.getByText(seeds!.bob)).toBeVisible();
    await expect(page.getByText(/race-marker-monitor/)).toHaveCount(0);
  });
});
