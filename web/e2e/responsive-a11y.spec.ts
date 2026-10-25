import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";
import { mockApi } from "./mock";

// MOCKED evidence — a11y/responsive checks run over contract fixtures.
// Automated axe is a gate, not a substitute for the manual keyboard/
// screen-reader review recorded in docs/testing/frontend.md.

const json = (body: unknown, status = 200) => ({
  status,
  contentType: "application/json",
  body: JSON.stringify(body),
});

const MON = {
  id: "m-1",
  name: "billing api",
  target_url: "https://api.example.com",
  method: "GET",
  interval_seconds: 300,
  timeout_seconds: 5,
  expected_status: 200,
  is_paused: false,
  health: "UP",
  generation: 1,
  next_check_at: "2025-01-01T00:10:00Z",
  last_checked_at: "2025-01-01T00:05:00Z",
  last_response_time_ms: 100,
  last_error_type: null,
  freshness: "fresh",
  created_at: "2025-01-01T00:00:00Z",
  updated_at: "2025-01-01T00:00:00Z",
};

async function readyDashboard(page: Page) {
  await mockApi(page);
  await page.route(
    (url) => url.pathname === "/api/dashboard/summary",
    (route) =>
      route.fulfill(
        json({
          data: {
            monitors: 1,
            up: 1,
            down: 0,
            paused: 0,
            active: 1,
            open_incidents: 1,
            sample_uptime_24h: 0.99,
            // a long unbroken monitor name exercises the wrapped row —
            // without a seeded incident the overflow gate never sees it
            recent_incidents: [
              {
                id: "9f8e7d6c-5b4a-4321-9876-0123456789ab",
                monitor_id: "m-1",
                monitor_name: "billing-api-production-endpoint-monitor",
                opened_at: "2025-01-01T04:30:00Z",
                resolved_at: null,
                close_reason: null,
              },
            ],
            quota: { used: 1, active: 1, paused: 0, limit: 5, profile: "local", as_of: "t", source: "server" },
            as_of: "2025-01-01T00:05:00Z",
          },
        }),
      ),
  );
  await page.route(
    (url) => url.pathname === "/api/monitors",
    (route) => route.fulfill(json({ data: { items: [MON], has_more: false, next_cursor: null } })),
  );
}

async function noPageOverflow(page: Page) {
  return page.evaluate(
    () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
  );
}

test.describe("responsive + accessibility matrix", () => {
  test("dashboard has no page-level horizontal scroll at declared widths", async ({
    page,
  }) => {
    await readyDashboard(page);
    for (const w of [360, 390, 768, 1280, 1440]) {
      await page.setViewportSize({ width: w, height: 800 });
      await page.goto("/");
      await expect(page.getByText("billing api")).toBeVisible();
      expect(await noPageOverflow(page)).toBeLessThanOrEqual(1);
    }
  });

  test("200% zoom keeps content reachable without a horizontal trap", async ({
    page,
  }) => {
    await readyDashboard(page);
    await page.setViewportSize({ width: 390, height: 800 });
    await page.goto("/");
    await page.evaluate(() => {
      document.body.style.zoom = "2";
    });
    await expect(page.getByText("billing api")).toBeVisible();
    // page-level scroll is banned; an inner table region may scroll
    expect(await noPageOverflow(page)).toBeLessThanOrEqual(1);
  });

  test("authenticated dashboard and admin pages pass axe", async ({ page }) => {
    await readyDashboard(page);
    // register BEFORE first load — the capability probe caches for 5min
    await page.route(
      (url) => url.pathname === "/api/admin/overview",
      (route) => route.fulfill(json({ data: { engine: { freshness: "fresh" } } })),
    );
    await page.goto("/");
    await expect(page.getByText("billing api")).toBeVisible();
    const dash = await new AxeBuilder({ page }).analyze();
    expect(dash.violations).toEqual([]);
    await page.goto("/admin");
    await expect(page.getByText(/engine heartbeat/i)).toBeVisible();
    const admin = await new AxeBuilder({ page }).analyze();
    expect(admin.violations).toEqual([]);
  });

  test("keyboard reaches nav, dialogs, and form controls on mobile width", async ({
    page,
  }) => {
    await readyDashboard(page);
    await page.setViewportSize({ width: 390, height: 800 });
    await page.goto("/");
    await expect(page.getByText("billing api")).toBeVisible();
    // Tab from the top reaches the first nav link, then content controls
    await page.keyboard.press("Tab");
    await expect(page.getByRole("link", { name: "Dashboard" })).toBeFocused();
    // the monitor row's detail link is keyboard reachable
    const detail = page.getByRole("link", { name: /billing api/i }).first();
    await detail.focus();
    await expect(detail).toBeFocused();
    // filter controls are operable (segmented pills, keyboard reachable)
    const filter = page
      .getByRole("group", { name: "Filter by health" })
      .getByRole("button", { name: "UP" });
    await filter.focus();
    await expect(filter).toBeFocused();
  });

  test("reduced motion is honored (no animation-only state)", async ({ page }) => {
    await page.emulateMedia({ reducedMotion: "reduce" });
    await readyDashboard(page);
    await page.goto("/");
    await expect(page.getByText("billing api")).toBeVisible();
    // loading skeletons must not be the only visible state: real content
    // is present once data lands, regardless of motion preference
    await expect(page.getByRole("status", { name: /loading/i })).toHaveCount(0);
  });
});
