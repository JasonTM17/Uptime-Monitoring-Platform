import { expect, test, type Page } from "@playwright/test";
import { mockApi } from "./mock";

// MOCKED evidence — contract fixtures over route interception. Proves
// UI state semantics only; a live engine/backend journey belongs to
// the phase-09/11 acceptance cards, not this matrix.

const json = (body: unknown, status = 200) => ({
  status,
  contentType: "application/json",
  body: JSON.stringify(body),
});

const PAUSED = {
  id: "m-paused",
  name: "legacy endpoint",
  target_url: "https://legacy.example.com",
  method: "GET",
  interval_seconds: 300,
  timeout_seconds: 5,
  expected_status: 200,
  is_paused: true,
  health: "UNKNOWN",
  generation: 1,
  next_check_at: "2025-01-01T00:10:00Z",
  last_checked_at: null,
  last_response_time_ms: null,
  last_error_type: null,
  freshness: null,
  created_at: "2025-01-01T00:00:00Z",
  updated_at: "2025-01-01T00:00:00Z",
};

const STALE_UP = {
  ...PAUSED,
  id: "m-stale",
  name: "billing api",
  is_paused: false,
  health: "UP",
  freshness: "stale",
  last_checked_at: "2025-01-01T00:04:00Z",
  last_response_time_ms: 180,
};

const NODATA = {
  ...PAUSED,
  id: "m-new",
  name: "brand new",
  is_paused: false,
  health: "UNKNOWN",
  freshness: null,
};

const SUMMARY = {
  monitors: 3,
  active: 2,
  paused: 1,
  up: 1,
  down: 0,
  open_incidents: 0,
  sample_uptime_24h: null,
  recent_incidents: [],
  quota: {
    used: 3,
    active: 2,
    paused: 1,
    limit: 5,
    profile: "local",
    as_of: "2025-01-01T00:00:00Z",
    source: "server",
  },
  as_of: "2025-01-01T00:05:00Z",
};

async function dashboardMocks(page: Page, items: unknown[] = [PAUSED, STALE_UP, NODATA]) {
  await page.route(
    (url) => url.pathname === "/api/dashboard/summary",
    (route) => route.fulfill(json({ data: SUMMARY })),
  );
  await page.route(
    (url) => url.pathname === "/api/monitors",
    (route) => route.fulfill(json({ data: { items, has_more: false, next_cursor: null } })),
  );
}

test.describe("user monitor journeys", () => {
  test("dashboard shows quota, paused badge, stale and no-data states honestly", async ({
    page,
  }) => {
    await mockApi(page);
    await dashboardMocks(page);
    await page.goto("/");
    await expect(page.getByText("3 / 5")).toBeVisible();
    await expect(page.getByText("No samples")).toBeVisible();
    await expect(page.getByText("PAUSED", { exact: true })).toBeVisible();
    await expect(page.getByText("STALE", { exact: true })).toBeVisible();
    await expect(page.getByText("NO DATA", { exact: true })).toBeVisible();
    // paused badge wins over health — no fabricated UP/DOWN next to it
    const pausedRow = page.getByRole("row", { name: /legacy endpoint/ });
    await expect(pausedRow.getByText("PAUSED")).toBeVisible();
    await expect(pausedRow.getByText("UNKNOWN")).toHaveCount(0);
  });

  test("paused filter is sent to the API, not hidden client-side", async ({
    page,
  }) => {
    await mockApi(page);
    let sawPausedParam = false;
    await page.route(
      (url) => url.pathname === "/api/dashboard/summary",
      (route) => route.fulfill(json({ data: SUMMARY })),
    );
    await page.route(
      (url) => url.pathname === "/api/monitors",
      (route) => {
        if (new URL(route.request().url()).searchParams.get("paused") === "true")
          sawPausedParam = true;
        return route.fulfill(json({ data: { items: [PAUSED], has_more: false, next_cursor: null } }));
      },
    );
    await page.goto("/");
    await page.getByLabel("Filter by paused").selectOption("true");
    await expect(page.getByText("legacy endpoint")).toBeVisible();
    expect(sawPausedParam).toBe(true);
  });

  test("monitor detail with no evidence says so — gap, not a zero", async ({
    page,
  }) => {
    await mockApi(page);
    await page.route(
      (url) => url.pathname === "/api/monitors/m-new",
      (route) => route.fulfill(json({ data: NODATA })),
    );
    await page.route(
      (url) => url.pathname === "/api/monitors/m-new/stats",
      (route) =>
        route.fulfill(
          json({
            data: {
              window_start: "2025-01-01T00:00:00Z",
              window_end: "2025-01-01T01:00:00Z",
              data_start: null,
              data_end: null,
              resolution: "hour",
              is_partial: true,
              sample_uptime: null,
              coverage: null,
              avg_duration_ms: null,
              valid_samples: 0,
              expected_samples: 0,
              missed_samples: 0,
              buckets: [],
            },
          }),
        ),
    );
    await page.route(
      (url) => url.pathname === "/api/monitors/m-new/checks",
      (route) =>
        route.fulfill(json({ data: { items: [], has_more: false, next_cursor: null } })),
    );
    await page.route(
      (url) => url.pathname === "/api/monitors/m-new/incidents",
      (route) =>
        route.fulfill(json({ data: { items: [], has_more: false, next_cursor: null } })),
    );
    await page.route(
      (url) => url.pathname === "/api/monitors/m-new/notification-channels",
      (route) => route.fulfill(json({ data: { items: [] } })),
    );
    await page.goto("/monitors/m-new");
    await expect(page.getByText(/no samples in this window yet/i)).toBeVisible();
    await expect(page.getByText("No check runs recorded yet.")).toBeVisible();
  });

  test("create form validates inline; a quota conflict explains scope", async ({
    page,
  }) => {
    await mockApi(page);
    let posts = 0;
    await page.route(
      (url) => url.pathname === "/api/monitors",
      (route) => {
        if (route.request().method() === "POST") {
          posts++;
          return route.fulfill(
            json(
              {
                error: {
                  code: "QUOTA_EXCEEDED",
                  message: "monitor limit reached",
                  fields: { scope: "account" },
                },
                request_id: "r",
              },
              409,
            ),
          );
        }
        return route.fulfill(json({ data: { items: [], has_more: false, next_cursor: null } }));
      },
    );
    await page.goto("/monitors");
    // interval below the 60s floor → inline error, no request sent
    await page.getByLabel(/interval/i).fill("10");
    await page.getByLabel(/name/i).fill("x");
    await page.getByLabel(/target|url/i).fill("https://api.example.com");
    await page.getByRole("button", { name: /create monitor/i }).click();
    await expect(page.getByText(/interval must be/i)).toBeVisible();
    expect(posts).toBe(0);
    // valid input → the server's quota conflict is explained in scope
    await page.getByLabel(/interval/i).fill("300");
    await page.getByRole("button", { name: /create monitor/i }).click();
    await expect(page.getByText(/monitor limit reached/i)).toBeVisible();
    expect(posts).toBe(1);
  });
});
