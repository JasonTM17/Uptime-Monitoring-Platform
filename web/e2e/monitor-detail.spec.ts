import { expect, test, type Page } from "@playwright/test";

const MON = {
  id: "m-1",
  name: "site",
  target_url: "https://example.com",
  method: "GET",
  interval_seconds: 300,
  timeout_seconds: 5,
  expected_status: 200,
  is_paused: false,
  health: "UP",
  generation: 3,
  next_check_at: "2025-01-01T00:05:00Z",
  last_checked_at: "2025-01-01T00:00:00Z",
  last_response_time_ms: 90,
  last_error_type: null,
  freshness: "fresh",
  created_at: "2025-01-01T00:00:00Z",
  updated_at: "2025-01-01T00:00:00Z",
};

const STATS = {
  window_start: "2025-01-01T00:00:00Z",
  window_end: "2025-01-02T00:00:00Z",
  data_start: "2025-01-01T06:00:00Z",
  data_end: "2025-01-02T00:00:00Z",
  valid_samples: 3,
  successes: 2,
  failures: 1,
  excluded_samples: 0,
  expected_samples: 5,
  missed_samples: 2,
  pending_samples: 0,
  coverage: 0.6,
  sample_uptime: 2 / 3,
  avg_duration_ms: 120,
  raw_retention_hours: 12,
  hourly_retention_days: 30,
  raw_available_from: "2025-01-01T12:00:00Z",
  resolution: "mixed",
  is_partial: true,
  series: [
    { bucket_start: "2025-01-01T06:00:00Z", valid_samples: 2, successes: 2, failures: 0, excluded_samples: 0, sample_uptime: 1, avg_duration_ms: 100 },
    { bucket_start: "2025-01-01T07:00:00Z", valid_samples: 0, successes: 0, failures: 0, excluded_samples: 0, sample_uptime: null, avg_duration_ms: null },
  ],
};

async function mockApi(page: Page) {
  const json = (body: unknown, status = 200) => ({
    status,
    contentType: "application/json",
    body: JSON.stringify(body),
  });
  await page.route(
    (url) => url.pathname.startsWith("/api/"),
    (route) => {
    const p = new URL(route.request().url()).pathname;
    if (p === "/api/auth/me")
      return route.fulfill(
        json({
          data: {
            user: { id: "u1", email: "u@example.com", display_name: "U", status: "ACTIVE", created_at: "t" },
            session_expires_at: "t",
          },
        }),
      );
    if (p === "/api/admin/overview") return route.fulfill(json({}, 403));
    if (p === "/api/notification-channels")
      return route.fulfill(json({ data: { items: [] } }));
    if (p === "/api/monitors/m-1") return route.fulfill(json({ data: MON }));
    if (p === "/api/monitors/m-1/stats")
      return route.fulfill(json({ data: STATS }));
    if (p === "/api/monitors/m-1/incidents")
      return route.fulfill(json({ data: { incidents: [], page: { has_more: false } } }));
    if (p === "/api/monitors/m-1/checks")
      return route.fulfill(
        json({
          data: {
            checks: [
              { run_id: "r1", slot_at: "2025-01-01T08:00:00Z", started_at: null, finished_at: null, status: "COMPLETED", outcome: "SUCCESS", eligible: true, success: true, http_status: 200, duration_ms: 42, observed_at: "2025-01-01T08:00:01Z" },
            ],
            page: { has_more: false },
          },
        }),
      );
    return route.fulfill(json({}, 404));
    },
  );
}

export { mockApi };

test.describe("monitor detail", () => {
  test("shows requested vs represented bounds, partial label, and keyboard data table", async ({ page }) => {
    await mockApi(page);
    await page.goto("/monitors/m-1");

    await expect(page.getByText(/requested/)).toBeVisible();
    await expect(page.getByText(/represented/)).toBeVisible();
    await expect(page.getByText("partial window")).toBeVisible();
    await expect(page.getByText("resolution mixed")).toBeVisible();
    await expect(page.getByRole("img", { name: /per-bucket check outcomes/i })).toBeVisible();

    // the data table is a native disclosure widget — keyboard-operable
    const summary = page.getByText(/data table/i);
    await summary.focus();
    await page.keyboard.press("Enter");
    await expect(
      page.getByRole("cell", { name: "2025-01-01T07:00:00Z" }),
    ).toBeVisible();

    // 200% zoom: no page-level horizontal scroll (tables scroll internally)
    await page.evaluate(() => {
      (document.body.style as CSSStyleDeclaration).zoom = "2";
    });
    const sw = await page.evaluate(() => ({
      doc: document.documentElement.scrollWidth,
      vw: window.innerWidth,
    }));
    expect(sw.doc).toBeLessThanOrEqual(sw.vw + 2);
  });
});
