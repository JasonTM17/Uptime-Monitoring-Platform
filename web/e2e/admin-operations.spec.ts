import { expect, test, type Page } from "@playwright/test";
import { mockApi } from "./mock";

const json = (body: unknown, status = 200) => ({
  status,
  contentType: "application/json",
  body: JSON.stringify(body),
});

const DEAD_ROW = {
  id: "d-deadbeef-0000-0000-0000-000000000001",
  monitor_id: "m-1",
  incident_id: null,
  event_kind: "incident_closed",
  state: "DEAD",
  attempts: 8,
  next_attempt_at: null,
  last_error_code: "delivery_failed",
  created_at: "2025-01-01T00:00:00Z",
  version: 3,
};

const AUDIT_ROW = {
  id: "a-1",
  actor_id: "u-admin",
  actor_kind: "user",
  action: "role.update",
  subject_type: "role",
  subject_id: "r-2",
  reason: "tighten grants",
  outcome: "ok",
  diff: { permissions: { before: ["audit:read"], after: ["audit:read", "platform:read"] } },
  request_id: "req-1",
  created_at: "2025-01-01T00:00:00Z",
};

async function adminProbe(page: Page) {
  await page.route(
    (url) => url.pathname === "/api/admin/overview",
    (route) => route.fulfill(json({ data: {} })),
  );
}

test.describe("admin operations screens", () => {
  test("operations shows stale/absent freshness, not fabricated zeros", async ({
    page,
  }) => {
    await mockApi(page);
    await adminProbe(page);
    await page.route(
      (url) => url.pathname === "/api/admin/operations",
      (route) =>
        route.fulfill(
          json({
            data: {
              engine: {
                epoch: 4,
                heartbeat_at: "2025-01-01T00:00:00Z",
                freshness: "stale",
                stale_after_seconds: 30,
              },
              runs: { reserved: 0, running: 0 },
              outbox: { pending: 0, leased: 0, dead: 3, oldest_pending: null, oldest_age_seconds: null },
              rollup: { last_bucket: null, freshness: "absent" },
            },
          }),
        ),
    );
    await page.goto("/admin/operations");
    await expect(page.getByText("stale", { exact: true })).toBeVisible();
    await expect(page.getByText("absent", { exact: true })).toBeVisible();
    await expect(page.getByText("no pending backlog")).toBeVisible();
  });

  test("outbox retry is reasoned, versioned, and its receipt says queued", async ({
    page,
  }) => {
    await mockApi(page);
    await adminProbe(page);
    await page.route(
      (url) => url.pathname.startsWith("/api/admin/outbox"),
      (route) => {
        const m = route.request().method();
        if (m === "POST" && route.request().url().endsWith("/retry")) {
          return route.fulfill(
            json({ data: { delivery_id: DEAD_ROW.id, state: "PENDING", version: 4 } }, 202),
          );
        }
        return route.fulfill(
          json({ data: { deliveries: [DEAD_ROW], next_cursor: null } }),
        );
      },
    );
    await page.goto("/admin/outbox");
    await page.getByRole("button", { name: /retry…/i }).click();
    // keyboard: type the reason and confirm
    await page.getByLabel(/reason/i).fill("provider outage cleared");
    await page.keyboard.press("Tab");
    await page.getByRole("button", { name: /^retry$/i }).press("Enter");
    await expect(page.getByText(/re-queued PENDING — not delivered/i)).toBeVisible();
  });

  test("audit list filters, keyboard detail navigation, read-only diff", async ({
    page,
  }) => {
    await mockApi(page);
    await adminProbe(page);
    await page.route(
      (url) => url.pathname === "/api/admin/audit-events",
      (route) =>
        route.fulfill(json({ data: { events: [AUDIT_ROW], next_cursor: null } })),
    );
    await page.route(
      (url) => url.pathname === "/api/admin/audit-events/a-1",
      (route) => route.fulfill(json({ data: AUDIT_ROW })),
    );
    await page.goto("/admin/audit");
    // bounded filters incl. time window exist
    await expect(page.getByLabel(/^from$/i)).toBeVisible();
    await expect(page.getByLabel(/^to$/i)).toBeVisible();
    // keyboard: focus the View link, Enter opens the detail
    const view = page.getByRole("link", { name: /^view$/i });
    await view.focus();
    await page.keyboard.press("Enter");
    await expect(page.getByRole("heading", { name: /audit event/i })).toBeVisible();
    // the diff region is keyboard-focusable, and there are no edit/export controls
    const diff = page.getByLabel(/redacted before\/after diff/i);
    await diff.focus();
    await expect(diff).toBeFocused();
    await expect(
      page.getByRole("article").getByRole("button", { name: /edit|export|delete/i }),
    ).toHaveCount(0);
    // no horizontal page trap at this viewport
    const overflow = await page.evaluate(
      () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
    );
    expect(overflow).toBeLessThanOrEqual(1);
  });
});
