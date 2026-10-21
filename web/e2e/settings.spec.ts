import { expect, test } from "@playwright/test";
import { mockApi } from "./mock";

const CUR = {
  id: "s-cur",
  device_label: "this laptop",
  created_at: "2025-01-01T00:00:00Z",
  last_seen_at: "2025-01-02T00:00:00Z",
  expires_at: "2025-01-10T00:00:00Z",
  current: true,
};

test.describe("settings page", () => {
  test("sessions render; sign-out-everywhere dialog is keyboard-operable", async ({
    page,
  }) => {
    await mockApi(page);
    await page.route(
      (url) =>
        url.pathname === "/api/auth/sessions" ||
        url.pathname.startsWith("/api/auth/sessions?"),
      (route) =>
        route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify({
            data: { sessions: [CUR], page: 1, page_size: 20 },
          }),
        }),
    );
    await page.route(
      (url) => url.pathname === "/api/dashboard/summary",
      (route) =>
        route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify({
            data: {
              monitors: 3, active: 2, paused: 1, up: 2, down: 0,
              open_incidents: 0, sample_uptime_24h: 1, recent_incidents: [],
              quota: { used: 3, active: 2, paused: 1, limit: 7, profile: "hosted-free", as_of: "t", source: "server" },
              as_of: "t",
            },
          }),
        }),
    );
    await page.goto("/settings");

    await expect(page.getByText("this laptop")).toBeVisible();
    await expect(page.getByText("this session")).toBeVisible();
    await expect(page.getByText("3 / 7 (hosted-free)")).toBeVisible();
    await expect(page.getByText(/isn’t offered/i)).toBeVisible();

    // keyboard walkthrough: open confirm, Escape, verify nothing posted
    const opener = page.getByRole("button", {
      name: /sign out everywhere…/i,
    });
    await opener.focus();
    await page.keyboard.press("Enter");
    const dialog = page.getByRole("dialog");
    await expect(dialog).toBeVisible();
    // focus landed on Cancel — Escape dismisses
    await page.keyboard.press("Escape");
    await expect(dialog).not.toBeVisible();
    // confirm no destructive request escaped
    let posted = false;
    page.on("request", (r) => {
      if (r.url().includes("revoke-all")) posted = true;
    });
    await page.waitForTimeout(300);
    expect(posted).toBe(false);
  });
});
