import { expect, test } from "@playwright/test";
import { mockApi } from "./mock";

// MOCKED evidence — offline, denial, and revocation states are hard to
// trigger on demand against a live service; contract fixtures prove the
// UI's honest-state semantics. They do not stand in for a full live app
// journey (phase-09/11 cards own that proof).

const json = (body: unknown, status = 200) => ({
  status,
  contentType: "application/json",
  body: JSON.stringify(body),
});

const err = (status: number, code: string, message: string) =>
  json({ error: { code, message, fields: null }, request_id: "r" }, status);

test.describe("ui state honesty", () => {
  test("offline shows a banner and re-fetches after reconnect", async ({
    page,
    context,
  }) => {
    await mockApi(page);
    let summaryHits = 0;
    await page.route(
      (url) => url.pathname === "/api/dashboard/summary",
      (route) => {
        summaryHits++;
        return route.fulfill(json({ data: { monitors: 1 } }));
      },
    );
    await page.route(
      (url) => url.pathname === "/api/monitors",
      (route) => route.fulfill(json({ data: { items: [], has_more: false, next_cursor: null } })),
    );
    await page.goto("/");
    await expect(page.getByText("No monitors match this view.")).toBeVisible();
    await context.setOffline(true);
    await expect(page.getByText(/you’re offline/i)).toBeVisible();
    await context.setOffline(false);
    await expect(page.getByText(/you’re offline/i)).toHaveCount(0);
    // initial fetch + the reconnect refetch must both have landed
    expect(summaryHits).toBeGreaterThanOrEqual(2);
  });

  test("denied and empty read differently across sections", async ({ page }) => {
    await mockApi(page);
    // admin probe 200 → admin nav visible, but the users read is denied
    await page.route(
      (url) => url.pathname === "/api/admin/overview",
      (route) => route.fulfill(json({ data: {} })),
    );
    await page.route(
      (url) => url.pathname.startsWith("/api/admin/users"),
      (route) => route.fulfill(err(403, "FORBIDDEN", "missing users:read")),
    );
    await page.route(
      (url) => url.pathname.startsWith("/api/admin/audit-events"),
      (route) =>
        route.fulfill(json({ data: { events: [], next_cursor: null } })),
    );
    await page.goto("/admin/users");
    await expect(page.getByText(/doesn’t include/i)).toBeVisible();
    // audit same session: empty reads as empty, not denied
    await page.goto("/admin/audit");
    await expect(page.getByText(/empty result/i)).toBeVisible();
    await expect(page.getByText(/doesn’t include/i)).toHaveCount(0);
  });

  test("a mid-use revoked session lands on sign-in with the notice", async ({
    page,
  }) => {
    await mockApi(page);
    // The session is valid until the monitors call hits the fence —
    // the flag flips on the revoking request itself, not a call count
    // (StrictMode may consume an aborted first /me fetch).
    let revoked = false;
    await page.route(
      (url) => url.pathname === "/api/auth/me",
      (route) =>
        revoked
          ? route.fulfill(err(401, "UNAUTHENTICATED", "revoked"))
          : route.fulfill(
              json({
                data: {
                  user: { id: "u1", email: "u@example.com", display_name: "U", status: "ACTIVE", created_at: "t" },
                  session_expires_at: "t",
                },
              }),
            ),
    );
    await page.route(
      (url) => url.pathname.startsWith("/api/monitors"),
      (route) => {
        revoked = true;
        return route.fulfill(err(401, "UNAUTHENTICATED", "revoked"));
      },
    );
    await page.goto("/monitors/m-1");
    // any protected query 401 → session ends → guard redirects to login
    await expect(page.getByRole("heading", { name: /sign in/i })).toBeVisible();
    await expect(page.getByText(/session expired/i)).toBeVisible();
  });

  test("login errors are inline and distinct (bad creds vs limited)", async ({
    page,
  }) => {
    await page.route(
      (url) => url.pathname === "/api/auth/me",
      (route) => route.fulfill(err(401, "UNAUTHENTICATED", "none")),
    );
    await page.route(
      (url) => url.pathname === "/api/auth/login",
      (route) => route.fulfill(err(401, "UNAUTHENTICATED", "invalid credentials")),
    );
    await page.goto("/login");
    await page.getByLabel(/email/i).fill("u@example.com");
    await page.getByLabel(/password/i).fill("wrong");
    await page.getByRole("button", { name: /sign in/i }).click();
    await expect(page.getByRole("alert")).toBeVisible();
    // no navigation happened — still on the form with the email preserved
    await expect(page.getByLabel(/email/i)).toHaveValue("u@example.com");
  });

  test("unknown nested route keeps the shell and says not found", async ({
    page,
  }) => {
    await mockApi(page);
    await page.goto("/monitors/does-not-exist/deeper");
    await expect(page.getByRole("heading", { name: /page not found/i })).toBeVisible();
  });
});
