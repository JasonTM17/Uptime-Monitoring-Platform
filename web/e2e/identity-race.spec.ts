import { expect, test, type Page } from "@playwright/test";

// MOCKED evidence — identity switching is driven through contract
// fixtures; what it proves is the cache-scoping invariant: after a
// sign-out/sign-in the previous identity's data can never hydrate the
// new one (every query key carries the user id; qc.clear() runs on
// login, logout and session events).

const json = (body: unknown, status = 200) => ({
  status,
  contentType: "application/json",
  body: JSON.stringify(body),
});

const USER_A = {
  id: "u-alice",
  email: "alice@example.com",
  display_name: "Alice",
  status: "ACTIVE",
  created_at: "2025-01-01T00:00:00Z",
};
const USER_B = { ...USER_A, id: "u-bob", email: "bob@example.com", display_name: "Bob" };

const MON_A = {
  id: "m-a1",
  name: "alice billing api",
  target_url: "https://a.example.com",
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
const MON_B = { ...MON_A, id: "m-b1", name: "bob storefront", target_url: "https://b.example.com" };

async function twoUserFixture(page: Page, opts?: { aIsAdmin?: boolean }) {
  let currentUser: typeof USER_A | null = null;
  await page.route(
    (url) => url.pathname.startsWith("/api/"),
    (route) => {
      const p = new URL(route.request().url()).pathname;
      const m = route.request().method();
      if (p === "/api/auth/me") {
        return currentUser
          ? route.fulfill(json({ data: { user: currentUser, session_expires_at: "t" } }))
          : route.fulfill(json({ error: { code: "UNAUTHENTICATED", message: "none" }, request_id: "r" }, 401));
      }
      if (p === "/api/auth/csrf")
        return route.fulfill(json({ data: { csrf_token: "tok" } }));
      if (p === "/api/auth/login" && m === "POST") {
        const body = route.request().postDataJSON() as { email?: string };
        currentUser = body?.email === "bob@example.com" ? USER_B : USER_A;
        return route.fulfill(json({ data: { user: currentUser, session_expires_at: "t" } }));
      }
      if (p === "/api/auth/logout" && m === "POST") {
        currentUser = null;
        return route.fulfill(json({ data: {} }));
      }
      if (p === "/api/admin/overview")
        return currentUser === USER_A && opts?.aIsAdmin
          ? route.fulfill(json({ data: {} }))
          : route.fulfill(json({ error: { code: "FORBIDDEN", message: "no" }, request_id: "r" }, 403));
      if (p === "/api/dashboard/summary")
        return route.fulfill(json({ data: { monitors: 1, open_incidents: 0 } }));
      if (p === "/api/monitors")
        return route.fulfill(
          json({
            data: {
              items: currentUser === USER_B ? [MON_B] : [MON_A],
              has_more: false,
              next_cursor: null,
            },
          }),
        );
      return route.fulfill(json({}, 404));
    },
  );
}

test.describe("identity race boundaries", () => {
  test("alice's cached rows never appear after signing in as bob", async ({
    page,
  }) => {
    await twoUserFixture(page);
    // sign in as alice → her monitor is the only row
    await page.goto("/login");
    await page.getByLabel(/email/i).fill("alice@example.com");
    await page.getByLabel(/password/i).fill("pw");
    await page.getByRole("button", { name: /sign in/i }).click();
    await expect(page.getByText("alice billing api")).toBeVisible();
    await expect(page.getByText("alice@example.com")).toBeVisible();
    // sign out → sign in as bob → the cache must not leak alice's row
    await page.getByRole("button", { name: /sign out/i }).click();
    await page.getByLabel(/email/i).fill("bob@example.com");
    await page.getByLabel(/password/i).fill("pw");
    await page.getByRole("button", { name: /sign in/i }).click();
    await expect(page.getByText("bob storefront")).toBeVisible();
    await expect(page.getByText("alice billing api")).toHaveCount(0);
    await expect(page.getByText("bob@example.com")).toBeVisible();
    await expect(page.getByText("alice@example.com")).toHaveCount(0);
  });

  test("admin navigation is granted per identity, not cached across", async ({
    page,
  }) => {
    await twoUserFixture(page, { aIsAdmin: true });
    await page.goto("/login");
    await page.getByLabel(/email/i).fill("alice@example.com");
    await page.getByLabel(/password/i).fill("pw");
    await page.getByRole("button", { name: /sign in/i }).click();
    await expect(
      page.getByRole("navigation", { name: /administration/i }),
    ).toBeVisible();
    await page.getByRole("button", { name: /sign out/i }).click();
    await page.getByLabel(/email/i).fill("bob@example.com");
    await page.getByLabel(/password/i).fill("pw");
    await page.getByRole("button", { name: /sign in/i }).click();
    await expect(page.getByText("bob storefront")).toBeVisible();
    // bob has no platform:read — the probe ran again and denied
    await expect(
      page.getByRole("navigation", { name: /administration/i }),
    ).toHaveCount(0);
  });
});
