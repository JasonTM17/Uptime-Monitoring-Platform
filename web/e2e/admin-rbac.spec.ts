import { expect, test, type Page } from "@playwright/test";
import { mockApi } from "./mock";

// MOCKED evidence — RBAC semantics proven against contract fixtures.
// A denied panel means "the grant is absent", never "the list is
// empty"; authorization truth stays server-side per route.

const json = (body: unknown, status = 200) => ({
  status,
  contentType: "application/json",
  body: JSON.stringify(body),
});

const err = (status: number, code: string, message: string) =>
  json({ error: { code, message, fields: null }, request_id: "r" }, status);

async function adminProbe(page: Page) {
  await page.route(
    (url) => url.pathname === "/api/admin/overview",
    (route) => route.fulfill(json({ data: {} })),
  );
}

test.describe("admin RBAC boundaries", () => {
  test("a non-admin sees a denied state and no admin navigation", async ({
    page,
  }) => {
    await mockApi(page); // default mock already denies the overview probe
    await page.goto("/");
    await expect(page.getByRole("heading", { name: /your monitors/i })).toBeVisible();
    await expect(page.getByRole("navigation", { name: /administration/i })).toHaveCount(0);
    // deep-linking an admin route lands on an explicit denial, not a page
    await page.goto("/admin/users");
    await expect(page.getByText(/access denied/i)).toBeVisible();
  });

  test("per-grant denial: roles page denied while the shell stays usable", async ({
    page,
  }) => {
    await mockApi(page);
    await adminProbe(page);
    await page.route(
      (url) => url.pathname === "/api/admin/roles",
      (route) => route.fulfill(err(403, "FORBIDDEN", "missing roles:read")),
    );
    await page.goto("/admin/roles");
    await expect(page.getByText(/doesn’t include/i)).toBeVisible();
    // denied ≠ empty: no "no roles yet" or dead table
    await expect(page.getByText(/no roles/i)).toHaveCount(0);
  });

  test("a quota conflict on user detail explains the stale state", async ({
    page,
  }) => {
    const TARGET = {
      id: "u-target",
      email: "target@example.com",
      display_name: "Target",
      status: "ACTIVE",
      monitor_limit: 5,
      monitors_live: 2,
      sessions_live: 0,
      roles: [],
      created_at: "2025-01-01T00:00:00Z",
      disabled_at: null,
      security_version: 1,
      version: 7,
    };
    await mockApi(page);
    await adminProbe(page);
    await page.route(
      (url) => url.pathname === "/api/admin/users/u-target",
      (route) => route.fulfill(json({ data: TARGET })),
    );
    await page.route(
      (url) => url.pathname === "/api/admin/users/u-target/quota",
      (route) => {
        if (route.request().method() === "PATCH")
          return route.fulfill(err(409, "CONFLICT", "version moved"));
        return route.fulfill(err(405, "METHOD_NOT_ALLOWED", "method"));
      },
    );
    await page.goto("/admin/users/u-target");
    await page.getByLabel(/new cap/i).fill("10");
    await page.getByRole("button", { name: /update…/i }).click();
    const dialog = page.getByRole("dialog");
    await dialog.getByLabel(/reason/i).fill("growth");
    await dialog.getByRole("button", { name: /set cap/i }).click();
    await expect(page.getByText(/changed since you loaded/i)).toBeVisible();
  });

  test("suspended user rows carry the SUSPENDED badge, not a ghost row", async ({
    page,
  }) => {
    const SUSPENDED = {
      id: "u-susp",
      email: "suspended@example.com",
      display_name: "Gone",
      status: "DISABLED",
      monitor_limit: 5,
      monitors_live: 0,
      sessions_live: 0,
      roles: [],
      created_at: "2025-01-01T00:00:00Z",
      disabled_at: "2025-01-02T00:00:00Z",
      security_version: 2,
      version: 9,
    };
    await mockApi(page);
    await adminProbe(page);
    await page.route(
      (url) => url.pathname === "/api/admin/users/u-susp",
      (route) => route.fulfill(json({ data: SUSPENDED })),
    );
    await page.goto("/admin/users/u-susp");
    await expect(page.getByText("suspended@example.com")).toBeVisible();
    await expect(page.getByText(/disabled|suspended/i).first()).toBeVisible();
    // restore affordance exists; no suspend button for a suspended user
    await expect(page.getByRole("button", { name: /restore/i })).toBeVisible();
    await expect(page.getByRole("button", { name: /suspend/i })).toHaveCount(0);
  });
});
