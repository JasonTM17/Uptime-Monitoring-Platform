import { expect, test } from "@playwright/test";
import { mockApi } from "./mock";

const CATALOG = {
  catalog: [
    { id: "platform:read", requires: [] },
    { id: "users:read", requires: [] },
    { id: "users:manage", requires: ["users:read"] },
  ],
  roles: [
    { id: "r-1", code: "SUPER_ADMIN", name: "Super", is_preset: true, version: 1, permissions: ["platform:read", "users:read", "users:manage"] },
    { id: "r-2", code: "AUDIT_READER", name: "Audit reader", is_preset: false, version: 2, permissions: ["platform:read"] },
  ],
  delegation_ceiling: ["platform:read", "users:read"],
};

async function adminProbe(page: import("@playwright/test").Page) {
  await page.route(
    (url) => url.pathname === "/api/admin/overview",
    (route) =>
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ data: {} }),
      }),
  );
}

test.describe("admin roles page", () => {
  test("catalog, ceiling and preset immutability render; over-ceiling is blocked", async ({
    page,
  }) => {
    await mockApi(page);
    await adminProbe(page);
    await page.route(
      (url) => url.pathname === "/api/admin/roles",
      (route) =>
        route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify({ data: CATALOG }),
        }),
    );
    await page.goto("/admin/roles");

    await expect(page.getByText("SUPER_ADMIN")).toBeVisible();
    await expect(page.getByText("preset").first()).toBeVisible();
    // custom role is editable
    await page.getByRole("button", { name: /edit/i }).click();
    // users:manage is over the ceiling — grant checkbox disabled
    await expect(
      page.getByRole("checkbox", { name: /grant users:manage/i }),
    ).toBeDisabled();
    // keyboard: toggle users:read on the custom role
    const grant = page.getByRole("checkbox", { name: /grant users:read/i });
    await grant.focus();
    await page.keyboard.press(" ");
    await expect(grant).toBeChecked();
    // Escape closes nothing here; Cancel exits the editor
    await page.keyboard.press("Escape");
    await page.getByRole("button", { name: /^cancel$/i }).click();
    await expect(
      page.getByRole("button", { name: /new custom role/i }),
    ).toBeVisible();
  });

  test("a 409 on submit is explained, not silently retried", async ({ page }) => {
    await mockApi(page);
    await adminProbe(page);
    await page.route(
      (url) => url.pathname.startsWith("/api/admin/roles"),
      (route) => {
        if (route.request().method() === "PATCH") {
          return route.fulfill({
            status: 409,
            contentType: "application/json",
            body: JSON.stringify({
              error: { code: "CONFLICT", message: "stale version" },
              request_id: "r",
            }),
          });
        }
        return route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify({ data: CATALOG }),
        });
      },
    );
    await page.goto("/admin/roles");
    await page.getByRole("button", { name: /edit/i }).click();
    await page.getByRole("button", { name: /update…/i }).click();
    // reason + confirm dialog
    await page.getByLabel(/reason/i).fill("adjusting grants");
    await page.getByRole("button", { name: /update role/i }).click();
    await expect(page.getByText(/changed since you loaded/i)).toBeVisible();
  });
});
