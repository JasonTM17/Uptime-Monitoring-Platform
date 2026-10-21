import { expect, test } from "@playwright/test";
import { mockApi } from "./mock";

const VERIFIED = {
  id: "c-1",
  label: "on-call",
  kind: "TELEGRAM",
  status: "VERIFIED",
  enabled: true,
  destination_mask: "•••5123",
  verified_at: "2025-01-01T00:00:00Z",
  version: 2,
  created_at: "2025-01-01T00:00:00Z",
  updated_at: "2025-01-01T00:00:00Z",
};
const PENDING = {
  ...VERIFIED,
  id: "c-2",
  label: "new-ch",
  status: "PENDING_VERIFICATION",
  enabled: true,
  destination_mask: null,
  verified_at: null,
  version: 1,
};

test.describe("channels page", () => {
  test("renders lifecycle states and only verified+enabled rows can test", async ({
    page,
  }) => {
    await mockApi(page, [VERIFIED, PENDING]);
    await page.route(
      (url) => url.pathname === "/api/monitors" || url.pathname.startsWith("/api/monitors?"),
      (route) =>
        route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify({
            data: {
              items: [{ id: "m-1", name: "site" }],
              has_more: false,
              next_cursor: null,
            },
          }),
        }),
    );
    await page.goto("/channels");

    await expect(page.getByText("on-call")).toBeVisible();
    await expect(page.getByText("verified", { exact: true })).toBeVisible();
    await expect(page.getByText("pending verification")).toBeVisible();
    await expect(page.getByText("•••5123")).toBeVisible();

    // only the verified row offers test-send
    await expect(
      page.getByRole("button", { name: /send test/i }),
    ).toHaveCount(1);
    await expect(
      page.getByText(/awaiting operator verification/i),
    ).toBeVisible();
  });

  test("empty state is honest", async ({ page }) => {
    await mockApi(page, []);
    await page.goto("/channels");
    await expect(
      page.getByText(/no channels yet/i),
    ).toBeVisible();
    await expect(page.getByLabel(/channel label/i)).toBeVisible();
  });
});
