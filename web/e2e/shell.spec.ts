import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

// Shell-level smoke: semantic landmarks + axe at the project's two
// acceptance viewports — feature journeys land with their cards.
test.describe("app shell", () => {
  test("renders primary nav + heading", async ({ page }) => {
    await page.goto("/");
    await expect(
      page.getByRole("navigation", { name: "Primary" }),
    ).toBeVisible();
    await expect(
      page.getByRole("heading", { name: "Dashboard" }),
    ).toBeVisible();
  });

  test("passes axe", async ({ page }) => {
    await page.goto("/");
    const results = await new AxeBuilder({ page }).analyze();
    expect(results.violations).toEqual([]);
  });
});
