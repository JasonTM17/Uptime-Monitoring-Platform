import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

// Shell-level smoke: with no backend running the session resolves
// anonymous and "/" redirects to sign-in. Authenticated journeys need
// a live API and land with their feature cards.
test.describe("app shell", () => {
  test("anonymous visitor reaches the sign-in screen", async ({ page }) => {
    await page.goto("/");
    await expect(
      page.getByRole("heading", { name: "Sign in" }),
    ).toBeVisible();
    await expect(page.getByLabel(/email/i)).toBeVisible();
  });

  test("unknown routes render a semantic fallback", async ({ page }) => {
    await page.goto("/no-such-route");
    await expect(
      page.getByRole("heading", { name: "Page not found" }),
    ).toBeVisible();
  });

  test("passes axe", async ({ page }) => {
    await page.goto("/login");
    const results = await new AxeBuilder({ page }).analyze();
    expect(results.violations).toEqual([]);
  });
});
