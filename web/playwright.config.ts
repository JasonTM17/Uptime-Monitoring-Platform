import { defineConfig, devices } from "@playwright/test";

// Shell-level smoke only: chromium, two viewports, the dev server.
export default defineConfig({
  testDir: "./e2e",
  timeout: 30_000,
  retries: 0,
  use: { baseURL: "http://localhost:5173" },
  webServer: {
    command: "npm run dev",
    url: "http://localhost:5173",
    // Acceptance (CI=1) must spawn its own dev server so the
    // E2E_API_TARGET proxy env applies; reusing a stale dev server
    // would silently proxy /api to the wrong upstream.
    reuseExistingServer: !process.env.CI,
    timeout: 60_000,
  },
  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"], viewport: { width: 1280, height: 800 } },
    },
    {
      name: "chromium-390",
      use: { ...devices["Desktop Chrome"], viewport: { width: 390, height: 800 } },
    },
  ],
});
