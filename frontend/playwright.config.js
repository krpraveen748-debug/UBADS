import { defineConfig } from "@playwright/test";

// Browser tests run against an isolated stack started by e2e/global-setup.js
// (own temp database, backend :8801, frontend :5801). They never use the real
// backend/database. Tracing, video and screenshots are OFF so typed
// credentials can never be captured into artifacts.
export default defineConfig({
  testDir: "./e2e",
  testMatch: /.*\.spec\.js/,
  globalSetup: "./e2e/global-setup.js",
  timeout: 60_000,
  expect: { timeout: 10_000 },
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: [["list"]],
  use: {
    baseURL: "http://127.0.0.1:5801",
    trace: "off",
    video: "off",
    screenshot: "off",
    headless: true,
  },
  projects: [{ name: "chromium", use: { browserName: "chromium" } }],
});
