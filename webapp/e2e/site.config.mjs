// The website's end-to-end checks (SITE-03, SITE-04): the published tree
// (tools/build-site.py --publish, served by tools/serve-site.py), so the Verify page and
// the demo copy of the app run exactly as GitHub Pages serves them. Headless only
// (docs/04 rule 17). Run from webapp/e2e:
//
//   npx playwright test -c site.config.mjs                  # port 8167, or OPENSEAL_SITE_E2E_PORT
//
// The verifier needs webapp/vendor/openseal-wasm/ (tools/build-webapp-wasm.sh); without
// it the Verify specs skip and say why. Refuses a server it did not start, as
// playwright.config.mjs does.

import path from "node:path";
import { fileURLToPath } from "node:url";

import { defineConfig, devices } from "@playwright/test";

const PORT = Number(process.env.OPENSEAL_SITE_E2E_PORT ?? 8167);
const REPO = path.resolve(fileURLToPath(new URL("../..", import.meta.url)));

async function refuseForeignServer() {
  try {
    const res = await fetch(`http://127.0.0.1:${PORT}/__openseal_site__`, { signal: AbortSignal.timeout(2000) });
    const who = res.ok ? await res.json() : {};
    throw new Error(`The site e2e will not run against a server it did not start: port ${PORT} is taken (${who.root || "something else"}). Pick another: OPENSEAL_SITE_E2E_PORT=${PORT + 100}`);
  } catch (err) {
    const code = err?.cause?.code ?? err?.code;
    if (code === "ECONNREFUSED" || code === "ECONNRESET") return;
    throw err;
  }
}

if (process.env.TEST_WORKER_INDEX === undefined && !process.argv.includes("--list")) await refuseForeignServer();

const chromiumArgs = (process.env.OPENSEAL_E2E_CHROMIUM_ARGS || "").split(" ").filter(Boolean);
const chromiumChannel = process.env.OPENSEAL_E2E_CHROMIUM_CHANNEL || undefined;

export default defineConfig({
  testDir: ".",
  testMatch: /(^|[\\/])site\.spec\.mjs$/,
  timeout: 60_000,
  expect: { timeout: 10_000 },
  workers: 1,
  retries: 0,
  forbidOnly: !!process.env.CI,
  reporter: process.env.CI ? [["github"], ["list"]] : [["list"]],
  outputDir: "../../target/site-e2e-results",
  use: { baseURL: `http://127.0.0.1:${PORT}`, headless: true, trace: "retain-on-failure", screenshot: "only-on-failure" },
  projects: [
    { name: "chromium", use: { ...devices["Desktop Chrome"], channel: chromiumChannel, launchOptions: { args: chromiumArgs } } },
  ],
  webServer: {
    command: `python3 -I ${path.join(REPO, "tools/serve-site.py")} ${PORT}`,
    url: `http://127.0.0.1:${PORT}/__openseal_site__`,
    reuseExistingServer: false,
    timeout: 60_000,
    stdout: "ignore",
    stderr: "pipe",
  },
});
