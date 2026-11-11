// The web app's end-to-end suite (WEB-01). Headless only (docs/04 rule 17).
//
// Two modes, one set of specs:
//  - **mock** (default): `tools/serve-webapp.py` serves webapp/ and every page runs
//    with `?mock=1`, the in-memory fake of the API (webapp/mock.js).
//  - **real**: `OPENSEAL_E2E_BASE_URL=https://…` points at a running OpenSeal server
//    (the Compose deployment, Phase 2F); no web server is started and mock is off.
//    Specs that need something only the mock can hand them (a signing link, which the
//    real server emails) read it from the environment or skip, saying why.
//
// Copied in shape from OpenCalc's `tests/browser/playwright.config.mjs` at `b23c67c`
// (PROVENANCE.md): the run starts its own server and refuses one it did not start
// (OpenCalc's CI-025: a run that attached to another checkout's server tested that
// tree and passed), one worker, no retries, traces kept on failure.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { defineConfig, devices } from "@playwright/test";

const PORT = Number(process.env.OPENSEAL_E2E_PORT ?? 8131);
const REAL = process.env.OPENSEAL_E2E_BASE_URL || "";
const WEBAPP = path.resolve(fileURLToPath(new URL("..", import.meta.url)));

async function occupant(port) {
  try {
    const res = await fetch(`http://127.0.0.1:${port}/__openseal__`, { signal: AbortSignal.timeout(2000) });
    return res.ok ? await res.json() : {};
  } catch (err) {
    const code = err?.cause?.code ?? err?.code;
    if (code === "ECONNREFUSED" || code === "ECONNRESET") return null;
    return {};
  }
}

async function refuseForeignServer() {
  const who = await occupant(PORT);
  if (!who) return;
  const same = who.root && fs.existsSync(who.root) && fs.realpathSync(who.root) === fs.realpathSync(WEBAPP);
  throw new Error([
    "The e2e suite will not run against a server it did not start.",
    `  port ${PORT}: ${same ? `a serve-webapp.py left from an earlier run of this checkout (pid ${who.pid})` : who.root ? `another checkout's serve-webapp.py: ${who.root}` : "something else"}`,
    `Stop it, or pick a free port: OPENSEAL_E2E_PORT=${PORT + 100} npm test`,
  ].join("\n"));
}

if (!REAL && process.env.TEST_WORKER_INDEX === undefined && !process.argv.includes("--list")) {
  await refuseForeignServer();
}

// Extra Chromium flags for a constrained host (e.g. `--disable-gpu` where the GPU
// process cannot start); empty on CI.
const chromiumArgs = (process.env.OPENSEAL_E2E_CHROMIUM_ARGS || "").split(" ").filter(Boolean);
const chromiumChannel = process.env.OPENSEAL_E2E_CHROMIUM_CHANNEL || undefined; // e.g. "chromium" (new headless)
const chrome = { ...devices["Desktop Chrome"], channel: chromiumChannel, launchOptions: { args: chromiumArgs } };

const desktop = /(manage|signin-dashboard|send|keyboard|a11y|screens|empty-states|web02|redesign-screens|visual|docview|real-stack)\.spec\.mjs$/;
const signer = /(ceremony|decline|a11y-sign)\.spec\.mjs$/;

export default defineConfig({
  testDir: ".",
  timeout: 60_000,
  expect: { timeout: 10_000 },
  workers: 1,
  retries: 0,
  forbidOnly: !!process.env.CI,
  reporter: process.env.CI ? [["github"], ["list"]] : [["list"]],
  outputDir: "../../target/e2e-results",
  use: {
    baseURL: REAL || `http://127.0.0.1:${PORT}`,
    headless: true,
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
  },
  projects: [
    { name: "chromium", use: chrome },
    { name: "webkit", use: { ...devices["Desktop Safari"] } },
    { name: "mobile", testMatch: signer, use: { ...devices["iPhone 13"] } },
    { name: "reduced-motion", testMatch: /(send|ceremony)\.spec\.mjs$/, use: { ...chrome, contextOptions: { reducedMotion: "reduce" } } },
  ].map((p) => (p.testMatch ? p : { ...p, testMatch: [desktop, signer] })),
  webServer: REAL ? undefined : {
    command: `python3 -I ../../tools/serve-webapp.py ${PORT}`,
    url: `http://127.0.0.1:${PORT}/__openseal__`,
    reuseExistingServer: false,
    timeout: 30_000,
    stdout: "ignore",
    stderr: "pipe",
  },
});
