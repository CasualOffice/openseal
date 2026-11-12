// Browser tests of the platform console UI (CON-17). Headless only (docs/04 rule 17).
//
// The run starts a real console (serve.sh: fresh database, every migration, the
// console's own LOGIN role, a bootstrapped platform owner) and refuses a port someone
// else holds. Needs OPENSEAL_TEST_DATABASE_URL and CONSOLE_BIN; SHOTS names a folder
// for screenshots of every screen at 1440 and 390 wide (optional).

import path from "node:path";
import os from "node:os";
import { fileURLToPath } from "node:url";

import { defineConfig, devices } from "@playwright/test";

const PORT = Number(process.env.CONSOLE_PORT ?? 8191);
const HERE = path.dirname(fileURLToPath(import.meta.url));
const STATE = process.env.STATE_DIR || path.join(os.tmpdir(), `openseal-console-ui-${process.pid}`);
process.env.STATE_DIR = STATE;

export default defineConfig({
  testDir: HERE,
  testMatch: /.*\.spec\.mjs$/,
  timeout: 240_000,
  workers: 1,
  retries: 0,
  reporter: [["list"]],
  use: {
    baseURL: `http://127.0.0.1:${PORT}`,
    headless: true,
    trace: "retain-on-failure",
    reducedMotion: "reduce",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
  webServer: {
    command: `bash ${path.join(HERE, "serve.sh")}`,
    url: `http://127.0.0.1:${PORT}/livez`,
    reuseExistingServer: false,
    timeout: 120_000,
    env: { ...process.env, CONSOLE_PORT: String(PORT), STATE_DIR: STATE },
  },
});
