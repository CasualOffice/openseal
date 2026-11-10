// Shared steps for the e2e specs (WEB-01). Every spec runs in mock mode by default and
// against a real server when OPENSEAL_E2E_BASE_URL is set (playwright.config.mjs).

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { expect } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";

import { MOCK } from "../mock.js";
import { makePdf } from "../mockpdf.js";

export const REAL = !!process.env.OPENSEAL_E2E_BASE_URL;
const q = REAL ? "" : "?mock=1";

/// Where screenshots for people go (not baselines): target/e2e-screens/.
export const SCREENS = path.resolve(fileURLToPath(new URL("../../target/e2e-screens", import.meta.url)));

export const creds = REAL
  ? { email: process.env.OPENSEAL_E2E_EMAIL || "", password: process.env.OPENSEAL_E2E_PASSWORD || "" }
  : { email: MOCK.email, password: MOCK.password };

/// The signing tokens: the mock's seeded ones, or what a real run provides.
export const tokens = REAL
  ? { sign: process.env.OPENSEAL_E2E_SIGN_TOKEN || "", decline: process.env.OPENSEAL_E2E_DECLINE_TOKEN || "", accessCode: process.env.OPENSEAL_E2E_ACCESS_CODE || "" }
  : { sign: MOCK.ceremonyToken, decline: MOCK.declineToken, accessCode: MOCK.accessCode };

export const app = (hash = "#/agreements") => `/app.html${q}${hash}`;
export const signPage = (token) => `/s/${encodeURIComponent(token)}${q}`;

export async function signIn(page) {
  if (REAL && !creds.email) throw new Error("OPENSEAL_E2E_EMAIL and OPENSEAL_E2E_PASSWORD are needed against a real server");
  await page.goto(app("#/signin"));
  await page.getByLabel("Email").fill(creds.email);
  await page.getByLabel("Password").fill(creds.password);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByRole("heading", { name: "Agreements" })).toBeVisible();
}

/// A small PDF made on the spot (two pages), as a file for `setInputFiles`.
export function pdfFile(name = "contract.pdf", title = "Services contract") {
  const bytes = makePdf([
    { title, lines: ["This contract is between the parties below.", "1. Services. 2. Fees. 3. Term."] },
    { title: `${title} (signatures)`, lines: ["Signed by the parties on the dates shown."] },
  ]);
  return { name, mimeType: "application/pdf", buffer: Buffer.from(bytes) };
}

/// Zero serious or critical axe violations (WCAG 2.2 A and AA rules).
export async function expectAccessible(page, what) {
  const results = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"]).analyze();
  const bad = results.violations.filter((v) => v.impact === "serious" || v.impact === "critical");
  const summary = bad.map((v) => `${v.id} (${v.impact}): ${v.nodes.length} × ${v.nodes.slice(0, 3).map((n) => n.target.join(" ")).join(", ")}`);
  expect(summary, `axe on ${what}`).toEqual([]);
}

/// Save a screenshot for people to look at (the visual check), and attach it.
export async function snap(target, testInfo, name) {
  fs.mkdirSync(SCREENS, { recursive: true });
  const file = path.join(SCREENS, `${testInfo.project.name}-${name}.png`);
  await target.screenshot({ path: file, animations: "disabled" });
  await testInfo.attach(name, { path: file, contentType: "image/png" });
  return file;
}

/// Press Tab until `locator` has focus (keyboard-only tests), at most `max` times.
export async function tabTo(page, locator, max = 80, shift = false) {
  for (let i = 0; i < max; i++) {
    if (await locator.evaluate((el) => el === document.activeElement).catch(() => false)) return;
    await page.keyboard.press(shift ? "Shift+Tab" : "Tab");
  }
  throw new Error(`could not reach ${locator} with Tab`);
}
