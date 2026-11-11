// Scratch driver (not a spec): screenshots of the editor and the signer at the sizes
// WEB-06 is checked at, real browser zoom reproduced as a smaller CSS viewport at a
// higher device scale (what Chromium does for Ctrl+Plus). Usage: node .shots.mjs OUT [filter]
import { chromium } from "@playwright/test";
import fs from "node:fs";
import path from "node:path";
import { MOCK } from "../mock.js";
import { makePdf } from "../mockpdf.js";

const BASE = process.env.BASE || "http://127.0.0.1:8391";
const OUT = process.argv[2];
const only = process.argv[3] || "";
fs.mkdirSync(OUT, { recursive: true });
const pdf = { name: "contract.pdf", mimeType: "application/pdf", buffer: Buffer.from(makePdf([1, 2, 3, 4, 5, 6].map((n) => ({ title: `Services contract, part ${n}`, lines: ["This contract is between the parties below.", "1. Services. 2. Fees. 3. Term."] })))) };

const SIZES = [
  ["1280", 1280, 800, 1], ["1440", 1440, 900, 1], ["1920", 1920, 1080, 1], ["390", 390, 844, 3],
  ["1440z150", 960, 600, 1.5], ["1440z200", 720, 450, 2],
];

const browser = await chromium.launch();
for (const [name, w, hgt, dpr] of SIZES) {
  if (only && !name.startsWith(only)) continue;
  const ctx = await browser.newContext({ viewport: { width: w, height: hgt }, deviceScaleFactor: dpr, hasTouch: name === "390", isMobile: name === "390" });
  await ctx.grantPermissions(["geolocation"]);
  await ctx.setGeolocation({ latitude: 52.37, longitude: 4.89 });
  const page = await ctx.newPage();
  const errors = [];
  page.on("pageerror", (e) => errors.push(String(e)));
  page.on("console", (m) => { if (m.type() === "error") errors.push(m.text()); });
  // Editor
  await page.goto(`${BASE}/app.html?mock=1#/signin`);
  await page.getByLabel("Email").fill(MOCK.email);
  await page.getByLabel("Password").fill(MOCK.password);
  await page.getByRole("button", { name: "Sign in" }).click();
  await page.getByRole("heading", { name: "Home", exact: true }).waitFor();
  await page.goto(`${BASE}/app.html?mock=1#/prepare`);
  await page.getByTestId("pdf-input").setInputFiles(pdf);
  await page.getByTestId("wizard-next").click();
  await page.getByRole("button", { name: /Add recipient/ }).first().click();
  await page.getByTestId("recipient-name").fill("Avery Chen");
  await page.getByTestId("recipient-email").fill("avery@example.com");
  await page.getByRole("button", { name: /Add recipient/ }).first().click();
  await page.getByTestId("recipient-name").nth(1).fill("Sam Patel");
  await page.getByTestId("recipient-email").nth(1).fill("sam@example.com");
  await page.screenshot({ path: path.join(OUT, `${name}-editor-recipients.png`) });
  await page.getByTestId("wizard-next").click();
  await page.waitForTimeout(600);
  const pal = page.locator(".os-palette");
  if (await pal.isVisible()) {
    await pal.getByRole("button", { name: "Add Signature field" }).click();
    await pal.getByRole("button", { name: "Add Date signed field" }).click();
  } else {
    await page.getByTestId("add-field-sheet").click();
    await pal.getByRole("button", { name: "Add Signature field" }).click();
  }
  await page.waitForTimeout(500);
  await page.screenshot({ path: path.join(OUT, `${name}-editor-fields.png`) });
  const m = await page.evaluate(() => {
    const s = document.querySelector("[data-testid=editor-doc]");
    const r = s?.getBoundingClientRect();
    return { docW: r?.width, docH: r?.height, vw: innerWidth, vh: innerHeight, pageScroll: document.scrollingElement.scrollHeight - innerHeight };
  });
  console.log(name, "editor", JSON.stringify(m));
  await page.getByTestId("wizard-next").click();
  await page.screenshot({ path: path.join(OUT, `${name}-editor-review.png`) });
  // Signer
  page.removeAllListeners?.("dialog");
  await page.goto(`${BASE}/s/${MOCK.ceremonyToken}?mock=1`);
  await page.getByLabel("Access code").fill(MOCK.accessCode);
  await page.getByRole("button", { name: "Continue" }).click();
  await page.getByRole("button", { name: "Share my location" }).click();
  await page.getByLabel("I agree to use electronic records and signatures.").check();
  await page.getByRole("button", { name: "Continue" }).click();
  await page.waitForTimeout(1200);
  await page.screenshot({ path: path.join(OUT, `${name}-signer-doc.png`) });
  const s = await page.evaluate(() => {
    const d = document.querySelector("[data-testid=signer-doc]");
    const r = d?.getBoundingClientRect();
    return { docW: r?.width, docH: r?.height, vw: innerWidth, vh: innerHeight, pageScroll: document.scrollingElement.scrollHeight - innerHeight };
  });
  console.log(name, "signer", JSON.stringify(s));
  const sig = page.getByRole("button", { name: /Signature, required/ });
  if (await sig.count()) {
    await sig.first().click();
    await page.waitForTimeout(500);
    await page.screenshot({ path: path.join(OUT, `${name}-signer-adopt.png`) });
  }
  if (errors.length) console.log(name, "ERRORS", errors.slice(0, 5));
  await ctx.close();
}
await browser.close();
