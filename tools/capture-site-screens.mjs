// Product screenshots for the website (SITE-01): the real web app in demo mode, driven
// by Playwright, in light and dark. Raw PNGs go to an output directory; then
// tools/build-site.py --screens turns them into site/assets/screens/*.webp and .png.
//
//   python3 -I tools/serve-webapp.py 8150 &            # the web app, demo mode
//   node tools/capture-site-screens.mjs [OUT] [BASE]   # OUT default target/site-screens
//
// Uses the e2e harness's Playwright (`cd webapp/e2e && npm ci`). Headless only. The
// demo-mode banner is hidden by a style injected here, never by the app. Steps follow
// webapp/e2e/visual.spec.mjs. Fails non-zero, naming the step, if a screen is missing.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const ROOT = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
const OUT = path.resolve(process.argv[2] || path.join(ROOT, "target/site-screens"));
const BASE = process.argv[3] || "http://127.0.0.1:8150";
const PW = path.join(ROOT, "webapp/e2e/node_modules/playwright/index.mjs");
if (!fs.existsSync(PW)) {
  console.error("capture-site-screens: Playwright is not installed; run `npm ci` in webapp/e2e");
  process.exit(1);
}
const { chromium } = await import(pathToFileURL(PW).href);
const { makePdf } = await import(pathToFileURL(path.join(ROOT, "webapp/mockpdf.js")).href);
const CERT = process.env.OPENSEAL_SITE_CERT_PDF || "";

fs.mkdirSync(OUT, { recursive: true });
const HIDE = "#mock-banner{display:none!important}";

function contractPdf() {
  const bytes = makePdf([
    { title: "Master services agreement", lines: ["Between Halden Logistics and Ferro Analytics.", "1. Services. 2. Fees. 3. Term and termination.", "4. Confidentiality. 5. Liability."] },
    { title: "Signatures", lines: ["Signed by the parties on the dates shown."] },
  ]);
  return { name: "services-agreement.pdf", mimeType: "application/pdf", buffer: Buffer.from(bytes) };
}

async function settle(page) {
  await page.waitForFunction(() => document.getAnimations().every((a) => a.playState !== "running" || a.effect?.getTiming().iterations === Infinity), null, { timeout: 15_000 });
  await page.waitForTimeout(250);
}

async function painted(page, selector) {
  await page.locator(`${selector} canvas`).first().waitFor({ state: "visible", timeout: 20_000 });
  await page.waitForFunction((sel) => [...document.querySelectorAll(`${sel} .os-page`)].every((p) => !p.classList.contains("is-loading")), selector, { timeout: 20_000 });
  await page.waitForTimeout(400);
}

async function run(scheme) {
  const browser = await chromium.launch({ headless: true });
  const shot = async (page, name, fullPage = false) => {
    await page.addStyleTag({ content: HIDE });
    await settle(page);
    await page.screenshot({ path: path.join(OUT, `${scheme}-${name}.png`), fullPage, animations: "disabled" });
    console.log(`  ${scheme}-${name}`);
  };
  const ctxFor = async (viewport, extra = {}) => {
    const ctx = await browser.newContext({ viewport, colorScheme: scheme, bypassCSP: true, ...extra }); // bypassCSP: only so the banner-hiding style applies
    await ctx.addInitScript(([s, css]) => {
      try { localStorage.setItem("openseal.theme", s); } catch { /* storage off */ }
      document.addEventListener("DOMContentLoaded", () => { const st = document.createElement("style"); st.textContent = css; document.head.append(st); });
    }, [scheme, HIDE]);
    return ctx;
  };

  // ---- Sender ------------------------------------------------------------------
  const desk = await ctxFor({ width: 1440, height: 900 });
  const page = await desk.newPage();
  await page.goto(`${BASE}/app.html?mock=1#/signin`);
  await page.getByLabel("Email").fill("demo@openseal.test");
  await page.getByLabel("Password").fill("openseal-demo-1");
  await page.getByRole("button", { name: "Sign in" }).click();
  await page.getByRole("heading", { name: "Home", exact: true }).waitFor();
  await page.locator(".os-counters:not([aria-busy])").waitFor();
  await page.locator(".os-recent__item").first().waitFor();
  await shot(page, "home");

  await page.goto(`${BASE}/app.html?mock=1#/agreements`);
  await page.locator(".os-row__sub").first().waitFor();
  await shot(page, "agreements");

  await page.getByRole("link", { name: "Mutual NDA — Acme and Globex" }).click();
  await page.getByRole("heading", { name: "Audit trail" }).waitFor();
  await shot(page, "envelope");

  await page.goto(`${BASE}/app.html?mock=1#/prepare`);
  await page.getByTestId("pdf-input").setInputFiles(contractPdf());
  await page.getByTestId("doc-card").first().waitFor();
  await page.getByTestId("wizard-next").click();
  await page.getByRole("button", { name: "Add recipient" }).first().click();
  await page.getByTestId("recipient-name").fill("Ilse Marten");
  await page.getByTestId("recipient-email").fill("ilse@halden.example");
  await page.getByRole("button", { name: "Add recipient" }).first().click();
  await page.getByTestId("recipient-name").nth(1).fill("Tomas Okafor");
  await page.getByTestId("recipient-email").nth(1).fill("tomas@ferro.example");
  await page.getByTestId("wizard-next").click();
  await painted(page, ".os-stage");
  const placing = (i) => page.getByRole("radiogroup", { name: "Placing fields for" }).getByRole("radio").nth(i).click();
  const add = (name) => page.locator(".os-palette").getByRole("button", { name: `Add ${name} field` }).click();
  await placing(0);
  await add("Signature"); await add("Date signed"); await add("Text");
  await placing(1);
  await add("Signature"); await add("Date signed");
  await page.mouse.click(5, 5);
  await shot(page, "editor");

  await page.goto(`${BASE}/app.html?mock=1#/templates`);
  const leave = page.getByRole("button", { name: "Leave without saving" });
  if (await leave.isVisible().catch(() => false)) await leave.click();
  await page.getByRole("link", { name: "Mutual NDA" }).waitFor();
  await shot(page, "templates");

  await page.goto(`${BASE}/app.html?mock=1#/admin`);
  await page.getByRole("cell", { name: "Robin Sender", exact: true }).waitFor();
  await page.getByRole("tab", { name: "API clients" }).click();
  await page.getByText("CRM integration").waitFor();
  await shot(page, "admin-api");

  // ---- Verify ----------------------------------------------------------------------
  await page.goto(`${BASE}/verify.html`);
  await page.getByTestId("trust-input").setInputFiles(path.join(ROOT, "fixtures/sealed/trust-root.pem"));
  await page.getByTestId("verify-input").setInputFiles(path.join(ROOT, "fixtures/sealed/p256-approval-blt.pdf"));
  await page.locator('[data-testid="verdict"][data-state="valid"]').waitFor({ timeout: 30_000 });
  await painted(page, ".os-preview__pages");
  await shot(page, "verify");

  // ---- Certificate of completion: page 1 drawn by the app's own pdf.js -------------
  if (CERT) {
    const b64 = fs.readFileSync(CERT).toString("base64");
    const png = await page.evaluate(async (data) => {
      const pdfjs = await import("./vendor/pdfjs/pdf.min.mjs");
      pdfjs.GlobalWorkerOptions.workerSrc = "./vendor/pdfjs/pdf.worker.min.mjs";
      const bytes = Uint8Array.from(atob(data), (c) => c.charCodeAt(0));
      const doc = await pdfjs.getDocument({ data: bytes, isEvalSupported: false, enableScripting: false, standardFontDataUrl: "./vendor/pdfjs/standard_fonts/", cMapUrl: "./vendor/pdfjs/cmaps/" }).promise;
      const p = await doc.getPage(1);
      const vp = p.getViewport({ scale: 2 });
      const c = document.createElement("canvas");
      c.width = vp.width; c.height = vp.height;
      await p.render({ canvasContext: c.getContext("2d"), viewport: vp }).promise;
      return c.toDataURL("image/png").split(",")[1];
    }, b64);
    fs.writeFileSync(path.join(OUT, `${scheme}-certificate.png`), Buffer.from(png, "base64"));
    console.log(`  ${scheme}-certificate`);
  }
  await desk.close();

  // ---- Signer: desktop and phone -----------------------------------------------------
  for (const [vp, size] of [["desktop", { width: 1440, height: 900 }], ["phone", { width: 390, height: 844 }]]) {
    const extra = vp === "phone" ? { deviceScaleFactor: 2 } : {};
    const ctx = await ctxFor(size, extra);
    await ctx.grantPermissions(["geolocation"]);
    await ctx.setGeolocation({ latitude: 52.37, longitude: 4.89, accuracy: 25 });
    const sp = await ctx.newPage();
    await sp.goto(`${BASE}/s/demo-sign?mock=1`);
    await sp.getByLabel("Access code").fill("2468");
    await sp.getByRole("button", { name: "Continue" }).click();
    await sp.getByRole("button", { name: "Share my location" }).click();
    await sp.getByLabel("I agree to use electronic records and signatures.").check();
    await sp.getByRole("button", { name: "Continue" }).click();
    await painted(sp, ".os-sign__pages");
    // The page opens scrolled to the first field; show the document from its top.
    await sp.locator('[data-testid="signer-doc"]').evaluate((el) => el.scrollTo(0, 0));
    await shot(sp, `sign-${vp}`);
    await sp.getByRole("button", { name: /Signature, required/ }).first().click();
    const dlg = sp.getByRole("dialog", { name: "Adopt your signature" });
    await dlg.waitFor();
    const typed = dlg.getByRole("textbox").first();
    if (await typed.isVisible().catch(() => false)) { await typed.fill("Jordan Rivera"); }
    await shot(sp, `adopt-${vp}`);
    if (vp === "desktop") {
      await dlg.getByTestId("adopt-confirm").click();
      await dlg.waitFor({ state: "hidden" });
      const title = sp.getByRole("textbox", { name: /Job title/ });
      if (await title.isVisible().catch(() => false)) { await title.fill("Head of People"); await title.blur(); }
      await sp.getByRole("button", { name: "Finish" }).click();
      await sp.getByRole("heading", { name: "Review and finish" }).waitFor();
      await painted(sp, ".os-review__pages");
      await sp.getByTestId("review-finish").click();
      await sp.getByTestId("sign-done").waitFor();
      await shot(sp, "sign-done");
    }
    await ctx.close();
  }
  await browser.close();
}

for (const scheme of ["light", "dark"]) {
  console.log(`capturing ${scheme}`);
  try {
    await run(scheme);
  } catch (err) {
    console.error(`capture-site-screens: ${scheme}: ${err.message.split("\n")[0]}`);
    process.exit(1);
  }
}
