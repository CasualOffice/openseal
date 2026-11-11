// Visual QA (WEB-02 redesign, owner's rule 4): every screen at 1440×900 and 390×844,
// full-page screenshots under target/e2e-screens/visual-*, and on each screen:
//  - nothing overflows the viewport horizontally;
//  - no two visible interactive elements overlap;
//  - no visible control is an unstyled browser default (each has an os-* class);
//  - every PDF page canvas that should be painted is painted (pixels sampled).
// Mock mode: the screens need the mock's seeded data.
import { test, expect } from "@playwright/test";
import { signIn, app, signPage, tokens, pdfFile, REAL } from "./helpers.mjs";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const SHOTS = path.resolve(fileURLToPath(new URL("../../target/e2e-screens", import.meta.url)));
const ROOT = path.resolve(fileURLToPath(new URL("../..", import.meta.url)));
const WASM = fs.existsSync(path.join(ROOT, "webapp/vendor/openseal-wasm/casual_sign_wasm_bg.wasm"));

/// The layout rules, measured in the page.
async function checkLayout(page, what) {
  await page.waitForFunction(() => document.getAnimations().every((a) => a.playState !== "running" || a.effect?.getTiming().iterations === Infinity));
  const problems = await page.evaluate(() => {
    const out = [];
    const vw = document.documentElement.clientWidth;
    if (document.documentElement.scrollWidth > vw + 1) out.push(`horizontal overflow: ${document.documentElement.scrollWidth} > ${vw}`);
    const visible = (el) => {
      const r = el.getBoundingClientRect();
      if (r.width < 1 || r.height < 1) return null;
      const cs = getComputedStyle(el);
      if (cs.visibility === "hidden" || cs.display === "none" || Number(cs.opacity) === 0) return null;
      if (el.closest("[hidden], [aria-hidden='true'], .os-sr-only")) return null;
      // Clip by every scrolling or clipping ancestor: what is scrolled out of view is not shown.
      let box = { left: r.left, top: r.top, right: r.right, bottom: r.bottom };
      for (let p = el.parentElement; p && p !== document.body; p = p.parentElement) {
        const ps = getComputedStyle(p);
        if (ps.overflowX !== "visible" || ps.overflowY !== "visible") {
          const q = p.getBoundingClientRect();
          box = { left: Math.max(box.left, q.left), top: Math.max(box.top, q.top), right: Math.min(box.right, q.right), bottom: Math.min(box.bottom, q.bottom) };
          if (box.right - box.left < 1 || box.bottom - box.top < 1) return null;
        }
      }
      if (box.right <= 0 || box.left >= innerWidth) return null; // off-canvas (a closed drawer)
      return box;
    };
    const controls = [...document.querySelectorAll("button, a[href], input:not([type=hidden]):not([type=file]), select, textarea")]
      .map((el) => ({ el, r: visible(el) })).filter((x) => x.r);
    // Unstyled defaults: a control with no class of ours (checkboxes and radios inside our labels count as styled).
    for (const { el } of controls) {
      const styled = [...el.classList].some((c) => c.startsWith("os-")) || el.closest(".os-check, .os-radio, .os-switch, .os-adopt__font, .os-segmented, .os-sfield");
      if (!styled) out.push(`unstyled ${el.tagName.toLowerCase()}: ${(el.getAttribute("aria-label") || el.textContent || el.name || "").trim().slice(0, 40)}`);
    }
    // Overlaps between interactive elements that are not nested in each other.
    const skip = (el) => el.closest(".os-page__overlay, .os-menu, dialog:not([open])");
    const live = controls.filter((x) => !skip(x.el));
    for (let i = 0; i < live.length; i++) {
      for (let j = i + 1; j < live.length; j++) {
        const a = live[i]; const b = live[j];
        if (a.el.contains(b.el) || b.el.contains(a.el)) continue;
        if (a.el.closest("label") && a.el.closest("label") === b.el.closest("label")) continue;
        const w = Math.min(a.r.right, b.r.right) - Math.max(a.r.left, b.r.left);
        const hgt = Math.min(a.r.bottom, b.r.bottom) - Math.max(a.r.top, b.r.top);
        if (w > 2 && hgt > 2) out.push(`overlap: ${a.el.tagName}(${(a.el.getAttribute("aria-label") || a.el.textContent).trim().slice(0, 30)}) × ${b.el.tagName}(${(b.el.getAttribute("aria-label") || b.el.textContent).trim().slice(0, 30)})`);
      }
    }
    return out;
  });
  expect(problems, `layout on ${what}`).toEqual([]);
}

/// Every canvas under `scope` has drawn something other than white: PDF previews work.
async function expectPainted(page, selector, what) {
  await expect(page.locator(`${selector} canvas`).first()).toBeVisible();
  await page.waitForFunction((sel) => [...document.querySelectorAll(`${sel}`)].every((p) => !p.classList.contains("is-loading")), selector.split(" ")[0] + " .os-page");
  const blank = () => page.evaluate((sel) => [...document.querySelectorAll(`${sel} canvas`)].map((c) => {
    const ctx = c.getContext("2d");
    if (!c.width || !c.height) return true;
    const d = ctx.getImageData(0, 0, c.width, c.height).data;
    let ink = 0;
    for (let i = 0; i < d.length; i += 4 * 97) if (d[i + 3] > 0 && (d[i] < 200 || d[i + 1] < 200 || d[i + 2] < 200)) ink++;
    return ink < 3;
  }).filter(Boolean).length, selector);
  await expect.poll(blank, { message: `blank canvases on ${what}`, timeout: 10_000 }).toBe(0);
}

async function shot(page, name, viewport, fullPage = true) {
  fs.mkdirSync(SHOTS, { recursive: true });
  await page.evaluate(() => window.scrollTo(0, 0));
  await page.screenshot({ path: path.join(SHOTS, `visual-${viewport}-${name}.png`), fullPage, animations: "disabled" });
}

for (const [vp, size] of [["desktop", { width: 1440, height: 900 }], ["phone", { width: 390, height: 844 }]]) {
  test.describe(`visual ${vp}`, () => {
    test.use({ viewport: size });

    test("sender screens", async ({ page }, testInfo) => {
      test.skip(REAL || testInfo.project.name !== "chromium", "mock data, one browser");
      test.setTimeout(180_000);
      const check = async (name) => { await checkLayout(page, `${vp} ${name}`); await shot(page, name, vp); };
      await page.goto(app("#/signin"));
      await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();
      await check("01-signin");
      await signIn(page, "home");
      await expect(page.locator(".os-counters:not([aria-busy])")).toBeVisible();
      await expect(page.locator(".os-recent__item").first()).toBeVisible();
      await check("02-home");
      await page.goto(app("#/agreements"));
      await expect(page.locator(".os-row__sub").first()).not.toBeEmpty();
      await check("03-agreements");
      await page.getByRole("link", { name: "Mutual NDA — Acme and Globex" }).click();
      await expect(page.getByRole("heading", { name: "Audit trail" })).toBeVisible();
      await check("04-envelope-summary");
      await page.getByRole("tab", { name: "Documents" }).click();
      await expectPainted(page, ".os-preview__pages", "envelope documents");
      await check("05-envelope-documents");

      await page.goto(app("#/prepare"));
      await expect(page.getByTestId("empty-documents")).toBeVisible();
      await check("06-prepare-empty");
      await page.getByTestId("pdf-input").setInputFiles(pdfFile());
      await expectPainted(page, ".os-doccard__frame", "document card");
      await check("07-prepare-documents");
      await page.getByTestId("wizard-next").click();
      await page.getByRole("button", { name: "Add recipient" }).first().click();
      await page.getByTestId("recipient-name").fill("Avery Chen");
      await page.getByTestId("recipient-email").fill("avery@example.com");
      await page.getByRole("button", { name: "Add recipient" }).first().click();
      await page.getByTestId("recipient-name").nth(1).fill("Sam Patel");
      await page.getByTestId("recipient-email").nth(1).fill("sam@example.com");
      await check("08-prepare-recipients");
      await page.getByTestId("wizard-next").click();
      await expectPainted(page, ".os-stage", "editor pages");
      await page.locator(".os-palette").getByRole("button", { name: "Add Signature field" }).click();
      await page.getByLabel("Placing fields for").selectOption({ index: 1 });
      await page.locator(".os-palette").getByRole("button", { name: "Add Signature field" }).click();
      await check("09-prepare-fields");
      await page.getByTestId("wizard-next").click();
      await check("10-prepare-review");

      await page.goto(app("#/templates"));
      await expect(page.getByRole("link", { name: "Mutual NDA" })).toBeVisible();
      await check("11-templates");
      await page.getByRole("button", { name: "Use Mutual NDA" }).click();
      await expectPainted(page, ".os-preview__pages", "template preview");
      await check("12-template-use");
      await page.goto(app("#/reports"));
      await expect(page.locator(".os-bars")).toBeVisible();
      await check("13-reports");
      await page.goto(app("#/admin"));
      await expect(page.getByRole("cell", { name: "Robin Sender", exact: true })).toBeVisible();
      await check("14-admin-users");
      await page.getByRole("tab", { name: "API clients" }).click();
      await expect(page.getByText("CRM integration")).toBeVisible();
      await check("15-admin-api");
    });

    test("verify", async ({ page }, testInfo) => {
      test.skip(!WASM || testInfo.project.name !== "chromium", "needs the WASM verifier; one browser");
      await page.goto("/verify.html");
      await checkLayout(page, `${vp} verify start`);
      await shot(page, "16-verify-start", vp);
      await page.getByTestId("trust-input").setInputFiles(path.join(ROOT, "fixtures/sealed/trust-root.pem"));
      await page.getByTestId("verify-input").setInputFiles(path.join(ROOT, "fixtures/sealed/p256-approval-blt.pdf"));
      await expect(page.getByTestId("verdict")).toHaveAttribute("data-state", "valid");
      await expectPainted(page, ".os-preview__pages", "verify preview");
      await checkLayout(page, `${vp} verify result`);
      await shot(page, "17-verify-result", vp);
    });

    test("signer screens", async ({ page, context }, testInfo) => {
      test.skip(REAL || testInfo.project.name !== "chromium", "mock data, one browser");
      await context.grantPermissions(["geolocation"]);
      await context.setGeolocation({ latitude: 52.37, longitude: 4.89, accuracy: 25 });
      // The signing page has fixed bars: the shots show the viewport, as a signer sees it.
      const check = async (name) => { await checkLayout(page, `${vp} ${name}`); await shot(page, name, vp, false); };
      await page.goto(signPage(tokens.sign));
      await expect(page.getByRole("heading", { name: "Enter your access code" })).toBeVisible();
      await check("20-sign-code");
      await page.getByLabel("Access code").fill(tokens.accessCode);
      await page.getByRole("button", { name: "Continue" }).click();
      await page.getByRole("button", { name: "Share my location" }).click();
      await expect(page.getByRole("heading", { name: "Electronic records and signatures" })).toBeVisible();
      await check("21-sign-consent");
      await page.getByLabel("I agree to use electronic records and signatures.").check();
      await page.getByRole("button", { name: "Continue" }).click();
      await expectPainted(page, ".os-sign__pages", "signer pages");
      await check("22-sign-document");
      await page.getByRole("textbox", { name: /Job title/ }).fill("Engineer");
      await page.getByRole("textbox", { name: /Job title/ }).blur();
      await page.getByRole("button", { name: /Signature, required/ }).click();
      const dlg = page.getByRole("dialog", { name: "Adopt your signature" });
      await expect(dlg).toBeVisible();
      await checkLayout(page, `${vp} adopt`);
      await page.screenshot({ path: path.join(SHOTS, `visual-${vp}-23-sign-adopt.png`), animations: "disabled" });
      await dlg.getByTestId("adopt-confirm").click();
      await expect(dlg).toBeHidden();
      await page.getByRole("button", { name: "Finish" }).click();
      await expect(page.getByRole("heading", { name: "Review and finish" })).toBeVisible();
      await expectPainted(page, ".os-review__pages", "review pages");
      await check("24-sign-review");
      await page.getByTestId("review-finish").click();
      await expect(page.getByTestId("sign-done")).toBeVisible();
      await check("25-sign-done");
    });
  });
}
