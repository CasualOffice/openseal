// The document-first editor and signing page (WEB-06, docs/47 §Layout spec): side
// panels resize by pointer and keyboard, collapse to a rail and are remembered; zoom
// keeps the place; only pages near the view are painted; and both views keep their
// rules (document share, one scroller, 12 px text floor) at 1280, 1440, 1920, 390 and
// at browser zoom 150 % and 200 % (a 1440×900 window at zoom z is a 1440/z × 900/z CSS
// viewport at device scale z, which is what Chromium does for Ctrl+Plus).
// Mock mode, Chromium: the mock's seeded envelope and signing link.
import { test, expect } from "@playwright/test";
import fs from "node:fs";
import path from "node:path";
import { signIn, app, signPage, tokens, REAL, SCREENS } from "./helpers.mjs";
import { makePdf } from "../mockpdf.js";

const longPdf = (n = 6) => ({
  name: "long.pdf", mimeType: "application/pdf",
  buffer: Buffer.from(makePdf(Array.from({ length: n }, (_, i) => ({ title: `Long contract, part ${i + 1}`, lines: ["Clause text for this page."] })))),
});

async function editorWithPages(page, { pdf = longPdf(), signedIn = false } = {}) {
  if (!signedIn) await signIn(page);
  await page.goto(app("#/prepare"));
  await page.getByTestId("pdf-input").setInputFiles(pdf);
  await page.getByTestId("wizard-next").click();
  await page.getByRole("button", { name: "Add recipient" }).first().click();
  await page.getByTestId("recipient-name").fill("Avery Chen");
  await page.getByTestId("recipient-email").fill("avery@example.com");
  await page.getByTestId("wizard-next").click();
  await expect(page.locator('[data-testid="editor-doc"] .os-page')).toHaveCount(6);
}

const rootPx = (page) => page.evaluate(() => Number.parseFloat(getComputedStyle(document.documentElement).fontSize));
const width = (loc) => loc.evaluate((el) => el.getBoundingClientRect().width);

test.describe("document view", () => {
  test.skip(({ browserName }) => REAL || browserName !== "chromium", "mock data, one browser");
  test.use({ viewport: { width: 1440, height: 900 } });

  test("panels resize by keyboard and pointer, collapse to a rail, and are remembered", async ({ page }) => {
    await editorWithPages(page);
    const panel = page.getByTestId("panel-fields");
    const handle = page.getByRole("separator", { name: "Resize Fields" });
    const px = await rootPx(page);
    await expect(handle).toHaveAttribute("aria-valuenow", "13.5");
    const w0 = await width(panel);
    await handle.focus();
    await page.keyboard.press("ArrowRight");
    await page.keyboard.press("ArrowRight");
    await expect(handle).toHaveAttribute("aria-valuenow", "15.5");
    expect(await width(panel)).toBeCloseTo(w0 + 2 * px, 0);
    await page.keyboard.press("End");
    await expect(handle).toHaveAttribute("aria-valuenow", "24");
    await page.keyboard.press("Home");
    await expect(handle).toHaveAttribute("aria-valuenow", "11");
    // Pointer: drag the inner edge 64 px to the right.
    const b = await handle.boundingBox();
    await page.mouse.move(b.x + b.width / 2, b.y + 200);
    await page.mouse.down();
    await page.mouse.move(b.x + b.width / 2 + 64, b.y + 200, { steps: 4 });
    await page.mouse.up();
    expect(Number(await handle.getAttribute("aria-valuenow"))).toBeCloseTo(11 + 64 / px, 0);
    // Collapse to the icon rail; the body leaves, the rail stays.
    await page.getByRole("button", { name: "Hide Fields" }).click();
    expect(await width(panel)).toBeCloseTo(3 * px, 0);
    await expect(page.locator(".os-palette")).toBeHidden();
    await expect(page.getByRole("button", { name: "Show Fields" })).toBeVisible();
    const saved = await page.evaluate(() => JSON.parse(localStorage.getItem("openseal.panel.editor-fields")));
    expect(saved.c).toBe(true);
    // Remembered: a new editor opens with the panel collapsed.
    await page.goto(app("#/agreements"));
    await page.getByRole("button", { name: "Leave without saving" }).click();
    await expect(page.getByRole("heading", { name: "Agreements" })).toBeVisible();
    await editorWithPages(page, { signedIn: true });
    await expect(page.getByRole("button", { name: "Show Fields" })).toBeVisible();
    await page.getByRole("button", { name: "Show Fields" }).click();
    await expect(page.locator(".os-palette")).toBeVisible();
  });

  test("zoom keeps the page in view, has presets and keys, and paints only nearby pages", async ({ page }) => {
    await editorWithPages(page);
    const doc = page.getByTestId("editor-doc");
    const sel = page.getByTestId("zoom-select");
    await expect(sel).toHaveValue("fit-width");
    // Only pages near the view are painted (A4).
    await expect.poll(() => doc.locator(".os-page > canvas").count()).toBeLessThan(6);
    // Go to page 4 by its thumbnail; the indicator follows.
    await page.locator(".os-thumb").nth(3).click();
    await expect(page.getByTestId("page-indicator")).toHaveText("Page 4 of 6");
    await expect(page.locator(".os-thumb").nth(3)).toHaveAttribute("aria-current", "page");
    // Keys zoom about the centre: still page 4.
    await doc.focus();
    await page.keyboard.press("Control+Equal");
    await expect(sel).not.toHaveValue("fit-width");
    await expect(page.getByTestId("page-indicator")).toHaveText("Page 4 of 6");
    await page.keyboard.press("Control+Minus");
    await page.keyboard.press("Control+Minus");
    await expect(page.getByTestId("page-indicator")).toHaveText("Page 4 of 6");
    await sel.selectOption("200");
    await expect(page.getByTestId("page-indicator")).toHaveText("Page 4 of 6");
    await expect.poll(() => doc.evaluate((el) => el.scrollWidth > el.clientWidth)).toBe(true);
    await sel.selectOption("fit-page");
    const fits = await doc.evaluate((el) => { const p = el.querySelector(".os-page").getBoundingClientRect(); return p.height <= el.clientHeight; });
    expect(fits).toBe(true);
    await page.keyboard.press("Control+0");
    await expect(sel).toHaveValue("fit-width");
    // Ctrl+wheel (a trackpad pinch) zooms at the pointer: the point under it stays put.
    const box = await doc.boundingBox();
    const at = { x: box.x + box.width / 2, y: box.y + box.height / 3 };
    const under = () => page.evaluate(({ x, y }) => {
      const el = document.elementsFromPoint(x, y).find((e) => e.classList.contains("os-page"));
      const r = el.getBoundingClientRect();
      return { n: el.dataset.index, fy: (y - r.top) / r.height };
    }, at);
    const before = await under();
    await page.mouse.move(at.x, at.y);
    await page.keyboard.down("Control");
    await page.mouse.wheel(0, -200);
    await page.keyboard.up("Control");
    await expect(sel).not.toHaveValue("fit-width");
    const after = await under();
    expect(after.n).toBe(before.n);
    expect(after.fy).toBeCloseTo(before.fy, 1);
  });
});

// Every size the owner asked for, both document views, with screenshots.
const SIZES = [
  ["1280", { width: 1280, height: 800 }, 1, "desktop"],
  ["1440", { width: 1440, height: 900 }, 1, "desktop"],
  ["1920", { width: 1920, height: 1080 }, 1, "desktop"],
  ["390", { width: 390, height: 844 }, 3, "phone"],
  ["1440-zoom150", { width: 960, height: 600 }, 1.5, "zoomed"],
  ["1440-zoom200", { width: 720, height: 450 }, 2, "zoomed"],
];
for (const [name, viewport, scale, kind] of SIZES) {
  test.describe(`document views at ${name}`, () => {
    test.skip(({ browserName }) => REAL || browserName !== "chromium", "mock data, one browser");
    test.use({ viewport, deviceScaleFactor: scale, hasTouch: kind === "phone" });

    test("editor and signer keep the document-first rules", async ({ page, context }) => {
      fs.mkdirSync(SCREENS, { recursive: true });
      const shotTo = (what) => page.screenshot({ path: path.join(SCREENS, `docview-${name}-${what}.png`), animations: "disabled" });
      const rules = (testId) => page.evaluate((id) => {
        const doc = document.querySelector(`[data-testid="${id}"]`);
        const scrolls = (el) => { const cs = getComputedStyle(el); return /(auto|scroll)/.test(`${cs.overflowY} ${cs.overflowX}`) && (el.scrollHeight > el.clientHeight + 1 || el.scrollWidth > el.clientWidth + 1); };
        const chain = [];
        for (let p = doc.querySelector(".os-page")?.parentElement; p; p = p.parentElement) if (scrolls(p)) chain.push(p === doc ? "document" : p.className);
        const se = document.scrollingElement;
        const small = [...document.querySelectorAll("body *")].filter((el) => !el.closest(".os-page__overlay, .os-sr-only, [hidden], [aria-hidden='true']")
          && [...el.childNodes].some((n) => n.nodeType === 3 && n.textContent.trim()) && el.getBoundingClientRect().width > 0
          && Number.parseFloat(getComputedStyle(el).fontSize) < 12).map((e) => e.className || e.tagName);
        return { share: doc.getBoundingClientRect().width / innerWidth, chain, rootScrolls: se.scrollHeight > se.clientHeight + 1, overflowX: se.scrollWidth > se.clientWidth + 1, small };
      }, testId);
      const expectRules = async (testId) => {
        const r = await rules(testId);
        if (kind === "desktop") expect(r.share, `${testId} share`).toBeGreaterThanOrEqual(0.65);
        expect(r.chain, `${testId} scrollers`).toEqual(["document"]);
        // Under 31.25em tall (200 % zoom here) the bars unpin and the page scrolls, by design (P-03).
        if (viewport.height >= 500) expect(r.rootScrolls, `${testId} page scrolls`).toBe(false);
        expect(r.overflowX, `${testId} horizontal overflow`).toBe(false);
        expect(r.small, `${testId} text under 12 px`).toEqual([]);
      };

      await editorWithPages(page);
      if (await page.getByTestId("add-field-sheet").isVisible()) await page.getByTestId("add-field-sheet").click();
      await page.locator(".os-palette").getByRole("button", { name: "Add Signature field" }).press("Enter");
      await expect(page.locator(".os-field")).toHaveCount(1);
      await expectRules("editor-doc");
      await shotTo("editor");

      await context.grantPermissions(["geolocation"]);
      await context.setGeolocation({ latitude: 52.37, longitude: 4.89 });
      await page.goto(signPage(tokens.sign));
      await page.getByLabel("Access code").fill(tokens.accessCode);
      await page.getByRole("button", { name: "Continue" }).click();
      await page.getByRole("button", { name: "Share my location" }).click();
      await page.getByLabel("I agree to use electronic records and signatures.").check();
      await page.getByRole("button", { name: "Continue" }).click();
      await expect(page.locator('[data-testid="signer-doc"] .os-page').first()).toBeVisible();
      await expectRules("signer-doc");
      await shotTo("signer");
      await page.getByRole("button", { name: /Signature, required/ }).click();
      await expect(page.getByRole("dialog", { name: "Adopt your signature" })).toBeVisible();
      await shotTo("signer-adopt");
    });
  });
}
