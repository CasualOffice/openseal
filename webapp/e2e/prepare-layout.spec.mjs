// The prepare editor's layout and placement (UX-05, docs/47 §As built UX-05): the toolbar
// keeps Back and Next or Send on its first row at common laptop widths; an armed field
// type places a field where the page is clicked; the field kinds the ceremony fills can
// be placed and configured and come back from the server as set; recipients have the
// engine's ready types and their options; template mode says "Review and save".
// Screenshots at 1440 and 390 go to target/e2e-screens/.
import { test, expect } from "@playwright/test";
import { signIn, app, pdfFile, snap, expectAccessible, REAL, placingFor } from "./helpers.mjs";

test.skip(REAL, "reads the mock's stored envelope to check the round trip");

const mockDb = (page) => page.evaluate(() => JSON.parse(sessionStorage.getItem("openseal.mock.v1")));

async function step(page, name) {
  await page.locator(".os-stepper__btn", { hasText: name }).click();
  await expect(page.locator('.os-stepper__btn[aria-current="step"]')).toContainText(name);
}

/// A new envelope with one document and the people given, on the fields step.
async function toFields(page, people = [["Ana Signer", "ana@example.com"]], { wide = false } = {}) {
  if (wide) await widen(page);
  await signIn(page);
  await page.goto(app("#/prepare"));
  await page.getByTestId("pdf-input").setInputFiles(pdfFile());
  await expect(page.getByTestId("doc-card")).toHaveCount(1);
  await page.getByTestId("wizard-next").click();
  for (const [i, [name, email]] of people.entries()) {
    await page.getByRole("button", { name: "Add recipient" }).first().click();
    const row = page.locator(".os-rcpt").nth(i);
    await row.getByTestId("recipient-name").fill(name);
    await row.getByTestId("recipient-email").fill(email);
    await row.getByTestId("recipient-email").blur();
  }
  await page.getByTestId("wizard-next").click();
  await expect(page.locator(".os-page")).toHaveCount(2);
  await expect(page.locator(".os-page.is-loading")).toHaveCount(0);
}

/// The system's own font in place of the web font, as when a network or a policy blocks
/// the font file: the Linux fallback (DejaVu Sans) is wider than Inter, as a longer
/// translation would be, and is how the audit's screens (UX-01) saw the bar wrap at
/// 1440. Called before the first navigation.
const widen = (page) => page.route(/\/fonts\//, (route) => route.abort());

/// Whether `btn` sits on the toolbar's first row: its vertical centre is the back link's,
/// and the bar is one row high.
async function onFirstRow(page, btn) {
  const bar = await page.locator(".os-prepare__bar").boundingBox();
  const back = await page.locator(".os-prepare__bar > a").first().boundingBox();
  const b = await btn.boundingBox();
  const mid = (r) => r.y + r.height / 2;
  // Inside the window too: a bar wider than the window (a nowrap bar that could not
  // shrink) pushes the button off screen while it still "fits" the bar.
  const vw = page.viewportSize().width;
  const scrolls = await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth);
  return { same: Math.abs(mid(b) - mid(back)) <= 2, barHeight: Math.round(bar.height), inside: b.x + b.width <= Math.min(bar.x + bar.width, vw) + 0.5 && !scrolls };
}

for (const [width, wide] of [1366, 1440, 1536].flatMap((w) => [[w, false], [w, true]])) {
  test(`at ${width} px${wide ? " in the system font" : ""} Back and Next, then Send, stay on the toolbar's first row`, async ({ page }, testInfo) => {
    await page.setViewportSize({ width, height: 900 });
    await toFields(page, undefined, { wide });
    // The fullest bar: a saved draft (its subject as the title, "Saved at …"), on the
    // fields step with its document tools.
    await page.locator(".os-palette").getByRole("button", { name: "Add Signature field" }).press("Enter");
    await page.getByTestId("save-draft").click();
    await expect(page.getByTestId("save-status")).toContainText("Saved");
    await expect(page.locator(".os-prepare__title")).toHaveText("Please sign: contract");
    for (const [name, btn] of [["fields next", page.getByTestId("wizard-next")], ["fields back", page.getByTestId("wizard-back")], ["save", page.getByTestId("save-draft")]]) {
      const r = await onFirstRow(page, btn);
      expect(r, `${name} at ${width}`).toEqual({ same: true, barHeight: r.barHeight, inside: true });
      expect(r.barHeight, `bar height at ${width}`).toBeLessThan(72);
    }
    if (width === 1440) await snap(page, testInfo, `prepare-fields-bar-1440${wide ? "-system-font" : ""}`);
    await step(page, "Review");
    const send = page.getByRole("button", { name: "Send", exact: true });
    const r = await onFirstRow(page, send);
    expect(r, `send at ${width}`).toEqual({ same: true, barHeight: r.barHeight, inside: true });
    expect(r.barHeight).toBeLessThan(72);
    if (width === 1440) await snap(page, testInfo, `prepare-review-1440${wide ? "-system-font" : ""}`);
  });
}

for (const width of [1366, 1440, 1536]) {
  test(`at ${width} px in the system font a template's toolbar keeps Back, Next and Save template on its first row`, async ({ page }, testInfo) => {
    await page.setViewportSize({ width, height: 900 });
    await widen(page);
    await signIn(page);
    await page.goto(app("#/templates/new"));
    await page.getByTestId("pdf-input").setInputFiles(pdfFile("master-services-agreement-2026.pdf"));
    await expect(page.getByTestId("doc-card")).toHaveCount(1);
    await page.getByTestId("wizard-next").click();
    await page.getByRole("button", { name: "Add role" }).first().click();
    await page.getByTestId("role-name").first().fill("Client");
    await page.getByTestId("wizard-next").click();
    await expect(page.locator(".os-page.is-loading")).toHaveCount(0);
    await page.locator(".os-palette").getByRole("button", { name: "Add Signature field" }).press("Enter");
    for (const btn of [page.getByTestId("wizard-next"), page.getByTestId("wizard-back")]) {
      const r = await onFirstRow(page, btn);
      expect(r, `template fields at ${width}`).toEqual({ same: true, barHeight: r.barHeight, inside: true });
      expect(r.barHeight).toBeLessThan(72);
    }
    if (width === 1440) await snap(page, testInfo, "prepare-template-bar-1440");
    await page.getByTestId("wizard-next").click();
    const save = page.getByRole("button", { name: "Save template" });
    const r = await onFirstRow(page, save);
    expect(r, `template review at ${width}`).toEqual({ same: true, barHeight: r.barHeight, inside: true });
  });
}
