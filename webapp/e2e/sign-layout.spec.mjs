// The signer ceremony package of the UX audit (UX-06; docs/47 §As built UX-06): fit
// width fits beside the field list at every desktop width, the sender is named before
// the signer agrees, a placed signature can be removed or changed (a new audit event),
// the view opens at the top of page 1, choices are picked on the page, review on a
// phone shows the document first, and the end screens say what is true.
// Mock data: the seeded envelopes (helpers.mjs, mock.js).
import fs from "node:fs";
import path from "node:path";
import { test, expect } from "@playwright/test";
import { signPage, tokens, REAL, SCREENS } from "./helpers.mjs";
import { MOCK } from "../mock.js";

test.skip(REAL, "uses the mock's seeded envelopes, sender and disclosure");

/// Wait until nothing on the page is animating (a sheet sliding in, a menu fading in).
const settled = (page) => expect.poll(() => page.evaluate(() => document.getAnimations().filter((a) => a.playState === "running" && a.effect?.getTiming().iterations !== Infinity).length)).toBe(0);

const shot = async (page, name) => {
  await settled(page);
  fs.mkdirSync(path.join(SCREENS, "ux06"), { recursive: true });
  await page.screenshot({ path: path.join(SCREENS, "ux06", `${name}.png`) });
};

/// Access code, no location, to the consent card.
async function toConsent(page) {
  await page.goto(signPage(tokens.sign));
  await page.getByLabel("Access code").fill(tokens.accessCode);
  await page.getByLabel("Access code").press("Enter");
  await page.getByRole("button", { name: "Don't share" }).click();
  await expect(page.getByRole("heading", { name: "Electronic records and signatures" })).toBeVisible();
}

async function toDocuments(page) {
  await toConsent(page);
  await page.getByLabel("I agree to use electronic records and signatures.").check();
  await page.getByRole("button", { name: "Continue" }).click();
  await expect(page.locator(".os-page canvas").first()).toBeVisible();
  await expect(page.locator(".os-page.is-loading")).toHaveCount(0);
}

/// The document scroller's widths: a page wider than its scroller scrolls sideways.
const widths = (page, testId) => page.getByTestId(testId).evaluate((el) => ({ client: el.clientWidth, scroll: el.scrollWidth }));

/// Adopt a typed signature (and initials) from the open adopt panel.
async function adoptTyped(page) {
  const dlg = page.getByRole("dialog", { name: /Adopt your signature/ });
  await expect(dlg).toBeVisible();
  await dlg.getByTestId("adopt-confirm").click();
  await expect(dlg).toBeHidden();
}

for (const width of [1024, 1280, 1440]) {
  test(`fit width fits beside the panels at ${width} px, signing and review`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    await toDocuments(page);
    await expect.poll(async () => { const w = await widths(page, "signer-doc"); return w.scroll - w.client; }, { message: "signing: no horizontal overflow" }).toBeLessThanOrEqual(0);
    // WEB-18: the page is never wider than the canvas's page, and centred.
    const pg = await page.locator(".os-page").first().boundingBox();
    const sc = await page.getByTestId("signer-doc").boundingBox();
    expect(Math.abs(pg.x - sc.x - (sc.x + sc.width - pg.x - pg.width))).toBeLessThanOrEqual(24);
    // To review: fill the two required fields.
    await page.getByRole("textbox", { name: /Job title/ }).fill("Engineer");
    await page.getByRole("textbox", { name: /Job title/ }).press("Tab");
    await page.getByRole("button", { name: /^Sign: Signature/ }).click();
    await adoptTyped(page);
    await page.locator("#guide-finish").click();
    await expect(page.getByRole("heading", { name: "Review and finish" })).toBeVisible();
    await expect.poll(async () => { const w = await widths(page, "review-doc"); return w.scroll - w.client; }, { message: "review: no horizontal overflow" }).toBeLessThanOrEqual(0);
    if (width === 1440) await shot(page, "review-1440");
  });
}

test("the consent card names the sender and the deadline, and opens the full disclosure", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await toConsent(page);
  const card = page.locator(".os-sign__card");
  await expect(card.getByTestId("sign-sender")).toContainText("Demo Admin");
  await expect(card.getByTestId("sign-sender")).toContainText("demo@openseal.test");
  await expect(card.getByTestId("sign-by")).toContainText("Sign by");
  await shot(page, "consent-1440");
  await card.getByRole("button", { name: "Read the full disclosure" }).click();
  const panel = page.getByRole("dialog", { name: "Electronic record and signature disclosure" });
  await expect(panel).toContainText("mock mode demo text");
  await panel.getByRole("button", { name: "Close" }).first().click();
  // A visible alternative to Continue.
  await expect(card.getByRole("button", { name: "Other actions" })).toBeVisible();
  // The sender is named beside the message and in Help too.
  await page.getByLabel("I agree to use electronic records and signatures.").check();
  await page.getByRole("button", { name: "Continue" }).click();
  await expect(page.locator(".os-page canvas").first()).toBeVisible();
  // WEB-18: the header says who asked; the field list (More) names them too.
  await expect(page.getByTestId("ask-line")).toContainText("Demo Admin");
  await page.locator("#more-btn").click();
  await page.getByTestId("menu-fields").click();
  await expect(page.getByTestId("sheet-fields")).toContainText("Demo Admin");
  await page.keyboard.press("Escape");
  await page.locator("#more-btn").click();
  await page.getByTestId("menu-help").click();
  await expect(page.getByTestId("sheet-help")).toContainText("demo@openseal.test");
});

test("first arrival opens at the top of page 1", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await toDocuments(page);
  await page.waitForTimeout(300);
  expect(await page.getByTestId("signer-doc").evaluate((el) => el.scrollTop)).toBe(0);
  // The next field is ringed (WEB-18), the guide bar names it.
  await expect(page.locator(".os-sfield.is-next")).toHaveCount(1);
  await expect(page.locator("#guide-title")).toHaveText("Fill in Job title");
  await shot(page, "documents-1440");
});

test("a signed field can be removed and changed, and the history records both", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await toDocuments(page);
  const field = page.locator('[data-field="signature"]');
  await page.getByRole("button", { name: /^Sign: Signature/ }).click();
  await adoptTyped(page);
  await expect(field.locator("img")).toBeVisible();
  const first = await field.locator("img").getAttribute("src");
  // Choosing the signed field offers Remove and Change.
  await page.getByRole("button", { name: /^Signed: Signature/ }).click();
  const menu = page.getByRole("menu", { name: "Signature" });
  await expect(menu.getByRole("menuitem", { name: "Remove" })).toBeFocused();
  await shot(page, "signed-menu-1440");
  await menu.getByRole("menuitem", { name: "Remove" }).click();
  await expect(page.getByRole("button", { name: /^Sign: Signature/ })).toBeVisible();
  await expect(page.locator("#guide-progress")).toHaveText("0 of 2 required");
  // Sign again, then change: a new adoption replaces the mark.
  await page.getByRole("button", { name: /^Sign: Signature/ }).click();
  await expect(page.getByRole("dialog", { name: /Adopt your signature/ })).toHaveCount(0); // the adopted mark is reused
  await expect(field.locator("img")).toBeVisible();
  await page.getByRole("button", { name: /^Signed: Signature/ }).click();
  await page.getByRole("menu", { name: "Signature" }).getByRole("menuitem", { name: "Change signature" }).click();
  const dlg = page.getByRole("dialog", { name: /Adopt your signature/ });
  // The style tile is what a person chooses (WEB-18); its radio follows.
  await dlg.locator("label", { has: page.getByRole("radio", { name: /Style Allura/ }) }).click();
  await expect(dlg.getByRole("radio", { name: /Style Allura/ })).toBeChecked();
  await dlg.getByTestId("adopt-confirm").click();
  await expect(dlg).toBeHidden();
  await expect.poll(() => field.locator("img").getAttribute("src")).not.toBe(first);
  // History: the removal and both adoptions are events of their own.
  await page.locator("#more-btn").click();
  await page.getByTestId("menu-history").click();
  const hist = page.getByTestId("sheet-history");
  await expect(hist.locator('[data-type="recipient.field_cleared"]')).toHaveCount(1);
  await expect(hist.locator('[data-type="recipient.field_cleared"]')).toContainText("You removed a value");
  await expect(hist.locator('[data-type="recipient.signature_adopted"]')).not.toHaveCount(0);
  // Every time says its zone; no event type is printed raw.
  await expect(hist.locator("time").first()).toHaveText(/(GMT|UTC|[A-Z]{2,5})/);
  for (const t of await hist.locator(".os-history__what").allTextContents()) expect(t).not.toMatch(/^[a-z]+ [a-z_ ]+$/);
});

test("adopting asks for name and initials together, with errors beside the control", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await toDocuments(page);
  await page.getByRole("button", { name: /^Sign: Signature/ }).click();
  const dlg = page.getByRole("dialog", { name: /Adopt your signature/ });
  // At least 30 rem wide, the draw pad 3:1.
  expect((await dlg.boundingBox()).width).toBeGreaterThanOrEqual(30 * 16 - 1);
  await expect(dlg.getByLabel("Your initials")).toHaveValue(/^[A-Z]{1,3}$/);
  await dlg.getByLabel("Your full name").fill("");
  await dlg.getByTestId("adopt-confirm").click();
  await expect(dlg.getByRole("alert")).toHaveText("Type your name first.");
  await dlg.getByLabel("Your full name").fill("Ana Signer");
  await dlg.getByRole("tab", { name: "Draw" }).click();
  const pad = await dlg.getByTestId("signature-pad").boundingBox();
  expect(pad.width / pad.height).toBeCloseTo(3, 1);
  await dlg.getByTestId("adopt-confirm").click();
  await expect(dlg.getByRole("alert")).toHaveText("Draw your signature first.");
  await dlg.getByRole("tab", { name: "Upload" }).click();
  await expect(dlg.getByTestId("adopt-drop")).toBeVisible();
  await shot(page, "adopt-upload-1440");
  await dlg.getByRole("tab", { name: "Type" }).click();
  await shot(page, "adopt-type-1440");
  await dlg.getByTestId("adopt-confirm").click();
  await expect(dlg).toBeHidden();
  // The initials were adopted with the signature: the history has two adoptions.
  await page.locator("#more-btn").click();
  await page.getByTestId("menu-history").click();
  await expect(page.getByTestId("sheet-history").locator('[data-type="recipient.signature_adopted"]')).toHaveCount(2);
});

test("a radio group is chosen in a popover on the field, saved on selection", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto(signPage(MOCK.fieldsToken));
  await page.getByLabel("I agree to use electronic records and signatures.").check();
  await page.getByRole("button", { name: "Continue" }).click();
  await expect(page.locator(".os-page canvas").first()).toBeVisible();
  const choice = page.locator('[data-field="radio_group"] button');
  await choice.click();
  const pop = page.getByRole("radiogroup", { name: "Plan" });
  await expect(pop).toBeVisible();
  await expect(page.getByTestId("choice-save")).toHaveCount(0);
  await pop.getByRole("radio", { name: "Pro" }).click();
  await expect(pop).toBeHidden();
  await expect(choice).toHaveText(/Pro/);
  await expect(page.locator('[data-field="radio_group"]')).toHaveClass(/is-done/);
});

test("Finish shows once nothing required is left; required is not error-red", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await toDocuments(page);
  const fin = page.locator("#guide-finish");
  // WEB-18 (the canvas): Start / Next until every required field is done, then Finish.
  await expect(fin).toBeHidden();
  await expect(page.locator("#guide-next")).toBeVisible();
  const req = page.locator(".os-sfield.is-required").first();
  // The danger colour as the browser writes it (rgb), against the required outline.
  const err = await page.evaluate(() => { const s = document.createElement("span"); s.style.color = "var(--os-danger)"; document.body.append(s); const c = getComputedStyle(s).color; s.remove(); return c; });
  expect(err).toMatch(/^rgb/);
  expect(await req.evaluate((el) => getComputedStyle(el).boxShadow)).not.toContain(err);
  await page.getByRole("textbox", { name: /Job title/ }).fill("Engineer");
  await page.getByRole("textbox", { name: /Job title/ }).press("Tab");
  await page.getByRole("button", { name: /^Sign: Signature/ }).click();
  await adoptTyped(page);
  await expect(fin).toBeVisible();
  await expect(fin).toHaveClass(/is-ready/);
  await expect(page.locator("#guide-next")).toBeHidden();
});

test("finish later clears the progress; the done page links Verify and prints", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await toDocuments(page);
  await expect(page.locator("#bar-progress")).not.toBeEmpty();
  await page.locator("#more-btn").click();
  await page.getByRole("menuitem", { name: "Finish later" }).click();
  await expect(page.getByTestId("sign-later")).toBeVisible();
  await expect(page.locator("#bar-progress")).toBeEmpty();
  await expect(page.getByTestId("sign-later")).toContainText("This envelope expires on");
  await page.getByTestId("later-continue").click();
  await page.getByRole("textbox", { name: /Job title/ }).fill("Engineer");
  await page.getByRole("textbox", { name: /Job title/ }).press("Tab");
  await page.getByRole("button", { name: /^Sign: Signature/ }).click();
  await adoptTyped(page);
  await page.locator("#guide-finish").click();
  await page.getByTestId("review-finish").click();
  const done = page.getByTestId("sign-done");
  await expect(done.getByRole("link", { name: "Verify page" })).toHaveAttribute("href", "/verify.html");
  await expect(done.getByRole("button", { name: "Print" })).toBeVisible();
  await shot(page, "done-1440");
});

// WEB-18 review: nothing floats over a field, no tile cuts a signature off.
test("Next brings a field above the floating guide bar; tiles show the whole name", async ({ page, isMobile }) => {
  test.skip(isMobile, "the floating guide bar is the desktop layout; Tab is a keyboard path");
  await page.setViewportSize({ width: 1440, height: 900 });
  await toDocuments(page);
  await page.getByRole("textbox", { name: /Job title/ }).fill("Engineer");
  await page.getByRole("textbox", { name: /Job title/ }).press("Tab");
  await expect(page.locator("#guide-progress")).toHaveText("1 of 2 required");
  const sig = page.locator('[data-field="signature"]');
  const isClear = async () => {
    const f = await sig.boundingBox();
    const g = await page.locator("#guide").boundingBox();
    const z = await page.locator(".os-docbar").boundingBox();
    const clear = (o) => f.x + f.width <= o.x || f.x >= o.x + o.width || f.y + f.height <= o.y;
    return clear(g) && clear(z);
  };
  // The focused checkbox's label tab does not cover the Job title field above it.
  await expect(page.locator('[data-field="checkbox"] input')).toBeFocused();
  await expect.poll(async () => {
    const tip = await page.locator('[data-field="checkbox"] .os-sfield__tip').boundingBox();
    const job = await page.locator('[data-field="text"]').boundingBox();
    return !tip || tip.y >= job.y + job.height || tip.y + tip.height <= job.y || tip.x >= job.x + job.width || tip.x + tip.width <= job.x;
  }, { message: "the label tab covers no other field" }).toBe(true);
  // The next field (the signature) is brought clear of the guide bar once it is next.
  await expect.poll(isClear, { message: "next: clear of the guide bar and the zoom pill" }).toBe(true);
  // Tabbing onto it (at the bottom of the view, where the bar floats) and Next alike.
  await page.keyboard.press("Tab");
  await expect(page.getByRole("button", { name: /^Sign: Signature/ })).toBeFocused();
  await expect.poll(isClear, { message: "tabbed to: clear of the guide bar and the zoom pill" }).toBe(true);
  await page.getByTestId("signer-doc").evaluate((el) => { el.scrollTop = 0; });
  await page.locator("#guide-next").click();
  await expect(page.getByRole("button", { name: /^Sign: Signature/ })).toBeFocused();
  await expect.poll(isClear, { message: "Next: clear of the guide bar and the zoom pill" }).toBe(true);
  // No label tab is on show over the page until a field is hovered or focused.
  await page.mouse.move(5, 300);
  await page.locator("#guide-next").focus();
  for (const tip of await page.locator(".os-sfield__tip").all()) await expect(tip).toHaveCSS("opacity", "0");
  await page.getByRole("button", { name: /^Sign: Signature/ }).click();
  const dlg = page.getByRole("dialog", { name: /Adopt your signature/ });
  await dlg.getByLabel("Your full name").fill("Maximilian Alexander Featherstonehaugh");
  await expect.poll(() => dlg.locator(".os-adopt__sample").evaluateAll((els) => els.every((el) => el.scrollWidth <= el.parentElement.clientWidth))).toBe(true);
});

test.describe("phone", () => {
  test.use({ viewport: { width: 390, height: 844 }, hasTouch: true });

  test("review shows the document first, with Finish in a bottom bar", async ({ page }) => {
    await toDocuments(page);
    await shot(page, "documents-390");
    await page.locator("#guide-next").click();
    const text = page.getByRole("textbox", { name: /Job title/ });
    await text.fill("Engineer");
    await text.press("Tab");
    await page.getByRole("button", { name: /^Sign: Signature/ }).click();
    await adoptTyped(page);
    // Nothing is left to do, so there is no dead Next in the bottom bar.
    await expect(page.locator("#guide-next")).toBeHidden();
    // WEB-18: the page fits the width again with a gutter; no pill sits on the page.
    await expect(page.locator(".os-docbar")).toBeHidden();
    await expect.poll(async () => {
      const p = await page.locator(".os-page").first().boundingBox();
      return p.x >= 8 && p.x + p.width <= 390 - 8;
    }, { message: "the page is fitted with a gutter" }).toBe(true);
    await page.locator("#guide-finish").click();
    await expect(page.getByRole("heading", { name: "Review and finish" })).toBeAttached();
    const pages = await page.getByTestId("review-doc").boundingBox();
    const fin = await page.getByTestId("review-finish").boundingBox();
    expect(pages.y).toBeLessThan(fin.y);
    expect(pages.height).toBeGreaterThan(844 / 2);
    expect(fin.y + fin.height).toBeLessThanOrEqual(844);
    await shot(page, "review-390");
    // The values are one tap away.
    await page.getByTestId("review-values-btn").click();
    await expect(page.getByTestId("review-values")).toBeInViewport();
    await expect(page.getByTestId("panel-review")).not.toContainText("null");
    await settled(page);
    expect((await page.getByTestId("panel-review").boundingBox()).y).toBeLessThan(844 * 0.7);
    await shot(page, "review-values-390");
  });

  test("the consent card names the sender", async ({ page }) => {
    await toConsent(page);
    await expect(page.getByTestId("sign-sender")).toContainText("Demo Admin");
    await shot(page, "consent-390");
  });
});
