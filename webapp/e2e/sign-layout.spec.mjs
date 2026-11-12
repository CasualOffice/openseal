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

const shot = async (page, name) => {
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
    // The Start flag sits in the margin, fully inside the scroller.
    const tag = await page.getByTestId("guide-tag").boundingBox();
    const sc = await page.getByTestId("signer-doc").boundingBox();
    expect(tag.x).toBeGreaterThanOrEqual(sc.x);
    // To review: fill the two required fields.
    await page.getByRole("textbox", { name: /Job title/ }).fill("Engineer");
    await page.getByRole("textbox", { name: /Job title/ }).press("Tab");
    await page.getByRole("button", { name: /^Sign: Signature/ }).click();
    await adoptTyped(page);
    await page.locator("#bar-finish").click();
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
  await expect(page.getByTestId("field-list")).toBeVisible();
  await expect(page.getByTestId("panel-fieldlist")).toContainText("Demo Admin");
  await page.locator("#more-btn").click();
  await page.getByTestId("menu-help").click();
  await expect(page.getByTestId("sheet-help")).toContainText("demo@openseal.test");
});

test("first arrival opens at the top of page 1", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await toDocuments(page);
  await page.waitForTimeout(300);
  expect(await page.getByTestId("signer-doc").evaluate((el) => el.scrollTop)).toBe(0);
  await expect(page.getByTestId("guide-tag")).toBeVisible();
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
  await dlg.getByRole("radio", { name: /Style Allura/ }).check({ force: true });
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

test("Finish reads as a secondary action until ready; required is not error-red", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await toDocuments(page);
  const fin = page.locator("#bar-finish");
  await expect(fin).toHaveClass(/os-btn--secondary/);
  expect(await fin.evaluate((el) => getComputedStyle(el).opacity)).toBe("1");
  const req = page.locator(".os-sfield.is-required").first();
  const err = await page.evaluate(() => getComputedStyle(document.documentElement).getPropertyValue("--os-danger").trim());
  expect(await req.evaluate((el) => getComputedStyle(el).boxShadow)).not.toContain(err);
  await page.getByRole("textbox", { name: /Job title/ }).fill("Engineer");
  await page.getByRole("textbox", { name: /Job title/ }).press("Tab");
  await page.getByRole("button", { name: /^Sign: Signature/ }).click();
  await adoptTyped(page);
  await expect(fin).toHaveClass(/os-btn--primary/);
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
  await page.locator("#bar-finish").click();
  await page.getByTestId("review-finish").click();
  const done = page.getByTestId("sign-done");
  await expect(done.getByRole("link", { name: "Verify page" })).toHaveAttribute("href", "/verify.html");
  await expect(done.getByRole("button", { name: "Print" })).toBeVisible();
  await shot(page, "done-1440");
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
    await page.locator("#guide-finish").click();
    await expect(page.getByRole("heading", { name: "Review and finish" })).toBeAttached();
    const pages = await page.getByTestId("review-doc").boundingBox();
    const fin = await page.getByTestId("review-finish").boundingBox();
    expect(pages.y).toBeLessThan(fin.y);
    expect(pages.height).toBeGreaterThan(844 / 2);
    expect(fin.y + fin.height).toBeLessThanOrEqual(844);
    await shot(page, "review-390");
    // The values are one tap away.
    await page.getByRole("button", { name: /Review values/ }).click();
    await expect(page.getByTestId("review-values")).toBeVisible();
    await shot(page, "review-values-390");
  });

  test("the consent card names the sender", async ({ page }) => {
    await toConsent(page);
    await expect(page.getByTestId("sign-sender")).toContainText("Demo Admin");
    await shot(page, "consent-390");
  });
});
