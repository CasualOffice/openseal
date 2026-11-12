// The signer's guided ceremony (WEB-06; owner instruction 22 audit: P-05, M-01..M-03,
// G-S1..G-S8): Start on arrival, zoom-to-field and 44 px touch areas on phones, the
// field sheet, full-screen drawing, the More menu, review, done, finish later and
// decline. Mock data: the seeded envelopes (helpers.mjs).
import { test, expect } from "@playwright/test";
import { signPage, tokens, REAL, expectAccessible } from "./helpers.mjs";
import { MOCK } from "../mock.js";

test.skip(REAL, "uses the mock's seeded envelopes and its reassignable signing option");

/// Through access code, location and consent to the documents.
async function toDocuments(page) {
  await page.goto(signPage(tokens.sign));
  await page.getByLabel("Access code").fill(tokens.accessCode);
  await page.getByLabel("Access code").press("Enter");
  await page.getByRole("button", { name: "Don't share" }).click();
  await page.getByLabel("I agree to use electronic records and signatures.").check();
  await page.getByRole("button", { name: "Continue" }).click();
  await expect(page.locator(".os-page canvas").first()).toBeVisible();
  // The first page is drawn and the loader gone (WEB-18); later pages paint as they near the view.
  await expect(page.locator(".os-page").first()).not.toHaveClass(/is-loading/);
  await expect(page.getByTestId("sign-loader")).toHaveCount(0);
}

/// Only the document view scrolls on the signing page (one scroll container).
async function scrollers(page) {
  return page.evaluate(() => {
    const scrolls = (el) => { const cs = getComputedStyle(el); return /(auto|scroll)/.test(`${cs.overflowY} ${cs.overflowX}`) && (el.scrollHeight > el.clientHeight + 1 || el.scrollWidth > el.clientWidth + 1); };
    const se = document.scrollingElement;
    const list = [...document.querySelectorAll("body *")].filter((el) => el.getClientRects().length && scrolls(el) && !el.closest(".os-dock, .os-sheet")).map((el) => el.dataset.testid || el.className);
    return { list, root: se.scrollHeight > se.clientHeight + 1 };
  });
}

test.describe("phone", () => {
  test.use({ viewport: { width: 390, height: 844 }, hasTouch: true });

  test("Start zooms to a 44 px field; every field has a 44 px touch area; a tap opens the field's sheet", async ({ page }) => {
    await toDocuments(page);
    // M-02: worded buttons; the field list is in More (WEB-18: the canvas's phone header).
    await page.locator("#more-btn").click();
    await expect(page.getByTestId("menu-fields")).toHaveText(/All fields/);
    await page.keyboard.press("Escape");
    await expect(page.locator("#guide-next > span")).toBeVisible();
    await expect(page.locator("#guide-next")).toHaveText(/Start/);
    // P-05: a touch area of at least 44 × 44 px for every field that takes input.
    for (const f of await page.locator(".os-sfield:not(.is-auto)").all()) {
      const hit = await f.locator(".os-sfield__hit").boundingBox();
      expect(hit, await f.getAttribute("data-field")).not.toBeNull();
      expect(Math.min(hit.width, hit.height), `${await f.getAttribute("data-field")} touch area`).toBeGreaterThanOrEqual(43.5);
    }
    // M-01: Start zooms until the field itself is a 44 px target, in view.
    await page.locator("#guide-next").click();
    const text = page.getByRole("textbox", { name: /Job title/ });
    await expect(text).toBeFocused();
    await expect.poll(async () => (await text.boundingBox()).height).toBeGreaterThanOrEqual(40);
    await expect.poll(async () => {
      const b = await text.boundingBox();
      return b.x >= 0 && b.x + b.width <= 390;
    }, { message: "the zoomed field is fully in view" }).toBe(true);
    expect((await scrollers(page)).list.length).toBe(1);
    expect((await scrollers(page)).root).toBe(false);
    await page.keyboard.press("Escape");
    await text.blur();
    // P-05: a tap on the field opens a full-width sheet with a large input.
    await text.tap();
    const sheet = page.getByRole("dialog", { name: "Job title" });
    await expect(sheet).toBeVisible();
    const input = sheet.getByLabel("Job title (required)");
    await expect(input).toBeFocused();
    expect((await input.boundingBox()).width).toBeGreaterThan(300);
    await expectAccessible(page, "field sheet");
    await input.fill("Engineer");
    await input.press("Enter");
    await expect(sheet).toBeHidden();
    await expect(text).toHaveValue("Engineer");
    await expect(page.locator("#guide-progress")).toHaveText("1 of 2 required");
    await expect(page.locator("#guide-next")).toHaveText(/Next/);
  });

  test("the signature can be drawn full screen, along the long edge of an upright phone", async ({ page }) => {
    await toDocuments(page);
    await page.getByRole("button", { name: /Signature, required/ }).click();
    const dlg = page.getByRole("dialog", { name: "Adopt your signature" });
    await dlg.getByRole("tab", { name: "Draw" }).click();
    await dlg.getByTestId("adopt-full").click();
    const pad = page.getByTestId("signature-pad");
    const b = await pad.boundingBox();
    // Turned a quarter: taller than wide, and most of the screen's height.
    expect(b.height).toBeGreaterThan(b.width);
    expect(b.height).toBeGreaterThan(844 * 0.6);
    await expectAccessible(page, "full-screen pad");
    // A stroke down the screen is a stroke along the pad.
    await page.mouse.move(b.x + b.width / 2, b.y + 30);
    await page.mouse.down();
    for (let i = 1; i <= 10; i++) await page.mouse.move(b.x + b.width / 2 + (i % 2 ? 12 : -12), b.y + 30 + i * 40);
    await page.mouse.up();
    // Escape leaves full screen only; the adopt panel stays.
    await page.keyboard.press("Escape");
    await expect(page.getByTestId("adopt-full-done")).toBeHidden();
    await expect(dlg).toBeVisible();
    const small = await pad.boundingBox();
    expect(small.width).toBeGreaterThan(small.height);
    // The adopt panel's actions are on screen.
    const adopt = dlg.getByTestId("adopt-confirm");
    const ab = await adopt.boundingBox();
    expect(ab.y + ab.height).toBeLessThanOrEqual(844);
    await adopt.click();
    await expect(dlg).toBeHidden();
    await expect(page.locator('[data-field="signature"] img')).toBeVisible();
  });

  test("the field list leaves the document visible", async ({ page }) => {
    await toDocuments(page);
    await page.locator("#more-btn").click();
    await page.getByTestId("menu-fields").click();
    const list = page.getByTestId("sheet-fields");
    await expect(list.getByTestId("field-list")).toBeVisible();
    const lb = await list.boundingBox();
    const doc = await page.getByTestId("signer-doc").boundingBox();
    expect(lb.y - doc.y, "document visible above the list").toBeGreaterThan(844 * 0.3);
    // However many fields there are, the list never takes more than about half the screen.
    const cap = await list.evaluate((el) => Number.parseFloat(getComputedStyle(el).maxHeight));
    expect(cap).toBeLessThanOrEqual(844 * 0.56);
  });
});

// A guard: the pinned footer already held at f10da57 (the panel rework); this keeps it so.
test.describe("200 % zoom", () => {
  test.use({ viewport: { width: 720, height: 450 } });

  test("the adopt panel's actions stay on screen", async ({ page }) => {
    await toDocuments(page);
    await page.getByRole("button", { name: /Signature, required/ }).click();
    const dlg = page.getByRole("dialog", { name: "Adopt your signature" });
    await expect(dlg).toBeVisible();
    for (const tab of ["Type", "Draw", "Upload"]) {
      await dlg.getByRole("tab", { name: tab }).click();
      for (const name of ["Cancel", "Adopt and sign"]) {
        const bb = await dlg.getByRole("button", { name, exact: true }).boundingBox();
        expect(bb.y + bb.height, `${tab}: ${name} on screen`).toBeLessThanOrEqual(450);
        expect(bb.y).toBeGreaterThanOrEqual(0);
      }
    }
  });
});

test.describe("desktop", () => {
  test.use({ viewport: { width: 1440, height: 900 } });

  test("arrival: Start in the bar, the view at the first required field, labels on the page", async ({ page }) => {
    await toDocuments(page);
    const start = page.locator("#guide-next");
    await expect(start).toBeVisible();
    await expect(start).toHaveText(/Start/);
    // G-S1: the first required field is in view without any action.
    const field = page.locator('[data-field="text"]');
    await expect.poll(async () => {
      const f = await field.boundingBox();
      const d = await page.getByTestId("signer-doc").boundingBox();
      return f.y >= d.y && f.y + f.height <= d.y + d.height;
    }).toBe(true);
    // G-S8 as WEB-18 draws it: the next field is ringed, its tab hidden so no tab sits
    // over another field; a field's tab shows on hover and focus.
    await expect(field).toHaveClass(/is-next/);
    await expect(field.locator(".os-sfield__tip")).toHaveCSS("opacity", "0");
    const box = page.locator('[data-field="checkbox"]');
    await box.hover();
    await expect(box.locator(".os-sfield__tip")).toHaveCSS("opacity", "1");
    await expect(box.locator(".os-sfield__tip")).toHaveText("Relocation package");
    expect((await scrollers(page)).root).toBe(false);
    await start.click();
    await expect(page.getByRole("textbox", { name: /Job title/ })).toBeFocused();
  });

  test("More: download, print, history, help, reassign, finish later and continue", async ({ page }) => {
    await toDocuments(page);
    const more = page.getByRole("button", { name: "More" });
    await more.click();
    const menu = page.getByRole("menu");
    for (const name of ["Download", "Print", "Assign to someone else", "View history", "Help", "Finish later", "Decline to sign"]) {
      await expect(menu.getByRole("menuitem", { name })).toBeVisible();
    }
    await expectAccessible(page, "more menu");
    const dl = page.waitForEvent("download");
    await menu.getByRole("menuitem", { name: "Download" }).click();
    const file = await dl;
    expect(file.suggestedFilename()).toMatch(/\.pdf$/);

    await more.click();
    await page.getByRole("menuitem", { name: "View history" }).click();
    const hist = page.getByRole("dialog", { name: "History" });
    await expect(hist.getByText("You agreed to electronic records")).toBeVisible();
    // The server's dotted audit types (WEB-07), and who acted without naming them.
    await expect(hist.locator('[data-type="envelope.sent"]')).toContainText("by the sender");
    await expect(hist.locator('[data-type*="_"]:not([data-type*="."])')).toHaveCount(0);
    await expectAccessible(page, "history panel");
    await hist.getByRole("button", { name: "Close" }).first().click();

    await more.click();
    await page.getByRole("menuitem", { name: "Help" }).click();
    await expect(page.getByRole("dialog", { name: "Help" }).getByText("How to sign")).toBeVisible();
    await page.keyboard.press("Escape");

    await more.click();
    await page.getByRole("menuitem", { name: "Assign to someone else" }).click();
    const re = page.getByRole("dialog", { name: "Assign to someone else" });
    await re.getByLabel("Their full name").fill("Sam Doe");
    await re.getByLabel("Their email").fill("not-an-email");
    await re.getByRole("button", { name: "Assign" }).click();
    await expect(re.getByText("Enter an email address")).toBeVisible();
    await re.getByRole("button", { name: "Cancel" }).click();

    // G-S4: Finish later, then straight back in.
    await more.click();
    await page.getByRole("menuitem", { name: "Finish later" }).click();
    await expect(page.getByTestId("sign-later")).toBeVisible();
    await page.getByRole("button", { name: "Continue signing" }).click();
    await expect(page.locator(".os-page canvas").first()).toBeVisible();
    await expect(page.locator("#guide-next")).toBeVisible();
  });

  test("review lists every value, opens at the top, has one Finish; done offers a copy", async ({ page }) => {
    await toDocuments(page);
    await page.getByRole("textbox", { name: /Job title/ }).fill("Engineer");
    await page.getByRole("textbox", { name: /Job title/ }).blur();
    await page.getByRole("button", { name: /Signature, required/ }).click();
    await page.getByTestId("adopt-confirm").click();
    await page.locator("#guide-finish").click();
    await expect(page.getByRole("heading", { name: "Review and finish" })).toBeVisible();
    const values = page.getByTestId("review-values");
    for (const v of ["Job title", "Engineer", "Signature", "Date signed"]) await expect(values).toContainText(v);
    // UX-06: the adopted mark itself, not the word "Signed".
    await expect(values.getByRole("img", { name: /Signature: your adopted mark/ })).toBeVisible();
    expect(await page.getByTestId("review-doc").evaluate((el) => el.scrollTop)).toBe(0);
    await expect(page.getByRole("button", { name: "Finish" })).toHaveCount(1);
    await expectAccessible(page, "review");
    await page.getByTestId("review-finish").click();
    const done = page.getByTestId("sign-done");
    await expect(done).toBeVisible();
    // WEB-18: the receipt says who they are, when they signed and what, and links Verify.
    await expect(done.getByRole("heading", { name: /^Signed. Thank you/ })).toBeVisible();
    await expect(done.getByTestId("receipt-facts")).toContainText(/signature/i);
    await expect(done.getByRole("link", { name: "Verify page" })).toBeVisible();
    const dl = page.waitForEvent("download");
    await done.getByRole("button", { name: "Download a copy" }).click();
    expect((await dl).suggestedFilename()).toMatch(/\.pdf$/);
    await expectAccessible(page, "done");
  });

  test("every field kind: notes and locked values shown, inline checks, choices, an attachment", async ({ page }) => {
    await page.goto(signPage(MOCK.fieldsToken));
    await page.getByLabel("I agree to use electronic records and signatures.").check();
    await page.getByRole("button", { name: "Continue" }).click();
    await expect(page.locator(".os-page canvas").first()).toBeVisible();
    // The sender's note and locked value: shown, not editable.
    await expect(page.getByRole("note", { name: /Note: Read clause 4/ })).toBeVisible();
    await expect(page.getByRole("note", { name: /PO number: PO-7781/ })).toBeVisible();
    await expect(page.getByRole("textbox", { name: /PO number/ })).toHaveCount(0);
    await expect(page.locator("#guide-progress")).toHaveText("0 of 4 required");
    await expect(page.locator("#guide-next")).toHaveText(/Start/);
    // Inline checks say the problem before the server is asked.
    const qty = page.getByRole("textbox", { name: /Quantity/ });
    await qty.fill("500");
    await qty.blur();
    await expect(page.getByText("Enter a number from 1 to 100.")).toBeVisible();
    await expect(qty).toHaveAttribute("aria-invalid", "true");
    await qty.fill("2.5");
    await qty.blur();
    await expect(page.getByText("Enter a whole number.")).toBeVisible();
    await qty.fill("42");
    await qty.blur();
    await expect(qty).not.toHaveAttribute("aria-invalid", "true");
    const mail = page.getByRole("textbox", { name: /^Email/ });
    await mail.fill("not an address");
    await mail.blur();
    await expect(page.getByText("Enter an email address like name@example.com.")).toBeVisible();
    await page.getByRole("textbox", { name: /Company/ }).fill("Northwind");
    await page.getByRole("textbox", { name: /Company/ }).blur();
    // A radio group: its choices in a popover on the field, saved on selection (UX-06).
    await page.getByRole("button", { name: /Plan, required/ }).click();
    const plan = page.getByRole("radiogroup", { name: "Plan" });
    await expect(plan).toBeVisible();
    await expectAccessible(page, "choice popover");
    await plan.getByRole("radio", { name: "Pro" }).click();
    await expect(plan).toBeHidden();
    await expect(page.getByRole("button", { name: /^Pro: Plan/ })).toBeVisible();
    // A dropdown: the platform's select.
    await page.getByRole("combobox", { name: /Term/ }).selectOption("24 months");
    // An attachment: PNG bytes.
    const png = Buffer.from("89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c4890000000d4944415478da63f8ffff3f0005fe02fea7d6a4a10000000049454e44ae426082", "hex");
    await page.locator('[data-field="attachment"] input[type="file"]').setInputFiles({ name: "id.png", mimeType: "image/png", buffer: png });
    await expect(page.getByRole("button", { name: /^id.png: Proof of ID, Attached/ })).toBeVisible();
    await expect(page.getByRole("button", { name: /^id.png: Proof of ID, Attached/ })).toContainText("id.png");
    await expect(page.locator("#guide-progress")).toHaveText("3 of 4 required");
    await page.getByRole("button", { name: /Signature, required/ }).click();
    await page.getByTestId("adopt-confirm").click();
    await expect(page.locator("#guide-progress")).toHaveText("4 of 4 required");
    await expectAccessible(page, "field kinds");
    await page.locator("#guide-finish").click();
    const values = page.getByTestId("review-values");
    for (const v of ["Northwind", "42", "Pro", "24 months", "id.png", "PO-7781", "Read clause 4"]) await expect(values).toContainText(v);
  });

  test("decline says it ends the envelope for everyone, with a filled danger button", async ({ page }) => {
    await page.goto(signPage(tokens.decline));
    await page.getByLabel("I agree to use electronic records and signatures.").check();
    await page.getByRole("button", { name: "Continue" }).click();
    await page.getByRole("button", { name: "More" }).click();
    await page.getByRole("menuitem", { name: "Decline to sign" }).click();
    const dlg = page.getByRole("dialog", { name: "Decline to sign?" });
    await expect(dlg).toContainText("ends this envelope for everyone");
    const btn = dlg.getByRole("button", { name: "Decline" });
    const bg = await btn.evaluate((el) => getComputedStyle(el).backgroundColor);
    const danger = await btn.evaluate((el) => { const p = document.createElement("span"); p.style.color = "var(--os-danger)"; el.append(p); const c = getComputedStyle(p).color; p.remove(); return c; });
    expect(bg).toBe(danger);
    await expectAccessible(page, "decline dialog");
  });
});
