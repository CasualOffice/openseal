// Scenario 6, signer side (WEB-01): axe-core on every ceremony step at phone width,
// light and dark, plus the 44 px target rule on the signing page (SC 2.5.5).
import { test, expect } from "@playwright/test";
import { signIn, signPage, tokens, REAL, expectAccessible } from "./helpers.mjs";

for (const scheme of ["light", "dark"]) {
  test(`every ceremony step is accessible (${scheme})`, async ({ page }) => {
    test.skip(REAL && !tokens.sign, "OPENSEAL_E2E_SIGN_TOKEN is needed against a real server");
    await page.addInitScript((s) => { try { localStorage.setItem("openseal.theme", s); } catch { /* storage off */ } }, scheme);
    await page.emulateMedia({ colorScheme: scheme });
    await page.setViewportSize({ width: 390, height: 844 });
    await page.goto(signPage(tokens.sign));
    await expect(page.getByRole("heading", { name: "Enter your access code" })).toBeVisible();
    await expectAccessible(page, `access code (${scheme})`);
    await page.getByLabel("Access code").fill(tokens.accessCode);
    await page.getByRole("button", { name: "Continue" }).click();
    await expect(page.getByRole("heading", { name: "Share your location?" })).toBeVisible();
    await expectAccessible(page, `location (${scheme})`);
    await page.getByRole("button", { name: "Don't share" }).click();
    await expect(page.getByRole("heading", { name: "Electronic records and signatures" })).toBeVisible();
    await expectAccessible(page, `consent (${scheme})`);
    await page.getByLabel("I agree to use electronic records and signatures.").check();
    await page.getByRole("button", { name: "Continue" }).click();
    await expect(page.locator("#guide-progress")).toBeVisible();
    await expect(page.locator(".os-sign__pages:not([aria-busy]) .os-page").first()).toBeVisible();
    await expect(page.locator(".os-page.is-loading")).toHaveCount(0);
    await expectAccessible(page, `documents (${scheme})`);
    await page.getByRole("button", { name: /Signature, required/ }).click();
    await expect(page.getByRole("dialog", { name: "Adopt your signature" })).toBeVisible();
    await expectAccessible(page, `adopt dialog (${scheme})`);
    await page.getByTestId("adopt-confirm").click();
    await page.getByRole("button", { name: "More" }).click();
    await expectAccessible(page, `more menu (${scheme})`);
  });
}

// VS-02: the steps of the acting recipients who are not signers (RTE-01): the approver's
// review with Approve, the viewer's finish and the agent's form naming the later signer,
// each from the documents step to the receipt, light and dark. Mock mode: the envelopes
// are made through api.js against the page's own mock (as recipient-types.spec.mjs); on
// the Compose stack routing.spec.mjs walks the same steps through the emailed links.
/// One sent envelope per type, `type` first and a signer after; answers the first token.
async function firstToken(page, type, name) {
  return page.evaluate(async ({ type, name }) => {
    const { createClient, recipientWire, fieldWire } = await import("/api.js");
    const { createMockFetch } = await import("/mock.js");
    const { makePdf } = await import("/mockpdf.js");
    const api = createClient({ fetch: createMockFetch({ store: sessionStorage }), store: sessionStorage });
    let bin = "";
    for (const b of makePdf([{ title: "Routing" }])) bin += String.fromCharCode(b);
    const env = await api.createEnvelope({
      subject: `Accessible ${type}`, status: "sent",
      documents: [{ name: "routing.pdf", content_base64: btoa(bin) }],
      recipients: [
        recipientWire({ ref: "r0", routing_order: 1, name, email: `${type}@example.com`, type }),
        recipientWire({ ref: "r1", routing_order: 2, name: "To be named", email: "later@example.com", type: "signer" }),
      ],
      fields: [fieldWire({ recipient: "r1", document: 0, type: "signature", page: 1, x: 72, y: 600, width: 160, height: 44, required: true })],
    });
    return env.recipients[0].mock_token;
  }, { type, name });
}

for (const scheme of ["light", "dark"]) {
  test(`the approver's, viewer's and agent's steps are accessible (${scheme})`, async ({ page, isMobile }) => {
    test.skip(REAL, "the links are emailed on a real server; routing.spec.mjs walks them there");
    await page.addInitScript((s) => { try { localStorage.setItem("openseal.theme", s); } catch { /* storage off */ } }, scheme);
    await page.emulateMedia({ colorScheme: scheme });
    await signIn(page);
    for (const [type, name, receipt] of [
      ["approver", "Ann Approver", "Approved. Thank you, Ann."],
      ["viewer", "Vic Viewer", "Viewed. Thank you, Vic."],
      ["agent", "Abe Agent", "Your part is finished. Thank you, Abe."],
    ]) {
      await page.goto(signPage(await firstToken(page, type, name)));
      await page.getByLabel("I agree to use electronic records and signatures.").check();
      await page.getByRole("button", { name: "Continue" }).click();
      await expect(page.locator(".os-sign__pages:not([aria-busy]) .os-page").first()).toBeVisible();
      await expect(page.locator(".os-page.is-loading")).toHaveCount(0);
      await expectAccessible(page, `${type} documents (${scheme})`);
      await page.locator("#guide-finish").click();
      await expect(page.getByTestId("review-finish")).toBeVisible();
      if (type === "approver") await expect(page.getByTestId("review-finish")).toHaveText("Approve");
      let finish = page.getByTestId("review-finish");
      if (type === "agent") {
        // On a phone the names are asked in the values sheet, open with its own Finish.
        const form = page.getByTestId("later-recipients");
        await expect(form).toBeVisible();
        await expectAccessible(page, `agent naming the later signer (${scheme})`);
        await form.getByTestId("later-email").fill("nope");
        if (isMobile) finish = page.getByTestId("review-finish-sheet");
        await finish.click();
        await expect(form.getByRole("alert")).not.toBeEmpty();
        await expectAccessible(page, `agent's refused address (${scheme})`);
        await form.getByTestId("later-name").fill("Bea Buyer");
        await form.getByTestId("later-email").fill("bea@example.com");
      } else {
        await expectAccessible(page, `${type} review (${scheme})`);
      }
      await finish.click();
      await expect(page.getByTestId("sign-done")).toContainText(receipt);
      await expectAccessible(page, `${type} receipt (${scheme})`);
    }
  });
}

test("the signing page's controls are at least 44 px", async ({ page }) => {
  test.skip(REAL && !tokens.decline, "OPENSEAL_E2E_DECLINE_TOKEN is needed against a real server");
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto(signPage(tokens.decline));
  await expect(page.getByRole("heading", { name: "Electronic records and signatures" })).toBeVisible();
  for (const b of await page.locator(".os-sign__card .os-btn, .os-sign__bar .os-btn, .os-check--lg").all()) {
    const box = await b.boundingBox();
    if (!box) continue; // not shown on this screen
    expect(box.height, await b.textContent()).toBeGreaterThanOrEqual(44);
  }
});
