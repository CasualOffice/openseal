// Slice 5 (VS-05) in a browser, mock mode: the signing page's identity steps (an
// emailed code, a texted code, a code read in a phone call, sign-in through an identity
// provider), then consent, then withdrawing it from the More menu. Runs on desktop and
// on a phone viewport (the `mobile` project). The same run on the Compose stack, with
// an SMS gateway and an identity provider in Compose, is row RAUTH-02.
import { test, expect } from "@playwright/test";
import { MOCK } from "../mock.js";
import { signPage, REAL } from "./helpers.mjs";

/// A sent envelope with one signer described by `recipient`, made through the mock
/// client in this tab (the mock keeps its data in the tab's session storage, where the
/// signing page then finds it); answers the signer's link token.
async function sentTo(page, recipient) {
  await page.goto(signPage("none"));
  return page.evaluate(async ({ r, email, password }) => {
    const { createMockFetch } = await import("/mock.js");
    const { createClient } = await import("/api.js");
    const { makePdf } = await import("/mockpdf.js");
    const c = createClient({ fetch: createMockFetch({ store: sessionStorage }), store: sessionStorage });
    await c.login(email, password);
    const pdf = makePdf([{ title: "Slice 5" }]);
    const env = await c.createEnvelope({
      subject: "Slice 5 identity",
      documents: [{ name: "a.pdf", content_base64: btoa(String.fromCharCode(...pdf)) }],
      recipients: [{ ref: "r1", type: "signer", name: "Ana Signer", email: "ana@example.com", ...r }],
      fields: [{ recipient: "r1", document: 0, type: "signature", page: 1, x: "72", y: "600", width: "160", height: "44", required: true }],
    });
    const sent = await c.sendEnvelope(env.id);
    return sent.recipients[0].mock_token;
  }, { r: recipient, email: MOCK.email, password: MOCK.password });
}

/// Ask for a code with `ask`, enter the mock's code, and continue.
async function code(page, title, ask) {
  await expect(page.getByRole("heading", { name: title })).toBeVisible();
  await page.getByRole("button", { name: ask }).click();
  await page.getByLabel("6-digit code").fill(MOCK.emailCode);
  await page.getByRole("button", { name: "Continue" }).click();
}

/// Consent, then withdraw it from More: the signer's part ends.
async function consentThenWithdraw(page) {
  await expect(page.getByRole("heading", { name: "Electronic records and signatures" })).toBeVisible();
  await page.getByLabel("I agree to use electronic records and signatures.").check();
  await page.getByRole("button", { name: "Continue" }).click();
  await expect(page.locator("#guide-progress")).toHaveText("0 of 1 required");
  await page.getByRole("button", { name: "More" }).click();
  await page.getByRole("menuitem", { name: "Withdraw consent to electronic records" }).click();
  const dlg = page.getByRole("dialog", { name: "Withdraw your consent?" });
  await dlg.getByRole("button", { name: "Withdraw consent" }).click();
  await expect(page.getByTestId("sign-withdrawn")).toBeVisible();
}

test("codes by email, text message and phone call, then consent and its withdrawal", async ({ page }) => {
  test.skip(REAL, "mock mode; the Compose run is RAUTH-02");
  const token = await sentTo(page, { phone: "+44 20 7946 0001", auth: ["email_otp", "sms_otp", "voice_otp"] });
  await page.goto(signPage(token));
  await code(page, "Check your email", "Email me a code");
  await code(page, "Check your phone", "Text me a code");
  await code(page, "Get a code by phone call", "Call me with a code");
  await consentThenWithdraw(page);
});

test("sign-in through an identity provider comes back to the signing page", async ({ page }) => {
  test.skip(REAL, "mock mode; the Compose run is RAUTH-02");
  const token = await sentTo(page, { auth: ["sso"] });
  await page.goto(signPage(token));
  await expect(page.getByRole("heading", { name: "Sign in to continue" })).toBeVisible();
  await page.getByRole("button", { name: `Sign in with ${MOCK.ssoProvider.name}` }).click();
  // Back from the provider: the address shows the link again, and the sign-in passed.
  await expect(page.getByRole("heading", { name: "Electronic records and signatures" })).toBeVisible();
  await expect(page).toHaveURL(new RegExp(`/s/${token}$`));
  await consentThenWithdraw(page);
});
