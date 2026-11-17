// Slice 5 (VS-05) in a browser: the signing page's identity steps (an access code, an
// emailed code, a texted code, a code read in a phone call, sign-in through an identity
// provider), then consent, then withdrawing it from the More menu.
//
// Two modes, as every spec (playwright.config.mjs):
//  - mock: the mock API in the tab; runs on desktop and on a phone viewport (`mobile`).
//  - real (RAUTH-02, CI's compose-e2e): the Compose stack with the CI-only stubs of
//    tools/e2e/compose.e2e.yml. The signing link and the emailed code are read from
//    Mailpit (OPENSEAL_E2E_MAIL_URL), the texted and spoken codes from the SMS gateway
//    stub (OPENSEAL_E2E_SMS_URL), and the signer signs in on the OpenID Connect stub's
//    page. The codes run on a phone (iPhone 13), the sign-in on a desktop; each signer's
//    screen is recorded into target/e2e-demo/vs05-*.webm, the slice 5 demo CI uploads.
//
// Accessibility: axe on the access-code, code-entry, sign-in and withdraw steps, light
// and dark, at phone width, in mock mode (the real run serves the same screens; its pace
// is set by the server's limits on sending codes).
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { test, expect, devices } from "@playwright/test";
import { MOCK } from "../mock.js";
import { signPage, signIn, REAL, expectAccessible } from "./helpers.mjs";

const MAIL = (process.env.OPENSEAL_E2E_MAIL_URL || "http://127.0.0.1:8025").replace(/\/$/, "");
const SMS = (process.env.OPENSEAL_E2E_SMS_URL || "http://127.0.0.1:8026").replace(/\/$/, "");
// The provider in tools/e2e/recipient-idps.json on the real stack; the mock's otherwise.
const PROVIDER = REAL ? "OpenSeal CI identity provider" : MOCK.ssoProvider.name;
const DEMO = path.resolve(fileURLToPath(new URL("../../target/e2e-demo", import.meta.url)));
const ACCESS_CODE = "2468";
const CODES = ["access_code", "email_otp", "sms_otp", "voice_otp"];

/// This run's signer: a fresh email and phone number on the real stack, so the codes
/// read back are this test's; the mock's own otherwise.
function signerOf(testInfo) {
  if (!REAL) return { email: "ana@example.com", phone: "+44 20 7946 0001" };
  const run = `${Date.now()}-${testInfo.project.name}`;
  return { email: `ana-${run}@example.com`, phone: `+4477009${String(Date.now()).slice(-5)}` };
}

/// Poll `find` (answers a value or null) every second until it answers; fail after
/// `seconds`, naming `what`.
async function waitFor(what, find, seconds = 60) {
  const deadline = Date.now() + seconds * 1000;
  while (Date.now() < deadline) {
    const v = await find().catch(() => null);
    if (v) return v;
    await new Promise((r) => setTimeout(r, 1000));
  }
  throw new Error(`${what} did not arrive within ${seconds} s`);
}

/// The first group of `re` (or its whole match) in an email to `to` received since
/// `after`, from Mailpit's API.
async function fromMail(to, re, after) {
  return waitFor(`an email to ${to} matching ${re}`, async () => {
    const res = await fetch(`${MAIL}/api/v1/search?query=${encodeURIComponent(`to:"${to}"`)}`);
    if (!res.ok) return null;
    for (const m of (await res.json()).messages || []) {
      if (Date.parse(m.Created) < after) continue;
      const full = await (await fetch(`${MAIL}/api/v1/message/${encodeURIComponent(m.ID)}`)).json();
      const hit = `${full.Text || ""}\n${full.HTML || ""}`.match(re);
      if (hit) return hit[1] ?? hit[0];
    }
    return null;
  });
}

/// The code in the newest `channel` message to `to` received since `after`, from the SMS
/// gateway stub. A spoken code reads its digits one by one ("1, 2, 3, …").
async function fromPhone(to, channel, after) {
  return waitFor(`a ${channel} message to ${to}`, async () => {
    const res = await fetch(`${SMS}/messages?to=${encodeURIComponent(to)}`);
    if (!res.ok) return null;
    const m = ((await res.json()).messages || []).find((x) => x.channel === channel && x.received * 1000 >= after);
    const digits = m?.text.match(/code is ([\d, ]+)/)?.[1].replace(/\D/g, "");
    return digits?.length === 6 ? digits : null;
  });
}

/// A sent envelope with one signer, Ana, described by `recipient`; answers the signing
/// link. Mock: made through the mock client in this tab (the signing page finds it in
/// the tab's session storage). Real: made through the API as the run's sender, with a
/// disclosure published first when the account has none (consent and its withdrawal
/// need one); the link is the one the worker emailed.
async function sentTo(page, recipient) {
  if (REAL) await signIn(page, "home");
  else await page.goto(signPage("none"));
  const started = Date.now() - 5_000;
  const token = await page.evaluate(async ({ r, email, password, real }) => {
    const at = (f) => new URL(`/${f}`, location.origin).href;
    const { createClient } = await import(at("api.js"));
    const { makePdf } = await import(at("mockpdf.js"));
    let c;
    if (real) {
      c = createClient({ store: sessionStorage });
      const ersd = await c.ersd.get();
      if (!ersd.current) await c.ersd.publish({ text: "We give you the records of this agreement electronically. You may withdraw this consent at any time from the signing page." });
    } else {
      const { createMockFetch } = await import(at("mock.js"));
      c = createClient({ fetch: createMockFetch({ store: sessionStorage }), store: sessionStorage });
      await c.login(email, password);
    }
    const pdf = makePdf([{ title: "Slice 5" }]);
    const env = await c.createEnvelope({
      subject: "Slice 5 identity",
      documents: [{ name: "a.pdf", content_base64: btoa(String.fromCharCode(...pdf)) }],
      recipients: [{ ref: "r1", type: "signer", name: "Ana Signer", ...r }],
      fields: [{ recipient: "r1", document: 0, type: "signature", page: 1, x: "72", y: "600", width: "160", height: "44", required: true }],
    });
    const sent = await c.sendEnvelope(env.id);
    return sent.recipients[0].mock_token || null;
  }, { r: recipient, email: MOCK.email, password: MOCK.password, real: REAL });
  if (!REAL) return signPage(token);
  return fromMail(recipient.email, /https?:\/\/[^\s"'<>]+\/s\/[A-Za-z0-9._~%-]+/, started);
}

/// Where the signer signs. Mock: this tab (the mock's data is in it). Real: a new
/// context, a phone or a desktop, recorded; `done()` closes it and keeps the video as
/// target/e2e-demo/vs05-<project>-<step>.webm.
async function signerPage(page, browser, testInfo, step, phone) {
  if (!REAL) return { sp: page, done: async () => {} };
  const size = phone ? { width: 390, height: 844 } : { width: 1280, height: 800 };
  const opts = phone ? { ...devices["iPhone 13"] } : { viewport: size };
  delete opts.defaultBrowserType;
  const ctx = await browser.newContext({ ...opts, recordVideo: { dir: testInfo.outputPath("video"), size } });
  const sp = await ctx.newPage();
  return {
    sp,
    done: async () => {
      await ctx.close();
      fs.mkdirSync(DEMO, { recursive: true });
      await sp.video()?.saveAs(path.join(DEMO, `vs05-${testInfo.project.name}-${step}.webm`));
    },
  };
}

async function accessCode(page) {
  await expect(page.getByRole("heading", { name: "Enter your access code" })).toBeVisible();
  await page.getByLabel("Access code").fill(ACCESS_CODE);
  await page.getByRole("button", { name: "Continue" }).click();
}

/// The server spaces one recipient's sent codes 30 s apart (all channels together) and
/// counts every request against a link's 3 a minute, refused or not (ceremony.rs
/// `otp_send`), so the real run waits out the spacing instead of asking repeatedly.
const CODE_SPACING_MS = 31_000;

/// Ask for a code (`testid`'s button) on the step titled `title`, `since` the previous
/// ask (`{at}`, updated), until the page says it was sent; answers when it was asked.
async function ask(page, title, testid, since = { at: 0 }) {
  await expect(page.getByRole("heading", { name: title })).toBeVisible();
  const wait = REAL ? since.at + CODE_SPACING_MS - Date.now() : 0;
  // A wait the server's documented limit sets, not a guess at timing.
  if (wait > 0) await page.waitForTimeout(wait);
  let asked = 0;
  await expect(async () => {
    asked = Date.now() - 2_000;
    await page.getByTestId(`${testid}-send`).click();
    await expect(page.locator("#otp-status")).not.toBeEmpty({ timeout: 3_000 });
  }).toPass({ timeout: 90_000, intervals: [15_000] });
  since.at = Date.now();
  return asked;
}

/// One sent-code step: ask, read the code where it went (`read(asked)`; the mock's code
/// in mock mode), enter it.
async function code(page, title, testid, read, since) {
  const asked = await ask(page, title, testid, since);
  await page.getByLabel("6-digit code").fill(REAL ? await read(asked) : MOCK.emailCode);
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

test("an access code, codes by email, text message and phone call, then consent and its withdrawal", async ({ page, browser }, testInfo) => {
  // Three sent codes, 30 s apart on the real stack.
  test.setTimeout(REAL ? 300_000 : 60_000);
  const who = signerOf(testInfo);
  const link = await sentTo(page, { email: who.email, phone: who.phone, auth: CODES, access_code: ACCESS_CODE });
  const { sp, done } = await signerPage(page, browser, testInfo, "codes-on-a-phone", true);
  await sp.goto(link, { waitUntil: "domcontentloaded" });
  await accessCode(sp);
  const since = { at: 0 };
  await code(sp, "Check your email", "email-code", (after) => fromMail(who.email, /Your code: (\d{6})/, after), since);
  await code(sp, "Check your phone", "sms-code", (after) => fromPhone(who.phone, "sms", after), since);
  await code(sp, "Get a code by phone call", "voice-code", (after) => fromPhone(who.phone, "voice", after), since);
  await consentThenWithdraw(sp);
  await done();
});

test("sign-in through an identity provider comes back to the signing page", async ({ page, browser }, testInfo) => {
  test.setTimeout(REAL ? 180_000 : 60_000);
  const who = signerOf(testInfo);
  const link = await sentTo(page, { email: who.email, auth: ["sso"] });
  const token = decodeURIComponent(new URL(link, "http://x").pathname.split("/").pop());
  const { sp, done } = await signerPage(page, browser, testInfo, "identity-provider-sign-in", false);
  await sp.goto(link, { waitUntil: "domcontentloaded" });
  await expect(sp.getByRole("heading", { name: "Sign in to continue" })).toBeVisible();
  await sp.getByRole("button", { name: `Sign in with ${PROVIDER}` }).click();
  if (REAL) {
    // The provider's own page (the CI stub): the signer signs in with the address the
    // sender used; the provider asserts it, verified, in the ID token.
    await sp.waitForURL(/^http:\/\/localhost:8090\/authorize\?/);
    await expect(sp.getByRole("heading", { name: "Sign in", exact: true })).toBeVisible();
    await sp.getByLabel("Email").fill(who.email);
    await sp.getByRole("button", { name: "Sign in", exact: true }).click();
  }
  // Back from the provider: the address shows the link again, and the sign-in passed.
  await expect(sp.getByRole("heading", { name: "Electronic records and signatures" })).toBeVisible();
  await expect(sp).toHaveURL(new RegExp(`/s/${token.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}$`));
  await consentThenWithdraw(sp);
  await done();
});

for (const scheme of ["light", "dark"]) {
  test(`the code entry, sign-in and withdraw steps are accessible (${scheme})`, async ({ page }, testInfo) => {
    test.skip(REAL, "mock mode: the real run serves the same screens (RAUTH-02 runs the flow there)");
    await page.addInitScript((s) => { try { localStorage.setItem("openseal.theme", s); } catch { /* storage off */ } }, scheme);
    await page.emulateMedia({ colorScheme: scheme });
    await page.setViewportSize({ width: 390, height: 844 });
    const who = signerOf(testInfo);
    await page.goto(await sentTo(page, { email: who.email, phone: who.phone, auth: [...CODES, "sso"], access_code: ACCESS_CODE }));

    await expect(page.getByRole("heading", { name: "Enter your access code" })).toBeVisible();
    await expectAccessible(page, `access code (${scheme})`);
    await accessCode(page);
    for (const [title, testid] of [["Check your email", "email-code"], ["Check your phone", "sms-code"], ["Get a code by phone call", "voice-code"]]) {
      await expect(page.getByRole("heading", { name: title })).toBeVisible();
      await expectAccessible(page, `${testid} entry (${scheme})`);
      await ask(page, title, testid);
      await expectAccessible(page, `${testid} sent (${scheme})`);
      if (testid === "email-code") {
        // A wrong code: the error is announced, and the step stays usable.
        await page.getByLabel("6-digit code").fill("000000");
        await page.getByRole("button", { name: "Continue" }).click();
        await expect(page.locator("#otp-err")).not.toBeEmpty();
        await expectAccessible(page, `${testid} wrong code (${scheme})`);
      }
      await page.getByLabel("6-digit code").fill(MOCK.emailCode);
      await page.getByRole("button", { name: "Continue" }).click();
    }
    await expect(page.getByRole("heading", { name: "Sign in to continue" })).toBeVisible();
    await expectAccessible(page, `identity provider sign-in (${scheme})`);
    await page.getByRole("button", { name: `Sign in with ${PROVIDER}` }).click();

    await expect(page.getByRole("heading", { name: "Electronic records and signatures" })).toBeVisible();
    await page.getByLabel("I agree to use electronic records and signatures.").check();
    await page.getByRole("button", { name: "Continue" }).click();
    await expect(page.locator("#guide-progress")).toHaveText("0 of 1 required");
    await page.getByRole("button", { name: "More" }).click();
    await page.getByRole("menuitem", { name: "Withdraw consent to electronic records" }).click();
    const dlg = page.getByRole("dialog", { name: "Withdraw your consent?" });
    await expect(dlg).toBeVisible();
    await expectAccessible(page, `withdraw consent dialog (${scheme})`);
    await dlg.getByRole("button", { name: "Withdraw consent" }).click();
    await expect(page.getByTestId("sign-withdrawn")).toBeVisible();
    await expectAccessible(page, `consent withdrawn (${scheme})`);
  });
}
