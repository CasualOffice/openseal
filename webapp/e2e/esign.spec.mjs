// RSP-02 (ADR-047), in a browser: a recipient signs with India eSign through a licensed
// ESP, OpenSeal the ASP, then a simple signer finishes.
//
// Real stack (CI's compose-e2e, with tools/e2e/compose.e2e.yml's `esign` stub: xmlsec1
// for the XML Signatures, `openssl` for the CMS): Admin makes an API key, enables the CI
// ESP for the workspace (`PUT /signing-providers/esign-ci`) and sends an envelope of two
// documents to an eSign signer and then a simple signer. The eSign signer reviews,
// chooses "Sign with eSign", reads and ticks the consent (unticked by default) and
// chooses OTP; cancels once at the ESP (`ESP-944`: the session fails and they start
// again); then, per document ("document 1 of 2", "2 of 2"), continues to the ESP, enters a
// made-up 12-digit number and a code there (never on our pages) and returns. The stub
// checked each request with xmlsec1 against the ASP certificate and found no Aadhaar data
// in it (`GET /requests`). The sealed PDFs and the certificate of completion are written to
// target/e2e-sealed/ for pyHanko, EU DSS and our verifier (the job's next steps); the
// eSign signer's screens are recorded into target/e2e-demo/rsp02-*.webm, uploaded as
// `rsp-02-demo`.
//
// Mock mode (chromium and webkit): the mock's ESP answers at once, so the page's steps
// (Sign with eSign, the consent, continue, done) run with axe on each screen.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { test, expect } from "@playwright/test";
import { signIn, REAL, app, signPage, expectAccessible } from "./helpers.mjs";
import { MOCK } from "../mock.js";
import { makePdf } from "../mockpdf.js";

const BASE = (process.env.OPENSEAL_E2E_BASE_URL || "").replace(/\/$/, "");
const MAIL = (process.env.OPENSEAL_E2E_MAIL_URL || "http://127.0.0.1:8025").replace(/\/$/, "");
const ESP = (process.env.OPENSEAL_E2E_ESIGN_URL || "http://127.0.0.1:8092").replace(/\/$/, "");
const OUT = path.resolve(fileURLToPath(new URL("../../target/e2e-sealed", import.meta.url)));
const DEMO = path.resolve(fileURLToPath(new URL("../../target/e2e-demo", import.meta.url)));
const PROVIDER = REAL ? "OpenSeal CI eSign provider" : "Demo eSign provider";
const SIZE = { width: 1280, height: 800 };

test.use({ video: REAL ? { mode: "on", size: SIZE } : "off" });

async function signingLink(to) {
  const deadline = Date.now() + 90_000;
  while (Date.now() < deadline) {
    const res = await fetch(`${MAIL}/api/v1/search?query=${encodeURIComponent(`to:"${to}"`)}`);
    if (res.ok) {
      for (const m of (await res.json()).messages || []) {
        const full = await (await fetch(`${MAIL}/api/v1/message/${encodeURIComponent(m.ID)}`)).json();
        const link = `${full.Text || ""}\n${full.HTML || ""}`.match(/https?:\/\/[^\s"'<>]+\/s\/[A-Za-z0-9._~%-]+/);
        if (link) return link[0];
      }
    }
    await new Promise((r) => setTimeout(r, 1000));
  }
  throw new Error(`no signing link emailed to ${to} within 90 s`);
}

async function adminKey(page, run) {
  await page.goto(app("#/admin?section=api"));
  await page.getByRole("button", { name: "New API client" }).first().click();
  const panel = page.getByRole("dialog", { name: "New API client" });
  await panel.getByLabel("Name", { exact: true }).fill(`RSP-02 ${run}`);
  await panel.getByLabel("Kind").selectOption("api_key");
  await panel.locator("#c-scope-admin-account").check();
  await panel.locator("#c-scope-audit-read").check();
  await panel.getByRole("button", { name: "Create" }).click();
  const secret = page.getByRole("dialog", { name: "Copy the secret now" });
  await expect(secret).toBeVisible();
  const [key] = await secret.getByTestId("secret-value").evaluateAll((els) => els.map((e) => e.value));
  await secret.getByRole("button", { name: "I have copied it" }).click();
  return key;
}

function api(key, run) {
  let n = 0;
  return async (method, p, body, raw = false) => {
    const r = await fetch(`${BASE}/api/v1${p}`, {
      method,
      headers: { authorization: `Bearer ${key}`, "content-type": "application/json", ...(method === "POST" ? { "idempotency-key": `rsp02-${run}-${++n}` } : {}) },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    if (raw) return r;
    const text = await r.text();
    expect(r.ok, `${method} ${p}: ${r.status} ${text}`).toBe(true);
    return text ? JSON.parse(text) : null;
  };
}

async function fillSignature(page) {
  const consent = page.getByRole("heading", { name: "Electronic records and signatures" });
  const progress = page.locator("#guide-progress");
  await expect(consent.or(progress).first()).toBeVisible({ timeout: 30_000 });
  if (await consent.isVisible()) {
    await page.getByLabel("I agree to use electronic records and signatures.").check();
    await page.getByRole("button", { name: "Continue" }).click();
  }
  // One signature field per document (the real-stack test sends two documents): the
  // first opens the adopt panel; each later one takes the adopted signature, or opens the
  // panel again; the fields keep their label, so each is taken by position.
  const fields = page.getByRole("button", { name: /Signature, required/ });
  const dlg = page.getByRole("dialog", { name: "Adopt your signature" });
  await expect(fields.first()).toBeVisible();
  const total = await fields.count();
  expect(total).toBeGreaterThan(0);
  for (let i = 0; i < total; i += 1) {
    await fields.nth(i).click();
    if (await dlg.waitFor({ state: "visible", timeout: 2000 }).then(() => true, () => false)) {
      await dlg.getByTestId("adopt-confirm").click();
      await expect(dlg).toBeHidden();
    }
  }
  await page.getByRole("button", { name: "Finish" }).click();
  await expect(page.getByRole("heading", { name: "Review and finish" })).toBeVisible();
}

/// The eSign consent: shown, unticked, and the start enabled only once ticked.
async function consent(page) {
  await page.getByTestId("review-finish").filter({ hasText: "Sign with" }).click();
  const card = page.getByTestId("esign-consent-card");
  await expect(card).toBeVisible();
  await expect(card.getByTestId("esign-consent-text")).toContainText("OpenSeal never receives them");
  await expect(card.getByTestId("esign-consent")).not.toBeChecked();
  await expect(card.getByTestId("esign-start")).toBeDisabled();
  await expectAccessible(page, "the eSign consent");
  await card.getByTestId("esign-consent").check();
  await card.getByTestId("esign-mode-otp").check();
  await card.getByTestId("esign-start").click();
}

/// At the stub ESP's page: authenticate and sign (or cancel).
async function atEsp(page, decision = "sign") {
  await page.waitForURL(/\/esign\/2\.1\/signdoc/, { timeout: 30_000 });
  await expect(page.getByRole("heading", { name: "CI eSign Service Provider" })).toBeVisible();
  if (decision === "sign") {
    await page.getByTestId("esp-uid").fill("999988887777");
    await page.getByTestId("esp-otp").fill("123456");
    await page.getByTestId("esp-sign").click();
  } else {
    await page.getByTestId("esp-cancel").click();
  }
}

test("an eSign signer signs two documents through the ESP; the requests verify and carry no Aadhaar data", async ({ browser, page }, testInfo) => {
  test.skip(!REAL, "the ESP stub runs on the Compose stack only; the mock flow is below");
  test.setTimeout(600_000);
  const run = `${Date.now()}-${testInfo.project.name}`;
  await signIn(page);
  const key = await adminKey(page, run);
  const call = api(key, run);
  expect((await call("GET", "/signing-providers")).items.map((p) => p.id)).toContain("esign-ci");
  await call("PUT", "/signing-providers/esign-ci", { enabled: true });
  const doc = (title) => Buffer.from(makePdf([{ title, lines: ["Signed with eSign, then by a second party."] }])).toString("base64");
  const who = (r) => `${r}-${run}@example.com`;
  const env = await call("POST", "/envelopes", {
    subject: `RSP-02 eSign ${run}`,
    status: "sent",
    documents: [{ name: "lease-deed.pdf", content_base64: doc("Lease deed") }, { name: "schedule.pdf", content_base64: doc("Schedule A") }],
    recipients: [
      { ref: "e", type: "signer", name: "Asha Esign", email: who("asha"), routing_order: 1, signature: { type: "remote", provider_id: "esign-ci" } },
      { ref: "c", type: "signer", name: "Cy Simple", email: who("cy"), routing_order: 2 },
    ],
    fields: [
      { recipient: "e", document: 0, type: "signature", page: 1, x: 72, y: 600, width: 200, height: 60, required: true },
      { recipient: "e", document: 1, type: "signature", page: 1, x: 72, y: 600, width: 200, height: 60, required: true },
      { recipient: "c", document: 0, type: "signature", page: 1, x: 300, y: 520, width: 160, height: 40, required: true },
    ],
  });
  const context = await browser.newContext({ recordVideo: { dir: DEMO, size: SIZE }, viewport: SIZE });
  const ep = await context.newPage();
  await ep.goto(await signingLink(who("asha")), { waitUntil: "domcontentloaded" });
  await fillSignature(ep);
  await consent(ep);
  // Cancelled at the ESP: the session fails, nothing is signed, the signer starts again.
  await expect(ep.getByTestId("esign-continue")).toBeVisible({ timeout: 120_000 });
  await ep.getByTestId("esign-continue").click();
  await atEsp(ep, "cancel");
  await expect(ep.getByTestId("remote-failed")).toBeVisible({ timeout: 60_000 });
  await ep.getByRole("button", { name: "Start again" }).click();
  await expect(ep.locator("#guide-progress").or(ep.getByRole("heading", { name: "Review and finish" })).first()).toBeVisible({ timeout: 30_000 });
  if (await ep.getByRole("button", { name: "Finish" }).isVisible()) await ep.getByRole("button", { name: "Finish" }).click();
  await consent(ep);
  for (let n = 1; n <= 2; n++) {
    await expect(ep.getByTestId("esign-continue")).toBeVisible({ timeout: 120_000 });
    await expectAccessible(ep, `the eSign ready step, document ${n}`);
    await ep.getByTestId("esign-continue").click();
    await atEsp(ep);
  }
  await expect(ep.getByTestId("sign-done")).toContainText("Your part is done", { timeout: 180_000 });
  const video = ep.video();
  await context.close();
  if (video) fs.renameSync(await video.path(), path.join(DEMO, `rsp02-${testInfo.project.name}-esign-signer.webm`));

  // Every request the stub took verified under xmlsec1 and carried no Aadhaar data.
  const seen = (await (await fetch(`${ESP}/requests`)).json()).requests;
  expect(seen.length).toBeGreaterThanOrEqual(3);
  for (const r of seen) {
    expect(r.verified, "xmlsec1 verified the ASP's request").toBe(true);
    expect(r.aadhaar_free, "no Aadhaar data in the request").toBe(true);
    expect(r.sc).toBe("Y");
  }

  // The simple signer finishes; the envelope completes.
  const c2 = await browser.newContext();
  const cp = await c2.newPage();
  await cp.goto(await signingLink(who("cy")), { waitUntil: "domcontentloaded" });
  await fillSignature(cp);
  await cp.getByTestId("review-finish").click();
  await expect(cp.getByTestId("sign-done")).toContainText("Everyone has signed", { timeout: 120_000 });
  await c2.close();
  const deadline = Date.now() + 120_000;
  let done = null;
  while (Date.now() < deadline) {
    done = await call("GET", `/envelopes/${env.id}`);
    if (done.status === "completed") break;
    await new Promise((r) => setTimeout(r, 2000));
  }
  expect(done.status).toBe("completed");
  const audit = await call("GET", `/envelopes/${env.id}/audit`);
  const items = audit.items || [];
  const types = items.map((i) => i.type);
  for (const t of ["recipient.remote_signing_started", "recipient.remote_signing_prepared", "recipient.remote_signing_failed", "recipient.remote_signed"]) {
    expect(types, t).toContain(t);
  }
  const failed = items.find((i) => i.type === "recipient.remote_signing_failed");
  expect(JSON.stringify(failed)).toContain("ESP-944");
  fs.mkdirSync(OUT, { recursive: true });
  const name = `rsp02-${testInfo.project.name}`;
  const manifest = path.join(OUT, "manifest.tsv");
  if (!fs.existsSync(manifest)) fs.writeFileSync(manifest, "file\texpect\twhy\tlevel\n");
  for (const [i, d] of done.documents.entries()) {
    const sealed = Buffer.from(await (await call("GET", `/envelopes/${env.id}/documents/${d.id}/content?version=sealed`, undefined, true)).arrayBuffer());
    expect(sealed.subarray(0, 5).toString()).toBe("%PDF-");
    // The eSign signature, then the platform seal.
    expect((sealed.toString("latin1").match(/\/ByteRange\s*\[/g) || []).length).toBe(2);
    fs.writeFileSync(path.join(OUT, `${name}-sealed-${i}.pdf`), sealed);
    fs.appendFileSync(manifest, `${name}-sealed-${i}.pdf\tintact\tRSP-02 eSign signature then the platform seal, ${testInfo.project.name}\tB-T\n`);
  }
  const certificate = Buffer.from(await (await call("GET", `/envelopes/${env.id}/certificate`, undefined, true)).arrayBuffer());
  fs.writeFileSync(path.join(OUT, `${name}-certificate.pdf`), certificate);
  fs.appendFileSync(manifest, `${name}-certificate.pdf\tintact\tRSP-02 certificate of completion, ${testInfo.project.name}\tB-T\n`);
});

test("mock: Sign with eSign, the consent, continue to the ESP, done; each step accessible", async ({ page }) => {
  test.skip(REAL, "the mock's ESP; the real stack runs the test above");
  await page.addInitScript(() => { try { sessionStorage.setItem("openseal.mock.rsp", "1"); } catch { /* none */ } });
  await page.goto(signPage(MOCK.esignSignToken));
  await fillSignature(page);
  await expect(page.getByTestId("review-finish")).toHaveText(`Sign with ${PROVIDER}`);
  await expectAccessible(page, "the eSign signer's review");
  await consent(page);
  await expect(page.getByTestId("esign-continue")).toBeVisible({ timeout: 30_000 });
  await expectAccessible(page, "the eSign ready step");
  await page.getByTestId("esign-continue").click();
  await expect(page.getByTestId("sign-done")).toBeVisible({ timeout: 30_000 });
  await expectAccessible(page, "the eSign signer's done step");
});
