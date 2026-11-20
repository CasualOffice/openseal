// RSP-01 (ADR-046), in a browser: a recipient signs with their own certificate at a CSC
// API v2 provider, between two simple signers.
//
// Real stack (CI's compose-e2e, with tools/e2e/compose.e2e.yml's `csc` stub, which signs
// with `openssl`): Admin makes an API key, enables the CI provider for the workspace
// (`PUT /signing-providers/csc-ci`) and sends an envelope to a simple signer, a remote
// signer and another simple signer, in that order. Each signs on the link the worker
// emailed (read from Mailpit); the remote signer reviews, chooses "Sign with <provider>",
// logs in at the provider (scope `service`), is shown the prepared documents, authorizes
// them at the provider (scope `credential`, bound to their hashes) and is done. The
// sealed PDF and the separate certificate of completion are written to
// target/e2e-sealed/ for pyHanko (tools/verify-sealed.py, the job's next step) and our
// verifier; the remote signer's screens are recorded into target/e2e-demo/rsp01-*.webm,
// uploaded as `rsp-01-demo`. A refusal at the provider ("Deny") fails the session and
// the signer can start again.
//
// Mock mode (chromium and webkit): the mock's provider answers at once on the same
// page, so the page's steps (Sign with, the progress, authorize, done) run with axe on
// each screen, light and dark.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { test, expect } from "@playwright/test";
import { signIn, REAL, app, signPage, expectAccessible } from "./helpers.mjs";
import { MOCK } from "../mock.js";
import { makePdf } from "../mockpdf.js";

const BASE = (process.env.OPENSEAL_E2E_BASE_URL || "").replace(/\/$/, "");
const MAIL = (process.env.OPENSEAL_E2E_MAIL_URL || "http://127.0.0.1:8025").replace(/\/$/, "");
const OUT = path.resolve(fileURLToPath(new URL("../../target/e2e-sealed", import.meta.url)));
const DEMO = path.resolve(fileURLToPath(new URL("../../target/e2e-demo", import.meta.url)));
const PROVIDER = REAL ? "OpenSeal CI signing provider" : "Demo CSC provider";
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

/// Admin's API key (the integrator's), as the embedding spec makes it.
async function adminKey(page, run) {
  await page.goto(app("#/admin?section=api"));
  await page.getByRole("button", { name: "New API client" }).first().click();
  const panel = page.getByRole("dialog", { name: "New API client" });
  await panel.getByLabel("Name", { exact: true }).fill(`RSP-01 ${run}`);
  await panel.getByLabel("Kind").selectOption("api_key");
  await panel.locator("#c-scope-admin-account").check();
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
      headers: { authorization: `Bearer ${key}`, "content-type": "application/json", ...(method === "POST" ? { "idempotency-key": `rsp01-${run}-${++n}` } : {}) },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    if (raw) return r;
    const text = await r.text();
    expect(r.ok, `${method} ${p}: ${r.status} ${text}`).toBe(true);
    return text ? JSON.parse(text) : null;
  };
}

/// Consent (when the account asks for it) and the signature adopted, on an open link.
async function fillSignature(page) {
  const consent = page.getByRole("heading", { name: "Electronic records and signatures" });
  const progress = page.locator("#guide-progress");
  await expect(consent.or(progress).first()).toBeVisible({ timeout: 30_000 });
  if (await consent.isVisible()) {
    await page.getByLabel("I agree to use electronic records and signatures.").check();
    await page.getByRole("button", { name: "Continue" }).click();
  }
  await page.getByRole("button", { name: /Signature, required/ }).click();
  const dlg = page.getByRole("dialog", { name: "Adopt your signature" });
  await dlg.getByTestId("adopt-confirm").click();
  await expect(dlg).toBeHidden();
  await page.getByRole("button", { name: "Finish" }).click();
  await expect(page.getByRole("heading", { name: "Review and finish" })).toBeVisible();
}

async function simpleSigner(browser, link, last) {
  const context = await browser.newContext();
  const page = await context.newPage();
  await page.goto(link, { waitUntil: "domcontentloaded" });
  await fillSignature(page);
  await page.getByTestId("review-finish").click();
  await expect(page.getByTestId("sign-done")).toContainText(last ? "Everyone has signed" : "Your part is done", { timeout: 120_000 });
  await context.close();
}

/// At the provider's consent page: Allow (or Deny).
async function atProvider(page, decision = "Allow") {
  await page.waitForURL(/\/oauth2\/authorize\?/, { timeout: 30_000 });
  await expect(page.getByRole("heading", { name: "CI signing provider" })).toBeVisible();
  await page.getByRole("button", { name: decision }).click();
}

test("a remote signer signs with their provider between two simple signers; the sealed PDF verifies", async ({ browser, page }, testInfo) => {
  test.skip(!REAL, "the provider stub runs on the Compose stack only; the mock flow is below");
  test.setTimeout(480_000);
  const run = `${Date.now()}-${testInfo.project.name}`;
  await signIn(page);
  const key = await adminKey(page, run);
  const call = api(key, run);
  const providers = await call("GET", "/signing-providers");
  expect(providers.items.map((p) => p.id)).toContain("csc-ci");
  await call("PUT", "/signing-providers/csc-ci", { enabled: true });
  const pdf = Buffer.from(makePdf([{ title: "Supply agreement", lines: ["Signed by three parties; the second with their own certificate."] }])).toString("base64");
  const who = (r) => `${r}-${run}@example.com`;
  const env = await call("POST", "/envelopes", {
    subject: `RSP-01 remote signing ${run}`,
    status: "sent",
    documents: [{ name: "supply.pdf", content_base64: pdf }],
    recipients: [
      { ref: "a", type: "signer", name: "Ada Simple", email: who("ada"), routing_order: 1 },
      { ref: "r", type: "signer", name: "Remote Signer", email: who("remote"), routing_order: 2, signature: { type: "remote", provider_id: "csc-ci" } },
      { ref: "c", type: "signer", name: "Cy Simple", email: who("cy"), routing_order: 3 },
    ],
    fields: [
      { recipient: "a", document: 0, type: "signature", page: 1, x: 72, y: 520, width: 160, height: 40, required: true },
      { recipient: "r", document: 0, type: "signature", page: 1, x: 72, y: 600, width: 200, height: 60, required: true },
      { recipient: "c", document: 0, type: "signature", page: 1, x: 300, y: 520, width: 160, height: 40, required: true },
    ],
  });
  await simpleSigner(browser, await signingLink(who("ada")), false);

  // The remote signer, recorded as the RSP-01 demo.
  const context = await browser.newContext({ recordVideo: { dir: DEMO, size: SIZE }, viewport: SIZE });
  const rp = await context.newPage();
  await rp.goto(await signingLink(who("remote")), { waitUntil: "domcontentloaded" });
  await fillSignature(rp);
  // A refusal at the provider fails the session; the signer starts again.
  await rp.getByTestId("review-finish").filter({ hasText: `Sign with ${PROVIDER}` }).click();
  await atProvider(rp, "Deny");
  await expect(rp.getByTestId("remote-failed")).toBeVisible({ timeout: 30_000 });
  await rp.getByRole("button", { name: "Start again" }).click();
  await expect(rp.locator("#guide-progress").or(rp.getByRole("heading", { name: "Review and finish" })).first()).toBeVisible({ timeout: 30_000 });
  if (await rp.getByRole("button", { name: "Finish" }).isVisible()) await rp.getByRole("button", { name: "Finish" }).click();
  await rp.getByTestId("review-finish").click();
  await atProvider(rp);
  // Back: the worker prepares the documents; the signer authorizes those exact hashes.
  await expect(rp.getByTestId("remote-ready")).toBeVisible({ timeout: 120_000 });
  await expectAccessible(rp, "the remote signer's ready step");
  await rp.getByTestId("remote-authorize").click();
  await atProvider(rp);
  await expect(rp.getByTestId("sign-done")).toContainText("Your part is done", { timeout: 120_000 });
  const video = rp.video();
  await context.close();
  if (video) fs.renameSync(await video.path(), path.join(DEMO, `rsp01-${testInfo.project.name}-remote-signer.webm`));

  await simpleSigner(browser, await signingLink(who("cy")), true);

  // Completed: the sealed PDF (remote signature, its DSS, the last fill, the platform seal
  // last) and the separate certificate of completion.
  const deadline = Date.now() + 120_000;
  let done = null;
  while (Date.now() < deadline) {
    done = await call("GET", `/envelopes/${env.id}`);
    if (done.status === "completed") break;
    await new Promise((r) => setTimeout(r, 2000));
  }
  expect(done.status).toBe("completed");
  const audit = await call("GET", `/envelopes/${env.id}/audit`);
  const types = (audit.items || []).map((i) => i.type);
  for (const t of ["recipient.remote_signing_started", "recipient.remote_signing_prepared", "recipient.remote_signing_failed", "recipient.remote_signed"]) {
    expect(types, t).toContain(t);
  }
  fs.mkdirSync(OUT, { recursive: true });
  const doc = done.documents[0].id;
  const sealed = Buffer.from(await (await call("GET", `/envelopes/${env.id}/documents/${doc}/content`, undefined, true)).arrayBuffer());
  const certificate = Buffer.from(await (await call("GET", `/envelopes/${env.id}/certificate`, undefined, true)).arrayBuffer());
  expect(sealed.subarray(0, 5).toString()).toBe("%PDF-");
  // Three signatures: the remote signer's, then the platform seal; nothing appended.
  expect((sealed.toString("latin1").match(/\/Type\s*\/Sig\b/g) || []).length).toBeGreaterThanOrEqual(2);
  const name = `rsp01-${testInfo.project.name}`;
  fs.writeFileSync(path.join(OUT, `${name}-sealed.pdf`), sealed);
  fs.writeFileSync(path.join(OUT, `${name}-certificate.pdf`), certificate);
  const manifest = path.join(OUT, "manifest.tsv");
  if (!fs.existsSync(manifest)) fs.writeFileSync(manifest, "file\texpect\twhy\tlevel\n");
  fs.appendFileSync(manifest, `${name}-sealed.pdf\tintact\tRSP-01 remote signature then the platform seal, ${testInfo.project.name}\tB-T\n`);
  fs.appendFileSync(manifest, `${name}-certificate.pdf\tintact\tRSP-01 certificate of completion, ${testInfo.project.name}\tB-T\n`);
});

test("mock: Sign with the provider, authorize the prepared documents, done; each step accessible", async ({ page }) => {
  test.skip(REAL, "the mock's provider; the real stack runs the test above");
  await page.addInitScript(() => { try { sessionStorage.setItem("openseal.mock.rsp", "1"); } catch { /* none */ } });
  await page.goto(signPage(MOCK.remoteSignToken));
  await fillSignature(page);
  const go = page.getByTestId("review-finish");
  await expect(go).toHaveText(`Sign with ${PROVIDER}`);
  await expectAccessible(page, "the remote signer's review");
  await go.click();
  await expect(page.getByTestId("remote-ready")).toBeVisible({ timeout: 30_000 });
  await expectAccessible(page, "the remote signer's ready step");
  await page.getByTestId("remote-authorize").click();
  await expect(page.getByTestId("sign-done")).toBeVisible({ timeout: 30_000 });
  await expectAccessible(page, "the remote signer's done step");
});
