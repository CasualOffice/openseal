// VS-09E (slice 9, embedding), in a browser: a host page on another origin and site
// (the example host page `sdk/embed/example/index.html`, served by this spec on the other
// loopback name: `http://localhost:<p>` for OpenSeal at `http://127.0.0.1:<port>` and
// back; a real server on loopback, since a browser lets only a loopback page load a
// loopback server's script, Private Network Access) loads `openseal-elements.js` from OpenSeal and embeds a
// signing view, a prepare view and a correct view, and hears their events: the signer
// signs (`openseal:complete`), another declines (`openseal:decline`), the sender sends a
// draft from the embedded editor (`openseal:complete`), and leaves the correct panel
// (`openseal:cancel`). A page on an origin the workspace does not allow cannot frame a
// view (the server's `frame-ancestors`, `openseal:error` on the element's timeout), and a
// message the host page forges is not taken for the view's. Axe scans the embedded
// views and Admin's Embedding card, light and dark.
//
// Both modes. In mock mode the views are the mock's seeded links (mock.js
// `MOCK.embed*Token`, framed by `embedOriginFor` as tools/serve-webapp.py lets them).
// On the Compose deployment (compose-e2e) Admin makes an API key with `admin:account`,
// which allows the host page's origin (`embedding_origins`) and, as the integrator's
// server does, creates the envelopes and asks for each view with `frame_origin`,
// `return_url` and `state`; every screen is recorded as the slice 9 demo
// (target/e2e-demo/vs09-*, uploaded by compose-e2e as `slice-9-demo`).
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { test, expect } from "@playwright/test";
import { signIn, REAL, app, expectAccessible } from "./helpers.mjs";
import { MOCK, embedOriginFor } from "../mock.js";
import { makePdf } from "../mockpdf.js";

const BASE = (process.env.OPENSEAL_E2E_BASE_URL || "").replace(/\/$/, "");
const OS = new URL(BASE || `http://127.0.0.1:${process.env.OPENSEAL_E2E_PORT ?? 8131}`);
const OTHER = OS.hostname === "localhost" ? "127.0.0.1" : "localhost";
const PAGE = "/embed-host/";
/// The host page, on the other loopback name (another site): in mock mode the port the
/// mock and tools/serve-webapp.py allow (mock.js `embedOriginFor`), on the real stack any
/// free one (the run allows it through the API). A page on OpenSeal's own name and the
/// host's port is another origin the workspace does not allow.
let HOST = embedOriginFor(OS);
let EVIL = null;
let server = null;

test.beforeAll(async () => {
  server = http.createServer((_req, res) => {
    res.writeHead(200, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" });
    res.end(EXAMPLE);
  });
  const port = REAL ? 0 : Number(new URL(HOST).port);
  await new Promise((ok, bad) => { server.once("error", bad); server.listen(port, "127.0.0.1", ok); });
  const p = server.address().port;
  HOST = `http://${OTHER}:${p}`;
  EVIL = `http://${OS.hostname}:${p}`;
});
test.afterAll(async () => { await new Promise((ok) => server?.close(ok)); });
const EXAMPLE = fs.readFileSync(fileURLToPath(new URL("../../sdk/embed/example/index.html", import.meta.url)), "utf8");
const DEMO = path.resolve(fileURLToPath(new URL("../../target/e2e-demo", import.meta.url)));
const SIZE = { width: 1280, height: 800 };

test.use({ video: REAL ? { mode: "on", size: SIZE } : "off" });

/// The example host page is served by `server` (beforeAll) at `HOST` and `EVIL`.
async function hostPages(_page) {}

/// The host page, embedding `src` as `view` (signing or prepare).
async function openHost(page, origin, view, src, osOrigin, extra = {}) {
  const q = new URLSearchParams({ view, src, origin: osOrigin, ...extra });
  await page.goto(`${origin}${PAGE}?${q}`);
}

const events = (page) => page.getByTestId("host-events");
const frame = (page, kind = "openseal-signing") => page.frameLocator(`${kind} iframe`);

/// Real stack: the integrator's server, with an API key.
function integrator(key, run) {
  let n = 0;
  return async (method, p, body) => {
    const r = await fetch(`${BASE}/api/v1${p}`, {
      method,
      headers: { authorization: `Bearer ${key}`, "content-type": "application/json", ...(method === "POST" ? { "idempotency-key": `vs09-${run}-${++n}` } : {}) },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const text = await r.text();
    expect(r.ok, `${method} ${p}: ${r.status} ${text}`).toBe(true);
    return text ? JSON.parse(text) : null;
  };
}

/// Real stack: an administrator's API key that may also change the workspace's settings.
async function adminKey(page, run) {
  await page.goto(app("#/admin?section=api"));
  await page.getByRole("button", { name: "New API client" }).first().click();
  const panel = page.getByRole("dialog", { name: "New API client" });
  await panel.getByLabel("Name", { exact: true }).fill(`VS-09 integrator ${run}`);
  await panel.getByLabel("Kind").selectOption("api_key");
  await panel.locator("#c-scope-admin-account").check();
  await panel.getByRole("button", { name: "Create" }).click();
  const secret = page.getByRole("dialog", { name: "Copy the secret now" });
  await expect(secret).toBeVisible();
  const [key] = await secret.getByTestId("secret-value").evaluateAll((els) => els.map((e) => e.value));
  await secret.getByRole("button", { name: "I have copied it" }).click();
  return key;
}

/// The views to embed: the mock's seeded links, or on the real stack the integrator's
/// envelopes and views for the host page.
async function views(page, run) {
  if (!REAL) {
    const os = new URL(page.url()).origin;
    const q = "?mock=1";
    return {
      os,
      sign: `${os}/s/${MOCK.embedSignToken}${q}`,
      decline: `${os}/s/${MOCK.embedDeclineToken}${q}`,
      prepare: `${os}/e/${MOCK.embedPrepareToken}${q}`,
      correct: `${os}/e/${MOCK.embedCorrectToken}${q}`,
      state: MOCK.embedState,
      signer: "Casey Embedded",
    };
  }
  const key = await adminKey(page, run);
  const call = integrator(key, run);
  // The workspace allows the host page to frame its views (kept with any already allowed).
  const acct = await call("GET", "/accounts/me");
  const allowed = new Set([...(acct.settings?.embedding_origins || []), HOST]);
  await call("PATCH", "/accounts/me", { settings: { embedding_origins: [...allowed] } });
  const pdf = Buffer.from(makePdf([{ title: "Embedded order", lines: ["Signed inside the shop's own page."] }])).toString("base64");
  const env = (subject, status, recipient, options = {}) => call("POST", "/envelopes", {
    subject, status, ...options,
    documents: [{ name: "order.pdf", content_base64: pdf }],
    recipients: [{ ref: "s", type: "signer", routing_order: 1, ...recipient }],
    fields: [{ recipient: "s", document: 0, type: "signature", page: 1, x: 72, y: 600, width: 180, height: 40, required: true }],
  });
  const state = `order-${run}`;
  const target = { frame_origin: HOST, state };
  const signer = "Casey Embedded";
  const e1 = await env(`VS-09 embedded signing ${run}`, "sent", { name: signer, email: `casey-${run}@example.com`, embedded_client_user_id: `shop-${run}` });
  const e2 = await env(`VS-09 embedded decline ${run}`, "sent", { name: signer, email: `casey2-${run}@example.com`, embedded_client_user_id: `shop2-${run}` }, { signing_options: { allow_decline: true } });
  const e3 = await env(`VS-09 embedded draft ${run}`, "draft", { name: "Riley Prepared", email: `riley-${run}@example.com` });
  const e4 = await env(`VS-09 embedded correct ${run}`, "sent", { name: "Jamie Corrected", email: `jamie-${run}@example.com` });
  const sign = await call("POST", `/envelopes/${e1.id}/views/signing`, { recipient_id: e1.recipients[0].id, ...target });
  const decline = await call("POST", `/envelopes/${e2.id}/views/signing`, { recipient_id: e2.recipients[0].id, ...target });
  const prepare = await call("POST", `/envelopes/${e3.id}/views/prepare`, target);
  const correct = await call("POST", `/envelopes/${e4.id}/views/correct`, target);
  // A fresh signing view for the refused origin: a link opens once.
  const refused = await call("POST", `/envelopes/${e1.id}/views/signing`, { recipient_id: e1.recipients[0].id });
  return { os: BASE, sign: sign.url, decline: decline.url, prepare: prepare.url, correct: correct.url, refused: refused.url, state, signer };
}

/// The ceremony's steps inside the frame: consent when asked, adopt, finish.
async function signInFrame(f, name) {
  const consent = f.getByRole("heading", { name: "Electronic records and signatures" });
  const progress = f.locator("#guide-progress");
  await expect(consent.or(progress).first()).toBeVisible({ timeout: 20_000 });
  if (await consent.isVisible()) {
    await f.getByLabel("I agree to use electronic records and signatures.").check();
    await f.getByRole("button", { name: "Continue" }).click();
  }
  await expect(progress).toHaveText("0 of 1 required");
  await f.getByRole("button", { name: /Signature, required/ }).click();
  const dlg = f.getByRole("dialog", { name: "Adopt your signature" });
  await expect(dlg.getByLabel("Your full name")).toHaveValue(name);
  await dlg.getByTestId("adopt-confirm").click();
  await expect(dlg).toBeHidden();
  await f.getByRole("button", { name: "Finish" }).click();
  await expect(f.getByRole("heading", { name: "Review and finish" })).toBeVisible();
  await f.getByTestId("review-finish").click();
  await expect(f.getByTestId("sign-done")).toBeVisible();
}

test("slice 9 (VS-09): a host page on another origin embeds signing, prepare and correct and hears their events", async ({ page }, testInfo) => {
  test.setTimeout(REAL ? 300_000 : 150_000);
  const run = `${Date.now()}-${testInfo.project.name}-${Math.random().toString(36).slice(2, 8)}`;
  if (REAL) fs.mkdirSync(DEMO, { recursive: true });
  await page.setViewportSize(SIZE);
  await hostPages(page);
  await signIn(page, "home");
  const v = await views(page, run);

  // Signing: the signer signs inside the shop's page; the page hears "complete" with
  // its own state, and nothing else.
  await openHost(page, HOST, "signing", v.sign, v.os);
  await expect(events(page)).toContainText(`openseal:ready ready ${v.state}`, { timeout: 20_000 });
  await signInFrame(frame(page), v.signer);
  await expect(events(page)).toContainText(`openseal:complete completed ${v.state}`);
  await expect(events(page).getByRole("listitem")).toHaveCount(2);

  // Declining is heard as a decline.
  await openHost(page, HOST, "signing", v.decline, v.os);
  const d = frame(page);
  // The disclosure is asked for only when the account has one (a fresh real account has none).
  await expect(d.getByRole("heading", { name: "Electronic records and signatures" }).or(d.locator("#guide-progress")).first()).toBeVisible({ timeout: 20_000 });
  await d.getByRole("button", { name: "More" }).click();
  await d.getByRole("menuitem", { name: "Decline to sign" }).click();
  const dlg = d.getByRole("dialog", { name: "Decline to sign?" });
  await dlg.getByLabel("Tell the sender why").fill("Wrong quantity");
  await dlg.getByRole("button", { name: "Decline" }).click();
  await expect(d.getByTestId("sign-declined")).toBeVisible();
  await expect(events(page)).toContainText(`openseal:decline declined ${v.state}`);

  // Prepare: the sender sends the draft from the editor inside the shop's page.
  await openHost(page, HOST, "prepare", v.prepare, v.os);
  await expect(events(page)).toContainText("openseal:ready ready", { timeout: 20_000 });
  const p = frame(page, "openseal-prepare");
  const send = p.getByRole("button", { name: "Send", exact: true }).first();
  for (let i = 0; i < 4 && !(await send.isVisible()); i++) await p.getByTestId("wizard-next").click();
  await send.click();
  await p.getByRole("dialog", { name: "Send this envelope?" }).getByRole("button", { name: "Send" }).click();
  await expect(p.getByTestId("embed-sent")).toBeVisible({ timeout: 20_000 });
  await expect(events(page)).toContainText(`openseal:complete sent ${v.state}`);

  // Correct: leaving the correct panel without a change is heard as a cancel.
  await openHost(page, HOST, "prepare", v.correct, v.os);
  await expect(events(page)).toContainText("openseal:ready ready", { timeout: 20_000 });
  const c = frame(page, "openseal-prepare");
  const panel = c.getByRole("dialog", { name: "Correct envelope" });
  await expect(panel).toBeVisible();
  await panel.getByRole("button", { name: "Cancel" }).click();
  await expect(c.getByTestId("embed-cancelled")).toBeVisible();
  await expect(events(page)).toContainText(`openseal:cancel cancelled ${v.state}`);

  // A view link opens once: the same prepare link again opens nothing.
  await openHost(page, HOST, "prepare", v.prepare, v.os, { timeout: "5" });
  await expect(events(page)).toContainText("openseal:error", { timeout: 15_000 });
  if (!REAL) return;
  // A recording is complete, and can be saved, once its page is closed.
  await page.close();
  await page.video()?.saveAs(path.join(DEMO, `vs09-${testInfo.project.name}-host-page-signing-prepare-correct.webm`));
});

test("a page on an origin the workspace does not allow cannot frame a view, and a forged message is ignored", async ({ page }, testInfo) => {
  test.setTimeout(REAL ? 240_000 : 90_000);
  const run = `${Date.now()}-${testInfo.project.name}-${Math.random().toString(36).slice(2, 8)}`;
  await hostPages(page);
  await signIn(page, "home");
  const v = await views(page, run);
  // The not-allowed page: the browser refuses the frame, so the view never answers.
  await openHost(page, EVIL, "signing", REAL ? v.refused : v.sign, v.os, { timeout: "4" });
  await expect(events(page)).toContainText("openseal:error error timeout", { timeout: 15_000 });
  await expect(events(page)).not.toContainText("openseal:ready");
  // The allowed page: a message the page itself posts, shaped as the view's, is ignored.
  await openHost(page, HOST, "signing", REAL ? v.refused : v.sign, v.os);
  await expect(events(page)).toContainText("openseal:ready", { timeout: 20_000 });
  await page.evaluate(() => window.postMessage({ type: "openseal", v: 1, event: "completed", state: "forged" }, "*"));
  await page.evaluate((os) => document.querySelector("openseal-signing iframe").contentWindow.postMessage({ type: "openseal", v: 1, command: "theme", tokens: { accentColor: "red; x" } }, os), v.os);
  await page.waitForTimeout(500);
  await expect(events(page)).not.toContainText("forged");
  await expect(events(page)).not.toContainText("openseal:complete");
});

for (const scheme of ["light", "dark"]) {
  test.describe(`embedded views are accessible (${scheme})`, () => {
    test.use({ colorScheme: scheme });
    test(`the embedded signing view, the embedded editor and Admin's Embedding card (${scheme})`, async ({ page }, testInfo) => {
      test.setTimeout(REAL ? 240_000 : 90_000);
      const run = `${Date.now()}-${testInfo.project.name}-${scheme}-${Math.random().toString(36).slice(2, 8)}`;
      await hostPages(page);
      await signIn(page, "home");
      const v = await views(page, run);
      // Admin's card lists the websites; its panel checks each line.
      await page.goto(app("#/admin?section=organization"));
      const card = page.getByTestId("account-embedding");
      await expect(card).toBeVisible();
      if (!REAL) {
        await card.getByRole("button", { name: "Edit websites" }).click();
        const panel = page.getByRole("dialog", { name: "Embedding" });
        await panel.getByLabel("Allowed websites, one per line").fill(`${HOST}\nhttps://shop.example/checkout`);
        await panel.getByRole("button", { name: "Save" }).click();
        await expect(panel.getByText("Not a website address this accepts: https://shop.example/checkout")).toBeVisible();
        await expectAccessible(page, `Admin's Embedding panel (${scheme})`);
        await panel.getByLabel("Allowed websites, one per line").fill(HOST);
        await panel.getByRole("button", { name: "Save" }).click();
        await expect(page.getByText("Embedding websites saved.")).toBeVisible();
      }
      await expect(card.getByTestId("embedding-origins")).toContainText(HOST);
      await expectAccessible(page, `Admin's Embedding card (${scheme})`);
      // The views, opened on their own (axe scans the page it is given).
      await page.goto(v.sign);
      await expect(page.getByRole("heading", { name: "Electronic records and signatures" }).or(page.locator("#guide-progress")).first()).toBeVisible({ timeout: 20_000 });
      await expectAccessible(page, `the embedded signing view (${scheme})`);
      await page.goto(v.prepare);
      await expect(page.getByTestId("wizard-next").or(page.getByRole("button", { name: "Send", exact: true })).first()).toBeVisible({ timeout: 20_000 });
      await expectAccessible(page, `the embedded editor (${scheme})`);
    });
  });
}
