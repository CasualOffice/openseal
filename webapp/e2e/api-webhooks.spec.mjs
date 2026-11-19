// VS-08C (slice 8, API and webhooks), in a browser: an integrator, signed in as an
// administrator, makes an API key and a webhook in Admin, sends an envelope through the
// API with the key, sees the receiver get signed deliveries, finds them in the delivery
// log, and delivers a failed one again; then registers an OAuth app, takes a member
// through its consent screen and, on the real stack, exchanges the code with PKCE for a
// token that acts as that member.
//
// Both modes. On the Compose deployment (compose-e2e, tools/e2e/compose.e2e.yml) the API
// calls go from this process to the server with the key the screen showed; the webhook's
// address is the CI receiver (auth_stubs.py `hooks`, https://hooks.e2e.test:8443),
// which checks each delivery's Standard Webhooks signature with the secret the worker
// signs with, and is told to fail, then to succeed, so a delivery fails and is delivered
// again; every screen is recorded as the slice 8 demo (target/e2e-demo/vs08-*, uploaded
// by compose-e2e as `slice-8-demo`). In mock mode the envelope is sent through the
// page's client (the mock has no key authentication), the receiver is the mock's
// (`…/fail-first` answers its first delivery 500), and the consent screen is opened
// directly (the authorization endpoint is the server's). Names are the run's own.
//
// The second test scans the API clients form, the webhooks screen with its deliveries,
// the consent screen and the profile's connected apps with axe, light and dark.
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { test, expect } from "@playwright/test";
import { signIn, REAL, app, expectAccessible, creds, passFactor } from "./helpers.mjs";
import { makePdf } from "../mockpdf.js";

const BASE = (process.env.OPENSEAL_E2E_BASE_URL || "").replace(/\/$/, "");
const HOOKS = (process.env.OPENSEAL_E2E_HOOKS_URL || "http://127.0.0.1:8027").replace(/\/$/, "");
const MAIL = (process.env.OPENSEAL_E2E_MAIL_URL || "http://127.0.0.1:8025").replace(/\/$/, "");

/// Real stack: the signing link in the newest email to `to` sent after `after` (Mailpit).
async function emailedLink(to, after) {
  const deadline = Date.now() + 90_000;
  while (Date.now() < deadline) {
    const res = await fetch(`${MAIL}/api/v1/search?query=${encodeURIComponent(`to:"${to}"`)}`);
    if (res.ok) {
      const { messages = [] } = await res.json();
      for (const m of messages) {
        if (after && Date.parse(m.Created) < after) continue;
        const full = await (await fetch(`${MAIL}/api/v1/message/${encodeURIComponent(m.ID)}`)).json();
        const link = `${full.Text || ""}\n${full.HTML || ""}`.match(/https?:\/\/[^\s"'<>]+\/s\/[A-Za-z0-9._~%-]+/);
        if (link) return link[0];
      }
    }
    await new Promise((r) => setTimeout(r, 1000));
  }
  throw new Error(`no signing link emailed to ${to} within 90 s`);
}
const DEMO = path.resolve(fileURLToPath(new URL("../../target/e2e-demo", import.meta.url)));
const SIZE = { width: 1280, height: 800 };
const CALLBACK = "https://app.vs08.example/callback";
const SECRET_REF = "OPENSEAL_E2E_WEBHOOK_SECRET";

test.use({ video: REAL ? { mode: "on", size: SIZE } : "off" });

const b64url = (buf) => buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

/// The receiver's deliveries of `type` for `envelope`, newest first (real stack).
async function received(type, envelope) {
  const r = await fetch(`${HOOKS}/deliveries?${new URLSearchParams({ type, envelope })}`);
  return (await r.json()).deliveries || [];
}

/// Make the receiver answer later deliveries with `status` (real stack).
async function answerWith(status) {
  const r = await fetch(`${HOOKS}/answer?status=${status}`, { method: "POST" });
  expect(r.ok).toBe(true);
}

/// Run `fn(arg)` in the signed-in app page with api.js's client on `window.__vs08`.
async function inApp(page, fn, arg) {
  await page.evaluate(async (real) => {
    const { createClient } = await import(new URL("api.js", location.href).href);
    const opts = { store: sessionStorage };
    if (!real) opts.fetch = (await import(new URL("mock.js", location.href).href)).createMockFetch({ store: sessionStorage });
    window.__vs08 = createClient(opts);
  }, REAL);
  return page.evaluate(fn, arg);
}

/// The account menu's profile panel.
async function openProfile(page) {
  await page.locator("#account-btn").click();
  await page.getByRole("menuitem", { name: "Profile and signature" }).click();
  const panel = page.getByRole("dialog", { name: "Profile and signature" });
  await expect(panel).toBeVisible();
  return panel;
}

/// Create an API client in Admin and read what the one-time panel shows.
async function newClient(page, { name, kind, redirect }) {
  await page.getByRole("button", { name: "New API client" }).first().click();
  const panel = page.getByRole("dialog", { name: "New API client" });
  await panel.getByLabel("Name", { exact: true }).fill(name);
  await panel.getByLabel("Kind").selectOption(kind);
  if (redirect) await panel.getByLabel("Redirect URIs").fill(redirect);
  await panel.getByRole("button", { name: "Create" }).click();
  const secret = page.getByRole("dialog", { name: "Copy the secret now" });
  await expect(secret).toBeVisible();
  const values = await secret.getByTestId("secret-value").evaluateAll((els) => els.map((e) => e.value));
  await secret.getByRole("button", { name: "I have copied it" }).click();
  await expect(secret).toBeHidden();
  return values;
}

test("slice 8 (VS-08C): an API key sends an envelope, signed webhooks arrive and one is delivered again; an app is allowed through the consent screen", async ({ page }, testInfo) => {
  test.setTimeout(REAL ? 300_000 : 120_000);
  const run = `${Date.now()}-${testInfo.project.name}-${Math.random().toString(36).slice(2, 8)}`;
  const subject = `VS-08 API envelope ${run}`;
  const hookUrl = REAL ? `https://hooks.e2e.test:8443/openseal/${run}` : `https://hooks.example.com/${run}/fail-first`;
  if (REAL) fs.mkdirSync(DEMO, { recursive: true });
  await page.setViewportSize(SIZE);
  await signIn(page, "home");

  // An API key, made in Admin and shown once.
  await page.goto(app("#/admin?section=api"));
  await expect(page.getByRole("heading", { name: "API and webhooks", level: 1 })).toBeVisible();
  const [key] = await newClient(page, { name: `VS-08 key ${run}`, kind: "api_key" });
  expect(key).toMatch(/^osk_/);
  await expect(page.getByRole("row", { name: new RegExp(`VS-08 key ${run}`) })).toContainText("API key");

  // A webhook to the receiver, for the envelope being sent.
  await page.goto(app("#/admin?section=webhooks"));
  await page.getByRole("button", { name: "New webhook" }).first().click();
  const add = page.getByRole("dialog", { name: "New webhook" });
  await add.getByLabel("Endpoint URL").fill(hookUrl);
  await add.getByLabel("Signing secret names").fill(SECRET_REF);
  await add.getByLabel("envelope.sent").check();
  await add.getByRole("button", { name: "Create" }).click();
  await expect(page.getByText("Webhook added.")).toBeVisible();

  // The receiver fails the first delivery.
  if (REAL) await answerWith(500);
  // The integrator's system sends an envelope through the API.
  const pdf = Buffer.from(makePdf([{ title: "Order form", lines: ["Signed through the API."] }])).toString("base64");
  const create = {
    subject, status: "sent",
    documents: [{ name: "order.pdf", content_base64: pdf }],
    recipients: [{ ref: "s", type: "signer", name: "Ada Api", email: `vs08-${run}@example.com` }],
    fields: [{ recipient: "s", document: 0, type: "signature", page: 1, x: 72, y: 600, width: 180, height: 40, required: true }],
  };
  let envelopeId;
  if (REAL) {
    const r = await fetch(`${BASE}/api/v1/envelopes`, { method: "POST", headers: { authorization: `Bearer ${key}`, "content-type": "application/json", "idempotency-key": `vs08-${run}` }, body: JSON.stringify(create) });
    expect(r.status).toBe(201);
    envelopeId = (await r.json()).id;
    // Delivered to the receiver, signed with the secret it holds: refused by it first.
    await expect.poll(async () => (await received("envelope.sent", envelopeId)).map((d) => [d.answered, d.verified]), { timeout: 90_000, intervals: [1000] })
      .toContainEqual([500, true]);
    await answerWith(200);
  } else {
    envelopeId = (await inApp(page, (body) => window.__vs08.createEnvelope(body), create)).id;
    // The page's own mock reads the tab's store afresh on a new load.
    await page.goto(app("#/admin?section=webhooks"));
    await page.reload();
  }
  expect(envelopeId).toBeTruthy();

  // The delivery log shows the failure; delivering it again succeeds.
  const row = page.getByRole("row", { name: new RegExp(hookUrl.replace(/[.*+?^${}()|[\]\\/]/g, "\\$&")) });
  await row.getByRole("button", { name: `Deliveries for ${hookUrl}` }).click();
  const del = page.getByTestId("deliveries");
  const failed = del.getByTestId("delivery-row").filter({ hasText: "envelope.sent" }).filter({ hasText: "Failed" });
  await expect.poll(async () => {
    if (await failed.count()) return true;
    await del.getByRole("button", { name: "Refresh" }).click();
    return false;
  }, { timeout: 60_000, intervals: [2000] }).toBe(true);
  await expect(failed.first()).toContainText("500");
  await failed.first().getByRole("button", { name: "Deliver again: envelope.sent" }).click();
  await expect(page.getByText("Delivered again.")).toBeVisible();
  const delivered = del.getByTestId("delivery-row").filter({ hasText: "envelope.sent" }).filter({ hasText: "Delivered" });
  await expect.poll(async () => {
    if (await delivered.count()) return true;
    await del.getByRole("button", { name: "Refresh" }).click();
    return false;
  }, { timeout: 60_000, intervals: [2000] }).toBe(true);
  if (REAL) {
    // The same event again, the same webhook-id, signed, and now accepted.
    const got = await received("envelope.sent", envelopeId);
    const ok = got.filter((d) => d.answered === 200 && d.verified);
    expect(ok.length).toBeGreaterThan(0);
    expect(new Set(got.map((d) => d.id)).size).toBe(1);
  }

  // An OAuth app: registered with its redirect URI, allowed by the member on the
  // consent screen, which sends the browser back with a code.
  await page.goto(app("#/admin?section=api"));
  const [clientId, clientSecret] = await newClient(page, { name: `VS-08 app ${run}`, kind: "oauth_app", redirect: CALLBACK });
  expect(clientId).toBeTruthy();
  expect(clientSecret).toBeTruthy();
  const verifier = b64url(crypto.randomBytes(48));
  const challenge = b64url(crypto.createHash("sha256").update(verifier).digest());
  const query = new URLSearchParams({ response_type: "code", client_id: clientId, redirect_uri: CALLBACK, scope: "envelopes:read", state: `st-${run}`, code_challenge: challenge, code_challenge_method: "S256" });
  // The app's callback page, answered here: the browser never leaves for the internet.
  await page.route(`${CALLBACK}**`, (route) => route.fulfill({ status: 200, contentType: "text/html", body: "<!doctype html><title>Partner app</title><p>Back at the app</p>" }));
  await page.goto(REAL ? `/api/v1/oauth/authorize?${query}` : app(`#/authorize?${query}`));
  await expect(page.getByRole("heading", { name: "Allow access" })).toBeVisible();
  await expect(page.getByTestId("oauth-app")).toContainText(`VS-08 app ${run}`);
  await expect(page.getByTestId("oauth-scopes")).toContainText("envelopes:read");
  await page.getByTestId("oauth-allow").click();
  await page.waitForURL(`${CALLBACK}**`);
  const back = new URL(page.url());
  expect(back.searchParams.get("state")).toBe(`st-${run}`);
  const code = back.searchParams.get("code");
  expect(code).toBeTruthy();
  if (REAL) {
    // The app's server exchanges the code with its secret and the verifier, and acts as
    // the member with what it was allowed.
    const tok = await fetch(`${BASE}/api/v1/oauth/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", authorization: `Basic ${Buffer.from(`${clientId}:${clientSecret}`).toString("base64")}` },
      body: new URLSearchParams({ grant_type: "authorization_code", code, redirect_uri: CALLBACK, code_verifier: verifier }).toString(),
    });
    expect(tok.status).toBe(200);
    const t = await tok.json();
    expect(t.refresh_token).toMatch(/^osr_/);
    const read = await fetch(`${BASE}/api/v1/envelopes/${envelopeId}`, { headers: { authorization: `Bearer ${t.access_token}` } });
    expect(read.status).toBe(200);
    expect((await read.json()).subject).toBe(subject);
  }

  // The member sees the app among their connected apps and removes its access.
  await page.goto(app("#/home"));
  const profile = await openProfile(page);
  const appRow = profile.getByTestId("app-row").filter({ hasText: `VS-08 app ${run}` });
  await expect(appRow).toContainText("envelopes:read");
  await appRow.getByRole("button", { name: `Remove access for VS-08 app ${run}` }).click();
  await expect(page.getByText("Access removed.")).toBeVisible();
  await expect(appRow).toHaveCount(0);

  if (!REAL) return;
  await page.close();
  await page.video()?.saveAs(path.join(DEMO, `vs08-${testInfo.project.name}-integrator-key-webhooks-redelivery-consent.webm`));
});

// ADR-041 (VS-08D): a sandbox workspace, made by the organization's owner, marks every
// screen; its keys start osk_test_; on the real stack an envelope sent with such a key
// is signed through its emailed link (the signing page says it is a test), sealed with the
// sandbox key, and the Verify page says the seal is not for agreements. The sandbox
// session is a sign-in of its own, in a context of its own: switching workspace ends the
// session it switches from, which the rest of the run shares.
test("sandbox (VS-08D): a sandbox workspace is marked everywhere, keys start osk_test_, and its seal says not for agreements", async ({ browser, page: shared }, testInfo) => {
  test.setTimeout(REAL ? 300_000 : 120_000);
  const run = `${Date.now()}-${testInfo.project.name}-${Math.random().toString(36).slice(2, 8)}`;
  const name = `VS-08 sandbox ${run}`;
  let context = null;
  let page = shared;
  if (REAL) {
    context = await browser.newContext({ viewport: SIZE, recordVideo: { dir: testInfo.outputPath("video-sandbox"), size: SIZE } });
    page = await context.newPage();
    await page.goto(app("#/signin"));
    await page.getByLabel("Email").fill(creds.email);
    await page.getByLabel("Password").fill(creds.password);
    await page.getByRole("button", { name: "Sign in" }).click();
    await passFactor(page);
    await expect(page.getByRole("heading", { name: "Home", exact: true })).toBeVisible();
  } else {
    await page.setViewportSize(SIZE);
    await signIn(page, "home");
  }
  await expect(page.getByTestId("sandbox-banner")).toBeHidden();

  // The owner makes the sandbox workspace and joins it.
  await page.goto(app("#/org?section=workspaces"));
  await page.getByRole("button", { name: "New workspace" }).first().click();
  const create = page.getByRole("dialog", { name: "New workspace" });
  await create.getByLabel("Name", { exact: true }).fill(name);
  await create.getByLabel("Sandbox workspace").check();
  await create.getByRole("button", { name: "Create workspace" }).click();
  const row = page.getByRole("row", { name: new RegExp(name) });
  await expect(row.getByTestId("ws-sandbox")).toHaveText("Sandbox");
  await row.getByRole("button", { name: `Join ${name}` }).click();
  await page.getByRole("dialog", { name: new RegExp(name) }).getByRole("button", { name: "Join" }).click();
  await expect(page.locator(".os-toast").last()).toContainText(name);

  // Switched into it: every screen says it is a sandbox.
  // The workspace menu lists what the page loaded: a fresh load lists the new one.
  await page.goto(app("#/home"));
  await page.reload();
  await page.locator("#ws-btn").click();
  await page.getByRole("menu", { name: "Workspace" }).getByRole("menuitem", { name }).click();
  if (REAL) await passFactor(page);
  await expect(page.getByTestId("sandbox-banner")).toBeVisible();
  await expect(page.getByTestId("sandbox-banner")).toContainText("Nothing sent, signed or sealed here is an agreement");
  await expectAccessible(page, "sandbox banner");

  // Its keys start osk_test_.
  await page.goto(app("#/admin?section=api"));
  await expect(page.getByTestId("sandbox-banner")).toBeVisible();
  const [key] = await newClient(page, { name: `VS-08 sandbox key ${run}`, kind: "api_key" });
  expect(key).toMatch(/^osk_test_/);
  if (!REAL) return;

  // An envelope sent with the key, signed through its emailed link.
  const signer = { name: "Sandy Box", email: `vs08-sandbox-${run}@example.com` };
  const started = Date.now() - 5_000;
  const pdf = Buffer.from(makePdf([{ title: "Sandbox order", lines: ["Sent from a sandbox workspace."] }])).toString("base64");
  const res = await fetch(`${BASE}/api/v1/envelopes`, {
    method: "POST",
    headers: { authorization: `Bearer ${key}`, "content-type": "application/json" },
    body: JSON.stringify({
      subject: `VS-08 sandbox envelope ${run}`, status: "sent",
      documents: [{ name: "order.pdf", content_base64: pdf }],
      recipients: [{ ref: "s", type: "signer", name: signer.name, email: signer.email }],
      fields: [{ recipient: "s", document: 0, type: "signature", page: 1, x: 72, y: 600, width: 180, height: 40, required: true }],
    }),
  });
  expect(res.status).toBe(201);
  const envelopeId = (await res.json()).id;
  const link = await emailedLink(signer.email, started);
  const p = await context.newPage();
  await p.goto(link, { waitUntil: "domcontentloaded" });
  await expect(p.getByTestId("sandbox-banner")).toBeVisible();
  const consent = p.getByRole("heading", { name: "Electronic records and signatures" });
  const progress = p.locator("#guide-progress");
  await expect(consent.or(progress).first()).toBeVisible();
  if (await consent.isVisible()) {
    await p.getByLabel("I agree to use electronic records and signatures.").check();
    await p.getByRole("button", { name: "Continue" }).click();
  }
  await expect(progress).toBeVisible();
  await p.getByRole("button", { name: /Signature, required/ }).click();
  const dlg = p.getByRole("dialog", { name: "Adopt your signature" });
  await dlg.getByTestId("adopt-confirm").click();
  await p.getByRole("button", { name: "Finish" }).click();
  await p.getByTestId("review-finish").click();
  await expect(p.getByTestId("sign-done")).toBeVisible();

  // Sealed with the sandbox key: the Verify page says it is not for agreements.
  let sealed = null;
  await expect.poll(async () => {
    const r = await fetch(`${BASE}/api/v1/envelopes/${envelopeId}/documents/combined`, { headers: { authorization: `Bearer ${key}` } });
    if (r.status !== 200) return r.status;
    sealed = Buffer.from(await r.arrayBuffer());
    return 200;
  }, { timeout: 120_000, intervals: [2000] }).toBe(200);
  fs.mkdirSync(DEMO, { recursive: true });
  const file = testInfo.outputPath("sandbox-sealed.pdf");
  fs.writeFileSync(file, sealed);
  await p.goto("/verify.html", { waitUntil: "domcontentloaded" });
  await expect(p.getByTestId("verify-engine")).toHaveAttribute("data-state", "ready");
  await p.getByTestId("verify-input").setInputFiles(file);
  await expect(p.getByTestId("verdict")).toBeVisible();
  await expect(p.getByTestId("verify-sandbox")).toContainText("not for agreements");
  await p.close();
  await page.close();
  await context.close();
  await page.video()?.saveAs(path.join(DEMO, `vs08-${testInfo.project.name}-sandbox-workspace-envelope-verify.webm`));
});

for (const scheme of ["light", "dark"]) {
  test.describe(`${scheme} theme`, () => {
    test.use({ colorScheme: scheme });
    test.beforeEach(async ({ page }) => { await page.addInitScript((s) => { try { localStorage.setItem("openseal.theme", s); } catch { /* storage off */ } }, scheme); });

    test("API and webhooks: the client form, deliveries, the consent screen and connected apps are accessible", async ({ page }, testInfo) => {
      test.setTimeout(120_000);
      const run = `${Date.now()}-${testInfo.project.name}-${scheme}`;
      await signIn(page, "home");
      await page.goto(app("#/admin?section=api"));
      await page.getByRole("button", { name: "New API client" }).first().click();
      const panel = page.getByRole("dialog", { name: "New API client" });
      await panel.getByLabel("Kind").selectOption("jwt_integration");
      await expect(panel.getByLabel("Redirect URIs")).toBeVisible();
      await expect(panel.getByLabel("Public key (PEM)")).toBeVisible();
      await expectAccessible(page, `API client form (${scheme})`);
      // A private key is refused before it leaves the page.
      await panel.getByLabel("Name", { exact: true }).fill(`VS-08 jwt ${run}`);
      await panel.getByLabel("Redirect URIs").fill(CALLBACK);
      await panel.getByLabel("Public key (PEM)").fill("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----");
      await panel.getByRole("button", { name: "Create" }).click();
      await expect(panel.getByText("That is a private key.")).toBeVisible();
      await panel.getByRole("button", { name: "Cancel" }).click();

      const [clientId] = await newClient(page, { name: `VS-08 a11y app ${run}`, kind: "oauth_app", redirect: CALLBACK });
      await page.goto(app("#/admin?section=webhooks"));
      await expect(page.getByRole("heading", { name: "API and webhooks", level: 1 })).toBeVisible();
      await expectAccessible(page, `webhooks (${scheme})`);

      const query = new URLSearchParams({ response_type: "code", client_id: clientId, redirect_uri: CALLBACK, scope: "envelopes:read envelopes:write", state: "s", code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", code_challenge_method: "S256" });
      await page.goto(app(`#/authorize?${query}`));
      await expect(page.getByTestId("oauth-allow")).toBeVisible();
      await expectAccessible(page, `consent screen (${scheme})`);
      // An unregistered redirect URI is refused on the screen, never followed.
      query.set("redirect_uri", "https://elsewhere.example/cb");
      await page.goto(app(`#/authorize?${query}`));
      await expect(page.getByTestId("oauth-refused")).toBeVisible();
      await expectAccessible(page, `refused consent (${scheme})`);
    });
  });
}
