// SEC-A07 (docs/07, P2-THREATS): stored XSS in a browser. Envelopes, recipients,
// templates, document names, field labels, members, API clients and account settings
// are made holding hostile payloads, then every screen that shows them is visited:
// home, agreements, envelope detail, each prepare step, templates (list, detail,
// editor), admin (users, API, account), the signer page, its review, and verify.
// On each: the payload never ran (`window.__xss` unset, no dialog), never became
// markup (no element carries `onerror`/`onload`, no `javascript:` link), and shows as
// the literal text it is.
//
// Mock mode (default): the data is made through the mock API (webapp/mock.js) in the
// page, sharing the tab's sessionStorage with the app. Real mode
// (OPENSEAL_E2E_BASE_URL): made through the real API with the signed-in session; the
// signer page needs the emailed link, read from Mailpit (OPENSEAL_E2E_MAIL_URL), and
// is skipped, saying so, when that is not set.

import { test, expect } from "@playwright/test";

import { REAL, app, signIn, signPage } from "./helpers.mjs";
import { makePdf } from "../mockpdf.js";

const IMG = "<img src=x onerror=window.__xss=1>";
const SVG = "\"><svg/onload=window.__xss=1>";
const JS = "javascript:window.__xss=1";
const EMAIL = "\"><svg/onload=window.__xss=1>@evil.test";
const MAIL = (process.env.OPENSEAL_E2E_MAIL_URL || "").replace(/\/$/, "");

const pdf = () => Buffer.from(makePdf([{ title: "Hostile", lines: ["Payloads ride in the metadata, not here."] }])).toString("base64");

/// The data, as API bodies. `run` makes names unique per run against a real account.
function bodies(run) {
  const recipients = [
    { ref: "a", type: "signer", name: `${IMG} Ana ${run}`, email: `ana.${run}@example.com`, routing_order: 1 },
    { ref: "b", type: "signer", name: `${SVG} Bo`, email: EMAIL, routing_order: 1 },
    { ref: "c", type: "cc", name: `${JS} Cy`, email: `cy.${run}@example.com`, routing_order: 2 },
  ];
  const fields = [
    { recipient: "a", document: 0, type: "signature", page: 1, x: 72, y: 600, width: 180, height: 40, required: false, label: `${SVG} sig` },
    { recipient: "a", document: 0, type: "text", page: 1, x: 72, y: 500, width: 180, height: 24, required: false, label: `${IMG} label` },
    { recipient: "b", document: 0, type: "signature", page: 1, x: 300, y: 600, width: 180, height: 40, required: true, label: `${JS} b` },
  ];
  const envelope = (status) => ({
    subject: `${IMG} XSS ${status} ${run}`,
    message: `${SVG} see ${JS}`,
    status,
    documents: [{ name: `${IMG}${run}.pdf`, content_base64: pdf() }],
    recipients,
    fields,
  });
  return {
    sent: envelope("sent"),
    draft: envelope("draft"),
    template: {
      name: `${IMG} Template ${run}`,
      email_subject: `${SVG} subject`,
      email_message: JS,
      roles: [{ name: `${SVG} Role`, type: "signer", routing_order: 1 }, { name: JS, type: "cc", routing_order: 2 }],
    },
    user: { name: `${IMG} Member`, email: `member.${run}@example.com`, profile: "sender" },
    client: { name: `${SVG} key ${run}`, kind: "api_key", scopes: ["envelopes:read"] },
    settings: { settings: { brand_name: IMG, support_url: JS, website: JS } },
  };
}

/// Make the data. Answers `{sent, draft, template, token}` (ids; the signer's token in
/// mock mode).
async function seed(page, run) {
  const b = bodies(run);
  if (!REAL) {
    return page.evaluate(async (b) => {
      const { createMockFetch, MOCK } = await import("/mock.js");
      const f = createMockFetch({ store: sessionStorage });
      const call = async (method, path, body, csrf) => {
        const res = await f(path, { method, headers: { "content-type": "application/json", ...(csrf ? { "x-csrf-token": csrf } : {}) }, body: body ? JSON.stringify(body) : undefined });
        const j = await res.json().catch(() => null);
        if (!res.ok) throw new Error(`${method} ${path}: ${res.status} ${JSON.stringify(j)}`);
        return j;
      };
      const { csrf_token: csrf } = await call("POST", "/api/v1/auth/login", { email: MOCK.email, password: MOCK.password });
      const sent = await call("POST", "/api/v1/envelopes", b.sent, csrf);
      const draft = await call("POST", "/api/v1/envelopes", b.draft, csrf);
      const template = await call("POST", "/api/v1/templates", b.template, csrf);
      await call("POST", "/api/v1/users", b.user, csrf);
      await call("POST", "/api/v1/api-clients", b.client, csrf);
      await call("PATCH", "/api/v1/account", b.settings, csrf).catch(() => null);
      const ana = sent.recipients.find((r) => r.name.includes("Ana")).id;
      const token = Object.entries(f.state().tokens).find(([, t]) => t.env === sent.id && t.rid === ana)?.[0];
      return { sent: sent.id, draft: draft.id, template: template.id, token };
    }, b);
  }
  const csrf = await page.evaluate(() => sessionStorage.getItem("openseal.csrf"));
  const post = async (method, path, data) => {
    const res = await page.request.fetch(path, { method, data, headers: { "X-CSRF-Token": csrf, "Idempotency-Key": `xss-${path}-${run}-${Math.random()}` } });
    expect(res.ok(), `${method} ${path}: ${res.status()} ${await res.text()}`).toBeTruthy();
    return res.json();
  };
  const sent = await post("POST", "/api/v1/envelopes", b.sent);
  const draft = await post("POST", "/api/v1/envelopes", b.draft);
  const template = await post("POST", "/api/v1/templates", b.template);
  await post("POST", "/api/v1/users", b.user);
  await post("POST", "/api/v1/api-clients", b.client);
  return { sent: sent.id, draft: draft.id, template: template.id, token: null };
}

/// Fail the test on any dialog (alert, confirm, prompt) a payload could open.
function watchDialogs(page) {
  const dialogs = [];
  page.on("dialog", async (d) => { dialogs.push(`${d.type()}: ${d.message()}`); await d.dismiss().catch(() => {}); });
  return dialogs;
}

/// The screen shows `literal` as text, and no payload ran or became markup.
async function clean(page, dialogs, where, literal = IMG) {
  if (literal) await expect(page.getByText(literal).first(), `${where}: the payload shows as text`).toBeAttached();
  const state = await page.evaluate(() => ({
    xss: window.__xss,
    handlers: [...document.querySelectorAll("[onerror],[onload]")].map((e) => e.outerHTML.slice(0, 120)),
    jsLinks: [...document.querySelectorAll("[href],[src],[action],[formaction]")]
      .map((e) => e.getAttribute("href") ?? e.getAttribute("src") ?? e.getAttribute("action") ?? e.getAttribute("formaction") ?? "")
      .filter((v) => /^\s*javascript:/i.test(v)),
  }));
  expect(state.xss, `${where}: a payload ran (window.__xss)`).toBeUndefined();
  expect(state.handlers, `${where}: a payload became markup`).toEqual([]);
  expect(state.jsLinks, `${where}: a javascript: URL became a link`).toEqual([]);
  expect(dialogs, `${where}: a dialog fired`).toEqual([]);
}

test("hostile names, subjects, labels and URLs render as text on every sender screen", async ({ page }, testInfo) => {
  test.setTimeout(300_000);
  const dialogs = watchDialogs(page);
  const run = `${Date.now()}-${testInfo.project.name}`;
  if (!REAL) await page.goto(app("#/signin"));
  else await signIn(page, "home");
  const ids = await seed(page, run);
  await signIn(page, "home");

  // Home lists only the few most recent envelopes; on the shared real stack other specs
  // may have sent newer ones, so the payload's presence is checked on the agreements
  // search below there. Every safety check (no script, no markup, no dialog) still runs.
  await clean(page, dialogs, "home", REAL ? null : IMG);
  await page.goto(app("#/agreements"));
  await expect(page.getByRole("heading", { name: "Agreements" })).toBeVisible();
  await clean(page, dialogs, "agreements");
  await page.goto(app(`#/agreements?q=${encodeURIComponent("XSS")}`));
  await clean(page, dialogs, "agreements search");

  await page.goto(app(`#/envelopes/${ids.sent}`));
  await clean(page, dialogs, "envelope detail");
  await expect(page.getByText(SVG).first(), "a recipient's name shows as text").toBeAttached();

  await page.goto(app(`#/prepare/${ids.draft}`));
  const steps = page.getByRole("navigation", { name: "Steps" });
  for (const name of ["Documents", "Recipients", "Fields", "Review and send"]) {
    await steps.getByRole("button", { name: new RegExp(`${name}$`) }).click();
    await expect(page.locator('.os-stepper__btn[aria-current="step"]')).toContainText(name);
    // The heading names the subject on every step.
    await clean(page, dialogs, `prepare: ${name}`);
  }
  await expect(page.getByText(SVG).first(), "prepare review: a recipient's name shows as text").toBeAttached();

  await page.goto(app("#/templates"));
  await clean(page, dialogs, "templates");
  await page.goto(app(`#/templates/${ids.template}`));
  await clean(page, dialogs, "template detail");
  await page.goto(app(`#/templates/${ids.template}/edit`));
  await clean(page, dialogs, "template editor", null);

  await page.goto(app("#/admin"));
  await clean(page, dialogs, "admin: users");
  await page.goto(app("#/admin?tab=api"));
  await clean(page, dialogs, "admin: API", SVG);
  await page.goto(app("#/admin?tab=account"));
  await clean(page, dialogs, "admin: account", null);
});

test("the signer page and its review show hostile names, labels and subjects as text", async ({ page }, testInfo) => {
  test.setTimeout(120_000);
  test.skip(REAL && !MAIL, "the signer page needs the emailed link: set OPENSEAL_E2E_MAIL_URL (Mailpit) with OPENSEAL_E2E_BASE_URL");
  const dialogs = watchDialogs(page);
  const run = `${Date.now()}-${testInfo.project.name}`;
  let link;
  if (!REAL) {
    await page.goto(app("#/signin"));
    const ids = await seed(page, run);
    expect(ids.token, "the mock minted a signing token").toBeTruthy();
    link = signPage(ids.token);
  } else {
    await signIn(page, "home");
    await seed(page, run);
    link = await emailedLink(`ana.${run}@example.com`);
  }
  await page.goto(link);
  const consent = page.getByRole("heading", { name: "Electronic records and signatures" });
  // The progress, once there is some: the guide's, or the bar's screen-reader copy (empty on consent).
  const progress = page.locator("#guide-progress, #bar-progress:not(:empty)").filter({ visible: true });
  await expect(consent.or(progress).first()).toBeVisible();
  await clean(page, dialogs, "signer page (first screen)");
  if (await consent.isVisible()) {
    await page.getByLabel("I agree to use electronic records and signatures.").check();
    await page.getByRole("button", { name: "Continue" }).click();
    await expect(progress.first()).toBeVisible();
  }
  await clean(page, dialogs, "signer page");
  await page.getByRole("button", { name: "Finish" }).click();
  await expect(page.getByRole("heading", { name: "Review and finish" })).toBeVisible();
  await clean(page, dialogs, "signer review");
});

test("verify shows a hostile file name as text", async ({ page }) => {
  const dialogs = watchDialogs(page);
  await page.goto(REAL ? "/verify.html" : "/verify.html?mock=1");
  const name = `${IMG}.pdf`;
  await page.getByTestId("verify-input").setInputFiles({ name, mimeType: "application/pdf", buffer: Buffer.from(pdf(), "base64") });
  // Without the verifier built (tools/build-webapp-wasm.sh) the page says so after
  // naming the file; either way nothing may run.
  const missing = page.getByTestId("verify-missing");
  await expect(page.getByText(name).first().or(missing)).toBeAttached();
  await clean(page, dialogs, "verify", (await missing.isVisible()) ? null : name);
});

/// The signing link in the newest email to `to` (real mode), from Mailpit.
async function emailedLink(to) {
  const deadline = Date.now() + 60_000;
  while (Date.now() < deadline) {
    const res = await fetch(`${MAIL}/api/v1/search?query=${encodeURIComponent(`to:"${to}"`)}`);
    if (res.ok) {
      const { messages = [] } = await res.json();
      for (const m of messages) {
        const full = await (await fetch(`${MAIL}/api/v1/message/${encodeURIComponent(m.ID)}`)).json();
        const link = `${full.Text || ""}`.match(/https?:\/\/[^\s"'<>]+\/s\/[A-Za-z0-9._~%-]+/);
        if (link) return link[0];
      }
    }
    await new Promise((r) => setTimeout(r, 1000));
  }
  throw new Error(`no signing link emailed to ${to} within 60 s`);
}
