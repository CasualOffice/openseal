// VS-03 (slice 3, templates), in a browser: roles, use a template, composite templates,
// folders and save as template, end to end.
//
// A sender has two templates with roles (made through api.js's client): an NDA whose
// Buyer signs, and an order whose buyer (the same role, another case) has a date and
// whose Seller signs. The sender files the NDA in a new template folder and finds it by
// the folder filter; opens it with Use, adds the order template to the same envelope
// (one Buyer for both, two documents), fills the two roles and sends. Each signer signs
// through their own link in their turn; the envelope completes; the sender saves it as a
// template and finds it in the list with its roles. Sharing has its own spec
// (template-sharing.spec.mjs, UXW-06).
//
// Both modes. On the Compose deployment (compose-e2e) each link is the one the worker
// emailed, read from Mailpit, and each signer acts in a browser context of their own;
// every screen is recorded as the slice 3 demo (target/e2e-demo/vs03-*, uploaded by
// compose-e2e as `slice-3-demo`). In mock mode the link is the mock's token for that
// address once routing reaches it, and the signers act in the sender's tab. Every run has
// its own names and addresses (the run id in each), and the spec changes no account
// setting: the shared account's disclosure, if any, is accepted, never published.
//
// The second test scans the template screens with axe, light and dark.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { test, expect } from "@playwright/test";
import { signIn, REAL, app, signPage, expectAccessible } from "./helpers.mjs";
import { makePdf } from "../mockpdf.js";

const MAIL = (process.env.OPENSEAL_E2E_MAIL_URL || "http://127.0.0.1:8025").replace(/\/$/, "");
const DEMO = path.resolve(fileURLToPath(new URL("../../target/e2e-demo", import.meta.url)));
const SIZE = { width: 1280, height: 800 };

// The sender's screens are recorded on the real stack only (the demo).
test.use({ video: REAL ? { mode: "on", size: SIZE } : "off" });

/// Real stack: the signing link in the newest email to `to` sent after `after`.
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

/// Run `fn(arg)` in the signed-in app page with api.js's client on `window.__vs03`
/// (the page's CSP allows no eval); in mock mode it shares the app's mock.
async function inApp(page, fn, arg) {
  await page.evaluate(async (real) => {
    const { createClient } = await import(new URL("api.js", location.href).href);
    const opts = { store: sessionStorage };
    if (!real) opts.fetch = (await import(new URL("mock.js", location.href).href)).createMockFetch({ store: sessionStorage });
    window.__vs03 = createClient(opts);
  }, REAL);
  return page.evaluate(fn, arg);
}

/// Two templates with roles, each with a one-page document and its fields: the NDA
/// (Buyer signs) and the order (buyer's date, Seller signs). Answers their names.
async function makeTemplates(page, run) {
  const pdf = (title) => Buffer.from(makePdf([{ title, lines: ["Between the parties below.", "Signed on the date shown."] }])).toString("base64");
  const nda = `VS-03 NDA ${run}`;
  const order = `VS-03 Order ${run}`;
  await inApp(page, async ({ specs }) => {
    const api = window.__vs03;
    const bytes = (b64) => Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
    for (const s of specs) {
      const tp = await api.templates.create({ name: s.name, email_subject: `Please sign: ${s.name}`, roles: s.roles });
      const whole = await api.templates.addDocument(tp.id, `${s.file}.pdf`, bytes(s.pdf));
      const doc = whole.documents[0].id;
      const role = (n) => whole.roles.find((r) => r.name === n).id;
      await api.templates.addFields(tp.id, s.fields.map(([who, type, y]) => ({
        role_id: role(who), document_id: doc, type, required: type === "signature",
        placement: { page: 1, x: "72", y: String(y), width: "180", height: "36" },
      })));
    }
  }, {
    specs: [
      { name: nda, file: "nda", pdf: pdf("Mutual NDA"), roles: [{ name: "Buyer", type: "signer", routing_order: 1 }], fields: [["Buyer", "signature", 420]] },
      { name: order, file: "order", pdf: pdf("Purchase order"), roles: [{ name: "buyer", type: "signer", routing_order: 1 }, { name: "Seller", type: "signer", routing_order: 2 }], fields: [["buyer", "date_signed", 360], ["Seller", "signature", 480]] },
    ],
  });
  return { nda, order };
}

/// Mock: the signing token the mock gave `email` on envelope `id` (null until routing
/// reaches them), read through api.js against the tab's own mock.
function mockToken(page, id, email) {
  return page.evaluate(async ({ id, email }) => {
    const { createClient } = await import("/api.js");
    const { createMockFetch } = await import("/mock.js");
    const api = createClient({ fetch: createMockFetch({ store: sessionStorage }), store: sessionStorage });
    const { envelope: env } = await api.getEnvelope(id);
    return env.recipients.find((r) => r.email === email)?.mock_token || null;
  }, { id, email });
}

/// Consent when the account asks for it, then the documents step.
async function openDocuments(p) {
  const consent = p.getByRole("heading", { name: "Electronic records and signatures" });
  const progress = p.locator("#guide-progress");
  await expect(consent.or(progress).first()).toBeVisible();
  if (await consent.isVisible()) {
    await p.getByLabel("I agree to use electronic records and signatures.").check();
    await p.getByRole("button", { name: "Continue" }).click();
  }
  await expect(progress).toBeVisible();
  await expect(p.locator(".os-page.is-loading")).toHaveCount(0);
}

test("slice 3 (VS-03): a template filed in a folder, used together with a second template, signed by the roles in order, then saved as a template", async ({ page, browser }, testInfo) => {
  test.setTimeout(REAL ? 420_000 : 120_000);
  const run = `${Date.now()}-${testInfo.project.name}-${Math.random().toString(36).slice(2, 8)}`;
  const buyer = { name: "Bea Buyer", email: `vs03-buyer-${run}@example.com` };
  const seller = { name: "Sol Seller", email: `vs03-seller-${run}@example.com` };
  const subject = `VS-03 deal ${run}`;
  const started = Date.now() - 5_000;
  if (REAL) fs.mkdirSync(DEMO, { recursive: true });
  const demo = (step) => path.join(DEMO, `vs03-${testInfo.project.name}-${step}.webm`);

  await signIn(page, "home");
  const { nda, order } = await makeTemplates(page, run);

  // Folders: a new template folder; the NDA moved into it; the filter finds it there.
  await page.goto(app("#/templates"), { waitUntil: "domcontentloaded" });
  await page.reload({ waitUntil: "domcontentloaded" });
  await expect(page.getByRole("heading", { name: "Templates", exact: true })).toBeVisible();
  const folder = `VS-03 ${run}`;
  await page.getByTestId("tpl-new-folder").click();
  await page.getByTestId("tpl-folder-name").fill(folder);
  await page.getByTestId("tpl-folder-create").click();
  await expect(page.locator(".os-toast").last()).toContainText(`Folder ${folder} created.`);
  const ndaRow = page.locator("tr.os-row", { hasText: nda });
  await ndaRow.getByRole("button", { name: `Actions for ${nda}` }).click();
  await page.getByRole("menuitem", { name: "Move to folder" }).click();
  await page.getByTestId("tpl-move-to").selectOption({ label: folder });
  await page.getByTestId("tpl-move-save").click();
  await expect(page.locator(".os-toast").last()).toContainText(`Moved to ${folder}.`);
  await expect(ndaRow.getByTestId("tpl-in-folder")).toHaveText(folder);
  await page.getByTestId("tpl-folder").selectOption({ label: `${folder} (1)` });
  await expect(page.locator("tr.os-row")).toHaveCount(1);
  await expect(page.locator("tr.os-row", { hasText: nda })).toBeVisible();
  await page.getByTestId("tpl-folder").selectOption({ label: "Not in a folder" });
  await expect(page.locator("tr.os-row", { hasText: order })).toBeVisible();
  await expect(page.locator("tr.os-row", { hasText: nda })).toHaveCount(0);
  await page.getByTestId("tpl-folder").selectOption({ label: folder + " (1)" });

  // Use the NDA, and add the order template to the same envelope: one Buyer for both.
  await page.locator("tr.os-row", { hasText: nda }).getByRole("button", { name: `Use ${nda}` }).click();
  await expect(page.getByRole("heading", { name: `Use ${nda}` })).toBeVisible();
  await expect(page.getByTestId("use-template")).toHaveCount(1);
  await page.getByTestId("use-add-template").selectOption({ label: order });
  await expect(page.getByTestId("use-template")).toHaveCount(2);
  await expect(page.getByTestId("use-templates")).toContainText(order);
  await expect(page.getByTestId("use-name")).toHaveCount(2);
  await expect(page.locator(".os-use__role strong").filter({ hasText: /^(Buyer|Seller)$/ })).toHaveText(["Buyer", "Seller"]);
  await expect(page.getByTestId("use-fields-n")).toHaveText("3 fields placed for the roles.");
  await page.getByTestId("use-name").nth(0).fill(buyer.name);
  await page.getByTestId("use-email").nth(0).fill(buyer.email);
  await page.getByTestId("use-name").nth(1).fill(seller.name);
  await page.getByTestId("use-email").nth(1).fill(seller.email);
  await page.getByLabel("Subject").fill(subject);
  await page.getByTestId("use-send").click();
  await page.getByRole("dialog", { name: "Send this envelope?" }).getByRole("button", { name: "Send" }).click();
  await expect(page).toHaveURL(/#\/envelopes\/[^/]+$/, { timeout: 20_000 });
  await expect(page.locator(".os-page-head .os-badge")).toHaveText("Sent");
  const id = decodeURIComponent(page.url().match(/#\/envelopes\/([^/]+)$/)[1]);
  // The envelope holds both templates' documents and the Buyer's fields from both.
  const made = await inApp(page, async ({ id, email }) => {
    const { envelope: e } = await window.__vs03.getEnvelope(id);
    const r = e.recipients.find((x) => x.email === email);
    return { docs: e.documents.length, buyerDocs: [...new Set(e.fields.filter((f) => f.recipient_id === r.id).map((f) => f.document_id))].length, people: e.recipients.length };
  }, { id, email: buyer.email });
  expect(made).toEqual({ docs: 2, buyerDocs: 2, people: 2 });

  // Each signer in turn, through their own link.
  const linkFor = async (who) => {
    if (REAL) return emailedLink(who.email, started);
    await expect.poll(() => mockToken(page, id, who.email), { message: `a link for ${who.name}` }).not.toBeNull();
    return signPage(await mockToken(page, id, who.email));
  };
  const sign = async (who, step) => {
    const link = await linkFor(who);
    let p = page;
    let context = null;
    if (REAL) {
      context = await browser.newContext({ viewport: SIZE, recordVideo: { dir: testInfo.outputPath(`video-${step}`), size: SIZE } });
      p = await context.newPage();
      await p.goto(link, { waitUntil: "domcontentloaded" });
    } else {
      await page.goto(link);
    }
    await openDocuments(p);
    await expect(p.locator(".os-sign__pages .os-page")).toHaveCount(2);
    await expect(p.locator("#guide-progress")).toHaveText("0 of 1 required");
    await p.getByRole("button", { name: /Signature, required/ }).click();
    const dlg = p.getByRole("dialog", { name: "Adopt your signature" });
    await expect(dlg.getByLabel("Your full name")).toHaveValue(who.name);
    await dlg.getByTestId("adopt-confirm").click();
    await expect(dlg).toBeHidden();
    await p.getByRole("button", { name: "Finish" }).click();
    await expect(p.getByRole("heading", { name: "Review and finish" })).toBeVisible();
    await p.getByTestId("review-finish").click();
    await expect(p.getByTestId("sign-done")).toBeVisible();
    if (context) {
      await context.close();
      await p.video()?.saveAs(demo(step));
    }
  };
  if (!REAL) expect(await mockToken(page, id, seller.email), "the Seller waits for the Buyer").toBeNull();
  await sign(buyer, "2-buyer-signs-both-documents");
  await sign(seller, "3-seller-signs");

  // Completed; saved as a template, whose roles come from the envelope's recipients.
  if (!REAL) await page.goto(app(`#/envelopes/${encodeURIComponent(id)}`));
  await expect(async () => {
    await page.reload();
    await expect(page.locator(".os-page-head .os-badge")).toHaveText("Completed", { timeout: 2_000 });
  }).toPass({ timeout: 120_000, intervals: [2_000] });
  const direct = page.getByTestId("envelope-template");
  if (await direct.isVisible()) await direct.click();
  else {
    await page.getByTestId("envelope-more").click();
    await page.getByRole("menuitem", { name: "Save as template" }).click();
  }
  await expect(page.locator(".os-toast").last()).toContainText(`Saved as template ${subject}`);
  await page.goto(app("#/templates"));
  const saved = page.locator("tr.os-row", { hasText: subject });
  await expect(saved).toBeVisible();
  await saved.getByRole("link", { name: subject }).click();
  await expect(page.locator(".os-use__role strong").filter({ hasText: /^Role \d$/ })).toHaveText(["Role 1", "Role 2"]);
  if (!REAL) return;
  await page.close();
  await page.video()?.saveAs(demo("1-4-sender-folders-uses-two-templates-saves"));
});

for (const scheme of ["light", "dark"]) {
  test.describe(`${scheme} theme`, () => {
    test.use({ colorScheme: scheme });
    test.beforeEach(async ({ page }) => { await page.addInitScript((s) => { try { localStorage.setItem("openseal.theme", s); } catch { /* storage off */ } }, scheme); });

    test("templates: the list with folders, the folder and move panels, and using two templates are accessible", async ({ page }, testInfo) => {
      test.setTimeout(120_000);
      const run = `${Date.now()}-${testInfo.project.name}-${scheme}`;
      await signIn(page, "home");
      const { nda, order } = await makeTemplates(page, run);
      await page.goto(app("#/templates"), { waitUntil: "domcontentloaded" });
      await page.reload({ waitUntil: "domcontentloaded" });
      await expect(page.locator("tr.os-row", { hasText: nda })).toBeVisible();
      await page.getByTestId("tpl-new-folder").click();
      await page.getByTestId("tpl-folder-name").fill(`A11y ${run}`);
      await expectAccessible(page, `new template folder (${scheme})`);
      await page.getByTestId("tpl-folder-create").click();
      await expect(page.locator(".os-toast").last()).toContainText("created");
      const row = page.locator("tr.os-row", { hasText: nda });
      await row.getByRole("button", { name: `Actions for ${nda}` }).click();
      await page.getByRole("menuitem", { name: "Move to folder" }).click();
      await page.getByTestId("tpl-move-to").selectOption({ label: `A11y ${run}` });
      await expectAccessible(page, `move to folder (${scheme})`);
      await page.getByTestId("tpl-move-save").click();
      await expect(row.getByTestId("tpl-in-folder")).toBeVisible();
      await expectAccessible(page, `templates with folders (${scheme})`);
      await row.getByRole("button", { name: `Use ${nda}` }).click();
      await page.getByTestId("use-add-template").selectOption({ label: order });
      await expect(page.getByTestId("use-template")).toHaveCount(2);
      await expect(page.locator(".os-preview__pages")).toHaveCount(2);
      await expectAccessible(page, `use two templates (${scheme})`);
    });
  });
}
