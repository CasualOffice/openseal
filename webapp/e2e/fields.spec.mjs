// VS-04 (slice 4, every field), in a browser: a signer fills every field kind slice 4
// adds, the field logic works as the server says (a condition shows a field, a formula
// computes, linked fields mirror, a checkbox group's rule holds), and the envelope
// completes.
//
// The sender makes the envelope through api.js's client (every kind and the logic as
// the API takes them); the editor's Logic panel has its own test below. Both modes. On
// the Compose deployment (compose-e2e) the link is the one the worker emailed, read from
// Mailpit, the signer acts in a browser context of their own, and the run is recorded as
// the slice 4 demo (target/e2e-demo/vs04-*, uploaded as `slice-4-demo`). In mock mode
// the link is the mock's token and the mock answers the rules through fieldrules.js.
// Every run has its own names and addresses, and the spec changes no account setting.
//
// The last tests scan the new signing controls and the editor's Logic panel with axe,
// light and dark.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { test, expect } from "@playwright/test";
import { signIn, REAL, app, signPage, expectAccessible, pdfFile, placingFor } from "./helpers.mjs";
import { makePdf } from "../mockpdf.js";

const MAIL = (process.env.OPENSEAL_E2E_MAIL_URL || "http://127.0.0.1:8025").replace(/\/$/, "");
const DEMO = path.resolve(fileURLToPath(new URL("../../target/e2e-demo", import.meta.url)));
const SIZE = { width: 1280, height: 800 };
// A 1×1 PNG, the stamp's image.
const STAMP = Buffer.from("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR4nGM4ISf3HwAEugIEPlcfxwAAAABJRU5ErkJggg==", "base64");

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

/// Every kind slice 4 adds and the logic, on page 1 of a one-page document, for `r0`.
const FIELDS = [
  ["signature", 60, { required: true }],
  ["checkbox", 110, { label: "agree" }],
  ["text", 140, { label: "detail", required: true, conditional: { parent_label: "agree", when: "checked" } }],
  ["number", 170, { label: "qty" }],
  ["number", 200, { label: "price" }],
  ["formula", 230, { label: "total", formula: { expression: "qty * price", precision: 2 } }],
  ["text", 260, { label: "ref" }],
  ["text", 290, { label: "ref", x: 330 }],
  ["date", 320, { label: "start", format: { date_format: "dd_mm_yyyy" } }],
  ["ssn", 350, { label: "ssn" }],
  ["zip", 380, { label: "zip" }],
  ["email_address", 410, { label: "mail" }],
  ["phone", 440, { label: "tel" }],
  ["multi_select", 470, { label: "extras", options: ["Insurance", "Delivery", "Warranty"] }],
  ["stamp", 500, { label: "seal" }],
  ["drawing", 540, { label: "sketch" }],
  ["envelope_id", 590, { label: "envid" }],
  ["hyperlink", 620, { label: "Terms", value: { text: "https://example.test/terms" }, read_only: true }],
  ["checkbox", 650, { label: "opt_a", group: { id: "opts", rule: { rule: "select_at_least", min: 1 } } }],
  ["checkbox", 650, { label: "opt_b", x: 200, group: { id: "opts", rule: { rule: "select_at_least", min: 1 } } }],
];

/// Make and send the envelope in the signed-in app page (the page's CSP allows no
/// eval); answers `{id, ids: label → field id, token}` (`token` in mock mode only).
async function makeEnvelope(page, { name, email, subject }) {
  const pdf = Buffer.from(makePdf([{ title: "Application form", lines: ["Fill in every field below.", "Signed on the date shown."] }])).toString("base64");
  return page.evaluate(async ({ real, pdf, fields, name, email, subject }) => {
    const { createClient, recipientWire, fieldWire } = await import(new URL("api.js", location.href).href);
    const opts = { store: sessionStorage };
    if (!real) opts.fetch = (await import(new URL("mock.js", location.href).href)).createMockFetch({ store: sessionStorage });
    const api = createClient(opts);
    const env = await api.createEnvelope({
      subject, status: "sent",
      documents: [{ name: "application.pdf", content_base64: pdf }],
      recipients: [recipientWire({ ref: "r0", routing_order: 1, name, email, type: "signer" })],
      fields: fields.map(([type, y, extra]) => fieldWire({ recipient: "r0", document: 0, type, page: 1, x: 72, y, width: 220, height: type === "drawing" || type === "stamp" ? 40 : 22, ...extra })),
    });
    const ids = {};
    for (const f of env.fields) if (f.label) (ids[f.label] ||= []).push(f.id); else ids[f.type] = [f.id];
    return { id: env.id, ids, token: env.recipients[0].mock_token || null };
  }, { real: REAL, pdf, fields: FIELDS, name, email, subject });
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

const field = (p, id) => p.locator(`.os-sfield[data-field-id="${id}"]`);

async function type(p, id, value) {
  const input = field(p, id).locator("input, textarea").first();
  await input.fill(value);
  await input.press("Tab");
  await expect(field(p, id)).toHaveClass(/is-done/);
}

test("slice 4 (VS-04): a signer fills every field kind, the logic follows the server, and the envelope completes", async ({ page, browser }, testInfo) => {
  test.setTimeout(REAL ? 300_000 : 120_000);
  const run = `${Date.now()}-${testInfo.project.name}-${Math.random().toString(36).slice(2, 8)}`;
  const who = { name: "Fay Fields", email: `vs04-${run}@example.com`, subject: `VS-04 application ${run}` };
  const started = Date.now() - 5_000;
  await signIn(page, "home");
  const { id, ids, token } = await makeEnvelope(page, who);
  const one = (label) => ids[label][0];

  let p = page;
  let context = null;
  if (REAL) {
    fs.mkdirSync(DEMO, { recursive: true });
    context = await browser.newContext({ viewport: SIZE, recordVideo: { dir: testInfo.outputPath("video"), size: SIZE } });
    p = await context.newPage();
    await p.goto(await emailedLink(who.email, started), { waitUntil: "domcontentloaded" });
  } else {
    await page.goto(signPage(token));
  }
  await openDocuments(p);

  // Conditional: the detail is hidden until "agree" is ticked.
  await expect(field(p, one("detail"))).toBeHidden();
  await field(p, one("agree")).locator("input").check();
  await expect(field(p, one("detail"))).toBeVisible();
  await type(p, one("detail"), "Details given");

  // Formula: the total follows its lines, worked out by the server.
  await type(p, one("qty"), "4");
  await type(p, one("price"), "2.25");
  await expect(field(p, one("total"))).toContainText("9.00");

  // Linked: one "ref" mirrors the other.
  await type(p, ids.ref[0], "R-77");
  await expect(field(p, ids.ref[1]).locator("input")).toHaveValue("R-77");

  // Each kind's check, as the engine's: a bad value is said beside the field.
  const ssn = field(p, one("ssn")).locator("input");
  await ssn.fill("666-12-3456");
  await ssn.press("Tab");
  await expect(field(p, one("ssn")).locator(".os-sfield__err")).toHaveText("Enter a Social Security number of 9 digits, like 123-45-6789.");
  await type(p, one("ssn"), "123-45-6789");
  const start = field(p, one("start")).locator("input");
  await start.fill("31/02/2026");
  await start.press("Tab");
  await expect(field(p, one("start")).locator(".os-sfield__err")).toHaveText("Enter a real date as DD/MM/YYYY.");
  await type(p, one("start"), "02/03/2026");
  await type(p, one("zip"), "94105-1234");
  await type(p, one("mail"), "fay@example.test");
  await type(p, one("tel"), "+44 20 7946 0958");

  // Multi-select: two options saved together.
  await field(p, one("extras")).getByTestId("multi-open").click();
  await p.getByLabel("Warranty").check();
  await p.getByLabel("Insurance").check();
  await p.getByTestId("multi-save").click();
  await expect(field(p, one("extras"))).toContainText("Insurance, Warranty");

  // Stamp (an image) and drawing (on the pad), each adopted as what it is.
  await field(p, one("seal")).getByTestId("stamp-field").click();
  await p.getByTestId("stamp-file").setInputFiles({ name: "stamp.png", mimeType: "image/png", buffer: STAMP });
  await p.getByTestId("image-use").click();
  await expect(field(p, one("seal"))).toHaveClass(/is-done/);
  await field(p, one("sketch")).getByTestId("drawing-field").click();
  const pad = p.getByTestId("drawing-pad");
  const box = await pad.boundingBox();
  await p.mouse.move(box.x + 20, box.y + 20);
  await p.mouse.down();
  await p.mouse.move(box.x + box.width / 2, box.y + box.height / 2, { steps: 5 });
  await p.mouse.move(box.x + box.width - 20, box.y + 30, { steps: 5 });
  await p.mouse.up();
  await p.getByTestId("image-use").click();
  await expect(field(p, one("sketch"))).toHaveClass(/is-done/);

  // The envelope id and the link are shown; the link opens only https.
  await expect(field(p, one("envid"))).toContainText(id);
  await expect(field(p, one("Terms")).getByTestId("field-link")).toHaveAttribute("href", "https://example.test/terms");
  await expect(field(p, one("Terms")).getByTestId("field-link")).toHaveAttribute("rel", "noopener noreferrer");

  // The group needs one box; the signature; then finish.
  await field(p, one("opt_b")).locator("input").check();
  await p.getByRole("button", { name: /Signature, required/ }).click();
  const dlg = p.getByRole("dialog", { name: /Adopt your signature/ });
  await dlg.getByTestId("adopt-confirm").click();
  await expect(dlg).toBeHidden();
  await p.getByRole("button", { name: "Finish" }).click();
  await expect(p.getByRole("heading", { name: "Review and finish" })).toBeVisible();
  await p.getByTestId("review-finish").click();
  await expect(p.getByTestId("sign-done")).toBeVisible();
  if (context) {
    await context.close();
    await p.video()?.saveAs(path.join(DEMO, `vs04-${testInfo.project.name}-signer-fills-every-field.webm`));
  }

  // The sender sees it completed.
  if (!REAL) await page.goto(app(`#/envelopes/${encodeURIComponent(id)}`));
  else await page.goto(app(`#/envelopes/${encodeURIComponent(id)}`));
  await expect(async () => {
    await page.reload();
    await expect(page.locator(".os-page-head .os-badge")).toHaveText("Completed", { timeout: 2_000 });
  }).toPass({ timeout: 120_000, intervals: [2_000] });
});

for (const scheme of ["light", "dark"]) {
  test.describe(`${scheme} theme`, () => {
    test.use({ colorScheme: scheme });
    test.beforeEach(async ({ page }) => { await page.addInitScript((s) => { try { localStorage.setItem("openseal.theme", s); } catch { /* storage off */ } }, scheme); });

    test("every field: the signing controls, the multi-select panel and the drawing pad are accessible", async ({ page }, testInfo) => {
      test.skip(REAL, "the link is emailed on a real server; the slice test walks it there");
      const run = `${Date.now()}-${testInfo.project.name}-${scheme}`;
      await signIn(page, "home");
      const { ids, token } = await makeEnvelope(page, { name: "Ally Access", email: `vs04-a11y-${run}@example.com`, subject: `VS-04 a11y ${run}` });
      await page.goto(signPage(token));
      await openDocuments(page);
      await expectAccessible(page, `every field kind (${scheme})`);
      await field(page, ids.extras[0]).getByTestId("multi-open").click();
      await expectAccessible(page, `multi-select panel (${scheme})`);
      await page.getByRole("button", { name: "Cancel" }).click();
      await field(page, ids.sketch[0]).getByTestId("drawing-field").click();
      await expect(page.getByTestId("drawing-pad")).toBeVisible();
      await expectAccessible(page, `drawing pad (${scheme})`);
    });

    test("every field: the editor's Logic panel sets a condition, a group and a formula, and is accessible", async ({ page }) => {
      test.skip(REAL, "reads the field's members from the mock's store; the slice test sends on the real stack");
      await signIn(page);
      await page.goto(app("#/prepare"));
      await page.getByTestId("pdf-input").setInputFiles(pdfFile("logic.pdf", "Logic form"));
      await expect(page.getByTestId("doc-card")).toHaveCount(1);
      await page.getByTestId("wizard-next").click();
      await page.getByRole("button", { name: "Add recipient" }).first().click();
      const row = page.locator(".os-rcpt").first();
      await row.getByTestId("recipient-name").fill("Lou Logic");
      await row.getByTestId("recipient-email").fill("lou@example.com");
      await row.getByTestId("recipient-email").blur();
      await page.getByTestId("wizard-next").click();
      await expect(page.locator(".os-page.is-loading")).toHaveCount(0);
      await placingFor(page, 0);
      const add = (kind) => page.locator(".os-palette").getByRole("button", { name: `Add ${kind} field` }).press("Enter");
      const label = async (sel, text) => {
        await page.locator(sel).first().click();
        await page.getByLabel("Data label", { exact: true }).fill(text);
        await page.getByLabel("Data label", { exact: true }).blur();
      };
      await add("Signature");
      await add("Checkbox");
      await label('.os-field[data-field="checkbox"]', "agree");
      await add("Text");
      await label('.os-field[data-field="text"]', "detail");
      // The text shows only when "agree" is checked.
      await page.getByTestId("cond-parent").selectOption("agree");
      await expect(page.getByTestId("cond-when")).toHaveValue("checked");
      await expectAccessible(page, `editor Logic panel (${scheme})`);
      // The checkbox belongs to a group of at least one.
      await page.locator('.os-field[data-field="checkbox"]').first().click();
      await page.getByLabel("Checkbox group").fill("opts");
      await page.getByLabel("Checkbox group").blur();
      await expect(page.getByLabel("Rule")).toHaveValue("select_at_least");
      // A formula field over the label.
      await add("Formula");
      await page.locator('.os-field[data-field="formula"]').first().click();
      await page.getByLabel("Formula", { exact: true }).fill("agree * 2");
      await page.getByLabel("Formula", { exact: true }).blur();
      await expectAccessible(page, `editor Logic panel with a formula (${scheme})`);
      // The draft keeps them as the engine takes them.
      await page.getByTestId("wizard-next").click();
      await page.getByLabel("Subject").fill(`Logic ${scheme}`);
      await page.getByRole("button", { name: "Send", exact: true }).first().click();
      await page.getByRole("dialog", { name: "Send this envelope?" }).getByRole("button", { name: "Send" }).click();
      await expect(page.locator(".os-page-head .os-badge")).toHaveText("Sent", { timeout: 20_000 });
      const fields = await page.evaluate((s) => JSON.parse(sessionStorage.getItem("openseal.mock.v1")).envelopes.find((e) => e.subject === s).fields, `Logic ${scheme}`);
      expect(fields.find((f) => f.label === "detail").conditional).toEqual({ parent_label: "agree", when: "checked" });
      expect(fields.find((f) => f.label === "agree").group).toEqual({ id: "opts", rule: { rule: "select_at_least", min: 1 } });
      expect(fields.find((f) => f.type === "formula").formula).toEqual({ expression: "agree * 2", precision: 2 });
    });
  });
}
