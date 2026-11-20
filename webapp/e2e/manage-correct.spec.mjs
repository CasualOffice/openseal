// Slice 6, Manage and correct (VS-06), in the browser: a signer fails their access code
// and the envelope shows in Agreements' Authentication failed view until it is resent;
// custom fields are added and searched; documents and fields are corrected in the
// editor; a copy is made; the server's reports are downloaded; the envelope is
// transferred to another member. On the Compose stack (`compose-e2e`) the envelope is
// sent for the run, its link read from Mailpit, and every screen is recorded as the
// slice 6 demo (target/e2e-demo/vs06-*, uploaded as `slice-6-demo`). In mock mode the
// seeded "Offer letter" (access code, signing token) is used. Then axe, light and dark,
// on each new screen (mock mode).
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { test, expect } from "@playwright/test";
import { signIn, app, signPage, tokens, pdfFile, expectAccessible, REAL } from "./helpers.mjs";
import { makePdf } from "../mockpdf.js";

const MAIL = (process.env.OPENSEAL_E2E_MAIL_URL || "http://127.0.0.1:8025").replace(/\/$/, "");
const DEMO = path.resolve(fileURLToPath(new URL("../../target/e2e-demo", import.meta.url)));
const SIZE = { width: 1280, height: 800 };
const CODE = "vs06-4711";
const OFFER = "Offer letter — Jordan Rivera";

test.use({ video: REAL ? { mode: "on", size: SIZE } : "off" });

/// Run `fn(arg)` in the signed-in app page with api.js's client on `window.__vs06`.
async function inApp(page, fn, arg) {
  await page.evaluate(async (real) => {
    const { createClient } = await import(new URL("api.js", location.href).href);
    const opts = { store: sessionStorage };
    if (!real) opts.fetch = (await import(new URL("mock.js", location.href).href)).createMockFetch({ store: sessionStorage });
    window.__vs06 = createClient(opts);
  }, REAL);
  return page.evaluate(fn, arg);
}

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

/// The envelope page's More menu item `name`.
async function more(page, name) {
  await page.getByTestId("envelope-more").click();
  await page.getByRole("menuitem", { name, exact: true }).click();
}

const row = (page, subject) => page.locator(".os-agr-row[data-id]", { hasText: subject });

test("slice 6 (VS-06): authentication failed view, resend, custom fields and search, correct documents, copy, reports, transfer", async ({ page }, testInfo) => {
  test.skip(!REAL && testInfo.project.name !== "chromium" && testInfo.project.name !== "webkit", "desktop browsers");
  test.setTimeout(REAL ? 300_000 : 120_000);
  const run = `${Date.now()}-${testInfo.project.name}-${Math.random().toString(36).slice(2, 8)}`;
  if (REAL) fs.mkdirSync(DEMO, { recursive: true });
  await page.setViewportSize(SIZE);
  await signIn(page, "home");

  // The envelope and the member it is transferred to.
  let id;
  let subject;
  let link;
  let member;
  if (REAL) {
    subject = `VS-06 lease ${run}`;
    const started = Date.now();
    const signer = `vs06-${run}@example.com`;
    const made = await inApp(page, async ({ subject, signer, pdf, code, run }) => {
      const api = window.__vs06;
      const e = await api.createEnvelope({
        subject, status: "sent",
        documents: [{ name: "lease.pdf", content_base64: pdf }],
        recipients: [{ ref: "s", type: "signer", name: "Lee Lessee", email: signer, routing_order: 1, auth: ["access_code"], access_code: code }],
        fields: [{ recipient: "s", document: 0, type: "signature", page: 1, x: 72, y: 600, width: 180, height: 40, required: true }],
      });
      const u = await api.users.create({ email: `vs06-member-${run}@example.com`, name: `Mo Member ${run}`, profile: "sender", password: `Vs06-${run}-pass!` });
      return { id: e.id, member: u.name };
    }, { subject, signer, pdf: Buffer.from(makePdf([{ title: subject, lines: ["Clause 1."] }])).toString("base64"), code: CODE, run });
    id = made.id;
    member = made.member;
    link = await emailedLink(signer, started);
  } else {
    subject = OFFER;
    id = await page.evaluate((s) => JSON.parse(sessionStorage.getItem("openseal.mock.v1")).envelopes.find((e) => e.subject === s).id, subject);
    link = signPage(tokens.sign);
    member = "Robin Sender";
  }

  // 1. The signer types a wrong access code.
  await page.goto(link, { waitUntil: "domcontentloaded" });
  await expect(page.getByRole("heading", { name: "Enter your access code" })).toBeVisible();
  await page.getByLabel("Access code").fill("wrong-code");
  await page.getByRole("button", { name: "Continue" }).click();
  await expect(page.getByRole("alert").or(page.locator(".os-field-error")).first()).toBeVisible();

  // 2. Agreements: the Authentication failed view holds it.
  await page.goto(app("#/agreements?folder=authfailed"), { waitUntil: "domcontentloaded" });
  await expect(page.getByRole("heading", { name: "Agreements" })).toBeVisible();
  await expect(page.locator('#nav-views [data-view="authfailed"]')).toBeVisible();
  await expect(row(page, subject)).toBeVisible();

  // 3. The envelope page: Resend clears the failure; the view lets it go.
  await page.goto(app(`#/envelopes/${encodeURIComponent(id)}`), { waitUntil: "domcontentloaded" });
  await expect(page.getByRole("heading", { name: subject })).toBeVisible();
  await page.getByTestId("envelope-resend").click();
  await expect(page.getByText("Resent to everyone who has not finished.")).toBeVisible();
  await page.goto(app("#/agreements?folder=authfailed"), { waitUntil: "domcontentloaded" });
  await expect(page.getByRole("heading", { name: "Agreements" })).toBeVisible();
  await expect(row(page, subject)).toHaveCount(0);

  // 4. Custom fields on the envelope, then found by them in Agreements.
  const deal = `D-${run}`;
  await page.goto(app(`#/envelopes/${encodeURIComponent(id)}`), { waitUntil: "domcontentloaded" });
  await expect(page.getByRole("heading", { name: subject })).toBeVisible();
  await more(page, "Edit custom fields");
  const cf = page.getByRole("dialog", { name: "Custom fields" });
  await cf.getByTestId("cf-add").click();
  await cf.getByTestId("cf-name").last().fill("Deal");
  await cf.getByTestId("cf-value").last().fill(deal);
  await cf.getByTestId("cf-save").click();
  await expect(page.getByText("Custom fields saved")).toBeVisible();
  await expect(page.getByTestId("custom-fields-card")).toContainText(deal);
  await page.goto(app("#/agreements"), { waitUntil: "domcontentloaded" });
  await expect(page.getByRole("heading", { name: "Agreements" })).toBeVisible();
  await page.getByTestId("filters-toggle").click();
  await page.getByTestId("filter-cf-name").fill("Deal");
  await page.getByTestId("filter-cf-value").fill(deal);
  await page.getByTestId("filter-cf-value").press("Tab");
  await expect(row(page, subject)).toBeVisible();
  await expect(page.locator(".os-agr-row[data-id]")).toHaveCount(1);

  // 5. Correct documents and fields: an annex added in the editor's Correct mode.
  await page.goto(app(`#/envelopes/${encodeURIComponent(id)}`), { waitUntil: "domcontentloaded" });
  const docs = page.getByTestId("envelope-documents").locator("[data-doc]");
  await expect(docs.first()).toBeVisible();
  const before = await docs.count();
  await more(page, "Correct documents and fields");
  await expect(page.locator(".os-prepare__title")).toContainText("Correcting:");
  await page.locator('.os-stepper__btn', { hasText: "Documents" }).click();
  await page.getByTestId("pdf-input").setInputFiles(pdfFile("annex.pdf", `Annex ${run}`));
  await expect(page.getByTestId("doc-card")).toHaveCount(before + 1);
  await page.locator(".os-stepper__btn", { hasText: "Review and send" }).click();
  await page.getByTestId("correct-finish").click();
  const confirm = page.getByRole("dialog", { name: "Save this correction?" });
  await confirm.getByRole("button", { name: "Save correction" }).click();
  await expect(page.getByRole("heading", { name: subject })).toBeVisible({ timeout: 20_000 });
  await expect(docs).toHaveCount(before + 1);
  await expect(page.getByText("Envelope corrected").first()).toBeVisible();

  // 6. Copy: a new draft with the same documents and people.
  await more(page, "Copy");
  await expect(page.locator(".os-prepare__title")).toContainText("(copy)", { timeout: 20_000 });
  await page.goto(app(`#/envelopes/${encodeURIComponent(id)}`), { waitUntil: "domcontentloaded" });
  await expect(page.getByRole("heading", { name: subject })).toBeVisible();

  // 7. Reports: the server's recipient report as CSV names the envelope.
  await page.goto(app("#/reports"), { waitUntil: "domcontentloaded" });
  await expect(page.getByTestId("server-reports")).toBeVisible();
  const [dl] = await Promise.all([page.waitForEvent("download"), page.getByTestId("server-report-recipients").click()]);
  const csv = fs.readFileSync(await dl.path(), "utf8");
  expect(csv.startsWith("envelope_id,subject,envelope_status,routing_order,name,email,type,status")).toBe(true);
  expect(csv).toContain(id);

  // 8. Transfer to another member: the trail records it.
  await page.goto(app(`#/envelopes/${encodeURIComponent(id)}`), { waitUntil: "domcontentloaded" });
  await expect(page.getByRole("heading", { name: subject })).toBeVisible();
  await more(page, "Transfer");
  const tr = page.getByRole("dialog", { name: "Transfer agreement" });
  const value = await tr.getByTestId("transfer-user").locator("option", { hasText: member }).first().getAttribute("value");
  await tr.getByTestId("transfer-user").selectOption(value);
  await tr.getByTestId("transfer-save").click();
  await expect(page.getByText(`Transferred to ${member}`)).toBeVisible();
  await expect(page.getByText("Ownership transferred").first()).toBeVisible();

  if (REAL) await page.video()?.saveAs(path.join(DEMO, `vs06-${testInfo.project.name}-manage-and-correct.webm`));
});

// WEB-07 on the Compose stack: the signer's own history and reassignment, through the
// signing page's More menu, on an envelope sent with reassignment allowed (its link
// read from Mailpit). guided-ceremony.spec.mjs covers the same in mock mode.
test("WEB-07: a signer reads their history and assigns the envelope to someone else on the server", async ({ page }, testInfo) => {
  test.skip(!REAL, "runs against a real server only (OPENSEAL_E2E_BASE_URL)");
  test.setTimeout(240_000);
  const run = `${Date.now()}-${testInfo.project.name}-${Math.random().toString(36).slice(2, 8)}`;
  await signIn(page, "home");
  const started = Date.now();
  const signer = `web07-${run}@example.com`;
  await inApp(page, ({ run, signer, pdf }) => window.__vs06.createEnvelope({
    subject: `WEB-07 ${run}`, status: "sent", signing_options: { allow_reassign: true },
    documents: [{ name: "w.pdf", content_base64: pdf }],
    recipients: [{ ref: "s", type: "signer", name: "Wes Signer", email: signer, routing_order: 1 }],
    fields: [{ recipient: "s", document: 0, type: "signature", page: 1, x: 72, y: 600, width: 180, height: 40, required: true }],
  }), { run, signer, pdf: Buffer.from(makePdf([{ title: `WEB-07 ${run}` }])).toString("base64") });
  const link = await emailedLink(signer, started);
  await page.goto(link, { waitUntil: "domcontentloaded" });
  const consent = page.getByRole("heading", { name: "Electronic records and signatures" });
  const progress = page.locator("#guide-progress");
  await expect(consent.or(progress).first()).toBeVisible();
  if (await consent.isVisible()) {
    await page.getByLabel("I agree to use electronic records and signatures.").check();
    await page.getByRole("button", { name: "Continue" }).click();
  }
  await expect(progress).toBeVisible();
  const more = page.getByRole("button", { name: "More" });
  await more.click();
  await page.getByRole("menuitem", { name: "View history" }).click();
  const hist = page.getByRole("dialog", { name: "History" });
  await expect(hist.locator('[data-type="envelope.sent"]')).toBeVisible();
  await hist.getByRole("button", { name: "Close" }).first().click();
  await more.click();
  await page.getByRole("menuitem", { name: "Assign to someone else" }).click();
  const re = page.getByRole("dialog", { name: "Assign to someone else" });
  await re.getByLabel("Their full name").fill("Ria Reassigned");
  await re.getByLabel("Their email").fill(`web07-new-${run}@example.com`);
  await re.getByRole("button", { name: "Assign" }).click();
  await expect(re).toBeHidden({ timeout: 20_000 });
  // The new signer is invited by email: the reassignment reached the server.
  expect(await emailedLink(`web07-new-${run}@example.com`, started)).toMatch(/\/s\//);
});

for (const scheme of ["light", "dark"]) {
  test.describe(`slice 6 screens, axe (${scheme})`, () => {
    test.use({ colorScheme: scheme });
    test(`the authentication failed view, custom fields, transfer, correct mode and full reports pass axe (${scheme})`, async ({ page }, testInfo) => {
      test.skip(REAL || (testInfo.project.name !== "chromium" && testInfo.project.name !== "webkit"), "mock data; desktop browsers");
      await signIn(page);
      const id = await page.evaluate((s) => JSON.parse(sessionStorage.getItem("openseal.mock.v1")).envelopes.find((e) => e.subject === s).id, OFFER);
      await page.goto(app("#/agreements?folder=authfailed"));
      await expect(page.getByRole("heading", { name: "Agreements" })).toBeVisible();
      await expectAccessible(page, `authentication failed view (${scheme})`);
      await page.goto(app(`#/envelopes/${encodeURIComponent(id)}`));
      await expect(page.getByRole("heading", { name: OFFER })).toBeVisible();
      await expect(page.getByTestId("custom-fields-card")).toBeVisible();
      await expectAccessible(page, `envelope page with custom fields (${scheme})`);
      await more(page, "Edit custom fields");
      await page.getByRole("dialog", { name: "Custom fields" }).getByTestId("cf-add").click();
      await expectAccessible(page, `custom fields panel (${scheme})`);
      await page.keyboard.press("Escape");
      await more(page, "Transfer");
      await expect(page.getByRole("dialog", { name: "Transfer agreement" })).toBeVisible();
      await expectAccessible(page, `transfer panel (${scheme})`);
      await page.keyboard.press("Escape");
      await more(page, "Correct documents and fields");
      await expect(page.locator(".os-prepare__title")).toContainText("Correcting:");
      await expectAccessible(page, `editor in correct mode (${scheme})`);
      await page.goto(app("#/reports"));
      await expect(page.getByTestId("server-reports")).toBeVisible();
      await expectAccessible(page, `reports with full reports (${scheme})`);
    });
  });
}

// ADR-031 (UXW-02): an envelope deleted from the lists is in the Deleted view; Restore
// there brings it back, and its history shows both the removal and the return. Mock:
// a seeded declined envelope; Compose stack: one sent and voided for the run. Axe,
// light and dark, on the Deleted view (mock).
test("ADR-031: a deleted envelope is restored from the Deleted view, with both events in its history", async ({ page }, testInfo) => {
  test.skip(!REAL && testInfo.project.name !== "chromium" && testInfo.project.name !== "webkit", "desktop browsers");
  test.setTimeout(REAL ? 180_000 : 90_000);
  const run = `${Date.now()}-${testInfo.project.name}-${Math.random().toString(36).slice(2, 8)}`;
  await page.setViewportSize(SIZE);
  await signIn(page, "home");
  let id;
  let subject;
  if (REAL) {
    subject = `ADR-031 restore ${run}`;
    id = await inApp(page, async ({ subject, pdf, run }) => {
      const api = window.__vs06;
      const e = await api.createEnvelope({
        subject, status: "sent",
        documents: [{ name: "r.pdf", content_base64: pdf }],
        recipients: [{ ref: "s", type: "signer", name: "Rae Restore", email: `adr031-${run}@example.com`, routing_order: 1 }],
        fields: [{ recipient: "s", document: 0, type: "signature", page: 1, x: 72, y: 600, width: 180, height: 40, required: true }],
      });
      await api.voidEnvelope(e.id, "Wrong party");
      return e.id;
    }, { subject, pdf: Buffer.from(makePdf([{ title: subject, lines: ["Clause 1."] }])).toString("base64"), run });
  } else {
    ({ id, subject } = await page.evaluate(() => JSON.parse(sessionStorage.getItem("openseal.mock.v1")).envelopes.find((e) => e.status === "declined")));
  }
  // Deleted from its own page.
  await page.goto(app(`#/envelopes/${encodeURIComponent(id)}`), { waitUntil: "domcontentloaded" });
  await expect(page.getByRole("heading", { name: subject })).toBeVisible();
  await more(page, "Delete");
  await page.getByRole("dialog").getByRole("button", { name: "Delete" }).click();
  await expect(page.getByText("Envelope deleted.")).toBeVisible();
  // Only in the Deleted view.
  await page.goto(app("#/agreements"), { waitUntil: "domcontentloaded" });
  await expect(page.getByRole("heading", { name: "Agreements" })).toBeVisible();
  await expect(page.locator(".os-agr-row[data-id]").first()).toBeVisible();
  await expect(row(page, subject)).toHaveCount(0);
  await page.locator('#nav-views [data-view="deleted"]').click();
  await expect(row(page, subject)).toBeVisible();
  if (!REAL) {
    for (const scheme of ["light", "dark"]) {
      await page.emulateMedia({ colorScheme: scheme });
      await expectAccessible(page, `Deleted view (${scheme})`);
    }
    await page.emulateMedia({ colorScheme: "light" });
  }
  await row(page, subject).click();
  await page.getByTestId("inspector-primary").filter({ hasText: "Restore" }).click();
  await expect(page.getByText("Envelope restored to the lists.")).toBeVisible();
  await expect(row(page, subject)).toHaveCount(0);
  // Back in the lists, with both events in its history.
  await page.goto(app("#/agreements?folder=all"), { waitUntil: "domcontentloaded" });
  await expect(row(page, subject)).toBeVisible();
  await page.goto(app(`#/envelopes/${encodeURIComponent(id)}`), { waitUntil: "domcontentloaded" });
  await expect(page.getByRole("heading", { name: subject })).toBeVisible();
  await more(page, "History");
  const hist = page.getByTestId("history-timeline");
  await expect(hist.getByText("Removed from the lists").first()).toBeVisible();
  await expect(hist.getByText("Restored to the lists").first()).toBeVisible();
});

/// The stored entries of a ZIP, from its central directory: `[{name, bytes}]`.
function readZip(buf) {
  const end = buf.length - 22;
  if (buf.readUInt32LE(end) !== 0x06054b50) throw new Error("not a ZIP end record");
  const count = buf.readUInt16LE(end + 10);
  let at = buf.readUInt32LE(end + 16);
  const out = [];
  for (let i = 0; i < count; i++) {
    const size = buf.readUInt32LE(at + 24);
    const nameLen = buf.readUInt16LE(at + 28);
    const local = buf.readUInt32LE(at + 42);
    const name = buf.subarray(at + 46, at + 46 + nameLen).toString("utf8");
    const start = local + 30 + buf.readUInt16LE(local + 26) + buf.readUInt16LE(local + 28);
    out.push({ name, bytes: buf.subarray(start, start + size) });
    at += 46 + nameLen + buf.readUInt16LE(at + 30) + buf.readUInt16LE(at + 32);
  }
  return out;
}

// VS-06D (UXW-20): the envelope page's "Download evidence package" saves one ZIP whose
// manifest names every entry's SHA-256; the export shows in the history. Mock: the
// seeded completed envelope; Compose stack: one voided for the run, once the worker
// has made its envelope certificate.
test("VS-06D: the evidence package downloads as one ZIP whose manifest hashes every entry", async ({ page }, testInfo) => {
  test.skip(!REAL && testInfo.project.name !== "chromium" && testInfo.project.name !== "webkit", "desktop browsers");
  test.setTimeout(REAL ? 180_000 : 90_000);
  const run = `${Date.now()}-${testInfo.project.name}-${Math.random().toString(36).slice(2, 8)}`;
  await page.setViewportSize(SIZE);
  await signIn(page, "home");
  let id;
  let subject;
  if (REAL) {
    subject = `VS-06D evidence ${run}`;
    id = await inApp(page, async ({ subject, pdf, run }) => {
      const api = window.__vs06;
      const e = await api.createEnvelope({
        subject, status: "sent",
        documents: [{ name: "e.pdf", content_base64: pdf }],
        recipients: [{ ref: "s", type: "signer", name: "Eve Evidence", email: `vs06d-${run}@example.com`, routing_order: 1 }],
        fields: [{ recipient: "s", document: 0, type: "signature", page: 1, x: 72, y: 600, width: 180, height: 40, required: true }],
      });
      await api.voidEnvelope(e.id, "Wrong party");
      // The worker makes the envelope certificate when it ends (UXW-30).
      for (let i = 0; i < 60; i++) {
        try { await api.certificate(e.id); return e.id; } catch { await new Promise((r) => setTimeout(r, 1000)); }
      }
      throw new Error("no envelope certificate within 60 s");
    }, { subject, pdf: Buffer.from(makePdf([{ title: subject, lines: ["Clause 1."] }])).toString("base64"), run });
  } else {
    ({ id, subject } = await page.evaluate(() => JSON.parse(sessionStorage.getItem("openseal.mock.v1")).envelopes.find((e) => e.status === "completed")));
  }
  await page.goto(app(`#/envelopes/${encodeURIComponent(id)}`), { waitUntil: "domcontentloaded" });
  await expect(page.getByRole("heading", { name: subject })).toBeVisible();
  const [dl] = await Promise.all([page.waitForEvent("download"), more(page, "Download evidence package")]);
  expect(dl.suggestedFilename()).toBe(`evidence-${id}.zip`);
  const entries = readZip(fs.readFileSync(await dl.path()));
  expect(entries[0].name).toBe("manifest.json");
  const manifest = JSON.parse(entries[0].bytes.toString("utf8"));
  expect(manifest.envelope_id).toBe(id);
  expect(manifest.entries.map((e) => e.path)).toEqual(entries.slice(1).map((e) => e.name));
  for (const [i, e] of manifest.entries.entries()) {
    expect(e.sha256, e.path).toBe(crypto.createHash("sha256").update(entries[i + 1].bytes).digest("hex"));
  }
  expect(entries.map((e) => e.name)).toEqual(expect.arrayContaining(["certificate.pdf", "audit-trail.json"]));
  const trail = JSON.parse(entries.find((e) => e.name === "audit-trail.json").bytes.toString("utf8"));
  expect(trail.items.at(-1).type).toBe("envelope.exported");
  expect(trail.chain_head).toBe(manifest.chain_head);
});

// FG-013 (ADR-043): sign on paper. The sender allows it; the signer opens their link,
// chooses Sign on paper in More, uploads the scan of the signed pages, and is done; the
// envelope gains the scan as a document and the trail records it. Mock: the link is
// the mock's token; Compose stack: read from Mailpit. Axe, light and dark, on the
// dialog (mock).
test("FG-013: a signer signs on paper and the scan joins the envelope as evidence", async ({ page }, testInfo) => {
  test.skip(!REAL && testInfo.project.name !== "chromium" && testInfo.project.name !== "webkit", "desktop browsers");
  test.setTimeout(REAL ? 180_000 : 90_000);
  const run = `${Date.now()}-${testInfo.project.name}-${Math.random().toString(36).slice(2, 8)}`;
  await page.setViewportSize(SIZE);
  await signIn(page, "home");
  const subject = `FG-013 paper ${run}`;
  const signer = `fg013-${run}@example.com`;
  const started = Date.now();
  const made = await inApp(page, async ({ subject, signer, pdf }) => {
    const api = window.__vs06;
    const e = await api.createEnvelope({
      subject, status: "sent", signing_options: { allow_sign_on_paper: true },
      documents: [{ name: "paper.pdf", content_base64: pdf }],
      recipients: [{ ref: "s", type: "signer", name: "Pat Paper", email: signer, routing_order: 1 }],
      fields: [{ recipient: "s", document: 0, type: "signature", page: 1, x: 72, y: 600, width: 180, height: 40, required: true }],
    });
    return { id: e.id, token: e.recipients?.[0]?.mock_token || null };
  }, { subject, signer, pdf: Buffer.from(makePdf([{ title: subject, lines: ["Clause 1."] }])).toString("base64") });
  const link = REAL ? await emailedLink(signer, started) : signPage(made.token);
  await page.goto(link, { waitUntil: "domcontentloaded" });
  const consent = page.getByRole("heading", { name: "Electronic records and signatures" });
  const progress = page.locator("#guide-progress");
  await expect(consent.or(progress).first()).toBeVisible();
  if (await consent.isVisible()) {
    await page.getByLabel("I agree to use electronic records and signatures.").check();
    await page.getByRole("button", { name: "Continue" }).click();
  }
  await expect(progress).toBeVisible();
  await page.getByRole("button", { name: "More" }).click();
  await page.getByTestId("menu-sign-on-paper").click();
  const dialog = page.getByRole("dialog", { name: "Sign on paper" });
  await expect(dialog).toBeVisible();
  if (!REAL) {
    for (const scheme of ["light", "dark"]) {
      await page.emulateMedia({ colorScheme: scheme });
      await expectAccessible(page, `sign on paper dialog (${scheme})`);
    }
    await page.emulateMedia({ colorScheme: "light" });
  }
  // Nothing chosen: said so, nothing sent.
  await dialog.getByTestId("paper-confirm").click();
  await expect(dialog.getByText("Choose the PDF of your signed pages.")).toBeVisible();
  await dialog.getByTestId("paper-file").setInputFiles(pdfFile("signed-scan.pdf", "Signed by hand"));
  await dialog.getByTestId("paper-confirm").click();
  await expect(page.getByTestId("done-download")).toBeVisible({ timeout: 30_000 });
  // The sender sees the scan among the documents and the event in the history.
  await signIn(page, "home");
  await page.goto(app(`#/envelopes/${encodeURIComponent(made.id)}`), { waitUntil: "domcontentloaded" });
  await expect(page.getByRole("heading", { name: subject })).toBeVisible();
  await expect(page.getByText("Signed on paper.pdf").first()).toBeVisible();
  await more(page, "History");
  await expect(page.getByTestId("history-timeline").getByText("Recipient signed on paper").first()).toBeVisible();
});
