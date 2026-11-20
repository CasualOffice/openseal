// Slice 6 additions (VS-06E, owner instruction 78) in the browser.
//  - FG-009, envelope id stamping: a draft made through the API is opened in the editor,
//    "Stamp the envelope ID on every page" is ticked on the review step and the envelope
//    sent; the document downloaded as it stands carries "Envelope ID: <id>" on every
//    page (read back with the app's own pdf.js), and the signer sees the stamp over every
//    page. On the Compose stack the signing link is read from Mailpit; in mock mode from
//    the mock's store. axe, light and dark, on the editor's options and the signing page.
//  - FG-141, Insights: reached from Reports; the tiles, the chart with its table, the
//    outcomes and the top senders, over the server's `GET /insights`; on the Compose
//    stack an envelope sent for the run is counted. axe, light and dark.
import { test, expect } from "@playwright/test";
import { signIn, app, signPage, expectAccessible, REAL } from "./helpers.mjs";
import { makePdf } from "../mockpdf.js";

const MAIL = (process.env.OPENSEAL_E2E_MAIL_URL || "http://127.0.0.1:8025").replace(/\/$/, "");

/// Run `fn(arg)` in the signed-in app page with api.js's client on `window.__vs06e`.
async function inApp(page, fn, arg) {
  await page.evaluate(async (real) => {
    const { createClient } = await import(new URL("api.js", location.href).href);
    const opts = { store: sessionStorage };
    if (!real) opts.fetch = (await import(new URL("mock.js", location.href).href)).createMockFetch({ store: sessionStorage });
    window.__vs06e = createClient(opts);
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

/// Each page's text of the PDF `bytes`, read in the page by the app's vendored pdf.js.
async function pdfPageTexts(page, bytes) {
  return page.evaluate(async (b64) => {
    const lib = await import(new URL("vendor/pdfjs/pdf.min.mjs", location.href).href);
    lib.GlobalWorkerOptions.workerSrc = new URL("vendor/pdfjs/pdf.worker.min.mjs", location.href).href;
    const data = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
    const doc = await lib.getDocument({ data, isEvalSupported: false, enableXfa: false, useSystemFonts: false,
      standardFontDataUrl: new URL("vendor/pdfjs/standard_fonts/", location.href).href }).promise;
    const out = [];
    for (let i = 1; i <= doc.numPages; i++) {
      const tc = await (await doc.getPage(i)).getTextContent();
      out.push(tc.items.map((x) => x.str).join(" "));
    }
    await doc.destroy();
    return out;
  }, Buffer.from(bytes).toString("base64"));
}

for (const scheme of ["light", "dark"]) test.describe(`envelope id stamping (${scheme})`, () => {
test.use({ colorScheme: scheme });
test(`FG-009: the sender stamps the envelope id; the signer sees it and the downloaded document carries it on every page (${scheme})`, async ({ page }, testInfo) => {
  test.skip(!REAL && testInfo.project.name !== "chromium" && testInfo.project.name !== "webkit", "desktop browsers");
  test.skip(REAL && scheme === "dark", "the stack runs it once; dark is checked in mock mode");
  test.setTimeout(REAL ? 240_000 : 90_000);
  const run = `${Date.now()}-${testInfo.project.name}-${Math.random().toString(36).slice(2, 8)}`;
  const subject = `FG-009 stamped ${run}`;
  const signer = `fg009-${run}@example.com`;
  await signIn(page, "home");

  // A draft with a two-page document, one signer and their signature field.
  const id = await inApp(page, async ({ subject, signer, pdf }) => {
    const e = await window.__vs06e.createEnvelope({
      subject, signing_options: { stamp_envelope_id: false },
      documents: [{ name: "stamped.pdf", content_base64: pdf }],
      recipients: [{ ref: "s", type: "signer", name: "Sam Stamp", email: signer, routing_order: 1 }],
      fields: [{ recipient: "s", document: 0, type: "signature", page: 1, x: 72, y: 600, width: 180, height: 40, required: true }],
    });
    return e.id;
  }, { subject, signer, pdf: Buffer.from(makePdf([{ title: subject, lines: ["Clause 1."] }, { title: "Schedule", lines: ["Clause 2."] }])).toString("base64") });

  // The editor's review step: the option, then Send.
  // A load, not a hash change: the mock answers from the store the draft was saved to.
  await page.goto(app(`#/prepare/${encodeURIComponent(id)}`), { waitUntil: "domcontentloaded" });
  await page.reload({ waitUntil: "domcontentloaded" });
  await expect(page.locator(".os-page")).toHaveCount(2);
  await page.locator(".os-stepper__btn", { hasText: "Review" }).click();
  await expect(page.getByLabel("Subject")).toHaveValue(subject);
  const stamp = page.getByLabel("Stamp the envelope ID on every page");
  await expect(stamp).not.toBeChecked();
  await stamp.check();
  await expectAccessible(page, `editor options with the envelope id stamp (${scheme})`);
  const started = Date.now();
  await page.getByRole("button", { name: "Send", exact: true }).first().click();
  await page.getByRole("dialog", { name: "Send this envelope?" }).getByRole("button", { name: "Send" }).click();
  await expect(page.getByRole("heading", { name: "Recipients" })).toBeVisible({ timeout: 20_000 });

  // The document as it stands: "Envelope ID: <id>" on both pages.
  await page.getByTestId("envelope-more").click();
  const [dl] = await Promise.all([page.waitForEvent("download"), page.getByRole("menuitem", { name: "Download current PDF" }).click()]);
  const fs = await import("node:fs");
  const texts = await pdfPageTexts(page, fs.readFileSync(await dl.path()));
  expect(texts).toHaveLength(2);
  for (const t of texts) expect(t).toContain(`Envelope ID: ${id}`);

  // The signer sees the stamp over every page, where the seal will draw it.
  let link;
  if (REAL) {
    link = await emailedLink(signer, started);
  } else {
    const token = await page.evaluate((id) => JSON.parse(sessionStorage.getItem("openseal.mock.v1")).envelopes.find((e) => e.id === id).recipients[0].token, id);
    link = signPage(token);
  }
  await page.goto(link, { waitUntil: "domcontentloaded" });
  const consent = page.getByRole("heading", { name: "Electronic records and signatures" });
  const start = page.getByRole("button", { name: "Start" });
  await expect(consent.or(start)).toBeVisible({ timeout: 20_000 });
  if (await consent.isVisible()) {
    await page.getByLabel("I agree to use electronic records and signatures.").check();
    await page.getByRole("button", { name: "Continue" }).click();
  }
  await expect(start).toBeVisible();
  await expect(page.getByTestId("envelope-stamp")).toHaveCount(2);
  await expect(page.getByTestId("envelope-stamp").first()).toHaveText(`Envelope ID: ${id}`);
  await expectAccessible(page, `signing page with the envelope id stamp (${scheme})`);
});
});

for (const scheme of ["light", "dark"]) test.describe(`insights (${scheme})`, () => {
test.use({ colorScheme: scheme });
test(`FG-141: Insights from Reports, with a table for each chart (${scheme})`, async ({ page }, testInfo) => {
  test.skip(!REAL && testInfo.project.name !== "chromium" && testInfo.project.name !== "webkit", "desktop browsers");
  test.skip(REAL && scheme === "dark", "the stack runs it once; dark is checked in mock mode");
  test.setTimeout(REAL ? 120_000 : 60_000);
  await signIn(page, "home");
  let before = 0;
  if (REAL) {
    // What the server counts in the last 7 days, then one more sent envelope.
    before = await inApp(page, async () => (await window.__vs06e.insights({ from: new Date(Date.now() - 7 * 86_400_000).toISOString() })).totals.sent);
    await inApp(page, async (pdf) => window.__vs06e.createEnvelope({
      subject: `FG-141 ${Date.now()}`, status: "sent",
      documents: [{ name: "i.pdf", content_base64: pdf }],
      recipients: [{ ref: "s", type: "signer", name: "Ivy Insight", email: `fg141-${Date.now()}@example.com`, routing_order: 1 }],
      fields: [{ recipient: "s", document: 0, type: "signature", page: 1, x: 72, y: 600, width: 180, height: 40, required: true }],
    }), Buffer.from(makePdf([{ title: "Insight" }])).toString("base64"));
  }
  await page.goto(app("#/reports"), { waitUntil: "domcontentloaded" });
  await page.getByTestId("reports-insights").click();
  await expect(page.getByRole("heading", { name: "Insights", level: 1 })).toBeVisible();
  await page.getByLabel("Period").selectOption(REAL ? "7" : "all");
  await expect(page.getByTestId("insights-note")).toContainText("Every envelope in this workspace");
  for (const id of ["sent", "completed", "rate", "median", "p90", "declined"]) await expect(page.getByTestId(`insight-${id}`)).toBeVisible();
  const sentN = async () => Number(((await page.getByTestId("insight-sent").locator(".os-counter__n").textContent()) || "").replace(/\D/g, ""));
  if (REAL) await expect.poll(sentN).toBeGreaterThan(before);
  else expect(await sentN()).toBeGreaterThan(0); // the mock's seeded agreements
  // The chart is an image with a summary, and its data a table behind a disclosure.
  const chart = page.getByTestId("insights-chart");
  await expect(chart).toHaveAttribute("role", "img");
  await expect(chart).toHaveAttribute("aria-label", /sent and \d+ completed from/);
  const table = page.getByTestId("insights-over-time-table");
  await expect(table).toBeHidden();
  await page.getByTestId("insights-show-table").click();
  await expect(table).toBeVisible();
  expect(await table.locator("tbody tr").count()).toBeGreaterThan(0);
  await expect(page.getByTestId("insights-outcomes").locator("tbody tr")).toHaveCount(5);
  await expect(page.getByTestId("insights-top-senders").locator("tbody tr").first()).toBeVisible();
  await expectAccessible(page, `insights (${scheme})`);
});
});
