// Phase 2 exit item 1, in a browser (E2E-01, T-2F): against the Compose deployment
// only. A sender signs in, uploads a PDF, sends it to two signers in order; each signs
// through the link the worker emailed (read from Mailpit's API); the sender sees it
// completed and downloads the sealed PDF and the certificate of completion, which are
// written to target/e2e-sealed/ for pyHanko (tools/verify-sealed.py) to check.
//
// Needs OPENSEAL_E2E_BASE_URL (the server), OPENSEAL_E2E_EMAIL and _PASSWORD (a user
// made with `casual-sign-server bootstrap`), and OPENSEAL_E2E_MAIL_URL (Mailpit's web
// address, default http://127.0.0.1:8025). Skipped in mock mode.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { test, expect, devices } from "@playwright/test";
import { signIn, pdfFile, REAL, placingFor } from "./helpers.mjs";

const MAIL = (process.env.OPENSEAL_E2E_MAIL_URL || "http://127.0.0.1:8025").replace(/\/$/, "");
const OUT = path.resolve(fileURLToPath(new URL("../../target/e2e-sealed", import.meta.url)));
// The slice 1 demo (S1-02): the VS-01 run's screens, recorded, uploaded by compose-e2e.
const DEMO = path.resolve(fileURLToPath(new URL("../../target/e2e-demo", import.meta.url)));

/// The signing link in the newest email to `to`, waiting for the worker to send it.
async function signingLink(to, after) {
  const deadline = Date.now() + 60_000;
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
  throw new Error(`no signing link emailed to ${to} within 60 s`);
}

/// The link in the completion email to `to` ("Completed: …"), waiting for the worker.
async function completionLink(to) {
  const deadline = Date.now() + 90_000;
  while (Date.now() < deadline) {
    const res = await fetch(`${MAIL}/api/v1/search?query=${encodeURIComponent(`to:"${to}" subject:"Completed"`)}`);
    if (res.ok) {
      const { messages = [] } = await res.json();
      for (const m of messages) {
        const full = await (await fetch(`${MAIL}/api/v1/message/${encodeURIComponent(m.ID)}`)).json();
        const link = `${full.Text || ""}\n${full.HTML || ""}`.match(/https?:\/\/[^\s"'<>]+\/s\/[A-Za-z0-9._~%-]+/);
        if (link) return link[0];
      }
    }
    await new Promise((r) => setTimeout(r, 1000));
  }
  throw new Error(`no completion email to ${to} within 90 s`);
}

async function addRecipient(page, n, { name, email }) {
  await page.getByRole("button", { name: "Add recipient" }).first().click();
  const row = page.locator(".os-rcpt").nth(n);
  await row.getByTestId("recipient-name").fill(name);
  await row.getByTestId("recipient-email").fill(email);
  await row.getByTestId("recipient-email").blur();
}

/// One signer's ceremony on the emailed link: consent, adopt a typed signature, finish.
async function sign(browser, link, name, last) {
  const context = await browser.newContext();
  const page = await context.newPage();
  await page.goto(link);
  // The disclosure is asked for only when the account has one (a fresh account has none).
  const consent = page.getByRole("heading", { name: "Electronic records and signatures" });
  // Progress is announced by the guide's status line at every width (the redesign keeps
  // a second, silent copy in the top bar: both are screen-reader text, so it is not used).
  const progress = page.locator("#guide-progress");
  await expect(consent.or(progress)).toBeVisible();
  if (await consent.isVisible()) {
    await page.getByLabel("I agree to use electronic records and signatures.").check();
    await page.getByRole("button", { name: "Continue" }).click();
  }
  await expect(progress).toHaveText("0 of 1 required");
  await page.getByRole("button", { name: /Signature, required/ }).click();
  const dlg = page.getByRole("dialog", { name: "Adopt your signature" });
  await expect(dlg.getByLabel("Your full name")).toHaveValue(name);
  await dlg.getByTestId("adopt-confirm").click();
  await expect(dlg).toBeHidden();
  await expect(progress).toHaveText("1 of 1 required");
  await page.getByRole("button", { name: "Finish" }).click();
  await expect(page.getByRole("heading", { name: "Review and finish" })).toBeVisible();
  await page.getByTestId("review-finish").click();
  await expect(page.getByTestId("sign-done")).toContainText(last ? "Everyone has signed" : "Your part is done");
  await context.close();
}

// Playwright refuses video inside a describe group (it forces a new worker), so the
// slice 1 demo recording (S1-02) is set for this file, which runs only on the Compose stack.
test.use({ video: { mode: "on", size: { width: 1280, height: 800 } } });

test("two signers in order sign through emailed links; the sealed PDF and certificate download", async ({ page, browser }, testInfo) => {
  test.skip(!REAL, "runs against the Compose deployment only (OPENSEAL_E2E_BASE_URL)");
  test.setTimeout(240_000);
  const run = `${Date.now()}-${testInfo.project.name}`;
  const subject = `Real stack ${run}`;
  const ana = { name: "Ana Signer", email: `ana-${run}@example.com` };
  const ben = { name: "Ben Signer", email: `ben-${run}@example.com` };
  const started = Date.now() - 5_000;

  await signIn(page);
  // UX-07: the top bar's Start is the one way in to a new envelope.
  await page.locator("#start-btn").click();
  await page.getByRole("menuitem", { name: "Send an envelope" }).click();
  await page.getByTestId("pdf-input").setInputFiles(pdfFile("real-stack.pdf", "Real stack agreement"));
  await expect(page.getByTestId("doc-card")).toHaveCount(1);
  await page.getByTestId("wizard-next").click();
  await addRecipient(page, 0, ana);
  await addRecipient(page, 1, ben);
  expect(await page.getByTestId("recipient-order").evaluateAll((els) => els.map((e) => e.value))).toEqual(["1", "2"]);
  await page.getByTestId("wizard-next").click();
  await expect(page.locator(".os-page")).toHaveCount(2);
  await expect(page.locator(".os-page.is-loading")).toHaveCount(0);
  for (const who of ["1. Ana Signer", "2. Ben Signer"]) {
    await placingFor(page, who);
    await page.locator(".os-palette").getByRole("button", { name: "Add Signature field" }).press("Enter");
  }
  await expect(page.locator(".os-field")).toHaveCount(2);
  await page.getByTestId("wizard-next").click();
  await page.getByLabel("Subject").fill(subject);
  await page.getByRole("button", { name: "Send", exact: true }).first().click();
  await page.getByRole("dialog", { name: "Send this envelope?" }).getByRole("button", { name: "Send" }).click();
  await expect(page).toHaveURL(/#\/envelopes\/[^/]+$/, { timeout: 20_000 });
  await expect(page.locator(".os-page-head .os-badge")).toHaveText("Sent");
  const detail = page.url();

  // In order: Ben's link is emailed only once Ana has signed.
  await sign(browser, await signingLink(ana.email, started), ana.name, false);
  await sign(browser, await signingLink(ben.email, started), ben.name, true);

  // The worker seals; the sender sees it completed.
  await expect(async () => {
    await page.reload();
    expect(page.url()).toBe(detail);
    await expect(page.locator(".os-page-head .os-badge")).toHaveText("Completed", { timeout: 2_000 });
  }).toPass({ timeout: 120_000, intervals: [2_000] });

  fs.mkdirSync(OUT, { recursive: true });
  const save = async (label, file) => {
    const [dl] = await Promise.all([page.waitForEvent("download"), page.getByRole("button", { name: label }).click()]);
    const to = path.join(OUT, `${testInfo.project.name}-${file}`);
    await dl.saveAs(to);
    const head = fs.readFileSync(to).subarray(0, 5).toString("latin1");
    expect(head, `${label} is a PDF`).toBe("%PDF-");
    return path.basename(to);
  };
  const sealed = await save("Download signed PDF", "sealed.pdf");
  const certificate = await save("Certificate", "certificate.pdf");
  // The manifest tools/verify-sealed.py reads (rows appended per browser project).
  const manifest = path.join(OUT, "manifest.tsv");
  if (!fs.existsSync(manifest)) fs.writeFileSync(manifest, "file\texpect\twhy\tlevel\n");
  fs.appendFileSync(manifest, `${sealed}\tintact\tsealed agreement, ${testInfo.project.name}\tB-T\n`);
  fs.appendFileSync(manifest, `${certificate}\tintact\tcertificate of completion, ${testInfo.project.name}\tB-T\n`);
});

// VS-01 (slice 1, send and sign), in a browser on the Compose deployment: the sender
// uploads a PDF, adds one signer, places a signature, a date and a text field, sends;
// the signer signs on a phone (iPhone 13: touch, 390 px); both get the sealed PDF and the
// certificate of completion, the signer through the completion email's link. Every
// download is written for pyHanko, and the signer's are the sender's bytes.
test.describe("slice 1 (VS-01)", () => {
  // Every screen of the run is recorded: the sender's (this page, by the file-level
  // video setting above) and the phone's (recordVideo below), as the slice 1 demo (S1-02).
  test("send and sign: one signer on a phone; both get the sealed PDF and the certificate (VS-01)", async ({ page, browser }, testInfo) => {
    test.skip(!REAL, "runs against the Compose deployment only (OPENSEAL_E2E_BASE_URL)");
    test.setTimeout(240_000);
    const run = `${Date.now()}-${testInfo.project.name}`;
    const cara = { name: "Cara Signer", email: `cara-${run}@example.com` };
    const started = Date.now() - 5_000;
    const phone = { ...devices["iPhone 13"], recordVideo: { dir: testInfo.outputPath("phone-video"), size: { width: 390, height: 844 } } };
    delete phone.defaultBrowserType;
    fs.mkdirSync(DEMO, { recursive: true });
    const demo = (step) => path.join(DEMO, `vs01-${testInfo.project.name}-${step}.webm`);

    await signIn(page);
    await page.locator("#start-btn").click();
    await page.getByRole("menuitem", { name: "Send an envelope" }).click();
    await page.getByTestId("pdf-input").setInputFiles(pdfFile("send-and-sign.pdf", "Send and sign agreement"));
    await expect(page.getByTestId("doc-card")).toHaveCount(1);
    await page.getByTestId("wizard-next").click();
    await addRecipient(page, 0, cara);
    await page.getByTestId("wizard-next").click();
    await expect(page.locator(".os-page.is-loading")).toHaveCount(0);
    for (const kind of ["Signature", "Date signed", "Text"]) {
      await page.locator(".os-palette").getByRole("button", { name: `Add ${kind} field` }).press("Enter");
    }
    await expect(page.locator(".os-field")).toHaveCount(3);
    await page.getByTestId("wizard-next").click();
    await page.getByLabel("Subject").fill(`Send and sign ${run}`);
    await page.getByRole("button", { name: "Send", exact: true }).first().click();
    await page.getByRole("dialog", { name: "Send this envelope?" }).getByRole("button", { name: "Send" }).click();
    await expect(page).toHaveURL(/#\/envelopes\/[^/]+$/, { timeout: 20_000 });
    await expect(page.locator(".os-page-head .os-badge")).toHaveText("Sent");
    const detail = page.url();

    // The signer, on a phone, through the emailed link.
    const signer = await browser.newContext(phone);
    const sp = await signer.newPage();
    await sp.goto(await signingLink(cara.email, started));
    const consent = sp.getByRole("heading", { name: "Electronic records and signatures" });
    const progress = sp.locator("#guide-progress");
    await expect(consent.or(progress)).toBeVisible();
    if (await consent.isVisible()) {
      await sp.getByLabel("I agree to use electronic records and signatures.").check();
      await sp.getByRole("button", { name: "Continue" }).click();
    }
    await expect(progress).toHaveText(/^0 of \d required$/);
    await expect(sp.locator('.os-sfield[data-field="date_signed"]').first()).toBeAttached();
    const text = sp.getByRole("textbox", { name: /^Text/ });
    await text.fill("Phase one deliverables");
    await text.blur();
    await sp.getByRole("button", { name: /Signature, required/ }).click();
    const dlg = sp.getByRole("dialog", { name: "Adopt your signature" });
    await expect(dlg.getByLabel("Your full name")).toHaveValue(cara.name);
    await dlg.getByTestId("adopt-confirm").click();
    await expect(dlg).toBeHidden();
    await sp.getByRole("button", { name: "Finish" }).click();
    await expect(sp.getByRole("heading", { name: "Review and finish" })).toBeVisible();
    await expect(sp.locator(".os-review")).toContainText("Phase one deliverables");
    await sp.getByTestId("review-finish").click();
    await expect(sp.getByTestId("sign-done")).toContainText("Everyone has signed");
    await signer.close();
    await sp.video()?.saveAs(demo("2-signer-signs-on-a-phone"));

    // The worker seals; the sender sees it completed and downloads both.
    await expect(async () => {
      await page.reload();
      expect(page.url()).toBe(detail);
      await expect(page.locator(".os-page-head .os-badge")).toHaveText("Completed", { timeout: 2_000 });
    }).toPass({ timeout: 120_000, intervals: [2_000] });
    fs.mkdirSync(OUT, { recursive: true });
    const keep = async (p, click, file) => {
      const [dl] = await Promise.all([p.waitForEvent("download"), click()]);
      const to = path.join(OUT, `${testInfo.project.name}-${file}`);
      await dl.saveAs(to);
      const bytes = fs.readFileSync(to);
      expect(bytes.subarray(0, 5).toString("latin1"), `${file} is a PDF`).toBe("%PDF-");
      return { name: path.basename(to), bytes };
    };
    const sealed = await keep(page, () => page.getByRole("button", { name: "Download signed PDF" }).click(), "vs01-sender-sealed.pdf");
    const certificate = await keep(page, () => page.getByRole("button", { name: "Certificate" }).click(), "vs01-sender-certificate.pdf");

    // The signer's copies, from the completion email, on the phone.
    const after = await browser.newContext(phone);
    const ap = await after.newPage();
    await ap.goto(await completionLink(cara.email));
    await expect(ap.getByTestId("sign-done")).toContainText("Everyone has signed");
    const mine = await keep(ap, () => ap.getByTestId("done-download").click(), "vs01-signer-sealed.pdf");
    const cert = await keep(ap, () => ap.getByTestId("done-certificate").click(), "vs01-signer-certificate.pdf");
    await after.close();
    await ap.video()?.saveAs(demo("4-signer-downloads"));
    await page.close();
    await page.video()?.saveAs(demo("1-3-sender-sends-and-downloads"));
    expect(mine.bytes.equals(sealed.bytes), "the signer's PDF is the sender's sealed PDF").toBe(true);
    expect(cert.bytes.equals(certificate.bytes), "the signer's certificate is the sender's").toBe(true);

    const manifest = path.join(OUT, "manifest.tsv");
    if (!fs.existsSync(manifest)) fs.writeFileSync(manifest, "file\texpect\twhy\tlevel\n");
    for (const [f, why] of [[sealed, "sender"], [certificate, "sender certificate"], [mine, "signer"], [cert, "signer certificate"]]) {
      fs.appendFileSync(manifest, `${f.name}\tintact\tVS-01 ${why}, ${testInfo.project.name}\tB-T\n`);
    }
  });
});
