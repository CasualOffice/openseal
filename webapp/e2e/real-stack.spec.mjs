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

import { test, expect } from "@playwright/test";
import { signIn, pdfFile, REAL } from "./helpers.mjs";

const MAIL = (process.env.OPENSEAL_E2E_MAIL_URL || "http://127.0.0.1:8025").replace(/\/$/, "");
const OUT = path.resolve(fileURLToPath(new URL("../../target/e2e-sealed", import.meta.url)));

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
  await expect(page.locator("#guide-progress")).toHaveText("1 of 1 required");
  await page.getByRole("button", { name: "Finish" }).click();
  await page.getByRole("dialog", { name: "Review and finish" }).getByTestId("review-finish").click();
  await expect(page.getByTestId("sign-done")).toContainText(last ? "Everyone has signed" : "Your part is done");
  await context.close();
}

test("two signers in order sign through emailed links; the sealed PDF and certificate download", async ({ page, browser }, testInfo) => {
  test.skip(!REAL, "runs against the Compose deployment only (OPENSEAL_E2E_BASE_URL)");
  test.setTimeout(240_000);
  const run = `${Date.now()}-${testInfo.project.name}`;
  const subject = `Real stack ${run}`;
  const ana = { name: "Ana Signer", email: `ana-${run}@example.com` };
  const ben = { name: "Ben Signer", email: `ben-${run}@example.com` };
  const started = Date.now() - 5_000;

  await signIn(page);
  await page.getByRole("button", { name: "New envelope" }).first().click();
  await page.getByTestId("pdf-input").setInputFiles(pdfFile("real-stack.pdf", "Real stack agreement"));
  await expect(page.locator(".os-page")).toHaveCount(2);
  await expect(page.locator(".os-page.is-loading")).toHaveCount(0);
  await page.getByLabel("Subject").fill(subject);
  await addRecipient(page, 0, ana);
  await addRecipient(page, 1, ben);
  await expect(page.locator(".os-rcpt .os-order")).toHaveText(["1", "2"]);
  for (const who of ["1. Ana Signer", "2. Ben Signer"]) {
    await page.getByLabel("Placing fields for").selectOption({ label: who });
    await page.locator(".os-palette").getByRole("button", { name: "Add Signature field" }).click();
  }
  await expect(page.locator(".os-field")).toHaveCount(2);
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
