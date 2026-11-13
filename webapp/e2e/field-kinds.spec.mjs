// Slice 1's remaining field rows, end to end in the browser (docs/14 S1-01, S1-03,
// S1-04, S1-05; docs/96 FG-057, FG-055, FG-072, FG-006): the editor offers a
// multi-line text box, first and last name fields and a locked value, the signer's page
// honours each, and the size limits are said in the editor. The first three read the
// mock's store to find the new envelope's signing link, so they run in mock mode; the
// size limits run against a real server too.
import fs from "node:fs";
import { test, expect } from "@playwright/test";
import { signIn, app, pdfFile, placingFor, signPage, REAL } from "./helpers.mjs";

const mockDb = (page) => page.evaluate(() => JSON.parse(sessionStorage.getItem("openseal.mock.v1")));

async function newEnvelope(page, signer) {
  await signIn(page);
  await page.goto(app("#/prepare"));
  await page.getByTestId("pdf-input").setInputFiles(pdfFile());
  await expect(page.getByTestId("doc-card")).toHaveCount(1);
  await page.getByTestId("wizard-next").click();
  await page.getByRole("button", { name: "Add recipient" }).first().click();
  const row = page.locator(".os-rcpt").first();
  await row.getByTestId("recipient-name").fill(signer.name);
  await row.getByTestId("recipient-email").fill(signer.email);
  await row.getByTestId("recipient-email").blur();
  await page.getByTestId("wizard-next").click();
  await expect(page.locator(".os-page.is-loading")).toHaveCount(0);
  await placingFor(page, 0);
}

const add = (page, type) => page.locator(".os-palette").getByRole("button", { name: `Add ${type} field` }).press("Enter");

/// Send the envelope being prepared; answers its signer's token from the mock's store.
async function sendAndOpenSigning(page, subject) {
  await page.getByTestId("wizard-next").click();
  await page.getByLabel("Subject").fill(subject);
  await page.getByRole("button", { name: "Send", exact: true }).first().click();
  await page.getByRole("dialog", { name: "Send this envelope?" }).getByRole("button", { name: "Send" }).click();
  await expect(page.locator(".os-page-head .os-badge")).toHaveText("Sent", { timeout: 20_000 });
  const db = await mockDb(page);
  const env = db.envelopes.find((e) => e.subject === subject);
  const token = env.recipients[0].token;
  expect(token).toBeTruthy();
  await page.goto(signPage(token));
  await page.getByLabel("I agree to use electronic records and signatures.").check();
  await page.getByRole("button", { name: "Continue" }).click();
  await expect(page.locator(".os-page canvas").first()).toBeVisible();
  return env.id;
}

const fieldsOf = async (page, envId) => (await mockDb(page)).envelopes.find((e) => e.id === envId).fields;

test.describe("mock", () => {
  test.skip(REAL, "reads the new envelope's signing link from the mock's store");

  test("a multi-line text box: offered in the editor, the signer types line breaks, the value keeps them (FG-057)", async ({ page }) => {
    const subject = `Multi-line ${Date.now()}`;
    await newEnvelope(page, { name: "Ana Signer", email: "ana@example.com" });
    await add(page, "Signature");
    await add(page, "Text");
    await page.locator('.os-field[data-field="text"]').click();
    await page.getByLabel("Label").fill("Notes");
    await page.getByLabel("Label").blur();
    await page.getByLabel("Several lines: the recipient can type line breaks").check();
    const envId = await sendAndOpenSigning(page, subject);
    expect((await fieldsOf(page, envId)).find((f) => f.type === "text").format).toEqual({ multiline: true });

    const notes = page.getByRole("textbox", { name: /Notes/ });
    expect(await notes.evaluate((el) => el.tagName)).toBe("TEXTAREA");
    await notes.click();
    await page.keyboard.type("Line one");
    await page.keyboard.press("Enter");
    await page.keyboard.type("Line two");
    await notes.blur();
    await expect.poll(async () => (await fieldsOf(page, envId)).find((f) => f.type === "text").value?.text).toBe("Line one\nLine two");
  });

  test("first and last name fields: in the editor's palette, shown to the signer from their name (FG-055)", async ({ page }) => {
    const subject = `Names ${Date.now()}`;
    await newEnvelope(page, { name: "Ludwig van Beethoven", email: "lvb@example.com" });
    await add(page, "Signature");
    await add(page, "First name");
    await add(page, "Last name");
    await page.locator('.os-field[data-field="first_name"]').click();
    await expect(page.getByText("Filled in with the first word of the recipient's name.")).toBeVisible();
    await sendAndOpenSigning(page, subject);
    await expect(page.locator('.os-sfield[data-field="first_name"] .os-sfield__auto')).toHaveText("Ludwig");
    await expect(page.locator('.os-sfield[data-field="last_name"] .os-sfield__auto')).toHaveText("van Beethoven");
  });

  test("a locked value: the sender locks it in the editor; the signer sees it and cannot change it (FG-072)", async ({ page }) => {
    const subject = `Locked ${Date.now()}`;
    await newEnvelope(page, { name: "Ana Signer", email: "ana@example.com" });
    await add(page, "Signature");
    await add(page, "Text");
    await page.locator('.os-field[data-field="text"]').click();
    await page.getByLabel("Label").fill("PO number");
    await page.getByLabel("Label").blur();
    await page.getByLabel("Locked: the value is fixed and nobody can change it").check();
    await page.getByLabel("Value", { exact: true }).fill("PO-1234");
    await page.getByLabel("Value", { exact: true }).blur();
    const envId = await sendAndOpenSigning(page, subject);
    const po = (await fieldsOf(page, envId)).find((f) => f.type === "text");
    expect(po.locked).toBe(true);
    expect(po.value).toEqual({ text: "PO-1234" });
    await expect(page.getByRole("note", { name: "PO number: PO-1234" })).toBeVisible();
    await expect(page.getByRole("textbox", { name: /PO number/ })).toHaveCount(0);
  });
});

/// A one-page PDF of about `bytes`: the bulk is an unused stream, so a viewer reads it
/// quickly and the cross-reference table stays exact.
function bigPdf(file, bytes) {
  const head = "%PDF-1.4\n";
  const objs = [
    "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n",
    "2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n",
    "3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n",
  ];
  const fd = fs.openSync(file, "w");
  let at = 0;
  const offsets = [];
  const put = (b) => { fs.writeSync(fd, b); at += b.length; };
  put(Buffer.from(head));
  for (const o of objs) { offsets.push(at); put(Buffer.from(o)); }
  offsets.push(at);
  put(Buffer.from(`4 0 obj\n<< /Length ${bytes} >>\nstream\n`));
  const chunk = Buffer.alloc(1024 * 1024, 0x20);
  for (let left = bytes; left > 0; left -= chunk.length) put(left >= chunk.length ? chunk : chunk.subarray(0, left));
  put(Buffer.from("\nendstream\nendobj\n"));
  const xref = at;
  put(Buffer.from(`xref\n0 5\n0000000000 65535 f \n${offsets.map((o) => `${String(o).padStart(10, "0")} 00000 n \n`).join("")}trailer\n<< /Size 5 /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF\n`));
  fs.closeSync(fd);
}

const MiB = 1024 * 1024;

test("a file over 50 MB is refused in the editor with its message (FG-006)", async ({ page }, testInfo) => {
  await signIn(page);
  await page.goto(app("#/prepare"));
  const big = testInfo.outputPath("over-50.pdf");
  bigPdf(big, 51 * MiB);
  try {
    await page.getByTestId("pdf-input").setInputFiles(big);
    await expect(page.locator(".os-toast").last()).toContainText("over-50.pdf is larger than 50 MB.");
    await expect(page.getByTestId("doc-card")).toHaveCount(0);
  } finally {
    fs.rmSync(big, { force: true });
  }
});

test("an envelope over 200 MB is refused by the server and its 413 is said in the editor (FG-006)", async ({ page, browserName }, testInfo) => {
  // Five 41 MiB documents (each under the 50 MiB file limit) in one browser: run once,
  // in Chromium, to keep the suite's memory in bounds.
  test.skip(browserName !== "chromium", "one engine is enough for a 205 MiB upload");
  test.setTimeout(180_000);
  const files = [1, 2, 3, 4, 5].map((n) => testInfo.outputPath(`part-${n}.pdf`));
  for (const f of files) bigPdf(f, 41 * MiB);
  try {
    await signIn(page);
    await page.goto(app("#/prepare"));
    await page.getByTestId("pdf-input").setInputFiles(files);
    await expect(page.getByTestId("doc-card")).toHaveCount(5, { timeout: 60_000 });
    await page.getByTestId("wizard-next").click();
    await page.getByRole("button", { name: "Add recipient" }).first().click();
    const row = page.locator(".os-rcpt").first();
    await row.getByTestId("recipient-name").fill("Ana Signer");
    await row.getByTestId("recipient-email").fill("ana@example.com");
    await row.getByTestId("recipient-email").blur();
    await page.getByRole("button", { name: "Save draft" }).click();
    await expect(page.locator(".os-toast").last()).toContainText(
      "The documents together are larger than 200 MB, the most one envelope can hold. Remove a document and save again.",
      { timeout: 60_000 },
    );
    await expect(page.getByText("Draft saved.")).toHaveCount(0);
  } finally {
    for (const f of files) fs.rmSync(f, { force: true });
  }
});
