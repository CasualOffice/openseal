// Scenario 2 (WEB-01): create an envelope — upload a PDF, two sequential signers and a
// CC, signature, date and text fields for each signer — send it, and find it as sent.
import { test, expect } from "@playwright/test";
import { signIn, app, pdfFile } from "./helpers.mjs";

async function addRecipient(page, n, { name, email, type = "signer" }) {
  await page.getByRole("button", { name: "Add recipient" }).first().click();
  const row = page.locator(".os-rcpt").nth(n);
  await row.getByTestId("recipient-name").fill(name);
  await row.getByTestId("recipient-email").fill(email);
  if (type !== "signer") await row.getByTestId("recipient-type").selectOption(type);
  await row.getByTestId("recipient-email").blur();
}

/// The send flow's steps (WEB-02 redesign): documents, recipients, fields, review.
async function step(page, name) {
  await page.locator(".os-stepper__btn", { hasText: name }).click();
  await expect(page.locator('.os-stepper__btn[aria-current="step"]')).toContainText(name);
}

async function placeFor(page, who, types) {
  await expect(page.getByLabel("Placing fields for").locator("option", { hasText: who })).toHaveCount(1);
  await page.getByLabel("Placing fields for").selectOption({ label: who });
  for (const type of types) await page.locator(".os-palette").getByRole("button", { name: `Add ${type} field` }).click();
}

test("upload, two signers in order and a CC, fields for each, send", async ({ page }) => {
  const subject = `Services contract ${Date.now()}`;
  await signIn(page);
  await page.getByRole("button", { name: "New envelope" }).first().click();
  await expect(page.getByTestId("empty-documents")).toBeVisible();
  await page.getByTestId("pdf-input").setInputFiles(pdfFile());
  await expect(page.getByTestId("doc-card")).toHaveCount(1);
  await expect(page.getByTestId("doc-card")).toContainText("2 pages");
  await page.getByTestId("wizard-next").click();

  await addRecipient(page, 0, { name: "Ana Signer", email: "ana@example.com" });
  await addRecipient(page, 1, { name: "Ben Signer", email: "ben@example.com" });
  await addRecipient(page, 2, { name: "Cleo Copy", email: "cleo@example.com", type: "cc" });
  await expect(page.locator(".os-rcpt .os-order")).toHaveText(["1", "2", "3"]);
  await page.getByTestId("wizard-next").click();
  await expect(page.locator(".os-page")).toHaveCount(2);
  await expect(page.locator(".os-page.is-loading")).toHaveCount(0);

  await placeFor(page, "1. Ana Signer", ["Signature", "Date signed", "Text"]);
  await placeFor(page, "2. Ben Signer", ["Signature", "Date signed", "Text"]);
  await expect(page.locator(".os-field")).toHaveCount(6);

  // Move a field by dragging it.
  const field = page.locator(".os-field").first();
  const before = await field.boundingBox();
  await field.hover();
  await page.mouse.down();
  await page.mouse.move(before.x + before.width / 2 + 40, before.y + before.height / 2 + 30, { steps: 5 });
  await page.mouse.up();
  const after = await field.boundingBox();
  expect(Math.round(after.x - before.x)).toBeGreaterThan(20);

  // The selected field's properties: make the text field optional with a label.
  await page.locator('.os-field[data-field="text"]').first().click();
  await page.getByLabel("Label").fill("Job title");
  await page.getByLabel("Label").blur();
  await expect(page.locator('.os-field[data-field="text"]').first()).toContainText("Job title");

  await page.getByTestId("wizard-next").click();
  await page.getByLabel("Subject").fill(subject);
  await page.getByLabel("First reminder after (days)").fill("3");
  await expect(page.locator(".os-summary__item")).toHaveCount(3);
  await expect(page.locator(".os-summary__item").first()).toContainText("3 fields");
  await page.getByRole("button", { name: "Send", exact: true }).first().click();
  await page.getByRole("dialog", { name: "Send this envelope?" }).getByRole("button", { name: "Send" }).click();
  await expect(page.getByRole("heading", { name: "Recipients" })).toBeVisible({ timeout: 20_000 });
  await expect(page.locator(".os-page-head .os-badge")).toHaveText("Sent");
  await expect(page.locator(".os-timeline__item")).toHaveCount(3);

  await page.getByRole("link", { name: "Agreements" }).first().click();
  const row = page.locator("tr", { hasText: subject });
  await expect(row).toContainText("Sent");
});

test("send refuses an envelope that is not ready, and says what is missing", async ({ page }) => {
  await signIn(page);
  await page.goto(app("#/prepare"));
  await page.getByTestId("pdf-input").setInputFiles(pdfFile());
  await page.getByTestId("wizard-next").click();
  await page.getByRole("button", { name: "Add recipient" }).first().click();
  await step(page, "Review and send");
  await page.getByRole("button", { name: "Send", exact: true }).first().click();
  const dlg = page.getByRole("dialog", { name: "Not ready to send" });
  await expect(dlg).toContainText("Enter a name for recipient 1");
  await expect(dlg).toContainText("Place at least one field");
  await dlg.getByRole("button", { name: "OK" }).click();
});

test("a saved draft reopens with its fields where they were", async ({ page }) => {
  await signIn(page);
  await page.goto(app("#/prepare"));
  await page.getByTestId("pdf-input").setInputFiles(pdfFile("draft.pdf", "Draft terms"));
  await page.getByTestId("wizard-next").click();
  await addRecipient(page, 0, { name: "Dee Draft", email: "dee@example.com" });
  await page.getByTestId("wizard-next").click();
  await page.locator(".os-palette").getByRole("button", { name: "Add Signature field" }).click();
  await page.keyboard.press("ArrowRight");
  await page.keyboard.press("Shift+ArrowDown");
  const x = await page.getByLabel("Left").inputValue();
  const y = await page.getByLabel("Top").inputValue();
  await page.getByRole("button", { name: "Save draft" }).click();
  await expect(page.getByText("Draft saved.").first()).toBeVisible();
  await expect(page).toHaveURL(/#\/prepare\/.+/);
  await page.reload();
  await expect(page.locator(".os-field")).toHaveCount(1);
  await page.locator(".os-field").click();
  await expect(page.getByLabel("Left")).toHaveValue(x);
  await expect(page.getByLabel("Top")).toHaveValue(y);
});

test("a field dragged from the palette lands on the page where it is dropped", async ({ page }) => {
  await signIn(page);
  await page.goto(app("#/prepare"));
  await page.getByTestId("pdf-input").setInputFiles(pdfFile());
  await page.getByTestId("wizard-next").click();
  await addRecipient(page, 0, { name: "Dana Drop", email: "dana@example.com" });
  await page.getByTestId("wizard-next").click();
  await expect(page.locator(".os-page.is-loading")).toHaveCount(0);
  const page2 = page.locator(".os-page__overlay").nth(1);
  await page.locator(".os-palette").getByRole("button", { name: "Add Initials field" }).dragTo(page2, { targetPosition: { x: 120, y: 160 } });
  await expect(page2.locator(".os-field")).toHaveCount(1);
  await expect(page.getByText("Page 2, from the top-left corner.")).toBeVisible();
});
