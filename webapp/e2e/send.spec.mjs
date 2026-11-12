// Scenario 2 (WEB-01): create an envelope — upload a PDF, two sequential signers and a
// CC, signature, date and text fields for each signer — send it, and find it as sent.
import { test, expect } from "@playwright/test";
import { signIn, app, pdfFile, placingFor } from "./helpers.mjs";

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
  await placingFor(page, who);
  for (const type of types) await page.locator(".os-palette").getByRole("button", { name: `Add ${type} field` }).press("Enter");
}

test("upload, two signers in order and a CC, fields for each, send", async ({ page }) => {
  const subject = `Services contract ${Date.now()}`;
  await signIn(page);
  // UX-07: the top bar's Start is the one way in to a new envelope.
  await page.locator("#start-btn").click();
  await page.getByRole("menuitem", { name: "Send an envelope" }).click();
  await expect(page.getByTestId("empty-documents")).toBeVisible();
  await page.getByTestId("pdf-input").setInputFiles(pdfFile());
  await expect(page.getByTestId("doc-card")).toHaveCount(1);
  await expect(page.getByTestId("doc-card")).toContainText("2 pages");
  await page.getByTestId("wizard-next").click();

  await addRecipient(page, 0, { name: "Ana Signer", email: "ana@example.com" });
  await addRecipient(page, 1, { name: "Ben Signer", email: "ben@example.com" });
  await addRecipient(page, 2, { name: "Cleo Copy", email: "cleo@example.com", type: "cc" });
  expect(await page.getByTestId("recipient-order").evaluateAll((els) => els.map((e) => e.value))).toEqual(["1", "2", "3"]);
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
  await expect(page.locator(".os-summary__item").first()).toContainText("3 fields: Signature, Date signed, Text");
  await expect(page.locator(".os-summary__item").nth(2)).toContainText("Gets a copy when it is complete");
  await expect(page.locator(".os-stepper__btn.is-done")).toHaveCount(3);
  await page.getByRole("button", { name: "Send", exact: true }).first().click();
  const confirm = page.getByRole("dialog", { name: "Send this envelope?" });
  await expect(confirm).toContainText("They sign in order: Ana Signer → Ben Signer. Cleo Copy will get a copy when it is complete.");
  await confirm.getByRole("button", { name: "Send" }).click();
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
  await page.locator(".os-palette").getByRole("button", { name: "Add Signature field" }).press("Enter");
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
  await expect(page.getByText("Page 2, from the top-left corner.")).toBeAttached();
});

test("recipients reorder with the arrows and by dragging a card", async ({ page }) => {
  await signIn(page);
  await page.goto(app("#/prepare"));
  await page.getByTestId("pdf-input").setInputFiles(pdfFile());
  await page.getByTestId("wizard-next").click();
  await addRecipient(page, 0, { name: "One", email: "one@example.com" });
  await addRecipient(page, 1, { name: "Two", email: "two@example.com" });
  await addRecipient(page, 2, { name: "Three", email: "three@example.com" });
  const names = () => page.getByTestId("recipient-name").evaluateAll((els) => els.map((e) => e.value));
  await page.locator(".os-rcpt").nth(0).getByRole("button", { name: "Move down in signing order" }).click();
  expect(await names()).toEqual(["Two", "One", "Three"]);
  // Dropped on the gap before the first step, a card takes a step of its own there.
  await page.setViewportSize({ width: 1280, height: 1300 }); // both ends on screen: no scroll mid-drag
  await page.locator(".os-rcpt__grip").nth(2).dragTo(page.getByTestId("step-gap").first());
  expect(await names()).toEqual(["Three", "Two", "One"]);
});

test("Shift+click selects several fields; they line up, move and delete together, and undo restores them", async ({ page }) => {
  await signIn(page);
  await page.goto(app("#/prepare"));
  await page.getByTestId("pdf-input").setInputFiles(pdfFile());
  await page.getByTestId("wizard-next").click();
  await addRecipient(page, 0, { name: "Gus Group", email: "gus@example.com" });
  await page.getByTestId("wizard-next").click();
  const sig = page.locator(".os-palette").getByRole("button", { name: "Add Signature field" });
  await sig.press("Enter");
  await page.locator(".os-palette").getByRole("button", { name: "Add Date signed field" }).press("Enter");
  await page.locator(".os-palette").getByRole("button", { name: "Add Text field" }).press("Enter");
  const fields = page.locator(".os-field");
  await expect(fields).toHaveCount(3);
  // Each new field goes just below the one placed before it, lined up (F-01).
  const [a, b2, c] = await Promise.all([0, 1, 2].map((i) => fields.nth(i).boundingBox()));
  expect(Math.round(b2.x)).toBe(Math.round(a.x));
  expect(b2.y).toBeGreaterThan(a.y + a.height);
  expect(c.y).toBeGreaterThan(b2.y + b2.height);
  expect(c.y - (a.y + a.height)).toBeLessThan(200);
  // Spread them out so that lining up has something to do.
  await fields.nth(1).click();
  for (let i = 0; i < 6; i++) await page.keyboard.press("Shift+ArrowRight");
  await fields.nth(0).click();
  await fields.nth(1).click({ modifiers: ["Shift"] });
  await fields.nth(2).click({ modifiers: ["Shift"] });
  await expect(page.getByRole("heading", { name: "3 fields selected" })).toBeVisible();
  await expect(page.locator(".os-field.is-selected")).toHaveCount(3);
  const lefts = async () => Promise.all([0, 1, 2].map(async (i) => Math.round((await fields.nth(i).boundingBox()).x)));
  const before = await lefts();
  expect(new Set(before).size).toBeGreaterThan(1);
  await page.getByTestId("arrange-left").click();
  expect(new Set(await lefts()).size).toBe(1);
  // The arrows move the group.
  const x0 = (await lefts())[0];
  await fields.nth(0).focus();
  await page.keyboard.press("Shift+ArrowRight");
  expect(new Set(await lefts()).size).toBe(1);
  expect((await lefts())[0]).toBeGreaterThan(x0);
  // Undo twice: back to the spread-out positions.
  await page.keyboard.press("Control+z");
  await page.keyboard.press("Control+z");
  expect(await lefts()).toEqual(before);
  // Select all three again and delete them together; Undo in the toast brings them back.
  await fields.nth(0).click();
  await fields.nth(1).click({ modifiers: ["Shift"] });
  await fields.nth(2).click({ modifiers: ["Shift"] });
  await page.getByRole("button", { name: "Delete 3 fields" }).click();
  await expect(fields).toHaveCount(0);
  await page.getByTestId("toast-action").click();
  await expect(fields).toHaveCount(3);
});

test("a draft saves itself after a pause, keeps the selection, and then leaves without asking", async ({ page }) => {
  await signIn(page);
  await page.goto(app("#/prepare"));
  await page.getByTestId("pdf-input").setInputFiles(pdfFile());
  await page.getByTestId("wizard-next").click();
  await addRecipient(page, 0, { name: "Ada Auto", email: "ada@example.com" });
  await page.getByTestId("wizard-next").click();
  await page.locator(".os-palette").getByRole("button", { name: "Add Signature field" }).press("Enter");
  await expect(page.getByTestId("save-status")).toContainText("Unsaved changes");
  // Unsaved: leaving asks (A12); staying keeps the work.
  await page.goto(app("#/agreements"));
  await page.getByRole("button", { name: "Cancel" }).click();
  await expect(page).toHaveURL(/#\/prepare$/);
  // Autosave (P-04): quietly, a few seconds after the last change.
  await expect(page.getByTestId("save-status")).toContainText("Saved at", { timeout: 15_000 });
  await expect(page).toHaveURL(/#\/prepare\/.+/);
  await expect(page.locator(".os-field.is-selected")).toHaveCount(1);
  await page.goto(app("#/agreements"));
  await expect(page.getByRole("heading", { name: "Agreements" })).toBeVisible();
});
