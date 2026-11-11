// The send editor's WEB-09 features (docs/47 §As built WEB-09): a template reopened in the
// editor and saved back, parallel signing groups, marquee selection and snapping guides,
// and field detection. Mock mode, since each needs the mock's seeded data; screenshots
// at 1440 and 390 go to target/e2e-screens/.
import { test, expect } from "@playwright/test";
import { signIn, app, pdfFile, snap, expectAccessible, REAL, placingFor } from "./helpers.mjs";

test.skip(REAL, "needs the mock's seeded template and its detection answers");

const mockDb = (page) => page.evaluate(() => JSON.parse(sessionStorage.getItem("openseal.mock.v1")));

async function step(page, name) {
  await page.locator(".os-stepper__btn", { hasText: name }).click();
  await expect(page.locator('.os-stepper__btn[aria-current="step"]')).toContainText(name);
}

// ---- 1. Templates: reopen documents, roles and fields; save back ----------------------------

test("Edit reopens a template's document, roles and fields, and Save brings the server into line", async ({ page }, testInfo) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await signIn(page);
  await page.goto(app("#/templates"));
  await page.getByRole("button", { name: "Actions for Mutual NDA" }).click();
  await page.getByRole("menuitem", { name: "Edit", exact: true }).click();
  await expect(page).toHaveURL(/#\/templates\/[^/]+\/edit$/);
  await expect(page.getByRole("heading", { name: "Mutual NDA" })).toBeVisible();
  // A template with documents and roles opens on its fields, two signers' worth.
  await expect(page.locator('.os-stepper__btn[aria-current="step"]')).toContainText("Fields");
  await expect(page.locator(".os-page")).toHaveCount(2);
  await expect(page.locator(".os-page.is-loading")).toHaveCount(0);
  await expect(page.locator(".os-field")).toHaveCount(4);
  // The placed list numbers pages once the pages are laid out (it said "page 0").
  await expect(page.getByTestId("placed-field").first()).toContainText("page 1");
  await expectAccessible(page, "template editor");
  await snap(page, testInfo, "editor-template-1440");

  // Rename a role, remove the copy role, add a field for the renamed role and delete another.
  await step(page, "Roles");
  expect(await page.getByTestId("role-name").evaluateAll((els) => els.map((e) => e.value))).toEqual(["Company", "Counterparty", "Legal"]);
  await page.getByTestId("role-name").nth(1).fill("Partner");
  await page.getByTestId("role-name").nth(1).blur();
  await page.getByRole("button", { name: "Remove Legal" }).click();
  await expect(page.getByTestId("role-name")).toHaveCount(2);
  await step(page, "Fields");
  await placingFor(page, "Partner");
  await page.locator(".os-palette").getByRole("button", { name: "Add Text field" }).click();
  await expect(page.locator(".os-field")).toHaveCount(5);
  await page.locator('.os-field[data-field="date_signed"]').first().click();
  await page.keyboard.press("Delete");
  await expect(page.locator(".os-field")).toHaveCount(4);
  await step(page, "Review");
  await page.getByLabel("Template name").fill("Mutual NDA 2027");
  await page.getByRole("button", { name: "Save template" }).click();
  await expect(page.locator(".os-toast").last()).toContainText("Template saved.");
  await expect(page.getByRole("link", { name: "Mutual NDA 2027" })).toBeVisible();

  // The server's template now says what the editor said.
  const tp = (await mockDb(page)).templates.find((x) => x.name === "Mutual NDA 2027");
  expect(tp.roles.map((r) => r.name)).toEqual(["Company", "Partner"]);
  const partner = tp.roles.find((r) => r.name === "Partner").id;
  expect(tp.fields).toHaveLength(4);
  expect(tp.fields.filter((f) => f.role_id === partner).map((f) => f.type)).toContain("text");
  expect(tp.fields.every((f) => tp.roles.some((r) => r.id === f.role_id))).toBe(true);

  // Reopened, it is as saved; leaving without a change asks nothing.
  await page.getByRole("button", { name: "Actions for Mutual NDA 2027" }).click();
  await page.getByRole("menuitem", { name: "Edit", exact: true }).click();
  await expect(page.locator(".os-field")).toHaveCount(4);
  await step(page, "Roles");
  expect(await page.getByTestId("role-name").evaluateAll((els) => els.map((e) => e.value))).toEqual(["Company", "Partner"]);
  await page.setViewportSize({ width: 390, height: 844 });
  await step(page, "Fields");
  await expect(page.locator(".os-page.is-loading")).toHaveCount(0);
  await snap(page, testInfo, "editor-template-390");
});

test("a template's document can be removed in the editor, and the server drops it with its fields", async ({ page }) => {
  await signIn(page);
  await page.goto(app("#/templates"));
  await page.getByRole("button", { name: "Actions for Mutual NDA" }).click();
  await page.getByRole("menuitem", { name: "Edit", exact: true }).click();
  await expect(page.locator(".os-field")).toHaveCount(4);
  await step(page, "Documents");
  await page.getByTestId("pdf-input").setInputFiles(pdfFile("annex.pdf", "Annex"));
  await expect(page.getByTestId("doc-card")).toHaveCount(2);
  await page.getByRole("button", { name: "Remove mutual-nda.pdf" }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Remove" }).click();
  await expect(page.getByTestId("doc-card")).toHaveCount(1);
  await step(page, "Fields");
  await page.locator(".os-palette").getByRole("button", { name: "Add Signature field" }).click();
  await step(page, "Review");
  await page.getByRole("button", { name: "Save template" }).click();
  await expect(page.locator(".os-toast").last()).toContainText("Template saved.");
  const tp = (await mockDb(page)).templates.find((x) => x.name === "Mutual NDA");
  expect(tp.documents.map((d) => d.name)).toEqual(["annex.pdf"]);
  expect(tp.fields).toHaveLength(1);
  expect(tp.fields[0].document_id).toBe(tp.documents[0].id);
});

// ---- 2. Parallel signing groups ---------------------------------------------------------------

async function newWithRecipients(page, people) {
  await signIn(page);
  await page.goto(app("#/prepare"));
  await page.getByTestId("pdf-input").setInputFiles(pdfFile());
  await page.getByTestId("wizard-next").click();
  for (const [i, [name, email]] of people.entries()) {
    await page.getByRole("button", { name: "Add recipient" }).first().click();
    const row = page.locator(".os-rcpt").nth(i);
    await row.getByTestId("recipient-name").fill(name);
    await row.getByTestId("recipient-email").fill(email);
    await row.getByTestId("recipient-email").blur();
  }
}
const names = (page) => page.getByTestId("recipient-name").evaluateAll((els) => els.map((e) => e.value));
const stepsOf = (page) => page.getByTestId("signing-step").evaluateAll((els) => els.map((g) => [...g.querySelectorAll('[data-testid="recipient-name"]')].map((e) => e.value)));
/// A card dragged by its grip; the pointer leaves the grip first, so the drag starts there.
async function dragCard(page, source, target) {
  const s = await source.boundingBox();
  const d = await target.boundingBox();
  await page.mouse.move(s.x + s.width / 2, s.y + s.height / 2);
  await page.mouse.down();
  await page.mouse.move(s.x + s.width / 2 + 4, s.y + s.height / 2 + 4);
  await page.mouse.move(d.x + d.width / 2, d.y + d.height / 2, { steps: 6 });
  await page.mouse.up();
}
const cardOf = (page, name) => page.locator(".os-rcpt").filter({ has: page.getByLabel(`Signing step for ${name}`) });

test("recipients sharing a step sign at the same time: grouped by number, drag and keys; saved as one routing order", async ({ page }, testInfo) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await newWithRecipients(page, [["Ana", "ana@example.com"], ["Ben", "ben@example.com"], ["Cleo", "cleo@example.com"], ["Dev", "dev@example.com"]]);
  expect(await stepsOf(page)).toEqual([["Ana"], ["Ben"], ["Cleo"], ["Dev"]]);
  // The number box: Cleo to step 2 joins Ben.
  await page.getByLabel("Signing step for Cleo").fill("2");
  await page.getByLabel("Signing step for Cleo").press("Enter");
  expect(await stepsOf(page)).toEqual([["Ana"], ["Ben", "Cleo"], ["Dev"]]);
  const step2 = page.getByTestId("signing-step").nth(1);
  await expect(step2).toContainText("2 sign at the same time");
  await expect(step2).toHaveAccessibleName(/Step 2/);
  // Drag Dev's card onto step 1's box: Dev signs with Ana.
  // Tall enough that both ends of the drag are on screen (no scrolling mid-drag).
  await page.setViewportSize({ width: 1440, height: 1400 });
  await dragCard(page, cardOf(page, "Dev").locator(".os-rcpt__grip"), page.getByTestId("signing-step").nth(0).locator(".os-rgroup__head"));
  await page.setViewportSize({ width: 1440, height: 900 });
  expect(await stepsOf(page)).toEqual([["Ana", "Dev"], ["Ben", "Cleo"]]);
  await expectAccessible(page, "signing steps");
  await snap(page, testInfo, "editor-steps-1440");
  // Keys: Dev up leaves the shared step for one of their own before it; then the
  // whole of step 3 moves earlier.
  await cardOf(page, "Dev").getByRole("button", { name: "Move up in signing order" }).click();
  expect(await stepsOf(page)).toEqual([["Dev"], ["Ana"], ["Ben", "Cleo"]]);
  await page.getByRole("button", { name: "Move step 3 earlier" }).click();
  expect(await stepsOf(page)).toEqual([["Dev"], ["Ben", "Cleo"], ["Ana"]]);
  // Undo puts the steps back as they were before the last change.
  await page.getByRole("heading", { name: "Recipients" }).click();
  await page.keyboard.press("ControlOrMeta+z");
  expect(await stepsOf(page)).toEqual([["Dev"], ["Ana"], ["Ben", "Cleo"]]);
  await page.setViewportSize({ width: 390, height: 844 });
  await snap(page, testInfo, "editor-steps-390");
  await page.setViewportSize({ width: 1440, height: 900 });

  // Fields for each signer, then save: one routing order per step on the server.
  await page.getByTestId("wizard-next").click();
  for (const who of ["Dev", "Ana", "Ben", "Cleo"]) {
    await placingFor(page, who);
    await page.locator(".os-palette").getByRole("button", { name: "Add Signature field" }).click();
  }
  await page.getByTestId("save-draft").click();
  await expect(page.getByTestId("save-status")).toContainText("Saved");
  const env = (await mockDb(page)).envelopes.find((e) => e.recipients.some((r) => r.name === "Dev"));
  expect(Object.fromEntries(env.recipients.map((r) => [r.name, r.routing_order]))).toEqual({ Dev: 1, Ana: 2, Ben: 3, Cleo: 3 });
  // Reopened, the steps are as saved; the send confirmation names them in order.
  await page.reload();
  await expect(page.locator(".os-page.is-loading")).toHaveCount(0);
  await step(page, "Recipients");
  expect(await stepsOf(page)).toEqual([["Dev"], ["Ana"], ["Ben", "Cleo"]]);
  await step(page, "Review");
  await page.getByRole("button", { name: "Send", exact: true }).click();
  await expect(page.getByRole("dialog")).toContainText("Dev → Ana → Ben & Cleo");
});

test("with signing order off, everyone signs at once; turning it on gives one step each", async ({ page }) => {
  await newWithRecipients(page, [["Ana", "ana@example.com"], ["Ben", "ben@example.com"]]);
  await page.getByText("Set signing order").click();
  await expect(page.getByTestId("signing-step")).toHaveCount(0);
  await expect(page.getByText("All signers get the envelope at once.")).toBeVisible();
  await page.getByText("Set signing order").click();
  expect(await stepsOf(page)).toEqual([["Ana"], ["Ben"]]);
  expect(await names(page)).toEqual(["Ana", "Ben"]);
});
