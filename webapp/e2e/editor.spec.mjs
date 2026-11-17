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
  // Nothing selected: the canvas's "Ready to save?" checks name each role's signature.
  await expect(page.getByTestId("send-checks")).toContainText("Company has a signature field");
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
  await page.locator(".os-palette").getByRole("button", { name: "Add Text field" }).press("Enter");
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
  await page.locator(".os-palette").getByRole("button", { name: "Add Signature field" }).press("Enter");
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
/// A card dragged by its grip onto `target` (HTML drag and drop, as Playwright drives it
/// in each engine).
async function dragCard(page, source, target) {
  await source.dragTo(target);
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
    await page.locator(".os-palette").getByRole("button", { name: "Add Signature field" }).press("Enter");
  }
  await page.getByTestId("save-draft").click();
  await expect(page.getByTestId("save-status")).toContainText("Saved");
  const env = (await mockDb(page)).envelopes.find((e) => e.recipients.some((r) => r.name === "Dev"));
  expect(Object.fromEntries(env.recipients.map((r) => [r.name, r.routing_order]))).toEqual({ Dev: 1, Ana: 2, Ben: 3, Cleo: 3 });
  // Reopened, the steps are as saved; the send confirmation names them in order.
  // The saved draft opens on its fields once loaded (E2E-09): until then it has no people,
  // so the steps are read only after that, and polled, never read once.
  await page.reload();
  await expect(page.locator('.os-stepper__btn[aria-current="step"]')).toContainText("Fields");
  await expect(page.locator(".os-page.is-loading")).toHaveCount(0);
  await step(page, "Recipients");
  await expect.poll(() => stepsOf(page)).toEqual([["Dev"], ["Ana"], ["Ben", "Cleo"]]);
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

// ---- 3. Marquee selection and snapping guides -----------------------------------------------------

/// A draft with one signer and a signature, a date and a text field stacked on page 1.
async function threeFields(page) {
  await newWithRecipients(page, [["Ana", "ana@example.com"]]);
  await page.getByTestId("wizard-next").click();
  await expect(page.locator(".os-page.is-loading")).toHaveCount(0);
  for (const type of ["Signature", "Date signed", "Text"]) await page.locator(".os-palette").getByRole("button", { name: `Add ${type} field` }).press("Enter");
  await expect(page.locator(".os-field")).toHaveCount(3);
}
/// The selected field's x, as its properties panel shows it (points).
async function xOf(page, field) {
  await field.click();
  const adv = page.locator(".os-advanced");
  if (!(await adv.evaluate((d) => d.open))) await adv.locator("summary").click();
  return Number(await page.locator("#fp-x").inputValue());
}

test("a marquee selects the fields it touches; the group moves as one", async ({ page }, testInfo) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await threeFields(page);
  const fields = page.locator(".os-field");
  const boxes = await fields.evaluateAll((els) => els.map((e) => { const r = e.getBoundingClientRect(); return { x: r.x, y: r.y, w: r.width, h: r.height }; }));
  const top = Math.min(...boxes.map((b) => b.y));
  const left = Math.min(...boxes.map((b) => b.x));
  // From empty page above-left of the fields to past the first two.
  await page.mouse.move(left - 30, top - 20);
  await page.mouse.down();
  await page.mouse.move(left + 40, boxes[1].y + boxes[1].h / 2, { steps: 6 });
  await expect(page.getByTestId("marquee")).toBeVisible();
  await snap(page, testInfo, "editor-marquee-1440");
  await page.mouse.up();
  await expect(page.getByTestId("marquee")).toHaveCount(0);
  await expect(page.locator(".os-field.is-selected")).toHaveCount(2);
  await expect(page.locator(".os-props")).toContainText("2 fields selected");
  // Dragging one of them moves both by the same distance.
  // Positions as placed (style, in % of the page), not as drawn: a dropped field bounces.
  const lefts = () => fields.evaluateAll((els) => els.slice(0, 2).map((e) => Number.parseFloat(e.style.left)));
  const before = await lefts();
  const f0 = boxes[0];
  await page.mouse.move(f0.x + f0.w / 2, f0.y + f0.h / 2);
  await page.mouse.down();
  await page.mouse.move(f0.x + f0.w / 2 + 60, f0.y + f0.h / 2 + 30, { steps: 6 });
  await page.mouse.up();
  const after = await lefts();
  expect((after[0] - before[0]).toFixed(2)).toBe((after[1] - before[1]).toFixed(2));
  expect(after[0] - before[0]).toBeGreaterThan(3);
  await expect(page.locator(".os-field.is-selected")).toHaveCount(2);
  // A click on an empty part of the page clears the selection.
  await page.mouse.click(left - 30, top - 20);
  await expect(page.locator(".os-field.is-selected")).toHaveCount(0);
});

test("a dragged field snaps to another field's edge with a guide; Alt turns snapping off", async ({ page }) => {
  await threeFields(page);
  const date = page.locator('.os-field[data-field="date_signed"]');
  const x0 = await xOf(page, date);
  const dragBy = async (dx, alt) => {
    const b = await date.boundingBox();
    await page.mouse.move(b.x + b.width / 2, b.y + b.height / 2);
    if (alt) await page.keyboard.down("Alt");
    await page.mouse.down();
    await page.mouse.move(b.x + b.width / 2 + dx / 2, b.y + b.height / 2, { steps: 2 });
    await page.mouse.move(b.x + b.width / 2 + dx, b.y + b.height / 2, { steps: 2 });
    const guides = await page.getByTestId("snap-guide").count();
    await page.mouse.up();
    if (alt) await page.keyboard.up("Alt");
    return guides;
  };
  // 4 screen pixels right is within the 6-pixel tolerance of the other fields' left edge.
  expect(await dragBy(4, false)).toBeGreaterThan(0);
  await expect(page.getByTestId("snap-guide")).toHaveCount(0);
  expect(await xOf(page, date)).toBe(x0);
  // With Alt the same move is kept as made.
  expect(await dragBy(4, true)).toBe(0);
  expect(await xOf(page, date)).toBeGreaterThan(x0 + 1);
});

test("keyboard parity: Ctrl/Cmd+A selects the page's fields; Alt+Shift+arrows jump to the next guide", async ({ page }) => {
  await threeFields(page);
  const date = page.locator('.os-field[data-field="date_signed"]');
  const x0 = await xOf(page, date);
  // Away from the others, then back to their left edge in one jump.
  for (let i = 0; i < 3; i++) await page.keyboard.press("Shift+ArrowRight");
  expect(await xOf(page, date)).toBe(x0 + 30);
  await date.focus();
  // Each press stops at the next guide (a centre or an edge lining up), never past x0.
  const seen = [];
  for (let i = 0; i < 6 && (seen.at(-1) ?? Infinity) > x0; i++) {
    await date.focus();
    await page.keyboard.press("Alt+Shift+ArrowLeft");
    // The guide it landed on shows for a moment.
    await expect(page.getByTestId("snap-guide").first()).toBeAttached();
    seen.push(await xOf(page, date));
  }
  expect(seen.at(-1)).toBe(x0);
  expect(seen.every((x, i) => x < (seen[i - 1] ?? x0 + 30))).toBe(true);
  await page.locator("#document").focus();
  await page.keyboard.press("ControlOrMeta+a");
  await expect(page.locator(".os-field.is-selected")).toHaveCount(3);
  await expect(page.locator(".os-props")).toContainText("3 fields selected");
  // In a text box, Ctrl/Cmd+A is the text's, not the fields'.
  await page.keyboard.press("Escape");
  await page.locator('.os-field[data-field="text"]').click();
  await page.getByLabel("Label").fill("Title");
  await page.getByLabel("Label").press("ControlOrMeta+a");
  await expect(page.locator(".os-field.is-selected")).toHaveCount(1);
});

// ---- 4. Detect fields ---------------------------------------------------------------------------

test("Detect fields: suggestions as ghosts for the current signer; accept one, accept all, dismiss; undoable", async ({ page }, testInfo) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await newWithRecipients(page, [["Ana", "ana@example.com"], ["Ben", "ben@example.com"]]);
  await page.getByTestId("wizard-next").click();
  await expect(page.locator(".os-page.is-loading")).toHaveCount(0);
  await placingFor(page, "Ben");
  // The draft is saved first (detection reads the stored documents), then the mock
  // suggests a signature, a date and a name on each of the two pages.
  await page.getByTestId("detect-fields").click();
  const ghosts = page.getByTestId("ghost");
  await expect(ghosts).toHaveCount(6);
  // The floating bar (canvas): "6 suggested fields for Ben", and Continue is held.
  await expect(page.getByTestId("suggestions")).toContainText("6 suggested fields for Ben");
  await expect(page.getByTestId("wizard-next")).toHaveAttribute("aria-disabled", "true");
  await expect(page.locator(".os-field")).toHaveCount(0);
  await expectAccessible(page, "detected fields");
  await snap(page, testInfo, "editor-detect-1440");

  // Accept one: a real field for Ben where the ghost was.
  await page.getByRole("button", { name: "Accept suggested Signature field, page 1" }).click();
  await expect(ghosts).toHaveCount(5);
  await expect(page.locator('.os-field[data-field="signature"]')).toHaveCount(1);
  await expect(page.locator('.os-field[data-field="signature"]')).toHaveAttribute("aria-label", /Ben/);
  // Dismiss one by keyboard.
  await page.getByRole("button", { name: "Accept suggested Date signed field, page 1" }).focus();
  await page.keyboard.press("Delete");
  await expect(ghosts).toHaveCount(4);
  // Undo brings the dismissed suggestion back; redo takes it away again.
  await page.getByTestId("undo").click();
  await expect(ghosts).toHaveCount(5);
  await page.getByTestId("redo").click();
  await expect(ghosts).toHaveCount(4);
  // Accept all for Ana.
  await placingFor(page, "Ana");
  await page.getByTestId("accept-all").click();
  await expect(ghosts).toHaveCount(0);
  await expect(page.locator(".os-field")).toHaveCount(5);
  await expect(page.locator(".os-field", { has: page.locator('[data-who="Ana"]') })).toHaveCount(4);
  await page.getByTestId("undo").click();
  await expect(ghosts).toHaveCount(4);
  await page.getByTestId("dismiss-all").click();
  await expect(ghosts).toHaveCount(0);
  await expect(page.locator(".os-field")).toHaveCount(1);
  // Detection again skips what is already placed.
  await page.getByTestId("detect-fields").click();
  await expect(ghosts).toHaveCount(5);
  await page.setViewportSize({ width: 390, height: 844 });
  await expect(page.locator(".os-page.is-loading")).toHaveCount(0);
  await snap(page, testInfo, "editor-detect-390");
});

test("Detect fields is not offered for a template (the API detects on envelopes)", async ({ page }) => {
  await signIn(page);
  await page.goto(app("#/templates/new"));
  await page.getByTestId("pdf-input").setInputFiles(pdfFile());
  await step(page, "Fields");
  await expect(page.getByTestId("detect-fields")).toHaveCount(0);
});

// ---- 5. The editor on the approved canvas (WEB-17 lane B) ------------------------------------

/// Open the seeded draft "Lease renewal 2027" (the mock's template match, scanned page and
/// personal data) on its fields.
async function openLease(page) {
  const env = (await mockDb(page)).envelopes.find((e) => /^Lease renewal/.test(e.subject));
  await page.goto(app(`#/prepare/${env.id}`));
  await expect(page.locator('.os-stepper__btn[aria-current="step"]')).toContainText("Fields");
  await expect(page.getByTestId("prepare-loading")).toHaveCount(0);
}

test("canvas: single-key tools arm a kind, the hint names it, and a click places it; Continue says why it is held", async ({ page }, testInfo) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await newWithRecipients(page, [["Jordan Rivera", "jordan@example.com"], ["Sam Patel", "sam@example.com"]]);
  await page.getByTestId("wizard-next").click();
  await expect(page.locator(".os-page.is-loading").first()).toHaveCount(0);
  // Nothing placed: the illustrated empty state with its two next actions.
  await expect(page.getByTestId("empty-fields")).toContainText("No fields yet");
  await expect(page.getByTestId("empty-place-signature")).toBeVisible();
  await page.locator(".os-stage").focus();
  await page.keyboard.press("s");
  await expect(page.getByTestId("arm-hint")).toContainText("Click on the page to place Signature for Jordan");
  await expect(page.getByRole("button", { name: "Signature (S)" })).toHaveAttribute("aria-pressed", "true");
  const ov = await page.locator(".os-page__overlay").first().boundingBox();
  await page.mouse.click(ov.x + ov.width * 0.3, ov.y + ov.height * 0.5);
  await expect(page.locator('.os-field[data-field="signature"]')).toHaveCount(1);
  await expect(page.getByTestId("arm-hint")).toHaveCount(0);
  // V is Select; N arms Full name here (not a new envelope).
  await page.locator(".os-stage").focus();
  await page.keyboard.press("n");
  await expect(page.getByRole("button", { name: "Name (N)" })).toHaveAttribute("aria-pressed", "true");
  await page.keyboard.press("v");
  await expect(page.getByRole("button", { name: "Select (V)" })).toHaveAttribute("aria-pressed", "true");
  await expect(page).toHaveURL(/#\/prepare/);
  // Sam has no field: Continue is held and says why; the press picks Sam.
  await page.getByTestId("wizard-next").click({ force: true });
  await expect(page.getByTestId("continue-why")).toHaveText("Every signer needs a field");
  await expect(page.getByRole("radiogroup", { name: "Placing fields for" }).getByRole("radio", { name: "Sam Patel" })).toHaveAttribute("aria-checked", "true");
  await page.keyboard.press("Escape");
  await expect(page.getByTestId("send-checks")).toContainText("Sam Patel has no fields yet");
  await expectAccessible(page, "canvas editor");
  await snap(page, testInfo, "editor-canvas-1440");
});

test("canvas: the template match is applied by a click, undone from its chip, and the model's results show", async ({ page }, testInfo) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await signIn(page);
  await openLease(page);
  const banner = page.getByTestId("tpl-banner");
  await expect(banner).toContainText("Looks like your “MSA v4” template");
  await expect(banner).toContainText("96% match");
  // Scanned page (OCR) and personal data, from the analysis and the suggestions.
  await expect(page.locator(".os-thumb__ocr")).toHaveCount(1);
  await expect(page.getByTestId("send-checks")).toContainText("is a scan; its text was read by OCR");
  await expect(page.getByTestId("pii-card")).toContainText("Personal data on page");
  await expectAccessible(page, "template match");
  await snap(page, testInfo, "editor-template-match-1440");
  const before = await page.locator(".os-field").count();
  await page.getByTestId("tpl-apply").click();
  await expect(page.getByTestId("tpl-applied")).toContainText("Applied “MSA v4”");
  await expect(page.locator(".os-field")).not.toHaveCount(before);
  const db = await mockDb(page);
  const env = db.envelopes.find((e) => /^Lease renewal/.test(e.subject));
  expect(db.ml.suggestions[env.id].find((s) => s.kind === "template").state).toBe("accepted");
  await page.getByTestId("tpl-undo").click();
  await expect(page.locator(".os-field")).toHaveCount(before);
  await expect(banner).toBeVisible();
  await page.getByTestId("tpl-skip").click();
  await expect(banner).toHaveCount(0);
});

test("canvas: with no model service (404) no ML control, badge or card appears", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await signIn(page);
  await page.evaluate(() => sessionStorage.setItem("openseal.mock.ml", "off"));
  await openLease(page);
  await expect(page.getByTestId("send-checks")).toContainText("has a signature field");
  for (const id of ["tpl-banner", "pii-card"]) await expect(page.getByTestId(id)).toHaveCount(0);
  await expect(page.locator(".os-thumb__ocr")).toHaveCount(0);
  await expect(page.getByTestId("send-checks")).not.toContainText("OCR");
  await expect(page.locator(".os-props__fine")).toHaveCount(0);
});
