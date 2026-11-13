// The prepare editor's layout and placement (UX-05, docs/47 §As built UX-05): the toolbar
// keeps Back and Next or Send on its first row at common laptop widths; an armed field
// type places a field where the page is clicked; the field kinds the ceremony fills can
// be placed and configured and come back from the server as set; recipients have the
// engine's ready types and their options; template mode says "Review and save".
// Screenshots at 1440 and 390 go to target/e2e-screens/.
import { test, expect } from "@playwright/test";
import { signIn, app, pdfFile, snap, expectAccessible, REAL, placingFor } from "./helpers.mjs";

test.skip(REAL, "reads the mock's stored envelope to check the round trip");

const mockDb = (page) => page.evaluate(() => JSON.parse(sessionStorage.getItem("openseal.mock.v1")));

async function step(page, name) {
  await page.locator(".os-stepper__btn", { hasText: name }).click();
  await expect(page.locator('.os-stepper__btn[aria-current="step"]')).toContainText(name);
}

/// A new envelope with one document and the people given, on the fields step.
async function toFields(page, people = [["Ana Signer", "ana@example.com"]], { wide = false } = {}) {
  if (wide) await widen(page);
  await signIn(page);
  await page.goto(app("#/prepare"));
  await page.getByTestId("pdf-input").setInputFiles(pdfFile());
  await expect(page.getByTestId("doc-card")).toHaveCount(1);
  await page.getByTestId("wizard-next").click();
  for (const [i, [name, email]] of people.entries()) {
    await page.getByRole("button", { name: "Add recipient" }).first().click();
    const row = page.locator(".os-rcpt").nth(i);
    await row.getByTestId("recipient-name").fill(name);
    await row.getByTestId("recipient-email").fill(email);
    await row.getByTestId("recipient-email").blur();
  }
  await page.getByTestId("wizard-next").click();
  await expect(page.locator(".os-page")).toHaveCount(2);
  await expect(page.locator(".os-page.is-loading")).toHaveCount(0);
}

/// The system's own font in place of the web font, as when a network or a policy blocks
/// the font file: the Linux fallback (DejaVu Sans) is wider than Inter, as a longer
/// translation would be, and is how the audit's screens (UX-01) saw the bar wrap at
/// 1440. Called before the first navigation.
const widen = (page) => page.route(/\/fonts\//, (route) => route.abort());

/// Whether `btn` sits on the toolbar's first row: its vertical centre is the back link's,
/// and the bar is one row high.
async function onFirstRow(page, btn) {
  const bar = await page.locator(".os-prepare__bar").boundingBox();
  const back = await page.locator(".os-prepare__lead > a").first().boundingBox();
  const b = await btn.boundingBox();
  const mid = (r) => r.y + r.height / 2;
  // Inside the window too: a bar wider than the window (a nowrap bar that could not
  // shrink) pushes the button off screen while it still "fits" the bar.
  const vw = page.viewportSize().width;
  const scrolls = await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth);
  return { same: Math.abs(mid(b) - mid(back)) <= 2, barHeight: Math.round(bar.height), inside: b.x + b.width <= Math.min(bar.x + bar.width, vw) + 0.5 && !scrolls };
}

for (const [width, wide] of [1366, 1440, 1536].flatMap((w) => [[w, false], [w, true]])) {
  test(`at ${width} px${wide ? " in the system font" : ""} Preview, Continue and Save, then Send, stay on the toolbar's first row (canvas bar)`, async ({ page }, testInfo) => {
    await page.setViewportSize({ width, height: 900 });
    await toFields(page, undefined, { wide });
    // The fullest bar: a saved draft (its subject as the title, "Saved at …"), on the
    // fields step with its document tools.
    await page.locator(".os-palette").getByRole("button", { name: "Add Signature field" }).press("Enter");
    await page.getByTestId("save-draft").click();
    await expect(page.getByTestId("save-status")).toContainText("Saved");
    await expect(page.locator(".os-prepare__title")).toHaveText("Please sign: contract");
    for (const [name, btn] of [["fields next", page.getByTestId("wizard-next")], ["preview", page.getByTestId("preview-signer")], ["save", page.getByTestId("save-draft")]]) {
      const r = await onFirstRow(page, btn);
      expect(r, `${name} at ${width}`).toEqual({ same: true, barHeight: r.barHeight, inside: true });
      expect(r.barHeight, `bar height at ${width}`).toBeLessThan(72);
    }
    if (width === 1440) await snap(page, testInfo, `prepare-fields-bar-1440${wide ? "-system-font" : ""}`);
    await step(page, "Review");
    const send = page.getByRole("button", { name: "Send", exact: true });
    const r = await onFirstRow(page, send);
    expect(r, `send at ${width}`).toEqual({ same: true, barHeight: r.barHeight, inside: true });
    expect(r.barHeight).toBeLessThan(72);
    if (width === 1440) await snap(page, testInfo, `prepare-review-1440${wide ? "-system-font" : ""}`);
  });
}

for (const width of [1366, 1440, 1536]) {
  test(`at ${width} px in the system font a template's toolbar keeps Continue and Save template on its first row`, async ({ page }, testInfo) => {
    await page.setViewportSize({ width, height: 900 });
    await widen(page);
    await signIn(page);
    await page.goto(app("#/templates/new"));
    await page.getByTestId("pdf-input").setInputFiles(pdfFile("master-services-agreement-2026.pdf"));
    await expect(page.getByTestId("doc-card")).toHaveCount(1);
    await page.getByTestId("wizard-next").click();
    await page.getByRole("button", { name: "Add role" }).first().click();
    await page.getByTestId("role-name").first().fill("Client");
    await page.getByTestId("wizard-next").click();
    await expect(page.locator(".os-page.is-loading")).toHaveCount(0);
    await page.locator(".os-palette").getByRole("button", { name: "Add Signature field" }).press("Enter");
    for (const btn of [page.getByTestId("wizard-next"), page.locator(".os-segsteps")]) {
      const r = await onFirstRow(page, btn);
      expect(r, `template fields at ${width}`).toEqual({ same: true, barHeight: r.barHeight, inside: true });
      expect(r.barHeight).toBeLessThan(72);
    }
    if (width === 1440) await snap(page, testInfo, "prepare-template-bar-1440");
    await page.getByTestId("wizard-next").click();
    const save = page.getByRole("button", { name: "Save template" });
    const r = await onFirstRow(page, save);
    expect(r, `template review at ${width}`).toEqual({ same: true, barHeight: r.barHeight, inside: true });
  });
}

// ---- Click-to-place ------------------------------------------------------------------------

/// The selected field's rectangle in points, as its properties panel shows it.
async function rectOf(page) {
  const adv = page.locator(".os-advanced");
  if (!(await adv.evaluate((d) => d.open))) await adv.locator("summary").click();
  const v = async (k) => Number(await page.locator(`#fp-${k}`).inputValue());
  return { x: await v("x"), y: await v("y"), width: await v("width"), height: await v("height") };
}
/// A point on page `n` (1-based) in screen pixels, from points; and back.
async function pageGeom(page, n = 1) {
  const ov = page.locator(".os-page__overlay").nth(n - 1);
  const box = await ov.boundingBox();
  return { box, scale: box.width / 612 };
}

test("a clicked field type places its field where the page is clicked; Escape cancels; a double click keeps it armed", async ({ page }, testInfo) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await toFields(page);
  const sig = page.locator(".os-palette").getByRole("button", { name: "Add Signature field" });
  await sig.click();
  // Armed, not placed: the type is pressed and the page has no field yet.
  await expect(sig).toHaveAttribute("aria-pressed", "true");
  await expect(page.locator(".os-field")).toHaveCount(0);
  const { box, scale } = await pageGeom(page, 1);
  // Below the body text, in the part of the page on screen.
  const at = { x: 400, y: 400 };
  const px = { x: box.x + at.x * scale, y: box.y + at.y * scale };
  await page.mouse.move(px.x - 20, px.y - 20);
  await page.mouse.move(px.x, px.y, { steps: 3 });
  await expect(page.getByTestId("arm-ghost")).toBeVisible();
  await snap(page, testInfo, "prepare-armed-1440");
  await page.mouse.click(px.x, px.y);
  await expect(page.locator(".os-field")).toHaveCount(1);
  await expect(sig).toHaveAttribute("aria-pressed", "false");
  await expect(page.getByTestId("arm-ghost")).toHaveCount(0);
  const r = await rectOf(page);
  // Centred on the clicked point, within 2 points.
  expect(Math.abs(r.x + r.width / 2 - at.x), `x centre ${JSON.stringify(r)}`).toBeLessThanOrEqual(2);
  expect(Math.abs(r.y + r.height / 2 - at.y), `y centre ${JSON.stringify(r)}`).toBeLessThanOrEqual(2);

  // Escape disarms: the next click on the page places nothing.
  const text = page.locator(".os-palette").getByRole("button", { name: "Add Text field" });
  await text.click();
  await expect(text).toHaveAttribute("aria-pressed", "true");
  await page.keyboard.press("Escape");
  await expect(text).toHaveAttribute("aria-pressed", "false");
  await page.mouse.click(box.x + 100 * scale, box.y + 300 * scale);
  await expect(page.locator(".os-field")).toHaveCount(1);

  // A double click keeps the type armed: two clicks, two fields; Escape ends it.
  const date = page.locator(".os-palette").getByRole("button", { name: "Add Date signed field" });
  await date.dblclick();
  await expect(date).toHaveAttribute("aria-pressed", "true");
  // Above the floating tool bar: with the document at least 65 % of the width the page
  // is drawn larger, and 460 pt down now sits under the bar.
  await page.mouse.click(box.x + 120 * scale, box.y + 320 * scale);
  await page.mouse.click(box.x + 420 * scale, box.y + 320 * scale);
  await expect(page.locator('.os-field[data-field="date_signed"]')).toHaveCount(2);
  await expect(date).toHaveAttribute("aria-pressed", "true");
  await page.keyboard.press("Escape");
  await expect(date).toHaveAttribute("aria-pressed", "false");

  // The keyboard still places on the page in view with Enter.
  await page.locator(".os-palette").getByRole("button", { name: "Add Initials field" }).press("Enter");
  await expect(page.locator('.os-field[data-field="initials"]')).toHaveCount(1);
  await expectAccessible(page, "editor with click-to-place");
});

// ---- Field kinds and their properties -------------------------------------------------------

const add = (page, type) => page.locator(".os-palette").getByRole("button", { name: `Add ${type} field` }).press("Enter");
const pick = (page, type) => page.locator(`.os-field[data-field="${type}"]`).first().click();

test("the ceremony's field kinds are placed and configured, and come back from the server as set", async ({ page }, testInfo) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await toFields(page);
  // The library (canvas): every kind the ceremony fills, the canvas's eight with their keys first.
  await expect(page.locator(".os-palette .os-lib")).toHaveCount(14);
  await expect(page.locator(".os-palette .os-lib[aria-keyshortcuts]")).toHaveCount(8);
  for (const type of ["Company", "Title", "Number", "Radio group", "Dropdown", "Attachment", "Note"]) await add(page, type);
  await add(page, "Text");
  await expect(page.locator(".os-field")).toHaveCount(8);

  // Text: required by default; a pattern, a tooltip and a sender's read-only value.
  await pick(page, "text");
  await expect(page.locator("#fp-required")).toBeChecked();
  await page.locator("#fp-validate").selectOption("regex");
  await page.locator("#fp-pattern").fill("[A-Z]{3}-\\d{4}");
  await page.locator("#fp-pattern").blur();
  await page.locator("#fp-vmsg").fill("Like ABC-1234");
  await page.locator("#fp-vmsg").blur();
  await page.locator("#fp-tooltip").fill("Your reference");
  await page.locator("#fp-tooltip").blur();
  await page.locator("#fp-label").fill("reference");
  await page.locator("#fp-label").blur();
  await snap(page, testInfo, "prepare-props-text-1440");
  // Number: a range.
  await pick(page, "number");
  await page.locator("#fp-min").fill("1");
  await page.locator("#fp-min").blur();
  await page.locator("#fp-max").fill("99.5");
  await page.locator("#fp-max").blur();
  // Dropdown: its options, and a typed answer allowed.
  await pick(page, "dropdown");
  await page.locator("#fp-options").fill("Red\nGreen\n\nRed\nBlue");
  await page.locator("#fp-options").blur();
  await page.locator("#fp-custom").check();
  // Note: the sender's text. Company: read only with a value, formatted.
  await pick(page, "note");
  await page.locator("#fp-note").fill("Initial each page.");
  await page.locator("#fp-note").blur();
  await pick(page, "company");
  await page.locator("#fp-readonly").check();
  await page.locator("#fp-value").fill("Acme Ltd");
  await page.locator("#fp-value").blur();
  await page.locator("#fp-font").selectOption("courier");
  await page.locator("#fp-align").selectOption("center");
  await expectAccessible(page, "field properties");

  await page.getByTestId("save-draft").click();
  await expect(page.getByTestId("save-status")).toContainText("Saved");
  const env = (await mockDb(page)).envelopes.find((e) => e.fields.some((f) => f.type === "dropdown"));
  const by = (type) => env.fields.find((f) => f.type === type);
  expect(env.fields.map((f) => f.type).sort()).toEqual(["attachment", "company", "dropdown", "note", "number", "radio_group", "text", "title"]);
  expect(by("text")).toMatchObject({ required: true, label: "reference", tooltip: "Your reference", validation: { kind: "regex", pattern: "[A-Z]{3}-\\d{4}", message: "Like ABC-1234" } });
  expect(by("number").validation).toEqual({ kind: "number", min: "1", max: "99.5" });
  expect(by("dropdown")).toMatchObject({ options: ["Red", "Green", "Blue"], allow_custom: true, required: true });
  expect(by("radio_group").options).toEqual(["Option 1", "Option 2"]);
  expect(by("note").value).toEqual({ text: "Initial each page." });
  expect(by("company")).toMatchObject({ read_only: true, value: { text: "Acme Ltd" }, format: { font_family: "courier", align: "center" } });
  expect(by("attachment").required).toBeUndefined();

  // Reopened from the server, the editor shows them as set.
  await page.reload();
  await expect(page.locator(".os-page.is-loading")).toHaveCount(0);
  await expect(page.locator(".os-field")).toHaveCount(8);
  await pick(page, "text");
  await expect(page.locator("#fp-pattern")).toHaveValue("[A-Z]{3}-\\d{4}");
  await expect(page.locator("#fp-tooltip")).toHaveValue("Your reference");
  await pick(page, "dropdown");
  await expect(page.locator("#fp-options")).toHaveValue("Red\nGreen\nBlue");
  await expect(page.locator("#fp-custom")).toBeChecked();
  // A cleared member is removed on the server, not left behind.
  await page.locator("#fp-custom").uncheck();
  await pick(page, "text");
  await page.locator("#fp-validate").selectOption("");
  await page.getByTestId("save-draft").click();
  await expect(page.getByTestId("save-status")).toContainText("Saved");
  const env2 = (await mockDb(page)).envelopes.find((e) => e.id === env.id);
  expect(env2.fields.find((f) => f.type === "dropdown").allow_custom).toBeUndefined();
  expect(env2.fields.find((f) => f.type === "text").validation).toBeUndefined();
});

// ---- Review, template mode, documents --------------------------------------------------------

test("documents: Next waits for a PDF", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await signIn(page);
  await page.goto(app("#/prepare"));
  await expect(page.getByTestId("wizard-next")).toBeDisabled();
  await page.getByTestId("pdf-input").setInputFiles(pdfFile());
  await expect(page.getByTestId("wizard-next")).toBeEnabled();
});

test("a template says Review and save and is named where it starts", async ({ page }, testInfo) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await signIn(page);
  await page.goto(app("#/templates/new"));
  await expect(page.locator(".os-stepper__btn").nth(3)).toContainText("Review and save");
  await expect(page.locator("#docs-h + p")).toContainText("this template starts with");
  await page.getByLabel("Name this template").fill("Mutual NDA 2027");
  await expect(page.locator(".os-prepare__title")).toHaveText("Mutual NDA 2027");
  await expectAccessible(page, "template documents step");
  await snap(page, testInfo, "prepare-template-start-1440");
  await page.getByTestId("pdf-input").setInputFiles(pdfFile());
  await page.getByTestId("wizard-next").click();
  await page.getByRole("button", { name: "Add role" }).first().click();
  await page.getByTestId("role-name").first().fill("Client");
  await step(page, "Review and save");
  await expect(page.getByRole("heading", { name: "Review and save" })).toBeVisible();
  await expect(page.getByLabel("Template name")).toHaveValue("Mutual NDA 2027");
});

test("review: a signer without fields is a warning with its fix; preview as a recipient; the confirmation follows the order", async ({ page }, testInfo) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await toFields(page, [["Ana Signer", "ana@example.com"], ["Ben Signer", "ben@example.com"]]);
  await add(page, "Signature");
  await step(page, "Review");
  const warn = page.getByTestId("summary-no-fields");
  await expect(warn).toHaveCount(1);
  await expect(warn).toContainText("No fields yet");
  await snap(page, testInfo, "prepare-review-warn-1440");
  await expectAccessible(page, "review with a warning");
  await warn.getByRole("button", { name: "Place fields for Ben Signer" }).click();
  await expect(page.locator('.os-stepper__btn[aria-current="step"]')).toContainText("Fields");
  await expect(page.getByRole("radiogroup", { name: "Placing fields for" }).getByRole("radio", { name: "Ben Signer" })).toHaveAttribute("aria-checked", "true");
  await add(page, "Signature");
  await step(page, "Review");
  await expect(page.getByTestId("summary-no-fields")).toHaveCount(0);

  // Preview as Ana: her field stands out, Ben's fades; ending it shows both alike.
  await page.getByTestId("preview-strip").getByRole("button", { name: "Preview as Ana Signer" }).click();
  await expect(page.getByTestId("preview-as")).toContainText("Previewing as Ana Signer");
  await expect(page.locator(".os-field.is-other")).toHaveCount(1);
  await snap(page, testInfo, "prepare-preview-as-1440");
  await page.getByTestId("preview-as").getByRole("button", { name: "End preview" }).click();
  await expect(page.locator(".os-field.is-other")).toHaveCount(0);
  await expect(page.getByTestId("preview-as")).toBeHidden();

  // In order (the default): only Ana is emailed now, then Ben.
  await step(page, "Review");
  await page.getByRole("button", { name: "Send", exact: true }).click();
  const dlg = page.getByRole("dialog", { name: "Send this envelope?" });
  await expect(dlg).toContainText("Ana Signer will get an email for “Please sign: contract” now");
  await expect(dlg).toContainText("Ana Signer → Ben Signer");
  await expect(dlg).not.toContainText("2 signers will get an email");
  await dlg.getByRole("button", { name: "Cancel" }).click();
});

test("suggested fields left undecided hold Continue and stop Send; their bar goes when the step is left", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await toFields(page);
  await add(page, "Signature");
  await page.getByTestId("detect-fields").click();
  await expect(page.getByTestId("ghost").first()).toBeVisible();
  const bar = page.getByTestId("suggestions");
  await expect(bar).toContainText("suggested fields");
  // Continue is held, and says why when pressed (canvas).
  await page.getByTestId("wizard-next").click({ force: true });
  await expect(page.getByTestId("continue-why")).toHaveText(/Accept or dismiss the \d+ suggested fields first/);
  await expect(page.locator('.os-stepper__btn[aria-current="step"]')).toContainText("Fields");
  await step(page, "Review");
  await expect(bar).toHaveCount(0);
  await page.getByRole("button", { name: "Send", exact: true }).click();
  await expect(page.getByText(/suggested fields are neither accepted nor dismissed/)).toBeVisible();
});

test("the pages stay in view beside the palette, grouped by document, with a band on the canvas", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await signIn(page);
  await page.goto(app("#/prepare"));
  await page.getByTestId("pdf-input").setInputFiles([pdfFile("contract.pdf"), pdfFile("annex.pdf", "Annex")]);
  await expect(page.getByTestId("doc-card")).toHaveCount(2);
  await page.getByTestId("wizard-next").click();
  await page.getByRole("button", { name: "Add recipient" }).first().click();
  await page.getByTestId("recipient-name").fill("Ana");
  await page.getByTestId("recipient-email").fill("ana@example.com");
  await page.getByTestId("wizard-next").click();
  await expect(page.locator(".os-page").first()).not.toHaveClass(/is-loading/);
  const rail = page.getByTestId("thumbs-rail");
  // In the window, not below the fold.
  const box = await rail.boundingBox();
  expect(box.y + 120).toBeLessThan(900);
  await expect(page.getByTestId("thumbs-doc")).toHaveText(["contract.pdf", "annex.pdf"]);
  await expect(page.getByTestId("doc-band")).toHaveCount(2);
});

test("on a phone the editor opens readable, places in view, and has one bottom bar", async ({ page }, testInfo) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await toFields(page);
  // Readable: a 612-point page is drawn at least 1 px a point (fit width was ~0.6).
  const pg = await page.locator(".os-page").first().boundingBox();
  expect(pg.width).toBeGreaterThanOrEqual(600);
  await page.getByTestId("add-field-sheet").click();
  await expect(page.getByTestId("palette-hint")).toBeVisible();
  await add(page, "Signature");
  const field = page.locator(".os-field").first();
  await expect(field).toBeVisible();
  const f = await field.boundingBox();
  const doc = await page.getByTestId("editor-doc").boundingBox();
  expect(f.x).toBeGreaterThanOrEqual(doc.x);
  expect(f.x + f.width).toBeLessThanOrEqual(doc.x + doc.width + 1);
  // One bar: the page indicator and both actions, none on top of another.
  const bar = page.locator(".os-docbar");
  for (const id of ["page-indicator", "add-field-sheet", "props-sheet"]) await expect(bar.getByTestId(id)).toBeVisible();
  const boxes = await Promise.all(["page-indicator", "add-field-sheet", "props-sheet"].map((id) => bar.getByTestId(id).boundingBox()));
  for (let i = 0; i < boxes.length; i++) for (let j = i + 1; j < boxes.length; j++) {
    const a = boxes[i]; const b = boxes[j];
    expect(a.x + a.width <= b.x + 0.5 || b.x + b.width <= a.x + 0.5, `bar items ${i} and ${j} overlap`).toBe(true);
  }
  for (const b of boxes) expect(b.x >= 0 && b.x + b.width <= 390, `bar item in the window: ${JSON.stringify(b)}`).toBe(true);
  // The toolbar's actions stay on its first row on a phone too.
  const r = await onFirstRow(page, page.getByTestId("wizard-next"));
  expect(r.same && r.inside).toBe(true);
  await snap(page, testInfo, "prepare-fields-390");
  await expectAccessible(page, "phone editor");
});


// ---- Recipients ----------------------------------------------------------------------------

for (const [label, vp] of [["1440", { width: 1440, height: 900 }], ["390", { width: 390, height: 844 }]]) {
  test(`recipients at ${label}: the engine's types, options per row, contacts autocomplete`, async ({ page }, testInfo) => {
    await page.setViewportSize(vp);
    await signIn(page);
    await page.goto(app("#/prepare"));
    await page.getByTestId("pdf-input").setInputFiles(pdfFile());
    await page.getByTestId("wizard-next").click();
    const addRow = async (n, name, email, type) => {
      await page.getByRole("button", { name: "Add recipient" }).first().click();
      const row = page.locator(".os-rcpt").nth(n);
      await row.getByTestId("recipient-name").fill(name);
      await row.getByTestId("recipient-email").fill(email);
      await row.getByTestId("recipient-email").blur();
      if (type) await row.getByTestId("recipient-type").selectOption(type);
      return page.locator(".os-rcpt").nth(n);
    };
    const ana = await addRow(0, "Ana Signer", "ana@example.com");
    // Every ready type is offered (in-person where staff can host it: the mock can).
    expect(await ana.getByTestId("recipient-type").locator("option").evaluateAll((os) => os.map((o) => o.value))).toEqual(["signer", "in_person_signer", "approver", "viewer", "cc"]);
    await addRow(1, "Ben Approver", "ben@example.com", "approver");
    await addRow(2, "Vic Viewer", "vic@example.com", "viewer");
    // Contacts: typing part of a name offers the people sent to before; choosing one fills the email.
    await page.getByRole("button", { name: "Add recipient" }).first().click();
    const jo = page.locator(".os-rcpt").nth(3);
    await jo.getByTestId("recipient-name").fill("Jord");
    await expect(page.locator("#rc-names option[value='Jordan Rivera']")).toHaveCount(1);
    await jo.getByTestId("recipient-name").fill("Jordan Rivera");
    await jo.getByTestId("recipient-name").blur();
    await expect(jo.getByTestId("recipient-email")).toHaveValue("jordan@example.com");
    // Ana's options: a labelled access code and the emailed code.
    const anaRow = page.locator(".os-rcpt").first();
    await expect(anaRow.getByTestId("recipient-name")).toHaveValue("Ana Signer");
    await anaRow.getByTestId("recipient-more").locator("summary").click();
    await anaRow.getByLabel("Access code").fill("4321");
    await snap(page, testInfo, `prepare-recipients-${label}`);
    await expectAccessible(page, `recipients at ${label}`);
    if (label === "1440") {
      // One line a recipient: name and email side by side.
      const n = await anaRow.getByTestId("recipient-name").boundingBox();
      const e = await anaRow.getByTestId("recipient-email").boundingBox();
      expect(Math.abs(n.y - e.y)).toBeLessThan(2);
    }
    await page.getByTestId("wizard-next").click();
    // Only those who sign take fields (on a phone the palette is a sheet).
    if (label === "390") await page.getByTestId("add-field-sheet").click();
    await expect(page.getByRole("radiogroup", { name: "Placing fields for" }).getByRole("radio")).toHaveCount(2);
    await page.getByTestId("save-draft").click();
    await expect(page.getByTestId("save-status")).toContainText("Saved");
    const env = (await mockDb(page)).envelopes.find((x) => x.recipients.some((r) => r.name === "Vic Viewer"));
    expect(env.recipients.map((r) => [r.name, r.type])).toEqual([["Ana Signer", "signer"], ["Ben Approver", "approver"], ["Vic Viewer", "viewer"], ["Jordan Rivera", "signer"]]);
    expect(env.recipients[0].auth).toEqual(["access_code"]);
    expect(env.recipients[0].access_code).toBe("4321");
  });
}

// UX-11: a template keeps every field setting the panel offers (templatesync.js), so the
// panel offers them all; saved, reopened, they are as set, and a cleared one is cleared.
test("a template's field panel offers every setting, and the template keeps them", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await signIn(page);
  await page.goto(app("#/templates/new"));
  await page.getByTestId("pdf-input").setInputFiles(pdfFile());
  await expect(page.getByTestId("doc-card")).toHaveCount(1);
  await page.getByTestId("wizard-next").click();
  await page.getByRole("button", { name: "Add role" }).first().click();
  await page.getByTestId("role-name").first().fill("Client");
  await page.getByTestId("wizard-next").click();
  await expect(page.locator(".os-page.is-loading")).toHaveCount(0);
  await page.locator(".os-palette").getByRole("button", { name: "Add Text field" }).press("Enter");
  for (const sec of ["props-general", "props-format", "props-validation"]) await expect(page.getByTestId(sec)).toBeVisible();
  const fill = async (id, v) => { await page.locator(id).fill(v); await page.locator(id).dispatchEvent("change"); };
  await fill("#fp-tooltip", "Your purchase order");
  await fill("#fp-placeholder", "PO-0000");
  await page.locator("#fp-readonly").check();
  await fill("#fp-value", "PO-1234");
  await fill("#fp-label", "po");
  await page.locator("#fp-font").selectOption("courier");
  await page.locator("#fp-align").selectOption("right");
  await page.locator("#fp-mask").check();
  await page.locator("#fp-validate").selectOption("length");
  await fill("#fp-maxlen", "12");
  await page.locator(".os-palette").getByRole("button", { name: "Add Dropdown field" }).press("Enter");
  await expect(page.getByTestId("props-options")).toBeVisible();
  await fill("#fp-options", "Red\nGreen");
  await page.locator("#fp-custom").check();
  await page.locator(".os-stepper__btn", { hasText: "Review" }).click();
  await page.getByLabel("Template name").fill("Order form");
  await page.getByRole("button", { name: "Save template" }).click();
  await expect(page.locator(".os-toast").last()).toContainText("Template saved.");
  const saved = async () => (await mockDb(page)).templates.find((x) => x.name === "Order form");
  let tp = await saved();
  const text = () => tp.fields.find((f) => f.type === "text");
  expect(text()).toMatchObject({ label: "po", tooltip: "Your purchase order", placeholder: "PO-0000", read_only: true, value: { text: "PO-1234" }, validation: { kind: "length", max: 12 }, format: { font_family: "courier", align: "right", mask: true } });
  expect(tp.fields.find((f) => f.type === "dropdown")).toMatchObject({ options: ["Red", "Green"], allow_custom: true });

  // Reopened, the panel shows what was saved; a setting cleared is cleared on the server.
  await page.getByRole("button", { name: "Actions for Order form" }).click();
  await page.getByRole("menuitem", { name: "Edit", exact: true }).click();
  await expect(page.locator(".os-field")).toHaveCount(2);
  await page.locator(".os-stepper__btn", { hasText: "Fields" }).click();
  await expect(page.locator(".os-page.is-loading")).toHaveCount(0);
  await page.locator('.os-field[data-field="text"]').click();
  await expect(page.locator("#fp-tooltip")).toHaveValue("Your purchase order");
  await expect(page.locator("#fp-placeholder")).toHaveValue("PO-0000");
  await expect(page.locator("#fp-readonly")).toBeChecked();
  await expect(page.locator("#fp-value")).toHaveValue("PO-1234");
  await expect(page.locator("#fp-font")).toHaveValue("courier");
  await expect(page.locator("#fp-validate")).toHaveValue("length");
  await expect(page.locator("#fp-maxlen")).toHaveValue("12");
  await fill("#fp-tooltip", "");
  await page.locator("#fp-readonly").uncheck();
  await page.locator('.os-field[data-field="dropdown"]').click();
  await expect(page.locator("#fp-options")).toHaveValue("Red\nGreen");
  await expect(page.locator("#fp-custom")).toBeChecked();
  await page.locator(".os-stepper__btn", { hasText: "Review" }).click();
  await page.getByRole("button", { name: "Save template" }).click();
  await expect(page).toHaveURL(/#\/templates$/);
  tp = await saved();
  expect(text().tooltip).toBeUndefined();
  expect(text().read_only).toBeUndefined();
  expect(text()).toMatchObject({ placeholder: "PO-0000", value: { text: "PO-1234" }, validation: { kind: "length", max: 12 } });
});
