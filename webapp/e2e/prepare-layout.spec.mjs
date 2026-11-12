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
  const back = await page.locator(".os-prepare__bar > a").first().boundingBox();
  const b = await btn.boundingBox();
  const mid = (r) => r.y + r.height / 2;
  // Inside the window too: a bar wider than the window (a nowrap bar that could not
  // shrink) pushes the button off screen while it still "fits" the bar.
  const vw = page.viewportSize().width;
  const scrolls = await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth);
  return { same: Math.abs(mid(b) - mid(back)) <= 2, barHeight: Math.round(bar.height), inside: b.x + b.width <= Math.min(bar.x + bar.width, vw) + 0.5 && !scrolls };
}

for (const [width, wide] of [1366, 1440, 1536].flatMap((w) => [[w, false], [w, true]])) {
  test(`at ${width} px${wide ? " in the system font" : ""} Back and Next, then Send, stay on the toolbar's first row`, async ({ page }, testInfo) => {
    await page.setViewportSize({ width, height: 900 });
    await toFields(page, undefined, { wide });
    // The fullest bar: a saved draft (its subject as the title, "Saved at …"), on the
    // fields step with its document tools.
    await page.locator(".os-palette").getByRole("button", { name: "Add Signature field" }).press("Enter");
    await page.getByTestId("save-draft").click();
    await expect(page.getByTestId("save-status")).toContainText("Saved");
    await expect(page.locator(".os-prepare__title")).toHaveText("Please sign: contract");
    for (const [name, btn] of [["fields next", page.getByTestId("wizard-next")], ["fields back", page.getByTestId("wizard-back")], ["save", page.getByTestId("save-draft")]]) {
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
  test(`at ${width} px in the system font a template's toolbar keeps Back, Next and Save template on its first row`, async ({ page }, testInfo) => {
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
    for (const btn of [page.getByTestId("wizard-next"), page.getByTestId("wizard-back")]) {
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
  await page.mouse.click(box.x + 120 * scale, box.y + 460 * scale);
  await page.mouse.click(box.x + 420 * scale, box.y + 460 * scale);
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
  // The palette is grouped, and has every kind the ceremony fills.
  await expect(page.locator(".os-palette__group")).toHaveCount(3);
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

