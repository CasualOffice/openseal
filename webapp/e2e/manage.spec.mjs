// The manage screens after the WEB-06 audit (docs/47 §UX audit, findings G-, A-, E-, T-,
// AD-, RP-): Home, Agreements, envelope details, Templates and use, Admin, Reports.
// Mock mode (seeded data); axe on each screen; no horizontal scroll at 320 px;
// screenshots for people at 1440, 1920, 390, 320 and 200 % zoom under
// target/e2e-screens/.
import { test, expect } from "@playwright/test";
import { signIn, app, snap, expectAccessible, REAL } from "./helpers.mjs";

test.beforeEach(({}, testInfo) => test.skip(REAL || testInfo.project.name !== "chromium", "mock data; one browser"));

const subjectId = (page, subject) => page.evaluate((s) => JSON.parse(sessionStorage.getItem("openseal.mock.v1")).envelopes.find((e) => e.subject === s).id, subject);
const templateId = (page, name) => page.evaluate((n) => JSON.parse(sessionStorage.getItem("openseal.mock.v1")).templates.find((x) => x.name === n).id, name);

/// The page scrolls sideways by no more than a pixel.
async function noSideScroll(page, what) {
  const { sw, cw } = await page.evaluate(() => ({ sw: document.documentElement.scrollWidth, cw: document.documentElement.clientWidth }));
  expect(sw, `${what}: page ${sw}px wide in a ${cw}px viewport`).toBeLessThanOrEqual(cw + 1);
}

test("home: one way in to a new envelope, recent templates, words for what needs doing", async ({ page }) => {
  await signIn(page, "home");
  await expect(page.getByTestId("counter-action")).toContainText("Declined or expired");
  await expect(page.locator("main").getByRole("button", { name: "New envelope" })).toHaveCount(0);
  await expect(page.locator("main").getByRole("button", { name: "Use a template" })).toHaveCount(0);
  const tpl = page.getByTestId("home-templates");
  await expect(tpl.getByRole("link", { name: "Use Mutual NDA" })).toBeVisible();
  await expect(page.locator(".os-recent__item").first()).toContainText("Created");
  await expectAccessible(page, "home");
});

test("agreements: status line, sort, filters, and a draft opens in the editor", async ({ page }) => {
  await signIn(page);
  const offer = page.locator("tbody tr", { hasText: "Offer letter — Jordan Rivera" });
  await expect(offer.locator(".os-row__line")).toHaveText("Waiting for Jordan Rivera");
  await expect(page.locator("tbody tr", { hasText: "Board consent" }).locator(".os-row__line")).toHaveText("Declined by Morgan Diaz");

  await page.getByRole("button", { name: "Subject" }).click();
  await expect(page.getByRole("columnheader", { name: "Subject" })).toHaveAttribute("aria-sort", "ascending");
  await expect(page.locator("tbody tr").first()).toContainText("Board consent");
  await page.getByRole("button", { name: "Subject" }).click();
  await expect(page.locator("tbody tr").first()).toContainText("Vendor services");

  await page.getByLabel("Last change").selectOption("custom");
  await page.getByLabel("From", { exact: true }).fill("2001-01-01");
  await page.getByLabel("To", { exact: true }).fill("2001-01-02");
  await expect(page.getByTestId("empty-filters")).toBeVisible();
  await page.getByTestId("empty-filters").getByRole("button", { name: "Clear filters" }).click();
  await page.getByLabel("Sender").selectOption("me");
  await expect(page.locator("tbody tr")).toHaveCount(6);
  await expectAccessible(page, "agreements");

  await page.getByRole("link", { name: "Lease renewal 2027" }).click();
  await expect(page).toHaveURL(/#\/prepare\//);
});

test("agreements row menu: copy, save as template, history, delete", async ({ page }) => {
  await signIn(page);
  const open = async (subject) => {
    await page.getByRole("button", { name: `Actions for ${subject}` }).click();
    return page.getByRole("menu", { name: `Actions for ${subject}` });
  };
  let menu = await open("Offer letter — Jordan Rivera");
  for (const item of ["Open and history", "Correct", "Resend", "Download current PDF", "Copy", "Save as template", "History", "Void"]) {
    await expect(menu.getByRole("menuitem", { name: item, exact: true })).toBeVisible();
  }
  await menu.getByRole("menuitem", { name: "History", exact: true }).click();
  const history = page.getByRole("dialog", { name: "History: Offer letter — Jordan Rivera" });
  await expect(history.getByRole("cell", { name: "You (sender)" }).first()).toBeVisible();
  await history.getByRole("button", { name: "Close" }).first().click();

  menu = await open("Mutual NDA — Acme and Globex");
  await menu.getByRole("menuitem", { name: "Save as template" }).click();
  await expect(page.locator(".os-toast")).toContainText("Saved as template Mutual NDA — Acme and Globex");

  menu = await open("Consulting SOW — Q1");
  await menu.getByRole("menuitem", { name: "Delete" }).click();
  await page.getByRole("dialog", { name: "Delete this envelope?" }).getByRole("button", { name: "Delete" }).click();
  await expect(page.getByRole("link", { name: "Consulting SOW — Q1" })).toHaveCount(0);

  menu = await open("Mutual NDA — Acme and Globex");
  await expect(menu.getByRole("menuitem", { name: "Delete" })).toHaveCount(0); // a completed agreement stays
  await menu.getByRole("menuitem", { name: "Copy" }).click();
  await expect(page).toHaveURL(/#\/prepare\//);
  const copies = await page.evaluate(() => JSON.parse(sessionStorage.getItem("openseal.mock.v1")).envelopes.filter((e) => e.subject === "Mutual NDA — Acme and Globex (copy)"));
  expect(copies).toHaveLength(1);
  expect(copies[0].status).toBe("draft");
  expect(copies[0].fields.length).toBe(4);
});

test("envelope: correct a recipient who has not signed, resend one, download in progress", async ({ page }, testInfo) => {
  await signIn(page);
  await page.goto(app(`#/envelopes/${await subjectId(page, "Offer letter — Jordan Rivera")}`));
  await expect(page.getByTestId("status-line")).toHaveText("Waiting for Jordan Rivera");
  // CC rows say when the copy goes, not Sent/Opened/Signed (E-04).
  const cc = page.getByTestId("recipient-row").filter({ hasText: "People Ops" });
  await expect(cc).toContainText("Gets a copy when everyone has signed");
  await expect(cc).not.toContainText("Opened");

  await page.getByRole("button", { name: "Resend to Jordan Rivera" }).click();
  await expect(page.locator(".os-toast").last()).toContainText("Resent to Jordan Rivera.");

  const [dl] = await Promise.all([page.waitForEvent("download"), page.getByRole("button", { name: "Download current PDF" }).click()]);
  expect(dl.suggestedFilename()).toMatch(/-current\.pdf$/);

  await page.getByTestId("envelope-correct").click();
  const panel = page.getByRole("dialog", { name: "Correct envelope" });
  await expect(panel).toBeVisible();
  await expect(page.locator("dialog[open]")).toHaveCount(0); // a side panel, not a modal
  await panel.getByLabel("Email").first().fill("not-an-email");
  await panel.getByTestId("correct-save").click();
  await expect(panel.getByText("Enter a valid email.")).toBeVisible();
  await panel.getByLabel("Name").first().fill("Jordan A. Rivera");
  await panel.getByLabel("Email").first().fill("jordan.rivera@example.com");
  await expectAccessible(page, "correct panel");
  await snap(page, testInfo, "manage-correct");
  await panel.getByTestId("correct-save").click();
  await expect(page.locator(".os-toast").last()).toContainText("Envelope corrected.");
  await expect(page.getByTestId("recipient-row").first()).toContainText("Jordan A. Rivera");
  await expect(page.getByTestId("recipient-row").first()).toContainText("jordan.rivera@example.com");
  await expect(page.locator(".os-audit")).toContainText("Envelope corrected");
});

test("envelope: every audit event names who did it, and its dates agree with the header", async ({ page }) => {
  await signIn(page);
  await page.goto(app(`#/envelopes/${await subjectId(page, "Mutual NDA — Acme and Globex")}`));
  const rows = page.locator(".os-audit tbody tr");
  await expect(rows).toHaveCount(8);
  for (const by of await rows.locator("td:nth-child(3)").allTextContents()) expect(by.trim()).not.toBe("");
  await expect(rows.filter({ hasText: "Recipient finished" }).first()).toContainText("Avery Chen");
  await expect(rows.filter({ hasText: "Seal applied" })).toContainText("OpenSeal (system)");
  const sentHeader = await page.locator(".os-meta dt", { hasText: "Sent" }).locator("xpath=following-sibling::dd[1]").textContent();
  await expect(rows.filter({ hasText: "Envelope sent" }).locator("time")).toHaveText(sentHeader);
  // Opened has a time for those who signed.
  await expect(page.getByTestId("recipient-row").first().locator("li", { hasText: "Opened" }).locator("time")).toBeVisible();
});

test("templates: search, owner and last use, duplicate, edit details, delete", async ({ page }) => {
  await signIn(page);
  await page.goto(app("#/templates"));
  const nda = page.locator("tbody tr", { hasText: "Mutual NDA" });
  await expect(nda.locator("td").nth(1)).toHaveText("You");
  await expect(page.locator("tbody tr", { hasText: "Contractor onboarding" })).toContainText("Never");
  await page.getByLabel("Search templates").fill("contract");
  await expect(page.locator("tbody tr")).toHaveCount(1);
  await page.getByLabel("Search templates").fill("zzz");
  await expect(page.getByTestId("empty-template-search")).toBeVisible();
  await page.getByLabel("Search templates").fill("");

  await page.getByRole("button", { name: "Actions for Mutual NDA" }).click();
  await page.getByRole("menuitem", { name: "Duplicate" }).click();
  await expect(page.getByRole("link", { name: "Mutual NDA (copy)" })).toBeVisible();

  await page.getByRole("button", { name: "Actions for Mutual NDA (copy)" }).click();
  await page.getByRole("menuitem", { name: "Edit details" }).click();
  const panel = page.getByRole("dialog", { name: "Edit template" });
  await expect(page.locator("dialog[open]")).toHaveCount(0);
  await panel.getByLabel("Email subject").fill("NDA for the Q1 partners");
  await expectAccessible(page, "template edit panel");
  await panel.getByRole("button", { name: "Save" }).click();
  await expect(page.locator("tbody tr", { hasText: "Mutual NDA (copy)" })).toContainText("NDA for the Q1 partners");

  await page.getByRole("button", { name: "Actions for Mutual NDA (copy)" }).click();
  await page.getByRole("menuitem", { name: "Delete" }).click();
  await page.getByRole("dialog", { name: "Delete this template?" }).getByRole("button", { name: "Delete" }).click();
  await expect(page.getByRole("link", { name: "Mutual NDA (copy)" })).toHaveCount(0);
  await expectAccessible(page, "templates");
});

test("use a template: the document beside a panel holding the roles and Send", async ({ page }) => {
  await signIn(page);
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto(app(`#/templates/${await templateId(page, "Mutual NDA")}`));
  const panel = page.locator(".os-usepanel");
  const doc = page.locator(".os-usedoc");
  await expect(panel.getByTestId("use-send")).toBeVisible();
  const [p, d] = [await panel.boundingBox(), await doc.boundingBox()];
  expect(d.x + d.width).toBeLessThanOrEqual(p.x);
  await page.mouse.wheel(0, 600);
  await expect(panel.getByTestId("use-send")).toBeInViewport();
  await expectAccessible(page, "use template");
});

test("no horizontal scroll at 320 px on the manage screens", async ({ page }, testInfo) => {
  await signIn(page);
  const env = await subjectId(page, "Offer letter — Jordan Rivera");
  const tpl = await templateId(page, "Mutual NDA");
  await page.setViewportSize({ width: 320, height: 640 });
  for (const [name, hash] of [["home", "#/home"], ["agreements", "#/agreements"], ["envelope", `#/envelopes/${env}`], ["templates", "#/templates"], ["use", `#/templates/${tpl}`], ["admin", "#/admin"], ["admin-api", "#/admin?tab=api"], ["reports", "#/reports"]]) {
    await page.goto(app(hash));
    await expect(page.locator("main h1")).toBeVisible();
    await page.waitForTimeout(400);
    await noSideScroll(page, name);
    await snap(page, testInfo, `manage-320-${name}`);
  }
});

test("screenshots at 1440, 1920, 390 and 200 % zoom", async ({ page, browser }, testInfo) => {
  await signIn(page);
  const env = await subjectId(page, "Offer letter — Jordan Rivera");
  const tpl = await templateId(page, "Mutual NDA");
  const routes = [["home", "#/home"], ["agreements", "#/agreements"], ["envelope", `#/envelopes/${env}`], ["templates", "#/templates"], ["use", `#/templates/${tpl}`], ["admin", "#/admin"], ["reports", "#/reports"]];
  for (const [w, hgt] of [[1440, 900], [1920, 1080], [390, 844]]) {
    await page.setViewportSize({ width: w, height: hgt });
    for (const [name, hash] of routes) {
      await page.goto(app(hash));
      await expect(page.locator("main h1")).toBeVisible();
      await page.waitForTimeout(400);
      await noSideScroll(page, `${name} at ${w}`);
      await snap(page, testInfo, `manage-${w}-${name}`);
    }
  }
  // 200 % zoom of a 1440 window: a 720 CSS px viewport at device scale 2.
  const state = await page.context().storageState();
  const session = await page.evaluate(() => JSON.stringify(Object.entries(sessionStorage)));
  const zoomed = await browser.newContext({ viewport: { width: 720, height: 450 }, deviceScaleFactor: 2, storageState: state });
  const z = await zoomed.newPage();
  await z.addInitScript((s) => { for (const [k, v] of JSON.parse(s)) sessionStorage.setItem(k, v); }, session);
  for (const [name, hash] of routes) {
    await z.goto(app(hash));
    await expect(z.locator("main h1")).toBeVisible();
    await z.waitForTimeout(400);
    await noSideScroll(z, `${name} at 200 %`);
    await snap(z, testInfo, `manage-zoom200-${name}`);
  }
  await zoomed.close();
});
