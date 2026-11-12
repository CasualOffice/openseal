// The manage screens after the WEB-06 audit (docs/47 §UX audit, findings G-, A-, E-, T-,
// AD-, RP-): Home, Agreements, envelope details, Templates and use, Admin, Reports.
// Mock mode (seeded data); axe on each screen; no horizontal scroll at 320 px;
// screenshots for people at 1440, 1920, 390, 320 and 200 % zoom under
// target/e2e-screens/.
import fs from "node:fs";
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
  // UX-07: each recent envelope says who it went to; Expiring soon opens its own view.
  await expect(page.getByTestId("recent-row").first()).toContainText("To: ");
  await expect(page.getByTestId("counter-expiring")).toHaveAttribute("href", "#/agreements?folder=expiring");
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
  for (const item of ["Open", "Correct", "Resend", "Download current PDF", "Copy", "Save as template", "History", "Void"]) {
    await expect(menu.getByRole("menuitem", { name: item, exact: true })).toBeVisible();
  }
  await menu.getByRole("menuitem", { name: "History", exact: true }).click();
  const history = page.getByRole("dialog", { name: "History: Offer letter — Jordan Rivera" });
  await expect(history.getByText(/^You \(sender\) ·/).first()).toBeVisible();
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

  // UX-07: one primary (Correct) and one secondary (Resend); the rest under More.
  await page.getByTestId("envelope-more").click();
  const [dl] = await Promise.all([page.waitForEvent("download"), page.getByRole("menuitem", { name: "Download current PDF" }).click()]);
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
  await expect(rows).toHaveCount(18);
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
  await expect(page.getByRole("link", { name: "Copy of Mutual NDA" })).toBeVisible();

  await page.getByRole("button", { name: "Actions for Copy of Mutual NDA" }).click();
  await page.getByRole("menuitem", { name: "Edit details" }).click();
  const panel = page.getByRole("dialog", { name: "Edit template" });
  await expect(page.locator("dialog[open]")).toHaveCount(0);
  await panel.getByLabel("Email subject").fill("NDA for the Q1 partners");
  await expectAccessible(page, "template edit panel");
  await panel.getByRole("button", { name: "Save" }).click();
  await expect(page.locator("tbody tr", { hasText: "Copy of Mutual NDA" })).toContainText("NDA for the Q1 partners");

  await page.getByRole("button", { name: "Actions for Copy of Mutual NDA" }).click();
  await page.getByRole("menuitem", { name: "Delete" }).click();
  await page.getByRole("dialog", { name: "Delete this template?" }).getByRole("button", { name: "Delete" }).click();
  await expect(page.getByRole("link", { name: "Copy of Mutual NDA" })).toHaveCount(0);
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

test("admin: invite by email, edit a user's profile and disable them, settings and branding in side panels", async ({ page }) => {
  await signIn(page);
  await page.goto(app("#/admin"));
  await page.getByRole("button", { name: "Invite user" }).click();
  const inv = page.getByRole("dialog", { name: "Invite user" });
  await expect(page.locator("dialog[open]")).toHaveCount(0);
  await inv.getByRole("button", { name: "Invite user" }).click();
  await expect(inv.getByText("Enter a valid email.")).toBeVisible();
  await inv.getByLabel("Email").fill("lee@example.com");
  // WEB-10: the server needs a name (UserCreate), so the form asks for one first.
  await inv.getByRole("button", { name: "Invite user" }).click();
  await expect(inv.getByLabel("Name", { exact: true })).toHaveAttribute("aria-invalid", "true");
  await inv.getByLabel("Name", { exact: true }).fill("Lee Park");
  await inv.getByRole("button", { name: "Invite user" }).click();
  await expect(page.locator(".os-toast").last()).toContainText("Invitation sent to lee@example.com.");
  await expect(page.getByRole("row", { name: /lee@example.com/ })).toContainText("Invited");

  await page.getByRole("button", { name: "Edit Robin Sender" }).click();
  const ed = page.getByRole("dialog", { name: "Edit user" });
  await ed.getByLabel("Permission profile").selectOption("viewer");
  await ed.getByText("Disable sign-in", { exact: true }).click();
  await expect(ed.getByRole("switch", { name: "Disable sign-in" })).toBeChecked();
  await expectAccessible(page, "edit user panel");
  await ed.getByRole("button", { name: "Save" }).click();
  const robin = page.getByRole("row", { name: /Robin Sender/ });
  await expect(robin).toContainText("Viewer");
  await expect(robin).toContainText("Disabled");
  await page.getByRole("button", { name: "Edit Demo Admin" }).click();
  await expect(page.getByRole("dialog", { name: "Edit user" }).getByRole("switch", { name: "Disable sign-in" })).toBeDisabled();
  await page.keyboard.press("Escape");

  await page.getByRole("tab", { name: "Account" }).click();
  await page.getByTestId("account-branding").getByRole("button", { name: "Edit branding" }).click();
  const br = page.getByRole("dialog", { name: "Branding" });
  await br.getByLabel("Accent colour").fill("red");
  await br.getByRole("button", { name: "Save" }).click();
  await expect(br.getByText("Enter a colour as # and six hex digits.")).toBeVisible();
  await br.getByLabel("Accent colour").fill("#0E7490");
  await br.getByLabel("Name shown to recipients").fill("Acme Legal");
  await br.getByRole("button", { name: "Save" }).click();
  await expect(page.getByTestId("account-branding")).toContainText("Acme Legal");
  await expect(page.getByTestId("account-branding")).toContainText("#0e7490");
  await page.getByTestId("account-settings").getByRole("button", { name: "Edit settings" }).click();
  const st = page.getByRole("dialog", { name: "Settings" });
  // The API has no rename (AccountPatch is settings only): the name is shown, not a field.
  await expect(st.getByTestId("account-name")).toHaveText("Demo account");
  await expect(st.getByRole("textbox", { name: "Account name" })).toHaveCount(0);
  await st.getByLabel("Envelopes expire after (days)").fill("30");
  await st.getByRole("button", { name: "Save" }).click();
  await expect(page.getByTestId("account-settings")).toContainText("30");
  await expectAccessible(page, "admin account");
});

test("an invited member sets a password from the emailed link, once", async ({ page }) => {
  await signIn(page);
  await page.goto(app("#/admin"));
  await page.getByRole("button", { name: "Invite user" }).click();
  const inv = page.getByRole("dialog", { name: "Invite user" });
  await inv.getByLabel("Email").fill("kai@example.com");
  await inv.getByLabel("Name", { exact: true }).fill("Kai Moreno");
  await inv.getByRole("button", { name: "Invite user" }).click();
  await page.getByRole("button", { name: "Resend invitation to kai@example.com" }).click();
  await expect(page.locator(".os-toast").last()).toContainText("Invitation sent again to kai@example.com.");
  const token = await page.evaluate(() => Object.keys(JSON.parse(sessionStorage.getItem("openseal.mock.v1")).invites)[0]);
  await page.getByRole("button", { name: "Account" }).click();
  await page.getByRole("menuitem", { name: "Sign out" }).click();
  await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();

  await page.goto(app(`#/accept-invite?token=${token}`));
  await expect(page.getByRole("heading", { name: "Set up your account" })).toBeVisible();
  await expect(page).not.toHaveURL(/token=/);
  await page.getByLabel("Password", { exact: true }).fill("short");
  await page.getByRole("button", { name: "Set password" }).click();
  await expect(page.getByRole("alert")).toContainText("At least 12 characters.");
  await page.getByLabel("Password", { exact: true }).fill("a-long-enough-password");
  await page.getByLabel("Password again").fill("a-long-enough-password");
  await expectAccessible(page, "accept invite");
  await page.getByRole("button", { name: "Set password" }).click();
  await expect(page.getByTestId("invite-done")).toBeVisible();

  await page.goto(app(`#/accept-invite?token=${token}`));
  await page.getByLabel("Password", { exact: true }).fill("a-long-enough-password");
  await page.getByLabel("Password again").fill("a-long-enough-password");
  await page.getByRole("button", { name: "Set password" }).click();
  await expect(page.getByRole("alert")).toContainText("expired or was already used");
});

test("reports: a period, a colour per status, no stray border", async ({ page }) => {
  await signIn(page);
  await page.goto(app("#/reports"));
  await expect(page.getByTestId("report-note")).toContainText("6 envelopes");
  const colours = await page.locator(".os-bars tbody .os-bar").evaluateAll((els) => els.map((e) => getComputedStyle(e).backgroundColor));
  expect(new Set(colours).size).toBe(colours.length);
  const last = page.locator(".os-bars tbody tr:last-child");
  for (const cell of [last.locator("th"), last.locator("td")]) expect(await cell.evaluate((e) => getComputedStyle(e).borderBottomWidth)).toBe("0px");
  await page.getByLabel("Period").selectOption("7");
  await expect(page.getByTestId("report-note")).toContainText("6 envelopes");
  await page.evaluate(() => { const k = "openseal.mock.v1"; const db = JSON.parse(sessionStorage.getItem(k)); db.envelopes[0].created_at = "2020-01-01T00:00:00.000Z"; sessionStorage.setItem(k, JSON.stringify(db)); });
  await page.reload();
  await page.getByLabel("Period").selectOption("30");
  await expect(page.getByTestId("report-note")).toContainText("5 envelopes");
  await expectAccessible(page, "reports");
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

// ---- UX-07: manage screens, DocuSign-level hierarchy, density and evidence ----------

// The four acceptance checks of UX-07, one test each so each is seen red on its own.
const declined = async (page) => {
  await signIn(page);
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto(app(`#/envelopes/${await subjectId(page, "Board consent — November")}`));
  await expect(page.getByTestId("status-line")).toBeVisible();
  return page.locator(".os-page-head");
};

test("UX-07 acceptance: Download is shown on a declined envelope", async ({ page }) => {
  const head = await declined(page);
  const [dl] = await Promise.all([page.waitForEvent("download"), head.getByRole("button", { name: "Download", exact: true }).click()]);
  expect(dl.suggestedFilename()).toMatch(/-declined\.pdf$/);
});

test("UX-07 acceptance: a declined envelope has a primary action, Copy and resend, and says why it ended", async ({ page }) => {
  const head = await declined(page);
  const primary = head.locator(".os-btn--primary");
  await expect(primary).toHaveCount(1);
  await expect(primary).toHaveText("Copy and resend");
  await expect(page.getByTestId("decline-callout")).toContainText("Wrong meeting date");
  await expectAccessible(page, "declined envelope");
  await primary.click();
  await expect(page).toHaveURL(/#\/prepare\//);
});

test("UX-07 acceptance: the search survives a reload", async ({ page }) => {
  await signIn(page);
  await page.locator("#top-search").fill("offer");
  await expect(page).toHaveURL(/[?&]q=offer/);
  await expect(page.locator("tbody tr")).toHaveCount(1);
  await page.reload();
  await expect(page.locator("tbody tr")).toHaveCount(1);
  await expect(page.locator("#top-search")).toHaveValue("offer");
  await expect(page.getByTestId("agreements-sub")).toContainText("“offer”");
  // A folder link keeps the search.
  await expect(page.locator('.os-rail__link[data-folder="waiting"]')).toHaveAttribute("href", "#/agreements?folder=waiting&q=offer");
});

test("UX-07 acceptance: rows are 64 px or less at 1440", async ({ page }, testInfo) => {
  await signIn(page);
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto(app("#/agreements"));
  await expect(page.locator("tbody tr").first()).toBeVisible();
  // Let the details fill every row (recipients, status line, dates) before measuring.
  await expect(page.locator("tbody tr .os-row__sub").filter({ hasText: /\S/ })).toHaveCount(await page.locator("tbody tr").count());
  const heights = await page.locator("tbody tr").evaluateAll((trs) => trs.map((tr) => tr.getBoundingClientRect().height));
  for (const hgt of heights) expect(hgt).toBeLessThanOrEqual(64);
  // No date spills out of its column.
  for (const over of await page.locator("tbody td.os-col-date").evaluateAll((tds) => tds.map((td) => td.scrollWidth - td.clientWidth))) expect(over).toBeLessThanOrEqual(0);
  await snap(page, testInfo, "ux07-agreements-1440");
});

test("UX-07 agreements: one way in, grouped row menu, one void dialog, bulk bar with export and delete", async ({ page }) => {
  await signIn(page);
  await page.setViewportSize({ width: 1440, height: 900 });
  await expect(page.locator("main").getByRole("button", { name: "New envelope" })).toHaveCount(0);
  // Every row is mine: no Sender column.
  await expect(page.getByRole("columnheader", { name: "Sender" })).toHaveCount(0);

  await page.getByRole("button", { name: "Actions for Offer letter — Jordan Rivera" }).click();
  const menu = page.getByRole("menu", { name: "Actions for Offer letter — Jordan Rivera" });
  await expect(menu.getByRole("separator")).toHaveCount(3);
  const labels = await menu.locator('[role="menuitem"], [role="separator"]').evaluateAll((els) => els.map((e) => e.getAttribute("role") === "separator" ? "|" : e.textContent));
  expect(labels.at(-1)).toBe("Void");
  await menu.getByRole("menuitem", { name: "Void" }).click();
  const dlg = page.getByRole("dialog", { name: "Void this envelope?" });
  await expect(dlg.getByTestId("dialog-consequence")).toContainText("cannot be undone");
  await expect(dlg.locator(".os-btn--danger-fill")).toHaveText("Void");
  await page.keyboard.press("Escape");

  // A declined envelope's menu: Copy and resend and Download, Delete last.
  await page.getByRole("button", { name: "Actions for Board consent — November" }).click();
  const dmenu = page.getByRole("menu", { name: "Actions for Board consent — November" });
  await expect(dmenu.getByRole("menuitem", { name: "Copy and resend" })).toBeVisible();
  await expect(dmenu.getByRole("menuitem", { name: "Download", exact: true })).toBeVisible();
  await page.keyboard.press("Escape");

  // Bulk: two waiting envelopes; one dialog for both, with the count.
  await page.getByRole("checkbox", { name: "Select Offer letter — Jordan Rivera" }).check();
  await page.getByRole("checkbox", { name: "Select Vendor services agreement" }).check();
  const bar = page.getByTestId("bulk-bar");
  await expect(bar).toBeVisible();
  expect(await bar.evaluate((e) => getComputedStyle(e).position)).toBe("sticky");
  const [csv] = await Promise.all([page.waitForEvent("download"), bar.getByTestId("bulk-export").click()]);
  expect(csv.suggestedFilename()).toMatch(/^agreements-.*\.csv$/);
  const text = fs.readFileSync(await csv.path(), "utf8");
  expect(text).toContain("Offer letter — Jordan Rivera");
  expect(text.trim().split("\r\n")).toHaveLength(3);
  await bar.getByTestId("bulk-void").click();
  const many = page.getByRole("dialog", { name: "Void 2 envelopes?" });
  await many.getByLabel("Reason (recipients will see it)").fill("Wrong terms");
  await many.getByRole("button", { name: "Void (2)" }).click();
  await expect(page.locator(".os-toast").last()).toContainText("Voided 2 envelopes.");
  await expect(page.locator("dialog[open]")).toHaveCount(0);
  await expect(page.locator('tbody tr[data-status="voided"]')).toHaveCount(3);

  // Bulk delete of the voided ones.
  for (const s of ["Offer letter — Jordan Rivera", "Vendor services agreement"]) await page.getByRole("checkbox", { name: `Select ${s}` }).check();
  await page.getByTestId("bulk-delete").click();
  await page.getByRole("dialog", { name: "Delete 2 envelopes?" }).getByRole("button", { name: "Delete (2)" }).click();
  await expect(page.getByRole("link", { name: "Offer letter — Jordan Rivera" })).toHaveCount(0);
  await expectAccessible(page, "agreements after bulk");
});

test("UX-07 expiring soon: the card and the quick view list the same envelopes", async ({ page }) => {
  await signIn(page, "home");
  const n = Number(await page.getByTestId("counter-expiring").locator(".os-counter__n").textContent());
  await page.getByTestId("counter-expiring").click();
  await expect(page).toHaveURL(/folder=expiring/);
  await expect(page.locator("tbody tr")).toHaveCount(n);
  await expect(page.locator(".os-rail__link[aria-current=page]")).toContainText("Expiring soon");
});

test("UX-07 envelope page: summary with the ID, evidence card, History as a timeline", async ({ page }, testInfo) => {
  await signIn(page);
  await page.setViewportSize({ width: 1440, height: 900 });
  const id = await subjectId(page, "Mutual NDA — Acme and Globex");
  await page.goto(app(`#/envelopes/${id}`));
  const head = page.locator(".os-page-head");
  await expect(head.locator(".os-btn--primary")).toHaveText("Download signed PDF");
  await expect(head.getByRole("button", { name: "Certificate" })).toBeVisible();
  await expect(page.getByTestId("envelope-id")).toHaveText(id);
  const evidence = page.getByTestId("evidence-card");
  await expect(evidence.getByTestId("chain-head")).toHaveText(/^[0-9a-f]{64}$/);
  await expect(evidence.getByTestId("evidence-verify")).toHaveAttribute("href", "verify.html");
  // The summary uses the width: two columns side by side.
  const cols = await page.locator(".os-envsum__col").evaluateAll((els) => els.map((e) => e.getBoundingClientRect().top));
  expect(cols[0]).toBe(cols[1]);
  await snap(page, testInfo, "ux07-envelope-completed-1440");

  await page.getByTestId("envelope-more").click();
  await page.getByRole("menuitem", { name: "History" }).click();
  const panel = page.getByRole("dialog", { name: "History: Mutual NDA — Acme and Globex" });
  const timeline = panel.getByTestId("history-timeline");
  await expect(timeline.locator(".os-histline__verb", { hasText: /^Signed$/ }).first()).toBeVisible();
  await expect(timeline).not.toContainText("Recipient finished");
  await expectAccessible(page, "history panel");
  await snap(page, testInfo, "ux07-history-1440");
});

test("UX-07 correct: add and remove a recipient, change the expiry and reminders", async ({ page }, testInfo) => {
  await signIn(page);
  await page.setViewportSize({ width: 1440, height: 900 });
  const id = await subjectId(page, "Offer letter — Jordan Rivera");
  await page.goto(app(`#/envelopes/${id}`));
  await page.getByTestId("envelope-correct").click();
  const panel = page.getByRole("dialog", { name: "Correct envelope" });
  await panel.getByRole("button", { name: "Remove People Ops" }).click();
  await panel.getByTestId("correct-add").click();
  const added = panel.getByTestId("correct-new");
  await added.getByLabel("Name").fill("Alex Manager");
  await added.getByLabel("Email").fill("alex@example.com");
  await added.getByLabel("Role").selectOption("signer");
  await added.getByLabel("Signing order").fill("1");
  await panel.getByLabel("Expires on").fill("2099-01-31");
  await panel.getByLabel("First reminder after (days)").fill("2");
  await panel.getByLabel("Then every (days)").fill("3");
  await expectAccessible(page, "correct panel with add");
  await snap(page, testInfo, "ux07-correct-1440");
  await panel.getByTestId("correct-save").click();
  await expect(page.locator(".os-toast").last()).toContainText("Envelope corrected.");
  const env = await page.evaluate((eid) => JSON.parse(sessionStorage.getItem("openseal.mock.v1")).envelopes.find((e) => e.id === eid), id);
  expect(env.recipients.map((r) => r.name).sort()).toEqual(["Alex Manager", "Jordan Rivera"]);
  expect(env.expires_at.slice(0, 7)).toBe("2099-01");
  expect(env.reminders).toEqual({ first_after_days: 2, then_every_days: 3 });
  await expect(page.locator(".os-envsum")).toContainText("first after 2 days, then every 3 days");
});

test("UX-07 phones: a folder select, Filters and Select toggles, one primary per envelope", async ({ page }, testInfo) => {
  await signIn(page);
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto(app("#/agreements"));
  await expect(page.getByTestId("folder-select")).toBeVisible();
  await expect(page.locator(".os-rail")).toBeHidden();
  await expect(page.locator(".os-filters")).toBeHidden();
  await expect(page.locator("tbody .os-checkbox").first()).toBeHidden();
  await page.getByTestId("filters-toggle").click();
  await expect(page.locator(".os-filters")).toBeVisible();
  await page.getByTestId("select-toggle").click();
  await expect(page.locator("tbody .os-checkbox").first()).toBeVisible();
  await page.getByTestId("folder-select").selectOption("completed");
  await expect(page).toHaveURL(/folder=completed/);
  await expect(page.locator("tbody tr")).toHaveCount(1);
  await snap(page, testInfo, "ux07-agreements-390");
  await page.goto(app(`#/envelopes/${await subjectId(page, "Board consent — November")}`));
  const primary = page.locator(".os-page-head .os-btn--primary");
  await expect(primary).toHaveText("Copy and resend");
  const [pb, hb] = [await primary.boundingBox(), await page.locator(".os-page-head").boundingBox()];
  expect(pb.width).toBeGreaterThan(hb.width * 0.9);
  await noSideScroll(page, "declined envelope at 390");
  await snap(page, testInfo, "ux07-envelope-declined-390");
  await page.goto(app("#/home"));
  await expect(page.getByTestId("recent-row").first()).toBeVisible();
  await snap(page, testInfo, "ux07-home-390");
});

test("UX-07 screenshots at 1440: home, declined and sent envelopes", async ({ page }, testInfo) => {
  await signIn(page, "home");
  await page.setViewportSize({ width: 1440, height: 900 });
  await expect(page.getByTestId("recent-row").first()).toContainText("To: ");
  // The recent list starts above the fold.
  expect((await page.getByTestId("recent-row").first().boundingBox()).y).toBeLessThan(450);
  await snap(page, testInfo, "ux07-home-1440");
  for (const [name, subject] of [["declined", "Board consent — November"], ["sent", "Offer letter — Jordan Rivera"], ["draft", "Lease renewal 2027"]]) {
    await page.goto(app(`#/envelopes/${await subjectId(page, subject)}`));
    await expect(page.locator(".os-envsum")).toBeVisible();
    // Nothing optional leaks into the page as the word "null".
    await expect(page.locator("main")).not.toContainText("null");
    await snap(page, testInfo, `ux07-envelope-${name}-1440`);
  }
});
