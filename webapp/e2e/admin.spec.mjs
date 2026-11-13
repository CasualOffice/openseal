// Admin, Reports and Template use after the UX-01 audit (UX-08): the section rail with
// the sections still to come shown as rows; webhooks with their deliveries; the one-time
// API secret that Escape cannot lose; one Add user panel with search and filters;
// branding with a colour picker and a contrast check; Reports that say how many
// envelopes each figure rests on; and a template used with an extra recipient.
// Runs in mock mode (the webhook test event and redelivery are mock answers ahead of the
// server, api.js NOT_ON_SERVER), at 1440 and at 390 px.

import { test, expect } from "@playwright/test";
import { app, signIn, expectAccessible, snap, REAL } from "./helpers.mjs";

const mockOnly = () => test.skip(REAL, "uses the mock's seeded data and its answers ahead of the server");
const db = (page) => page.evaluate(() => JSON.parse(sessionStorage.getItem("openseal.mock.v1")));
const templateId = async (page, name) => (await db(page)).templates.find((x) => x.name === name).id;

for (const [label, width, height] of [["1440", 1440, 900], ["390", 390, 844]]) {
  test.describe(`at ${label} px`, () => {
    test.beforeEach(async ({ page }) => {
      mockOnly();
      await page.setViewportSize({ width, height });
      await signIn(page);
    });

    test("admin: the canvas's nav, the pages still to come say so and what they will hold", async ({ page }, testInfo) => {
      await page.goto(app("#/admin"));
      await expect(page.getByRole("heading", { name: "Members and roles", level: 1 })).toBeVisible();
      if (width > 600) {
        const rail = page.getByRole("navigation", { name: "Admin sections" });
        await expect(rail.getByRole("link", { name: "Members and roles" })).toHaveAttribute("aria-current", "page");
        const names = ["Organization", "Members and roles", "Security and sign-in", "Signing and seals", "Branding", "Document intelligence", "Retention", "API and webhooks", "Audit log"];
        await expect(rail.locator("a[data-section]")).toHaveText(names.map((n) => new RegExp(`^${n}`)));
        // No nav label wraps (owner instruction 44: no control label may wrap).
        for (const link of await rail.locator("a[data-section]").all()) {
          const box = await link.boundingBox();
          expect(box.height, await link.innerText()).toBeLessThan(48);
        }
        await rail.getByRole("link", { name: /^Signing and seals/ }).click();
      } else {
        await expect(page.getByRole("navigation", { name: "Admin sections" })).toBeHidden();
        await page.getByLabel("Section", { exact: true }).selectOption("signing");
      }
      const waiting = page.getByTestId("waiting-signing");
      await expect(waiting).toContainText("Not available on this server yet");
      for (const part of ["Signing and sending", "Seal and timestamp"]) await expect(waiting.getByRole("heading", { name: part, level: 2 })).toBeVisible();
      // ERSD-01: the disclosure is on this server, drawn above the parts still to come.
      await expect(page.getByTestId("ersd-card").getByRole("heading", { name: "Electronic disclosure", level: 2 })).toBeVisible();
      // Old links still land: ?section=seal opens the page that now holds it.
      await page.goto(app("#/admin?section=seal"));
      await expect(page.getByTestId("waiting-seal")).toHaveCount(0);
      await expect(page.getByTestId("wait-part-seal")).toBeVisible();
      await expectAccessible(page, "admin waiting section");
      await snap(page, testInfo, `ux08-admin-waiting-${label}`);
    });

    test("admin › electronic disclosure: publish a new version; the signer is asked to accept it", async ({ page }, testInfo) => {
      await page.goto(app("#/admin?section=ersd"));
      const card = page.getByTestId("ersd-card");
      await expect(card.getByTestId("ersd-version")).toHaveText("2026-1");
      await card.getByRole("button", { name: "Publish new version" }).click();
      const sheet = page.getByTestId("sheet-ersd-publish");
      await sheet.getByLabel("Disclosure text").fill("");
      await sheet.getByRole("button", { name: "Publish", exact: true }).click();
      await expect(sheet.getByRole("alert")).toHaveText("Enter the disclosure text.");
      await sheet.getByLabel("Disclosure text").fill("Our electronic record and signature disclosure, version one.");
      await sheet.getByRole("button", { name: "Publish", exact: true }).click();
      await expect(sheet).toHaveCount(0);
      await expect(card.getByTestId("ersd-version")).toHaveText("1");
      await expect(card.getByTestId("ersd-preview")).toHaveText("Our electronic record and signature disclosure, version one.");
      await expect(card.getByTestId("ersd-history")).toContainText("Version 1 (en)");
      const d = await db(page);
      expect(d.ersd.at(-1).text).toBe("Our electronic record and signature disclosure, version one.");
      await expectAccessible(page, "admin electronic disclosure");
      await snap(page, testInfo, `ersd-admin-${label}`);
    });

    test("admin › document intelligence: count, cards, scripts, models; a switch saves and survives a reload", async ({ page }, testInfo) => {
      await page.goto(app("#/admin?section=intelligence"));
      await expect(page.getByRole("heading", { name: "Document intelligence", level: 1 })).toBeVisible();
      await expect(page.getByTestId("intel-count")).toHaveText("5 of 5 on");
      await expect(page.getByTestId("intel-promises")).toContainText("Runs on your servers");
      for (const f of ["Read scanned pages", "Detect fields on upload", "Match templates", "Extract agreement details", "Find personal data"]) {
        await expect(page.getByRole("switch", { name: f })).toHaveAttribute("aria-checked", "true");
      }
      // Detect fields has no setting of its own: it follows OCR and says so.
      await expect(page.getByRole("switch", { name: "Detect fields on upload" })).toBeDisabled();
      await expect(page.getByTestId("intel-detect-why")).toContainText("follows Read scanned pages");
      const scripts = page.getByTestId("intel-scripts");
      await expect(scripts).toContainText("✓ Latin, Cyrillic, Greek, CJK");
      await expect(scripts).toContainText("Arabic · installing");
      await expect(scripts).toContainText("Devanagari · ask your operator");
      await expect(page.getByTestId("intel-ocr")).toContainText("PP-OCRv6");
      const models = page.getByTestId("intel-models");
      await expect(models.getByRole("listitem")).toHaveCount(5);
      await expect(models).toContainText("sha256 9c41…e07a");
      await expect(models).toContainText("sha256 pending");
      await expect(page.getByTestId("intel-footer")).toContainText("With everything off, OpenSeal works exactly as it does without models");
      await expectAccessible(page, "document intelligence");
      await snap(page, testInfo, `web18-intel-${label}`);

      // Turning one off: at once, said politely, and kept by the server.
      const pii = page.getByRole("switch", { name: "Find personal data" });
      await pii.click();
      await expect(pii).toHaveAttribute("aria-checked", "false");
      await expect(page.getByTestId("intel-count")).toHaveText("4 of 5 on");
      await expect(page.getByTestId("intel-live")).toHaveText("Find personal data is off.");
      await expect(page.getByTestId("intel-pii").getByText(/English only for now/)).toBeHidden();
      // OCR off takes Detect fields with it.
      await page.getByRole("switch", { name: "Read scanned pages" }).click();
      await expect(page.getByRole("switch", { name: "Detect fields on upload" })).toHaveAttribute("aria-checked", "false");
      await expect(page.getByTestId("intel-count")).toHaveText("2 of 5 on");
      await page.reload();
      await expect(page.getByTestId("intel-count")).toHaveText("2 of 5 on");
      await expect(page.getByRole("switch", { name: "Find personal data" })).toHaveAttribute("aria-checked", "false");
    });

    test("admin › document intelligence: a refused change goes back and says why", async ({ page }) => {
      await page.goto(app("#/admin?section=intelligence"));
      const sw = page.getByRole("switch", { name: "Match templates" });
      await expect(sw).toHaveAttribute("aria-checked", "true");
      // The plan is taken away after the page loaded: the PATCH answers 403 CS-ML-0011.
      await page.evaluate(() => sessionStorage.setItem("openseal.mock.ml", "no-plan"));
      await sw.click();
      await expect(page.locator(".os-toast--error")).toBeVisible();
      await expect(sw).toHaveAttribute("aria-checked", "true");
      await expect(page.getByTestId("intel-count")).toHaveText("5 of 5 on");
    });

    test("admin › document intelligence: not installed on this server, and not in the plan", async ({ page }, testInfo) => {
      await page.evaluate(() => sessionStorage.setItem("openseal.mock.ml", "off"));
      await page.goto(app("#/admin?section=intelligence"));
      const none = page.getByTestId("intel-not-installed");
      await expect(none).toContainText("Not installed on this server");
      await expect(none).toContainText("your operator");
      // Nothing ML is offered: no switch, no count, no model list.
      await expect(page.getByRole("switch")).toHaveCount(0);
      await expect(page.getByTestId("intel-count")).toHaveCount(0);
      await expect(page.getByTestId("intel-models")).toHaveCount(0);
      await expectAccessible(page, "document intelligence not installed");
      await snap(page, testInfo, `web18-intel-none-${label}`);

      await page.evaluate(() => sessionStorage.setItem("openseal.mock.ml", "no-plan"));
      await page.reload();
      await expect(page.getByTestId("intel-no-plan")).toContainText("Not in your plan");
      await expect(page.getByTestId("intel-count")).toHaveText("0 of 5 on");
      for (const sw of await page.getByRole("switch").all()) {
        await expect(sw).toBeDisabled();
        await expect(sw).toHaveAttribute("aria-checked", "false");
      }
      await page.evaluate(() => sessionStorage.removeItem("openseal.mock.ml"));
    });

    test("admin › API and webhooks: pill tabs with arrow keys, the URL follows the tab", async ({ page }) => {
      await page.goto(app("#/admin?section=api"));
      const tabs = page.getByRole("tablist", { name: "API and webhooks" });
      await expect(tabs.getByRole("tab", { name: "API clients" })).toHaveAttribute("aria-selected", "true");
      await tabs.getByRole("tab", { name: "API clients" }).focus();
      await page.keyboard.press("ArrowRight");
      await expect(tabs.getByRole("tab", { name: "Webhooks" })).toHaveAttribute("aria-selected", "true");
      await expect(tabs.getByRole("tab", { name: "Webhooks" })).toBeFocused();
      await expect(page.getByRole("heading", { name: "Webhooks", level: 2 })).toBeVisible();
      await expect(page).toHaveURL(/section=webhooks$/);
      await page.reload();
      await expect(page.getByRole("tab", { name: "Webhooks" })).toHaveAttribute("aria-selected", "true");
    });

    test("admin: create a webhook, send a test event and see its delivery row", async ({ page }, testInfo) => {
      await page.goto(app("#/admin?section=webhooks"));
      await expect(page.getByRole("heading", { name: "Webhooks", level: 2 })).toBeVisible();
      // The seeded subscription's deliveries, one failed: deliver it again.
      const del = page.getByTestId("deliveries");
      await expect(del.getByTestId("delivery-row")).toHaveCount(2);
      await expect(del.getByTestId("delivery-row").first()).toContainText("Failed");
      await expect(del.getByTestId("delivery-row").first()).toContainText("503");
      await del.getByRole("button", { name: "Deliver again: envelope.declined" }).click();
      await expect(del.getByTestId("delivery-row").first()).toContainText("Delivered");
      await snap(page, testInfo, `ux08-webhooks-${label}`);

      await page.getByRole("button", { name: "New webhook" }).first().click();
      const panel = page.getByRole("dialog", { name: "New webhook" });
      await panel.getByLabel("Endpoint URL").fill("http://10.0.0.5/hook");
      await panel.getByLabel("Signing secret names").fill("erp_secret");
      await panel.getByRole("button", { name: "Create" }).click();
      await expect(panel.getByText("Enter an address that starts with https://.")).toBeVisible();
      await panel.getByLabel("Endpoint URL").fill("https://10.0.0.5/hook");
      await panel.getByRole("button", { name: "Create" }).click();
      await expect(panel.getByText("This address is refused")).toBeVisible();
      await panel.getByLabel("Endpoint URL").fill("https://erp.example.com/openseal");
      await panel.getByLabel("envelope.sent").check();
      await expectAccessible(page, "new webhook panel");
      await snap(page, testInfo, `ux08-webhook-new-${label}`);
      await panel.getByRole("button", { name: "Create" }).click();
      await expect(page.getByText("Webhook added.")).toBeVisible();
      const row = page.getByRole("row", { name: /erp\.example\.com/ });
      await expect(row).toContainText("Active");
      const hooks = (await db(page)).webhooks;
      expect(hooks.find((w) => w.url === "https://erp.example.com/openseal").event_types).toContain("envelope.sent");
      await expect(del).toContainText("erp.example.com");
      await expect(del.getByTestId("no-deliveries")).toBeVisible();
      await del.getByTestId("webhook-test").click();
      await expect(del.getByTestId("delivery-row")).toHaveCount(1);
      await expect(del.getByTestId("delivery-row")).toContainText("webhook.test");
      await expect(del.getByTestId("delivery-row")).toContainText("200");

      // Pause from the row menu, then resume.
      await row.getByRole("button", { name: "Actions for https://erp.example.com/openseal" }).click();
      await page.getByRole("menuitem", { name: "Pause" }).click();
      await expect(page.getByRole("row", { name: /erp\.example\.com/ })).toContainText("Off");
      await expectAccessible(page, "webhooks");
    });

    test("admin: the one-time API secret survives Escape and navigation; columns, revoked toggle", async ({ page }, testInfo) => {
      await page.goto(app("#/admin?section=api"));
      await expect(page.getByTestId("dev-account-value")).toHaveValue("acct-demo");
      await expect(page.getByTestId("dev-base-value")).toHaveValue(/\/api\/v1$/);
      await page.getByRole("button", { name: "New API client" }).first().click();
      const create = page.getByRole("dialog", { name: "New API client" });
      await create.getByLabel("Name").fill("Billing sync");
      await expect(create.getByText("Add and change webhooks and read their deliveries.")).toBeVisible();
      await create.getByLabel("Expires after (days)").fill("10");
      await create.getByRole("button", { name: "Create" }).click();
      const secret = page.getByRole("dialog", { name: "Copy the secret now" });
      await expect(secret.getByTestId("secret-value")).toHaveValue(/^osk_/);
      await expect(secret.getByRole("button", { name: "Close" })).toHaveCount(0);
      await page.keyboard.press("Escape");
      await page.waitForTimeout(300);
      await expect(secret.getByTestId("secret-value")).toHaveValue(/^osk_/);
      await secret.getByTestId("secret-value").press("Escape");
      await page.waitForTimeout(300);
      await expect(secret).toBeVisible();
      await page.evaluate(() => { location.hash = "#/templates"; });
      await expect(page.getByRole("heading", { name: "Templates", level: 1 })).toBeVisible();
      await expect(secret).toBeVisible();
      await snap(page, testInfo, `ux08-secret-${label}`);
      await secret.getByRole("button", { name: "I have copied it" }).click();
      await expect(secret).toHaveCount(0);

      await page.goto(app("#/admin?section=api"));
      const row = page.getByRole("row", { name: /Billing sync/ });
      await expect(row.getByTestId("expiry-badge")).toHaveText("In 10 days");
      await row.getByRole("button", { name: "Actions for Billing sync" }).click();
      await page.getByRole("menuitem", { name: "Revoke" }).click();
      await page.getByRole("dialog", { name: "Revoke this API client?" }).getByRole("button", { name: "Revoke" }).click();
      await expect(page.getByRole("row", { name: /Billing sync/ })).toHaveCount(0);
      await page.getByText("Show revoked (1)").click();
      await expect(page.getByRole("row", { name: /Billing sync/ })).toContainText("Revoked");
      await expectAccessible(page, "api clients");
      await snap(page, testInfo, `ux08-api-${label}`);
    });

    test("admin users: one Add user panel, search and filters, Remove in the row menu", async ({ page }, testInfo) => {
      await page.goto(app("#/admin"));
      await expect(page.getByRole("button", { name: "Invite user" })).toHaveCount(0);
      await page.getByRole("button", { name: "Add user" }).first().click();
      const add = page.getByRole("dialog", { name: "Add user" });
      await expect(add.getByRole("switch", { name: "Send an invitation email" })).toBeChecked();
      await expect(add.getByLabel("Password")).toBeHidden();
      await add.getByLabel("Name", { exact: true }).fill("Lee Park");
      await add.getByLabel("Email", { exact: true }).fill("lee@example.com");
      await add.getByRole("button", { name: "Add user" }).click();
      await expect(page.getByText("Invitation sent to lee@example.com.")).toBeVisible();
      await expect(page.getByRole("row", { name: /lee@example.com/ })).toContainText("Invited");

      await page.getByRole("button", { name: "Add user" }).first().click();
      await add.getByLabel("Name", { exact: true }).fill("Kim Lee");
      await add.getByLabel("Email", { exact: true }).fill("kim@example.com");
      await add.getByText("Send an invitation email").click();
      await add.getByRole("button", { name: "Add user" }).click();
      await expect(add.getByLabel("Password")).toHaveAttribute("aria-invalid", "true");
      await add.getByLabel("Password").fill("a-long-enough-password");
      await add.getByRole("button", { name: "Add user" }).click();
      await expect(page.getByText("User added.")).toBeVisible();

      await page.getByLabel("Search users").fill("lee");
      await expect(page.getByTestId("users-count")).toHaveText("2 of 4 users");
      await page.getByLabel("Status").selectOption("pending");
      await expect(page.locator("tbody tr")).toHaveCount(1);
      await expect(page.locator("tbody tr")).toContainText("Lee Park");
      await page.getByLabel("Search users").fill("");
      await page.getByLabel("Status").selectOption("all");
      await page.locator("#u-filter-profile").selectOption("admin");
      await expect(page.locator("tbody tr")).toHaveCount(1);
      await page.locator("#u-filter-profile").selectOption("all");
      await snap(page, testInfo, `ux08-users-${label}`);

      await expect(page.getByRole("button", { name: "Remove Kim Lee" })).toHaveCount(0);
      await page.getByRole("button", { name: "Actions for Kim Lee" }).click();
      await page.getByRole("menuitem", { name: "Remove" }).click();
      await page.getByRole("dialog", { name: "Remove this user?" }).getByRole("button", { name: "Remove" }).click();
      await expect(page.getByRole("row", { name: /kim@example.com/ })).toHaveCount(0);
      await expectAccessible(page, "admin users");
    });

    test("admin branding: a colour picker, a contrast warning and a preview", async ({ page }, testInfo) => {
      await page.goto(app("#/admin?section=branding"));
      await page.getByTestId("account-branding").getByRole("button", { name: "Edit branding" }).click();
      const br = page.getByRole("dialog", { name: "Branding" });
      // The dialog fills its fields from the account once open; on a slow WebKit that can land
      // after the first fill and replace it, so fill until the warning shows (E2E-04).
      await expect(async () => {
        await br.getByLabel("Accent colour", { exact: true }).fill("#f5c518");
        await expect(br.getByTestId("brand-contrast")).toContainText("needs at least 4.5:1", { timeout: 1000 });
      }).toPass();
      await expect(br.getByLabel("Pick the accent colour")).toHaveValue("#f5c518");
      await br.getByLabel("Pick the accent colour").fill("#0e7490");
      await expect(br.getByLabel("Accent colour", { exact: true })).toHaveValue("#0e7490");
      await expect(br.getByTestId("brand-contrast")).toContainText("Readable");
      await br.getByLabel("Name shown to recipients").fill("Acme Legal");
      await expect(br.getByTestId("brand-preview")).toContainText("Acme Legal");
      await expectAccessible(page, "branding panel");
      await snap(page, testInfo, `ux08-branding-${label}`);
      await br.getByRole("button", { name: "Save" }).click();
      await expect(page.getByTestId("account-branding")).toContainText("#0e7490");
      await snap(page, testInfo, `ux08-account-${label}`);
    });

    test("reports: each figure says how many envelopes it rests on; a custom range, a sender, rows to the list", async ({ page }, testInfo) => {
      await page.goto(app("#/reports"));
      await expect(page.getByTestId("tile-sent")).toContainText("of 7 envelopes loaded");
      await expect(page.getByTestId("tile-median")).toContainText(/from \d+ completed/);
      await expect(page.getByRole("heading", { name: "Reports" })).toBeVisible();
      await expect(page.getByText("computed from the envelopes list")).toHaveCount(0);
      await page.getByLabel("Period").selectOption("custom");
      await page.getByLabel("From", { exact: true }).fill("2020-01-01");
      await page.getByLabel("To", { exact: true }).fill("2020-01-02");
      await expect(page.getByTestId("report-note")).toContainText("0 envelopes");
      await page.getByLabel("Period").selectOption("all");
      await page.getByLabel("Sender").selectOption("me");
      await expect(page.getByTestId("report-note")).toContainText("6 envelopes");
      await expectAccessible(page, "reports");
      await snap(page, testInfo, `ux08-reports-${label}`);
      await page.getByTestId("report-bars").getByRole("link", { name: /^Completed/ }).click();
      await expect(page).toHaveURL(/#\/agreements\?status=completed$/);
    });

    test("use a template: role labels say Name and Email, an extra recipient, the field count in view", async ({ page }, testInfo) => {
      await page.goto(app(`#/templates/${await templateId(page, "Mutual NDA")}`));
      const panel = page.locator(".os-usepanel");
      await expect(panel.getByLabel("Name", { exact: true }).first()).toBeVisible();
      await expect(panel.getByText(/: name$/)).toHaveCount(0);
      // Above the pages beside the panel on a desktop, not below the fold (at 900 px high).
      if (width > 600) await expect(page.getByTestId("use-fields-n")).toBeInViewport();
      await expect(page.locator(".os-use__field")).toHaveCount(4);
      for (const [i, who] of [[0, "ana"], [1, "bo"], [2, "lex"]]) {
        await panel.getByTestId("use-name").nth(i).fill(`${who} person`);
        await panel.getByTestId("use-email").nth(i).fill(`${who}@example.com`);
      }
      await panel.getByRole("button", { name: "Add recipient" }).click();
      await panel.getByTestId("extra-name").fill("Carl Copy");
      await panel.getByTestId("extra-email").fill("carl@example.com");
      await panel.getByTestId("extra-type").selectOption("cc");
      await expectAccessible(page, "use template");
      await snap(page, testInfo, `ux08-use-${label}`);
      await panel.getByTestId("use-send").click();
      await page.getByRole("dialog", { name: /Send/ }).getByRole("button", { name: "Send" }).click();
      await expect(page).toHaveURL(/#\/envelopes\//);
      const env = (await db(page)).envelopes.at(-1);
      expect(env.recipients.map((r) => [r.name, r.type])).toContainEqual(["Carl Copy", "cc"]);
    });

    test("templates on phones keep the word Use", async ({ page }) => {
      await page.goto(app("#/templates"));
      const use = page.getByRole("button", { name: "Use Mutual NDA" });
      const box = await use.boundingBox();
      expect(box.width).toBeGreaterThan(44);
      await expect(use.locator("span")).toHaveText("Use");
      expect(await use.locator("span").evaluate((e) => getComputedStyle(e).position)).not.toBe("absolute");
    });
  });
}
