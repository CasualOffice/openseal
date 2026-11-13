// Admin screens over routes the server already serves (UXW-09, UXW-10, RTE-03): the
// workspace's admin audit log (`GET /admin-events`: list, filters, export, a full chain
// check), webhooks end to end (list, create, edit, test, deliveries, deliver again; the
// `/webhooks` routes of UXW-31..33), and the expiry warning days an admin sets on the
// Organization page (`settings.workflow_policy` through `PATCH /accounts/me`).
// Runs in mock mode, whose answers follow the server's for these routes.

import { test, expect } from "@playwright/test";
import { app, signIn, expectAccessible, REAL } from "./helpers.mjs";

const db = (page) => page.evaluate(() => JSON.parse(sessionStorage.getItem("openseal.mock.v1")));

test.describe("admin screens", () => {
  test.beforeEach(async ({ page }) => {
    test.skip(REAL, "uses the mock's seeded data");
    await page.setViewportSize({ width: 1440, height: 900 });
    await signIn(page);
  });

  test("audit log: events with who and what changed, filters, details, CSV export, chain check (UXW-09)", async ({ page }) => {
    // A change made here is in the log.
    await page.goto(app("#/admin?section=organization"));
    await page.getByTestId("account-settings").getByRole("button", { name: "Edit settings" }).click();
    const sheet = page.getByRole("dialog", { name: "Settings" });
    await sheet.getByLabel("Envelopes expire after (days)").fill("45");
    await sheet.getByRole("button", { name: "Save" }).click();
    await expect(page.getByText("Settings saved.")).toBeVisible();

    await page.goto(app("#/admin?section=audit"));
    await expect(page.getByRole("heading", { name: "Audit log", level: 1 })).toBeVisible();
    await expect(page.getByTestId("waiting-audit")).toHaveCount(0);
    const rows = page.getByTestId("audit-row");
    await expect(rows.first()).toBeVisible();
    const total = await rows.count();
    expect(total).toBeGreaterThan(2);
    // Newest first: the settings change just made, by the signed-in admin.
    await expect(rows.first()).toContainText("workspace.settings_changed");
    await expect(rows.first()).toContainText("Demo Admin");
    await expect(rows.first()).toContainText("default_expiry_days");
    await expect(page.getByTestId("audit-count")).toHaveText(`${total} of ${total} events`);

    // Filters: by action, by who, by text.
    await page.getByLabel("Action", { exact: true }).selectOption("member.added");
    await expect(rows.first()).toContainText("member.added");
    for (const r of await rows.all()) await expect(r).toContainText("member.added");
    await page.getByLabel("Action", { exact: true }).selectOption("all");
    await page.getByLabel("Made by", { exact: true }).selectOption("system");
    for (const r of await rows.all()) await expect(r).toContainText("The server");
    await page.getByLabel("Made by", { exact: true }).selectOption("all");
    await page.getByLabel("Search the log").fill("default_expiry_days");
    await expect(rows).toHaveCount(1);
    await expect(page.getByTestId("audit-count")).toHaveText(`1 of ${total} events`);

    // Details: each change with its old and new value, and the chain link.
    await rows.first().getByRole("button", { name: /^Details/ }).click();
    const details = page.getByRole("dialog", { name: /^Event \d+$/ });
    await expect(details.getByTestId("audit-change")).toContainText("default_expiry_days");
    await expect(details.getByTestId("audit-change")).toContainText("45");
    await expect(details.getByTestId("audit-hash")).toHaveText(/^[0-9a-f]{64}$/);
    await expectAccessible(page, "audit event details");
    await details.getByRole("button", { name: "Close" }).first().click();
    await page.getByLabel("Search the log").fill("");

    // Export: the server's CSV, every page.
    const [download] = await Promise.all([
      page.waitForEvent("download"),
      page.getByRole("button", { name: "Export CSV" }).click(),
    ]);
    expect(download.suggestedFilename()).toMatch(/^admin-log-.*\.csv$/);
    const csv = await (await download.createReadStream()).toArray().then((c) => Buffer.concat(c).toString("utf8"));
    const lines = csv.trim().split(/\r?\n/);
    expect(lines[0]).toBe("seq,at,action,hash,prev,event");
    expect(lines.length).toBe(total + 1);

    // The whole chain checked by the server.
    await page.getByRole("button", { name: "Verify the log" }).click();
    await expect(page.getByText("The whole log checks out")).toBeVisible();
    await expectAccessible(page, "audit log");
  });

  test("webhooks: list, edit (address checked again), test event, deliveries, deliver again (UXW-10)", async ({ page }) => {
    await page.goto(app("#/admin?section=webhooks"));
    const row = page.getByRole("row", { name: /hooks\.example\.com/ });
    await expect(row).toContainText("Active");
    const del = page.getByTestId("deliveries");
    await expect(del.getByTestId("delivery-row")).toHaveCount(2);

    // Edit from the row menu: the address and events, prefilled.
    await row.getByRole("button", { name: "Actions for https://hooks.example.com/openseal" }).click();
    await page.getByRole("menuitem", { name: "Edit" }).click();
    const panel = page.getByRole("dialog", { name: "Edit webhook" });
    await expect(panel.getByLabel("Endpoint URL")).toHaveValue("https://hooks.example.com/openseal");
    await expect(panel.getByLabel("envelope.completed")).toBeChecked();
    await expect(panel.getByLabel("envelope.sent")).not.toBeChecked();
    await panel.getByLabel("Endpoint URL").fill("https://192.168.1.4/hook");
    await panel.getByRole("button", { name: "Save" }).click();
    await expect(panel.getByText("This address is refused")).toBeVisible();
    await panel.getByLabel("Endpoint URL").fill("https://crm.example.net/events");
    await panel.getByLabel("envelope.sent").check();
    await panel.getByLabel("recipient.completed").uncheck();
    await expectAccessible(page, "edit webhook panel");
    await panel.getByRole("button", { name: "Save" }).click();
    await expect(page.getByText("Webhook saved.")).toBeVisible();
    const edited = page.getByRole("row", { name: /crm\.example\.net/ });
    await expect(edited).toBeVisible();
    const hook = (await db(page)).webhooks.find((w) => w.url === "https://crm.example.net/events");
    expect(hook.event_types.sort()).toEqual(["envelope.completed", "envelope.declined", "envelope.sent"]);
    expect(hook.secret_refs).toEqual(["crm_signing_secret"]);

    // Deliveries: the failed one delivered again, then a test event.
    await expect(del).toContainText("crm.example.net");
    await del.getByRole("button", { name: "Deliver again: envelope.declined" }).click();
    await expect(page.getByText("Delivered again.")).toBeVisible();
    await expect(del.getByTestId("delivery-row").first()).toContainText("Delivered");
    await del.getByTestId("webhook-test").click();
    await expect(del.getByTestId("delivery-row")).toHaveCount(3);
    await expect(del.getByTestId("delivery-row").first()).toContainText("webhook.test");
    await expectAccessible(page, "webhooks");
  });

  test("organization: an admin sets the expiry warning days; the workflow policy carries them (RTE-03)", async ({ page }) => {
    await page.goto(app("#/admin?section=organization"));
    const card = page.getByTestId("account-settings");
    await expect(card.getByTestId("expiry-warning")).toHaveText("No warning");
    await card.getByRole("button", { name: "Edit settings" }).click();
    const sheet = page.getByRole("dialog", { name: "Settings" });
    const field = sheet.getByLabel("Warn signers before expiry (days)");
    await expect(field).toHaveValue("0");
    await field.fill("400");
    await sheet.getByRole("button", { name: "Save" }).click();
    await expect(sheet.getByText("Enter between 0 and 365 days.")).toBeVisible();
    await field.fill("3");
    await sheet.getByRole("button", { name: "Save" }).click();
    await expect(page.getByText("Settings saved.")).toBeVisible();
    await expect(card.getByTestId("expiry-warning")).toHaveText("3 days before");
    const policy = (await db(page)).account.settings.workflow_policy;
    expect(policy.expiry_warning_days).toBe(3);
    // The whole policy is sent (the server takes no partial policy), the rest unchanged.
    expect(policy.max_auth_attempts).toBe(3);
    expect(policy.date_format).toBe("yyyy_mm_dd");

    // It survives a reload and is shown in the form; 0 turns it off.
    await page.reload();
    await expect(card.getByTestId("expiry-warning")).toHaveText("3 days before");
    await card.getByRole("button", { name: "Edit settings" }).click();
    await expect(field).toHaveValue("3");
    await field.fill("0");
    await sheet.getByRole("button", { name: "Save" }).click();
    await expect(card.getByTestId("expiry-warning")).toHaveText("No warning");
    expect((await db(page)).account.settings.workflow_policy.expiry_warning_days).toBe(0);
    await expectAccessible(page, "organization settings");
  });
});
