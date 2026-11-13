// Organization admin, first cut (ORG-06, docs/23 §10): Overview, Workspaces, Users,
// Administrators and Audit log over `/organizations/me` (ORG-03, ORG-05). Mock mode at
// 1440 and 390 px: the demo user owns an organization of two workspaces
// (webapp/mock.js `organization()`); the server's own rules are tested in
// server/casual-sign-server/tests/organizations.rs. The last test runs on any server, the
// Compose stack included, whose bootstrap administrator owns its organization (E2E-11).

import { test, expect } from "@playwright/test";
import { app, signIn, expectAccessible, REAL } from "./helpers.mjs";

const mockOnly = () => test.skip(REAL, "uses the mock's seeded organization (its workspaces, members and counts); on a real server the test at the end runs (ORG-06)");

// E2E-11: over `/organizations/me` on any server: a new workspace is listed, its creation
// is in the organization's audit log, whose chain verifies; the owner is listed as one.
test("organization admin on any server: a workspace made is listed and logged; the owner is an administrator (ORG-06)", async ({ page }, testInfo) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await signIn(page, "home");
  const name = `E2E ${Date.now()}-${testInfo.project.name}`;
  await page.goto(app("#/org?section=workspaces"));
  await expect(page.getByRole("heading", { name: "Workspaces", level: 1 })).toBeVisible();
  await page.getByRole("button", { name: "New workspace" }).click();
  const sheet = page.getByTestId("sheet-org-ws-new");
  await sheet.getByLabel("Name").fill(name);
  await sheet.getByRole("button", { name: "Create workspace" }).click();
  await expect(sheet).toHaveCount(0);
  await expect(page.getByTestId("org-workspaces").locator("tbody tr", { hasText: name })).toContainText("Active");

  await page.goto(app("#/org?section=audit"));
  await expect(page.getByRole("heading", { name: "Audit log", level: 1 })).toBeVisible();
  const log = page.getByTestId("org-audit");
  await expect(log.locator('tr[data-action="workspace.created"]').first()).toBeVisible();
  await page.getByTestId("org-audit-verify").click();
  await expect(page.getByText("Every entry in the log is linked to the one before it.")).toBeVisible();

  await page.goto(app("#/org?section=admins"));
  await expect(page.getByRole("heading", { name: "Administrators", level: 1 })).toBeVisible();
  await expect(page.getByTestId("org-admins").locator("tbody tr", { hasText: "Owner" }).first()).toBeVisible();
  await expectAccessible(page, "organization administrators on any server");
});

for (const [label, width, height] of [["1440", 1440, 900], ["390", 390, 844]]) {
  test.describe(`organization admin at ${label} px`, () => {
    test.beforeEach(async ({ page }) => {
      mockOnly();
      await page.setViewportSize({ width, height });
      await signIn(page, "home");
    });

    test("overview: reached from the workspace menu; counts; rename", async ({ page }) => {
      if (width > 600) {
        await page.locator("#ws-btn").click();
        await page.getByRole("menu", { name: "Workspace" }).getByRole("menuitem", { name: "Organization settings" }).click();
        await expect(page).toHaveURL(/#\/org$/);
        const rail = page.getByRole("navigation", { name: "Organization sections" });
        await expect(rail.locator("a[data-section]")).toHaveText(["Overview", "Workspaces", "Users", "Administrators", "Audit log"]);
        await expect(rail.getByRole("link", { name: "Overview" })).toHaveAttribute("aria-current", "page");
      } else {
        await page.goto(app("#/org"));
        await expect(page.getByRole("navigation", { name: "Organization sections" })).toBeHidden();
        await expect(page.getByLabel("Section", { exact: true })).toHaveValue("overview");
      }
      await expect(page.getByRole("heading", { name: "Overview", level: 1 })).toBeVisible();
      await expect(page.getByTestId("org-tile-workspaces")).toContainText("2");
      await expect(page.getByTestId("org-tile-admins")).toContainText("1");
      await expect(page.getByTestId("org-role")).toHaveText("Owner");
      await page.getByRole("button", { name: "Rename organization" }).click();
      const sheet = page.getByTestId("sheet-org-rename");
      await sheet.getByLabel("Organization name").fill("Acme Group");
      await sheet.getByRole("button", { name: "Save" }).click();
      await expect(sheet).toHaveCount(0);
      await expect(page.getByTestId("org-name")).toHaveText("Acme Group");
      await expectAccessible(page, "organization overview");
    });

    test("workspaces: create, join, archive; each change is in the audit log, whose chain verifies", async ({ page }) => {
      await page.goto(app("#/org?section=workspaces"));
      await expect(page.getByRole("heading", { name: "Workspaces", level: 1 })).toBeVisible();
      const list = page.getByTestId("org-workspaces");
      await expect(list.locator("tbody tr")).toHaveCount(2);
      await page.getByRole("button", { name: "New workspace" }).click();
      const sheet = page.getByTestId("sheet-org-ws-new");
      await sheet.getByRole("button", { name: "Create workspace" }).click();
      await expect(sheet.getByRole("alert")).toHaveText("This is required.");
      await sheet.getByLabel("Name").fill("Finance");
      await sheet.getByRole("button", { name: "Create workspace" }).click();
      await expect(sheet).toHaveCount(0);
      const row = list.locator("tbody tr", { hasText: "Finance" });
      await expect(row).toContainText("Active");
      await row.getByRole("button", { name: "Join Finance" }).click();
      const join = page.getByTestId("sheet-org-ws-join");
      await join.getByLabel("Permission profile").selectOption("sender");
      await join.getByRole("button", { name: "Join", exact: true }).click();
      await expect(join).toHaveCount(0);
      await expect(row).toContainText("Member");
      await row.getByRole("button", { name: "Actions for Finance" }).click();
      await page.getByRole("menuitem", { name: "Archive workspace" }).click();
      await page.getByRole("dialog").getByRole("button", { name: "Archive workspace" }).click();
      await expect(row).toContainText("Archived");
      await expectAccessible(page, "organization workspaces");

      await page.goto(app("#/org?section=audit"));
      await expect(page.getByRole("heading", { name: "Audit log", level: 1 })).toBeVisible();
      const log = page.getByTestId("org-audit");
      await expect(log.locator("tbody tr").first()).toContainText("Workspace archived");
      for (const a of ["workspace.created", "org.workspace_joined", "workspace.archived", "organization.created"]) await expect(log.locator(`tr[data-action="${a}"]`)).toHaveCount(1);
      await expect(log.locator('tr[data-action="workspace.created"]')).toContainText("Demo Admin");
      await page.getByLabel("Filter the log").fill("archived");
      await expect(page.getByTestId("org-audit-count")).toHaveText("1 of 4 entries");
      await page.getByTestId("org-audit-verify").click();
      await expect(page.getByText("Every entry in the log is linked to the one before it.")).toBeVisible();
      await expectAccessible(page, "organization audit log");
    });

    test("administrators: an owner adds one, changes the role, removes them; the last owner stays", async ({ page }) => {
      await page.goto(app("#/org?section=admins"));
      await expect(page.getByRole("heading", { name: "Administrators", level: 1 })).toBeVisible();
      const list = page.getByTestId("org-admins");
      await expect(list.locator("tbody tr")).toHaveCount(1);
      await expect(list).toContainText("Demo Admin");
      await page.getByRole("button", { name: "Add administrator" }).click();
      const sheet = page.getByTestId("sheet-org-admin-add");
      await sheet.getByLabel("Member").selectOption({ label: "Robin Sender (sender@openseal.test)" });
      await sheet.getByRole("button", { name: "Add administrator" }).click();
      await expect(sheet).toHaveCount(0);
      const robin = list.locator("tbody tr", { hasText: "Robin Sender" });
      await expect(robin).toContainText("Admin");
      await robin.getByRole("button", { name: "Actions for Robin Sender" }).click();
      await page.getByRole("menuitem", { name: "Change role" }).click();
      const role = page.getByTestId("sheet-org-admin-role");
      await role.getByLabel("Organization role").selectOption("owner");
      await role.getByRole("button", { name: "Save" }).click();
      await expect(robin).toContainText("Owner");
      await robin.getByRole("button", { name: "Actions for Robin Sender" }).click();
      await page.getByRole("menuitem", { name: "Remove administrator" }).click();
      await page.getByRole("dialog").getByRole("button", { name: "Remove administrator" }).click();
      await expect(robin).toHaveCount(0);
      // The only owner cannot step down (CS-ORG-0008), said in place.
      const me = list.locator("tbody tr", { hasText: "Demo Admin" });
      await me.getByRole("button", { name: "Actions for Demo Admin" }).click();
      await page.getByRole("menuitem", { name: "Step down" }).click();
      await page.getByRole("dialog").getByRole("button", { name: "Step down" }).click();
      await expect(page.getByText(/The organization must keep at least one owner/)).toBeVisible();
      await expect(me).toBeVisible();
      await expectAccessible(page, "organization administrators");

      await page.goto(app("#/org?section=users"));
      const users = page.getByTestId("org-users");
      await expect(users.locator("tbody tr", { hasText: "Demo Admin" })).toContainText("Owner");
      await expect(users.locator("tbody tr", { hasText: "Robin Sender" })).not.toContainText("Owner");
      await expect(page.getByTestId("org-users-later")).toBeVisible();
      await expectAccessible(page, "organization users");
    });

    test("without an organization role: no menu entry, and the page says so", async ({ page }) => {
      await page.evaluate(() => {
        const d = JSON.parse(sessionStorage.getItem("openseal.mock.v1"));
        d.org ||= {};
        d.org = { ...d.org, id: "org-demo", name: "Demo organization", status: "active", workspaces: [{ id: "acct-demo", name: null, status: "active", member: true }], admins: [], events: d.org.events || [] };
        sessionStorage.setItem("openseal.mock.v1", JSON.stringify(d));
      });
      await page.goto(app("#/org?section=workspaces"));
      await page.reload();
      await expect(page.getByTestId("org-no-role")).toContainText("You are not an organization administrator");
      if (width > 600) {
        await page.locator("#ws-btn").click();
        const menu = page.getByRole("menu", { name: "Workspace" });
        await expect(menu.getByRole("menuitem", { name: "Workspace settings" })).toBeVisible();
        await expect(menu.getByRole("menuitem", { name: "Organization settings" })).toHaveCount(0);
      }
    });
  });
}
