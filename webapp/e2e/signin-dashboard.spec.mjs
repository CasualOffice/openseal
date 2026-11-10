// Scenario 1 (WEB-01): sign in, the dashboard lists envelopes, filters and search work.
import { test, expect } from "@playwright/test";
import { signIn, app, creds, REAL } from "./helpers.mjs";

test("a wrong password is refused with a message, and the right one signs in", async ({ page }) => {
  await page.goto(app("#/signin"));
  await page.getByLabel("Email").fill(creds.email || "nobody@example.com");
  await page.getByLabel("Password").fill("not-the-password");
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByRole("alert")).toContainText("not right");
  await signIn(page);
});

test("the dashboard lists envelopes with their status and opens one", async ({ page }) => {
  await signIn(page);
  const rows = page.locator("tbody tr");
  await expect(rows.first()).toBeVisible();
  if (!REAL) {
    await expect(page.getByRole("link", { name: "Mutual NDA — Acme and Globex" })).toBeVisible();
    await expect(page.locator("tbody")).toContainText("Completed");
    await expect(page.locator("tbody")).toContainText("Draft");
  }
  await rows.first().getByRole("link").click();
  await expect(page.getByRole("heading", { name: "Recipients" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Audit trail" })).toBeVisible();
});

test("a status filter narrows the list and search filters it by subject", async ({ page }) => {
  await signIn(page);
  await page.getByRole("button", { name: "Draft", exact: true }).click();
  await expect(page).toHaveURL(/status=draft/);
  await expect(page.getByRole("button", { name: "Draft", exact: true })).toHaveAttribute("aria-pressed", "true");
  await expect(page.locator("tbody tr").first()).toBeVisible();
  for (const badge of await page.locator("tbody .os-badge").allTextContents()) expect(badge).toContain("Draft");
  await page.getByRole("button", { name: "All", exact: true }).click();
  await expect(page.getByRole("button", { name: "All", exact: true })).toHaveAttribute("aria-pressed", "true");
  await expect(page.locator("tbody tr").first()).toBeVisible();
  await page.getByRole("searchbox").fill("zzz-no-such-subject");
  await expect(page.getByTestId("empty-search")).toBeVisible();
  await page.getByRole("button", { name: "Clear search" }).click();
  await expect(page.locator("tbody tr").first()).toBeVisible();
});

test("a completed envelope offers the signed PDF and certificate downloads", async ({ page }) => {
  test.skip(REAL, "needs a completed envelope seeded on the server");
  await signIn(page);
  await page.getByRole("link", { name: "Mutual NDA — Acme and Globex" }).click();
  const [dl] = await Promise.all([page.waitForEvent("download"), page.getByRole("button", { name: "Download signed PDF" }).click()]);
  expect(dl.suggestedFilename()).toMatch(/-sealed\.pdf$/);
  const [cert] = await Promise.all([page.waitForEvent("download"), page.getByRole("button", { name: "Certificate" }).click()]);
  expect(cert.suggestedFilename()).toMatch(/^certificate-/);
});

test("resend and void act on a sent envelope", async ({ page }) => {
  test.skip(REAL, "needs a sent envelope seeded on the server");
  await signIn(page);
  await page.getByRole("link", { name: "Vendor services agreement" }).click();
  await page.getByRole("button", { name: "Resend" }).click();
  await expect(page.getByText("Reminder sent to recipients")).toBeVisible();
  await page.getByRole("button", { name: "Void", exact: true }).click();
  const dlg = page.getByRole("dialog", { name: "Void this envelope?" });
  await dlg.getByRole("button", { name: "Void", exact: true }).click();
  await expect(dlg.getByText("This is required.")).toBeVisible();
  await dlg.getByLabel("Reason (recipients will see it)").fill("Terms changed");
  await dlg.getByRole("button", { name: "Void", exact: true }).click();
  await expect(page.locator(".os-page-head .os-badge")).toHaveText("Voided");
  await expect(page.getByText("Terms changed")).toBeVisible();
});

test("signing out returns to sign-in, and the app then asks to sign in again", async ({ page }) => {
  await signIn(page);
  await page.getByRole("button", { name: "Account" }).click();
  await page.getByRole("menuitem", { name: "Sign out" }).click();
  await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();
  await page.goto(app("#/agreements"));
  await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();
});
