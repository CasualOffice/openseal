// Scenario 1 (WEB-01): sign in, the dashboard lists envelopes, filters and search work.
// WEB-17: the list is the canvas's grouped grid with an inspector; views are pill tabs
// and the sidebar's Views; a row selects, Enter or Open opens.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { test, expect } from "@playwright/test";
import { signIn, app, creds, REAL, expectAccessible } from "./helpers.mjs";

const ROOT = path.resolve(fileURLToPath(new URL("../..", import.meta.url)));
const fixture = (p) => path.join(ROOT, "fixtures", p);
const WASM = fs.existsSync(path.join(ROOT, "webapp/vendor/openseal-wasm/casual_sign_wasm_bg.wasm"));

test("a wrong password is refused with a message, and the right one signs in", async ({ page }) => {
  await page.goto(app("#/signin"));
  await page.getByLabel("Email").fill(creds.email || "nobody@example.com");
  await page.getByLabel("Password").fill("not-the-password");
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByRole("alert")).toContainText("Incorrect email or password.");
  await signIn(page);
});

test("the dashboard lists envelopes with their status and opens one", async ({ page }) => {
  await signIn(page);
  const rows = page.locator(".os-agr-row[data-id]");
  await expect(rows.first()).toBeVisible();
  if (!REAL) {
    await expect(rows.filter({ hasText: "Mutual NDA — Acme and Globex" })).toBeVisible();
    await expect(page.getByRole("grid")).toContainText("Completed");
    await expect(page.getByRole("grid")).toContainText("Draft");
  }
  // A draft opens in the editor (WEB-06 A-02); a sent envelope opens its details.
  const sent = page.locator('.os-agr-row[data-id]:not([data-status="draft"])').first();
  await sent.click();
  await page.getByTestId("inspector-open").click();
  await expect(page.getByRole("heading", { name: "Recipients" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Audit trail" })).toBeVisible();
});

test("a view narrows the list and search filters it by subject", async ({ page }) => {
  await signIn(page);
  const tabs = page.getByRole("tablist", { name: "Views" });
  await tabs.getByRole("tab", { name: "Drafts" }).click();
  await expect(page).toHaveURL(/folder=drafts/);
  await expect(tabs.getByRole("tab", { name: "Drafts" })).toHaveAttribute("aria-selected", "true");
  await expect(page.locator(".os-agr-row[data-id]").first()).toBeVisible();
  for (const s of await page.locator(".os-agr-row[data-id]").evaluateAll((els) => els.map((e) => e.dataset.status))) expect(s).toBe("draft");
  // The sidebar's Views switch the same list in place.
  await page.locator('#nav-views a[data-view="completed"]').click();
  await expect(page).toHaveURL(/folder=completed/);
  await expect(tabs.getByRole("tab", { name: "Completed" })).toHaveAttribute("aria-selected", "true");
  await tabs.getByRole("tab", { name: "All" }).click();
  await expect(page.locator(".os-agr-row[data-id]").first()).toBeVisible();
  await page.getByRole("button", { name: "Search agreements" }).click();
  await page.getByRole("searchbox").fill("zzz-no-such-subject");
  await expect(page.getByTestId("empty-search")).toBeVisible();
  await page.getByTestId("empty-search").getByRole("button", { name: "Clear search" }).click();
  await expect(page.locator(".os-agr-row[data-id]").first()).toBeVisible();
});

test("rows can be selected for bulk actions, and each agreement has its own actions", async ({ page }) => {
  test.skip(REAL, "needs the mock's seeded envelopes");
  await signIn(page);
  await page.getByTestId("display-toggle").click();
  await page.getByRole("menuitem", { name: "Select agreements" }).click();
  await page.getByRole("checkbox", { name: "Select Offer letter — Jordan Rivera" }).check();
  const bulk = page.getByRole("region", { name: "Actions on the selected envelopes" });
  await expect(bulk).toContainText("1 selected");
  await bulk.getByRole("button", { name: "Resend (1)" }).click();
  await expect(page.locator(".os-toast")).toContainText("Resent");
  await bulk.getByRole("button", { name: "Clear selection" }).click();
  await expect(bulk).toContainText("0 selected");
  await bulk.getByTestId("select-off").click();
  await expect(bulk).toBeHidden();
  await page.locator(".os-agr-row", { hasText: "Mutual NDA — Acme and Globex" }).click();
  await page.getByRole("button", { name: "Actions for Mutual NDA — Acme and Globex" }).click();
  const menu = page.getByRole("menu", { name: "Actions for Mutual NDA — Acme and Globex" });
  await expect(menu.getByRole("menuitem", { name: "Download signed PDF" })).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(menu).toBeHidden();
});

test("a completed envelope offers the signed PDF and certificate downloads", async ({ page }) => {
  test.skip(REAL, "needs a completed envelope seeded on the server");
  await signIn(page);
  await page.locator(".os-agr-row", { hasText: "Mutual NDA — Acme and Globex" }).dblclick();
  const [dl] = await Promise.all([page.waitForEvent("download"), page.getByRole("button", { name: "Download signed PDF" }).click()]);
  expect(dl.suggestedFilename()).toMatch(/-sealed\.pdf$/);
  const [cert] = await Promise.all([page.waitForEvent("download"), page.getByRole("button", { name: "Certificate" }).click()]);
  expect(cert.suggestedFilename()).toMatch(/^certificate-/);
});

test("resend and void act on a sent envelope", async ({ page }) => {
  test.skip(REAL, "needs a sent envelope seeded on the server");
  await signIn(page);
  await page.locator(".os-agr-row", { hasText: "Vendor services agreement" }).click();
  await page.keyboard.press("Enter");
  await page.getByRole("button", { name: "Resend", exact: true }).click();
  await expect(page.getByText("Resent to everyone who has not finished.")).toBeVisible();
  // UX-07: Void is in the More menu, destructive items last.
  await page.getByTestId("envelope-more").click();
  await page.getByRole("menuitem", { name: "Void", exact: true }).click();
  const dlg = page.getByRole("dialog", { name: "Void this envelope?" });
  await dlg.getByRole("button", { name: "Void", exact: true }).click();
  await expect(dlg.getByText("This is required.")).toBeVisible();
  await dlg.getByLabel("Reason (recipients will see it)").fill("Terms changed");
  await dlg.getByRole("button", { name: "Void", exact: true }).click();
  await expect(page.locator(".os-page-head .os-badge")).toHaveText("Voided");
  await expect(page.getByTestId("decline-callout")).toContainText("Terms changed");
});

test("signing out returns to sign-in, and the app then asks to sign in again", async ({ page }) => {
  await signIn(page);
  await page.getByRole("button", { name: "Account" }).click();
  await page.getByRole("menuitem", { name: "Sign out" }).click();
  await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();
  await page.goto(app("#/agreements"));
  await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();
});

// ---- WEB-18 lane E: the signed-out pages and Verify on the approved canvas ------------------

test("sign-in checks the email's shape inline and clears the message once it is fixed", async ({ page }) => {
  await page.goto(app("#/signin"));
  const email = page.getByLabel("Email");
  await email.fill("dana");
  await page.getByLabel("Password", { exact: true }).fill("x");
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  await expect(page.locator("#signin-email-error")).toHaveText("Enter an email address like name@example.com.");
  await expect(email).toBeFocused();
  await email.fill("dana@acme.example");
  await expect(page.locator("#signin-email-error")).toBeEmpty();
  await expect(email).not.toHaveAttribute("aria-invalid", "true");
});

test("sign-in shows its side panel only where there is room for it", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto(app("#/signin"));
  const aside = page.getByRole("complementary", { name: "Agreements, signed and proven" });
  await expect(aside).toBeVisible();
  await page.setViewportSize({ width: 390, height: 844 });
  await expect(aside).toBeHidden();
  await expect(page.getByRole("button", { name: "Sign in", exact: true })).toBeVisible();
});

test("accept invite ticks its rules as the person types", async ({ page }) => {
  test.skip(REAL, "the invitation token comes from the mock");
  await page.goto(app("#/accept-invite?token=not-a-real-token"));
  const length = page.locator('[data-rule="length"]');
  const match = page.locator('[data-rule="match"]');
  await expect(length).not.toHaveClass(/is-met/);
  await page.getByLabel("Password", { exact: true }).fill("a-long-enough-password");
  await expect(length).toHaveClass(/is-met/);
  await expect(match).not.toHaveClass(/is-met/);
  await page.getByLabel("Password again").fill("a-long-enough-password");
  await expect(match).toHaveClass(/is-met/);
  await expect(page.locator("#inv-error")).toBeEmpty();
});

test("an invitation link without a token says so and offers sign-in", async ({ page }) => {
  await page.goto(app("#/accept-invite"));
  await expect(page.getByTestId("invite-missing")).toContainText("This link has no invitation in it.");
  await expect(page.getByRole("link", { name: "Go to sign in" }).first()).toBeVisible();
});

test.describe("verify on the sealed-receipt design", () => {
  test.skip(!WASM || REAL, "the WASM verifier is built locally by tools/build-webapp-wasm.sh");

  test("the verifier loads behind a skeleton line, then a check scans and ends on the receipt", async ({ page }) => {
    await page.goto("/verify.html?mock=1");
    await expect(page.getByTestId("verify-engine")).toHaveAttribute("data-state", "ready");
    await expect(page.getByTestId("verify-engine")).toContainText("Verifier ready");
    await page.getByTestId("trust-input").setInputFiles(fixture("sealed/trust-root.pem"));
    await page.getByTestId("verify-input").setInputFiles(fixture("sealed/p256-approval-blt.pdf"));
    await expect(page.getByTestId("verify-scanning")).toBeVisible();
    await expect(page.getByTestId("verify-scanning")).toContainText("Checking each signature against the document");
    const verdict = page.getByTestId("verdict");
    await expect(verdict).toHaveAttribute("data-state", "valid");
    await expect(verdict).toHaveClass(/is-ok/);
    await expect(verdict).toContainText("1 valid");
    await expect(page.getByRole("heading", { name: "Signed and unchanged" })).toBeFocused();
    // Every check the verifier reports, by name: seven rows, none invented.
    await expect(page.getByTestId("signature").locator(".os-vfy__check")).toHaveCount(7);
    await expectAccessible(page, "verify receipt");
  });

  test("a tampered PDF ends on a red receipt with the failing check marked", async ({ page }) => {
    await page.goto("/verify.html?mock=1");
    await page.getByTestId("trust-input").setInputFiles(fixture("signed/trust-root.der"));
    await page.getByTestId("verify-input").setInputFiles(fixture("signed/flip-range1.pdf"));
    const verdict = page.getByTestId("verdict");
    await expect(verdict).toHaveAttribute("data-state", "invalid");
    await expect(verdict).toHaveClass(/is-bad/);
    await expect(page.locator(".os-vfy__check.is-bad").first()).toBeVisible();
  });
});
