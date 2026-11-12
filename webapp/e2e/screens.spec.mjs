// Screenshots of the main screens for people to look at (WEB-01 acceptance), saved
// under target/e2e-screens/: sign-in, dashboard, editor with a placed field, the
// signing page at 390 px, in light and dark. Not pixel baselines.
import { test, expect } from "@playwright/test";
import { signIn, app, pdfFile, snap, signPage, tokens, REAL, placingFor } from "./helpers.mjs";

for (const scheme of ["light", "dark"]) {
  test(`screens (${scheme})`, async ({ page }, testInfo) => {
    test.skip(testInfo.project.name !== "chromium", "one browser is enough for the pictures");
    await page.addInitScript((s) => { try { localStorage.setItem("openseal.theme", s); } catch { /* storage off */ } }, scheme);
    await page.emulateMedia({ colorScheme: scheme });
    await page.setViewportSize({ width: 1366, height: 860 });
    await page.goto(app("#/signin"));
    await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();
    await snap(page, testInfo, `${scheme}-1-signin`);

    await signIn(page);
    await expect(page.locator("tbody tr").first()).toBeVisible();
    await snap(page, testInfo, `${scheme}-2-dashboard`);

    if (!REAL) {
      await page.getByRole("link", { name: "Offer letter — Jordan Rivera" }).click();
      await expect(page.getByRole("heading", { name: "Audit trail" })).toBeVisible();
      await snap(page, testInfo, `${scheme}-3-envelope`);
    }

    await page.goto(app("#/prepare"));
    await page.getByTestId("pdf-input").setInputFiles(pdfFile());
    await expect(page.getByTestId("doc-card")).toHaveCount(1);
    await snap(page, testInfo, `${scheme}-4a-prepare-documents`);
    await page.getByTestId("wizard-next").click();
    await page.getByRole("button", { name: "Add recipient" }).first().click();
    await page.getByTestId("recipient-name").fill("Avery Chen");
    await page.getByTestId("recipient-email").fill("avery@example.com");
    await page.getByRole("button", { name: "Add recipient" }).first().click();
    await page.getByTestId("recipient-name").nth(1).fill("Sam Patel");
    await page.getByTestId("recipient-email").nth(1).fill("sam@example.com");
    await snap(page, testInfo, `${scheme}-4b-prepare-recipients`);
    await page.getByTestId("wizard-next").click();
    await expect(page.locator(".os-page.is-loading")).toHaveCount(0);
    await placingFor(page, 0);
    await page.locator(".os-palette").getByRole("button", { name: "Add Signature field" }).press("Enter");
    await page.locator(".os-palette").getByRole("button", { name: "Add Date signed field" }).press("Enter");
    await placingFor(page, 1);
    await page.locator(".os-palette").getByRole("button", { name: "Add Signature field" }).press("Enter");
    await page.locator(".os-palette").getByRole("button", { name: "Add Text field" }).press("Enter");
    await snap(page, testInfo, `${scheme}-4c-prepare-fields`);
    await page.getByTestId("wizard-next").click();
    await snap(page, testInfo, `${scheme}-4d-prepare-review`);

    if (REAL && !tokens.sign) return;
    await page.setViewportSize({ width: 390, height: 844 });
    await page.goto(signPage(tokens.sign));
    await page.getByLabel("Access code").fill(tokens.accessCode);
    await page.getByRole("button", { name: "Continue" }).click();
    await page.getByRole("button", { name: "Don't share" }).click();
    await snap(page, testInfo, `${scheme}-5-sign-consent-390`);
    await page.getByLabel("I agree to use electronic records and signatures.").check();
    await page.getByRole("button", { name: "Continue" }).click();
    await expect(page.locator(".os-sign__pages:not([aria-busy]) .os-page").first()).toBeVisible();
    await expect(page.locator(".os-page.is-loading")).toHaveCount(0);
    await page.getByRole("button", { name: "Start" }).click();
    await snap(page, testInfo, `${scheme}-6-sign-document-390`);
    await page.getByRole("button", { name: /Signature, required/ }).click();
    await snap(page, testInfo, `${scheme}-7-sign-adopt-390`);
  });
}
