// Screenshots of the main screens for people to look at (WEB-01 acceptance), saved
// under target/e2e-screens/: sign-in, dashboard, editor with a placed field, the
// signing page at 390 px, in light and dark. Not pixel baselines.
import { test, expect } from "@playwright/test";
import { signIn, app, pdfFile, snap, signPage, tokens, REAL } from "./helpers.mjs";

for (const scheme of ["light", "dark"]) {
  test(`screens (${scheme})`, async ({ page }, testInfo) => {
    test.skip(testInfo.project.name !== "chromium", "one browser is enough for the pictures");
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
    await expect(page.locator(".os-page.is-loading")).toHaveCount(0);
    await page.getByRole("button", { name: "Add recipient" }).first().click();
    await page.getByTestId("recipient-name").fill("Avery Chen");
    await page.getByTestId("recipient-email").fill("avery@example.com");
    await page.getByRole("button", { name: "Add recipient" }).first().click();
    await page.getByTestId("recipient-name").nth(1).fill("Sam Patel");
    await page.getByTestId("recipient-email").nth(1).fill("sam@example.com");
    await page.getByLabel("Placing fields for").selectOption({ index: 0 });
    await page.locator(".os-palette").getByRole("button", { name: "Add Signature field" }).click();
    await page.locator(".os-palette").getByRole("button", { name: "Add Date signed field" }).click();
    await page.getByLabel("Placing fields for").selectOption({ index: 1 });
    await page.locator(".os-palette").getByRole("button", { name: "Add Signature field" }).click();
    await page.locator(".os-palette").getByRole("button", { name: "Add Text field" }).click();
    await snap(page, testInfo, `${scheme}-4-editor`);

    if (REAL && !tokens.sign) return;
    await page.setViewportSize({ width: 390, height: 844 });
    await page.goto(signPage(tokens.sign));
    await page.getByLabel("Access code").fill(tokens.accessCode);
    await page.getByRole("button", { name: "Continue" }).click();
    await page.getByRole("button", { name: "Don't share" }).click();
    await snap(page, testInfo, `${scheme}-5-sign-consent-390`);
    await page.getByLabel("I agree to use electronic records and signatures.").check();
    await page.getByRole("button", { name: "Continue" }).click();
    await expect(page.locator(".os-page.is-loading")).toHaveCount(0);
    await page.getByRole("button", { name: "Start" }).click();
    await snap(page, testInfo, `${scheme}-6-sign-document-390`);
    await page.getByRole("button", { name: /Signature, required/ }).click();
    await snap(page, testInfo, `${scheme}-7-sign-adopt-390`);
  });
}
