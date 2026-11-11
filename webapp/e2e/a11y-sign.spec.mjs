// Scenario 6, signer side (WEB-01): axe-core on every ceremony step at phone width,
// light and dark, plus the 44 px target rule on the signing page (SC 2.5.5).
import { test, expect } from "@playwright/test";
import { signPage, tokens, REAL, expectAccessible } from "./helpers.mjs";

for (const scheme of ["light", "dark"]) {
  test(`every ceremony step is accessible (${scheme})`, async ({ page }) => {
    test.skip(REAL && !tokens.sign, "OPENSEAL_E2E_SIGN_TOKEN is needed against a real server");
    await page.emulateMedia({ colorScheme: scheme });
    await page.setViewportSize({ width: 390, height: 844 });
    await page.goto(signPage(tokens.sign));
    await expect(page.getByRole("heading", { name: "Enter your access code" })).toBeVisible();
    await expectAccessible(page, `access code (${scheme})`);
    await page.getByLabel("Access code").fill(tokens.accessCode);
    await page.getByRole("button", { name: "Continue" }).click();
    await expect(page.getByRole("heading", { name: "Share your location?" })).toBeVisible();
    await expectAccessible(page, `location (${scheme})`);
    await page.getByRole("button", { name: "Don't share" }).click();
    await expect(page.getByRole("heading", { name: "Electronic records and signatures" })).toBeVisible();
    await expectAccessible(page, `consent (${scheme})`);
    await page.getByLabel("I agree to use electronic records and signatures.").check();
    await page.getByRole("button", { name: "Continue" }).click();
    await expect(page.locator("#guide-progress")).toBeVisible();
    await expect(page.locator(".os-sign__pages:not([aria-busy]) .os-page").first()).toBeVisible();
    await expect(page.locator(".os-page.is-loading")).toHaveCount(0);
    await expectAccessible(page, `documents (${scheme})`);
    await page.getByRole("button", { name: /Signature, required/ }).click();
    await expect(page.getByRole("dialog", { name: "Adopt your signature" })).toBeVisible();
    await expectAccessible(page, `adopt dialog (${scheme})`);
    await page.getByTestId("adopt-confirm").click();
    await page.getByRole("button", { name: "More" }).click();
    await expectAccessible(page, `more menu (${scheme})`);
  });
}

test("the signing page's controls are at least 44 px", async ({ page }) => {
  test.skip(REAL && !tokens.decline, "OPENSEAL_E2E_DECLINE_TOKEN is needed against a real server");
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto(signPage(tokens.decline));
  await expect(page.getByRole("heading", { name: "Electronic records and signatures" })).toBeVisible();
  for (const b of await page.locator(".os-sign__card .os-btn, .os-sign__bar .os-btn, .os-check--lg").all()) {
    const box = await b.boundingBox();
    if (!box) continue; // not shown on this screen
    expect(box.height, await b.textContent()).toBeGreaterThanOrEqual(44);
  }
});
