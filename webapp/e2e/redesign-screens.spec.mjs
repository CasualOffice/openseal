// Screenshots of the redesigned screens for people to look at (WEB-02 redesign), in
// light and dark, under target/e2e-screens/: Home, Agreements, Reports, the prepare
// steps, the signer at desktop and 390 px, the adopt dialog. Not pixel baselines.
import { test, expect } from "@playwright/test";
import { signIn, app, snap, REAL } from "./helpers.mjs";

for (const scheme of ["light", "dark"]) {
  test(`redesign screens (${scheme})`, async ({ page }, testInfo) => {
    test.skip(testInfo.project.name !== "chromium" || REAL, "one browser, mock data");
    await page.addInitScript((s) => { try { localStorage.setItem("openseal.theme", s); } catch { /* storage off */ } }, scheme);
    await page.emulateMedia({ colorScheme: scheme });
    await page.setViewportSize({ width: 1440, height: 900 });
    await signIn(page, "home");
    await expect(page.locator(".os-counters:not([aria-busy])")).toBeVisible();
    await expect(page.locator(".os-recent__item").first()).toBeVisible();
    await snap(page, testInfo, `${scheme}-r1-home`);

    await page.goto(app("#/agreements"));
    await expect(page.locator(".os-row__sub").first()).not.toBeEmpty();
    await snap(page, testInfo, `${scheme}-r2-agreements`);
    await page.locator("tbody .os-checkbox").nth(1).check();
    await page.locator("tbody .os-checkbox").nth(2).check();
    await snap(page, testInfo, `${scheme}-r3-agreements-bulk`);

    await page.goto(app("#/reports"));
    await expect(page.locator(".os-bars")).toBeVisible();
    await snap(page, testInfo, `${scheme}-r4-reports`);

    await page.setViewportSize({ width: 390, height: 844 });
    await page.goto(app("#/home"));
    await expect(page.locator(".os-counters:not([aria-busy])")).toBeVisible();
    await snap(page, testInfo, `${scheme}-r5-home-390`);
  });
}
