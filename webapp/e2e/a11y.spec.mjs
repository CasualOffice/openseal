// Scenario 6 (WEB-01): axe-core on every sender screen, light and dark — zero serious
// or critical violations (WCAG 2.2 AA rule set).
import { test, expect } from "@playwright/test";
import { signIn, app, pdfFile, expectAccessible, REAL } from "./helpers.mjs";

for (const scheme of ["light", "dark"]) {
  test.describe(`${scheme} theme`, () => {
    test.use({ colorScheme: scheme });
    test.beforeEach(async ({ page }) => { await page.addInitScript((s) => { try { localStorage.setItem("openseal.theme", s); } catch { /* storage off */ } }, scheme); });

    test("sign-in", async ({ page }) => {
      await page.goto(app("#/signin"));
      await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();
      await expectAccessible(page, `sign-in (${scheme})`);
    });

    test("agreements, its empty states, and envelope detail", async ({ page }) => {
      await signIn(page);
      await expect(page.locator("tbody tr").first()).toBeVisible();
      await expectAccessible(page, `agreements (${scheme})`);
      await page.getByRole("searchbox").fill("zzz-nothing");
      await expect(page.getByTestId("empty-search")).toBeVisible();
      await expectAccessible(page, `agreements, no results (${scheme})`);
      if (!REAL) {
        await page.goto(app("#/agreements?folder=expired"));
        await expect(page.getByTestId("empty-filter")).toBeVisible();
        await expectAccessible(page, `agreements, empty filter (${scheme})`);
        await page.goto(app("#/agreements"));
        await page.getByRole("link", { name: "Offer letter — Jordan Rivera" }).click();
      } else {
        await page.locator("tbody tr a").first().click();
      }
      await expect(page.getByRole("heading", { name: "Audit trail" })).toBeVisible();
      await expectAccessible(page, `envelope detail (${scheme})`);
    });

    test("prepare: empty, with a document, with a selected field, and the send dialog", async ({ page }) => {
      await signIn(page);
      await page.goto(app("#/prepare"));
      await expect(page.getByTestId("empty-documents")).toBeVisible();
      await expectAccessible(page, `prepare, empty (${scheme})`);
      await page.getByTestId("pdf-input").setInputFiles(pdfFile());
      await expect(page.getByTestId("doc-card")).toHaveCount(1);
      await expectAccessible(page, `prepare, documents step (${scheme})`);
      await page.getByTestId("wizard-next").click();
      await expectAccessible(page, `prepare, no recipients (${scheme})`);
      await page.getByRole("button", { name: "Add recipient" }).first().click();
      await page.getByTestId("recipient-name").fill("Ari Access");
      await page.getByTestId("recipient-email").fill("ari@example.com");
      await expectAccessible(page, `prepare, recipients step (${scheme})`);
      await page.getByTestId("wizard-next").click();
      await expect(page.locator(".os-page.is-loading")).toHaveCount(0);
      await page.locator(".os-palette").getByRole("button", { name: "Add Signature field" }).click();
      await expect(page.getByLabel("Left")).toBeVisible();
      await expectAccessible(page, `prepare, field selected (${scheme})`);
      await page.getByTestId("wizard-next").click();
      await expectAccessible(page, `prepare, review step (${scheme})`);
      await page.getByRole("button", { name: "Send", exact: true }).first().click();
      await expect(page.getByRole("dialog")).toBeVisible();
      await expectAccessible(page, `send dialog (${scheme})`);
    });
  });
}

test("at phone width the navigation is a menu and the list still reads", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await signIn(page);
  await expect(page.getByRole("navigation", { name: "Main" })).not.toBeInViewport();
  await page.getByRole("button", { name: "Menu" }).click();
  await expect(page.getByRole("link", { name: "Agreements" })).toBeInViewport();
  const scrollW = await page.evaluate(() => document.documentElement.scrollWidth);
  expect(scrollW).toBeLessThanOrEqual(390);
  await expectAccessible(page, "agreements at 390 px");
});
