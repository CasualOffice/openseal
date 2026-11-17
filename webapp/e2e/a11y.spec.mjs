// Scenario 6 (WEB-01): axe-core on every sender screen, light and dark — zero serious
// or critical violations (WCAG 2.2 AA rule set).
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { test, expect } from "@playwright/test";
import { signIn, app, pdfFile, expectAccessible, REAL } from "./helpers.mjs";

const ROOT = path.resolve(fileURLToPath(new URL("../..", import.meta.url)));
const fixture = (p) => path.join(ROOT, "fixtures", p);
// The Verify page's verifier: built into webapp/ in mock mode (tools/build-webapp-wasm.sh,
// CI's e2e job), served by a real server (deploy/Dockerfile's wasm stage).
const WASM = fs.existsSync(path.join(ROOT, "webapp/vendor/openseal-wasm/casual_sign_wasm_bg.wasm"));

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
      await expect(page.locator(".os-agr-row[data-id]").first()).toBeVisible();
      await expectAccessible(page, `agreements (${scheme})`);
      // Search opens from its button in the list's header (WEB-17).
      await page.getByRole("button", { name: "Search agreements" }).click();
      await page.getByRole("searchbox").fill("zzz-nothing");
      await expect(page.getByTestId("empty-search")).toBeVisible();
      await expectAccessible(page, `agreements, no results (${scheme})`);
      if (!REAL) {
        await page.goto(app("#/agreements?folder=expired"));
        await expect(page.getByTestId("empty-filter")).toBeVisible();
        await expectAccessible(page, `agreements, empty filter (${scheme})`);
        await page.goto(app("#/agreements"));
        await page.locator(".os-agr-row[data-id]", { hasText: "Offer letter — Jordan Rivera" }).dblclick();
      } else {
        await page.getByTestId("empty-search").getByRole("button", { name: "Clear search" }).click();
        // A draft opens in the editor (A-02), so open the newest one that was sent.
        await page.locator('.os-agr-row[data-id]:not([data-status="draft"])').first().dblclick();
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
      await page.getByTestId("recipient-email").blur();
      await expectAccessible(page, `prepare, recipients step (${scheme})`);
      await page.getByTestId("wizard-next").click();
      await expect(page.locator(".os-page.is-loading")).toHaveCount(0);
      await page.locator(".os-palette").getByRole("button", { name: "Add Signature field" }).press("Enter");
      await expect(page.getByRole("heading", { name: "Signature field" })).toBeVisible();
      await expectAccessible(page, `prepare, field selected (${scheme})`);
      // On a real server the recipient and the field are saved before Next is offered:
      // wait for the app to stop holding it ("Every signer needs a field").
      await expect(page.getByTestId("wizard-next")).not.toHaveAttribute("aria-disabled", "true");
      await page.getByTestId("wizard-next").click();
      await expectAccessible(page, `prepare, review step (${scheme})`);
      await page.getByRole("button", { name: "Send", exact: true }).first().click();
      await expect(page.getByRole("dialog")).toBeVisible();
      await expectAccessible(page, `send dialog (${scheme})`);
    });

    // VS-07 (slice 7): verify.html at every state a visitor reaches: the start with the
    // verifier loaded, the valid receipt with its detail cards, the red receipt of a
    // tampered PDF, and a refused file.
    test("verify: start, valid, tampered and refused", async ({ page }) => {
      test.skip(!WASM && !REAL, "the WASM verifier is built locally by tools/build-webapp-wasm.sh");
      await page.goto(REAL ? "/verify.html" : "/verify.html?mock=1");
      await expect(page.locator("html")).toHaveAttribute("data-theme", scheme);
      await expect(page.getByTestId("verify-engine")).toHaveAttribute("data-state", "ready");
      await expectAccessible(page, `verify, start (${scheme})`);
      await page.getByTestId("trust-input").setInputFiles(fixture("sealed/trust-root.pem"));
      await page.getByTestId("verify-input").setInputFiles(fixture("sealed/p256-approval-blt.pdf"));
      await expect(page.getByTestId("verdict")).toHaveAttribute("data-state", "valid");
      await expectAccessible(page, `verify, valid (${scheme})`);
      await page.getByTestId("verify-another").click();
      await page.getByTestId("trust-input").setInputFiles(fixture("signed/trust-root.der"));
      await page.getByTestId("verify-input").setInputFiles(fixture("signed/flip-range1.pdf"));
      await expect(page.getByTestId("verdict")).toHaveAttribute("data-state", "invalid");
      await expectAccessible(page, `verify, tampered (${scheme})`);
      await page.getByTestId("verify-another").click();
      await page.getByTestId("verify-input").setInputFiles({ name: "note.pdf", mimeType: "application/pdf", buffer: Buffer.from("hello") });
      await expect(page.getByTestId("verify-problem")).toContainText("not a PDF");
      await expectAccessible(page, `verify, refused (${scheme})`);
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
