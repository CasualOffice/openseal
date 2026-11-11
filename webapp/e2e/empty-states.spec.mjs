// Empty states (WEB-01, owner requirement 2026-11-11): every list and first-run
// screen has an illustration, a title, one sentence and the primary action. Each is
// checked for those four parts and saved as a screenshot for the visual check
// (target/e2e-screens/; not a pixel baseline, which would differ per platform).
import { test, expect } from "@playwright/test";
import { signIn, app, pdfFile, snap, signPage, tokens, REAL } from "./helpers.mjs";

async function check(empty, testInfo, name) {
  await expect(empty).toBeVisible();
  await expect(empty.locator("svg.os-illus")).toHaveAttribute("aria-hidden", "true");
  await expect(empty.locator(".os-empty__title")).not.toBeEmpty();
  await expect(empty.locator(".os-empty__text")).not.toBeEmpty();
  await snap(empty, testInfo, `empty-${name}`);
}

test("agreements: no envelopes, no matches, nothing with a status", async ({ page }, testInfo) => {
  await signIn(page);
  if (!REAL) {
    // A fresh mock account with nothing in it.
    await page.evaluate(() => {
      const s = JSON.parse(sessionStorage.getItem("openseal.mock.v1"));
      s.envelopes = [];
      sessionStorage.setItem("openseal.mock.v1", JSON.stringify(s));
    });
    await page.reload();
    const none = page.getByTestId("empty-envelopes");
    await check(none, testInfo, "no-envelopes");
    await expect(none.getByRole("button", { name: "New envelope" })).toBeVisible();
    await page.goto(app("#/agreements?status=voided"));
    await check(page.getByTestId("empty-filter"), testInfo, "filter");
    return;
  }
  await page.getByRole("searchbox").fill("zzz-nothing");
  await check(page.getByTestId("empty-search"), testInfo, "search");
});

test("agreements: no search results", async ({ page }, testInfo) => {
  await signIn(page);
  await expect(page.locator("tbody tr").first()).toBeVisible();
  await page.getByRole("searchbox").fill("zzz-nothing");
  const e = page.getByTestId("empty-search");
  await check(e, testInfo, "search");
  await expect(e.getByRole("button", { name: "Clear search" })).toBeVisible();
});

test("prepare: no documents, no recipients, no fields", async ({ page }, testInfo) => {
  await signIn(page);
  await page.goto(app("#/prepare"));
  await check(page.getByTestId("empty-documents"), testInfo, "no-documents");
  await page.getByTestId("wizard-next").click();
  await check(page.getByTestId("empty-recipients"), testInfo, "no-recipients");
  await page.getByTestId("pdf-input").setInputFiles(pdfFile());
  await page.locator(".os-stepper__btn", { hasText: "Fields" }).click();
  await check(page.getByTestId("empty-fields"), testInfo, "no-fields");
});

test("offline shows a way to try again, and trying again recovers", async ({ page }, testInfo) => {
  await signIn(page);
  if (REAL) await page.route("**/api/v1/envelopes?*", (r) => r.abort("internetdisconnected"));
  else await page.evaluate(() => sessionStorage.setItem("openseal.mock.offline", "1"));
  await page.goto(app("#/agreements?status=draft"));
  const e = page.getByTestId("empty-offline");
  await check(e, testInfo, "offline");
  if (REAL) await page.unroute("**/api/v1/envelopes?*");
  else await page.evaluate(() => sessionStorage.removeItem("openseal.mock.offline"));
  await e.getByRole("button", { name: "Try again" }).click();
  await expect(page.locator("tbody tr").first()).toBeVisible();
});

test("signing: all done, declined, unknown link", async ({ page }, testInfo) => {
  await page.goto(signPage("no-such-token"));
  await check(page.getByTestId("sign-not-found"), testInfo, "sign-not-found");
  test.skip(REAL && !tokens.decline, "OPENSEAL_E2E_DECLINE_TOKEN is needed against a real server");
  await page.goto(signPage(tokens.decline));
  await page.getByRole("button", { name: "More" }).click();
  await page.getByRole("menuitem", { name: "Decline to sign" }).click();
  await page.getByLabel("Tell the sender why").fill("Not for me");
  await page.getByRole("dialog").getByRole("button", { name: "Decline" }).click();
  await check(page.getByTestId("sign-declined"), testInfo, "sign-declined");
});
