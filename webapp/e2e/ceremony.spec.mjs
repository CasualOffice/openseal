// Scenario 3 (WEB-01): the signing ceremony on a 390 px wide phone screen — access
// code, location, consent, the Next-field guide, a drawn signature, a text value,
// finish — ends completed.
import { test, expect } from "@playwright/test";
import { signPage, tokens, REAL } from "./helpers.mjs";

test.use({ viewport: { width: 390, height: 844 }, geolocation: { latitude: 52.37, longitude: 4.89, accuracy: 25 }, permissions: ["geolocation"] });

test("access code, location, consent, guide, draw, fill, finish", async ({ page }) => {
  test.skip(REAL && !tokens.sign, "OPENSEAL_E2E_SIGN_TOKEN is needed against a real server (the link is emailed)");
  await page.goto(signPage(tokens.sign));

  // Identity: a wrong code is refused, the right one passes.
  await expect(page.getByRole("heading", { name: "Enter your access code" })).toBeVisible();
  await page.getByLabel("Access code").fill("0000");
  await page.getByRole("button", { name: "Continue" }).click();
  await expect(page.getByRole("alert")).toContainText("not right");
  await page.getByLabel("Access code").fill(tokens.accessCode);
  await page.getByRole("button", { name: "Continue" }).click();

  // Location, asked once because the envelope captures it (GEO-01).
  await expect(page.getByRole("heading", { name: "Share your location?" })).toBeVisible();
  await page.getByRole("button", { name: "Share my location" }).click();

  // Consent: the box must be ticked.
  await expect(page.getByRole("heading", { name: "Electronic records and signatures" })).toBeVisible();
  await page.getByRole("button", { name: "Continue" }).click();
  await expect(page.getByRole("alert")).toContainText("Tick the box");
  await page.getByLabel("I agree to use electronic records and signatures.").check();
  await page.getByRole("button", { name: "Continue" }).click();

  // Documents with the guide.
  const progress = page.locator("#guide-progress");
  await expect(progress).toHaveText("0 of 2 required");
  // WEB-18: Finish shows once nothing required is left; until then the guide says how many.
  await expect(page.getByRole("button", { name: "Finish" })).toBeHidden();
  await expect(page.locator("#guide-sub")).toHaveText("2 required fields left");
  await page.getByRole("button", { name: "Start" }).click();
  const text = page.getByRole("textbox", { name: /Job title/ });
  await expect(text).toBeFocused();
  await text.fill("Senior engineer");
  await text.press("Enter");
  await text.blur();
  await expect(progress).toHaveText("1 of 2 required");

  await page.getByRole("button", { name: "Next" }).click();
  const sign = page.getByRole("button", { name: /Signature, required/ });
  await expect(sign).toBeFocused();
  await sign.click();

  const dlg = page.getByRole("dialog", { name: "Adopt your signature" });
  await dlg.getByRole("tab", { name: "Draw" }).click();
  const pad = dlg.getByTestId("signature-pad");
  const box = await pad.boundingBox();
  await page.mouse.move(box.x + 20, box.y + box.height / 2);
  await page.mouse.down();
  for (let i = 1; i <= 10; i++) await page.mouse.move(box.x + 20 + i * 25, box.y + box.height / 2 + (i % 2 ? -15 : 15));
  await page.mouse.up();
  await dlg.getByTestId("adopt-confirm").click();
  await expect(dlg).toBeHidden();
  await expect(progress).toHaveText("2 of 2 required");
  await expect(page.locator('[data-field="signature"] img')).toBeVisible();

  await page.getByRole("button", { name: "Finish" }).click();
  // The review step (ADR-020): the pages with the values drawn in, then Finish.
  await expect(page.getByRole("heading", { name: "Review and finish" })).toBeVisible();
  await expect(page.getByTestId("review-page")).toHaveCount(2);
  await expect(page.getByTestId("review-page").first().locator(".os-flat--text")).toHaveText("Senior engineer");
  await expect(page.locator(".os-review")).toContainText("Senior engineer");
  await page.getByTestId("review-finish").click();
  await expect(page.getByTestId("sign-done")).toBeVisible();
  await expect(page.getByTestId("sign-done")).toContainText("Everyone has signed");
});

test("the typed signature is the keyboard path", async ({ page }) => {
  test.skip(REAL && !tokens.sign, "OPENSEAL_E2E_SIGN_TOKEN is needed against a real server");
  await page.goto(signPage(tokens.sign));
  await page.getByLabel("Access code").fill(tokens.accessCode);
  await page.getByLabel("Access code").press("Enter");
  await page.getByRole("button", { name: "Don't share" }).click();
  await page.getByLabel("I agree to use electronic records and signatures.").check();
  await page.getByLabel("I agree to use electronic records and signatures.").press("Enter");
  const sign = page.getByRole("button", { name: /Signature, required/ });
  await sign.focus();
  await page.keyboard.press("Enter");
  const dlg = page.getByRole("dialog", { name: "Adopt your signature" });
  await expect(dlg.getByLabel("Your full name")).toHaveValue("Jordan Rivera");
  await dlg.getByTestId("adopt-confirm").focus();
  await page.keyboard.press("Enter");
  await expect(dlg).toBeHidden();
  await expect(page.locator("#guide-progress")).toHaveText("1 of 2 required");
});

test("an unknown link says so", async ({ page }) => {
  await page.goto(signPage("no-such-token"));
  await expect(page.getByTestId("sign-not-found")).toBeVisible();
});
