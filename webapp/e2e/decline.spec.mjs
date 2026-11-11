// Scenario 4 (WEB-01): decline with a reason, then the sender sees it.
import { test, expect } from "@playwright/test";
import { signPage, tokens, REAL, signIn } from "./helpers.mjs";

test("decline needs a reason, ends the ceremony, and the sender sees it", async ({ page }) => {
  test.skip(REAL && !tokens.decline, "OPENSEAL_E2E_DECLINE_TOKEN is needed against a real server (the link is emailed)");
  await page.goto(signPage(tokens.decline));
  await expect(page.getByRole("heading", { name: "Electronic records and signatures" })).toBeVisible();
  await page.getByRole("button", { name: "More" }).click();
  await page.getByRole("menuitem", { name: "Decline to sign" }).click();
  const dlg = page.getByRole("dialog", { name: "Decline to sign?" });
  await dlg.getByRole("button", { name: "Decline" }).click();
  await expect(dlg.getByText("This is required.")).toBeVisible();
  await dlg.getByLabel("Tell the sender why").fill("The fee is wrong");
  await dlg.getByRole("button", { name: "Decline" }).click();
  await expect(page.getByTestId("sign-declined")).toBeVisible();

  // Opening the link again shows the outcome, not the documents.
  await page.reload();
  await expect(page.getByTestId("sign-declined")).toBeVisible();

  test.skip(REAL, "the sender's side is checked with the seeded mock envelope");
  await signIn(page);
  await page.getByRole("navigation", { name: "Folders" }).getByRole("link", { name: /^Declined\s*\d*$/ }).click();
  await page.getByRole("link", { name: "Vendor services agreement" }).click();
  await expect(page.getByText("Reason given: The fee is wrong")).toBeVisible();
});
