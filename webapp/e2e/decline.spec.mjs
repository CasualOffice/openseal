// Scenario 4 (WEB-01): decline with a reason, then the sender sees it.
import { test, expect } from "@playwright/test";
import { signPage, tokens, REAL, signIn } from "./helpers.mjs";

test("decline needs a reason, ends the ceremony, and the sender sees it", async ({ page, isMobile }) => {
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
  // Home's "Declined or expired" opens the list of what ended; the row opens the envelope:
  // a double click on a desktop; on a phone a tap opens the full-page inspector over the
  // list (a second tap would land on it), and its Open goes to the envelope.
  await signIn(page, "home");
  await page.getByTestId("counter-action").click();
  const row = page.locator(".os-agr-row[data-id]", { hasText: "Vendor services agreement" });
  if (isMobile) {
    await row.click();
    await page.getByTestId("inspector").getByTestId("inspector-open").click();
  } else {
    await row.dblclick();
  }
  await expect(page.getByTestId("decline-callout").getByText("Reason given: The fee is wrong")).toBeVisible();
  // Said once, in the callout: not again on the recipient's row.
  await expect(page.getByText("Reason given: The fee is wrong")).toHaveCount(1);
});
