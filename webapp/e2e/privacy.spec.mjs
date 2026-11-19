// ASVS-16 and ASVS-18 in the browser: the profile panel's "Your data" section downloads
// the person's own data as a JSON file and asks before deleting the account (the demo
// user owns the organization, so the server's refusal is shown); Admin › Retention saves
// rules per data class, refuses what is not whole days, and shows the dry run.
// The server's own tests (`server/casual-sign-server/tests/privacy.rs`) prove the rules.

import { test, expect } from "@playwright/test";

import { app, signIn, REAL, expectAccessible } from "./helpers.mjs";

test.describe("mock: personal data and retention", () => {
  test.skip(REAL, "the mock's demo data; the server's tests cover the real routes");

  test("the profile downloads the person's data and explains why deleting is refused", async ({ page }) => {
    await signIn(page, "home");
    await page.locator("#account-btn").click();
    await page.getByRole("menuitem", { name: "Profile and signature" }).click();
    const panel = page.getByRole("dialog", { name: "Profile and signature" });
    const data = panel.getByTestId("profile-data");
    await expect(data).toBeVisible();
    const download = page.waitForEvent("download");
    await data.getByTestId("privacy-export").click();
    const file = await download;
    expect(file.suggestedFilename()).toBe("openseal-personal-data.json");
    await expect(page.getByText("Your data was downloaded.")).toBeVisible();

    await data.getByTestId("privacy-erase").click();
    const confirm = page.getByRole("dialog", { name: "Delete your account?" });
    await expect(confirm).toBeVisible();
    await expectAccessible(page, "erase confirmation");
    await confirm.getByRole("button", { name: "Delete my account" }).click();
    await expect(page.getByText(/Hand the role over first/)).toBeVisible();
  });

  test("retention rules save per class, refuse a bad value and show the dry run", async ({ page }) => {
    await signIn(page, "home");
    await page.goto(app("#/admin?section=retention"));
    const ended = page.getByLabel("Declined, voided and expired envelopes");
    await expect(ended).toHaveValue("");
    await ended.fill("0");
    await page.getByTestId("retention-save").click();
    await expect(page.getByText("Enter whole days from 1 to 36500, or leave it empty.")).toBeVisible();
    await ended.fill("30");
    await page.getByTestId("retention-save").click();
    await expect(page.getByText("Retention rules saved.")).toBeVisible();
    await page.getByTestId("retention-preview-btn").click();
    await expect(page.getByTestId("retention-preview-held")).toHaveText("Kept by a legal hold: 0");
    await expectAccessible(page, "retention");
    await page.reload();
    await expect(page.getByLabel("Declined, voided and expired envelopes")).toHaveValue("30");
  });
});
