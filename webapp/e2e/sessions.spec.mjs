// ASVS-06 and ASVS-07 in the browser: the person's sessions in the profile panel (this
// one marked, any other signed out), and the step-up prompt a sensitive action raises
// when the last proof of the password is more than five minutes old: the person enters
// it, and the action goes through without being started again.
//
// Mock mode drives the clock (Playwright's `page.clock`) to make the session stale. On a
// real server (`OPENSEAL_E2E_BASE_URL`), the list is checked as the Compose stack serves
// it; the prompt needs the clock, so it is mock-only (the server's own tests,
// `server/casual-sign-server/tests/sessions.rs`, prove the refusal and the window).

import { test, expect } from "@playwright/test";

import { app, signIn, creds, REAL, expectAccessible } from "./helpers.mjs";

async function openProfile(page) {
  await page.locator("#account-btn").click();
  await page.getByRole("menuitem", { name: "Profile and signature" }).click();
  const panel = page.getByRole("dialog", { name: "Profile and signature" });
  await expect(panel).toBeVisible();
  return panel;
}

test("the profile lists this session, marked, among the person's sessions", async ({ page }) => {
  await signIn(page, "home");
  const panel = await openProfile(page);
  const list = panel.getByTestId("sessions-list");
  await expect(list.getByTestId("session-row").first()).toBeVisible();
  const current = list.locator('[data-testid="session-row"][data-current="true"]');
  await expect(current).toHaveCount(1);
  await expect(current.getByTestId("session-current")).toHaveText("This browser");
  await expect(current.getByTestId("session-end")).toHaveCount(0);
  await expectAccessible(page, "profile sessions");
});

test.describe("mock: step-up", () => {
  test.skip(REAL, "needs the mock's clock; the server's tests prove the window");

  test("signing another session out after five minutes asks for the password, then signs it out", async ({ page }) => {
    await page.clock.install({ time: new Date("2026-11-19T09:00:00Z") });
    await signIn(page, "home");
    const panel = await openProfile(page);
    const rows = panel.getByTestId("sessions-list").getByTestId("session-row");
    await expect(rows).toHaveCount(3);
    await expect(rows.first()).toHaveAttribute("data-current", "true");

    // Just signed in: no prompt.
    await rows.nth(1).getByTestId("session-end").click();
    await expect(page.getByText("Signed out of that session.")).toBeVisible();
    await expect(rows).toHaveCount(2);

    // Six minutes on: the prompt; a wrong password is said beside the field.
    await page.clock.fastForward("06:00");
    await rows.nth(1).getByTestId("session-end").click();
    const prompt = page.getByRole("dialog", { name: "Confirm it's you" });
    await expect(prompt).toBeVisible();
    await expectAccessible(page, "step-up prompt");
    await prompt.getByLabel("Password").fill("not the password");
    await prompt.getByTestId("stepup-confirm").click();
    await expect(prompt.getByText("That password is not correct.")).toBeVisible();
    await prompt.getByLabel("Password").fill(creds.password);
    await prompt.getByTestId("stepup-confirm").click();
    await expect(prompt).toHaveCount(0);
    // The action went through without being asked for again.
    await expect(rows).toHaveCount(1);
    await expect(panel.getByTestId("sessions-note")).toHaveText("You are not signed in anywhere else.");
  });

  test("a new API key on a stale session asks for the password; cancelling creates nothing", async ({ page }) => {
    await page.clock.install({ time: new Date("2026-11-19T09:00:00Z") });
    await signIn(page, "home");
    await page.clock.fastForward("06:00");
    await page.goto(app("#/admin?section=api"));
    const create = async () => {
      await page.getByRole("button", { name: "New API client" }).first().click();
      const dlg = page.getByRole("dialog", { name: "New API client" });
      await dlg.getByLabel("Name").fill("Billing sync");
      await dlg.getByRole("button", { name: "Create" }).click();
      return dlg;
    };
    let dlg = await create();
    let prompt = page.getByRole("dialog", { name: "Confirm it's you" });
    await expect(prompt).toBeVisible();
    await prompt.getByRole("button", { name: "Cancel" }).click();
    await expect(prompt).toHaveCount(0);
    await expect(page.getByRole("dialog", { name: "Copy the secret now" })).toHaveCount(0);
    await dlg.getByRole("button", { name: "Cancel" }).click();

    dlg = await create();
    prompt = page.getByRole("dialog", { name: "Confirm it's you" });
    await prompt.getByLabel("Password").fill(creds.password);
    await prompt.getByTestId("stepup-confirm").click();
    const secret = page.getByRole("dialog", { name: "Copy the secret now" });
    await expect(secret.getByTestId("secret-value")).toHaveValue(/^osk_/);
  });
});
