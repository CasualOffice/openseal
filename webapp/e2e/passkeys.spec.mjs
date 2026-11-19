// CON-13 in the browser: a staff passkey set up, used at sign-in and at step-up, with
// Chromium's virtual authenticator (CDP `WebAuthn.addVirtualAuthenticator`) standing in
// for the person's device, so the browser makes real WebAuthn credentials.
//
// Mock mode: the profile's "Add a passkey", the sign-in card's passkey step, and the
// step-up prompt a stale session raises (the mock's clock), "Continue with passkey".
// Real mode (`OPENSEAL_E2E_BASE_URL`): the server verifies what Chromium made. It needs
// an administrator of its own, `OPENSEAL_E2E_PASSKEY_EMAIL` and `_PASSWORD`, with no
// second factor yet (a passkey would change the run's shared administrator's factor):
// enrolment on the sign-in card with "Set up a passkey instead", the passkey step at the
// next sign-in, and the step-up prompt opened directly (the server's clock cannot be
// moved), each answered by the virtual authenticator and checked by the server.
// WebAuthn needs a domain, not an IP address: pages are opened on `localhost`.

import { test, expect } from "@playwright/test";

import { REAL } from "./helpers.mjs";
import { MOCK } from "../mock.js";

const creds = REAL
  ? { email: process.env.OPENSEAL_E2E_PASSKEY_EMAIL || "", password: process.env.OPENSEAL_E2E_PASSKEY_PASSWORD || "" }
  : { email: MOCK.email, password: MOCK.password };

test.skip(({ browserName }) => browserName !== "chromium", "the virtual authenticator is Chromium's (CDP)");
test.skip(REAL && !creds.email, "needs OPENSEAL_E2E_PASSKEY_EMAIL and _PASSWORD: an administrator with no second factor");

/// The app on `localhost` (an RP id cannot be an IP address).
function at(baseURL, hash) {
  const u = new URL(`/app.html${REAL ? "" : "?mock=1"}${hash}`, baseURL);
  if (u.hostname === "127.0.0.1") u.hostname = "localhost";
  return u.href;
}

async function authenticator(page) {
  const cdp = await page.context().newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  const { authenticatorId } = await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: { protocol: "ctap2", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true },
  });
  return { cdp, authenticatorId };
}

async function credentials(a) {
  return (await a.cdp.send("WebAuthn.getCredentials", { authenticatorId: a.authenticatorId })).credentials;
}

async function passwordStep(page, baseURL) {
  await page.goto(at(baseURL, "#/signin"));
  await page.getByLabel("Email").fill(creds.email);
  await page.getByLabel("Password").fill(creds.password);
  await page.getByRole("button", { name: "Sign in" }).click();
}

const home = (page) => page.getByRole("heading", { name: "Home", exact: true });

async function openProfile(page) {
  await page.locator("#account-btn").click();
  await page.getByRole("menuitem", { name: "Profile and signature" }).click();
  const panel = page.getByRole("dialog", { name: "Profile and signature" });
  await expect(panel).toBeVisible();
  return panel;
}

async function signOut(page) {
  await page.locator("#account-btn").click();
  await page.getByRole("menuitem", { name: "Sign out" }).click();
  await expect(page.getByRole("button", { name: "Sign in" })).toBeVisible();
}

/// The sign-in card's passkey step, answered by the virtual authenticator.
async function passkeyStep(page) {
  await expect(page.getByRole("heading", { name: "Use your passkey" })).toBeVisible();
  await page.getByRole("button", { name: "Use passkey" }).click();
  await expect(home(page)).toBeVisible();
}

test.describe("mock", () => {
  test.skip(REAL, "the mock's clock makes the session stale; real mode below");

  test("a passkey is added in the profile, passes the next sign-in, and answers step-up", async ({ page, baseURL }) => {
    await page.clock.install({ time: new Date("2026-11-19T09:00:00Z") });
    const a = await authenticator(page);
    await passwordStep(page, baseURL);
    await expect(home(page)).toBeVisible();

    // Add one: the browser's ceremony, then the recovery codes of a first factor.
    let panel = await openProfile(page);
    await panel.getByTestId("passkey-add").click();
    const codes = page.getByRole("dialog", { name: "Your new recovery codes" });
    await expect(codes).toBeVisible();
    await expect(codes.getByTestId("factors-recovery-codes").locator("code")).toHaveCount(10);
    await codes.getByRole("button", { name: "I saved them, continue" }).click();
    await expect(panel.getByTestId("passkey-row")).toHaveCount(1);
    expect(await credentials(a)).toHaveLength(1);
    await page.keyboard.press("Escape");

    // The next sign-in asks for it first.
    await signOut(page);
    await passwordStep(page, baseURL);
    await passkeyStep(page);

    // Six minutes on, renaming it asks the person to confirm it's them: the password,
    // then the passkey.
    await page.clock.fastForward("06:00");
    panel = await openProfile(page);
    await panel.getByTestId("passkey-rename").click();
    const rename = page.getByRole("dialog", { name: "Rename passkey" });
    await rename.getByLabel("Name").fill("Work laptop");
    await rename.getByTestId("passkey-rename-save").click();
    const prompt = page.getByRole("dialog", { name: "Confirm it's you" });
    await expect(prompt).toBeVisible();
    await expect(prompt.getByTestId("stepup-confirm")).toHaveCount(0);
    await prompt.getByLabel("Password").fill(creds.password);
    await prompt.getByTestId("stepup-passkey").click();
    await expect(prompt).toHaveCount(0);
    await expect(page.getByText("Passkey renamed.")).toBeVisible();
    await expect(panel.getByTestId("passkey-row").first()).toContainText("Work laptop");
  });
});

test.describe("real server", () => {
  test.skip(!REAL, "runs against a real server only (OPENSEAL_E2E_BASE_URL)");

  test("enrol with a passkey, pass the next sign-in and step-up with it; the server checks each", async ({ page, baseURL }) => {
    const a = await authenticator(page);
    await passwordStep(page, baseURL);
    // An administrator with no factor sets one up: a passkey instead of the app.
    await expect(page.getByRole("heading", { name: "Set up two-step verification" })).toBeVisible();
    await page.getByRole("button", { name: "Set up a passkey instead" }).click();
    await expect(page.getByTestId("mfa-recovery-codes").locator("code")).toHaveCount(10);
    await page.getByRole("button", { name: "I saved them, continue" }).click();
    await expect(home(page)).toBeVisible();
    expect(await credentials(a)).toHaveLength(1);

    await signOut(page);
    await passwordStep(page, baseURL);
    await passkeyStep(page);
    const counted = (await credentials(a))[0].signCount;
    expect(counted).toBeGreaterThan(0);

    // Step-up, as a sensitive action would open it: the server takes the passkey.
    const until = page.evaluate(async () => {
      const { createClient } = await import(new URL("api.js", location.href).href);
      const { stepUpDialog } = await import(new URL("stepup.js", location.href).href);
      const api = createClient({ store: sessionStorage });
      const ok = await stepUpDialog(api);
      return ok ? (await api.session()).reauthenticated_until : null;
    });
    const prompt = page.getByRole("dialog", { name: "Confirm it's you" });
    await expect(prompt).toBeVisible();
    await prompt.getByLabel("Password").fill(creds.password);
    await prompt.getByTestId("stepup-passkey").click();
    expect(await until).toBeTruthy();
    expect((await credentials(a))[0].signCount).toBeGreaterThan(counted);
  });
});
