// The app shell on phones and desktops (UX-04): the drawer, search, panels and toasts
// across navigation, the missing page, the account and help menus, notifications,
// sign-in, the verify page's bar and the public site. Each check runs at 1440 and 390
// where the two differ. Screens for people under target/e2e-screens/shell-*.

import { test, expect } from "@playwright/test";
import { app, signIn, creds, expectAccessible, snap, REAL } from "./helpers.mjs";

const WIDTHS = [["desktop", { width: 1440, height: 900 }], ["phone", { width: 390, height: 844 }]];

/// Every element Tab reaches from the page's start, as ids or tag names, `max` presses.
async function tabStops(page, max = 40) {
  const seen = [];
  await page.locator("body").focus();
  for (let i = 0; i < max; i++) {
    await page.keyboard.press("Tab");
    seen.push(await page.evaluate(() => {
      const a = document.activeElement;
      return { inNav: !!a?.closest?.("#nav"), text: (a?.textContent || "").trim().slice(0, 30) };
    }));
  }
  return seen;
}

test.describe("phone drawer", () => {
  test.use({ viewport: { width: 390, height: 844 } });

  test("Escape and a scrim tap close the drawer; it starts under the bar; it is out of the tab order while closed", async ({ page }, testInfo) => {
    await signIn(page, "home");
    const toggle = page.locator("#nav-toggle");
    const nav = page.locator("#nav");
    const scrim = page.locator("#nav-scrim");

    // Closed: no section link can take focus.
    await expect(nav).toHaveJSProperty("inert", true);
    expect((await tabStops(page)).filter((s) => s.inNav), "drawer links in the tab order while closed").toEqual([]);

    // Open: under the bar (the demo banner is above it), a scrim, focus on the first link.
    await toggle.click();
    await expect(toggle).toHaveAttribute("aria-expanded", "true");
    await expect(scrim).toBeVisible();
    await expect(nav.getByRole("link", { name: "Home" })).toBeFocused();
    const barBottom = await page.locator(".os-topbar").evaluate((b) => b.getBoundingClientRect().bottom);
    const navTop = await nav.evaluate((n) => n.getBoundingClientRect().top);
    expect(Math.abs(navTop - barBottom), "drawer top at the bar's bottom").toBeLessThanOrEqual(1);
    await expect(toggle).toBeVisible();
    await snap(page, testInfo, "shell-drawer-open");
    await expectAccessible(page, "drawer open");

    // Escape closes and returns focus to Menu.
    await page.keyboard.press("Escape");
    await expect(toggle).toHaveAttribute("aria-expanded", "false");
    await expect(scrim).toBeHidden();
    await expect(toggle).toBeFocused();
    await expect(nav).toHaveJSProperty("inert", true);

    // A tap on the scrim closes it.
    await toggle.click();
    await expect(scrim).toBeVisible();
    await page.mouse.click(370, 600);
    await expect(toggle).toHaveAttribute("aria-expanded", "false");
    await expect(scrim).toBeHidden();

    // Opening another menu closes it.
    await toggle.click();
    await expect(scrim).toBeVisible();
    await page.locator("#account-btn").click();
    await expect(page.getByRole("menu", { name: "Account" })).toBeVisible();
    await expect(toggle).toHaveAttribute("aria-expanded", "false");
    await expect(scrim).toBeHidden();
  });

  test("a section chosen in the drawer opens and the drawer closes", async ({ page }) => {
    await signIn(page, "home");
    await page.locator("#nav-toggle").click();
    await page.locator("#nav").getByRole("link", { name: "Templates" }).click();
    await expect(page.getByRole("heading", { name: "Templates", level: 1 })).toBeVisible();
    await expect(page.locator("#nav-scrim")).toBeHidden();
    await expect(page.locator("#nav")).toHaveJSProperty("inert", true);
  });
});

test("at 1440 the sections are in the bar and in the tab order", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await signIn(page, "home");
  await expect(page.locator("#nav")).toHaveJSProperty("inert", false);
  await expect(page.locator("#nav-toggle")).toBeHidden();
  expect((await tabStops(page)).some((s) => s.inNav && s.text === "Agreements")).toBe(true);
});

for (const [name, viewport] of WIDTHS) {
  test.describe(`at ${viewport.width}`, () => {
    test.use({ viewport });

    test("search is reachable, from the bar and with /", async ({ page }, testInfo) => {
      await signIn(page, "home");
      const search = page.getByRole("searchbox", { name: "Search agreements" });
      if (name === "phone") {
        await expect(search).toBeHidden();
        const toggle = page.getByRole("button", { name: "Search agreements" });
        await toggle.click();
        await expect(search).toBeVisible();
        await expect(search).toBeFocused();
        await snap(page, testInfo, "shell-search-open");
        await page.keyboard.press("Escape");
        await expect(search).toBeHidden();
        await expect(toggle).toBeFocused();
      }
      // "/" from Home, not only from Agreements.
      await page.locator("main").focus();
      await page.keyboard.press("/");
      await expect(search).toBeVisible();
      await expect(search).toBeFocused();
      await search.fill("NDA");
      await search.press("Enter");
      await expect(page).toHaveURL(/#\/agreements\?q=NDA/);
      await expect(page.getByRole("heading", { name: "Agreements", level: 1 })).toBeVisible();
    });

    test("navigating with a side panel open closes it; with input in it, it asks first", async ({ page }) => {
      await signIn(page, "home");
      await page.goto(app("#/admin"));
      await page.getByRole("button", { name: "Invite user" }).click();
      const panel = page.getByRole("dialog", { name: "Invite user" });
      await expect(panel).toBeVisible();
      const goTemplates = async () => {
        if (name === "phone") { await page.locator("#nav-toggle").click(); await page.locator("#nav").getByRole("link", { name: "Templates" }).click(); }
        else await page.locator("#nav").getByRole("link", { name: "Templates" }).click();
      };
      // Untouched: it simply closes.
      await goTemplates();
      await expect(page.getByRole("heading", { name: "Templates", level: 1 })).toBeVisible();
      await expect(panel).toHaveCount(0);

      // Typed into: asked; Cancel keeps the panel and the address.
      await page.goto(app("#/admin"));
      await page.getByRole("button", { name: "Invite user" }).click();
      await panel.getByLabel("Email").fill("kai@example.com");
      await goTemplates();
      const ask = page.getByRole("dialog", { name: "Discard your changes?" });
      await expect(ask).toBeVisible();
      await ask.getByRole("button", { name: "Cancel" }).click();
      await expect(panel).toBeVisible();
      await expect(panel.getByLabel("Email")).toHaveValue("kai@example.com");
      await expect(page).toHaveURL(/#\/admin$/);
      // Discard: the panel goes and the new screen shows.
      await goTemplates();
      await page.getByRole("dialog", { name: "Discard your changes?" }).getByRole("button", { name: "Discard changes" }).click();
      await expect(page.getByRole("heading", { name: "Templates", level: 1 })).toBeVisible();
      await expect(panel).toHaveCount(0);
    });

    test("an unknown address shows that the page does not exist", async ({ page }, testInfo) => {
      await signIn(page, "home");
      await page.goto(app("#/nope"));
      const empty = page.getByTestId("empty-not-found");
      await expect(empty).toBeVisible();
      await expect(empty).toContainText("This page does not exist");
      await expect(page.getByRole("heading", { name: "Home", exact: true })).toHaveCount(0);
      await expectAccessible(page, "not found");
      await snap(page, testInfo, `shell-404-${name}`);
      await empty.getByRole("button", { name: "Go to Home" }).click();
      await expect(page.getByRole("heading", { name: "Home", exact: true })).toBeVisible();
    });

    test("sign-in: an error under each field, an alert for a refused sign-in, show password, a footer", async ({ page }, testInfo) => {
      await page.goto(app("#/signin"));
      const email = page.getByLabel("Email");
      const password = page.getByLabel("Password", { exact: true });
      await page.getByRole("button", { name: "Sign in", exact: true }).click();
      await expect(email).toHaveAttribute("aria-invalid", "true");
      await expect(email).toBeFocused();
      await expect(page.locator("#signin-email-error")).toHaveText("Enter your email.");
      await expect(page.locator("#signin-password-error")).toHaveText("Enter your password.");
      await expect(email).toHaveAttribute("aria-describedby", "signin-email-error");
      await expect(password).toHaveAttribute("aria-describedby", "signin-password-error");
      await snap(page, testInfo, `shell-signin-empty-${name}`);

      await email.fill(creds.email);
      await password.fill("wrong-password");
      const show = page.getByRole("button", { name: "Show password" });
      await show.click();
      await expect(password).toHaveAttribute("type", "text");
      await expect(show).toHaveAttribute("aria-pressed", "true");
      await show.click();
      await expect(password).toHaveAttribute("type", "password");
      await page.getByRole("button", { name: "Sign in", exact: true }).click();
      const alert = page.getByTestId("signin-alert");
      await expect(alert).toBeVisible();
      await expect(alert).toContainText("Incorrect email or password.");
      await expect(page.locator("#signin-email-error")).toBeEmpty();
      await expect(page.getByRole("link", { name: "Verify a signed PDF" })).toBeVisible();
      await expect(page.getByRole("link", { name: "About OpenSeal" })).toBeVisible();
      await expect(page.getByTestId("signin-sso")).toBeHidden();
      await expectAccessible(page, "sign-in error");
      await snap(page, testInfo, `shell-signin-error-${name}`);
    });

    test("forgot password sends a reset link, saying the same for any address", async ({ page }) => {
      test.skip(REAL, "the reset request is not on the server yet (UXW-38)");
      await page.goto(app("#/signin"));
      await page.getByLabel("Email").fill("someone@example.com");
      await page.getByRole("button", { name: "Forgot password?" }).click();
      await expect(page.getByRole("heading", { name: "Reset your password" })).toBeVisible();
      await expect(page.getByLabel("Email")).toHaveValue("someone@example.com");
      await page.getByRole("button", { name: "Send reset link" }).click();
      await expect(page.getByTestId("reset-sent")).toContainText("If someone@example.com has an account here");
      await page.getByRole("button", { name: "Back to sign in" }).click();
      await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();
    });

    test("the account menu, help menu and notifications", async ({ page }, testInfo) => {
      await signIn(page, "home");
      await page.locator("#account-btn").click();
      const menu = page.getByRole("menu", { name: "Account" });
      for (const item of ["Profile and signature", "Notification settings", "Light theme", "Dark theme", "Match system", "Help and shortcuts", "About OpenSeal", "Sign out"]) {
        await expect(menu.getByRole("menuitem", { name: item })).toBeVisible();
      }
      await expect(menu).toContainText(creds.email);
      await snap(page, testInfo, `shell-account-${name}`);
      await page.keyboard.press("Escape");

      // The bar has no theme or keyboard buttons; Help and the bell replace them.
      await expect(page.locator("#theme-btn")).toHaveCount(0);
      await expect(page.getByRole("button", { name: /^Notifications/ })).toBeVisible();
      if (name === "desktop") {
        await page.getByRole("button", { name: "Help", exact: true }).click();
        await page.getByRole("menuitem", { name: "Keyboard shortcuts" }).click();
      } else {
        await page.locator("#account-btn").click();
        await page.getByRole("menuitem", { name: "Help and shortcuts" }).click();
      }
      const keys = page.getByRole("dialog", { name: "Keyboard shortcuts" });
      await expect(keys.getByRole("heading", { name: "Everywhere" })).toBeVisible();
      await expect(keys.getByRole("heading", { name: "Send editor" })).toBeVisible();
      // One row per action: the two help keys are one row; Redo lists both of its keys.
      await expect(keys.getByRole("row", { name: /Keyboard shortcuts/ })).toHaveCount(1);
      await expect(keys.getByRole("row", { name: /^Redo/ }).locator("kbd")).toHaveCount(5);
      await snap(page, testInfo, `shell-shortcuts-${name}`);
      await page.keyboard.press("Escape");
      await expect(keys).toHaveCount(0);

      // Notifications: recent changes, each opening its envelope.
      await page.getByRole("button", { name: /^Notifications/ }).click();
      const bell = page.getByRole("menu", { name: "Notifications" });
      await expect(bell).toBeVisible();
      const first = bell.getByRole("menuitem").first();
      await expect(first).toBeVisible();
      await snap(page, testInfo, `shell-notifications-${name}`);
      await first.click();
      await expect(page).toHaveURL(/#\/envelopes\//);
    });

    test("profile and signature: the name is saved and the avatar follows it", async ({ page }) => {
      test.skip(REAL, "the profile calls are not on the server yet (UXW-37)");
      await signIn(page, "home");
      await page.locator("#account-btn").click();
      await page.getByRole("menuitem", { name: "Profile and signature" }).click();
      const panel = page.getByRole("dialog", { name: "Profile and signature" });
      await expect(panel).toBeVisible();
      await expect(panel).toContainText(creds.email);
      await expect(panel.getByTestId("profile-signature")).toContainText("None saved yet.");
      await panel.getByLabel("Name").fill("Robin Quinn");
      await panel.getByLabel("a recipient opens an envelope").check();
      await expectAccessible(page, "profile");
      await panel.getByTestId("profile-save").click();
      await expect(panel).toHaveCount(0);
      await expect(page.locator("#account-btn .os-avatar")).toHaveText("RQ");
      await page.locator("#account-btn").click();
      await page.getByRole("menuitem", { name: "Notification settings" }).click();
      await expect(panel.getByLabel("a recipient opens an envelope")).toBeChecked();
      await expect(panel.getByLabel("Name")).toHaveValue("Robin Quinn");
    });
  });
}

test("a company sign-in button shows only when the server names an identity provider", async ({ page }) => {
  test.skip(REAL, "the provider list is not on the server yet (UXW-39)");
  await page.goto(app("#/signin"));
  await expect(page.getByLabel("Email")).toBeFocused();
  await expect(page.getByTestId("signin-sso")).toBeHidden();
  await page.evaluate(() => sessionStorage.setItem("openseal.mock.idp", "Acme SSO"));
  await page.reload();
  await expect(page.getByRole("link", { name: "Sign in with Acme SSO" })).toBeVisible();
});

test.describe("verify page and public site", () => {
  for (const [name, viewport] of WIDTHS) {
    test(`verify keeps demo mode, matches the app's bar and names no build tool, at ${viewport.width}`, async ({ page }, testInfo) => {
      test.skip(REAL, "demo mode only");
      await page.setViewportSize(viewport);
      await page.goto("/verify.html?mock=1");
      await expect(page.getByRole("note")).toContainText("Demo mode");
      await expect(page.getByRole("link", { name: "Open OpenSeal" })).toHaveAttribute("href", "app.html?mock=1");
      await expect(page.locator(".os-brand")).toHaveAttribute("href", "app.html?mock=1");
      // The app's bar height, --os-topbar-h (WEB-02: 36 px here against 60 there).
      const [bar, want] = await page.locator(".os-topbar").evaluate((b) => {
        const probe = document.createElement("div");
        probe.style.height = "var(--os-topbar-h)";
        document.body.append(probe);
        const v = probe.getBoundingClientRect().height;
        probe.remove();
        return [b.getBoundingClientRect().height, v];
      });
      expect(Math.abs(bar - want), `bar ${bar}px, app bar ${want}px`).toBeLessThanOrEqual(1);
      await expect(page.locator("body")).not.toContainText("PAdES");
      await expectAccessible(page, "verify start");
      await snap(page, testInfo, `shell-verify-${name}`);
    });
  }

  test("a sealed document handed over from the envelope page is checked without choosing a file", async ({ page }) => {
    test.skip(REAL, "demo mode only");
    await signIn(page, "home");
    const ref = await page.evaluate(() => {
      const db = JSON.parse(sessionStorage.getItem("openseal.mock.v1"));
      const env = db.envelopes.find((e) => e.status === "completed" && e.documents?.length);
      return env ? { envelope: env.id, document: env.documents[0].id } : null;
    });
    expect(ref).not.toBeNull();
    await page.goto(`/verify.html?mock=1&envelope=${ref.envelope}&document=${ref.document}`);
    // Checked: a verdict where the verifier is built, else the page says checking is not
    // available here. Never the picker, and never "could not be opened".
    await expect(page.getByTestId("verdict").or(page.getByTestId("verify-missing"))).toBeVisible();
    await expect(page.getByTestId("verify-missing")).not.toContainText("tools/");
    await expect(page.getByTestId("verify-problem")).toHaveCount(0);
  });

  for (const [name, viewport] of WIDTHS) {
    test(`the site has one primary action, a feature row, a footer and the app's light default, at ${viewport.width}`, async ({ page }, testInfo) => {
      await page.setViewportSize(viewport);
      await page.emulateMedia({ colorScheme: "dark" });
      await page.goto("/");
      await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
      await expect(page.locator("body")).not.toContainText("docs/");
      await expect(page.locator(".os-btn--primary")).toHaveCount(1);
      await expect(page.locator(".os-site__feature")).toHaveCount(4);
      await expect(page.getByRole("contentinfo")).toContainText("Apache License 2.0");
      await expect(page.getByRole("link", { name: "OpenSeal home" })).toBeVisible();
      await expectAccessible(page, "site");
      await snap(page, testInfo, `shell-site-${name}`);
    });
  }
});
