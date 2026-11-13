// UXW-07, the exit test: admin groups and custom permission profiles in the browser.
// The administrator makes a custom profile (templates only) on Admin > Members and roles
// > Permission profiles, gives it to a member on the Users tab, makes a group on the
// Groups tab and puts the member in it. Against the Compose stack
// (OPENSEAL_E2E_BASE_URL) the member then signs in through the API: templates are
// theirs to write and envelopes are refused; the administrator untics template writing
// in the browser and the member's next request is refused, so the server, not the page,
// decides. In mock mode the browser part runs against the mock's sender.
import { test, expect, request as pwRequest } from "@playwright/test";
import { signIn, app, REAL } from "./helpers.mjs";

const PASSWORD = "uxw07-e2e-password-only";

test("a custom profile is made, given to a member and enforced; a group gets the member (UXW-07)", async ({ page, baseURL }, testInfo) => {
  test.setTimeout(120_000);
  await signIn(page, "home");
  const stamp = `${Date.now()}-${testInfo.project.name}`;
  const profile = `Author ${stamp}`;
  const group = `Legal ${stamp}`;

  // The member: a sender made through the API on the stack, the mock's sender otherwise.
  const member = REAL
    ? await page.evaluate(async ({ stamp, password }) => {
      const { createClient } = await import(new URL("api.js", location.href).href);
      const api = createClient({ store: sessionStorage });
      const u = await api.users.create({ email: `uxw07-kim-${stamp}@example.com`, name: `Kim ${stamp}`, profile: "sender", password });
      return { email: u.email, name: u.name };
    }, { stamp, password: PASSWORD })
    : { email: "sender@openseal.test", name: "Robin Sender" };

  // Permission profiles: the built-in ones are listed and fixed; a custom one is made.
  await page.goto(app("#/admin?section=profiles"), { waitUntil: "domcontentloaded" });
  const tabs = page.getByRole("tablist", { name: "Users, groups and permission profiles" });
  await expect(tabs.getByRole("tab", { name: "Permission profiles" })).toHaveAttribute("aria-selected", "true");
  await expect(page.locator("tr", { hasText: "Administrator" }).getByText("Built in")).toBeVisible();
  await page.getByRole("button", { name: "New profile" }).first().click();
  const sheet = page.getByTestId("sheet-profile-edit");
  await sheet.getByLabel("Profile name").fill(profile);
  await sheet.locator("#pp-templates-read").check();
  await sheet.locator("#pp-templates-write").check();
  await sheet.getByRole("button", { name: "Create" }).click();
  await expect(page.getByText("Profile saved.")).toBeVisible();
  const prow = page.locator("tr", { hasText: profile });
  await expect(prow).toContainText("templates:read, templates:write");
  await expect(prow.getByText("Custom")).toBeVisible();

  // Users: the member gets the custom profile.
  await tabs.getByRole("tab", { name: "Users" }).click();
  const urow = page.locator("tr", { hasText: member.email });
  await urow.getByRole("button", { name: `Edit ${member.name}` }).click();
  const edit = page.getByTestId("sheet-user-edit");
  await edit.getByLabel("Permission profile").selectOption({ label: profile });
  await edit.getByRole("button", { name: "Save" }).click();
  await expect(page.getByText("User saved.")).toBeVisible();
  await expect(urow).toContainText(profile);

  // Groups: a new group, and the member in it.
  await tabs.getByRole("tab", { name: "Groups" }).click();
  await page.getByRole("button", { name: "New group" }).first().click();
  const gsheet = page.getByTestId("sheet-group-name");
  await gsheet.getByLabel("Group name").fill(group);
  await gsheet.getByRole("button", { name: "Create" }).click();
  const msheet = page.getByTestId("sheet-group-members");
  await expect(msheet).toBeVisible();
  await msheet.getByLabel("Search users").fill(member.email);
  await msheet.getByLabel(new RegExp(member.email.replace(/[.+]/g, "\\$&"))).check();
  await msheet.getByRole("button", { name: "Save" }).click();
  const grow = page.locator("tr", { hasText: group });
  await expect(grow.locator("td").nth(1)).toHaveText("1");

  if (!REAL) return;
  // The server decides: the member writes templates and is refused envelopes; once the
  // administrator unticks template writing, the member's next request is refused.
  const kim = await pwRequest.newContext({ baseURL });
  const login = await kim.post("/api/v1/auth/login", { data: { email: member.email, password: PASSWORD } });
  expect(login.ok(), `login ${login.status()}`).toBeTruthy();
  const csrf = (await login.json()).csrf_token;
  const headers = csrf ? { "x-csrf-token": csrf } : {};
  const made = await kim.post("/api/v1/templates", { headers, data: { name: `Kim ${stamp}` } });
  expect(made.status()).toBe(201);
  expect((await kim.get("/api/v1/envelopes")).status()).toBe(403);

  await tabs.getByRole("tab", { name: "Permission profiles" }).click();
  await prow.getByRole("button", { name: `Actions for ${profile}` }).click();
  await page.getByRole("menuitem", { name: "Edit" }).click();
  await sheet.locator("#pp-templates-write").uncheck();
  // Wait for the server to take the change before the member's next request: the toast
  // and "templates:read" were already on screen from the first save, so they prove nothing.
  const saved = page.waitForResponse((r) => /\/api\/v1\/.*profiles/.test(r.url()) && ["PATCH", "PUT", "POST"].includes(r.request().method()));
  await sheet.getByRole("button", { name: "Save" }).click();
  expect((await saved).ok()).toBeTruthy();
  await expect(prow).toContainText("templates:read");
  await expect(prow).not.toContainText("templates:write");
  const refused = await kim.post("/api/v1/templates", { headers, data: { name: `Kim 2 ${stamp}` } });
  expect(refused.status()).toBe(403);
  await kim.dispose();
});
