// UXW-06, the exit test: template sharing, Shared with me and Favourites in the browser.
// The owner opens Share from a template's row menu, adds a member by email with Can
// edit, saves; stars the template and finds it under Favourites. Against the Compose
// stack (OPENSEAL_E2E_BASE_URL) the member it was shared with signs in through the API
// and finds it under Shared with me with edit access, and another member does not see
// it at all. In mock mode the browser part runs against the mock's demo member.
import { test, expect, request as pwRequest } from "@playwright/test";
import { signIn, app, REAL } from "./helpers.mjs";

/// Run `fn(api, arg)` in the signed-in app page with api.js's client (the page's CSP
/// allows no eval, so the client is put on `window` first and `fn` reads it).
async function inApp(page, fn, arg) {
  await page.evaluate(async (real) => {
    const { createClient } = await import(new URL("api.js", location.href).href);
    const opts = { store: sessionStorage };
    // Mock mode: the app's mock keeps its data in sessionStorage; this one shares it.
    if (!real) opts.fetch = (await import(new URL("mock.js", location.href).href)).createMockFetch({ store: sessionStorage });
    window.__uxw06 = createClient(opts);
  }, REAL);
  return page.evaluate(fn, arg);
}

const PASSWORD = "uxw06-e2e-password-only";

test("a template is shared by email with Can edit, starred, and found under Favourites (UXW-06)", async ({ page, baseURL }, testInfo) => {
  test.setTimeout(120_000);
  await signIn(page, "home");
  const stamp = `${Date.now()}-${testInfo.project.name}`;
  const name = `UXW-06 NDA ${stamp}`;

  // A member to share with, and one who is not shared with (the mock has its sender).
  const people = REAL
    ? await inApp(page, async ({ stamp, password }) => {
      const api = window.__uxw06;
      const mk = async (who) => (await api.users.create({ email: `uxw06-${who}-${stamp}@example.com`, name: `UXW06 ${who}`, profile: "sender", password })).email;
      return { lee: await mk("lee"), pat: await mk("pat") };
    }, { stamp, password: PASSWORD })
    : { lee: "sender@openseal.test", pat: null };

  // The template, made with api.js's client; the list then shows it.
  await inApp(page, async ({ name }) => window.__uxw06.templates.create({ name, roles: [{ name: "Client", type: "signer", routing_order: 1 }] }), { name });
  await page.goto(app("#/templates"), { waitUntil: "domcontentloaded" });
  await page.reload({ waitUntil: "domcontentloaded" });
  await expect(page.getByRole("heading", { name: "Templates", exact: true })).toBeVisible();
  const tabs = page.getByRole("tablist", { name: "Template views" });
  await expect(tabs.getByRole("tab", { name: "Shared with me" })).toBeVisible();
  const row = page.locator("tr.os-row", { hasText: name });
  await expect(row).toBeVisible();

  // Share: by email, Can edit, Save.
  await row.getByRole("button", { name: `Actions for ${name}` }).click();
  await page.getByRole("menuitem", { name: "Share" }).click();
  const sheet = page.getByTestId("sheet-template-share");
  await expect(sheet).toBeVisible();
  await expect(sheet.getByTestId("share-none")).toBeVisible();
  await sheet.getByLabel("Add a member by email").fill("not an email");
  await sheet.getByTestId("share-add").click();
  await expect(sheet.getByText("Enter a member's email address.")).toBeVisible();
  await sheet.getByLabel("Add a member by email").fill(people.lee);
  await sheet.getByTestId("share-add").click();
  await expect(sheet.getByTestId("share-entry")).toHaveCount(1);
  await sheet.getByTestId("share-can-edit").check();
  await sheet.getByTestId("share-save").click();
  await expect(page.getByText("Sharing saved.")).toBeVisible();
  await expect(row.getByText("Shared")).toBeVisible();

  // Reopened, the share is there with Can edit.
  await row.getByRole("button", { name: `Actions for ${name}` }).click();
  await page.getByRole("menuitem", { name: "Share" }).click();
  await expect(sheet.getByTestId("share-entry")).toHaveCount(1);
  await expect(sheet.getByTestId("share-entry")).toContainText(people.lee);
  await expect(sheet.getByTestId("share-can-edit")).toBeChecked();
  await sheet.getByRole("button", { name: "Cancel" }).click();

  // Star it; Favourites lists it; Mine lists it; Shared with me does not (it is mine).
  const star = row.getByTestId("tpl-star");
  await expect(star).toHaveAttribute("aria-pressed", "false");
  await star.click();
  await expect(page.getByText("Added to favourites.")).toBeVisible();
  await expect(row.getByTestId("tpl-star")).toHaveAttribute("aria-pressed", "true");
  await tabs.getByRole("tab", { name: "Favourites" }).click();
  await expect(page.locator("tr.os-row", { hasText: name })).toBeVisible();
  await tabs.getByRole("tab", { name: "Shared with me" }).click();
  await expect(page.locator("tr.os-row", { hasText: name })).toHaveCount(0);
  await tabs.getByRole("tab", { name: "Mine" }).click();
  await expect(page.locator("tr.os-row", { hasText: name })).toBeVisible();

  if (!REAL) return;
  // The member it was shared with finds it under Shared with me, with edit access; the
  // other member is answered as if it did not exist.
  const as = async (email) => {
    const ctx = await pwRequest.newContext({ baseURL });
    const login = await ctx.post("/api/v1/auth/login", { data: { email, password: PASSWORD } });
    expect(login.ok(), `login ${login.status()}`).toBeTruthy();
    return ctx;
  };
  const lee = await as(people.lee);
  const shared = await (await lee.get("/api/v1/templates?view=shared")).json();
  const mine = shared.items.find((x) => x.name === name);
  expect(mine?.access).toBe("edit");
  const pat = await as(people.pat);
  const all = await (await pat.get("/api/v1/templates")).json();
  expect(all.items.some((x) => x.name === name)).toBe(false);
  const direct = await pat.get(`/api/v1/templates/${encodeURIComponent(mine.id)}`);
  expect(direct.status()).toBe(404);
  await lee.dispose();
  await pat.dispose();
});
