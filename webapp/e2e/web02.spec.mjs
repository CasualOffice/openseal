// WEB-02 screens: Home, Templates (create in the editor with roles, use, rename),
// Admin (users, API clients), Verify (the WASM verifier on real sealed fixtures, and
// an embedded audit trail), and mock mode surviving navigation. Mock mode only where
// the spec needs seeded data; axe on every screen; screenshots under
// target/e2e-screens/.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { test, expect } from "@playwright/test";
import { signIn, app, pdfFile, snap, expectAccessible, REAL, placingFor } from "./helpers.mjs";
import { pdfWithAttachments } from "./pdfattach.mjs";

const ROOT = path.resolve(fileURLToPath(new URL("../..", import.meta.url)));
const fixture = (p) => path.join(ROOT, "fixtures", p);
const WASM = fs.existsSync(path.join(ROOT, "webapp/vendor/openseal-wasm/casual_sign_wasm_bg.wasm"));
const mockOnly = () => test.skip(REAL, "needs the mock's seeded data");

test("home shows counters, recent envelopes and where to start", async ({ page }, testInfo) => {
  mockOnly();
  await signIn(page, "home");
  await expect(page.getByTestId("counter-waiting").locator(".os-counter__n")).toHaveText("2");
  await expect(page.getByTestId("counter-expiring").locator(".os-counter__n")).toHaveText("1");
  await expect(page.getByTestId("counter-action").locator(".os-counter__n")).toHaveText("1");
  await expect(page.getByTestId("counter-completed").locator(".os-counter__n")).toHaveText("1");
  await expect(page.locator("section[aria-labelledby=recent-h] .os-recent__item")).toHaveCount(6);
  await expectAccessible(page, "home");
  await snap(page, testInfo, "web02-home");
  await page.getByTestId("counter-completed").click();
  await expect(page.getByRole("heading", { name: "Agreements" })).toBeVisible();
  await expect(page.locator("tbody tr")).toHaveCount(1);
});

test("home with nothing sent shows its empty state", async ({ page }, testInfo) => {
  mockOnly();
  await signIn(page, "home");
  await page.evaluate(() => { const k = "openseal.mock.v1"; const db = JSON.parse(sessionStorage.getItem(k)); db.envelopes = []; sessionStorage.setItem(k, JSON.stringify(db)); });
  await page.reload();
  await expect(page.getByTestId("empty-home")).toBeVisible();
  await expect(page.getByTestId("counter-completed").locator(".os-counter__n")).toHaveText("0");
  await snap(page, testInfo, "web02-home-empty");
});

test("templates: empty state, then a new template from a PDF with roles and fields", async ({ page }, testInfo) => {
  mockOnly();
  await signIn(page);
  await page.evaluate(() => { const k = "openseal.mock.v1"; const db = JSON.parse(sessionStorage.getItem(k)); db.templates = []; sessionStorage.setItem(k, JSON.stringify(db)); });
  await page.goto(app("#/templates"));
  await page.reload(); // the mock reads its state on load
  await expect(page.getByTestId("empty-templates")).toBeVisible();
  await expectAccessible(page, "templates empty");
  await snap(page, testInfo, "web02-templates-empty");

  await page.getByTestId("empty-templates").getByRole("button", { name: "New template" }).click();
  await expect(page.getByTestId("empty-documents")).toBeVisible();
  await page.getByTestId("pdf-input").setInputFiles(pdfFile("lease.pdf", "Lease"));
  await expect(page.getByTestId("doc-card")).toHaveCount(1);
  await page.getByTestId("wizard-next").click();
  await expect(page.getByTestId("empty-roles")).toBeVisible();
  await page.getByRole("button", { name: "Add role" }).first().click();
  await page.getByTestId("role-name").fill("Tenant");
  await expect(page.getByTestId("recipient-email")).toHaveCount(0);
  await page.getByRole("button", { name: "Add role" }).first().click();
  await page.getByTestId("role-name").nth(1).fill("Landlord");
  await page.getByTestId("wizard-next").click();
  await expect(page.locator(".os-page.is-loading")).toHaveCount(0);
  await placingFor(page, 0);
  await page.locator(".os-palette").getByRole("button", { name: "Add Signature field" }).click();
  await placingFor(page, 1);
  await page.locator(".os-palette").getByRole("button", { name: "Add Signature field" }).click();
  await expectAccessible(page, "template editor");
  await snap(page, testInfo, "web02-template-editor");
  await page.getByTestId("wizard-next").click();
  await expect(page.getByLabel("Template name")).toHaveValue("lease");
  await page.getByRole("button", { name: "Save template" }).click();
  await expect(page.getByRole("heading", { name: "Templates" })).toBeVisible();
  await expect(page.getByRole("link", { name: "lease" })).toBeVisible();
  await expect(page.locator(".os-toast")).toContainText("Template saved.");
});

test("use a template: fill the roles, send, and the envelope has its fields", async ({ page }, testInfo) => {
  mockOnly();
  await signIn(page);
  await page.goto(app("#/templates"));
  await page.getByRole("button", { name: "Use Mutual NDA" }).click();
  await expect(page.getByRole("heading", { name: "Use Mutual NDA" })).toBeVisible();
  await expect(page.getByText("4 fields placed for the roles.")).toBeVisible();
  await page.getByTestId("use-send").click();
  await expect(page.getByLabel("Company: name")).toBeFocused();
  await expect(page.getByLabel("Company: name")).toHaveAttribute("aria-invalid", "true");
  await page.getByLabel("Company: name").fill("Avery Chen");
  await page.getByLabel("Company: email").fill("avery@acme.example");
  await page.getByLabel("Counterparty: name").fill("Sam Patel");
  await page.getByLabel("Counterparty: email").fill("sam@globex.example");
  await page.getByLabel("Legal: name").fill("Legal team");
  await page.getByLabel("Legal: email").fill("legal@acme.example");
  await expectAccessible(page, "use template");
  await snap(page, testInfo, "web02-template-use");
  await page.getByTestId("use-send").click();
  await page.getByRole("dialog", { name: "Send this envelope?" }).getByRole("button", { name: "Send" }).click();
  await expect(page.getByRole("heading", { name: "Audit trail" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Mutual NDA for signature" })).toBeVisible();
  await expect(page.locator(".os-timeline__item")).toHaveCount(3);
});

test("a template the server keeps without documents continues in the editor", async ({ page }) => {
  mockOnly();
  await signIn(page);
  await page.evaluate(() => sessionStorage.setItem("openseal.mock.no-template-docs", "1"));
  await page.goto(app("#/templates"));
  await page.getByRole("button", { name: "Use Contractor onboarding" }).click();
  await expect(page.getByTestId("use-no-docs")).toBeVisible();
  await expect(page.getByTestId("use-send")).toHaveCount(0);
  await page.getByLabel("Contractor: name").fill("Jo Park");
  await page.getByLabel("Contractor: email").fill("jo@example.com");
  await page.getByTestId("use-edit").click();
  await expect(page.getByTestId("empty-documents")).toBeVisible();
  await expect(page.getByTestId("recipient-name")).toHaveValue("Jo Park");
  await page.locator(".os-stepper__btn", { hasText: "Review and send" }).click();
  await expect(page.getByLabel("Subject")).toHaveValue("Welcome aboard: documents to sign");
});

test("a new template on a server without template documents keeps its roles and says so", async ({ page }) => {
  mockOnly();
  await signIn(page);
  await page.evaluate(() => sessionStorage.setItem("openseal.mock.no-template-docs", "1"));
  await page.goto(app("#/templates/new"));
  await page.getByTestId("pdf-input").setInputFiles(pdfFile("w9.pdf", "Form"));
  await page.getByTestId("wizard-next").click();
  await page.getByRole("button", { name: "Add role" }).first().click();
  await page.getByTestId("role-name").fill("Vendor");
  await page.getByTestId("wizard-next").click();
  await page.locator(".os-palette").getByRole("button", { name: "Add Signature field" }).click();
  await page.getByTestId("wizard-next").click();
  await page.getByRole("button", { name: "Save template" }).click();
  await expect(page.locator(".os-toast")).toContainText("does not keep template documents");
  await expect(page.getByRole("link", { name: "w9" })).toBeVisible();
});

test("rename a template in its details panel (WEB-06 T-01)", async ({ page }) => {
  mockOnly();
  await signIn(page);
  await page.goto(app("#/templates"));
  await page.getByRole("button", { name: "Actions for Contractor onboarding" }).click();
  await page.getByRole("menuitem", { name: "Edit details" }).click();
  const dlg = page.getByRole("dialog", { name: "Edit template" });
  await dlg.getByLabel("Template name").fill("");
  await dlg.getByRole("button", { name: "Save" }).click();
  await expect(dlg.getByText("This is required.")).toBeVisible();
  await dlg.getByLabel("Template name").fill("Contractor onboarding 2027");
  await dlg.getByRole("button", { name: "Save" }).click();
  await expect(page.getByRole("link", { name: "Contractor onboarding 2027" })).toBeVisible();
});

test("admin: add and remove a user; an API client's key is shown once, then revoked", async ({ page }, testInfo) => {
  mockOnly();
  await signIn(page);
  await page.getByRole("link", { name: "Admin" }).click();
  await expect(page.getByRole("tab", { name: "Users" })).toHaveAttribute("aria-selected", "true");
  await expect(page.getByRole("cell", { name: "Robin Sender", exact: true })).toBeVisible();
  await expectAccessible(page, "admin users");
  await snap(page, testInfo, "web02-admin-users");
  await page.getByRole("button", { name: "Add user" }).click();
  const add = page.getByRole("dialog", { name: "Add user" });
  await add.getByLabel("Name").fill("Kim Lee");
  await add.getByLabel("Email").fill("kim@example.com");
  await add.getByRole("button", { name: "Add user" }).click();
  await expect(page.getByRole("cell", { name: "Kim Lee", exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Remove Kim Lee" }).click();
  await page.getByRole("dialog", { name: "Remove this user?" }).getByRole("button", { name: "Remove" }).click();
  await expect(page.getByRole("cell", { name: "Kim Lee", exact: true })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Remove Demo Admin" })).toHaveCount(0);

  await page.getByRole("tab", { name: "Users" }).press("ArrowRight");
  await expect(page.getByRole("tab", { name: "API clients" })).toHaveAttribute("aria-selected", "true");
  await page.getByRole("button", { name: "New API client" }).click();
  const create = page.getByRole("dialog", { name: "New API client" });
  await create.getByLabel("Name").fill("Billing sync");
  await create.getByRole("button", { name: "Create" }).click();
  const secret = page.getByRole("dialog", { name: "Copy the secret now" });
  await expect(secret.getByTestId("secret-value")).toHaveValue(/^osk_/);
  await snap(page, testInfo, "web02-admin-secret");
  await secret.getByRole("button", { name: "I have copied it" }).click();
  await page.getByRole("button", { name: "Revoke Billing sync" }).click();
  await page.getByRole("dialog", { name: "Revoke this API client?" }).getByRole("button", { name: "Revoke" }).click();
  await expect(page.getByRole("row", { name: /Billing sync/ })).toContainText("Revoked");
  await expectAccessible(page, "admin api clients");
});

test.describe("verify", () => {
  test.skip(!WASM || REAL, "the WASM verifier is built locally by tools/build-webapp-wasm.sh; the server image does not ship it yet");

  test("a sealed PDF verifies against its trust root, and is only indeterminate without it", async ({ page }, testInfo) => {
    await page.goto("/verify.html");
    await expect(page.getByRole("heading", { name: "Verify a signed PDF" })).toBeVisible();
    await expectAccessible(page, "verify start");
    await snap(page, testInfo, "web02-verify-start");
    await page.getByTestId("verify-input").setInputFiles(fixture("sealed/p256-approval-bb.pdf"));
    await expect(page.getByTestId("verdict")).toHaveAttribute("data-state", "indeterminate");
    await expect(page.getByTestId("verdict")).toContainText("Add the issuer's certificate");
    await page.getByTestId("verify-another").click();
    await page.getByTestId("trust-input").setInputFiles(fixture("sealed/trust-root.pem"));
    await expect(page.getByText("trust-root.pem")).toBeVisible();
    await page.getByTestId("verify-input").setInputFiles(fixture("sealed/p256-approval-blt.pdf"));
    await expect(page.getByTestId("verdict")).toHaveAttribute("data-state", "valid");
    await expect(page.getByTestId("signature")).toHaveCount(1);
    await expect(page.getByTestId("signature")).toContainText("Valid");
    await expect(page.getByTestId("signature")).toContainText("from a signature timestamp");
    await expect(page.getByTestId("trail-none")).toBeVisible();
    await expectAccessible(page, "verify valid");
    await snap(page, testInfo, "web02-verify-valid");
  });

  test("a tampered PDF is invalid", async ({ page }, testInfo) => {
    await page.goto("/verify.html");
    await page.getByTestId("trust-input").setInputFiles(fixture("signed/trust-root.der"));
    await page.getByTestId("verify-input").setInputFiles(fixture("signed/flip-range1.pdf"));
    await expect(page.getByTestId("verdict")).toHaveAttribute("data-state", "invalid");
    await expect(page.getByTestId("signature")).toContainText("HASH_FAILURE");
    await snap(page, testInfo, "web02-verify-invalid");
  });

  test("an attached audit trail is shown as a timeline with its links checked", async ({ page }, testInfo) => {
    const H = (n) => n.toString(16).padStart(64, "0");
    const events = ["envelope.created", "envelope.sent", "recipient.signed"].map((type, seq) => ({ v: 1, envelope_id: "e1", seq, prev: seq ? H(seq) : null, at: `2026-11-10T09:1${seq}:00.000Z`, type, actor: { kind: seq ? "recipient" : "sender", name: seq ? "Ada" : "Sam" }, context: {}, data: {}, hash: H(seq + 1) }));
    const json = JSON.stringify({ format: "openseal.audit-trail", v: 1, envelope_id: "e1", head: H(3), events });
    await page.goto("/verify.html");
    await page.getByTestId("verify-input").setInputFiles({ name: "with-trail.pdf", mimeType: "application/pdf", buffer: pdfWithAttachments({ "audit-trail.json": json }) });
    await expect(page.getByTestId("verdict")).toHaveAttribute("data-state", "unsigned");
    await expect(page.getByTestId("trail").locator("li")).toHaveCount(3);
    await expect(page.getByTestId("trail-links")).toContainText("3 events, each linked to the one before.");
    await expectAccessible(page, "verify trail");
    await snap(page, testInfo, "web02-verify-trail");
  });

  test("a file that is not a PDF is refused", async ({ page }) => {
    await page.goto("/verify.html");
    await page.getByTestId("verify-input").setInputFiles({ name: "note.pdf", mimeType: "application/pdf", buffer: Buffer.from("hello") });
    await expect(page.getByTestId("verify-problem")).toContainText("not a PDF");
  });
});

test("mock mode survives navigation from the site page", async ({ page }) => {
  test.skip(REAL, "mock mode only");
  await page.goto("/?mock=1");
  await page.getByRole("link", { name: "Open the app" }).click();
  await expect(page).toHaveURL(/app\.html\?mock=1/);
  await expect(page.getByRole("note")).toContainText("Demo mode");
  // A link that drops the query keeps mock mode for this tab.
  await page.goto("/app.html#/signin", { waitUntil: "domcontentloaded" });
  await expect(page.getByRole("note")).toContainText("Demo mode");
  await signIn(page, "home");
  await expect(page.getByRole("heading", { name: "Home", exact: true })).toBeVisible();
});

test("on this machine without a server or mock, the app says so", async ({ page }, testInfo) => {
  test.skip(REAL, "a dev server only");
  await page.goto("/app.html");
  await expect(page.getByTestId("empty-no-server")).toContainText("No OpenSeal server is running here");
  await snap(page, testInfo, "web02-no-server");
  await page.getByTestId("open-demo").click();
  await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();
});
