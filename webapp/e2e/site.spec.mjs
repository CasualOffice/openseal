// The website (SITE-03, SITE-04), as published: the Verify page runs the WASM verifier
// with the network blocked, so the file provably never leaves the page; and from the
// home page's primary call to action a visitor sends and signs a sample agreement in the
// demo copy of the app, with no server. Run by site.config.mjs (not the app's config).
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { test, expect } from "@playwright/test";

const ROOT = path.resolve(fileURLToPath(new URL("../..", import.meta.url)));
const fixture = (p) => path.join(ROOT, "fixtures", p);
const WASM = fs.existsSync(path.join(ROOT, "webapp/vendor/openseal-wasm/casual_sign_wasm_bg.wasm"));

test.describe("verify", () => {
  test.skip(!WASM, "the WASM verifier is built by tools/build-webapp-wasm.sh");

  test("Verify is in the top navigation and says the file is not uploaded", async ({ page }) => {
    await page.goto("/index.html");
    await page.getByRole("navigation", { name: "Main", exact: true }).getByRole("link", { name: "Verify" }).click();
    await expect(page).toHaveURL(/\/verify\.html$/);
    await expect(page.getByRole("heading", { name: "Verify a sealed PDF", level: 1 })).toBeVisible();
    await expect(page.getByText("Your file is not uploaded.")).toBeVisible();
    await expect(page.getByRole("navigation", { name: "Main", exact: true }).getByRole("link", { name: "Verify" })).toHaveAttribute("aria-current", "page");
  });

  test("with the network blocked, a sealed PDF verifies and a tampered one fails", async ({ page, context }) => {
    await page.goto("/verify.html");
    await expect(page.getByTestId("vfy-engine")).toHaveAttribute("data-state", "ready");

    // From here nothing may leave the page: every request is refused and recorded.
    const sent = [];
    await context.route("**/*", (route) => { const r = route.request(); sent.push({ method: r.method(), url: r.url(), body: r.postDataBuffer()?.length ?? 0 }); return route.abort(); });
    await context.setOffline(true);

    await page.getByTestId("vfy-trust-input").setInputFiles([fixture("sealed/trust-root.pem"), fixture("signed/trust-root.der")]);
    await expect(page.getByTestId("vfy-trusted")).toContainText("trust-root.pem");
    await page.getByTestId("vfy-input").setInputFiles(fixture("sealed/p256-approval-blt.pdf"));
    const verdict = page.getByTestId("vfy-verdict");
    await expect(verdict).toHaveAttribute("data-state", "valid");
    await expect(verdict).toContainText("Signed and unchanged");
    await expect(page.getByTestId("vfy-integrity")).toHaveAttribute("data-tone", "ok");
    await expect(page.getByTestId("vfy-trust")).toHaveAttribute("data-tone", "ok");
    await expect(page.getByTestId("vfy-timestamp")).toHaveAttribute("data-tone", "ok");
    await expect(page.getByTestId("vfy-timestamp")).toContainText("RFC 3161");
    await expect(page.getByTestId("vfy-revisions")).toContainText("revision");
    await expect(verdict).toContainText("p256-approval-blt.pdf");

    await page.getByTestId("vfy-input").setInputFiles(fixture("signed/flip-range1.pdf"));
    await expect(verdict).toHaveAttribute("data-state", "invalid");
    await expect(page.getByTestId("vfy-integrity")).toHaveAttribute("data-tone", "bad");
    await page.getByText(/Every check, signature by signature/).click();
    await expect(page.getByTestId("vfy-signature")).toContainText("HASH_FAILURE");

    // Only the page's own lazy images may have been asked for (and were refused); nothing
    // carried a body or went anywhere but this site.
    const site = new URL(page.url()).origin;
    expect(sent.filter((r) => r.method !== "GET" || r.body > 0 || new URL(r.url).origin !== site || !/\.(svg|png|webp|woff2)$/.test(new URL(r.url).pathname)), "requests that could carry the file").toEqual([]);
  });

  test("without a trusted root the verdict is never valid", async ({ page }) => {
    await page.goto("/verify.html");
    await page.getByTestId("vfy-input").setInputFiles(fixture("sealed/p256-approval-blt.pdf"));
    await expect(page.getByTestId("vfy-verdict")).toHaveAttribute("data-state", "indeterminate");
    await expect(page.getByTestId("vfy-trust")).toContainText("add it under Trusted certificates");
  });

  test("the samples show both outcomes", async ({ page }) => {
    await page.goto("/verify.html");
    await page.getByTestId("vfy-sample-sealed").click();
    await expect(page.getByTestId("vfy-verdict")).toHaveAttribute("data-state", "valid");
    await expect(page.getByTestId("vfy-trusted")).toContainText("test-roots.pem");
    await page.getByTestId("vfy-sample-tampered").click();
    await expect(page.getByTestId("vfy-verdict")).toHaveAttribute("data-state", "invalid");
  });

  test("a file that is not a PDF is refused", async ({ page }) => {
    await page.goto("/verify.html");
    await page.getByTestId("vfy-input").setInputFiles({ name: "<img src=x onerror=alert(1)>.pdf", mimeType: "application/pdf", buffer: Buffer.from("hello") });
    await expect(page.getByTestId("vfy-problem")).toContainText("not a PDF");
    await expect(page.locator(".vfy img")).toHaveCount(0);
  });
});

test("from the home page, a visitor sends and signs a sample agreement in the demo", async ({ page }) => {
  // The demo is the app with no server: nothing may go anywhere but this static site, and
  // no API path is ever requested over the network.
  const offsite = [];
  const api = [];
  page.on("request", (r) => {
    const u = new URL(r.url());
    if (u.origin !== new URL(page.url() === "about:blank" ? r.url() : page.url()).origin) offsite.push(r.url());
    if (u.pathname.includes("/api/") || /\/s\/[^/]+$/.test(u.pathname)) api.push(r.url());
  });

  await page.goto("/index.html");
  await page.getByTestId("cta-demo").click();
  await expect(page).toHaveURL(/\/app\/app\.html/);
  await expect(page.getByRole("note").filter({ hasText: "Demo mode" })).toBeVisible();
  // Signed in with the demo account, filled in for the visitor.
  await expect(page.getByLabel("Email")).toHaveValue("demo@openseal.test");
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByRole("heading", { name: "Home", exact: true })).toBeVisible();

  // Send: a template with its document and fields, two signers and a copy.
  await page.goto("/app/app.html#/templates");
  await page.getByRole("button", { name: "Use Mutual NDA" }).click();
  await page.getByTestId("use-send").click();
  await page.locator("#use-name-0").fill("Avery Chen");
  await page.locator("#use-email-0").fill("avery@acme.example");
  await page.locator("#use-name-1").fill("Sam Patel");
  await page.locator("#use-email-1").fill("sam@globex.example");
  await page.locator("#use-name-2").fill("Legal team");
  await page.locator("#use-email-2").fill("legal@acme.example");
  await page.getByTestId("use-send").click();
  await page.getByRole("dialog", { name: "Send this envelope?" }).getByRole("button", { name: "Send" }).click();
  await expect(page.getByRole("heading", { name: "Mutual NDA for signature" })).toBeVisible();

  // Sign: the demo shows the first signer's link (a real install emails it).
  await page.getByTestId("signing-link").first().click();
  await expect(page).toHaveURL(/\/app\/sign\.html\?t=/);
  await expect(page.getByRole("heading", { name: "Electronic records and signatures" })).toBeVisible();
  await page.getByLabel("I agree to use electronic records and signatures.").check();
  await page.getByRole("button", { name: "Continue" }).click();
  const sign = page.getByRole("button", { name: /Signature, required/ });
  await sign.click();
  const dlg = page.getByRole("dialog", { name: "Adopt your signature" });
  await expect(dlg.getByLabel("Your full name")).toHaveValue("Avery Chen");
  await dlg.getByTestId("adopt-confirm").click();
  await expect(dlg).toBeHidden();
  await page.getByRole("button", { name: "Finish" }).click();
  await expect(page.getByRole("heading", { name: "Review and finish" })).toBeVisible();
  await page.getByTestId("review-finish").click();
  await expect(page.getByTestId("sign-done")).toBeVisible();
  // The done screen's link to Verify stays inside the demo copy.
  await expect(page.getByTestId("sign-done").getByRole("link")).toHaveAttribute("href", "verify.html");

  expect(offsite, "requests that left the site").toEqual([]);
  expect(api, "API requests over the network (the demo's API is in the page)").toEqual([]);
});
