// RTE-01 (VS-02): the signing page's last step for each acting recipient type that is
// not a signer. An approver approves, a viewer finishes once every page was viewed, and
// an agent names the later recipient before finishing; each receipt says what they did
// (RTE-02), never "signed". Mock mode: the envelopes are made through api.js against the
// page's own mock, whose shapes tests/contract.test.mjs checks against the server's
// (server/casual-sign-server/tests/routing.rs runs the same types on the real server).
import { test, expect } from "@playwright/test";
import { signIn, signPage, REAL } from "./helpers.mjs";

test.skip(REAL, "the links are emailed on a real server; tests/routing.rs covers the server");

/// Send one envelope in the page's mock and answer each recipient's signing token.
async function sent(page, recipients, fields) {
  return page.evaluate(async ({ recipients, fields }) => {
    const at = (m) => new URL(m, location.href).href;
    const { createClient, recipientWire, fieldWire } = await import(at("api.js"));
    const { createMockFetch } = await import(at("mock.js"));
    const { makePdf } = await import(at("mockpdf.js"));
    const api = createClient({ fetch: createMockFetch({ store: sessionStorage }), store: sessionStorage });
    const bytes = makePdf([{ title: "Routing" }]);
    let bin = "";
    for (const b of bytes) bin += String.fromCharCode(b);
    const env = await api.createEnvelope({
      subject: "Routing types", status: "sent",
      documents: [{ name: "routing.pdf", content_base64: btoa(bin) }],
      recipients: recipients.map((r, i) => recipientWire({ ref: `r${i}`, routing_order: i + 1, ...r })),
      fields: fields.map(({ to, ...f }) => fieldWire({ recipient: `r${to}`, document: 0, ...f })),
    });
    return { id: env.id, tokens: env.recipients.map((r) => r.mock_token) };
  }, { recipients, fields });
}

const signature = { to: 1, type: "signature", page: 1, x: 72, y: 600, width: 160, height: 44, required: true };

/// Consent, then the guide's Finish into the review step.
async function toReview(page, token) {
  await page.goto(signPage(token));
  await page.getByLabel("I agree to use electronic records and signatures.").check();
  await page.getByRole("button", { name: "Continue" }).click();
  await expect(page.getByTestId("review-page").or(page.locator("#guide-finish"))).toBeVisible();
  if (await page.locator("#guide-finish").isVisible()) await page.locator("#guide-finish").click();
  await expect(page.getByTestId("review-finish")).toBeVisible();
}

test("an approver approves, and the receipt says approved", async ({ page }) => {
  await signIn(page);
  const env = await sent(page, [{ name: "Ann Approver", email: "ann@example.com", type: "approver" }, { name: "Sig Signer", email: "sig@example.com", type: "signer" }], [signature]);
  await toReview(page, env.tokens[0]);
  await expect(page.getByTestId("review-finish")).toHaveText("Approve");
  // The words above Approve say what it does: nobody signs here.
  await expect(page.getByText("By selecting Approve, you approve these documents")).toHaveCount(1);
  await expect(page.getByText("you sign these documents")).toHaveCount(0);
  await page.getByTestId("review-finish").click();
  const done = page.getByTestId("sign-done");
  await expect(done).toContainText("Approved. Thank you, Ann.");
  await expect(done.getByTestId("receipt-facts")).toContainText("Approved");
  await expect(done).not.toContainText("Signed");
});

test("a viewer finishes after viewing every page, and the receipt says viewed", async ({ page }) => {
  await signIn(page);
  const env = await sent(page, [{ name: "Vic Viewer", email: "vic@example.com", type: "viewer" }, { name: "Sig Signer", email: "sig@example.com", type: "signer" }], [signature]);
  await toReview(page, env.tokens[0]);
  await page.getByTestId("review-finish").click();
  const done = page.getByTestId("sign-done");
  await expect(done).toContainText("Viewed. Thank you, Vic.");
  await expect(done).not.toContainText("Signed");
});

test("an agent names the later signer before finishing", async ({ page, isMobile }) => {
  await signIn(page);
  const env = await sent(page, [{ name: "Ag Ent", email: "ag@example.com", type: "agent" }, { name: "To be named", email: "placeholder@example.com", type: "signer" }], [signature]);
  await toReview(page, env.tokens[0]);
  const form = page.getByTestId("later-recipients");
  await expect(form).toBeVisible();
  // On a phone the names are asked in the values sheet, which opens with them and has
  // its own Finish (it covers the bottom bar).
  const finish = page.getByTestId(isMobile ? "review-finish-sheet" : "review-finish");
  await expect(form.getByTestId("later-name")).toHaveValue("To be named");
  // A bad address is refused on the page, before anything is sent.
  await form.getByTestId("later-email").fill("nope");
  await finish.click();
  await expect(form.getByRole("alert")).not.toBeEmpty();
  await expect(page.getByTestId("sign-done")).toHaveCount(0);
  await form.getByTestId("later-name").fill("Bea Buyer");
  await form.getByTestId("later-email").fill("bea@example.com");
  await finish.click();
  const done = page.getByTestId("sign-done");
  await expect(done).toContainText("Your part is finished. Thank you, Ag.");
  await expect(done).not.toContainText("Signed");

  // The sender sees the signer the agent named, now asked to sign.
  await page.goto(`/app.html?mock=1#/envelopes/${encodeURIComponent(env.id)}`);
  const row = page.getByTestId("recipient-row").filter({ hasText: "Bea Buyer" });
  await expect(row).toContainText("bea@example.com");
});

// UXW-18: the sender hosts an in-person signer from the envelope page; the signing page
// opens in the same tab on the link the host call answers (real-stack.spec.mjs runs the
// same walk against the Compose deployment, from the editor).
test("an in-person signer is hosted from the envelope page and signs there", async ({ page, isMobile }) => {
  test.skip(isMobile, "the sender's envelope page is a desktop screen");
  await signIn(page);
  const env = await sent(page, [{ name: "Walk In", email: "walkin@example.com", type: "in_person_signer" }],
    [{ ...signature, to: 0 }]);
  // A reload: the app's own mock reads the envelope made beside it from the tab's storage.
  await page.goto(`/app.html?mock=1#/envelopes/${encodeURIComponent(env.id)}`);
  await page.reload();
  await page.getByTestId("host-in-person").click();
  await expect(page).toHaveURL(new RegExp(`/s/${encodeURIComponent(env.tokens[0])}\\?mock=1$`));
  await page.getByLabel("I agree to use electronic records and signatures.").check();
  await page.getByRole("button", { name: "Continue" }).click();
  await page.getByRole("button", { name: /Signature, required/ }).click();
  const dlg = page.getByRole("dialog", { name: "Adopt your signature" });
  await dlg.getByTestId("adopt-confirm").click();
  await expect(dlg).toBeHidden();
  await page.locator("#guide-finish").click();
  await page.getByTestId("review-finish").click();
  await expect(page.getByTestId("sign-done")).toContainText("Signed. Thank you, Walk.");
});
