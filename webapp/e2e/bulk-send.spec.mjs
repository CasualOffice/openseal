// UXW-04, the exit test of bulk send: a template with two roles is sent to a pasted CSV
// list from `#/templates/{id}/bulk`. The check shows each row's problems, Send makes the
// batch and sends it to the end with progress, and the result lists an envelope for
// every good row and the reason for every other. Runs in mock mode (the page's own mock,
// whose shapes tests/bulk.test.mjs checks) and against a real server
// (OPENSEAL_E2E_BASE_URL; server/casual-sign-server/tests/bulk_send.rs covers its rules).
import { test, expect } from "@playwright/test";
import { signIn, app, REAL } from "./helpers.mjs";

/// A two-role template with one document and a signature field per role, made through
/// api.js in the page (the mock, or the real server with the page's session).
async function leaseTemplate(page, stamp) {
  return page.evaluate(async ({ stamp, real }) => {
    const at = (m) => new URL(m, location.href).href;
    const { createClient } = await import(at("api.js"));
    const { makePdf } = await import(at("mockpdf.js"));
    let fetchFn;
    if (!real) fetchFn = (await import(at("mock.js"))).createMockFetch({ store: sessionStorage });
    const api = createClient({ ...(fetchFn ? { fetch: fetchFn } : {}), store: sessionStorage });
    const tp = await api.templates.create({
      name: `Lease ${stamp}`, email_subject: `Please sign the lease ${stamp}`,
      roles: [{ name: "Tenant", type: "signer", routing_order: 1 }, { name: "Landlord", type: "signer", routing_order: 2 }],
    });
    const withDoc = await api.templates.addDocument(tp.id, "lease.pdf", makePdf([{ title: `Lease ${stamp}` }]));
    const doc = withDoc.documents[0].id;
    await api.templates.addFields(tp.id, withDoc.roles.map((r, i) => ({
      role_id: r.id, document_id: doc, type: "signature", required: true,
      placement: { page: 1, x: "72", y: String(500 + 80 * i), width: "160", height: "36" },
    })));
    return tp.id;
  }, { stamp, real: REAL });
}

test("bulk send from a template: check a CSV list, send it with progress, see each row's result (UXW-04)", async ({ page }, testInfo) => {
  test.setTimeout(120_000);
  await signIn(page);
  const stamp = `${Date.now()}-${testInfo.project.name}`;
  const id = await leaseTemplate(page, stamp);

  // The template list's row menu leads to the bulk send page.
  await page.goto(app("#/templates"));
  const row = page.locator(`tr[data-id="${id}"]`);
  await row.getByRole("button", { name: /Actions for/ }).click();
  await page.getByRole("menuitem", { name: "Bulk send" }).click();
  await expect(page).toHaveURL(new RegExp(`#/templates/${id}/bulk$`));
  await expect(page.getByRole("heading", { name: `Bulk send Lease ${stamp}` })).toBeVisible();
  await expect(page.locator("#bulk-cols")).toContainText("Tenant::name, Tenant::email, Landlord::name, Landlord::email");

  // Nothing pasted: said so, nothing asked.
  await page.getByTestId("bulk-check").click();
  await expect(page.getByTestId("bulk-checked")).toContainText("Choose a CSV file or paste the list first.");

  // A header that does not fit the template is refused whole.
  await page.getByTestId("bulk-csv").fill("Tenant::name,Tenant::email,Owner::email\nA,a@example.test,b@example.test\n");
  await page.getByTestId("bulk-check").click();
  await expect(page.getByTestId("bulk-checked")).toContainText("The list is missing columns the template needs.");

  const csv = [
    "Tenant::name,Tenant::email,Landlord::name,Landlord::email",
    `Ann ${stamp},ann.${stamp}@example.test,Lou Park,lou@example.test`,
    `"Bo, Jr.",bo.${stamp}@example.test,Lou Park,lou@example.test`,
    "Cy Moe,not-an-email,Lou Park,lou@example.test",
    ",dee@example.test,Lou Park,lou@example.test",
  ].join("\n");
  await page.getByTestId("bulk-csv").fill(csv);
  await page.getByTestId("bulk-check").click();
  await expect(page.getByTestId("bulk-summary")).toHaveText("4 rows: 2 ready to send, 2 with problems.");
  const checked = page.getByTestId("bulk-check-card");
  await expect(checked.locator('tr[data-row="2"]')).toContainText("Tenant::email: not an email address");
  await expect(checked.locator('tr[data-row="3"]')).toContainText("Tenant::name: a value is missing");

  await page.getByTestId("bulk-send").click();
  const confirm = page.getByRole("dialog", { name: "Send these envelopes?" });
  await confirm.getByRole("button", { name: "Send 2 envelopes" }).click();

  const run = page.getByTestId("bulk-run-card");
  await expect(page.getByTestId("bulk-progress")).toHaveText("Done: 2 sent, 2 not sent.", { timeout: 60_000 });
  await expect(run.getByRole("progressbar")).toHaveAttribute("aria-valuenow", "4");
  await expect(run.locator('tr[data-status="sent"]')).toHaveCount(2);
  await expect(run.locator('tr[data-status="failed"]')).toHaveCount(2);
  await expect(page.getByTestId("bulk-cancel")).toBeHidden();

  // A sent row opens its envelope, sent to the row's people.
  await run.locator('tr[data-row="1"]').getByRole("link", { name: "Open envelope" }).click();
  await expect(page.getByRole("heading", { name: `Please sign the lease ${stamp}` })).toBeVisible();
  await expect(page.getByText("Bo, Jr.").first()).toBeVisible();
});
