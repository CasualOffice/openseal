// WEB-09 and WEB-10 against the Compose deployment (docs/65): the calls api.js makes,
// in the shapes api/openapi.yaml gives, answered by the real server, and the editor's
// template round trip, signing steps and field detection through the UI. Skipped in
// mock mode (the mock's shapes are checked by tests/web02.test.mjs and editor.spec.mjs).
import { test, expect } from "@playwright/test";
import { signIn, app, pdfFile, REAL, placingFor } from "./helpers.mjs";

test.skip(!REAL, "runs against a real server only (OPENSEAL_E2E_BASE_URL)");

/// Run `fn(api, helpers)` in the signed-in app page with api.js's client.
async function inApp(page, fn, arg) {
  return page.evaluate(async ([src, a]) => {
    const { createClient } = await import(new URL("api.js", location.href).href);
    const { templatePlan, applyTemplate, added } = await import(new URL("templatesync.js", location.href).href);
    const { makePdf } = await import(new URL("mockpdf.js", location.href).href);
    const api = createClient({ store: sessionStorage });
    // eslint-disable-next-line no-new-func
    return new Function("api", "lib", "arg", `return (${src})(api, lib, arg);`)(api, { templatePlan, applyTemplate, added, makePdf }, a);
  }, [fn.toString(), arg]);
}

test("api.js against the server: templates, account settings, members, correction, detection (WEB-10)", async ({ page }) => {
  await signIn(page, "home");
  const out = await inApp(page, async (api, lib) => {
    const r = {};
    const stamp = Date.now();
    // Templates: roles with ids, a document read from the whole template, fields by role_id.
    const tp = await api.templates.create({ name: `WEB-10 ${stamp}`, roles: [{ name: "Tenant", type: "signer", routing_order: 1 }] });
    const whole = await api.templates.addDocument(tp.id, "lease.pdf", lib.makePdf([{ title: "Lease" }, { title: "Lease 2" }]));
    const doc = lib.added(tp.documents || [], whole.documents)[0];
    r.docFromWhole = !!doc && whole.id === tp.id;
    const placement = { page: 1, x: "72", y: "600", width: "160", height: "44" };
    const f = await api.templates.addFields(tp.id, [{ role_id: tp.roles[0].id, document_id: doc.id, type: "signature", placement, required: true }]);
    r.fieldRole = f.items[0].role_id === tp.roles[0].id;
    // The editor's plan: a new role, a moved field, a new field; applied with If-Match.
    const { template: server } = await api.templates.get(tp.id);
    const st = {
      details: { name: `WEB-10 ${stamp} edited`, email_subject: "Please sign", email_message: "" },
      roles: [{ key: "t", id: tp.roles[0].id, name: "Tenant", type: "signer", routing_order: 1 }, { key: "l", id: null, name: "Landlord", type: "signer", routing_order: 2 }],
      docs: [{ key: "d", id: doc.id, name: doc.name }],
      fields: [
        { key: "f1", id: f.items[0].id, roleKey: "t", docKey: "d", type: "signature", page: 1, x: 90, y: 600, width: 160, height: 44, required: true, label: "" },
        { key: "f2", id: null, roleKey: "l", docKey: "d", type: "date_signed", page: 2, x: 72, y: 100, width: 110, height: 22, required: false, label: "" },
      ],
    };
    const after = await lib.applyTemplate(api, tp.id, st, lib.templatePlan(server, st));
    r.afterName = after.name;
    r.afterRoles = after.roles.map((x) => x.name).sort();
    r.afterFields = after.fields.map((x) => [after.roles.find((y) => y.id === x.role_id)?.name, Number(x.placement.x)]).sort();
    const g = await api.templates.get(tp.id);
    await api.templates.remove(tp.id, g.etag);
    // Account settings: {settings} only; the answer is {settings}.
    const acct = await api.account();
    const set = await api.patchAccountSettings({ web10_probe: stamp });
    r.settingsKeys = Object.keys(set);
    r.settingsProbe = set.settings.web10_probe === stamp;
    await api.patchAccountSettings({ web10_probe: null });
    r.builtin = Object.keys(acct.settings?.builtin_profiles || {}).sort();
    try { await api.request("PATCH", "/api/v1/accounts/me", { body: { name: "x", settings: {} } }); r.nameRefused = false; } catch (e) { r.nameRefused = e.code; }
    // Members: invite needs a name; the state is on a single read and the reinvite.
    try { await api.users.invite({ email: `noname${stamp}@example.com`, profile: "viewer" }); r.inviteNoName = "accepted"; } catch (e) { r.inviteNoName = e.code; }
    const u = await api.users.invite({ email: `inv${stamp}@example.com`, name: "Invited Probe", profile: "viewer" });
    r.inviteState = u.invitation;
    r.listHasState = "invitation" in ((await api.users.list()).items.find((x) => x.id === u.id) || {});
    r.getState = (await api.users.get(u.id)).invitation;
    r.reinviteState = (await api.users.reinvite(u.id)).invitation;
    await api.users.remove(u.id);
    // A sent envelope corrected by PATCH: name, and an access code newly required.
    const env = await api.createEnvelope({
      subject: `WEB-10 correct ${stamp}`, status: "sent",
      documents: [{ name: "c.pdf", content_base64: btoa(String.fromCharCode(...lib.makePdf([{ title: "Correct me" }]))) }],
      recipients: [{ ref: "a", type: "signer", name: "Ana Probe", email: `ana${stamp}@example.com`, routing_order: 1 }, { ref: "b", type: "signer", name: "Ben Probe", email: `ben${stamp}@example.com`, routing_order: 1 }],
      fields: [{ recipient: "a", document: 0, type: "signature", page: 1, x: "72", y: "600", width: "160", height: "44" }, { recipient: "b", document: 0, type: "signature", page: 1, x: "300", y: "600", width: "160", height: "44" }],
    });
    r.parallelOrders = env.recipients.map((x) => x.routing_order);
    const { envelope: e1, etag } = await api.getEnvelope(env.id);
    const ana = e1.recipients.find((x) => x.name === "Ana Probe");
    try { await api.correctEnvelope(env.id, etag, [{ op: "update_recipient", recipient: { id: ana.id, type: ana.type, routing_order: ana.routing_order, name: "X", email: ana.email, auth: ["access_code"], access_code: "1234" } }]); r.correctWithCode = "accepted"; } catch (e) { r.correctWithCode = e.code; }
    await api.patchRecipient(env.id, ana.id, (await api.getEnvelope(env.id)).etag, { name: "Ana Corrected", auth: ["access_code"], access_code: "2468" });
    const a2 = (await api.getEnvelope(env.id)).envelope.recipients.find((x) => x.id === ana.id);
    r.corrected = [a2.name, a2.auth, a2.delivery];
    // Detection: suggestions in the field geometry, nothing changed.
    const before = (await api.getEnvelope(env.id)).etag;
    const det = await api.detectFields(env.id, e1.documents[0].id);
    r.detectShape = Array.isArray(det.items) && typeof det.truncated === "boolean";
    r.detectSame = (await api.getEnvelope(env.id)).etag === before;
    await api.voidEnvelope(env.id, "WEB-10 probe");
    return r;
  });
  expect(out).toMatchObject({
    docFromWhole: true, fieldRole: true,
    afterRoles: ["Landlord", "Tenant"],
    afterFields: [["Landlord", 72], ["Tenant", 90]],
    settingsKeys: ["settings"], settingsProbe: true, builtin: ["admin", "sender", "viewer"],
    nameRefused: "CS-API-0001", inviteNoName: "CS-API-0001",
    listHasState: false,
    parallelOrders: [1, 1],
    correctWithCode: "CS-API-0001",
    corrected: ["Ana Corrected", ["access_code"], "email"],
    detectShape: true, detectSame: true,
  });
  expect(out.afterName).toMatch(/edited$/);
  for (const k of ["inviteState", "getState", "reinviteState"]) expect(["pending", "sent"]).toContain(out[k]);
});

test("the editor on the server: a template saved, reopened and saved back; a parallel step; detection", async ({ page }) => {
  await signIn(page, "home");
  const name = `Editor template ${Date.now()}`;
  await page.goto(app("#/templates/new"));
  await page.getByTestId("pdf-input").setInputFiles(pdfFile("tpl.pdf", "Template"));
  await page.getByTestId("wizard-next").click();
  await page.getByRole("button", { name: "Add role" }).first().click();
  await page.getByTestId("role-name").fill("Client");
  await page.getByTestId("wizard-next").click();
  await expect(page.locator(".os-page.is-loading")).toHaveCount(0);
  await page.locator(".os-palette").getByRole("button", { name: "Add Signature field" }).click();
  await page.locator(".os-stepper__btn", { hasText: "Review" }).click();
  await page.getByLabel("Template name").fill(name);
  await page.getByRole("button", { name: "Save template" }).click();
  await expect(page.locator(".os-toast").last()).toContainText("Template saved.");
  await page.getByRole("button", { name: `Actions for ${name}` }).click();
  await page.getByRole("menuitem", { name: "Edit", exact: true }).click();
  await expect(page.locator(".os-field")).toHaveCount(1);
  await page.locator(".os-stepper__btn", { hasText: "Roles" }).click();
  await page.getByRole("button", { name: "Add role" }).first().click();
  await page.getByTestId("role-name").nth(1).fill("Witness");
  await page.getByLabel("Signing step for Witness").fill("1");
  await page.getByLabel("Signing step for Witness").press("Enter");
  await page.locator(".os-stepper__btn", { hasText: "Fields" }).click();
  await placingFor(page, "Witness");
  await page.locator(".os-palette").getByRole("button", { name: "Add Date signed field" }).click();
  await page.locator(".os-stepper__btn", { hasText: "Review" }).click();
  await page.getByRole("button", { name: "Save template" }).click();
  await expect(page.locator(".os-toast").last()).toContainText("Template saved.");
  const tp = await inApp(page, async (api, _lib, n) => {
    const t = (await api.templates.list()).items.find((x) => x.name === n);
    const { template } = await api.templates.get(t.id);
    return { roles: template.roles.map((r) => [r.name, r.routing_order]).sort(), fields: template.fields.map((f) => [template.roles.find((r) => r.id === f.role_id)?.name, f.type]).sort() };
  }, name);
  expect(tp).toEqual({ roles: [["Client", 1], ["Witness", 1]], fields: [["Client", "signature"], ["Witness", "date_signed"]] });

  // Detection on a draft: the server's suggestions, or its "none", never an error.
  await page.goto(app("#/prepare"));
  await page.getByTestId("pdf-input").setInputFiles(pdfFile("detect.pdf", "Detect me"));
  await page.getByTestId("wizard-next").click();
  await page.getByRole("button", { name: "Add recipient" }).first().click();
  await page.getByTestId("recipient-name").fill("Dee Tect");
  await page.getByTestId("recipient-email").fill("dee@example.com");
  await page.getByTestId("wizard-next").click();
  await expect(page.locator(".os-page.is-loading")).toHaveCount(0);
  await page.getByTestId("detect-fields").click();
  await expect(page.locator(".os-toast").last()).toContainText(/suggested fields for Dee Tect|No fields found to suggest/);
});
