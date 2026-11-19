// Slice 3 (templates, VS-03): composite templates and template folders, the pure rules
// (templatemodel.js) and the mock as the server answers them (server tests/use_templates.rs).
// Run: npm test (in webapp/).
import test from "node:test";
import assert from "node:assert/strict";

import { createMockFetch, MOCK } from "../mock.js";
import { createClient } from "../api.js";
import { makePdf } from "../mockpdf.js";
import { mergeTemplates, fromTemplatesBody, roleKey } from "../templatemodel.js";

test("roles of the same name in several templates are one recipient, the first template's type and order", () => {
  const nda = { roles: [{ id: "a1", name: "Buyer", type: "signer", routing_order: 1 }, { id: "a2", name: "Agent", type: "cc", routing_order: 3 }] };
  const order = { roles: [{ id: "b1", name: " buyer ", type: "signer", routing_order: 4 }, { id: "b2", name: "Seller", type: "signer", routing_order: 2 }] };
  const { roles, roleOf, conflict } = mergeTemplates([nda, order]);
  assert.deepEqual(roles.map((r) => [r.name, r.type, r.routing_order]), [["Buyer", "signer", 1], ["Seller", "signer", 2], ["Agent", "cc", 3]]);
  assert.equal(conflict, -1);
  assert.equal(roleOf.get("b1"), roleOf.get("a1"));
  assert.equal(roleOf.get("b1"), roleKey("BUYER"));
});

test("a role named again with another type is a conflict at that template", () => {
  const a = { roles: [{ id: "a1", name: "Buyer", type: "signer" }] };
  const b = { roles: [{ id: "b1", name: "Other", type: "signer" }] };
  const c = { roles: [{ id: "c1", name: "buyer", type: "cc" }] };
  assert.equal(mergeTemplates([a, b, c]).conflict, 2);
});

test("the from-templates body fills each role once and puts added people after them", () => {
  const { roles } = mergeTemplates([{ roles: [{ id: "x", name: "Client", type: "signer" }] }]);
  const body = fromTemplatesBody(["t1", "t2"], roles, { client: { name: " Ada ", email: " ada@example.test " } },
    { extra: [{ name: "Cy", email: "cy@example.test", type: "cc" }], subject: " Hi ", message: "M", status: "sent" });
  assert.deepEqual(body, {
    template_ids: ["t1", "t2"], status: "sent", subject: "Hi", message: "M",
    recipients: [{ role: "Client", name: "Ada", email: "ada@example.test" }, { name: "Cy", email: "cy@example.test", type: "cc" }],
  });
});

async function signedIn() {
  const c = createClient({ fetch: createMockFetch() });
  await c.login(MOCK.email, MOCK.password);
  return c;
}

/// A template with one document and a signature field per signer role.
async function template(c, name, roles) {
  const tp = await c.templates.create({ name, email_subject: `Please sign: ${name}`, roles });
  const whole = await c.templates.addDocument(tp.id, `${name}.pdf`, makePdf([{ title: name }]));
  const doc = whole.documents[0].id;
  const signers = whole.roles.filter((r) => r.type === "signer");
  if (signers.length) {
    await c.templates.addFields(tp.id, signers.map((r, i) => ({ role_id: r.id, document_id: doc, type: "signature", required: true, label: `${name} ${r.name}`, placement: { page: 1, x: "72", y: String(100 + 60 * i), width: "160", height: "36" } })));
  }
  return (await c.templates.get(tp.id)).template;
}

test("the mock makes one envelope from two templates as the server does", async () => {
  const c = await signedIn();
  const nda = await template(c, "NDA", [{ name: "Buyer", type: "signer", routing_order: 1 }]);
  const order = await template(c, "Order", [{ name: "buyer", type: "signer", routing_order: 3 }, { name: "Seller", type: "signer", routing_order: 2 }]);
  const env = await c.templates.use({
    template_ids: [nda.id, order.id], status: "sent",
    recipients: [{ role: "BUYER", name: "Bea", email: "bea@example.test" }, { role: "Seller", name: "Sol", email: "sol@example.test" }],
  });
  assert.equal(env.status, "sent");
  assert.equal(env.subject, "Please sign: NDA");
  assert.deepEqual(env.documents.map((d) => d.name), ["NDA.pdf", "Order.pdf"]);
  assert.deepEqual(env.recipients.map((r) => [r.email, r.routing_order]).sort(), [["bea@example.test", 1], ["sol@example.test", 2]]);
  const bea = env.recipients.find((r) => r.email === "bea@example.test").id;
  assert.deepEqual(env.fields.filter((f) => f.recipient_id === bea).map((f) => f.document_id).sort(), [env.documents[0].id, env.documents[1].id].sort());
  // Refused at the member that is wrong.
  const pointer = async (body) => { try { await c.templates.use(body); return null; } catch (e) { return e.errors?.[0]?.pointer; } };
  assert.equal(await pointer({ template_ids: [nda.id, order.id], recipients: [{ role: "Buyer", name: "B", email: "b@example.test" }] }), "/recipients");
  assert.equal(await pointer({ template_ids: [nda.id, nda.id], recipients: [] }), "/template_ids/1");
  assert.equal(await pointer({ template_ids: [nda.id], recipients: [{ role: "Nobody", name: "N", email: "n@example.test" }] }), "/recipients/0/role");
});

test("the mock files templates in each member's template folders, apart from envelope folders", async () => {
  const c = await signedIn();
  const nda = await template(c, "NDA", [{ name: "Client", type: "signer", routing_order: 1 }]);
  const f = await c.createFolder("Sales", "templates");
  assert.equal(f.kind, "templates");
  await c.createFolder("Sales");
  await assert.rejects(c.createFolder("sales", "templates"), (e) => e.errors?.[0]?.code === "exists");
  assert.equal((await c.moveTemplates(f.id, [nda.id])).moved, 1);
  assert.deepEqual((await c.listFolders("templates")).items.map((x) => [x.name, x.count]), [["Sales", 1]]);
  assert.ok((await c.listFolders()).items.every((x) => x.kind === "envelopes"));
  assert.deepEqual((await c.templates.list("all", f.id)).items.map((x) => x.name), ["NDA"]);
  assert.ok(!(await c.templates.list("all", "none")).items.some((x) => x.id === nda.id));
  const envFolder = (await c.listFolders()).items[0].id;
  await assert.rejects(c.moveTemplates(envFolder, [nda.id]), (e) => e.status === 404);
  await c.moveTemplates(null, [nda.id]);
  assert.ok((await c.templates.list("all", "none")).items.some((x) => x.id === nda.id));
});
