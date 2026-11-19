// Slice 4 through the mock server (VS-04C): the signing view's `rules` follow each fill,
// as the real server's do (server/casual-sign-server/tests/every_field.rs).
import { test } from "node:test";
import assert from "node:assert/strict";

import { createClient, recipientWire, fieldWire } from "../api.js";
import { createMockFetch, MOCK } from "../mock.js";
import { makePdf } from "../mockpdf.js";

function memoryStore() {
  const m = new Map();
  return { getItem: (k) => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)), removeItem: (k) => m.delete(k) };
}

test("the mock's signing view carries rules that follow each fill", async () => {
  const store = memoryStore();
  const api = createClient({ fetch: createMockFetch({ store }), store });
  await api.login(MOCK.email, MOCK.password);
  const pdf = Buffer.from(makePdf([{ title: "Form" }])).toString("base64");
  const at = (type, y, extra = {}) => fieldWire({ recipient: "r0", document: 0, type, page: 1, x: 72, y, width: 200, height: 20, ...extra });
  const env = await api.createEnvelope({
    subject: "rules", status: "sent",
    documents: [{ name: "f.pdf", content_base64: pdf }],
    recipients: [recipientWire({ ref: "r0", routing_order: 1, name: "S", email: "s@example.com", type: "signer" })],
    fields: [at("signature", 40, { required: true }), at("checkbox", 80, { label: "agree" }),
      at("text", 120, { label: "detail", conditional: { parent_label: "agree", when: "checked" } }),
      at("text", 160, { label: "ref" }), at("text", 200, { label: "ref" })],
  });
  const token = env.recipients[0].mock_token;
  let v = await api.ceremony.open(token);
  if (v.consent_required) v = await api.ceremony.consent(token, v.consent_required.version);
  const id = (label) => v.fields.filter((f) => f.label === label).map((f) => f.id);
  assert.deepEqual(v.rules.hidden, id("detail"));
  v = await api.ceremony.fill(token, id("agree")[0], { checked: true });
  assert.deepEqual(v.rules.hidden, []);
  const [a, b] = id("ref");
  v = await api.ceremony.fill(token, a, { text: "R-77" });
  assert.deepEqual(v.rules.values[b], { text: "R-77" });
});

test("the mock's Detect fields suggests a PDF's own form fields and its text tags (VS-04E, VS-04F)", async () => {
  const store = memoryStore();
  const api = createClient({ fetch: createMockFetch({ store }), store });
  await api.login(MOCK.email, MOCK.password);
  const pdf = Buffer.from(makePdf([{
    title: "Form", lines: ["{{date:applicant:req:start_date}}"],
    form: [{ name: "policy_number", type: "text", rect: [72, 560, 272, 580] }, { name: "sig", type: "signature", rect: [72, 200, 272, 240] }],
  }])).toString("base64");
  const env = await api.createEnvelope({ subject: "form", documents: [{ name: "f.pdf", content_base64: pdf }] });
  const { items } = await api.detectFields(env.id, env.documents[0].id);
  const own = items.filter((x) => x.source === "acroform").map((x) => [x.type, x.cue, x.y, x.height]);
  assert.deepEqual(own, [["text", "policy_number", "212", "20"], ["signature", "sig", "552", "40"]]);
  const tags = items.filter((x) => x.source === "tag").map((x) => [x.type, x.cue]);
  assert.deepEqual(tags, [["date", "start_date"]]);
});

test("the mock shares a field with a second signer, who sees and changes it (VS-04D)", async () => {
  const store = memoryStore();
  const api = createClient({ fetch: createMockFetch({ store }), store });
  await api.login(MOCK.email, MOCK.password);
  const pdf = Buffer.from(makePdf([{ title: "Form" }])).toString("base64");
  const env = await api.createEnvelope({
    subject: "shared", status: "sent",
    documents: [{ name: "f.pdf", content_base64: pdf }],
    recipients: [
      recipientWire({ ref: "r0", routing_order: 1, name: "One", email: "one@example.com", type: "signer" }),
      recipientWire({ ref: "r1", routing_order: 1, name: "Two", email: "two@example.com", type: "signer" }),
    ],
    fields: [
      fieldWire({ recipient: "r0", document: 0, type: "text", label: "notes", shared_with: ["r1"], page: 1, x: 72, y: 100, width: 200, height: 20 }),
      fieldWire({ recipient: "r1", document: 0, type: "signature", page: 1, x: 72, y: 300, width: 160, height: 40 }),
    ],
  });
  const notes = env.fields[0];
  const two = env.recipients.find((r) => r.email === "two@example.com");
  assert.deepEqual(notes.shared_with, [two.id]);
  let v = await api.ceremony.open(two.mock_token);
  if (v.consent_required) v = await api.ceremony.consent(two.mock_token, v.consent_required.version);
  assert.ok(v.fields.some((f) => f.id === notes.id), "the shared field is in the second signer's view");
  v = await api.ceremony.fill(two.mock_token, notes.id, { text: "Changed by Two" });
  assert.deepEqual(v.fields.find((f) => f.id === notes.id).value, { text: "Changed by Two" });
});
