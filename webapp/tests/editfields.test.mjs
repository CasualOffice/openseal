// VS-06A: an editor changes fields during their turn, and an intermediary sets a later
// recipient's authentication. The pure model (editfields.js) and the mock answering as
// the server's ceremony does (ceremony.rs `place_fields`, `edit_field`, `remove_field`).
// Run: npm test (in webapp/).
import test from "node:test";
import assert from "node:assert/strict";

import { createMockFetch, MOCK } from "../mock.js";
import { createClient } from "../api.js";
import { makePdf } from "../mockpdf.js";
import { canEditFields, editableFields, ownersOf, newField, keyStep, moved, movePatch, laterAuthOf, laterAuthChange } from "../editfields.js";

const ME = { id: "ed", type: "editor", name: "Eda" };
const VIEW = {
  recipient: ME,
  fields: [{ id: "f1", recipient_id: "ed", type: "signature", placement: { page: 1, x: "72", y: "100", width: "160", height: "44" } },
    { id: "f2", recipient_id: "other", shared_with: ["ed"], type: "text", placement: { page: 1, x: "72", y: "200", width: "160", height: "22" } }],
  editable_fields: [{ id: "f3", recipient_id: "s2", type: "signature", placement: { page: 1, x: "72", y: "300", width: "160", height: "44" } }],
  later_recipients: [{ id: "s2", name: "Sam", type: "signer" }],
};

test("an editor may change their own fields and the later recipients' listed, never a field merely shared with them", () => {
  assert.equal(canEditFields(VIEW), true);
  assert.equal(canEditFields({ ...VIEW, recipient: { ...ME, type: "signer" } }), false);
  assert.equal(canEditFields({ ...VIEW, editable_fields: undefined }), false);
  assert.deepEqual(editableFields(VIEW).map((f) => f.id), ["f1", "f3"]);
  assert.deepEqual(editableFields(VIEW)[1].p, { page: 1, x: 72, y: 300, width: 160, height: 44 });
  assert.deepEqual(ownersOf(VIEW), [{ id: "ed", name: "Eda", me: true }, { id: "s2", name: "Sam", me: false }]);
});

test("a new field lands on the page clear of the others; arrows move it 1 point, 10 with Shift, kept on the page", () => {
  const page = { width: 612, height: 792 };
  const w = newField({ type: "signature", recipientId: "s2", documentId: "d", pageNo: 2, page, existing: [] });
  assert.equal(w.recipient_id, "s2");
  assert.equal(w.page, 2);
  assert.equal(w.required, true);
  const r = { x: Number(w.x), y: Number(w.y), width: Number(w.width), height: Number(w.height) };
  const again = newField({ type: "signature", recipientId: "s2", documentId: "d", pageNo: 2, page, existing: [r] });
  assert.notEqual(again.y, w.y, "a second field does not cover the first");
  assert.deepEqual(keyStep({ key: "ArrowLeft" }), [-1, 0, 0, 0]);
  assert.deepEqual(keyStep({ key: "ArrowDown", shiftKey: true }), [0, 10, 0, 0]);
  assert.equal(keyStep({ key: "a" }), null);
  assert.deepEqual(movePatch(moved({ x: 1, y: 5, width: 10, height: 10 }, -10, 2.5, page)), { x: "0", y: "7.5", width: "10", height: "10" });
  // FG-080: Alt resizes, so a strike-through is made as long as the words it strikes.
  assert.deepEqual(keyStep({ key: "ArrowRight", altKey: true, shiftKey: true }), [0, 0, 10, 0]);
  assert.deepEqual(movePatch(moved({ x: 600, y: 5, width: 10, height: 10 }, 0, 0, page, 10, 0)), { x: "592", y: "5", width: "20", height: "10" });
});

/// A sent envelope in the mock: an editor and a parallel signer at order 1, a signer
/// at 2; answers the client, the envelope and each recipient's token.
async function sent() {
  const c = createClient({ fetch: createMockFetch() });
  await c.login(MOCK.email, MOCK.password);
  const pdf = Buffer.from(makePdf([{ title: "VS-06A" }])).toString("base64");
  const sig = (r, y) => ({ recipient: r, document: 0, type: "signature", page: 1, x: 72, y, width: 160, height: 44, required: true });
  const env = await c.createEnvelope({
    subject: "VS-06A", status: "sent",
    documents: [{ name: "a.pdf", content_base64: pdf }],
    recipients: [{ ref: "ed", type: "editor", name: "Eda", email: "ed@example.com", routing_order: 1 },
      { ref: "p1", type: "signer", name: "Pat", email: "pat@example.com", routing_order: 1 },
      { ref: "s2", type: "signer", name: "Sam", email: "sam@example.com", routing_order: 2 }],
    fields: [sig("ed", 100), sig("p1", 200), sig("s2", 300)],
  });
  return { c, env, tokens: env.recipients.map((r) => r.mock_token) };
}

async function ready(c, t) {
  await c.ceremony.open(t);
  return c.ceremony.consent(t, MOCK.ersd);
}

test("the mock, as the server: an editor adds and moves a later signer's field; a reached one's is refused; a signer may not", async () => {
  const { c, env, tokens } = await sent();
  const [, p1, s2] = env.recipients.map((r) => r.id);
  const doc = env.documents[0].id;
  let v = await ready(c, tokens[0]);
  const later = v.editable_fields.map((f) => f.recipient_id);
  assert.deepEqual(later, [s2], "the parallel signer's field is not listed");
  v = await c.ceremony.placeFields(tokens[0], [{ recipient_id: s2, document_id: doc, type: "text", page: 1, x: "300", y: "300", width: "120", height: "22" }]);
  assert.equal(v.editable_fields.length, 2);
  const target = v.editable_fields.find((f) => f.type === "signature");
  v = await c.ceremony.editField(tokens[0], target.id, { x: "320" });
  assert.equal(v.editable_fields.find((f) => f.id === target.id).placement.x, "320");
  const pf = env.fields.find((f) => f.recipient_id === p1).id;
  await assert.rejects(c.ceremony.editField(tokens[0], pf, { x: "10" }), (e) => e.status === 409 && e.code === "CS-WF-0001");
  await assert.rejects(c.ceremony.placeFields(tokens[0], [{ recipient_id: p1, document_id: doc, type: "text", page: 1, x: "1", y: "1", width: "50", height: "20" }]), (e) => e.status === 409);
  v = await c.ceremony.removeField(tokens[0], v.editable_fields.find((f) => f.type === "text").id);
  assert.equal(v.editable_fields.length, 1);
  await ready(c, tokens[1]);
  await assert.rejects(c.ceremony.editField(tokens[1], target.id, { x: "1" }), (e) => e.status === 409);
});

test("the later recipient's authentication: a method chosen, its code or number asked, nothing sent when unchanged", () => {
  assert.equal(laterAuthOf([]), "none");
  assert.equal(laterAuthOf(["kba", "sms_otp"]), "sms_otp");
  assert.deepEqual(laterAuthChange({ had: "none", method: "none" }), { body: null });
  assert.deepEqual(laterAuthChange({ had: "none", method: "access_code" }), { error: "need-code" });
  assert.deepEqual(laterAuthChange({ had: "none", method: "access_code", code: "c-1" }), { body: { auth: ["access_code"], access_code: "c-1" } });
  assert.deepEqual(laterAuthChange({ had: "access_code", method: "access_code" }), { body: null }, "the code set stays");
  assert.deepEqual(laterAuthChange({ had: "none", method: "sms_otp", phone: "07700" }), { error: "need-phone" });
  assert.deepEqual(laterAuthChange({ had: "none", method: "sms_otp", phone: "+44 7700 900123" }), { body: { auth: ["sms_otp"], phone: "+44 7700 900123" } });
  assert.deepEqual(laterAuthChange({ had: "email_otp", method: "none" }), { body: { auth: [] } });
});

test("the mock, as the server: an intermediary sets an access code the signer must then pass; an agent may not", async () => {
  const c = createClient({ fetch: createMockFetch() });
  await c.login(MOCK.email, MOCK.password);
  const pdf = Buffer.from(makePdf([{ title: "VS-06A auth" }])).toString("base64");
  const env = await c.createEnvelope({
    subject: "VS-06A auth", status: "sent",
    documents: [{ name: "a.pdf", content_base64: pdf }],
    recipients: [{ ref: "ag", type: "agent", name: "Al", email: "al@example.com", routing_order: 1 },
      { ref: "im", type: "intermediary", name: "Ian", email: "ian@example.com", routing_order: 2 },
      { ref: "s", type: "signer", name: "Bea", email: "bea@example.com", routing_order: 3 }],
    fields: [{ recipient: "s", document: 0, type: "signature", page: 1, x: 72, y: 100, width: 160, height: 44, required: true }],
  });
  const [ag, im, s] = env.recipients;
  await ready(c, ag.mock_token);
  await assert.rejects(c.ceremony.nameRecipients(ag.mock_token, [{ id: s.id, auth: ["access_code"], access_code: "x-1" }]), (e) => e.status === 403);
  await c.ceremony.finish(ag.mock_token);
  const sent = (await c.getEnvelope(env.id)).envelope;
  const it = sent.recipients.find((r) => r.id === im.id);
  await ready(c, it.mock_token);
  await assert.rejects(c.ceremony.nameRecipients(it.mock_token, [{ id: s.id, auth: ["access_code"] }]), (e) => e.status === 422 && e.errors[0]?.pointer === "/recipients/0/access_code");
  const v = await c.ceremony.nameRecipients(it.mock_token, [{ id: s.id, auth: ["access_code"], access_code: "set-by-ian" }]);
  assert.deepEqual(v.later_recipients[0].auth, ["access_code"]);
  assert.ok(!JSON.stringify(v).includes("set-by-ian"), "never answered");
  await c.ceremony.finish(it.mock_token);
  const signer = (await c.getEnvelope(env.id)).envelope.recipients.find((r) => r.id === s.id);
  await c.ceremony.open(signer.mock_token);
  await assert.rejects(c.ceremony.authenticate(signer.mock_token, "access_code", "guess"));
  const ok = await c.ceremony.authenticate(signer.mock_token, "access_code", "set-by-ian");
  assert.deepEqual(ok.auth_required, []);
});

test("FG-080, the mock as the server: an editor's strike-through is listed to everyone who sees the document", async () => {
  const { c, env, tokens } = await sent();
  const [ed] = env.recipients.map((r) => r.id);
  const doc = env.documents[0].id;
  let v = await ready(c, tokens[0]);
  assert.deepEqual(v.strikes, []);
  v = await c.ceremony.placeFields(tokens[0], [{ recipient_id: ed, document_id: doc, type: "strikethrough", page: 1, x: "72", y: "400", width: "200", height: "10" }]);
  assert.equal(v.strikes.length, 1);
  assert.equal(v.strikes[0].placement.width, "200");
  assert.ok(editableFields(v).some((f) => f.type === "strikethrough"), "the editor may move it");
  const other = await ready(c, tokens[1]);
  assert.equal(other.strikes.length, 1, "the parallel signer sees it too");
  assert.ok(!other.fields.some((f) => f.type === "strikethrough"));
});
