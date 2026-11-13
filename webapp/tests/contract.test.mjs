// The API client and mock contract the UI packages build on (UX-03): every new call
// against the mock, the shapes it round-trips, and the calls the server does not serve
// yet refused by the client at once. Run: npm test (in webapp/).
import test from "node:test";
import assert from "node:assert/strict";

import { createMockFetch, MOCK, MOCK_DISCLOSURE } from "../mock.js";
import {
  createClient, corrections, fieldWire, recipientWire, recipientSpec, NOT_ON_SERVER, WEBHOOK_EVENT_TYPES,
  RECIPIENT_TYPES, FIELD_TYPES, FIELD_MEMBERS,
} from "../api.js";
import { makePdf } from "../mockpdf.js";
import { EN } from "../strings.en.js";
import { readFileSync } from "node:fs";

const PNG = btoa("\x89PNG\r\n\x1a\n" + "x".repeat(16));
const b64 = (bytes) => btoa(String.fromCharCode(...bytes));

async function signedIn() {
  const c = createClient({ fetch: createMockFetch() });
  await c.login(MOCK.email, MOCK.password);
  return c;
}
async function sha256hex(text) {
  const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
/// A sent envelope of one two-page document with these recipients and fields.
async function sentWith(c, recipients, fields) {
  const pdf = makePdf([{ title: "P1" }, { title: "P2" }]);
  const env = await c.createEnvelope({
    subject: "Contract test", documents: [{ name: "a.pdf", content_base64: b64(pdf) }],
    recipients: recipients.map((r, i) => recipientWire({ ref: `r${i}`, ...r })),
    fields: fields.map(({ to, ...f }) => fieldWire({ recipient: `r${to}`, document: 0, ...f })),
    status: "sent",
  });
  return env;
}
const tokenOf = (env, i) => env.recipients[i].mock_token;

// ---- webhooks ---------------------------------------------------------------------------
test("webhooks: list, create (public https only), get, deliveries for subscribed events, disable", async () => {
  const c = await signedIn();
  const seeded = await c.listWebhooks();
  assert.equal(seeded.items.length, 1);
  assert.deepEqual(Object.keys(seeded.items[0]).sort(), ["active", "envelope_id", "event_types", "id", "secret_refs", "url"]);
  const rows = await c.listDeliveries(seeded.items[0].id);
  assert.deepEqual(rows.items.map((d) => d.status), ["failed", "delivered"]);
  assert.deepEqual(Object.keys(rows.items[0]).sort(), ["attempts", "event_id", "event_type", "id", "last_status_code", "status"]);

  for (const url of ["http://hooks.example.com/x", "https://localhost/x", "https://10.0.0.8/x", "https://169.254.169.254/latest", "https://user@hooks.example.com/", "https://intranet/x"]) {
    await assert.rejects(c.createWebhook({ url, event_types: ["envelope.voided"], secret_refs: ["s1"] }), (e) => e.status === 422 && e.code === "CS-API-0013", url);
  }
  await assert.rejects(c.createWebhook({ url: "https://hooks.example.org/a", event_types: ["envelope.nope"], secret_refs: ["s1"] }), (e) => e.code === "CS-API-0001" && e.errors[0].pointer === "/event_types");
  await assert.rejects(c.createWebhook({ url: "https://hooks.example.org/a", event_types: ["envelope.voided"], secret_refs: [] }), (e) => e.errors[0].pointer === "/secret_refs");
  await assert.rejects(c.createWebhook({ url: "https://hooks.example.org/a", event_types: ["envelope.voided"], secret_refs: ["s1"], secret: "x" }), (e) => e.code === "CS-API-0001");

  const w = await c.createWebhook({ url: "https://hooks.example.org/a", event_types: ["envelope.voided", "recipient.completed"], secret_refs: ["s1"] });
  assert.equal(w.active, true);
  assert.deepEqual(await c.getWebhook(w.id), w);
  assert.deepEqual((await c.listDeliveries(w.id)).items, []);
  // A subscribed event is delivered; another is not.
  const list = await c.listEnvelopes({ status: "sent", limit: 200 });
  const target = list.items.find((e) => e.subject.startsWith("Vendor"));
  await c.voidEnvelope(target.id, "Test");
  const after = (await c.listDeliveries(w.id)).items;
  assert.deepEqual(after.map((d) => [d.event_type, d.status, d.last_status_code]), [["envelope.voided", "delivered", 200]]);
  await c.deleteWebhook(w.id);
  assert.equal((await c.getWebhook(w.id)).active, false);
  assert.equal((await c.listDeliveries(w.id)).items.length, 1, "deliveries stay readable");
  await assert.rejects(c.getWebhook("nope"), (e) => e.code === "CS-API-0002");
  assert.ok(WEBHOOK_EVENT_TYPES.includes("envelope.completed") && WEBHOOK_EVENT_TYPES.length === 20);
});

test("webhooks: update, test and redeliver answer in the mock as the server does (UXW-31..33)", async () => {
  const c = await signedIn();
  const [w] = (await c.listWebhooks()).items;
  assert.equal((await c.updateWebhook(w.id, { active: false })).active, false);
  await assert.rejects(c.testWebhook(w.id), (e) => e.status === 409 && e.code === "CS-API-0009");
  await c.updateWebhook(w.id, { active: true, event_types: ["envelope.sent"] });
  await assert.rejects(c.updateWebhook(w.id, { url: "http://x.example/" }), (e) => e.code === "CS-API-0013");
  const d = await c.testWebhook(w.id);
  assert.equal(d.event_type, "webhook.test");
  const failed = (await c.listDeliveries(w.id)).items.find((x) => x.status === "failed");
  const again = await c.redeliver(w.id, failed.id);
  assert.deepEqual([again.status, again.attempts], ["delivered", 7]);
});

// ---- the ceremony view ------------------------------------------------------------------
test("the ceremony view names the sender and the disclosure it asks consent to", async () => {
  const c = await signedIn();
  const v = await c.ceremony.open(MOCK.ceremonyToken);
  assert.deepEqual(v.sender, { name: "Demo Admin", email: MOCK.email, organisation: "Demo account" });
  assert.equal(v.capture_location, true);
  assert.equal(v.consent_required.version, MOCK.ersd);
  assert.equal(v.consent_required.sha256, `sha256:${await sha256hex(MOCK_DISCLOSURE)}`);
  assert.equal(v.consent_required.url, `/s/${MOCK.ceremonyToken}/disclosure`);
  assert.ok(v.envelope.expires_at);
  // As consent: only once every authentication has passed (UXW-34).
  await assert.rejects(c.ceremony.disclosure(MOCK.ceremonyToken), (e) => e.code === "CS-AUTH-0003");
  await c.ceremony.authenticate(MOCK.ceremonyToken, "access_code", MOCK.accessCode);
  const d = await c.ceremony.disclosure(MOCK.ceremonyToken);
  assert.deepEqual(d, { version: MOCK.ersd, sha256: v.consent_required.sha256, text: MOCK_DISCLOSURE });
  // The brand name, when the account has one, is the organisation.
  await c.patchAccountSettings({ branding: { name: "Acme Legal" } });
  assert.equal((await c.ceremony.view(MOCK.ceremonyToken)).sender.organisation, "Acme Legal");
});

// ---- field and recipient shapes ---------------------------------------------------------
test("every field member round-trips through the mock, and null removes one", async () => {
  const c = await signedIn();
  const members = {
    required: true, label: "Qty", tooltip: "How many", placeholder: "1-100",
    validation: { kind: "number", min: "1", max: "100", decimals: 0, message: "1 to 100" },
    format: { font_family: "courier", font_size: "11", color: "#112233", align: "right" },
    default: { text: "1" },
    conditional: { parent_label: "Wants", when: "checked" },
    group: { id: "g1", rule: { rule: "select_at_least", min: 1 } },
  };
  const env = await c.createEnvelope({
    documents: [{ name: "a.pdf", content_base64: b64(makePdf([{ title: "T" }])) }],
    recipients: [recipientWire({ ref: "a", name: "A", email: "a@example.com", phone: "+15550100", delivery: "email", time_zone_offset_minutes: 60, date_format: "dd/mm/yyyy" })],
    fields: [
      fieldWire({ recipient: "a", document: 0, type: "number", page: 1, x: 72, y: 100, width: 80, height: 20, ...members, read_only: false }),
      fieldWire({ recipient: "a", document: 0, type: "dropdown", page: 1, x: 72, y: 140, width: 80, height: 20, options: ["One", "Two"], allow_custom: true }),
      fieldWire({ recipient: "a", document: 0, type: "formula", page: 1, x: 72, y: 180, width: 80, height: 20, formula: { expression: "[Qty] * 2", precision: 0 } }),
    ],
  });
  const [num, drop, formula] = env.fields;
  for (const [k, v] of Object.entries(members)) assert.deepEqual(num[k], v, k);
  assert.ok(!("read_only" in num), "false members are absent, as the server writes them");
  assert.deepEqual([drop.options, drop.allow_custom], [["One", "Two"], true]);
  assert.deepEqual(formula.formula, { expression: "[Qty] * 2", precision: 0 });
  assert.deepEqual([env.recipients[0].phone, env.recipients[0].time_zone_offset_minutes, env.recipients[0].date_format], ["+15550100", 60, "dd/mm/yyyy"]);
  const { etag } = await c.getEnvelope(env.id);
  const patched = await c.patchField(env.id, num.id, etag, { tooltip: null, format: { font_size: "9" }, locked: true });
  assert.ok(!("tooltip" in patched));
  assert.deepEqual([patched.format, patched.locked, patched.label], [{ font_size: "9" }, true, "Qty"]);
  // The kinds are checked: a member of the wrong JSON kind, an unknown type.
  const { etag: e2 } = await c.getEnvelope(env.id);
  await assert.rejects(c.patchField(env.id, num.id, e2, { options: "One" }), (e) => e.code === "CS-FLD-0002");
  await assert.rejects(c.addFields(env.id, [fieldWire({ recipient: env.recipients[0].id, document: env.documents[0].id, type: "hologram", page: 1, x: 1, y: 1, width: 9, height: 9 })]), (e) => e.code === "CS-FLD-0002");
  assert.equal(FIELD_TYPES.length, 30);
  assert.ok(FIELD_MEMBERS.includes("conditional"));
});

test("template fields take the same members", async () => {
  const c = await signedIn();
  const tp = await c.templates.create({ name: "Members", roles: [{ name: "Buyer", type: "approver", routing_order: 1 }] });
  const withDoc = await c.templates.addDocument(tp.id, "a.pdf", makePdf([{ title: "T" }]));
  const out = await c.templates.addFields(tp.id, [fieldWire({ role_id: withDoc.roles[0].id, document: withDoc.documents[0].id, type: "radio_group", page: 1, x: 10, y: 10, width: 90, height: 20, options: ["Yes", "No"], tooltip: "Pick one", required: true })]);
  assert.deepEqual([out.items[0].options, out.items[0].tooltip, out.items[0].required], [["Yes", "No"], "Pick one", true]);
});

test("every engine recipient type is taken; an approver approves and a viewer views to the end", async () => {
  const c = await signedIn();
  assert.equal(RECIPIENT_TYPES.length, 11);
  const env = await sentWith(c,
    [{ name: "Ann Approver", email: "ann@example.com", type: "approver", routing_order: 1 },
      { name: "Vic Viewer", email: "vic@example.com", type: "viewer", routing_order: 2 },
      { name: "Sig Signer", email: "sig@example.com", type: "signer", routing_order: 3 }],
    [{ to: 0, type: "text", page: 1, x: 72, y: 100, width: 100, height: 20, required: true, label: "PO" },
      { to: 2, type: "signature", page: 2, x: 72, y: 600, width: 160, height: 44, required: true }]);
  assert.deepEqual(env.recipients.map((r) => r.status), ["sent", "created", "created"]);
  const a = tokenOf(env, 0);
  let v = await c.ceremony.open(a);
  await c.ceremony.consent(a, MOCK.ersd);
  await assert.rejects(c.ceremony.finish(a), (e) => e.status === 409 && e.code === "CS-WF-0001", "an approver does not finish");
  await assert.rejects(c.ceremony.approve(a), (e) => e.code === "CS-WF-0004", "their required field first");
  await c.ceremony.fill(a, v.fields[0].id, { text: "PO-1" });
  v = await c.ceremony.approve(a);
  assert.equal(v.recipient.status, "completed");
  const { envelope: mid } = await c.getEnvelope(env.id);
  const vt = mid.recipients[1].mock_token;
  assert.equal(mid.recipients[1].status, "sent", "routing reached the viewer");
  v = await c.ceremony.open(vt);
  await c.ceremony.consent(vt, MOCK.ersd);
  await assert.rejects(c.ceremony.finish(vt), (e) => e.code === "CS-WF-0014");
  v = await c.ceremony.viewed(vt, v.envelope.documents[0].id, [1, 2]);
  assert.equal(v.recipient.status, "completed", "viewing to the end completes a viewer");
  const s = await c.getEnvelope(env.id);
  assert.equal(s.envelope.recipients[2].status, "sent");
  // A signer may not approve.
  const st = s.envelope.recipients[2].mock_token;
  await c.ceremony.open(st);
  await c.ceremony.consent(st, MOCK.ersd);
  await assert.rejects(c.ceremony.approve(st), (e) => e.code === "CS-WF-0001");
});

test("an agent names the later signer through the ceremony, then finishes (VS-02)", async () => {
  const c = await signedIn();
  const env = await sentWith(c,
    [{ name: "Ag Ent", email: "ag@example.com", type: "agent", routing_order: 1 },
      { name: "To Name", email: "placeholder@example.com", type: "signer", routing_order: 2 }],
    [{ to: 1, type: "signature", page: 1, x: 72, y: 600, width: 160, height: 44, required: true }]);
  const a = tokenOf(env, 0);
  let v = await c.ceremony.open(a);
  await c.ceremony.consent(a, MOCK.ersd);
  v = await c.ceremony.view(a);
  assert.deepEqual(v.later_recipients.map((r) => [r.id, r.type, r.name]), [[env.recipients[1].id, "signer", "To Name"]]);
  await assert.rejects(c.ceremony.nameRecipients(a, [{ id: env.recipients[1].id, email: "nope" }]), (e) => e.status === 422);
  v = await c.ceremony.nameRecipients(a, [{ id: env.recipients[1].id, name: "Bea Buyer", email: "bea@example.com" }]);
  assert.deepEqual([v.later_recipients[0].name, v.later_recipients[0].email], ["Bea Buyer", "bea@example.com"]);
  v = await c.ceremony.finish(a);
  assert.equal(v.recipient.status, "completed");
  const { envelope: after } = await c.getEnvelope(env.id);
  assert.deepEqual([after.recipients[1].email, after.recipients[1].status], ["bea@example.com", "sent"]);
  // The signer's own view has no later recipients and may name no one.
  const s = after.recipients[1].mock_token;
  v = await c.ceremony.open(s);
  await c.ceremony.consent(s, MOCK.ersd);
  assert.equal((await c.ceremony.view(s)).later_recipients, undefined);
  await assert.rejects(c.ceremony.nameRecipients(s, [{ id: env.recipients[0].id, name: "X" }]), (e) => e.status === 409);
});

test("sending refuses a field the recipient's type may not hold", async () => {
  const c = await signedIn();
  await assert.rejects(sentWith(c, [{ name: "Ann", email: "ann@example.com", type: "approver" }],
    [{ to: 0, type: "signature", page: 1, x: 72, y: 100, width: 100, height: 40 }]),
  (e) => e.code === "CS-WF-0004" && e.errors.some((x) => x.code === "field_not_allowed"));
  // An approver needs no field at all; a signer still does.
  const ok = await sentWith(c, [{ name: "Ann", email: "ann@example.com", type: "approver" }], []);
  assert.equal(ok.status, "sent");
});

test("withdrawing consent declines, whatever allow_decline says", async () => {
  const c = await signedIn();
  const env = await sentWith(c, [{ name: "Sig", email: "sig@example.com" }], [{ to: 0, type: "signature", page: 1, x: 72, y: 600, width: 160, height: 44 }]);
  const t = tokenOf(env, 0);
  await c.ceremony.open(t);
  await assert.rejects(c.ceremony.withdrawConsent(t), (e) => e.code === "CS-WF-0001", "nothing to withdraw yet");
  await c.ceremony.consent(t, MOCK.ersd);
  const v = await c.ceremony.withdrawConsent(t);
  assert.deepEqual([v.recipient.status, v.envelope.status], ["declined", "declined"]);
});

// ---- corrections ------------------------------------------------------------------------
test("corrections: one call adds, updates and removes recipients and sets the expiry, all or none", async () => {
  const c = await signedIn();
  const env = await sentWith(c,
    [{ name: "One", email: "one@example.com", routing_order: 1 }, { name: "Two", email: "two@example.com", routing_order: 2 }, { name: "Three", email: "three@example.com", routing_order: 3 }],
    [{ to: 0, type: "signature", page: 1, x: 72, y: 600, width: 160, height: 44 }, { to: 1, type: "signature", page: 1, x: 300, y: 600, width: 160, height: 44 },
      { to: 2, type: "signature", page: 2, x: 72, y: 600, width: 160, height: 44 }]);
  const [one, two, three] = env.recipients;
  const at = new Date(Date.now() + 5 * 864e5);
  const addField = corrections.addField({ recipient_id: two.id, document_id: env.documents[0].id, type: "text", page: 2, x: 72, y: 100, width: 100, height: 20, tooltip: "Your title" });
  const changes = [
    corrections.updateRecipient({ ...one, email: "one-fixed@example.com" }),
    corrections.addRecipient({ type: "cc", name: "Legal", email: "legal@example.com", routing_order: 4 }),
    corrections.removeRecipient(three.id),
    addField,
    corrections.setExpiry(at),
    corrections.setReminders({ first_after_days: 2, then_every_days: 3 }),
    corrections.setMessage("Updated terms"),
  ];
  // The spec the engine takes: only its members (no status, no access_code, no token).
  assert.deepEqual(Object.keys(changes[0].recipient).sort(), ["delivery", "email", "id", "name", "routing_order", "type"]);
  assert.match(changes[1].recipient.id, /^[0-9a-f-]{36}$/);
  assert.deepEqual(Object.keys(addField.field).sort(), ["document_id", "id", "placement", "recipient_id", "tooltip", "type"]);
  let { etag } = await c.getEnvelope(env.id);
  // One bad change and nothing is kept: a change of type is refused.
  await assert.rejects(c.correctEnvelope(env.id, etag, [...changes, corrections.updateRecipient({ ...two, type: "approver" })]), (e) => e.status === 409 && e.code === "CS-WF-0001");
  const same = await c.getEnvelope(env.id);
  assert.equal(same.etag, etag);
  assert.deepEqual(same.envelope.recipients.map((r) => r.email), ["one@example.com", "two@example.com", "three@example.com"]);
  const out = await c.correctEnvelope(env.id, etag, changes);
  assert.deepEqual(out.recipients.map((r) => [r.name, r.email]), [["One", "one-fixed@example.com"], ["Two", "two@example.com"], ["Legal", "legal@example.com"]]);
  assert.equal(out.expires_at, at.toISOString());
  assert.deepEqual(out.reminders, { first_after_days: 2, then_every_days: 3 });
  assert.equal(out.message, "Updated terms");
  assert.equal(out.fields.find((f) => f.id === addField.field.id).tooltip, "Your title");
  const audit = await c.audit(env.id);
  const last = audit.items.findLast((i) => i.type === "envelope.corrected");
  assert.deepEqual(last.event.data.changed, [`recipients.${one.id}`, `recipients.${changes[1].recipient.id}`, `recipients.${three.id}`, `fields.${addField.field.id}`, "expires_at", "reminders", "message"]);
  ({ etag } = await c.getEnvelope(env.id));
  await assert.rejects(c.correctEnvelope(env.id, etag, [corrections.setExpiry(new Date(Date.now() - 864e5))]), (e) => e.code === "CS-WF-0004");
  await assert.rejects(c.correctEnvelope(env.id, etag, [{ op: "set_seal_profile", profile: "pades-b-lta" }]), (e) => e.code === "CS-WF-0001");
  await assert.rejects(c.correctEnvelope(env.id, etag, [{ op: "add_document", document: {} }]), (e) => e.code === "CS-API-0001");
  await assert.rejects(c.correctEnvelope(env.id, etag, [{ op: "update_recipient", recipient: { ...recipientSpec(two), status: "sent" } }]), (e) => e.code === "CS-API-0001");
});

test("corrections: a recipient who acted is not changed or removed", async () => {
  const c = await signedIn();
  const env = await sentWith(c, [{ name: "One", email: "one@example.com" }, { name: "Two", email: "two@example.com", routing_order: 2 }],
    [{ to: 0, type: "signature", page: 1, x: 72, y: 600, width: 160, height: 44 }, { to: 1, type: "signature", page: 1, x: 300, y: 600, width: 160, height: 44 }]);
  const t = tokenOf(env, 0);
  const v = await c.ceremony.open(t);
  await c.ceremony.consent(t, MOCK.ersd);
  const a = await c.ceremony.adopt(t, "signature", "draw", PNG);
  await c.ceremony.fill(t, v.fields[0].id, { signature: a.adoption_id });
  await c.ceremony.finish(t);
  const { envelope, etag } = await c.getEnvelope(env.id);
  await assert.rejects(c.correctEnvelope(env.id, etag, [corrections.removeRecipient(envelope.recipients[0].id)]), (e) => e.code === "CS-WF-0001");
  await assert.rejects(c.correctEnvelope(env.id, etag, [corrections.updateRecipient({ ...envelope.recipients[0], name: "X" })]), (e) => e.code === "CS-WF-0001");
  await assert.rejects(c.correctEnvelope(env.id, etag, [corrections.removeRecipient("nope")]), (e) => e.code === "CS-WF-0008");
});

test("the per-element calls correct a sent envelope too, as the server's", async () => {
  const c = await signedIn();
  const env = await sentWith(c, [{ name: "One", email: "one@example.com" }, { name: "Two", email: "two@example.com", routing_order: 2 }],
    [{ to: 0, type: "signature", page: 1, x: 72, y: 600, width: 160, height: 44 }, { to: 1, type: "signature", page: 1, x: 300, y: 600, width: 160, height: 44 }]);
  const added = await c.addRecipients(env.id, [recipientWire({ type: "signer", name: "Four", email: "four@example.com", routing_order: 3 })]);
  const four = added.items[0];
  await c.addFields(env.id, [fieldWire({ recipient_id: four.id, document_id: env.documents[0].id, type: "signature", page: 1, x: 72, y: 300, width: 160, height: 44 })]);
  let { etag } = await c.getEnvelope(env.id);
  await c.deleteRecipient(env.id, env.recipients[1].id, etag);
  const { envelope } = await c.getEnvelope(env.id);
  assert.deepEqual(envelope.recipients.map((r) => [r.name, r.status]), [["One", "sent"], ["Four", "created"]]);
  assert.equal(envelope.fields.filter((f) => f.recipient_id === env.recipients[1].id).length, 0, "their fields went with them");
  const trail = (await c.audit(env.id)).items;
  const sentAt = trail.find((i) => i.type === "envelope.sent").seq;
  const corrected = trail.filter((i) => i.type === "envelope.corrected" && i.seq > sentAt);
  assert.equal(corrected.length, 3);
  ({ etag } = await c.getEnvelope(env.id));
  await c.voidEnvelope(env.id, "done");
  ({ etag } = await c.getEnvelope(env.id));
  await assert.rejects(c.addRecipients(env.id, [recipientWire({ name: "Late", email: "late@example.com" })]), (e) => e.code === "CS-WF-0001");
});

// ---- calls the server does not serve yet --------------------------------------------------
test("calls not on the server fail at once with CS-NET-0002 and never reach it", async () => {
  const seen = [];
  const fake = async (url) => { seen.push(url); return new Response(JSON.stringify({ items: [] }), { status: 200 }); };
  const c = createClient({ fetch: fake });
  assert.equal(c.available("restoreEnvelope"), false);
  assert.equal(c.available("listWebhooks"), true, "a call the server serves is available");
  const refused = [c.restoreEnvelope("e"), c.ceremony.clearField("t", "f")];
  for (const p of refused) await assert.rejects(p, (e) => e.status === 501 && e.code === "CS-NET-0002" && Object.hasOwn(NOT_ON_SERVER, e.detail));
  assert.deepEqual(seen, []);
  await c.listEnvelopes({ status: ["sent", "delivered"] });
  assert.deepEqual(seen, ["/api/v1/envelopes?status=sent%2Cdelivered&limit=25"]);
  // UXW-34: the disclosure is served, so the call reaches the server.
  await c.ceremony.disclosure("t");
  assert.equal(seen.at(-1), "/s/t/disclosure");
  for (const [name, { needs }] of Object.entries(NOT_ON_SERVER)) assert.ok(needs.length > 10, name);
});

test("webhook edit, test and redelivery reach the server as it serves them (UXW-31..33)", async () => {
  const seen = [];
  const fake = async (url, init = {}) => { seen.push(`${init.method || "GET"} ${url}`); return new Response("{}", { status: 200 }); };
  const c = createClient({ fetch: fake });
  for (const name of ["updateWebhook", "testWebhook", "redeliver"]) assert.ok(c.available(name) && !Object.hasOwn(NOT_ON_SERVER, name), name);
  await c.updateWebhook("w", { active: false });
  await c.testWebhook("w");
  await c.redeliver("w", "d");
  assert.deepEqual(seen, ["PATCH /api/v1/webhooks/w", "POST /api/v1/webhooks/w/test", "POST /api/v1/webhooks/w/deliveries/d/redeliver"]);
});

test("the Inbox, folders, filters, the Deleted views and an ended envelope's certificate reach the server as it serves them (UXW-01/02/03/30)", async () => {
  const seen = [];
  const fake = async (url, init = {}) => {
    seen.push(`${init.method || "GET"} ${url}`);
    return new Response(JSON.stringify({ items: [] }), { status: 200 });
  };
  const c = createClient({ fetch: fake });
  for (const name of ["inbox", "envelopeFilters", "folders", "deleted", "certificateEnded"]) {
    assert.ok(!Object.hasOwn(NOT_ON_SERVER, name), name);
  }
  await c.inbox();
  await c.signLink("e1");
  await c.listEnvelopes({ recipient: "ann", date_field: "sent_at", folder: "f1", deleted: true });
  await c.listFolders();
  await c.createFolder("Leases");
  await c.renameFolder("f1", "Old leases");
  await c.deleteFolder("f1");
  await c.moveEnvelopes("f1", ["e1"]);
  await c.moveEnvelopes(null, ["e1"]);
  await c.templates.listDeleted();
  await c.templates.restore("t1");
  await c.certificate("e1");
  assert.deepEqual(seen, [
    "GET /api/v1/envelopes?waiting_for=me&limit=25",
    "POST /api/v1/envelopes/e1/sign-link",
    "GET /api/v1/envelopes?limit=25&recipient=ann&date_field=sent_at&folder=f1&deleted=true",
    "GET /api/v1/folders",
    "POST /api/v1/folders",
    "PATCH /api/v1/folders/f1",
    "DELETE /api/v1/folders/f1",
    "POST /api/v1/folders/f1/envelopes",
    "POST /api/v1/folders/none/envelopes",
    "GET /api/v1/templates?deleted=true",
    "POST /api/v1/templates/t1/restore",
    "GET /api/v1/envelopes/e1/certificate",
  ]);
});

test("the mock keeps a deleted template whole, lists it in the Deleted view and restores it (UXW-02)", async () => {
  const c = await signedIn();
  const tp = await c.templates.create({ name: "Kept", roles: [{ name: "Client", type: "signer", routing_order: 1 }] });
  const { etag } = await c.templates.get(tp.id);
  await c.templates.remove(tp.id, etag);
  assert.ok(!(await c.templates.list()).items.some((x) => x.id === tp.id), "left the list");
  assert.deepEqual((await c.templates.listDeleted()).items.map((x) => x.id), [tp.id]);
  await assert.rejects(c.templates.get(tp.id), (e) => e.status === 404);
  const back = await c.templates.restore(tp.id);
  assert.equal(back.roles[0].name, "Client", "with its roles");
  assert.ok((await c.templates.list()).items.some((x) => x.id === tp.id));
  await assert.rejects(c.templates.restore(tp.id), (e) => e.status === 404, "a live template is not restored");
  await c.templates.remove(tp.id, (await c.templates.get(tp.id)).etag);
  await c.templates.remove(tp.id, `"v${back.version + 1}"`);
  assert.deepEqual((await c.templates.listDeleted()).items, [], "deleted twice: gone for good");
});

test("ahead of the server, the mock serves the Inbox and signing from it", async () => {
  const c = await signedIn();
  assert.equal(c.available("inbox"), true);
  const box = await c.inbox();
  assert.equal(box.items.length, 1);
  const [item] = box.items;
  assert.equal(item.subject, "Expense policy acknowledgement");
  assert.ok(item.my_recipient_id);
  const { url } = await c.signLink(item.id);
  assert.equal(url, `/s/${MOCK.inboxToken}`);
  const v = await c.ceremony.open(MOCK.inboxToken);
  assert.deepEqual(v.sender, { name: "Robin Sender", email: "sender@openseal.test", organisation: "Demo account" });
});

test("ahead of the server, folders file envelopes and the list filters by folder", async () => {
  const c = await signedIn();
  const f = await c.createFolder("Clients");
  await assert.rejects(c.createFolder("clients"), (e) => e.code === "CS-API-0001");
  const all = (await c.listEnvelopes({ limit: 200 })).items;
  await c.moveEnvelopes(f.id, [all[0].id, all[1].id]);
  assert.deepEqual((await c.listFolders()).items, [{ id: f.id, name: "Clients", count: 2 }]);
  assert.deepEqual((await c.listEnvelopes({ folder: f.id })).items.map((e) => e.id).sort(), [all[0].id, all[1].id].sort());
  await c.moveEnvelopes(null, [all[0].id]);
  assert.equal((await c.renameFolder(f.id, "Key clients")).count, 1);
  await c.deleteFolder(f.id);
  assert.deepEqual((await c.listFolders()).items, []);
  assert.equal((await c.listEnvelopes({ folder: "none", limit: 200 })).items.length, all.length);
});

test("deleting an ended envelope keeps it, readable and restorable; a draft is removed", async () => {
  const c = await signedIn();
  const declined = (await c.listEnvelopes({ status: "declined" })).items[0];
  let { etag } = await c.getEnvelope(declined.id);
  await c.deleteEnvelope(declined.id, etag);
  assert.ok(!(await c.listEnvelopes({ limit: 200 })).items.some((e) => e.id === declined.id));
  const kept = await c.getEnvelope(declined.id);
  assert.ok(kept.envelope.deleted_at);
  await assert.rejects(c.deleteEnvelope(declined.id, kept.etag), (e) => e.code === "CS-WF-0001", "a second delete");
  assert.deepEqual((await c.listEnvelopes({ deleted: true })).items.map((e) => e.id), [declined.id]);
  await c.restoreEnvelope(declined.id);
  assert.ok((await c.listEnvelopes({ limit: 200 })).items.some((e) => e.id === declined.id));
  // The certificate of an ended envelope (ahead of the server).
  const cert = await c.certificate(declined.id);
  assert.ok(cert.size > 100);
  const draft = (await c.listEnvelopes({ status: "draft" })).items[0];
  ({ etag } = await c.getEnvelope(draft.id));
  await c.deleteEnvelope(draft.id, etag);
  await assert.rejects(c.getEnvelope(draft.id), (e) => e.code === "CS-API-0002");
});

test("the list takes several statuses, sorts, and filters by recipient and date field", async () => {
  const c = await signedIn();
  const active = await c.listEnvelopes({ status: ["sent", "delivered"], limit: 200 });
  assert.ok(active.items.length >= 2 && active.items.every((e) => ["sent", "delivered"].includes(e.status)));
  const bySubject = (await c.listEnvelopes({ sort: "subject", order: "asc", limit: 200 })).items.map((e) => e.subject.toLowerCase());
  assert.deepEqual(bySubject, [...bySubject].sort());
  assert.ok((await c.listEnvelopes({ limit: 1 })).items[0].updated_at);
  const avery = await c.listEnvelopes({ recipient: "avery@acme", limit: 200 });
  assert.deepEqual(avery.items.map((e) => e.subject), ["Mutual NDA — Acme and Globex"]);
  const done = await c.listEnvelopes({ date_field: "completed_at", from: new Date(Date.now() - 30 * 864e5), limit: 200 });
  assert.ok(done.items.length >= 1 && done.items.every((e) => e.status === "completed"));
  await assert.rejects(c.listEnvelopes({ date_field: "signed_at" }), (e) => e.code === "CS-API-0001");
  const mine = await c.listEnvelopes({ sender: "me", limit: 200 });
  assert.ok(mine.items.every((e) => e.sender_user_id === "user-demo"));
});

test("ahead of the server: a signer clears a value, and staff host an in-person signer", async () => {
  const c = await signedIn();
  const env = await sentWith(c, [{ name: "Sig", email: "sig@example.com" }, { name: "Ina", email: "ina@example.com", type: "in_person_signer", routing_order: 2 }],
    [{ to: 0, type: "text", page: 1, x: 72, y: 100, width: 100, height: 20 }, { to: 0, type: "signature", page: 1, x: 72, y: 600, width: 160, height: 44 },
      { to: 1, type: "signature", page: 1, x: 300, y: 600, width: 160, height: 44 }]);
  const t = tokenOf(env, 0);
  let v = await c.ceremony.open(t);
  await c.ceremony.consent(t, MOCK.ersd);
  const text = v.fields.find((f) => f.type === "text");
  await assert.rejects(c.ceremony.clearField(t, text.id), (e) => e.code === "CS-WF-0001", "nothing to clear");
  await c.ceremony.fill(t, text.id, { text: "x" });
  v = await c.ceremony.clearField(t, text.id);
  assert.ok(!("value" in v.fields.find((f) => f.id === text.id)));
  const sig = v.fields.find((f) => f.type === "signature");
  const a = await c.ceremony.adopt(t, "signature", "draw", PNG);
  await c.ceremony.fill(t, sig.id, { signature: a.adoption_id });
  await c.ceremony.finish(t);
  const { envelope } = await c.getEnvelope(env.id);
  const ina = envelope.recipients[1];
  await c.ceremony.open(ina.mock_token);
  await assert.rejects(c.ceremony.consent(ina.mock_token, MOCK.ersd), (e) => e.code === "CS-WF-0001", "not hosted yet");
  const { url } = await c.hostInPerson(env.id, ina.id);
  assert.equal(url, `/s/${ina.mock_token}`);
  await c.ceremony.consent(ina.mock_token, MOCK.ersd);
});

test("every client-side error code api.js raises has an English string and a docs/20 entry", () => {
  const src = readFileSync(new URL("../api.js", import.meta.url), "utf8");
  const registry = readFileSync(new URL("../../docs/20-ERROR-CODE-REGISTRY.md", import.meta.url), "utf8");
  const codes = [...new Set(src.match(/CS-NET-\d{4}/g))];
  assert.deepEqual(codes.sort(), ["CS-NET-0001", "CS-NET-0002"]);
  for (const c of codes) {
    assert.ok(EN[`error.${c}`], `no English string for ${c}`);
    assert.match(registry, new RegExp(`\\| ${c} \\|`), `${c} not in docs/20`);
  }
});

test("every call not on the server names the tracker row that builds it, and docs/40 lists it", () => {
  const doc = readFileSync(new URL("../../docs/40-API-DESIGN.md", import.meta.url), "utf8");
  for (const [name, { row }] of Object.entries(NOT_ON_SERVER)) {
    assert.match(String(row), /^[A-Z]+-\d+$/, `${name} has no tracker row`);
    assert.ok(doc.includes(`\`${row}\``), `${name}'s row ${row} is not in docs/40`);
  }
});

// ---- workspace switching (ORG-04) ------------------------------------------------------
test("workspaces: listed by organization, a switch replaces the CSRF token, a stranger's id is CS-ORG-0001", async () => {
  const c = await signedIn();
  const l = await c.workspaces();
  assert.equal(l.current, "acct-demo");
  const ws = l.organizations.flatMap((o) => o.workspaces);
  assert.deepEqual(ws.map((w) => [w.id, w.current]), [["acct-demo", true], ["acct-legal", false]]);
  assert.deepEqual(Object.keys(ws[0]).sort(), ["current", "id", "name", "status"]);
  await assert.rejects(c.switchWorkspace("acct-elsewhere"), (e) => e.status === 403 && e.code === "CS-ORG-0001");
  const r = await c.switchWorkspace("acct-legal");
  assert.equal(r.account_id, "acct-legal");
  assert.equal((await c.session()).account_id, "acct-legal");
  assert.equal((await c.account()).name, "Legal");
  assert.equal((await c.workspaces()).current, "acct-legal");
  // The new CSRF token is the one sent: a changing call still passes.
  await c.switchWorkspace("acct-demo");
  assert.equal((await c.session()).account_id, "acct-demo");
});
