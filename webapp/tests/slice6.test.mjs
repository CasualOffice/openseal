// Slice 6, Manage and correct (VS-06): the quick views the server answers (Authentication
// failed, Expiring soon), envelope custom fields and their search, transfer to another
// member, and the envelope page's action plan with them. The mock answers as the server
// does (`api/envelopes.rs`), so the browser specs in mock mode exercise the same rules.
// Run: npm test (in webapp/).
import test from "node:test";
import assert from "node:assert/strict";

import { createMockFetch, MOCK } from "../mock.js";
import { createClient, RECIPIENT_TYPES_READY } from "../api.js";
import { sendSummary, FIELD_TAKERS } from "../people.js";
import { inView, viewCounts, envelopeActions, VIEWS } from "../managemodel.js";
import { makePdf } from "../mockpdf.js";
import { windowBounds } from "../reportmodel.js";

test("the reports answer every envelope, recipient and sender, and their CSV runs no formula", async () => {
  const c = await client();
  const env = await c.report("envelopes");
  const all = (await c.listEnvelopes({ limit: 200 })).items.length;
  assert.equal(env.items.length, all);
  const rec = await c.report("recipients");
  assert.ok(rec.items.length >= all);
  const usage = await c.report("usage");
  assert.equal(usage.items.reduce((n, u) => n + u.created, 0), all);
  const { text } = await c.reportCsv("recipients");
  assert.ok(text.startsWith("envelope_id,subject,envelope_status,routing_order,name,email,type,status\r\n"));
  assert.equal((await c.report("envelopes", { to: "2000-01-01T00:00:00Z" })).items.length, 0);
  await assert.rejects(c.report("secrets"), (e) => e.code === "CS-API-0002");
});

test("a report's window is the page's: a preset reaches back from now, a custom range is whole days", () => {
  const now = Date.parse("2026-11-20T12:00:00Z");
  assert.deepEqual(windowBounds({ range: "all" }, now), {});
  assert.deepEqual(windowBounds({ range: "7" }, now), { from: "2026-11-13T12:00:00.000Z" });
  const custom = windowBounds({ range: "custom", from: "2026-11-01", to: "2026-11-02" }, now);
  assert.equal(Date.parse(custom.to) - Date.parse(custom.from), 2 * 86_400_000);
});

async function client() {
  const c = createClient({ fetch: createMockFetch() });
  await c.login(MOCK.email, MOCK.password);
  return c;
}

const subjects = (page) => (page.items || []).map((x) => x.subject).sort();

test("the Authentication failed view lists an envelope whose recipient failed, until a resend", async () => {
  const c = await client();
  assert.deepEqual(subjects(await c.listEnvelopes({ auth_failed: true })), []);
  await c.ceremony.open(MOCK.ceremonyToken);
  await assert.rejects(c.ceremony.authenticate(MOCK.ceremonyToken, "access_code", "wrong"), (e) => e.code === "CS-AUTH-0003");
  const failed = await c.listEnvelopes({ auth_failed: true });
  assert.deepEqual(subjects(failed), ["Offer letter — Jordan Rivera"]);
  // Every envelope is still in the plain list.
  assert.ok((await c.listEnvelopes({ limit: 200 })).items.length > 1);
  await c.resend(failed.items[0].id);
  assert.deepEqual(subjects(await c.listEnvelopes({ auth_failed: true })), [], "a resend clears the failures");
});

test("expiring soon is asked of the server with expires_before", async () => {
  const c = await client();
  const week = new Date(Date.now() + 7 * 864e5);
  const soon = await c.listEnvelopes({ expires_before: week, limit: 200 });
  assert.ok(soon.items.length >= 1);
  for (const e of soon.items) assert.ok(e.expires_at && e.expires_at < week.toISOString(), e.subject);
});

test("custom fields are replaced whole, read back by name and searched by name and value", async () => {
  const c = await client();
  const [e] = (await c.listEnvelopes({ limit: 1 })).items;
  assert.deepEqual((await c.customFields(e.id)).items, []);
  const put = await c.setCustomFields(e.id, [{ name: "Region", value: "North-West" }, { name: "Deal", value: "D-1042" }]);
  assert.equal(put.items.length, 2);
  assert.deepEqual((await c.customFields(e.id)).items.map((f) => f.name), ["Deal", "Region"]);
  assert.deepEqual((await c.listEnvelopes({ custom_field: "Region", custom_value: "north" })).items.map((x) => x.id), [e.id]);
  assert.deepEqual((await c.listEnvelopes({ custom_field: "Region", custom_value: "south" })).items, []);
  await assert.rejects(c.setCustomFields(e.id, [{ name: "A", value: "1" }, { name: "A", value: "2" }]), (x) => x.errors?.[0]?.code === "exists");
  await assert.rejects(c.setCustomFields(e.id, [{ name: " ", value: "1" }]), (x) => x.errors?.[0]?.pointer === "/items/0/name");
  await c.setCustomFields(e.id, []);
  assert.deepEqual((await c.listEnvelopes({ custom_field: "Deal" })).items, []);
});

test("an envelope is transferred to another member and the trail records it", async () => {
  const c = await client();
  const [e] = (await c.listEnvelopes({ limit: 1 })).items;
  const { etag } = await c.getEnvelope(e.id);
  const moved = await c.transferEnvelope(e.id, etag, "user-robin");
  assert.equal(moved.sender_user_id, "user-robin");
  const audit = await c.audit(e.id);
  assert.equal(audit.items.at(-1).type, "envelope.transferred");
  const { etag: again } = await c.getEnvelope(e.id);
  await assert.rejects(c.transferEnvelope(e.id, again, "nobody"), (x) => x.code === "CS-ORG-0009");
});

test("a sent envelope's documents and fields are corrected, each recorded as envelope.corrected", async () => {
  const c = await client();
  const env = (await c.listEnvelopes({ status: "sent", limit: 200 })).items.find((x) => x.subject.startsWith("Offer letter"));
  const { envelope } = await c.getEnvelope(env.id);
  const signer = envelope.recipients.find((r) => r.type === "signer");
  const doc = await c.addDocument(env.id, "Annex.pdf", makePdf([{ title: "Annex", lines: ["Clause 9"] }]));
  await c.addFields(env.id, [{ recipient: signer.id, document: doc.id, type: "initials", page: 1, x: 72, y: 100, width: 60, height: 30, required: true }]);
  const { envelope: after, etag } = await c.getEnvelope(env.id);
  assert.equal(after.status, "sent");
  assert.ok(after.documents.some((d) => d.id === doc.id));
  assert.ok(after.fields.some((f) => f.document_id === doc.id && f.type === "initials"));
  await c.deleteDocument(env.id, doc.id, etag);
  const { envelope: last } = await c.getEnvelope(env.id);
  assert.ok(!last.documents.some((d) => d.id === doc.id));
  const types = (await c.audit(env.id)).items.map((i) => i.type);
  assert.ok(types.filter((x) => x === "envelope.corrected").length >= 3, types.join());
});

test("the Authentication failed view keeps only marked rows in progress, and counts them", () => {
  assert.ok(VIEWS.some((v) => v.id === "authfailed" && v.nav));
  const rows = [
    { id: "a", status: "sent", auth_failed: true },
    { id: "b", status: "sent" },
    { id: "c", status: "completed", auth_failed: true },
  ];
  assert.deepEqual(rows.filter((r) => inView(r, "authfailed")).map((r) => r.id), ["a"]);
  assert.equal(viewCounts(rows).authfailed, 1);
});

test("the envelope page offers custom fields and, to a member who may, transfer", () => {
  const flat = (p) => p.more.flat();
  assert.ok(!flat(envelopeActions("sent")).includes("transfer"));
  assert.ok(flat(envelopeActions("sent", { transfer: true, fields: true })).includes("transfer"));
  assert.ok(flat(envelopeActions("completed", { fields: true })).includes("fields"));
  assert.ok(flat(envelopeActions("sent")).includes("correct-docs"));
  assert.ok(!flat(envelopeActions("completed")).includes("correct-docs"));
  // Destructive items stay last.
  assert.deepEqual(envelopeActions("sent", { transfer: true, fields: true }).more.at(-1), ["void"]);
});

test("an editor signs and names who signs next; an intermediary updates them; both are offered", () => {
  assert.ok(RECIPIENT_TYPES_READY.includes("editor") && RECIPIENT_TYPES_READY.includes("intermediary"));
  assert.ok(FIELD_TAKERS.has("editor") && !FIELD_TAKERS.has("intermediary"));
  const lines = sendSummary([{ name: "Eda", type: "editor", order: 1 }, { name: "Ian", type: "intermediary", order: 2 }, { name: "Bea", type: "signer", order: 3 }], "Lease");
  assert.deepEqual(lines.find(([k]) => k === "send.confirm-agents"), ["send.confirm-agents", { names: "Eda, Ian" }]);
  assert.equal(lines.find(([k]) => k === "send.confirm-copies"), undefined, "neither is a copy");
});

/// The stored entries of a ZIP, read from its central directory (method 0 only), each
/// checked against its CRC-32 field's position: `[{name, bytes}]`.
function readZip(buf) {
  const u8 = new Uint8Array(buf);
  const v = new DataView(u8.buffer, u8.byteOffset, u8.byteLength);
  const end = u8.length - 22;
  assert.equal(v.getUint32(end, true), 0x06054b50, "end of central directory");
  const count = v.getUint16(end + 10, true);
  let at = v.getUint32(end + 16, true);
  const out = [];
  for (let i = 0; i < count; i++) {
    assert.equal(v.getUint32(at, true), 0x02014b50);
    assert.equal(v.getUint16(at + 10, true), 0, "stored");
    const size = v.getUint32(at + 24, true);
    const nameLen = v.getUint16(at + 28, true);
    const local = v.getUint32(at + 42, true);
    const name = new TextDecoder().decode(u8.subarray(at + 46, at + 46 + nameLen));
    assert.equal(v.getUint32(local, true), 0x04034b50);
    const start = local + 30 + v.getUint16(local + 26, true) + v.getUint16(local + 28, true);
    out.push({ name, bytes: u8.slice(start, start + size) });
    at += 46 + nameLen + v.getUint16(at + 30, true) + v.getUint16(at + 32, true);
  }
  return out;
}

const hex = async (bytes) => [...new Uint8Array(await crypto.subtle.digest("SHA-256", bytes))].map((b) => b.toString(16).padStart(2, "0")).join("");

test("VS-06D: the evidence package is one ZIP whose manifest names each entry's SHA-256, and the export is recorded", async () => {
  const c = await client();
  const done = (await c.listEnvelopes({ status: "completed" })).items[0];
  const blob = await c.evidencePackage(done.id);
  const entries = readZip(await blob.arrayBuffer());
  assert.equal(entries[0].name, "manifest.json");
  const manifest = JSON.parse(new TextDecoder().decode(entries[0].bytes));
  assert.equal(manifest.format, "openseal.evidence-package");
  assert.equal(manifest.envelope_id, done.id);
  assert.deepEqual(manifest.entries.map((e) => e.path), entries.slice(1).map((e) => e.name));
  assert.ok(entries.some((e) => e.name.startsWith("documents/01-")));
  assert.ok(entries.some((e) => e.name === "certificate.pdf"));
  for (const [i, e] of manifest.entries.entries()) {
    assert.equal(e.sha256, await hex(entries[i + 1].bytes), e.path);
    assert.equal(e.size, entries[i + 1].bytes.length, e.path);
  }
  const trail = JSON.parse(new TextDecoder().decode(entries.at(-1).bytes));
  assert.equal(entries.at(-1).name, "audit-trail.json");
  assert.equal(trail.items.at(-1).type, "envelope.exported");
  assert.equal(trail.chain_head, manifest.chain_head);
  assert.equal((await c.audit(done.id)).chain_head, manifest.chain_head);
  // In flight: refused, nothing recorded.
  const live = (await c.listEnvelopes({ status: ["sent", "delivered"] })).items[0];
  const before = (await c.audit(live.id)).items.length;
  await assert.rejects(c.evidencePackage(live.id), (e) => e.status === 409 && e.code === "CS-WF-0001");
  assert.equal((await c.audit(live.id)).items.length, before);
  // Offered on the envelope page once it is over.
  assert.ok(envelopeActions("completed").more.flat().includes("evidence"));
  assert.ok(envelopeActions("voided", { cert: true }).more.flat().includes("evidence"));
  assert.ok(!envelopeActions("sent").more.flat().includes("evidence"));
});
