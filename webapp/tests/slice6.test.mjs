// Slice 6, Manage and correct (VS-06): the quick views the server answers (Authentication
// failed, Expiring soon), envelope custom fields and their search, transfer to another
// member, and the envelope page's action plan with them. The mock answers as the server
// does (`api/envelopes.rs`), so the browser specs in mock mode exercise the same rules.
// Run: npm test (in webapp/).
import test from "node:test";
import assert from "node:assert/strict";

import { createMockFetch, MOCK } from "../mock.js";
import { createClient } from "../api.js";
import { inView, viewCounts, envelopeActions, VIEWS } from "../managemodel.js";

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
  // Destructive items stay last.
  assert.deepEqual(envelopeActions("sent", { transfer: true, fields: true }).more.at(-1), ["void"]);
});
