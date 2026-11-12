// WEB-12: the mock's audit trail has the server's shape, so screens built on the mock
// work on a real server: dotted types from casual-sign-audit, the whole event of
// docs/32 §2 with `actor {kind, id}` and the recipient in `data.recipient_id`, `seq`
// from 0. Run: npm test (in webapp/).
import test from "node:test";
import assert from "node:assert/strict";

import { createMockFetch, MOCK } from "../mock.js";
import { createClient } from "../api.js";

const PNG = btoa("\x89PNG\r\n\x1a\n" + "x".repeat(16));

/// casual-sign-audit `EventData` (crates/casual-sign-audit/src/event.rs), every type.
const SERVER_TYPES = new Set([
  "envelope.created", "envelope.sent", "envelope.corrected", "envelope.voided", "envelope.declined", "envelope.expired",
  "envelope.completing", "envelope.completed", "envelope.purged", "envelope.deleted", "document.added", "document.admitted",
  "document.fixed", "document.replaced", "document.flattened", "document.sealed", "invitation.sent", "invitation.bounced",
  "reminder.sent", "recipient.delivered", "recipient.auth_challenged", "recipient.auth_passed", "recipient.auth_failed",
  "recipient.consented", "recipient.consent_withdrawn", "recipient.viewed_document", "recipient.signature_adopted",
  "recipient.field_completed", "recipient.signed", "recipient.approved", "recipient.completed", "recipient.declined",
  "recipient.reassigned", "recipient.finish_later", "recipient.in_person_hosted", "envelope.viewed_by_sender",
  "document.downloaded", "certificate.downloaded", "attachment.downloaded", "auth.asserted_by_host",
]);
const ACTOR_KINDS = new Set(["system", "sender", "recipient", "user", "host"]);

async function signedIn() {
  const c = createClient({ fetch: createMockFetch() });
  await c.login(MOCK.email, MOCK.password);
  return c;
}

/// Every item as the server's `GET …/audit` answers it.
function checkTrail(trail, envId) {
  assert.ok(trail.items.length > 0);
  trail.items.forEach((item, i) => {
    assert.deepEqual(Object.keys(item).sort(), ["at", "event", "hash", "prev", "seq", "type"], `item ${i}`);
    assert.equal(item.seq, i, "seq counts from 0");
    assert.equal(item.prev, i ? trail.items[i - 1].hash : null);
    assert.ok(SERVER_TYPES.has(item.type), `${item.type} is a server audit type`);
    const e = item.event;
    assert.deepEqual(Object.keys(e).sort(), ["actor", "at", "context", "data", "envelope_id", "prev", "seq", "type", "v"], item.type);
    assert.deepEqual([e.v, e.envelope_id, e.seq, e.prev, e.at, e.type], [1, envId, item.seq, item.prev, item.at, item.type]);
    assert.ok(ACTOR_KINDS.has(e.actor.kind), item.type);
    assert.ok(!("recipient_id" in e), "the recipient is in data, never at the top");
    if (item.type.startsWith("recipient.") || ["invitation.sent", "reminder.sent", "envelope.declined"].includes(item.type)) assert.ok(e.data.recipient_id, `${item.type} names its recipient in data`);
  });
  assert.equal(trail.chain_head, trail.items.at(-1).hash);
}

test("WEB-12: the seeded trails have the server's dotted types and event shape", async () => {
  const c = await signedIn();
  for (const e of (await c.listEnvelopes({ limit: 200 })).items) checkTrail(await c.audit(e.id), e.id);
  const done = (await c.listEnvelopes({ status: "completed" })).items[0];
  const { envelope } = await c.getEnvelope(done.id);
  const types = (await c.audit(done.id)).items.map((i) => i.type);
  // As the engine: signed then completed per recipient; completing, the seal, completed.
  for (const want of ["envelope.created", "envelope.sent", "document.fixed", "invitation.sent", "recipient.delivered", "recipient.signed", "recipient.completed", "envelope.completing", "document.flattened", "document.sealed", "envelope.completed"]) {
    assert.ok(types.includes(want), want);
  }
  assert.ok(types.indexOf("envelope.completing") < types.indexOf("document.sealed") && types.indexOf("document.sealed") < types.indexOf("envelope.completed"));
  const trail = (await c.audit(done.id)).items;
  const opened = trail.find((i) => i.type === "recipient.delivered");
  assert.deepEqual(opened.event.actor, { kind: "recipient", id: envelope.recipients[0].id, name: envelope.recipients[0].name, email: envelope.recipients[0].email });
  assert.equal(opened.event.data.recipient_id, envelope.recipients[0].id);
  assert.deepEqual(trail.find((i) => i.type === "envelope.sent").event.actor, { kind: "sender", id: envelope.sender_user_id });
  assert.deepEqual(trail.find((i) => i.type === "document.sealed").event.actor, { kind: "system" });
});

test("WEB-12: a ceremony records the server's types, with the location in context", async () => {
  const c = await signedIn();
  const t = MOCK.ceremonyToken;
  let v = await c.ceremony.open(t);
  await assert.rejects(c.ceremony.authenticate(t, "access_code", "0000"));
  await c.ceremony.authenticate(t, "access_code", MOCK.accessCode);
  await c.ceremony.consent(t, MOCK.ersd, { latitude: 1.5, longitude: 2.5, accuracy_m: 20 });
  await c.ceremony.viewed(t, v.envelope.documents[0].id, [1, 2]);
  const a = await c.ceremony.adopt(t, "signature", "draw", PNG);
  await c.ceremony.fill(t, v.fields.find((f) => f.type === "signature").id, { signature: a.adoption_id });
  await c.ceremony.fill(t, v.fields.find((f) => f.type === "text").id, { text: "Engineer" });
  v = await c.ceremony.finish(t);
  const trail = await c.audit(v.envelope.id);
  checkTrail(trail, v.envelope.id);
  const mine = trail.items.filter((i) => i.event.data.recipient_id === v.recipient.id).map((i) => i.type);
  assert.deepEqual(mine, ["invitation.sent", "recipient.delivered", "recipient.auth_failed", "recipient.auth_passed", "recipient.consented", "recipient.viewed_document", "recipient.signature_adopted", "recipient.field_completed", "recipient.field_completed", "recipient.signed", "recipient.completed"]);
  const consent = trail.items.find((i) => i.type === "recipient.consented");
  assert.deepEqual(consent.event.context.location, { latitude: 1.5, longitude: 2.5, accuracy_m: 20 });
  assert.equal(consent.event.data.ersd_version, MOCK.ersd);
  assert.match(consent.event.data.ersd_hash, /^sha256:[0-9a-f]{64}$/);
  assert.deepEqual(trail.items.find((i) => i.type === "recipient.auth_failed").event.data, { recipient_id: v.recipient.id, method: "access_code", attempt: 1 });
});

test("WEB-12: decline records the recipient's and the envelope's events", async () => {
  const c = await signedIn();
  await c.ceremony.open(MOCK.declineToken);
  const v = await c.ceremony.decline(MOCK.declineToken, "Wrong amount");
  const items = (await c.audit(v.envelope.id)).items;
  const [rd, ed] = items.slice(-2);
  assert.deepEqual([rd.type, rd.event.data], ["recipient.declined", { recipient_id: v.recipient.id, reason: "Wrong amount" }]);
  assert.deepEqual([ed.type, ed.event.data], ["envelope.declined", { recipient_id: v.recipient.id }]);
});

test("WEB-12: the signer's history is the server's: their events and the milestones, by without names", async () => {
  const c = await signedIn();
  const t = MOCK.ceremonyToken;
  await c.ceremony.open(t);
  await c.ceremony.authenticate(t, "access_code", MOCK.accessCode);
  await c.ceremony.consent(t, MOCK.ersd);
  const h = await c.ceremony.history(t);
  assert.deepEqual(h.events.map((e) => [e.type, e.by]), [
    // The draft's own edit is `envelope.corrected` on the server too, a milestone.
    ["envelope.corrected", "sender"], ["envelope.sent", "sender"], ["invitation.sent", "system"], ["recipient.delivered", "you"], ["recipient.auth_passed", "you"], ["recipient.consented", "you"],
  ]);
  assert.deepEqual(h.events.map((e) => e.seq), [...h.events.map((e) => e.seq)].sort((a, b) => a - b));
});
