// WF-02: document visibility, delayed routing and scheduled sending through the client
// and the mock, as the server takes them. Run: cd webapp && npm test
import test from "node:test";
import assert from "node:assert/strict";

import { recipientPatch } from "../preparemodel.js";
import { createClient, recipientWire } from "../api.js";
import { createMockFetch, MOCK } from "../mock.js";

const pdf = Buffer.from("%PDF-1.7\n%%EOF\n").toString("base64");
const saved = { id: "r1", type: "signer", name: "Ana", email: "ana@example.test", routing_order: 1, auth: [] };
const body = (over) => ({ type: "signer", name: "Ana", email: "ana@example.test", routing_order: 1, ...over });

test("a recipient's delay and hidden documents are part of the saved recipient's patch", () => {
  assert.equal(recipientPatch(saved, body()), null);
  assert.deepEqual(recipientPatch(saved, body({ route_delay_hours: 24 })), { route_delay_hours: 24 });
  assert.deepEqual(recipientPatch({ ...saved, route_delay_hours: 24 }, body()), { route_delay_hours: 0 });
  assert.deepEqual(recipientPatch(saved, body({ excluded_documents: ["d2"] })), { excluded_documents: ["d2"] });
  assert.deepEqual(recipientPatch({ ...saved, excluded_documents: ["d2"] }, body()), { excluded_documents: [] });
  assert.equal(recipientPatch({ ...saved, excluded_documents: ["d2", "d3"] }, body({ excluded_documents: ["d3", "d2"] })), null);
  assert.deepEqual(recipientWire({ type: "signer", name: "A", route_delay_hours: 2, excluded_documents: [1] }), { type: "signer", name: "A", email: "", route_delay_hours: 2, excluded_documents: [1] });
});

test("a draft keeps its recipients' delay and hidden documents, and schedules, refuses edits, cancels", async () => {
  const api = createClient({ fetch: createMockFetch() });
  await api.login(MOCK.email, MOCK.password);
  const env = await api.createEnvelope({
    subject: "Later",
    documents: [{ name: "a.pdf", content_base64: pdf }, { name: "b.pdf", content_base64: pdf }],
    recipients: [{ ref: "r0", type: "signer", name: "Ana", email: "ana@example.test", routing_order: 1, route_delay_hours: 24, excluded_documents: [1] }],
  });
  const { envelope } = await api.getEnvelope(env.id);
  const r = envelope.recipients[0];
  assert.equal(r.route_delay_hours, 24);
  assert.deepEqual(r.excluded_documents, [envelope.documents[1].id]);

  const at = new Date(Date.now() + 86_400_000).toISOString();
  const scheduled = await api.scheduleSend(env.id, at);
  assert.equal(scheduled.status, "draft");
  assert.equal(Date.parse(scheduled.send_at), Date.parse(at));
  const { etag } = await api.getEnvelope(env.id);
  await assert.rejects(api.patchEnvelope(env.id, etag, { subject: "Changed" }), (e) => e.code === "CS-WF-0022");
  await assert.rejects(api.scheduleSend(env.id, new Date(Date.now() - 60_000).toISOString()), (e) => e.code === "CS-WF-0023");
  const cancelled = await api.unscheduleSend(env.id);
  assert.equal(cancelled.send_at, null);
});
