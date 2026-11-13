// UX-12: a saved recipient's type change reaches the server on save. The editor builds
// its PATCH with `recipientPatch`; the mock answers as the server does (a draft takes
// the change, a correction keeps the type). Run: cd webapp && npm test
import test from "node:test";
import assert from "node:assert/strict";

import { recipientPatch } from "../preparemodel.js";
import { createClient } from "../api.js";
import { createMockFetch, MOCK } from "../mock.js";

const saved = { id: "r1", type: "signer", name: "Ana", email: "ana@example.test", routing_order: 1, auth: ["access_code"] };
const body = (over) => ({ type: "signer", name: "Ana", email: "ana@example.test", routing_order: 1, ...over });

test("a type change is part of the saved recipient's patch", () => {
  assert.equal(recipientPatch(saved, body()), null);
  assert.deepEqual(recipientPatch(saved, body({ type: "approver" })), { type: "approver" });
  assert.deepEqual(recipientPatch(saved, body({ name: "Ana B", type: "viewer" })), { name: "Ana B", type: "viewer" });
  // A copy takes no authentication.
  assert.deepEqual(recipientPatch(saved, body({ type: "cc" })), { type: "cc", auth: [] });
  assert.deepEqual(recipientPatch({ ...saved, auth: [] }, body({ type: "cc" })), { type: "cc" });
});

test("a draft's recipient keeps its new type after save and reload", async () => {
  const api = createClient({ fetch: createMockFetch() });
  await api.login(MOCK.email, MOCK.password);
  const env = await api.createEnvelope({
    subject: "Type later",
    documents: [{ name: "t.pdf", content_base64: Buffer.from("%PDF-1.7\n%%EOF\n").toString("base64") }],
    recipients: [{ ref: "r0", type: "signer", name: "Ana", email: "ana@example.test", routing_order: 1 }],
  });
  const { envelope, etag } = await api.getEnvelope(env.id);
  const r = envelope.recipients[0];
  const patch = recipientPatch(r, body({ type: "approver" }));
  await api.patchRecipient(env.id, r.id, etag, patch);
  const after = (await api.getEnvelope(env.id)).envelope.recipients[0];
  assert.equal(after.type, "approver");
  assert.equal(after.id, r.id);
});
