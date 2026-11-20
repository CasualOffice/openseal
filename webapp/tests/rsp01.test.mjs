// RSP-01 (ADR-046): a signer's signature type through the client and the mock, as the
// server takes it. Run: cd webapp && npm test
import test from "node:test";
import assert from "node:assert/strict";

import { recipientPatch } from "../preparemodel.js";
import { createClient, recipientSpec, recipientWire } from "../api.js";
import { createMockFetch, MOCK } from "../mock.js";

const pdf = Buffer.from("%PDF-1.7\n%%EOF\n").toString("base64");
const remote = { type: "remote", provider_id: "csc-demo" };
const saved = { id: "r1", type: "signer", name: "Ana", email: "ana@example.test", routing_order: 1, auth: [], signature: null };
const body = (over) => ({ type: "signer", name: "Ana", email: "ana@example.test", routing_order: 1, ...over });

function withProviders(on) {
  const store = new Map(on ? [["openseal.mock.rsp", "1"]] : []);
  globalThis.sessionStorage = { getItem: (k) => store.get(k) ?? null, setItem: (k, v) => store.set(k, v), removeItem: (k) => store.delete(k) };
}

test("the signature type is part of the saved recipient's patch, simple when dropped", () => {
  assert.equal(recipientPatch(saved, body()), null);
  assert.deepEqual(recipientPatch(saved, body({ signature: remote })), { signature: remote });
  assert.deepEqual(recipientPatch({ ...saved, signature: remote }, body()), { signature: { type: "simple" } });
  assert.equal(recipientPatch({ ...saved, signature: remote }, body({ signature: remote })), null);
  assert.deepEqual(recipientWire({ type: "signer", name: "A", signature: remote }), { type: "signer", name: "A", email: "", signature: remote });
  // The API shows a simple signer's type as null; the engine's spec leaves it out.
  assert.equal("signature" in recipientSpec(saved), false);
  assert.deepEqual(recipientSpec({ ...saved, signature: remote }).signature, remote);
});

test("the mock lists the enabled provider and refuses two remote signers at one step", async () => {
  withProviders(true);
  try {
    const api = createClient({ fetch: createMockFetch() });
    await api.login(MOCK.email, MOCK.password);
    assert.deepEqual((await api.listSigningProviders()).items.map((p) => [p.id, p.enabled]), [["csc-demo", true]]);
    const env = await api.createEnvelope({
      subject: "Remote",
      documents: [{ name: "a.pdf", content_base64: pdf }],
      recipients: [
        { ref: "r0", type: "signer", name: "Ana", email: "ana@example.test", routing_order: 1, signature: remote },
        { ref: "r1", type: "signer", name: "Bo", email: "bo@example.test", routing_order: 1, signature: remote },
      ],
      fields: [
        { recipient: "r0", document: 0, type: "signature", page: 1, x: 72, y: 100, width: 180, height: 40 },
        { recipient: "r1", document: 0, type: "signature", page: 1, x: 72, y: 200, width: 180, height: 40 },
      ],
    });
    const { envelope } = await api.getEnvelope(env.id);
    assert.deepEqual(envelope.recipients[0].signature, remote);
    await assert.rejects(api.sendEnvelope(env.id), (e) => e.code === "CS-RSP-0007" && e.errors.length === 2);
    await assert.rejects(
      api.createEnvelope({ subject: "x", recipients: [{ type: "signer", name: "C", email: "c@example.test", signature: { type: "remote", provider_id: "other" } }] }),
      (e) => e.code === "CS-RSP-0001",
    );
  } finally {
    withProviders(false);
  }
  const api = createClient({ fetch: createMockFetch() });
  await api.login(MOCK.email, MOCK.password);
  assert.deepEqual((await api.listSigningProviders()).items, []);
});
