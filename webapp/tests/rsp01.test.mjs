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

test("the return from the provider names the link this tab kept, once, and only at /s/rsp", async () => {
  const { rspReturn, RSP_KEY } = await import("../signfields.js");
  const store = new Map([[RSP_KEY, "tok-1"]]);
  const storage = { getItem: (k) => store.get(k) ?? null, removeItem: (k) => store.delete(k) };
  assert.equal(rspReturn({ pathname: "/s/tok-1", search: "?state=s&code=c" }, storage), null);
  assert.equal(rspReturn({ pathname: "/s/rsp", search: "?code=c" }, storage), null);
  assert.deepEqual(rspReturn({ pathname: "/s/rsp", search: "?state=s&code=c" }, storage), { token: "tok-1", state: "s", code: "c", error: null });
  assert.equal(rspReturn({ pathname: "/s/rsp", search: "?state=s&code=c" }, storage), null);
  store.set(RSP_KEY, "tok-1");
  assert.deepEqual(rspReturn({ pathname: "/s/rsp/", search: "?state=s&error=access_denied" }, storage), { token: "tok-1", state: "s", code: null, error: "access_denied" });
});

test("the mock's remote signer: start, a refusal, start again, prepared, authorized, signed; a state works once", async () => {
  withProviders(true);
  try {
    const api = createClient({ fetch: createMockFetch() });
    const tok = MOCK.remoteSignToken;
    const v = await api.ceremony.open(tok);
    assert.equal(v.recipient.signature.type, "remote");
    assert.equal(v.remote_provider_name, "Demo CSC provider");
    const sig = v.fields.find((f) => f.type === "signature");
    await api.ceremony.consent(tok, v.consent_required.version);
    const a = await api.ceremony.adopt(tok, "signature", "type", btoa("\x89PNG\r\n\x1a\n" + "x".repeat(16)));
    await api.ceremony.fill(tok, sig.id, { signature: a.adoption_id });
    const back = (r) => new URL(r.remote_authorization_url, "http://x").searchParams;
    let r = await api.ceremony.remoteStart(tok);
    assert.equal(r.remote_signing.status, "authorizing_service");
    // Another start while the session is open is refused.
    await assert.rejects(api.ceremony.remoteStart(tok), (e) => e.code === "CS-RSP-0007");
    r = await api.ceremony.remoteCallback(tok, back(r).get("state"), null, "access_denied");
    assert.deepEqual([r.remote_signing.status, r.remote_signing.failure], ["failed", "cancelled"]);
    r = await api.ceremony.remoteStart(tok);
    const q = back(r);
    await assert.rejects(api.ceremony.remoteCallback(tok, "another", q.get("code")), (e) => e.code === "CS-RSP-0003");
    r = await api.ceremony.remoteCallback(tok, q.get("state"), q.get("code"));
    assert.equal(r.remote_signing.status, "prepared");
    await assert.rejects(api.ceremony.remoteCallback(tok, q.get("state"), q.get("code")), (e) => e.code === "CS-RSP-0003");
    r = await api.ceremony.remoteAuthorize(tok);
    r = await api.ceremony.remoteCallback(tok, back(r).get("state"), "c");
    assert.equal(r.remote_signing.status, "completed");
    assert.equal(r.recipient.status, "completed");
  } finally {
    withProviders(false);
  }
});
