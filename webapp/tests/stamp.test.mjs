// Envelope id stamping (FG-009, ADR-045) in mock mode, as the server: the account's
// default for a request that does not say, the option absent when off, fixed once sent,
// and the current document carrying "Envelope ID: <id>" on every page as an incremental
// update. Run: node --test webapp/tests/
import test from "node:test";
import assert from "node:assert/strict";

import { createMockFetch, MOCK } from "../mock.js";
import { createClient, ApiError } from "../api.js";
import { makePdf, stampPdf } from "../mockpdf.js";

const latin1 = (b) => new TextDecoder("latin1").decode(b);

test("stampPdf appends one update stamping every page, the original a prefix", () => {
  const base = makePdf([{ title: "One" }, { title: "Two", width: 200, height: 100 }]);
  const out = stampPdf(base, "Envelope ID: env-1");
  assert.ok(out.length > base.length);
  assert.deepEqual(out.subarray(0, base.length), base);
  const tail = latin1(out.subarray(base.length));
  assert.equal(tail.match(/\(Envelope ID: env-1\) Tj/g)?.length, 2);
  assert.match(tail, /\/Prev \d+/);
  // Something it cannot read comes back as it was.
  const odd = new TextEncoder().encode("%PDF-1.7\nnot a pdf");
  assert.equal(stampPdf(odd, "x"), odd);
});

async function signedIn() {
  const c = createClient({ fetch: createMockFetch() });
  await c.login(MOCK.email, MOCK.password);
  return c;
}

const doc = () => ({ name: "a.pdf", content_base64: Buffer.from(makePdf([{ title: "A" }, { title: "B" }])).toString("base64") });

test("the stamp default, absent when off, and refused as a setting that is not true or false", async () => {
  const c = await signedIn();
  const off = await c.createEnvelope({ subject: "x", documents: [doc()] });
  assert.equal("stamp_envelope_id" in off.signing_options, false);
  await assert.rejects(c.patchAccountSettings({ stamp_envelope_id: "yes" }), (e) => e instanceof ApiError && e.status === 422);
  await c.patchAccountSettings({ stamp_envelope_id: true });
  assert.equal((await c.createEnvelope({ subject: "x", documents: [doc()] })).signing_options.stamp_envelope_id, true);
  assert.equal((await c.createEnvelope({ subject: "x", signing_options: { capture_location: true }, documents: [doc()] })).signing_options.stamp_envelope_id, true);
  const own = await c.createEnvelope({ subject: "x", signing_options: { stamp_envelope_id: false }, documents: [doc()] });
  assert.equal("stamp_envelope_id" in own.signing_options, false);
});

test("a sent stamped envelope's current document carries its id on every page, and a correction cannot turn it off", async () => {
  const c = await signedIn();
  const e = await c.createEnvelope({
    subject: "Stamped", status: "sent", signing_options: { stamp_envelope_id: true }, documents: [doc()],
    recipients: [{ ref: "a", type: "signer", name: "Ada", email: "ada@example.test" }],
    fields: [{ recipient: "a", document: 0, type: "signature", page: 1, x: 72, y: 600, width: 180, height: 40 }],
  });
  assert.equal(e.signing_options.stamp_envelope_id, true);
  const blob = await c.documentContent(e.id, e.documents[0].id, "current");
  const text = latin1(new Uint8Array(await blob.arrayBuffer()));
  assert.equal(text.split(`(Envelope ID: ${e.id}) Tj`).length - 1, 2);
  const plain = await c.documentContent(e.id, e.documents[0].id, "normalized");
  assert.equal(latin1(new Uint8Array(await plain.arrayBuffer())).includes("Envelope ID"), false);
  const { etag } = await c.getEnvelope(e.id);
  await assert.rejects(
    c.correctEnvelope(e.id, etag, [{ op: "set_signing_options", options: { allow_decline: true } }]),
    (err) => err.code === "CS-WF-0001",
  );
});
