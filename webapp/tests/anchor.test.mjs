// The Verify page's anchor-proof rules (FG-158, docs/32 §5; verifyreport.js): what the
// WASM `verify_anchor` answer means for a person, and whether the PDF's own audit trail
// can be matched to the proof. None may upgrade the verifier's outcome.
// Also: the trail reader (trail.js) reads real trails, whose hashes carry `sha256:`.
// Run: cd webapp && node --test tests/anchor.test.mjs
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";

import { EN } from "../strings.en.js";
import { summarizeAnchor, anchorTrailPlan, ANCHOR_CHECKS, MAX_ANCHOR_PROOF } from "../verifyreport.js";
import { parseTrail } from "../trail.js";

const FIX = new URL("../../fixtures/anchor/", import.meta.url);
const proofBytes = fs.readFileSync(new URL("anchor-proof.json", FIX));
const trailBytes = fs.readFileSync(new URL("audit-trail.json", FIX));

const passed = { status: "passed", sub_indication: null, code: null };
const failed = (code) => ({ status: "failed", sub_indication: null, code });
const notRun = { status: "not_run", sub_indication: null, code: null };
const answer = (outcome, over = {}) => JSON.stringify({ ok: {
  outcome, envelope_id: "e1", seq: 2, head: "sha256:ab", anchor: { id: "a1", period: "2026-11-16", tree_size: 3, root: "sha256:cd" },
  inclusion: passed, timestamp: passed, tsa_chain: passed, trail: passed, tsa_time: 1_794_874_200, tsa_name: "Example TSA", ...over } });

test("a passed proof reads as anchored on the token's day by its TSA", () => {
  const a = summarizeAnchor(answer("passed"));
  assert.equal(a.state, "anchored");
  assert.equal(a.at, "2026-11-17T00:10:00.000Z");
  assert.equal(a.tsa, "Example TSA");
  assert.equal(a.envelopeId, "e1");
  assert.equal(a.seq, 2);
  assert.deepEqual(a.checks.map((c) => c.name), ANCHOR_CHECKS);
  assert.ok(a.checks.every((c) => c.status === "passed"));
  for (const k of ["verify.anchor", "verify.anchor.anchored", "verify.anchor.unconfirmed", "verify.anchor.failed", "verify.anchor.error", "verify.anchor.not-yet"]) assert.ok(k in EN, k);
  for (const c of ANCHOR_CHECKS) assert.ok(`verify.anchor.check.${c}` in EN, c);
});

test("the verifier's outcome is never upgraded", () => {
  assert.equal(summarizeAnchor(answer("indeterminate", { tsa_chain: failed("CS-VER-0004") })).state, "unconfirmed");
  const f = summarizeAnchor(answer("failed", { inclusion: failed("CS-AUD-0009") }));
  assert.equal(f.state, "failed");
  assert.equal(f.checks.find((c) => c.name === "inclusion").code, "CS-AUD-0009");
  // An unknown or missing outcome is a failure, whatever the checks say.
  assert.equal(summarizeAnchor(answer("great")).state, "failed");
  assert.equal(summarizeAnchor(answer(undefined)).state, "failed");
  // A check the verifier did not report is not run, never passed.
  assert.equal(summarizeAnchor(answer("passed", { trail: undefined })).checks.find((c) => c.name === "trail").status, "not_run");
  assert.equal(summarizeAnchor(answer("passed", { trail: notRun })).checks.find((c) => c.name === "trail").status, "not_run");
  // No time or name from a token that did not pass.
  const bare = summarizeAnchor(answer("failed", { tsa_time: null, tsa_name: null }));
  assert.equal(bare.at, null);
  assert.equal(bare.tsa, null);
});

test("an error or an unreadable answer is an error with its code", () => {
  assert.deepEqual(summarizeAnchor(JSON.stringify({ error: { code: "CS-AUD-0001", message: "x" } })).state, "error");
  assert.equal(summarizeAnchor(JSON.stringify({ error: { code: "CS-AUD-0001" } })).code, "CS-AUD-0001");
  assert.equal(summarizeAnchor("not json").code, "CS-API-0001");
  assert.equal(summarizeAnchor(JSON.stringify({ ok: null })).state, "error");
});

test("the PDF's trail is matched only when it holds the anchored event", () => {
  const trail = parseTrail(trailBytes);
  // The fixture: the proof anchors the trail's last event.
  assert.deepEqual(anchorTrailPlan(proofBytes, trail), { use: true, note: "checked" });
  // No trail in the PDF.
  assert.deepEqual(anchorTrailPlan(proofBytes, null), { use: false, note: "none" });
  assert.deepEqual(anchorTrailPlan(proofBytes, { ok: false, problem: "not_json" }), { use: false, note: "none" });
  // An event after the trail ends (the sealed PDF's trail stops at sealing).
  const later = JSON.parse(new TextDecoder().decode(proofBytes));
  later.seq = trail.events.length + 4;
  assert.deepEqual(anchorTrailPlan(new TextEncoder().encode(JSON.stringify(later)), trail), { use: false, note: "later" });
  // Another envelope's trail: matched, so the verifier refuses it (CS-AUD-0012).
  const other = JSON.parse(new TextDecoder().decode(proofBytes));
  other.envelope_id = "someone-else";
  assert.deepEqual(anchorTrailPlan(new TextEncoder().encode(JSON.stringify(other)), trail), { use: true, note: "other" });
  // Not a proof: nothing to plan; the verifier names the problem.
  assert.deepEqual(anchorTrailPlan(new TextEncoder().encode("nope"), trail), { use: false, note: "none" });
  assert.equal(MAX_ANCHOR_PROOF, 256 * 1024);
});

test("the client answers null while nothing is anchored, as the server's 404 CS-API-0017", async () => {
  const { createMockFetch, MOCK } = await import("../mock.js");
  const { createClient } = await import("../api.js");
  const c = createClient({ fetch: createMockFetch() });
  await c.login(MOCK.email, MOCK.password);
  const env = (await c.listEnvelopes({ limit: 1 })).items[0];
  assert.equal(await c.anchorProof(env.id), null);
  // Any other refusal is not "not anchored".
  await assert.rejects(c.anchorProof("no-such-envelope"), (e) => e.code === "CS-API-0002");
});

test("a real trail, with sha256: hashes, reads with its links intact", () => {
  const trail = parseTrail(trailBytes);
  assert.equal(trail.ok, true);
  assert.equal(trail.events.length, 3);
  assert.deepEqual(trail.links, { ok: true, problems: [] });
});
