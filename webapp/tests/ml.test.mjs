// The web app's model layer (WEB-18; webapp/ml.js) and its mock endpoints (docs/33 §6).
// Run: cd webapp && node --test tests/
import test from "node:test";
import assert from "node:assert/strict";

import { createMockFetch, MOCK } from "../mock.js";
import { createClient, ApiError } from "../api.js";
import {
  statusFrom, featureOn, isLowConfidence, isUnavailable, percent, openOf, withState,
  initMl, mlStatus, loadSuggestions, suggestions, openCount, acceptSuggestion, dismissSuggestion, onSuggestions,
} from "../ml.js";

/// A session store for the mock's test hooks (sessionStorage in the browser).
function memoryStore(init = {}) {
  const m = new Map(Object.entries(init));
  return { getItem: (k) => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)), removeItem: (k) => m.delete(k) };
}

async function signedIn(storeInit = {}, now) {
  const c = createClient({ fetch: createMockFetch({ store: memoryStore(storeInit), ...(now ? { now } : {}) }) });
  await c.login(MOCK.email, MOCK.password);
  return c;
}

const byPrefix = async (c, prefix) => (await c.listEnvelopes({ limit: 200 })).items.find((e) => e.subject.startsWith(prefix));

// ---- pure decisions ----------------------------------------------------------------------

test("a 404, CS-ML-0011 or a call the client refuses means every ML surface hides", () => {
  for (const error of [
    new ApiError({ status: 404, code: "CS-API-0002" }),
    new ApiError({ status: 404, code: "HTTP-404" }),
    new ApiError({ status: 403, code: "CS-ML-0011" }),
    new ApiError({ status: 501, code: "CS-NET-0002" }),
  ]) {
    const s = statusFrom({ error });
    assert.equal(s.available, false, error.code);
    assert.equal(featureOn(s), false);
    assert.equal(featureOn(s, "ocr"), false);
    assert.ok(isUnavailable(error));
  }
  assert.equal(statusFrom({ error: new ApiError({ status: 404, code: "CS-API-0002" }) }).notInstalled, true);
  assert.equal(statusFrom({ error: new ApiError({ status: 403, code: "CS-ML-0011" }) }).notInstalled, false);
  // Offline is not "unavailable for good", but nothing ML shows this session either.
  assert.equal(statusFrom({ error: new ApiError({ code: "CS-NET-0001" }) }).available, false);
  assert.equal(isUnavailable(new ApiError({ code: "CS-NET-0001" })), false);
});

test("settings: each feature on only when on and in the plan; installed false hides all", () => {
  const s = statusFrom({ settings: { ocr: true, template_matching: false, extraction: true, personal_data: true, not_in_plan: ["personal_data"] } });
  assert.deepEqual(s.features, { ocr: true, template_matching: false, extraction: true, personal_data: false });
  assert.deepEqual(s.notInPlan, ["personal_data"]);
  assert.equal(s.available, true);
  assert.equal(featureOn(s, "template_matching"), false);
  const off = statusFrom({ settings: { ocr: false, template_matching: false, extraction: false, personal_data: false } });
  assert.equal(off.available, false);
  const gone = statusFrom({ settings: { ocr: true, extraction: true, installed: false } });
  assert.equal(gone.available, false);
  assert.equal(gone.notInstalled, true);
  // Not an admin: the settings are refused, so each surface asks for itself.
  const member = statusFrom({ error: new ApiError({ status: 403, code: "CS-AUTH-0004" }) });
  assert.equal(member.available, true);
  assert.equal(member.known, false);
});

test("under 75 % a suggestion says check this; scores read as whole percents", () => {
  assert.equal(isLowConfidence({ score: 0.64 }), true);
  assert.equal(isLowConfidence({ score: 0.749 }), true);
  assert.equal(isLowConfidence({ score: 0.75 }), false);
  assert.equal(isLowConfidence({ confidence: 0.96 }), false);
  assert.equal(isLowConfidence({}), true);
  assert.equal(percent({ score: 0.944 }), "94%");
  assert.equal(percent(2), "100%");
  const list = [{ id: "a", state: "open" }, { id: "b", state: "accepted" }, { id: "c" }];
  assert.deepEqual(openOf(list).map((s) => s.id), ["a", "c"]);
  const next = withState(list, "a", "dismissed");
  assert.equal(next[0].state, "dismissed");
  assert.equal(list[0].state, "open", "the original list is not changed");
});

// ---- the mock's endpoints ---------------------------------------------------------------------

test("the mock serves settings, suggestions with the canvas's examples, and search by meaning", async () => {
  const c = await signedIn();
  const settings = await c.getMlSettings();
  for (const f of ["ocr", "template_matching", "extraction", "personal_data"]) assert.equal(settings[f], true, f);
  const vendor = await byPrefix(c, "Vendor services");
  const page = await c.listSuggestions(vendor.id);
  const law = page.items.find((s) => s.label === "Governing law");
  assert.equal(law.value, "Portugal");
  assert.equal(law.score, 0.64);
  assert.ok(page.items.some((s) => s.kind === "personal_data"));
  const pii = await c.listSuggestions(vendor.id, { kind: "personal_data" });
  assert.ok(pii.items.length > 0 && pii.items.every((s) => s.kind === "personal_data"));
  // Decided once only.
  await c.acceptSuggestion(vendor.id, law.id);
  await assert.rejects(c.dismissSuggestion(vendor.id, law.id), (e) => e.status === 409 && e.code === "CS-ML-0012");
  const open = await c.listSuggestions(vendor.id, { state: "open" });
  assert.ok(!open.items.some((s) => s.id === law.id));
  // Search by meaning finds the payment clause although the words differ.
  const found = await c.searchByMeaning("payment within 30 days");
  assert.ok(found.items.length >= 1);
  assert.equal(found.items[0].subject, vendor.subject);
  assert.ok(found.items[0].snippet.some((r) => r.mark));
});

test("the draft matches MSA v4 at 96 %, its analysis runs for about 2 s, page 3 is scanned or its last", async () => {
  let t = Date.parse("2026-11-13T10:00:00Z");
  const c = await signedIn({}, () => new Date(t));
  const lease = await byPrefix(c, "Lease renewal");
  const doc = (await c.getEnvelope(lease.id)).envelope.documents[0];
  const match = (await c.listSuggestions(lease.id, { kind: "template" })).items[0];
  assert.equal(match.label, "MSA v4");
  assert.equal(match.score, 0.96);
  const first = await c.requestAnalysis(lease.id, doc.id);
  assert.equal(first.status, "running");
  assert.equal((await c.getAnalysis(lease.id, doc.id)).status, "running");
  t += 2100;
  const done = await c.getAnalysis(lease.id, doc.id);
  assert.equal(done.status, "done");
  assert.deepEqual(done.ocr_pages, [Math.min(3, doc.pages)]);
  // Analysis is for drafts only.
  const nda = await byPrefix(c, "Mutual NDA");
  const ndaDoc = (await c.getEnvelope(nda.id)).envelope.documents[0];
  await assert.rejects(c.requestAnalysis(nda.id, ndaDoc.id), (e) => e.status === 409);
});

test("with ML off on the server (404) or not in the plan (CS-ML-0011), the layer reports unavailable and loads nothing", async () => {
  for (const mode of ["off", "no-plan"]) {
    const c = await signedIn({ "openseal.mock.ml": mode });
    initMl(c);
    const s = await mlStatus();
    assert.equal(s.available, false, mode);
    const vendor = await byPrefix(c, "Vendor services");
    assert.deepEqual(await loadSuggestions(vendor.id), [], mode);
    assert.equal(openCount(vendor.id), 0);
  }
});

// ---- the store: optimistic, rolled back, announced -------------------------------------------------

test("accept and dismiss show at once, roll back when refused, and tell listeners", async () => {
  const c = await signedIn();
  initMl(c);
  assert.equal((await mlStatus()).available, true);
  const offer = await byPrefix(c, "Offer letter");
  const items = await loadSuggestions(offer.id);
  assert.equal(items.length, 6);
  assert.equal(openCount(offer.id), 6);
  const seen = [];
  const stop = onSuggestions((e) => seen.push([e.envId, openOf(e.items).length]));
  const [a, b] = items;
  const pending = acceptSuggestion(offer.id, a.id);
  assert.equal(openCount(offer.id), 5, "accepted before the server answers");
  await pending;
  assert.equal(suggestions(offer.id).find((s) => s.id === a.id).state, "accepted");
  await dismissSuggestion(offer.id, b.id);
  assert.equal(openCount(offer.id), 4);
  // Refused (already decided on the server): back as it was.
  await assert.rejects(acceptSuggestion(offer.id, b.id), (e) => e.code === "CS-ML-0012");
  assert.equal(suggestions(offer.id).find((s) => s.id === b.id).state, "dismissed");
  assert.equal(openCount(offer.id), 4);
  stop();
  assert.ok(seen.length >= 4 && seen.every(([id]) => id === offer.id));
  assert.deepEqual(seen.slice(0, 2).map(([, n]) => n), [5, 5]);
});

test("a failed accept rolls the suggestion back to open", async () => {
  const c = await signedIn();
  const refusing = { ...c, acceptSuggestion: () => Promise.reject(new ApiError({ status: 0, code: "CS-NET-0001" })) };
  initMl(refusing);
  const offer = await byPrefix(c, "Offer letter");
  const [a] = await loadSuggestions(offer.id);
  const p = acceptSuggestion(offer.id, a.id);
  assert.equal(suggestions(offer.id)[0].state, "accepted");
  await assert.rejects(p, (e) => e.code === "CS-NET-0001");
  assert.equal(suggestions(offer.id)[0].state, "open");
  assert.equal(openCount(offer.id), 6);
});
