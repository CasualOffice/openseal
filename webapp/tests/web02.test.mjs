// Pure modules of WEB-02 and WEB-03: templates as data, the verifier report, the
// embedded audit trail, zoom, the extra API calls and the mock's new endpoints.
// Run: cd webapp && npm test
import test from "node:test";
import assert from "node:assert/strict";

import { EN } from "../strings.en.js";
import { rolesFrom, rolesOf, peopleProblems, envelopeFromTemplate, countLabel } from "../templatemodel.js";
import { summarize, coverage, certificatesFrom, CHECKS } from "../verifyreport.js";
import { parseTrail, eventLabel, MAX_TRAIL_BYTES } from "../trail.js";
import { clampZoom, pinchZoom, enlargeFor, MIN_ZOOM, MAX_ZOOM } from "../zoom.js";
import { createClient, isMockMode, isNoServer } from "../api.js";
import { extend, templateDocsUnsupported } from "../api-extra.js";
import { createMockFetch, MOCK } from "../mock.js";
import { makePdf } from "../mockpdf.js";

// ---- templates ----------------------------------------------------------------------
test("rolesFrom orders signers and puts copies after them; names are unique", () => {
  const rs = [{ name: "Client", type: "signer" }, { name: "", type: "cc" }, { name: "client", type: "signer" }];
  assert.deepEqual(rolesFrom(rs, "sequential"), [
    { name: "Client", type: "signer", routing_order: 1 },
    { name: "Role 2", type: "cc", routing_order: 3 },
    { name: "client (2)", type: "signer", routing_order: 2 },
  ]);
  assert.deepEqual(rolesFrom(rs, "parallel").map((r) => r.routing_order), [1, 2, 1]);
});

test("rolesOf sorts by routing order and survives junk from the API", () => {
  const r = rolesOf({ roles: [{ name: "B", routing_order: 2, type: "signer" }, { name: "A", routing_order: 1, type: "cc" }, null, { routing_order: -3 }] });
  assert.deepEqual(r.map((x) => [x.name, x.type, x.routing_order]), [["A", "cc", 1], ["Role 3", "signer", 1], ["Role 4", "signer", 1], ["B", "signer", 2]]);
  assert.deepEqual(rolesOf(null), []);
});

test("peopleProblems names each missing name and bad email", () => {
  const roles = rolesOf({ roles: [{ name: "Client", type: "signer" }, { name: "Witness", type: "signer", routing_order: 2 }] });
  assert.deepEqual(peopleProblems(roles, { Client: { name: "Ada", email: "ada@example.com" }, Witness: { name: " ", email: "nope" } }),
    [{ role: "Witness", problem: "name" }, { role: "Witness", problem: "email" }]);
});

test("envelopeFromTemplate maps roles to recipients and fields, dropping orphans", () => {
  const tp = { name: "NDA", email_subject: "Sign the NDA", roles: [{ name: "Company", type: "signer", routing_order: 1 }, { name: "Legal", type: "cc", routing_order: 2 }] };
  const placement = { page: 1, x: "72", y: "600", width: "160", height: "44" };
  const { body, dropped } = envelopeFromTemplate(tp, { Company: { name: "Ada", email: "ada@example.com" }, Legal: { name: "Lin", email: "lin@example.com" } }, {
    docs: [{ id: "d1", name: "nda.pdf", base64: "JVBERi0=" }],
    fields: [{ document_id: "d1", role: "Company", type: "signature", placement, required: true }, { document_id: "d9", role: "Company", type: "text", placement }, { document_id: "d1", role: "Gone", type: "text", placement }],
    status: "sent",
  });
  assert.equal(dropped, 2);
  assert.equal(body.subject, "Sign the NDA");
  assert.equal(body.status, "sent");
  assert.deepEqual(body.recipients.map((r) => [r.ref, r.name, r.type, r.routing_order]), [["role0", "Ada", "signer", 1], ["role1", "Lin", "cc", 2]]);
  assert.deepEqual(body.fields, [{ recipient: "role0", document: 0, type: "signature", page: 1, x: "72", y: "600", width: "160", height: "44", required: true }]);
});

test("countLabel says when the list went on", () => {
  assert.equal(countLabel({ n: 7, more: false }), "7");
  assert.equal(countLabel({ n: 200, more: true }), "200+");
});

// ---- verifier report ------------------------------------------------------------------
const passed = { status: "passed", sub_indication: null, code: null };
const sig = (indication, extra = {}) => ({
  field: 7, value: 6, sub_filter: "ETSI.CAdES.detached", kind: { type: "approval" }, byte_range: [0, 1, 2, 3], signed_revision: 1,
  covers_whole_document: true, indication, checks: Object.fromEntries(CHECKS.map((c) => [c, passed])),
  validation_time: { secs: 1793534400, nanos: 0 }, time_source: "signature_timestamp", timestamp: { secs: 1793534400, nanos: 0 }, modifications_after: [], ...extra,
});
const report = (signatures, extra = {}) => JSON.stringify({ ok: { error: null, revisions: 2, signatures, revision_changes: [], covered_by_last_signature: true, all_passed: false, ...extra } });

test("summarize names the verifier's verdict and never upgrades it", () => {
  assert.equal(summarize(report([sig({ indication: "TOTAL_PASSED" })])).state, "valid");
  const ind = summarize(report([sig({ indication: "INDETERMINATE", sub_indication: "NO_CERTIFICATE_CHAIN_FOUND", code: "CS-VER-0004" })]));
  assert.equal(ind.state, "indeterminate");
  assert.equal(ind.needsTrust, true);
  assert.equal(summarize(report([sig({ indication: "TOTAL_PASSED" }), sig({ indication: "TOTAL_FAILED", sub_indication: "HASH_FAILURE" })])).state, "invalid");
  // A disallowed change after the last signature fails the document even when each signature passed.
  assert.equal(summarize(report([sig({ indication: "TOTAL_PASSED" })], { revision_changes: [{ revision: 2, allowed: false, classes: [{ disallowed: "page_changed", number: 3 }] }] })).state, "invalid");
  assert.equal(summarize(report([])).state, "unsigned");
  assert.deepEqual(summarize(JSON.stringify({ error: { code: "CS-PDF-0001", message: "x" } })).state, "error");
  assert.equal(summarize("not json").state, "error");
  assert.equal(summarize(report([], { error: { code: "CS-VER-0001" } })).code, "CS-VER-0001");
});

test("coverage reads whole, allowed later revisions, or changed", () => {
  const one = (extra) => summarize(report([sig({ indication: "TOTAL_PASSED" }, extra)])).signatures[0];
  assert.equal(coverage(one({})), "whole");
  assert.equal(coverage(one({ covers_whole_document: false, modifications_after: [{ revision: 2, allowed: true, classes: ["dss_update"] }] })), "allowed");
  assert.equal(coverage(one({ covers_whole_document: false, modifications_after: [{ revision: 2, allowed: false, classes: [] }] })), "changed");
});

test("certificatesFrom takes DER as is and every PEM certificate block", () => {
  assert.deepEqual(certificatesFrom(new Uint8Array([0x30, 0x03, 0x02, 0x01, 0x01])), ["MAMCAQE="]);
  const pem = "junk\n-----BEGIN CERTIFICATE-----\nMAMC\nAQE=\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nMAA=\n-----END CERTIFICATE-----\n";
  assert.deepEqual(certificatesFrom(new TextEncoder().encode(pem)), ["MAMCAQE=", "MAA="]);
  assert.deepEqual(certificatesFrom(new TextEncoder().encode("hello")), []);
});

// ---- audit trail ------------------------------------------------------------------------
const H = (n) => n.toString(16).padStart(64, "0");
const trail = (events, head = events.length ? events[events.length - 1].hash : null) =>
  new TextEncoder().encode(JSON.stringify({ format: "openseal.audit-trail", v: 1, envelope_id: "e1", head, events }));
const ev = (seq, extra = {}) => ({ v: 1, envelope_id: "e1", seq, prev: seq ? H(seq) : null, at: "2026-11-10T09:14:03.512Z", type: "envelope.created", actor: { kind: "sender", name: "Ada" }, context: {}, data: {}, hash: H(seq + 1), ...extra });

test("parseTrail reads events and checks their links", () => {
  const ok = parseTrail(trail([ev(0), ev(1), ev(2)]));
  assert.equal(ok.ok, true);
  assert.equal(ok.links.ok, true);
  assert.equal(ok.events.length, 3);
  assert.deepEqual(ok.events[0].actor, { kind: "sender", name: "Ada" });
  const broken = parseTrail(trail([ev(0), ev(1, { prev: H(9) }), ev(3)]));
  assert.deepEqual(broken.links.problems, [{ seq: 1, problem: "prev" }, { seq: 2, problem: "seq" }, { seq: 2, problem: "prev" }]);
  assert.deepEqual(parseTrail(trail([ev(0)], H(5))).links.problems, [{ seq: 1, problem: "head" }]);
});

test("parseTrail refuses what is not a trail, and too much of one", () => {
  assert.equal(parseTrail(new TextEncoder().encode("{")).problem, "not_json");
  assert.equal(parseTrail(new TextEncoder().encode('{"format":"x","events":[]}')).problem, "not_trail");
  assert.equal(parseTrail(new Uint8Array(MAX_TRAIL_BYTES + 1)).problem, "too_large");
  assert.equal(parseTrail(new Uint8Array([0xff, 0xfe])).problem, "not_json");
  assert.equal(eventLabel("recipient.signature_adopted"), "Recipient signature adopted");
});

// ---- zoom ----------------------------------------------------------------------------------
test("zoom stays in range; a pinch scales by the spread; a field grows to 44 px within the screen", () => {
  assert.equal(clampZoom(10), MAX_ZOOM);
  assert.equal(clampZoom(0), MIN_ZOOM);
  assert.equal(clampZoom(Number.NaN), 1);
  assert.equal(pinchZoom(1, 100, 200), 2);
  assert.equal(pinchZoom(2, 0, 50), 2);
  assert.equal(enlargeFor(100, 22, 358), 2);
  assert.equal(enlargeFor(300, 11, 358), 1.19);
  assert.equal(enlargeFor(100, 60, 358), 1);
});

// ---- api ------------------------------------------------------------------------------------
test("mock mode is remembered for the tab once seen on loopback, and ?mock=0 forgets", () => {
  const m = new Map();
  const store = { getItem: (k) => m.get(k) ?? null, setItem: (k, v) => m.set(k, v), removeItem: (k) => m.delete(k) };
  assert.equal(isMockMode({ hostname: "127.0.0.1", search: "" }, store), false);
  assert.equal(isMockMode({ hostname: "127.0.0.1", search: "?mock=1" }, store), true);
  assert.equal(isMockMode({ hostname: "127.0.0.1", search: "" }, store), true);
  assert.equal(isMockMode({ hostname: "sign.example.com", search: "" }, store), false);
  assert.equal(isMockMode({ hostname: "127.0.0.1", search: "?mock=0" }, store), false);
  assert.equal(isMockMode({ hostname: "127.0.0.1", search: "" }, store), false);
});

test("isNoServer is a loopback dev server's 404 or 501, or no answer; never a real problem", () => {
  const lo = { hostname: "127.0.0.1" };
  assert.equal(isNoServer({ code: "HTTP-501" }, lo), true);
  assert.equal(isNoServer({ code: "CS-NET-0001" }, lo), true);
  assert.equal(isNoServer({ code: "CS-API-0002" }, lo), false);
  assert.equal(isNoServer({ code: "HTTP-501" }, { hostname: "sign.example.com" }), false);
});

async function signedIn() {
  const api = extend(createClient({ fetch: createMockFetch() }));
  await api.login(MOCK.email, MOCK.password);
  return api;
}

test("templates: list, create with roles, rename with If-Match; slice-3 documents and fields", async () => {
  const api = await signedIn();
  const before = (await api.templates.list()).items.length;
  const tp = await api.templates.create({ name: "Lease", roles: [{ name: "Tenant", type: "signer", routing_order: 1 }] });
  assert.equal((await api.templates.list()).items.length, before + 1);
  const { etag } = await api.templates.get(tp.id);
  const renamed = await api.templates.rename(tp.id, etag, "Lease 2027");
  assert.equal(renamed.name, "Lease 2027");
  await assert.rejects(api.templates.rename(tp.id, etag, "stale"), (e) => e.code === "CS-WF-0002");
  const doc = await api.templates.addDocument(tp.id, "lease.pdf", makePdf([{ title: "Lease" }]));
  const placement = { page: 1, x: "72", y: "600", width: "160", height: "44" };
  await api.templates.addFields(tp.id, [{ document_id: doc.id, role: "Tenant", type: "signature", placement, required: true }]);
  await assert.rejects(api.templates.addFields(tp.id, [{ document_id: doc.id, role: "Nobody", type: "text", placement }]), (e) => e.code === "CS-WF-0008");
  const { template } = await api.templates.get(tp.id);
  assert.equal(template.fields.length, 1);
  const blob = await api.templates.documentContent(tp.id, doc.id);
  assert.equal(new TextDecoder().decode(new Uint8Array(await blob.arrayBuffer()).subarray(0, 5)), "%PDF-");
});

test("a template becomes one envelope on the envelope API", async () => {
  const api = await signedIn();
  const nda = (await api.templates.list()).items.find((x) => x.name === "Mutual NDA");
  const { template } = await api.templates.get(nda.id);
  const docs = [];
  for (const d of template.documents) {
    const b = new Uint8Array(await (await api.templates.documentContent(template.id, d.id)).arrayBuffer());
    docs.push({ id: d.id, name: d.name, base64: Buffer.from(b).toString("base64") });
  }
  const people = { Company: { name: "Ada", email: "ada@example.com" }, Counterparty: { name: "Bo", email: "bo@example.com" }, Legal: { name: "Lin", email: "lin@example.com" } };
  const { body } = envelopeFromTemplate(template, people, { docs, fields: template.fields, status: "sent" });
  const env = await api.createEnvelope(body);
  assert.equal(env.status, "sent");
  assert.equal(env.recipients.length, 3);
  assert.equal(env.fields.length, template.fields.length);
});

test("users and API clients: list, add, rename, remove; a secret is returned once", async () => {
  const api = await signedIn();
  const u = await api.users.create({ name: "Kim", email: "kim@example.com", profile: "viewer" });
  assert.equal((await api.users.patch(u.id, { name: "Kim Lee" })).name, "Kim Lee");
  await api.users.remove(u.id);
  assert.ok(!(await api.users.list()).items.some((x) => x.id === u.id));
  await assert.rejects(api.users.create({ name: "X", email: "bad", profile: "viewer" }), (e) => e.code === "CS-API-0001");
  const c = await api.apiClients.create({ name: "CI", kind: "api_key", scopes: ["envelopes:read"], expires_in_days: 30 });
  assert.match(c.key, /^osk_/);
  assert.ok(!("key" in (await api.apiClients.list()).items.find((x) => x.id === c.id)));
  await api.apiClients.revoke(c.id);
  assert.equal((await api.apiClients.list()).items.find((x) => x.id === c.id).revoked, true);
});

test("countEnvelopes counts one page and says when there is more", async () => {
  const api = await signedIn();
  const all = (await api.listEnvelopes({ limit: 200 })).items.length;
  const drafts = await api.countEnvelopes("draft");
  assert.ok(drafts.n >= 1 && drafts.n <= all);
  assert.equal((await api.countEnvelopes(undefined, 1)).more, all > 1);
});

test("templateDocsUnsupported is a 404 or 405 only", () => {
  assert.equal(templateDocsUnsupported({ status: 404 }), true);
  assert.equal(templateDocsUnsupported({ status: 405 }), true);
  assert.equal(templateDocsUnsupported({ status: 422 }), false);
  assert.equal(templateDocsUnsupported(null), false);
});

// ---- strings built from data ------------------------------------------------------------------
test("every message family the WEB-02 screens build from data has its strings", () => {
  const missing = [];
  const need = (k) => { if (!(k in EN)) missing.push(k); };
  for (const k of ["action", "waiting", "completed", "drafts"]) need(`home.counter.${k}`);
  for (const k of ["valid", "invalid", "indeterminate", "unsigned", "error"]) { need(`verify.state.${k}`); if (k !== "error") need(`verify.state.${k}-text`); }
  for (const k of ["valid", "invalid", "indeterminate"]) need(`verify.sig.${k}`);
  for (const k of CHECKS) need(`verify.check.${k}`);
  for (const k of ["passed", "failed", "not_run"]) need(`verify.status.${k}`);
  for (const k of ["approval", "certification", "document_timestamp"]) need(`verify.kind.${k}`);
  for (const k of ["signature_timestamp", "document_timestamp", "validation_time"]) need(`verify.source.${k}`);
  for (const k of ["whole", "allowed", "changed"]) need(`verify.coverage.${k}`);
  for (const k of ["too_large", "not_json", "not_trail", "too_many"]) need(`verify.trail-bad.${k}`);
  for (const k of ["admin", "sender", "viewer"]) need(`admin.profile.${k}`);
  for (const k of ["api_key", "oauth_app"]) need(`admin.kind.${k}`);
  assert.deepEqual(missing, []);
});
