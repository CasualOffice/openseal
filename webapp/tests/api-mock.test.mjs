// The API client against the mock server, end to end (WEB-01). Run: node --test webapp/tests/
import test from "node:test";
import assert from "node:assert/strict";

import { createMockFetch, MOCK } from "../mock.js";
import { createClient, ApiError, errorMessage } from "../api.js";
import { makePdf } from "../mockpdf.js";

const PNG = btoa("\x89PNG\r\n\x1a\n" + "x".repeat(16));

async function signedIn() {
  const c = createClient({ fetch: createMockFetch() });
  await c.login(MOCK.email, MOCK.password);
  return c;
}

test("staff calls need a session, and a wrong password is CS-AUTH-0007", async () => {
  const c = createClient({ fetch: createMockFetch() });
  await assert.rejects(c.listEnvelopes(), (e) => e instanceof ApiError && e.code === "CS-AUTH-0001" && e.status === 401);
  await assert.rejects(c.login(MOCK.email, "wrong"), (e) => e.code === "CS-AUTH-0007");
});

test("a changing request without the CSRF token is refused (CS-AUTH-0008)", async () => {
  const fetch = createMockFetch();
  const c = createClient({ fetch });
  await c.login(MOCK.email, MOCK.password);
  await assert.rejects(c.request("POST", "/api/v1/envelopes", { body: {}, ceremony: true }), (e) => e.code === "CS-AUTH-0008");
  const ok = await c.createEnvelope({ subject: "x" });
  assert.equal(ok.status, "draft");
});

test("the list filters by status and pages by cursor", async () => {
  const c = await signedIn();
  const all = await c.listEnvelopes({ limit: 200 });
  assert.ok(all.items.length >= 6);
  const drafts = await c.listEnvelopes({ status: "draft" });
  assert.ok(drafts.items.length >= 1 && drafts.items.every((e) => e.status === "draft"));
  const p1 = await c.listEnvelopes({ limit: 2 });
  assert.equal(p1.items.length, 2);
  assert.ok(p1.next_cursor);
  const p2 = await c.listEnvelopes({ limit: 2, cursor: p1.next_cursor });
  assert.notEqual(p2.items[0].id, p1.items[0].id);
});

test("the list searches subject and recipients with q (WEB-04)", async () => {
  const c = await signedIn();
  const all = await c.listEnvelopes({ limit: 200 });
  const one = all.items[0];
  const bySubject = await c.listEnvelopes({ q: one.subject.toUpperCase(), limit: 200 });
  assert.ok(bySubject.items.some((e) => e.id === one.id));
  assert.ok(bySubject.items.length < all.items.length);
  const none = await c.listEnvelopes({ q: "no envelope says this" });
  assert.equal(none.items.length, 0);
  const seen = [];
  const fake = async (url) => { seen.push(url); return new Response(JSON.stringify({ items: [], next_cursor: null }), { status: 200 }); };
  await createClient({ fetch: fake }).listEnvelopes({ q: "a&b c" });
  assert.equal(seen[0], "/api/v1/envelopes?limit=25&q=a%26b+c");
});

test("create, edit with If-Match, send; a stale ETag is CS-WF-0002 and none is CS-API-0008", async () => {
  const c = await signedIn();
  const pdf = makePdf([{ title: "T", lines: ["a"] }]);
  const env = await c.createEnvelope({
    subject: "S",
    documents: [{ name: "a.pdf", content_base64: btoa(String.fromCharCode(...pdf)) }],
    recipients: [{ ref: "r1", type: "signer", name: "A", email: "a@example.com", routing_order: 1 }],
    fields: [{ recipient: "r1", document: 0, type: "signature", page: 1, x: "72", y: "600", width: "160", height: "44", required: true }],
  });
  assert.equal(env.fields.length, 1);
  assert.equal(env.fields[0].placement.x, "72");
  const { etag } = await c.getEnvelope(env.id);
  await c.patchEnvelope(env.id, etag, { subject: "S2" });
  await assert.rejects(c.patchEnvelope(env.id, etag, { subject: "S3" }), (e) => e.code === "CS-WF-0002" && e.status === 412);
  await assert.rejects(c.patchEnvelope(env.id, null, { subject: "S3" }), (e) => e.code === "CS-API-0008");
  const sent = await c.sendEnvelope(env.id);
  assert.equal(sent.status, "sent");
});

test("sending a signer with no field is CS-WF-0004 with a pointer", async () => {
  const c = await signedIn();
  const pdf = makePdf([{ title: "T" }]);
  const env = await c.createEnvelope({
    documents: [{ name: "a.pdf", content_base64: btoa(String.fromCharCode(...pdf)) }],
    recipients: [{ type: "signer", name: "A", email: "a@example.com" }],
  });
  await assert.rejects(c.sendEnvelope(env.id), (e) => e.code === "CS-WF-0004" && e.errors.some((x) => x.code === "no_fields"));
});

test("the ceremony: access code, consent with location, adopt, fill, finish completes the envelope", async () => {
  const c = await signedIn();
  const t = MOCK.ceremonyToken;
  await assert.rejects(c.ceremony.consent(t, MOCK.ersd), (e) => e.code === "CS-AUTH-0009");
  let v = await c.ceremony.open(t);
  assert.deepEqual(v.auth_required, ["access_code"]);
  assert.equal(v.envelope.signing_options.capture_location, true);
  // SEC-CER-01: before the code the view names no document and no field.
  assert.deepEqual(v.envelope.documents, []);
  assert.deepEqual(v.fields, []);
  await assert.rejects(c.ceremony.authenticate(t, "access_code", "0000"), (e) => e.code === "CS-AUTH-0003");
  v = await c.ceremony.authenticate(t, "access_code", MOCK.accessCode);
  assert.ok(v.envelope.documents.length > 0 && v.fields.length > 0);
  await assert.rejects(c.ceremony.fill(t, v.fields[0].id, { text: "x" }), (e) => e.code === "CS-AUTH-0005");
  await c.ceremony.consent(t, MOCK.ersd, { latitude: 1.5, longitude: 2.5, accuracy_m: 20 });
  const sig = v.fields.find((f) => f.type === "signature");
  await assert.rejects(c.ceremony.fill(t, sig.id, { signature: "nope" }), (e) => e.code === "CS-WF-0013");
  await assert.rejects(c.ceremony.finish(t), (e) => e.code === "CS-WF-0004");
  const a = await c.ceremony.adopt(t, "signature", "draw", PNG);
  await c.ceremony.fill(t, sig.id, { signature: a.adoption_id });
  await c.ceremony.fill(t, v.fields.find((f) => f.type === "text").id, { text: "Engineer" });
  v = await c.ceremony.finish(t, [], { declined: true });
  assert.equal(v.recipient.status, "completed");
  assert.equal(v.envelope.status, "completed");
  const audit = await c.audit(v.envelope.id);
  const consent = audit.items.find((i) => i.type === "recipient.consented");
  assert.deepEqual(consent.event.context.location, { latitude: 1.5, longitude: 2.5, accuracy_m: 20 });
  for (let i = 1; i < audit.items.length; i++) assert.equal(audit.items[i].prev, audit.items[i - 1].hash);
});

test("the signer downloads the certificate of completion once the envelope completes (VS-01)", async () => {
  const c = await signedIn();
  const t = MOCK.ceremonyToken;
  await c.ceremony.open(t);
  let v = await c.ceremony.authenticate(t, "access_code", MOCK.accessCode);
  await c.ceremony.consent(t, MOCK.ersd);
  await assert.rejects(c.ceremony.certificate(t), (e) => e.status === 409 && e.code === "CS-API-0009");
  const a = await c.ceremony.adopt(t, "signature", "draw", PNG);
  await c.ceremony.fill(t, v.fields.find((f) => f.type === "signature").id, { signature: a.adoption_id });
  await c.ceremony.fill(t, v.fields.find((f) => f.type === "text").id, { text: "Engineer" });
  v = await c.ceremony.finish(t);
  assert.equal(v.envelope.status, "completed");
  const blob = await c.ceremony.certificate(t);
  assert.equal(new TextDecoder().decode((await blob.arrayBuffer()).slice(0, 5)), "%PDF-");
});

test("decline with a reason ends the envelope as declined", async () => {
  const c = await signedIn();
  await c.ceremony.open(MOCK.declineToken);
  const v = await c.ceremony.decline(MOCK.declineToken, "Wrong amount");
  assert.equal(v.envelope.status, "declined");
  assert.equal(v.recipient.declined_reason, "Wrong amount");
});

test("errorMessage names the code and request id", () => {
  const e = new ApiError({ status: 404, code: "CS-API-0002", title: "Not found", request_id: "r-1" });
  assert.match(errorMessage(e), /CS-API-0002, r-1/);
  assert.match(errorMessage(new ApiError({})), /CS-NET-0001/);
});

test("the client sends CSRF on changes, Idempotency-Key on POST, If-Match when given", async () => {
  const seen = [];
  const fake = async (url, init) => {
    seen.push({ url, init });
    if (url.endsWith("/auth/login")) return new Response(JSON.stringify({ csrf_token: "tok" }), { status: 200 });
    return new Response(null, { status: 204 });
  };
  const c = createClient({ fetch: fake, baseUrl: "https://api.example" });
  await c.login("a", "b");
  await c.patchField("e", "f", '"v3"', { required: true });
  await c.voidEnvelope("e", "r");
  await c.listEnvelopes({ status: "sent", cursor: "c1" });
  assert.equal(seen[1].init.headers["X-CSRF-Token"], "tok");
  assert.equal(seen[1].init.headers["If-Match"], '"v3"');
  assert.ok(seen[2].init.headers["Idempotency-Key"]);
  assert.equal(seen[2].init.credentials, "include");
  assert.equal(seen[3].init.headers["X-CSRF-Token"], undefined);
  assert.equal(seen[3].url, "https://api.example/api/v1/envelopes?status=sent&cursor=c1&limit=25");
});

test("a problem response becomes an ApiError with its code; a non-JSON error still has one", async () => {
  const c1 = createClient({ fetch: async () => new Response(JSON.stringify({ type: "x", title: "Stale", status: 412, code: "CS-WF-0002", request_id: "q" }), { status: 412 }) });
  await assert.rejects(c1.session(), (e) => e.code === "CS-WF-0002" && e.requestId === "q");
  const c2 = createClient({ fetch: async () => new Response("<html>", { status: 502 }) });
  await assert.rejects(c2.session(), (e) => e.code === "HTTP-502");
  const c3 = createClient({ fetch: async () => { throw new TypeError("offline"); } });
  await assert.rejects(c3.session(), (e) => e.code === "CS-NET-0001");
});

test("SMS and voice codes (VS-05): a phone in international form, the method sent and checked", async () => {
  const c = await signedIn();
  const pdf = makePdf([{ title: "T" }]);
  const doc = { name: "a.pdf", content_base64: btoa(String.fromCharCode(...pdf)) };
  await assert.rejects(c.createEnvelope({ documents: [doc], recipients: [{ type: "signer", name: "A", email: "a@example.com", auth: ["sms_otp"], phone: "020 7946 0000" }] }),
    (e) => e.status === 422 && e.errors.some((x) => x.pointer === "/phone"));
  const env = await c.createEnvelope({
    documents: [doc],
    recipients: [{ ref: "r1", type: "signer", name: "A", email: "a@example.com", phone: "+44 20 7946 0001", auth: ["sms_otp"] }],
    fields: [{ recipient: "r1", document: 0, type: "signature", page: 1, x: "72", y: "600", width: "160", height: "44", required: true }],
  });
  const sent = await c.sendEnvelope(env.id);
  const t = sent.recipients[0].mock_token;
  let v = await c.ceremony.open(t);
  assert.deepEqual(v.auth_required, ["sms_otp"]);
  await assert.rejects(c.ceremony.otpSend(t), (e) => e.code === "CS-API-0014");
  await c.ceremony.otpSend(t, "sms_otp");
  await assert.rejects(c.ceremony.otpVerify(t, "000000", "sms_otp"), (e) => e.status === 403);
  await c.ceremony.otpSend(t, "sms_otp");
  v = await c.ceremony.otpVerify(t, MOCK.emailCode, "sms_otp");
  assert.deepEqual(v.auth_required, []);
});

test("sign-in through an identity provider (RAUTH-01): providers listed, the state works once", async () => {
  const c = await signedIn();
  const pdf = makePdf([{ title: "T" }]);
  const doc = { name: "a.pdf", content_base64: btoa(String.fromCharCode(...pdf)) };
  const env = await c.createEnvelope({
    documents: [doc],
    recipients: [{ ref: "r1", type: "signer", name: "A", email: "a@example.com", auth: ["sso"] }],
    fields: [{ recipient: "r1", document: 0, type: "signature", page: 1, x: "72", y: "600", width: "160", height: "44", required: true }],
  });
  const sent = await c.sendEnvelope(env.id);
  const t = sent.recipients[0].mock_token;
  let v = await c.ceremony.open(t);
  assert.deepEqual(v.auth_required, ["sso"]);
  assert.deepEqual(v.sso_providers, [MOCK.ssoProvider]);
  assert.deepEqual(v.envelope.documents, []);
  await assert.rejects(c.ceremony.ssoStart(t, "other"), (e) => e.status === 422);
  const started = await c.ceremony.ssoStart(t, MOCK.ssoProvider.id);
  const q = new URLSearchParams(started.sso_authorization_url.split("?")[1]);
  await assert.rejects(c.ceremony.ssoVerify(t, q.get("state"), "wrong-code"), (e) => e.status === 403);
  // That state is spent: the right code no longer passes with it.
  await assert.rejects(c.ceremony.ssoVerify(t, q.get("state"), MOCK.ssoCode), (e) => e.status === 403);
  const again = new URLSearchParams((await c.ceremony.ssoStart(t, MOCK.ssoProvider.id)).sso_authorization_url.split("?")[1]);
  v = await c.ceremony.ssoVerify(t, again.get("state"), again.get("code"));
  assert.deepEqual(v.auth_required, []);
  assert.equal(v.envelope.documents.length, 1);
  assert.equal(v.sso_providers, undefined);
});
