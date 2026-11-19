// The TypeScript SDK against the recorded contract (sdk/contract/recorded.json), with no
// network: each call is checked as sent and answered as recorded. Run: node --test
// sdk/typescript/test/ (or npm test in sdk/typescript).
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { OpenSeal, OpenSealError, OPERATIONS, verifyWebhook } from "../index.js";

const REC = JSON.parse(readFileSync(new URL("../../contract/recorded.json", import.meta.url), "utf8"));
const API = readFileSync(new URL("../../../api/openapi.yaml", import.meta.url), "utf8");

/// A fetch that answers `response` and keeps what it was asked.
function replay(response) {
  const seen = [];
  const f = async (url, init) => {
    seen.push({ url, ...init });
    return new Response(response.body == null ? null : JSON.stringify(response.body), { status: response.status, headers: response.headers });
  };
  return { f, seen };
}

test("every public operation of the contract is a method, and nothing else is", () => {
  const ids = [...API.matchAll(/^ {6}operationId: (\S+)$/gm)].map((m) => m[1]);
  const os = new OpenSeal({ baseUrl: REC.base_url, fetch: async () => { throw new Error("no network"); } });
  for (const id of Object.keys(OPERATIONS)) {
    assert.ok(ids.includes(id), `${id} is not in api/openapi.yaml`);
    assert.equal(typeof os[id], "function", id);
  }
  // The ceremony (`/s/`) is not public API (docs/40 §6).
  assert.ok(Object.values(OPERATIONS).every((o) => !o.path.startsWith("/s/")));
  assert.ok(Object.keys(OPERATIONS).length >= 150);
});

for (const x of REC.exchanges) {
  test(`recorded: ${x.name}`, async () => {
    const { f, seen } = replay(x.response);
    const os = new OpenSeal({ baseUrl: REC.base_url, apiKey: x.credential, fetch: f });
    const call = os[x.operation](x.params);
    if (x.error) {
      await assert.rejects(call, (e) => e instanceof OpenSealError && e.code === x.error.code && e.status === x.error.status && e.requestId === "req-1");
    } else {
      const got = await call;
      assert.deepEqual(got, x.response.body);
    }
    assert.equal(seen.length, 1);
    assert.equal(seen[0].method, x.request.method);
    assert.equal(seen[0].url, x.request.url);
    for (const [k, v] of Object.entries(x.request.headers)) assert.equal(seen[0].headers[k], v, k);
    if (x.params.body) assert.deepEqual(JSON.parse(seen[0].body), x.params.body);
  });
}

test("a missing path parameter or body is refused before any request", async () => {
  const os = new OpenSeal({ baseUrl: REC.base_url, fetch: async () => { throw new Error("no network"); } });
  await assert.rejects(os.getEnvelope({}), /id is required/);
  await assert.rejects(os.createEnvelope({}), /body is required/);
});

test("OAuth: the authorization URL carries an S256 challenge of its verifier; the code exchange is the recorded one", async () => {
  const os = new OpenSeal({ baseUrl: REC.base_url, fetch: async () => { throw new Error("no network"); } });
  const { url, verifier, state } = await os.authorizationUrl({ clientId: "c1", redirectUri: "https://app.example.test/callback", scope: ["envelopes:read", "envelopes:write"] });
  const u = new URL(url);
  assert.equal(`${u.origin}${u.pathname}`, `${REC.base_url}/api/v1/oauth/authorize`);
  assert.equal(u.searchParams.get("scope"), "envelopes:read envelopes:write");
  assert.equal(u.searchParams.get("state"), state);
  assert.equal(u.searchParams.get("code_challenge_method"), "S256");
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier)));
  const want = btoa(String.fromCharCode(...digest)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  assert.equal(u.searchParams.get("code_challenge"), want);
  assert.ok(verifier.length >= 43 && verifier.length <= 128);

  const t = REC.token;
  const { f, seen } = replay(t.response);
  const client = new OpenSeal({ baseUrl: REC.base_url, fetch: f });
  const tok = await client.token({ clientId: t.client_id, clientSecret: t.client_secret, ...t.form });
  assert.equal(tok.refresh_token, "osr_refresh");
  assert.equal(seen[0].url, t.request.url);
  for (const [k, v] of Object.entries(t.request.headers)) assert.equal(seen[0].headers[k], v, k);
  assert.deepEqual(Object.fromEntries(new URLSearchParams(seen[0].body)), t.form);
  // Later calls carry the access token.
  client.fetch = replay({ status: 200, headers: { "content-type": "application/json" }, body: { items: [] } }).f;
  const later = replay({ status: 200, headers: { "content-type": "application/json" }, body: { items: [] } });
  client.fetch = later.f;
  await client.listEnvelopes();
  assert.equal(later.seen[0].headers.authorization, "Bearer eyJ.access.token");
  // An OAuth refusal is an error with the CS code.
  const bad = new OpenSeal({ baseUrl: REC.base_url, fetch: replay(t.refused).f });
  await assert.rejects(bad.token({ clientId: "c", clientSecret: "s", grant_type: "refresh_token", refresh_token: "osr_x" }),
    (e) => e.oauthError === "invalid_grant" && e.code === "CS-AUTH-0014");
});

test("webhooks: the Standard Webhooks example verifies; a changed body, an old timestamp or another secret does not", async () => {
  const w = REC.webhook;
  const event = await verifyWebhook(w.secret, w.headers, w.body, { now: w.now_ms });
  assert.deepEqual(event, { test: 2432232314 });
  await assert.rejects(verifyWebhook(w.secret, w.headers, w.body.replace("2432", "2433"), { now: w.now_ms }), (e) => e.code === "webhook_signature");
  await assert.rejects(verifyWebhook(w.secret, w.headers, w.body, { now: w.now_ms + 301_000 }), /webhook_signature/);
  await assert.rejects(verifyWebhook("whsec_c2Vjb25kLXNlY3JldC1mb3Itcm90YXRpb24=", w.headers, w.body, { now: w.now_ms }), /webhook_signature/);
  // During a rotation the header carries one signature per secret: either verifies.
  const rotated = { ...w.headers, "webhook-signature": `v1,AAAA ${w.headers["webhook-signature"]}` };
  assert.deepEqual(await verifyWebhook(w.secret, new Headers(rotated), new TextEncoder().encode(w.body), { now: w.now_ms }), { test: 2432232314 });
});
