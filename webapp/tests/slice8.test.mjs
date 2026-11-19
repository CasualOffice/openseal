// Slice 8, API and webhooks (VS-08A, VS-08B): the OAuth rules the Admin screen and the
// consent screen share with the server (`api/oauth.rs`), and the mock's consent flow the
// browser specs run against. Run: npm test (in webapp/).
import test from "node:test";
import assert from "node:assert/strict";

import { createMockFetch, MOCK } from "../mock.js";
import { createClient } from "../api.js";
import { redirectUriOk, parseRedirectUris, publicKeyProblem, authorizeParams } from "../adminmodel.js";

const CB = "https://app.example.test/callback";
const CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

test("redirect URIs are https or loopback http, without fragments or credentials, as the server says", () => {
  for (const ok of ["https://app.example.com/callback", "https://app.example.com:8443/cb?x=1", "http://localhost:8080/cb", "http://127.0.0.1/cb", "http://[::1]:9000/cb"]) {
    assert.equal(redirectUriOk(ok), true, ok);
  }
  for (const bad of ["", "http://app.example.com/cb", "https://app.example.com/cb#frag", "https://user@app.example.com/cb", "https:///cb", "javascript:alert(1)", "https://app.example.com/c b", "http://localhost.evil.example/cb"]) {
    assert.equal(redirectUriOk(bad), false, bad);
  }
  assert.deepEqual(parseRedirectUris(`${CB}\n\n http://localhost:3000/cb \n${CB}`), { uris: [CB, "http://localhost:3000/cb"] });
  assert.deepEqual(parseRedirectUris(`${CB}\nhttp://evil.example/cb`), { error: "bad", index: 1 });
  assert.equal(parseRedirectUris(Array.from({ length: 11 }, (_, i) => `${CB}/${i}`).join("\n")).error, "many");
});

test("a JWT integration's key is a public key; a private key never leaves the browser", () => {
  assert.equal(publicKeyProblem(""), "missing");
  assert.equal(publicKeyProblem("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----"), "private");
  assert.equal(publicKeyProblem("-----BEGIN EC PRIVATE KEY-----\nAAAA\n-----END EC PRIVATE KEY-----"), "private");
  assert.equal(publicKeyProblem("ssh-ed25519 AAAA"), "bad");
  assert.equal(publicKeyProblem("-----BEGIN PUBLIC KEY-----\nMFkw\n-----END PUBLIC KEY-----\n"), null);
});

test("the consent screen reads only the authorization request's own members", () => {
  const p = new URLSearchParams(`response_type=code&client_id=c1&redirect_uri=${encodeURIComponent(CB)}&scope=envelopes%3Aread&state=s&code_challenge=${CHALLENGE}&code_challenge_method=S256&evil=1`);
  assert.deepEqual(authorizeParams(p), {
    response_type: "code", client_id: "c1", redirect_uri: CB, scope: "envelopes:read", state: "s", code_challenge: CHALLENGE, code_challenge_method: "S256",
  });
  assert.equal(authorizeParams(new URLSearchParams("scope=x")), null);
});

test("the mock registers an OAuth app and a JWT integration, and answers consent as the server does", async () => {
  const c = createClient({ fetch: createMockFetch() });
  await c.login(MOCK.email, MOCK.password);
  await assert.rejects(c.apiClients.create({ name: "App", kind: "oauth_app", scopes: ["envelopes:read"], redirect_uris: ["http://app.example.test/cb"] }),
    (e) => e.errors?.[0]?.pointer === "/redirect_uris/0");
  await assert.rejects(c.apiClients.create({ name: "Jwt", kind: "jwt_integration", scopes: ["envelopes:read"], redirect_uris: [CB], public_key: "-----BEGIN PRIVATE KEY-----\nAA\n-----END PRIVATE KEY-----" }),
    (e) => e.errors?.[0]?.pointer === "/public_key");
  const app = await c.apiClients.create({ name: "Partner CRM", kind: "oauth_app", scopes: ["envelopes:read", "envelopes:write"], redirect_uris: [CB] });
  assert.ok(app.client_id && app.client_secret);
  assert.deepEqual(app.redirect_uris, [CB]);
  const jwt = await c.apiClients.create({ name: "Back office", kind: "jwt_integration", scopes: ["envelopes:read"], redirect_uris: [CB], public_key: "-----BEGIN PUBLIC KEY-----\nMFkw\n-----END PUBLIC KEY-----" });
  assert.equal(jwt.client_secret, undefined);
  assert.equal(jwt.has_public_key, true);

  const req = { response_type: "code", client_id: app.client_id, redirect_uri: CB, scope: "envelopes:read", state: "xyz", code_challenge: CHALLENGE, code_challenge_method: "S256" };
  const checked = await c.oauth.request(req);
  assert.equal(checked.client.name, "Partner CRM");
  assert.deepEqual(checked.scopes, ["envelopes:read"]);
  await assert.rejects(c.oauth.request({ ...req, redirect_uri: "https://evil.example/cb" }), (e) => e.errors?.[0]?.pointer === "/redirect_uri");
  await assert.rejects(c.oauth.request({ ...req, scope: "envelopes:send" }), (e) => e.errors?.[0]?.pointer === "/scope");

  const denied = new URL((await c.oauth.answer(req, "deny")).redirect_to);
  assert.equal(denied.searchParams.get("error"), "access_denied");
  assert.equal(denied.searchParams.get("state"), "xyz");
  assert.equal((await c.oauth.consents()).items.length, 0);
  const allowed = new URL((await c.oauth.answer(req, "allow")).redirect_to);
  assert.equal(`${allowed.origin}${allowed.pathname}`, CB);
  assert.ok(allowed.searchParams.get("code"));
  assert.equal(allowed.searchParams.get("state"), "xyz");
  const { items } = await c.oauth.consents();
  assert.equal(items.length, 1);
  assert.equal(items[0].client.name, "Partner CRM");
  await c.oauth.revoke(items[0].id);
  assert.equal((await c.oauth.consents()).items.length, 0);
});

// ---- Sandbox workspaces (ADR-041, VS-08D) ------------------------------------------------

test("a sandbox seal is named by its signer's subject, and only marks the report", async () => {
  const { summarize, isSandboxSigner } = await import("../verifyreport.js");
  assert.equal(isSandboxSigner("O=OpenSeal development,OU=Sandbox - not for agreements,CN=OpenSeal sandbox seal - not for agreements"), true);
  assert.equal(isSandboxSigner("O=OpenSeal development,CN=OpenSeal development seal"), false);
  assert.equal(isSandboxSigner(null), false);
  const sig = (signer) => ({ signer, indication: { indication: "TOTAL_PASSED" }, checks: {}, covers_whole_document: true });
  const sandbox = summarize({ ok: { signatures: [sig("CN=OpenSeal sandbox seal - not for agreements")] } });
  assert.equal(sandbox.sandbox, true);
  assert.equal(sandbox.state, "valid", "the mark never changes the verdict");
  assert.equal(sandbox.signatures[0].signer, "CN=OpenSeal sandbox seal - not for agreements");
  assert.equal(summarize({ ok: { signatures: [sig("CN=OpenSeal seal")] } }).sandbox, false);
});

test("the mock makes a sandbox workspace for good; in it the session says so and keys start osk_test_", async () => {
  const c = createClient({ fetch: createMockFetch() });
  await c.login(MOCK.email, MOCK.password);
  assert.equal((await c.session()).sandbox, false);
  const ws = await c.org.createWorkspace("Integration tests", { sandbox: true });
  assert.equal(ws.sandbox, true);
  assert.equal((await c.org.workspaces()).items.find((w) => w.id === ws.id).sandbox, true);
  await c.org.joinWorkspace(ws.id, "admin");
  await c.switchWorkspace(ws.id);
  assert.equal((await c.session()).sandbox, true);
  const key = await c.apiClients.create({ name: "CI", kind: "api_key", scopes: ["envelopes:read"] });
  assert.match(key.key, /^osk_test_/);
});
