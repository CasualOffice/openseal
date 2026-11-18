// Staff passkeys in the browser (CON-13): passkey.js's conversions between the server's
// base64url options and the browser's ArrayBuffers, the bodies it sends, the words for a
// ceremony that failed, and the mock behaving as the server does (a passkey as the first
// factor, the sign-in step, step-up, rename and remove, a spent challenge refused).
// A software authenticator stands in for `navigator.credentials` (Node's WebCrypto key).
// Run: cd webapp && node --test tests/passkey.test.mjs
import test from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";

import { EN } from "../strings.en.js";
import {
  toB64url, fromB64url, creationOptions, requestOptions, registrationBody, assertionBody,
  hasPasskey, canAddPasskey, ceremonyError, createPasskey, getPasskey,
} from "../passkey.js";
import { createMockFetch, MOCK } from "../mock.js";
import { createClient, ApiError } from "../api.js";

const enc = new TextEncoder();

/// A software authenticator behind a `navigator`-shaped object: one P-256 credential,
/// answering create and get with what a browser gives (client data, authenticator data,
/// the SPKI from `getPublicKey()`, a DER signature is not needed by the mock).
async function softNavigator() {
  const key = await webcrypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const spki = new Uint8Array(await webcrypto.subtle.exportKey("spki", key.publicKey));
  const rawId = new Uint8Array(16).fill(7);
  const seen = { create: null, get: null };
  const clientData = (type, challenge) => enc.encode(JSON.stringify({ type, challenge: toB64url(challenge), origin: "https://sign.example.test" }));
  const authData = new Uint8Array(37).fill(1);
  return {
    seen,
    credentials: {
      async create({ publicKey }) {
        seen.create = publicKey;
        return {
          rawId: rawId.buffer,
          response: {
            clientDataJSON: clientData("webauthn.create", publicKey.challenge).buffer,
            getAuthenticatorData: () => authData.buffer,
            getPublicKey: () => spki.buffer,
            getPublicKeyAlgorithm: () => -7,
            getTransports: () => ["internal"],
          },
        };
      },
      async get({ publicKey }) {
        seen.get = publicKey;
        const cd = clientData("webauthn.get", publicKey.challenge);
        const sig = new Uint8Array(await webcrypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key.privateKey, cd));
        return { rawId: rawId.buffer, response: { clientDataJSON: cd.buffer, authenticatorData: authData.buffer, signature: sig.buffer, userHandle: null } };
      },
    },
  };
}

test("base64url round-trips bytes, padding tolerated, and refuses anything else", () => {
  const bytes = new Uint8Array([0, 1, 250, 251, 252, 253, 254, 255]);
  const s = toB64url(bytes);
  assert.match(s, /^[A-Za-z0-9_-]+$/);
  assert.deepEqual(fromB64url(s), bytes);
  assert.deepEqual(fromB64url(`${s}=`), bytes);
  assert.throws(() => fromB64url("a+b/"), TypeError);
});

test("the server's options become what the browser takes, binary members as bytes", () => {
  const c = creationOptions({ challenge: toB64url([1, 2, 3]), user: { id: toB64url([9]), name: "a@b", displayName: "A" }, rp: { id: "x" }, excludeCredentials: [{ type: "public-key", id: toB64url([5]), transports: ["usb"] }] });
  assert.deepEqual(c.challenge, new Uint8Array([1, 2, 3]));
  assert.deepEqual(c.user.id, new Uint8Array([9]));
  assert.equal(c.user.name, "a@b");
  assert.deepEqual(c.excludeCredentials[0], { type: "public-key", id: new Uint8Array([5]), transports: ["usb"] });
  const r = requestOptions({ challenge: toB64url([4]), rpId: "x", allowCredentials: [{ type: "public-key", id: toB64url([6]), transports: [] }] });
  assert.deepEqual(r.allowCredentials[0], { type: "public-key", id: new Uint8Array([6]) });
  assert.equal(r.rpId, "x");
});

test("a browser without getPublicKey() is said to be unsupported, not sent half a body", () => {
  const cred = { rawId: new Uint8Array([1]).buffer, response: { clientDataJSON: new Uint8Array([1]).buffer, getAuthenticatorData: () => new Uint8Array([1]).buffer, getPublicKeyAlgorithm: () => -7 } };
  assert.throws(() => registrationBody(cred, "x"), (e) => ceremonyError(e) === "passkey.unsupported");
  assert.equal(ceremonyError({ name: "NotAllowedError" }), "passkey.cancelled");
  assert.equal(ceremonyError({ name: "InvalidStateError" }), "passkey.already");
  assert.equal(ceremonyError(new ApiError({ code: "CS-AUTH-0012" })), null);
  for (const k of ["passkey.cancelled", "passkey.already", "passkey.unsupported", "passkey.refused"]) assert.ok(EN[k], k);
});

test("the session says whether a passkey is held and may be added", () => {
  assert.equal(hasPasskey({ factors: { passkeys: 2 } }), true);
  assert.equal(hasPasskey({ factors: { passkeys: 0 } }), false);
  assert.equal(hasPasskey(null), false);
  const win = { PublicKeyCredential: function () {}, navigator: { credentials: { create() {} } }, isSecureContext: true };
  assert.equal(canAddPasskey({ factors: { passkeys_available: true } }, win), true);
  assert.equal(canAddPasskey({ factors: { passkeys_available: false } }, win), false);
  assert.equal(canAddPasskey({}, { navigator: {} }), false);
});

test("a passkey registers, passes the sign-in step and step-up, and is renamed and removed (mock)", async () => {
  let at = Date.parse("2026-11-19T09:00:00Z");
  const fetch = createMockFetch({ now: () => new Date(at) });
  const c = createClient({ fetch });
  await c.login(MOCK.email, MOCK.password);
  const nav = await softNavigator();
  const done = await createPasskey(c, "Laptop", nav);
  assert.equal(done.passkey.name, "Laptop");
  assert.equal(done.recovery_codes.length, 10, "the first factor shows recovery codes once");
  // What the browser was asked for, and what reached the server.
  assert.equal(nav.seen.create.attestation, "none");
  assert.ok(nav.seen.create.challenge instanceof Uint8Array && nav.seen.create.challenge.length === 32);
  let s = await c.session();
  assert.equal(s.second_factor, "passed");
  assert.equal(s.factors.passkeys, 1);

  // A new sign-in owes the factor; the passkey passes it.
  await c.logout();
  await c.login(MOCK.email, MOCK.password);
  assert.equal((await c.session()).second_factor, "verify");
  const answer = await getPasskey(c, "verify", nav);
  assert.equal(answer.credential_id, toB64url(new Uint8Array(16).fill(7)));
  assert.ok(nav.seen.get.allowCredentials.length === 1);
  await c.verifySecondFactor({ passkey: answer });
  assert.equal((await c.session()).second_factor, "passed");
  // The same answer again: its challenge is spent.
  await assert.rejects(c.verifySecondFactor({ passkey: answer }), (e) => e.code === "CS-AUTH-0012");

  // Six minutes on, renaming asks for step-up: the password and the passkey.
  at += 6 * 60_000;
  const id = (await c.passkeys()).items[0].id;
  let asked = 0;
  c.setStepUp(async () => {
    asked += 1;
    await c.reauthenticate({ password: MOCK.password, passkey: await getPasskey(c, "reauthenticate", nav) });
    return true;
  });
  const renamed = await c.renamePasskey(id, "Work laptop");
  assert.equal(renamed.name, "Work laptop");
  assert.equal(asked, 1);
  // The password alone does not re-authenticate a person with a passkey.
  await assert.rejects(c.reauthenticate({ password: MOCK.password }), (e) => e.code === "CS-API-0001");
  await c.removePasskey(id);
  s = await c.session();
  assert.equal(s.factors.passkeys, 0);
  assert.equal(s.factors.recovery_codes_left, 0, "the codes went with the last factor");
});
