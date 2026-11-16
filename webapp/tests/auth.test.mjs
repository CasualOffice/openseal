// Sign-in, reset and accept-invite rules (WEB-18 lane E, authmodel.js).
// Run: cd webapp && node --test tests/auth.test.mjs
import test from "node:test";
import assert from "node:assert/strict";

import { EN } from "../strings.en.js";
import { signInErrors, firstInvalid, resetError, inviteChecks, inviteError, inviteToken, usableProviders, signInFailure, MIN_PASSWORD, owedFactor, factorError, groupSecret } from "../authmodel.js";
import { createMockFetch, MOCK } from "../mock.js";
import { createClient } from "../api.js";

test("sign-in names a missing email and password, and a malformed email", () => {
  assert.deepEqual(signInErrors({}), { email: "signin.email-missing", password: "signin.password-missing" });
  assert.deepEqual(signInErrors({ email: "  ", password: "x" }), { email: "signin.email-missing", password: null });
  assert.deepEqual(signInErrors({ email: "dana", password: "x" }), { email: "signin.email-invalid", password: null });
  assert.deepEqual(signInErrors({ email: " dana@acme.example ", password: "x" }), { email: null, password: null });
});

test("the first invalid field follows reading order", () => {
  assert.equal(firstInvalid({ email: null, password: "k" }, ["email", "password"]), "password");
  assert.equal(firstInvalid({ email: "k", password: "k" }, ["email", "password"]), "email");
  assert.equal(firstInvalid({ email: null, password: null }, ["email", "password"]), null);
});

test("the reset form wants a real-looking address", () => {
  assert.equal(resetError(""), "signin.email-missing");
  assert.equal(resetError("nope"), "signin.email-invalid");
  assert.equal(resetError("a@b.co"), null);
});

test("the invitation checklist ticks length and match as the person types", () => {
  const short = "x".repeat(MIN_PASSWORD - 1);
  const long = "x".repeat(MIN_PASSWORD);
  assert.deepEqual(inviteChecks("", "").map((r) => r.met), [false, false]);
  assert.deepEqual(inviteChecks(short, short).map((r) => r.met), [false, true]);
  assert.deepEqual(inviteChecks(long, "").map((r) => r.met), [true, false], "an empty second field never counts as matching");
  assert.deepEqual(inviteChecks(long, long).map((r) => r.met), [true, true]);
});

test("the invitation form says length first, then mismatch", () => {
  assert.deepEqual(inviteError("short", "other"), { field: "password", key: "invite.password-help" });
  assert.deepEqual(inviteError("a-long-enough-password", "a-long-enough-passwor"), { field: "again", key: "invite.mismatch" });
  assert.equal(inviteError("a-long-enough-password", "a-long-enough-password"), null);
});

test("an invitation token is taken only when it has token characters", () => {
  assert.equal(inviteToken(new URLSearchParams("token=abc.DEF_1-~")), "abc.DEF_1-~");
  assert.equal(inviteToken(new URLSearchParams("token=<img>")), "");
  assert.equal(inviteToken(new URLSearchParams("token=")), "");
  assert.equal(inviteToken(null), "");
  assert.equal(inviteToken(new URLSearchParams(`token=${"a".repeat(513)}`)), "");
});

test("company sign-in links stay on this site", () => {
  const got = usableProviders([
    { url: "/api/v1/auth/sso/okta", name: " Okta " },
    { url: "//evil.example/sso", name: "Protocol-relative" },
    { url: "/\\evil.example/sso", name: "Backslash" },
    { url: "https://evil.example/sso", name: "Absolute" },
    { url: "/sso", name: "" },
    { url: "/sso/long", name: "N".repeat(200) },
    null,
  ]);
  assert.deepEqual(got.map((p) => p.url), ["/api/v1/auth/sso/okta", "/sso/long"]);
  assert.equal(got[0].name, "Okta");
  assert.equal(got[1].name.length, 80);
  assert.deepEqual(usableProviders("junk"), []);
});

test("only wrong credentials get the plain sentence", () => {
  assert.equal(signInFailure({ code: "CS-AUTH-0007" }), "signin.invalid");
  assert.equal(signInFailure({ code: "CS-API-0500" }), null);
  assert.equal(signInFailure(null), null);
});

test("every key the signed-out pages use has English text", () => {
  const keys = ["signin.email-invalid", "signin.show-password", "signin.show-title", "signin.hide-title",
    "signin.aside.title", "signin.aside.send", "signin.aside.sign", "signin.aside.verify",
    "invite.done-title", "invite.show-again", "invite.rule-length", "invite.rule-match", "invite.rule-met", "invite.rule-unmet",
    "invite.password-help", "invite.mismatch", ...inviteChecks().map((r) => r.key)];
  for (const k of keys) assert.ok(k in EN, `missing ${k}`);
});

// ---- Second factor (ASVS-01) -------------------------------------------------------------
test("the second-factor step reads what the session owes and checks the code's shape", () => {
  assert.equal(owedFactor({ second_factor: "verify" }), "verify");
  assert.equal(owedFactor({ second_factor: "enrol" }), "enrol");
  assert.equal(owedFactor({ second_factor: "passed" }), null);
  assert.equal(owedFactor({}), null);
  assert.equal(factorError("12 34 56"), null);
  assert.equal(factorError("12345"), "mfa.code-missing");
  assert.equal(factorError("abcdef"), "mfa.code-missing");
  assert.equal(factorError("", true), "mfa.recovery-missing");
  assert.equal(factorError("ABCDE-FGHIJ", true), null);
  assert.equal(groupSecret("JBSWY3DPEHPK3PXP"), "JBSW Y3DP EHPK 3PXP");
  for (const k of ["mfa.code-missing", "mfa.recovery-missing", "mfa.invalid", "error.CS-AUTH-0011", "error.CS-AUTH-0012"]) assert.ok(EN[k], k);
});

test("under a policy, an administrator enrols before anything else; codes and recovery codes work once (mock)", async () => {
  const c = createClient({ fetch: createMockFetch() });
  await c.login(MOCK.email, MOCK.password);
  await c.request("PATCH", "/api/v1/accounts/me", { body: { settings: { mfa_policy: "administrators" } } });
  assert.equal((await c.session()).second_factor, "enrol");
  await assert.rejects(c.account(), (e) => e.status === 403 && e.code === "CS-AUTH-0011" && e.detail === "enrol");
  const seed = await c.enrolTotp();
  assert.match(seed.otpauth_uri, /^otpauth:\/\/totp\//);
  await assert.rejects(c.confirmTotp("12345"), (e) => e.code === "CS-AUTH-0012");
  const done = await c.confirmTotp("111111");
  assert.equal(done.recovery_codes.length, 10);
  assert.equal((await c.session()).second_factor, "passed");
  await c.account();

  await c.login(MOCK.email, MOCK.password);
  assert.equal((await c.session()).second_factor, "verify");
  await assert.rejects(c.verifySecondFactor({ code: "111111" }), (e) => e.code === "CS-AUTH-0012");
  await c.verifySecondFactor({ code: "222222" });
  await c.account();

  await c.login(MOCK.email, MOCK.password);
  const r = await c.verifySecondFactor({ recovery_code: done.recovery_codes[0].toLowerCase() });
  assert.equal(r.recovery_codes_left, 9);
  await c.login(MOCK.email, MOCK.password);
  await assert.rejects(c.verifySecondFactor({ recovery_code: done.recovery_codes[0] }), (e) => e.code === "CS-AUTH-0012");
});

test("with no mfa_policy, the default asks an administrator to enrol (ASVS-31, mock)", async () => {
  const c = createClient({ fetch: createMockFetch() });
  await c.login(MOCK.email, MOCK.password);
  // The demo account opted out; removing the choice returns it to the default.
  assert.equal((await c.session()).second_factor, "none");
  await c.request("PATCH", "/api/v1/accounts/me", { body: { settings: { mfa_policy: null } } });
  await c.login(MOCK.email, MOCK.password);
  assert.equal((await c.session()).second_factor, "enrol");
  await assert.rejects(c.account(), (e) => e.status === 403 && e.code === "CS-AUTH-0011" && e.detail === "enrol");
});
