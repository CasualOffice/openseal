// Sign-in, reset and accept-invite rules (WEB-18 lane E, authmodel.js).
// Run: cd webapp && node --test tests/auth.test.mjs
import test from "node:test";
import assert from "node:assert/strict";

import { EN } from "../strings.en.js";
import { signInErrors, firstInvalid, resetError, inviteChecks, inviteError, inviteToken, usableProviders, signInFailure, MIN_PASSWORD } from "../authmodel.js";

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
