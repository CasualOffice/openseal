// Password strength indication (ASVS 2.1.8, ASVS-03): pwstrength.js's estimate.
import test from "node:test";
import assert from "node:assert/strict";
import { passwordStrength } from "../pwstrength.js";
import { EN as STRINGS } from "../strings.en.js";

const score = (pw, inputs) => passwordStrength(pw, inputs).score;

test("nothing typed shows nothing", () => {
  assert.deepEqual(passwordStrength(""), { score: null, bits: 0, label: null, hints: [] });
});

test("the obvious twelve-character passwords the server takes score very weak", () => {
  // Each is long enough for the server (12 characters); the meter still warns.
  for (const pw of ["password1234", "P@ssw0rd2024", "aaaaaaaaaaaa", "abcdefghijkl", "123456789012", "qwertyuiop12"]) {
    assert.equal(score(pw), 0, pw);
  }
});

test("random characters and long uncommon passphrases score strong", () => {
  for (const pw of ["kdjf8wq2mzlp", "Tr7#kq9!Lm2$vX", "xkcd-mule-orbit-tango-lamp"]) {
    assert.equal(score(pw), 4, pw);
  }
});

test("more length and fewer patterns never score lower", () => {
  assert.ok(score("Summer2024!!") < score("Summer2024!!kq7Lmz"));
  assert.ok(score("correct horse battery staple") < score("cobalt heron basalt stipple"));
});

test("the person's own name or email counts as a guess", () => {
  const inputs = ["ada.lovelace@example.com", "Ada Lovelace"];
  assert.ok(score("ada.lovelace1815", inputs) < score("ada.lovelace1815"));
  assert.ok(passwordStrength("ada.lovelace1815", inputs).hints.includes("pwstrength.hint-personal"));
});

test("advice names what was found, at most two pieces, none for a strong password", () => {
  assert.deepEqual(passwordStrength("password1234").hints, ["pwstrength.hint-common", "pwstrength.hint-sequence"]);
  assert.deepEqual(passwordStrength("aaaaaaaaaaaa").hints, ["pwstrength.hint-repeat", "pwstrength.hint-longer"]);
  assert.ok(passwordStrength("Summer2024!!").hints.includes("pwstrength.hint-year"));
  assert.deepEqual(passwordStrength("Tr7#kq9!Lm2$vX").hints, []);
  for (const pw of ["password1234", "P@ssw0rd2024", "Summer2024!!", "abcdefghijkl", "zxcvbnm,./123", "ada.lovelace1815"]) {
    assert.ok(passwordStrength(pw, ["ada@example.com"]).hints.length <= 2, pw);
  }
});

test("every label and advice key has an English string", () => {
  const keys = new Set(["pwstrength.0", "pwstrength.1", "pwstrength.2", "pwstrength.3", "pwstrength.4", "pwstrength.label"]);
  for (const pw of ["password1234", "Summer2024!!", "ada.lovelace1815", "abcdefghijkl", "aaaaaaaaaaaa", "kdjf8wq2mzlp", "qwerty", "zz"]) {
    for (const k of passwordStrength(pw, ["ada@example.com"]).hints) keys.add(k);
  }
  for (const k of ["pwstrength.hint-mix", "pwstrength.hint-personal"]) keys.add(k);
  for (const k of keys) assert.ok(typeof STRINGS[k] === "string" && STRINGS[k], k);
});

test("a hostile or very long input stays bounded and never throws", () => {
  const long = "a".repeat(256) + "\u{1F600}".repeat(64) + "<script>";
  const s = passwordStrength(long, [null, undefined, 42, "x".repeat(10_000)]);
  assert.ok(Number.isInteger(s.score) && s.score >= 0 && s.score <= 4);
});
