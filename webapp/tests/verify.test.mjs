// The Verify page's presentation rules (WEB-18 lane E, verifyreport.js): stages, tones,
// tallies and sizes. None may add a check or upgrade a verdict.
// Run: cd webapp && node --test tests/verify.test.mjs
import test from "node:test";
import assert from "node:assert/strict";

import { EN } from "../strings.en.js";
import { summarize, STEPS, stepStates, verdictTone, checkTone, tally, fileSize, CHECKS } from "../verifyreport.js";

const sig = (indication, checks = {}) => ({ indication: { indication }, checks });

test("the scanning stages are the three the page really runs, ticked in order", () => {
  assert.deepEqual(STEPS, ["read", "verify", "trail"]);
  assert.deepEqual(stepStates("read").map((s) => s.state), ["active", "todo", "todo"]);
  assert.deepEqual(stepStates("verify").map((s) => s.state), ["done", "active", "todo"]);
  assert.deepEqual(stepStates("trail").map((s) => s.state), ["done", "done", "active"]);
  assert.deepEqual(stepStates("done").map((s) => s.state), ["done", "done", "done"]);
  for (const id of STEPS) assert.ok(`verify.step.${id}` in EN);
});

test("only a valid report gets the green seal", () => {
  assert.equal(verdictTone("valid"), "ok");
  assert.equal(verdictTone("invalid"), "bad");
  assert.equal(verdictTone("error"), "bad");
  assert.equal(verdictTone("indeterminate"), "warn");
  assert.equal(verdictTone("unsigned"), "warn");
  assert.equal(verdictTone("anything else"), "warn");
});

test("a check is green only when the verifier says passed", () => {
  assert.equal(checkTone("passed"), "ok");
  assert.equal(checkTone("failed"), "bad");
  assert.equal(checkTone("not_run"), "none");
  assert.equal(checkTone(undefined), "none");
});

test("the checks shown are the verifier's, in its order, with its status", () => {
  const r = summarize({ ok: { signatures: [sig("TOTAL_PASSED", { digest: { status: "passed" }, chain: { status: "failed", sub_indication: "NO_CERTIFICATE_CHAIN_FOUND", code: "CS-VER-0001" }, bogus: { status: "passed" } })] } });
  const checks = r.signatures[0].checks;
  assert.deepEqual(checks.map((c) => c.name), CHECKS, "no invented check, none dropped");
  assert.equal(checks.find((c) => c.name === "digest").status, "passed");
  assert.equal(checks.find((c) => c.name === "chain").status, "failed");
  assert.equal(checks.find((c) => c.name === "byte_range").status, "not_run", "a check the verifier did not report is not run, never passed");
  for (const c of CHECKS) assert.ok(`verify.check.${c}` in EN);
});

test("the tally counts the verifier's verdicts", () => {
  const r = summarize({ ok: { signatures: [sig("TOTAL_PASSED"), sig("TOTAL_FAILED"), sig("INDETERMINATE"), sig("TOTAL_PASSED")] } });
  assert.deepEqual(tally(r.signatures), { valid: 2, invalid: 1, indeterminate: 1 });
  assert.deepEqual(tally(null), { valid: 0, invalid: 0, indeterminate: 0 });
  assert.deepEqual(tally([{ verdict: "toString" }, { verdict: "__proto__" }]), { valid: 0, invalid: 0, indeterminate: 0 });
});

test("file sizes read as KB under a megabyte, MB above", () => {
  assert.deepEqual(fileSize(10), { key: "verify.size-kb", n: 1 });
  assert.deepEqual(fileSize(300 * 1024), { key: "verify.size-kb", n: 300 });
  assert.deepEqual(fileSize(2.25 * 1024 * 1024), { key: "verify.size-mb", n: 2.3 });
  assert.deepEqual(fileSize(-5), { key: "verify.size-kb", n: 1 });
  assert.ok("verify.size-kb" in EN && "verify.size-mb" in EN);
});
