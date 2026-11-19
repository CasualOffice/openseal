// Slice 4, every field (VS-04A, VS-04C), the signer's side: each kind a signer fills,
// its check as the engine's (`casual-sign-fields` validate; the same examples as
// server/casual-sign-server/tests/every_field.rs), and the server's rules applied.
import { test } from "node:test";
import assert from "node:assert/strict";

import * as sf from "../signfields.js";
import { rulesFor, finishProblems } from "../fieldrules.js";
import { SIGN } from "../strings/sign.en.js";

const { fills, isFilled, checkText, inputModeFor, nextAction } = sf;

test("every engine kind that takes input but payment is filled by the signer", () => {
  for (const type of ["date", "email_address", "phone", "ssn", "zip", "multi_select", "stamp", "drawing"]) {
    assert.equal(fills({ type }), true, type);
  }
  for (const type of ["envelope_id", "formula", "hyperlink", "note", "approve", "decline", "date_signed", "payment"]) {
    assert.equal(fills({ type }), false, type);
  }
  assert.equal(isFilled({ type: "multi_select" }, { choices: [] }), false);
  assert.equal(isFilled({ type: "multi_select" }, { choices: ["Warranty"] }), true);
  assert.equal(isFilled({ type: "stamp" }, { signature: "ab" }), true);
  assert.equal(isFilled({ type: "ssn" }, { text: " " }), false);
});

test("each kind's implied rule refuses what the engine refuses and passes what it passes", () => {
  const bad = [
    [{ type: "date", format: { date_format: "dd_mm_yyyy" } }, "2026-13-45", "sign.check.date"],
    [{ type: "date", format: { date_format: "dd_mm_yyyy" } }, "31/02/2026", "sign.check.date"],
    [{ type: "date" }, "next week", "sign.check.date"],
    [{ type: "email_address" }, "not an address", "sign.check.email"],
    [{ type: "phone" }, "call me", "sign.check.phone"],
    [{ type: "ssn" }, "123-45-678", "sign.check.ssn"],
    [{ type: "ssn" }, "666-12-3456", "sign.check.ssn"],
    [{ type: "zip" }, "ABCDE", "sign.check.zip"],
    [{ type: "text", validation: { kind: "regex", pattern: "POL-[0-9]{4}" } }, "POL-12", "sign.check.pattern"],
    [{ type: "text", validation: { kind: "date", format: "d_mmm_yyyy" } }, "7 Smarch 2026", "sign.check.date"],
  ];
  for (const [f, v, key] of bad) assert.equal(checkText(f, v)?.key, key, `${f.type} ${v}`);
  const good = [
    [{ type: "date", format: { date_format: "dd_mm_yyyy" } }, "02/03/2026"],
    [{ type: "date" }, "2024-02-29"],
    [{ type: "email_address" }, "buyer@example.test"],
    [{ type: "phone" }, "+44 20 7946 0958"],
    [{ type: "ssn" }, "123-45-6789"],
    [{ type: "ssn" }, "123456789"],
    [{ type: "zip" }, "94105-1234"],
    [{ type: "text", validation: { kind: "regex", pattern: "POL-[0-9]{4}" } }, "POL-2026"],
    [{ type: "text", validation: { kind: "date", format: "d_mmm_yyyy" } }, "7 Mar 2026"],
  ];
  for (const [f, v] of good) assert.equal(checkText(f, v), null, `${f.type} ${v}`);
});

test("the sender's message replaces the default one, and an uncompilable pattern is left to the server", () => {
  const f = { type: "text", validation: { kind: "regex", pattern: "POL-[0-9]{4}", message: "POL- and four digits" } };
  assert.deepEqual(checkText(f, "x"), { key: "sign.check.custom", vars: { message: "POL- and four digits" } });
  assert.equal(checkText({ type: "text", validation: { kind: "regex", pattern: "(?P<y>\\d)" } }, "anything"), null);
});

test("phone keyboards open for the kind", () => {
  assert.equal(inputModeFor({ type: "ssn" }), "numeric");
  assert.equal(inputModeFor({ type: "date" }), "numeric");
  assert.equal(inputModeFor({ type: "date", format: { date_format: "d_mmm_yyyy" } }), "text");
  assert.equal(inputModeFor({ type: "email_address" }), "email");
  assert.equal(inputModeFor({ type: "phone" }), "tel");
});

test("the guide names a stamp, a drawing and a multi-select", () => {
  assert.equal(nextAction({ type: "stamp" }, "Seal").key, "sign.guide.stamp");
  assert.equal(nextAction({ type: "drawing" }, "Sketch").key, "sign.guide.draw");
  assert.equal(nextAction({ type: "multi_select" }, "Extras").key, "sign.guide.choose");
});

test("the server's rules: hidden, computed, mirrored", () => {
  const rules = { hidden: ["d"], computed: { t: { ok: "9.00" }, z: { error: "DivisionByZero" } }, values: { r2: { text: "R-77" } } };
  assert.equal(sf.isHidden({ id: "d" }, rules), true);
  assert.equal(sf.isHidden({ id: "x" }, rules), false);
  assert.equal(sf.isHidden({ id: "d" }, null), false);
  assert.deepEqual(sf.computedOf({ id: "t" }, rules), { text: "9.00" });
  assert.deepEqual(sf.computedOf({ id: "z" }, rules), { error: "DivisionByZero" });
  assert.equal(sf.computedOf({ id: "q" }, rules), null);
  assert.deepEqual(sf.effectiveValue({ id: "r2" }, null, rules), { text: "R-77" });
  assert.deepEqual(sf.effectiveValue({ id: "r2" }, { text: "mine" }, rules), { text: "mine" });
});

test("a hyperlink opens only http and https", () => {
  assert.equal(sf.safeHref("https://example.test/terms"), "https://example.test/terms");
  assert.equal(sf.safeHref("http://example.test"), "http://example.test/");
  for (const bad of ["javascript:alert(1)", "data:text/html,x", "file:///etc/passwd", "terms", ""]) assert.equal(sf.safeHref(bad), null, bad);
});

// The mock server's stand-in for the engine's rules (fieldrules.js): the same outcomes as
// server/casual-sign-server/tests/every_field.rs, so mock-mode browser runs see them.
test("the mock's rules: a condition hides, a formula computes, a label links, a group holds", () => {
  const r = "r1";
  const fields = [
    { id: "a", recipient_id: r, type: "checkbox", label: "agree" },
    { id: "d", recipient_id: r, type: "text", label: "detail", required: true, conditional: { parent_label: "agree", when: "checked" } },
    { id: "q", recipient_id: r, type: "number", label: "qty" },
    { id: "p", recipient_id: r, type: "number", label: "price" },
    { id: "t", recipient_id: r, type: "formula", label: "total", formula: { expression: "qty * price", precision: 2 } },
    { id: "r1f", recipient_id: r, type: "text", label: "ref" },
    { id: "r2f", recipient_id: r, type: "text", label: "ref" },
    { id: "o1", recipient_id: r, type: "checkbox", group: { id: "g", rule: { rule: "select_at_least", min: 1 } } },
    { id: "o2", recipient_id: r, type: "checkbox", group: { id: "g", rule: { rule: "select_at_least", min: 1 } } },
  ];
  let rules = rulesFor(fields, r);
  assert.deepEqual(rules.hidden, ["d"]);
  assert.deepEqual(rules.computed.t, { ok: "0.00" });
  assert.deepEqual(finishProblems(fields, r).map((x) => x.pointer), ["/fields/o1", "/fields/o2"]);
  const by = (id) => fields.find((f) => f.id === id);
  by("a").value = { checked: true };
  by("q").value = { text: "4" };
  by("p").value = { text: "2.25" };
  by("r1f").value = { text: "R-77" };
  by("o2").value = { checked: true };
  rules = rulesFor(fields, r);
  assert.deepEqual(rules.hidden, []);
  assert.deepEqual(rules.computed.t, { ok: "9.00" });
  assert.deepEqual(rules.values.r2f, { text: "R-77" });
  assert.deepEqual(finishProblems(fields, r).map((x) => x.pointer), ["/fields/d"]);
  by("t").formula.expression = "qty / (price - 2.25)";
  assert.deepEqual(rulesFor(fields, r).computed.t, { error: "DivisionByZero" });
});

test("the editor's logic: a condition, a checkbox group and a formula as the engine takes them", async () => {
  const { conditionFrom, groupFrom, formulaFrom, labelsFor } = await import("../fieldlogic.js");
  assert.equal(conditionFrom("", "checked"), null);
  assert.deepEqual(conditionFrom(" agree ", "checked"), { parent_label: "agree", when: "checked" });
  assert.deepEqual(conditionFrom("plan", "value", "Pro"), { parent_label: "plan", when: { value: "Pro" } });
  assert.equal(conditionFrom("plan", "value", ""), null);
  assert.deepEqual(conditionFrom("x", "bogus"), { parent_label: "x", when: "checked" });
  assert.equal(groupFrom("", "select_at_least", 1), null);
  assert.deepEqual(groupFrom("opts", "select_at_least", "2"), { id: "opts", rule: { rule: "select_at_least", min: 2 } });
  assert.deepEqual(groupFrom("opts", "select_at_most", "1"), { id: "opts", rule: { rule: "select_at_most", max: 1 } });
  assert.deepEqual(groupFrom("opts", "select_exactly", "x"), { id: "opts", rule: { rule: "select_exactly", count: 1 } });
  assert.equal(formulaFrom("  ", 2), null);
  assert.deepEqual(formulaFrom("qty * price", "2"), { expression: "qty * price", precision: 2 });
  assert.deepEqual(formulaFrom("a", "99"), { expression: "a", precision: 2 });
  assert.deepEqual(labelsFor([{ key: "a", label: "qty" }, { key: "b", label: "price" }, { key: "c", label: "qty" }, { key: "d" }], "b"), ["qty"]);
});

test("the editor places every kind, keeps the logic members and gives a multi-select options", async () => {
  const { takesInput, CHOICE, TYPED } = await import("../geometry.js");
  const { FIELD_SETTINGS } = await import("../templatesync.js");
  for (const ty of ["date", "email_address", "phone", "ssn", "zip", "multi_select", "stamp", "drawing"]) assert.equal(takesInput(ty), true, ty);
  assert.ok(CHOICE.has("multi_select"));
  for (const ty of ["date", "ssn", "zip"]) assert.ok(TYPED.has(ty), ty);
  for (const k of ["conditional", "group", "formula"]) assert.ok(FIELD_SETTINGS.includes(k), k);
});

test("every new signing string is in the strings table", () => {
  for (const k of ["sign.check.ssn", "sign.check.date", "sign.check.pattern", "sign.check.custom", "sign.guide.stamp", "sign.guide.draw",
    "sign.stamp.title", "sign.stamp.choose", "sign.stamp.here", "sign.draw.title", "sign.draw.here", "sign.draw.clear", "sign.adopt.use",
    "sign.multi.save", "sign.formula.error", "sign.approve", "sign.decline-field", "sign.link.opens", "sign.envelope-id"]) {
    assert.ok(typeof SIGN[k] === "string" && SIGN[k], k);
  }
});
