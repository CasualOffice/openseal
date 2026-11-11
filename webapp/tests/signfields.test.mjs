// The signer's field kinds (WEB-06): what is filled, and the inline checks, which
// follow casual-sign-fields `validate` (server/casual-sign-server/tests/field_types.rs
// uses the same examples).
import { test } from "node:test";
import assert from "node:assert/strict";

import { fills, isFilled, isFixed, checkText, isPhone, isZip, fixedText, inputModeFor } from "../signfields.js";

test("locked, read-only and note fields are shown, not filled", () => {
  assert.equal(fills({ type: "note", value: { text: "x" } }), false);
  assert.equal(fills({ type: "text", locked: true }), false);
  assert.equal(fills({ type: "company", read_only: true }), false);
  assert.equal(isFixed({ type: "note" }), true);
  assert.equal(fixedText({ type: "text", value: { text: "PO-7781" }, locked: true }), "PO-7781");
  for (const type of ["company", "title", "number", "radio_group", "dropdown", "attachment", "text", "checkbox", "signature", "initials"]) assert.equal(fills({ type }), true, type);
  for (const type of ["date_signed", "name", "email"]) assert.equal(fills({ type }), false, type);
});

test("what counts as filled, per kind", () => {
  assert.equal(isFilled({ type: "company" }, { text: "  " }), false);
  assert.equal(isFilled({ type: "company" }, { text: "Acme" }), true);
  assert.equal(isFilled({ type: "radio_group" }, { choice: "" }), false);
  assert.equal(isFilled({ type: "dropdown" }, { choice: "Pro" }), true);
  assert.equal(isFilled({ type: "attachment" }, { attachment: "ab".repeat(32) }), true);
  assert.equal(isFilled({ type: "checkbox", required: true }, { checked: false }), false);
  assert.equal(isFilled({ type: "signature" }, null), false);
});

test("text presets refuse what the engine refuses and pass what it passes", () => {
  const mail = { type: "text", validation: { kind: "email" } };
  assert.ok(checkText(mail, "not an address"));
  assert.equal(checkText(mail, "a@example.test"), null);
  const tel = { type: "text", validation: { kind: "phone" } };
  assert.ok(checkText(tel, "call me"));
  assert.equal(checkText(tel, "+1 555 123 4567"), null);
  assert.equal(isPhone("(555) 123-4567"), true);
  assert.equal(isPhone("12345"), false);
  const zip = { type: "text", validation: { kind: "zip" } };
  assert.ok(checkText(zip, "ABCDE"));
  assert.equal(checkText(zip, "94105"), null);
  assert.equal(isZip("94105-1234"), true);
  assert.equal(isZip("9410"), false);
  const code = { type: "text", validation: { kind: "length", max: 5 } };
  assert.deepEqual(checkText(code, "TOOLONG"), { key: "sign.check.max-length", vars: { n: 5 } });
  assert.equal(checkText(code, "AB12"), null);
  assert.equal(checkText(mail, ""), null, "empty is required's business");
});

test("numbers: a number, whole when decimals is 0, within min and max", () => {
  const qty = { type: "number", validation: { kind: "number", min: "1", max: "100", decimals: 0 } };
  assert.deepEqual(checkText(qty, "500"), { key: "sign.check.between", vars: { min: "1", max: "100" } });
  assert.deepEqual(checkText(qty, "2.5"), { key: "sign.check.whole" });
  assert.deepEqual(checkText(qty, "lots"), { key: "sign.check.number" });
  assert.equal(checkText(qty, "42"), null);
  assert.deepEqual(checkText({ type: "number" }, "x"), { key: "sign.check.number" }, "a number field needs a number without a rule");
  assert.equal(inputModeFor(qty), "numeric");
  assert.equal(inputModeFor({ type: "text", validation: { kind: "email" } }), "email");
});
