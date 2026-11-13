// The signer's field kinds (WEB-06): what is filled, and the inline checks, which
// follow casual-sign-fields `validate` (server/casual-sign-server/tests/field_types.rs
// uses the same examples).
import { test } from "node:test";
import assert from "node:assert/strict";

import { fills, isFilled, isFixed, checkText, isPhone, isZip, fixedText, inputModeFor, nextAction, guideState, ringDash, loaderSteps, pageCounts, pageTotal, filledKinds, firstName, nameParts, orgMark, askLine, dateField, phoneSegments, actedAs } from "../signfields.js";
import { SIGN } from "../strings/sign.en.js";

// ---- The ceremony's model (WEB-18) ---------------------------------------------------------

test("the guide bar: Start, then Next, then Finish once nothing required is left", () => {
  const sig = { type: "signature", p: { page: 1 } };
  const g0 = guideState({ total: 3, left: 3, started: false, next: sig });
  assert.deepEqual([g0.cta, g0.done, g0.total, g0.ready], ["start", 0, 3, false]);
  assert.deepEqual(g0.title, { key: "sign.guide.sign" });
  assert.deepEqual(g0.sub, { key: "sign.finish-reason", vars: { n: 3 } });
  const g1 = guideState({ total: 3, left: 1, started: true, next: { type: "initials", p: { page: 2 } } });
  assert.equal(g1.cta, "next");
  assert.deepEqual(g1.title, { key: "sign.guide.initial", vars: { n: 2 } });
  assert.deepEqual(g1.sub, { key: "sign.finish-reason-one", vars: { n: 1 } });
  const g2 = guideState({ total: 3, left: 0, started: true });
  assert.deepEqual([g2.cta, g2.ready, g2.fraction], ["finish", true, 1]);
  assert.deepEqual(g2.title, { key: "sign.guide.all-done" });
  // Nothing required: the ring is full and Finish shows at once.
  const g3 = guideState({ total: 0, left: 0, started: false });
  assert.deepEqual([g3.cta, g3.fraction, g3.title.key], ["finish", 1, "sign.guide.nothing"]);
  // A count out of range is clamped, never negative.
  assert.equal(guideState({ total: 2, left: 5, started: false }).done, 0);
});

test("the next action is worded by the field's kind", () => {
  assert.deepEqual(nextAction({ type: "checkbox" }, "Schedule A"), { key: "sign.guide.tick", vars: { label: "Schedule A" } });
  assert.deepEqual(nextAction({ type: "radio_group" }, "Plan"), { key: "sign.guide.choose", vars: { label: "Plan" } });
  assert.deepEqual(nextAction({ type: "attachment" }, "ID"), { key: "sign.guide.attach", vars: { label: "ID" } });
  assert.deepEqual(nextAction({ type: "company" }, "Company"), { key: "sign.guide.fill", vars: { label: "Company" } });
  assert.deepEqual(nextAction(null), { key: "sign.guide.all-done" });
});

test("the ring's dash is the share done of its circumference", () => {
  assert.equal(ringDash(0), "0.0 94.2");
  assert.equal(ringDash(1 / 3), "31.4 94.2");
  assert.equal(ringDash(1), "94.2 94.2");
  assert.equal(ringDash(7), "94.2 94.2");
  assert.equal(ringDash(Number.NaN), "0.0 94.2");
});

test("the loader ticks only real steps, and names pages only when it knows them", () => {
  const s = loaderSteps(1, 3);
  assert.deepEqual(s.map((x) => x.state), ["done", "active", "todo"]);
  assert.deepEqual(s.map((x) => x.key), ["sign.loader.link", "sign.loader.document", "sign.loader.pages"]);
  assert.deepEqual(s[2].vars, { n: 3 });
  assert.equal(loaderSteps(0, 1)[2].key, "sign.loader.page");
  assert.equal(loaderSteps(3, null)[2].key, "sign.loader.pages-unknown");
  assert.deepEqual(loaderSteps(3, 2).map((x) => x.state), ["done", "done", "done"]);
  // No step claims an integrity check.
  for (const st of loaderSteps(0, 2)) assert.doesNotMatch(st.key, /unchanged|verif(y|ied)-doc|hash/);
});

test("required fields left are counted per page; pages are totalled only when all are known", () => {
  const pages = [{ key: "d1", n: 1 }, { key: "d1", n: 2 }, { key: "d2", n: 1 }];
  const left = [{ document_id: "d1", p: { page: 1 } }, { document_id: "d1", p: { page: 1 } }, { document_id: "d2", p: { page: 1 } }];
  assert.deepEqual(pageCounts(pages, left), [2, 0, 1]);
  assert.equal(pageTotal([{ pages: 2 }, { pages: 3 }]), 5);
  assert.equal(pageTotal([{ pages: 2 }, {}]), null);
  assert.equal(pageTotal([]), null);
});

test("the header and the receipt: org mark, who asked, first name, kinds filled", () => {
  assert.equal(orgMark("Acme Corporation"), "AC");
  assert.equal(orgMark("Northwind"), "NO");
  assert.equal(orgMark("  "), "");
  assert.equal(orgMark("é-volution labs"), "ÉL");
  assert.deepEqual(askLine({ name: "Dana Admin", organisation: "Acme" }), { key: "sign.ask.org", vars: { name: "Dana Admin", org: "Acme" } });
  assert.deepEqual(askLine({ name: "Acme", organisation: "Acme" }), { key: "sign.ask", vars: { name: "Acme" } });
  assert.deepEqual(askLine({ email: "a@b.test" }), { key: "sign.ask", vars: { name: "a@b.test" } });
  assert.equal(askLine({}), null);
  assert.equal(askLine(null), null);
  assert.equal(firstName("Jordan  Rivera"), "Jordan");
  assert.equal(firstName(""), "");
  const fields = [{ type: "signature" }, { type: "text" }, { type: "signature" }, { type: "initials" }];
  assert.deepEqual(filledKinds(fields, (f) => f.type !== "text"), ["signature", "initials"]);
});

test("the date fills itself once signed; the phone header has two segments", () => {
  assert.deepEqual(dateField(false, "13 Nov 2026"), { key: "sign.date.pending" });
  assert.deepEqual(dateField(true, "13 Nov 2026"), { key: "sign.date.on", vars: { date: "13 Nov 2026" } });
  assert.deepEqual(phoneSegments(false, false), [false, false]);
  assert.deepEqual(phoneSegments(true, false), [true, false]);
  assert.deepEqual(phoneSegments(false, true), [true, true]);
});

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

test("a name splits into first and last as the server's engine fills them (FG-055)", () => {
  assert.deepEqual(nameParts("Ada Lovelace"), { first: "Ada", last: "Lovelace" });
  assert.deepEqual(nameParts(" Ludwig  van Beethoven "), { first: "Ludwig", last: "van Beethoven" });
  assert.deepEqual(nameParts("Plato"), { first: "Plato", last: "" });
  assert.deepEqual(nameParts(""), { first: "", last: "" });
  // The same whitespace as Rust's `char::is_whitespace`, so the page shows what is sealed:
  // U+0085 separates, U+FEFF (a JavaScript `\s`) does not.
  assert.deepEqual(nameParts("Ada\u0085Lovelace"), { first: "Ada", last: "Lovelace" });
  assert.deepEqual(nameParts("\uFEFFAda Lovelace\uFEFF"), { first: "\uFEFFAda", last: "Lovelace\uFEFF" });
  assert.deepEqual(nameParts("Ada\uFEFFLovelace"), { first: "Ada\uFEFFLovelace", last: "" });
});

// ---- RTE-02: the receipt says what the recipient did ---------------------------------------

test("the receipt says approved, viewed or finished, and signed only to a signing type", () => {
  assert.deepEqual(["approver", "viewer", "agent", "intermediary", "signer", "in_person_signer", "editor"].map(actedAs),
    ["approved", "viewed", "finished", "finished", "signed", "signed", "signed"]);
  for (const act of ["approved", "viewed", "finished"]) {
    for (const k of [`sign.review.legal.${act}`, `sign.receipt.${act}`, `sign.done.thanks.${act}`, `sign.done.thanks-anon.${act}`, `sign.done.already.${act}`]) {
      assert.ok(SIGN[k], k);
      assert.doesNotMatch(SIGN[k], /sign/i, k);
    }
  }
});
