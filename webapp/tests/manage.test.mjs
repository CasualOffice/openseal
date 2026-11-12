// The manage screens' pure rules (UX-07): action hierarchy per state, the Agreements
// address, "expiring soon", CSV export and the short list date.
import test from "node:test";
import assert from "node:assert/strict";

import { envelopeActions, rowActions, agreementsHash, expiringSoon, csvCell, toCsv, ENDED } from "../managemodel.js";
import { fmtShortDate } from "../dom.js";

test("every state has one primary; declined, voided and expired copy and resend, and download as ended", () => {
  for (const s of ["draft", "sent", "delivered", "completed", "declined", "voided", "expired"]) {
    assert.ok(envelopeActions(s).primary, `${s} has a primary action`);
  }
  for (const s of ENDED) {
    const a = envelopeActions(s);
    assert.equal(a.primary, "copy-resend");
    assert.equal(a.secondary, "download-ended");
    assert.deepEqual(a.more.at(-1), ["delete"], `${s}: delete is last, alone`);
    assert.ok(!a.more.flat().includes("certificate"), `${s}: no certificate until the server serves it`);
    assert.ok(envelopeActions(s, { cert: true }).more.flat().includes("certificate"));
  }
  assert.deepEqual(envelopeActions("sent").more.at(-1), ["void"], "void is last, in More, never a top-level button");
  assert.equal(envelopeActions("completed").primary, "download");
  assert.equal(envelopeActions("completed").secondary, "certificate");
});

test("the row menu groups actions and puts destructive ones last", () => {
  assert.deepEqual(rowActions("sent"), [["open"], ["correct", "resend", "download-current"], ["copy", "template", "history"], ["void"]]);
  assert.deepEqual(rowActions("declined"), [["open"], ["copy-resend", "download-ended"], ["template", "history"], ["delete"]]);
  assert.deepEqual(rowActions("draft"), [["edit"], ["copy", "template"], ["delete"]]);
  assert.deepEqual(rowActions("completed"), [["open"], ["download", "certificate"], ["copy", "template", "history"]]);
  for (const s of ["draft", "sent", "delivered", "completed", "declined", "voided", "expired"]) {
    assert.ok(rowActions(s).flat().every((a, i, all) => all.indexOf(a) === i), `${s}: no action twice`);
  }
});

test("the Agreements address carries the folder and the search", () => {
  assert.equal(agreementsHash(), "#/agreements");
  assert.equal(agreementsHash("all", ""), "#/agreements");
  assert.equal(agreementsHash("waiting", "offer"), "#/agreements?folder=waiting&q=offer");
  assert.equal(agreementsHash("all", "a&b c"), "#/agreements?q=a%26b+c");
  assert.equal(new URLSearchParams(agreementsHash("all", "a&b c").split("?")[1]).get("q"), "a&b c");
});

test("expiring soon: within seven days and not yet passed", () => {
  const now = Date.parse("2026-11-12T12:00:00Z");
  assert.equal(expiringSoon("2026-11-15T12:00:00Z", now), true);
  assert.equal(expiringSoon("2026-11-19T12:00:00Z", now), true);
  assert.equal(expiringSoon("2026-11-19T12:00:01Z", now), false);
  assert.equal(expiringSoon("2026-11-12T11:59:59Z", now), false);
  assert.equal(expiringSoon(null, now), false);
  assert.equal(expiringSoon("not a date", now), false);
});

test("CSV cells are quoted when needed and never run as formulas", () => {
  assert.equal(csvCell("plain"), "plain");
  assert.equal(csvCell("a,b"), '"a,b"');
  assert.equal(csvCell('say "hi"'), '"say ""hi"""');
  assert.equal(csvCell("=HYPERLINK(\"x\")"), "\"'=HYPERLINK(\"\"x\"\")\"");
  assert.equal(csvCell("+1"), "'+1");
  assert.equal(csvCell("@cmd"), "'@cmd");
  assert.equal(csvCell(null), "");
  assert.equal(toCsv([["a", "b"], ["c", "d,e"]]), 'a,b\r\nc,"d,e"\r\n');
});

test("the short list date: today, yesterday, this year, another year", () => {
  const now = new Date(2026, 10, 12, 18, 0).getTime();
  const labels = { today: "Today", yesterday: "Yesterday" };
  assert.match(fmtShortDate(new Date(2026, 10, 12, 9, 5).toISOString(), labels, now), /^Today, /);
  assert.match(fmtShortDate(new Date(2026, 10, 11, 23, 59).toISOString(), labels, now), /^Yesterday, /);
  const thisYear = fmtShortDate(new Date(2026, 2, 3, 10, 0).toISOString(), labels, now);
  assert.doesNotMatch(thisYear, /2026|Today|Yesterday/);
  assert.match(fmtShortDate(new Date(2025, 2, 3, 10, 0).toISOString(), labels, now), /2025/);
  assert.equal(fmtShortDate("", labels, now), "");
  assert.equal(fmtShortDate("nope", labels, now), "");
});
