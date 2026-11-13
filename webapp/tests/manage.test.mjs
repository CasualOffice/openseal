// The manage screens' pure rules (UX-07): action hierarchy per state, the Agreements
// address, "expiring soon", CSV export and the short list date.
import test from "node:test";
import assert from "node:assert/strict";

import {
  envelopeActions, rowActions, agreementsHash, expiringSoon, csvCell, toCsv, ENDED,
  viewFrom, groupOf, toneOf, pillOf, inView, viewCounts, groupRows, flatIds, moveSelection, signingProgress, primaryVerb,
  relativeWhen, recipientBadge, piiSummary, auditLinks, documentFingerprint, groupHex,
} from "../managemodel.js";
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

// ---- WEB-17 Agreements list and inspector ------------------------------------------------

const NOW = Date.parse("2026-11-12T12:00:00Z");
const ROWS = [
  { id: "inbox", status: "sent", updated_at: "2026-11-12T09:00:00Z", expires_at: "2026-11-14T00:00:00Z" },
  { id: "wait", status: "delivered", updated_at: "2026-11-12T10:00:00Z", expires_at: "2026-12-30T00:00:00Z" },
  { id: "soon", status: "sent", updated_at: "2026-11-10T10:00:00Z", expires_at: "2026-11-15T00:00:00Z" },
  { id: "done", status: "completed", updated_at: "2026-11-10T11:00:00Z" },
  { id: "draft", status: "draft", updated_at: "2026-11-09T11:00:00Z" },
  { id: "declined", status: "declined", updated_at: "2026-11-08T11:00:00Z" },
  { id: "voided", status: "voided", updated_at: "2026-11-07T11:00:00Z" },
];
const MINE = new Set(["inbox"]);

test("views: the address names one, older ?status= addresses still open the right one", () => {
  assert.equal(viewFrom(new URLSearchParams("folder=expiring")), "expiring");
  assert.equal(viewFrom(new URLSearchParams("folder=nope")), "all");
  assert.equal(viewFrom(new URLSearchParams("status=sent")), "waiting");
  assert.equal(viewFrom(new URLSearchParams("status=voided")), "voided");
  assert.equal(viewFrom(null), "all");
});

test("an envelope waiting for my signature is in Needs me, not Waiting, whatever its status", () => {
  assert.equal(groupOf(ROWS[0], MINE), "you");
  assert.equal(groupOf(ROWS[0]), "wait");
  assert.equal(inView(ROWS[0], "me", MINE, NOW), true);
  assert.equal(inView(ROWS[0], "waiting", MINE, NOW), false);
  assert.equal(toneOf(ROWS[5]), "danger");
  assert.equal(toneOf(ROWS[6]), "draft");
});

test("Declined, Voided and Expired pills are three different states, none a draft's (UX-02)", () => {
  const pill = (status) => pillOf({ id: "x", status });
  assert.deepEqual(pill("declined"), { tone: "declined", ic: "circle-x" });
  assert.deepEqual(pill("voided"), { tone: "voided", ic: "ban" });
  assert.deepEqual(pill("expired"), { tone: "expired", ic: "clock" });
  assert.equal(new Set(["declined", "voided", "expired", "draft"].map((s) => pill(s).tone)).size, 4);
  assert.deepEqual(pill("completed"), { tone: toneOf({ status: "completed" }), ic: null });
  // Waiting for my signature wins over the status.
  assert.equal(pillOf({ id: "x", status: "sent" }, new Set(["x"])).tone, toneOf({ id: "x", status: "sent" }, new Set(["x"])));
});

test("view counts: Expiring is within seven days and still open; Declined or expired keeps both", () => {
  const c = viewCounts(ROWS, MINE, NOW);
  assert.deepEqual([c.all, c.me, c.waiting, c.completed, c.drafts, c.expiring, c.action, c.voided], [7, 1, 2, 1, 1, 2, 1, 1]);
});

test("grouped rows: in group order, newest change first, empty groups left out", () => {
  const g = groupRows(ROWS, "all", MINE, { now: NOW });
  assert.deepEqual(g.map((x) => x.group), ["you", "wait", "done", "draft", "ended"]);
  assert.deepEqual(g[1].items.map((r) => r.id), ["wait", "soon"]);
  assert.deepEqual(flatIds(g), ["inbox", "wait", "soon", "done", "draft", "declined", "voided"]);
  assert.deepEqual(groupRows(ROWS, "expiring", MINE, { now: NOW }).map((x) => x.group), ["you", "wait"]);
  assert.deepEqual(groupRows([], "expiring", MINE, { now: NOW }), []);
});

test("arrow keys move the selection and stop at the ends", () => {
  const ids = ["a", "b", "c"];
  assert.equal(moveSelection(ids, "a", "ArrowDown"), "b");
  assert.equal(moveSelection(ids, "c", "ArrowDown"), "c");
  assert.equal(moveSelection(ids, "a", "ArrowUp"), "a");
  assert.equal(moveSelection(ids, "b", "End"), "c");
  assert.equal(moveSelection(ids, "b", "Home"), "a");
  assert.equal(moveSelection(ids, "gone", "ArrowDown"), "a");
  assert.equal(moveSelection([], "a", "ArrowDown"), null);
});

test("progress counts those who sign or approve, not copies", () => {
  const env = { recipients: [{ type: "signer", status: "completed" }, { type: "approver", status: "sent" }, { type: "cc", status: "created" }] };
  assert.deepEqual(signingProgress(env), { signed: 1, total: 2 });
  assert.equal(signingProgress(null), null);
});

test("the inspector's primary action follows the state and who it waits for", () => {
  assert.equal(primaryVerb("sent", true), "sign");
  assert.equal(primaryVerb("delivered"), "remind");
  assert.equal(primaryVerb("completed"), "download");
  assert.equal(primaryVerb("draft"), "edit");
  assert.equal(primaryVerb("voided"), "copy-resend");
  assert.equal(primaryVerb("completing"), null);
});

test("relative times: minutes, hours, today, yesterday, this year, another year", () => {
  const now = new Date(2026, 10, 12, 18, 0).getTime();
  assert.equal(relativeWhen(new Date(now - 20_000).toISOString(), now).kind, "now");
  assert.deepEqual(relativeWhen(new Date(now - 5 * 60_000).toISOString(), now), { kind: "min", n: 5 });
  assert.deepEqual(relativeWhen(new Date(now - 2 * 3_600_000).toISOString(), now), { kind: "hours", n: 2 });
  assert.equal(relativeWhen(new Date(2026, 10, 12, 9, 0).toISOString(), now).kind, "time");
  assert.equal(relativeWhen(new Date(2026, 10, 11, 23, 0).toISOString(), now).kind, "yesterday");
  assert.equal(relativeWhen(new Date(2026, 1, 3).toISOString(), now).kind, "date");
  assert.equal(relativeWhen(new Date(2025, 1, 3).toISOString(), now).kind, "year");
  assert.equal(relativeWhen("", now).kind, "none");
});

test("recipient badges: signed, declined, my turn, their turn, not yet, a copy", () => {
  assert.deepEqual(recipientBadge({ type: "signer", status: "completed", routing_order: 1 }), { kind: "done", mark: "✓" });
  assert.deepEqual(recipientBadge({ type: "signer", status: "declined", routing_order: 1 }), { kind: "declined", mark: "✕" });
  assert.deepEqual(recipientBadge({ id: "me", type: "signer", status: "sent", routing_order: 2 }, { mineId: "me" }), { kind: "you", mark: "2" });
  assert.deepEqual(recipientBadge({ id: "x", type: "signer", status: "delivered", routing_order: 2 }, { mineId: "me" }), { kind: "wait", mark: "2" });
  assert.deepEqual(recipientBadge({ type: "signer", status: "created", routing_order: 3 }), { kind: "next", mark: "3" });
  assert.deepEqual(recipientBadge({ type: "cc", status: "created", routing_order: 2 }), { kind: "next", mark: "cc" });
});

test("personal data is summarised by kind and page; dismissed items drop out", () => {
  const s = piiSummary([
    { kind: "personal_data", label: "Email address", page: 3, state: "open" },
    { kind: "personal_data", label: "Email address", page: 1, state: "accepted" },
    { kind: "personal_data", label: "Phone number", page: 3, state: "dismissed" },
    { kind: "entity", label: "Term", page: 1, state: "open" },
  ]);
  assert.deepEqual(s, { items: [{ label: "Email address", n: 2 }], pages: [1, 3], total: 2 });
});

test("audit links: a dense, linked chain passes; a broken link, a gap or a wrong head does not", () => {
  const H = (c) => c.repeat(64);
  const good = { items: [{ seq: 0, hash: H("a"), prev: null }, { seq: 1, hash: H("b"), prev: H("a") }], chain_head: H("b") };
  assert.deepEqual(auditLinks(good), { ok: true, n: 2, problems: [] });
  assert.equal(auditLinks({ ...good, chain_head: H("c") }).ok, false);
  assert.equal(auditLinks({ items: [good.items[0], { ...good.items[1], prev: H("c") }], chain_head: H("b") }).ok, false);
  assert.equal(auditLinks({ items: [good.items[0], { ...good.items[1], seq: 2 }], chain_head: H("b") }).ok, false);
  assert.equal(auditLinks({ items: [{ seq: 0, hash: "short", prev: null }] }).ok, false);
  assert.deepEqual(auditLinks(null), { ok: true, n: 0, problems: [] });
});

test("a document fingerprint is shown only when the server recorded one", () => {
  assert.equal(documentFingerprint({ delivered_sha256: null, upload_sha256: null }), null);
  assert.equal(documentFingerprint({ upload_sha256: "AB".repeat(32) }), "ab".repeat(32));
  assert.equal(documentFingerprint({ sha256: `sha256:${"c".repeat(64)}` }), "c".repeat(64));
  assert.equal(documentFingerprint({ upload_sha256: "zz" }), null);
  assert.equal(groupHex("0123456789"), "0123 4567 89");
});
