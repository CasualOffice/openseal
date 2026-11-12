// UX-08: the pure rules behind Admin, Reports and Template use.
import { test } from "node:test";
import assert from "node:assert/strict";

import { NAV, routeFrom, navHref, SCOPE_GROUPS, eventGroups, parseSecretRefs, expiryState, userState, filterUsers, contrastRatio } from "../adminmodel.js";
import { medianHours, inWindow, csvRows, hasTimes, toCsv } from "../reportmodel.js";
import { envelopeFromTemplate, extraProblems } from "../templatemodel.js";

const q = (s) => new URLSearchParams(s);

test("the admin nav is the canvas's nine pages in order, the waiting ones included", () => {
  assert.deepEqual(NAV.map((n) => n.id), ["organization", "members", "security", "signing", "branding", "intelligence", "retention", "integrations", "audit"]);
  assert.deepEqual(NAV.filter((n) => n.ready).map((n) => n.id), ["organization", "members", "branding", "intelligence", "integrations"]);
  // Every page not built yet names what it waits for, so none is a dead link.
  for (const n of NAV.filter((x) => !x.ready)) assert.ok(n.waits?.length, n.id);
});

test("old ?section= and ?tab= links land on the page that now holds them", () => {
  assert.deepEqual(routeFrom(q("")), { nav: "members", tab: null });
  assert.deepEqual(routeFrom(q("tab=api")), { nav: "integrations", tab: "api" });
  assert.deepEqual(routeFrom(q("section=webhooks")), { nav: "integrations", tab: "webhooks" });
  assert.deepEqual(routeFrom(q("section=integrations")), { nav: "integrations", tab: "api" });
  assert.deepEqual(routeFrom(q("tab=account")), { nav: "organization", tab: null });
  assert.deepEqual(routeFrom(q("section=seal")), { nav: "signing", tab: null });
  assert.deepEqual(routeFrom(q("section=groups")), { nav: "members", tab: null });
  assert.deepEqual(routeFrom(q("section=intelligence")), { nav: "intelligence", tab: null });
  assert.deepEqual(routeFrom(q("section=nope")), { nav: "members", tab: null });
});

test("nav links: Members is bare #/admin, a tabbed page opens on its first tab", () => {
  assert.equal(navHref("members"), "#/admin");
  assert.equal(navHref("integrations"), "#/admin?section=api");
  assert.equal(navHref("integrations", "webhooks"), "#/admin?section=webhooks");
  assert.equal(navHref("intelligence"), "#/admin?section=intelligence");
  // Each href routes back to its own page.
  for (const n of NAV) assert.equal(routeFrom(q(navHref(n.id).split("?")[1] || "")).nav, n.id, n.id);
});

test("every server scope is offered once", () => {
  const all = SCOPE_GROUPS.flatMap(([, s]) => s);
  assert.equal(new Set(all).size, 10);
  for (const s of ["admin:users", "admin:account", "webhooks:manage", "audit:read", "bulk:send"]) assert.ok(all.includes(s), s);
});

test("webhook events group by subject; secret names follow the server's rule", () => {
  assert.deepEqual(eventGroups(["envelope.sent", "recipient.sent", "envelope.voided"]), [["envelope", ["envelope.sent", "envelope.voided"]], ["recipient", ["recipient.sent"]]]);
  assert.deepEqual(parseSecretRefs(" crm_secret, other-1 crm_secret"), { refs: ["crm_secret", "other-1"] });
  assert.deepEqual(parseSecretRefs(""), { error: "none" });
  assert.deepEqual(parseSecretRefs("a b c d e"), { error: "many" });
  assert.deepEqual(parseSecretRefs("bad.name"), { error: "bad" });
  assert.deepEqual(parseSecretRefs("x".repeat(65)), { error: "bad" });
});

test("a key's expiry: never, expired, soon within 30 days, else fine", () => {
  const now = Date.parse("2026-01-01T00:00:00Z");
  assert.deepEqual(expiryState(null, now), { state: "none", days: null });
  assert.deepEqual(expiryState("2025-12-31T00:00:00Z", now), { state: "expired", days: 0 });
  assert.deepEqual(expiryState("2026-01-10T12:00:00Z", now), { state: "soon", days: 10 });
  assert.deepEqual(expiryState("2026-06-01T00:00:00Z", now).state, "ok");
});

test("members filter by text, profile and state", () => {
  const items = [
    { id: "a", name: "Ana Admin", email: "ana@x.test", p: "admin" },
    { id: "b", name: "Bo", email: "bo@x.test", p: "sender", invitation: "sent" },
    { id: "c", name: "Cy", email: "cy@y.test", p: "sender", disabled: true },
  ];
  const prof = (u) => u.p;
  assert.deepEqual(filterUsers(items, { q: "X.TEST" }, prof).map((u) => u.id), ["a", "b"]);
  assert.deepEqual(filterUsers(items, { profile: "sender" }, prof).map((u) => u.id), ["b", "c"]);
  assert.deepEqual(filterUsers(items, { status: "pending" }, prof).map((u) => u.id), ["b"]);
  assert.equal(userState(items[2]), "disabled");
  assert.equal(userState({ invitation: "accepted" }), "active");
});

test("contrast follows WCAG: white on seal red passes, on yellow it does not", () => {
  assert.equal(contrastRatio("#ffffff", "#000000"), 21);
  assert.ok(contrastRatio("#b3141f", "#ffffff") >= 4.5);
  assert.ok(contrastRatio("#f5c518", "#ffffff") < 4.5);
  assert.equal(contrastRatio("red", "#ffffff"), null);
});

test("reports: the median over every completed summary, a custom range, a richer CSV", () => {
  const rows = [
    { id: "1", status: "completed", sender_user_id: "u1", created_at: "2026-01-01T10:00:00Z", sent_at: "2026-01-01T10:00:00Z", completed_at: "2026-01-01T12:00:00Z" },
    { id: "2", status: "completed", sender_user_id: "u2", created_at: "2026-01-05T10:00:00Z", sent_at: "2026-01-05T10:00:00Z", completed_at: "2026-01-05T16:00:00Z" },
    { id: "3", status: "draft", sender_user_id: "u1", created_at: "2026-02-01T10:00:00Z", sent_at: null, completed_at: null },
  ];
  assert.ok(rows.every(hasTimes));
  assert.equal(medianHours(rows.filter((r) => r.status === "completed")), 4);
  assert.equal(medianHours([{ sent_at: "2026-01-01T00:00:00Z", ended_at: "2026-01-01T03:00:00Z" }]), 3);
  assert.deepEqual(inWindow(rows, { range: "custom", from: "2026-01-02", to: "2026-01-31" }).map((r) => r.id), ["2"]);
  assert.deepEqual(inWindow(rows, { range: "custom", to: "2026-01-05" }).map((r) => r.id), ["1", "2"]);
  assert.deepEqual(inWindow(rows, { range: "7" }, Date.parse("2026-02-03T00:00:00Z")).map((r) => r.id), ["3"]);
  const csv = toCsv(csvRows(rows, (id) => (id === "u1" ? "Ana" : "")));
  assert.equal(csv.split("\r\n")[0], "id,subject,status,sender,created_at,sent_at,completed_at,expires_at,updated_at");
  assert.match(csv.split("\r\n")[1], /^1,,completed,Ana,/);
  assert.match(csv.split("\r\n")[2], /^2,,completed,u2,/);
});

test("using a template with added people: they follow every role, and are checked", () => {
  const tp = { name: "NDA", roles: [{ id: "r1", name: "Client", type: "signer", routing_order: 1 }, { id: "r2", name: "Legal", type: "cc", routing_order: 2 }] };
  const people = { Client: { name: "A", email: "a@x.test" }, Legal: { name: "L", email: "l@x.test" } };
  const { body } = envelopeFromTemplate(tp, people, { extra: [{ name: " Carl ", email: "c@x.test", type: "cc" }, { name: "Sig", email: "s@x.test", type: "signer" }] });
  assert.deepEqual(body.recipients.slice(2), [
    { ref: "extra0", type: "cc", name: "Carl", email: "c@x.test", routing_order: 3 },
    { ref: "extra1", type: "signer", name: "Sig", email: "s@x.test", routing_order: 3 },
  ]);
  assert.equal(envelopeFromTemplate(tp, people).body.recipients.length, 2);
  assert.deepEqual(extraProblems([{ name: "", email: "nope" }, { name: "Ok", email: "ok@x.test" }]), [{ index: 0, problem: "name" }, { index: 0, problem: "email" }]);
});
