// UX-08: the pure rules behind Admin, Reports and Template use.
import { test } from "node:test";
import assert from "node:assert/strict";

import {
  NAV, routeFrom, navHref, SCOPE_GROUPS, eventGroups, parseSecretRefs, expiryState, userState, filterUsers, contrastRatio,
  POLICY_DEFAULTS, expiryWarningOf, withExpiryWarning, expiryWarningPatch, filterAdminEvents, joinCsvPages,
} from "../adminmodel.js";
import { createClient } from "../api.js";
import { createMockFetch, MOCK } from "../mock.js";
import { medianHours, inWindow, csvRows, hasTimes, toCsv } from "../reportmodel.js";
import { envelopeFromTemplate, extraProblems } from "../templatemodel.js";

const q = (s) => new URLSearchParams(s);

test("the admin nav is the canvas's nine pages in order, the waiting ones included", () => {
  assert.deepEqual(NAV.map((n) => n.id), ["organization", "members", "security", "signing", "branding", "intelligence", "retention", "integrations", "audit"]);
  assert.deepEqual(NAV.filter((n) => n.ready).map((n) => n.id), ["organization", "members", "branding", "intelligence", "integrations", "audit"]);
  // Every page not built yet names what it waits for, so none is a dead link.
  for (const n of NAV.filter((x) => !x.ready)) assert.ok(n.waits?.length, n.id);
});

test("old ?section= and ?tab= links land on the page that now holds them", () => {
  assert.deepEqual(routeFrom(q("")), { nav: "members", tab: "users" });
  assert.deepEqual(routeFrom(q("tab=api")), { nav: "integrations", tab: "api" });
  assert.deepEqual(routeFrom(q("section=webhooks")), { nav: "integrations", tab: "webhooks" });
  assert.deepEqual(routeFrom(q("section=integrations")), { nav: "integrations", tab: "api" });
  assert.deepEqual(routeFrom(q("tab=account")), { nav: "organization", tab: null });
  assert.deepEqual(routeFrom(q("section=seal")), { nav: "signing", tab: null });
  assert.deepEqual(routeFrom(q("section=groups")), { nav: "members", tab: "groups" });
  assert.deepEqual(routeFrom(q("section=profiles")), { nav: "members", tab: "profiles" });
  assert.deepEqual(routeFrom(q("section=intelligence")), { nav: "intelligence", tab: null });
  assert.deepEqual(routeFrom(q("section=nope")), { nav: "members", tab: "users" });
});

test("nav links: Members is bare #/admin, a tabbed page opens on its first tab", () => {
  assert.equal(navHref("members"), "#/admin");
  assert.equal(navHref("members", "groups"), "#/admin?section=groups");
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

// ---- RTE-03, UXW-09 -------------------------------------------------------------------------
test("expiry warning days go back in the whole workflow policy, the account's own members kept (RTE-03)", () => {
  assert.equal(expiryWarningOf({}), 0);
  assert.equal(expiryWarningOf({ workflow_policy: { expiry_warning_days: 4 } }), 4);
  assert.deepEqual(withExpiryWarning({}, 2), { ...POLICY_DEFAULTS, expiry_warning_days: 2 });
  const ersd = { version: "2026-1", hash: `sha256:${"ab".repeat(32)}` };
  const own = { ...POLICY_DEFAULTS, max_auth_attempts: 5, ersd };
  assert.deepEqual(withExpiryWarning({ workflow_policy: own }, 7), { ...own, expiry_warning_days: 7 });
});

test("the expiry warning is set on the policy as it is now, not as the page loaded it (RTE-03)", async () => {
  const c = createClient({ fetch: createMockFetch() });
  await c.login(MOCK.email, MOCK.password);
  // The page loads the account; then another admin changes the policy (a disclosure
  // required, more sign-in attempts) before this one saves the warning days.
  await c.account();
  const ersd = { version: "2", hash: `sha256:${"a".repeat(64)}` };
  await c.patchAccountSettings({ workflow_policy: { ...POLICY_DEFAULTS, ersd, max_auth_attempts: 5 } });
  const patch = await expiryWarningPatch(c, 7);
  const out = await c.patchAccountSettings(patch);
  assert.deepEqual(out.settings.workflow_policy, { ...POLICY_DEFAULTS, ersd, max_auth_attempts: 5, expiry_warning_days: 7 });
  // Already those days: nothing to send.
  assert.equal(await expiryWarningPatch(c, 7), null);
});

test("the mock takes a workflow policy only whole, as the server does, and logs the change (RTE-03, UXW-09)", async () => {
  const c = createClient({ fetch: createMockFetch() });
  await c.login(MOCK.email, MOCK.password);
  await assert.rejects(c.patchAccountSettings({ workflow_policy: { expiry_warning_days: 2 } }), (e) => e.status === 422 && e.errors[0].pointer === "/settings/workflow_policy");
  const out = await c.patchAccountSettings({ workflow_policy: withExpiryWarning({}, 2) });
  assert.equal(out.settings.workflow_policy.expiry_warning_days, 2);
  const log = await c.adminEvents({ limit: 1000, verify: "full" });
  const last = log.items.at(-1);
  assert.equal(last.action, "workspace.settings_changed");
  assert.equal(last.event.changes[0].key, "workflow_policy");
  assert.equal(last.prev, log.items.at(-2).hash);
  // Paged by cursor; the CSV pages join with one header.
  const first = await c.adminEvents({ limit: 2 });
  assert.equal(first.next_cursor, first.items[1].seq);
  const csv = [];
  let cursor;
  for (;;) {
    const page = await c.adminEventsCsv({ limit: 2, cursor });
    csv.push(page.text);
    if (page.next == null) break;
    cursor = page.next;
  }
  assert.ok(csv.length > 1);
  const lines = joinCsvPages(csv).trim().split("\r\n");
  assert.equal(lines[0], "seq,at,action,hash,prev,event");
  assert.equal(lines.length, log.items.length + 1);
});

test("admin events filter by action, by who and by text in keys, targets and names (UXW-09)", () => {
  const ev = (seq, action, kind, keys = [], target = {}) => ({ seq, action, event: { actor: kind === "system" ? { kind } : { kind, id: `${kind}-1` }, target, changes: keys.map((key) => ({ key })) } });
  const items = [ev(0, "workspace.created", "system"), ev(1, "member.added", "user", ["profile"], { user: "u-77" }), ev(2, "workspace.settings_changed", "api_client", ["branding"])];
  const name = (e) => (e.event.actor.kind === "user" ? "Robin" : "");
  assert.deepEqual(filterAdminEvents(items, { action: "member.added" }).map((e) => e.seq), [1]);
  assert.deepEqual(filterAdminEvents(items, { actor: "system" }).map((e) => e.seq), [0]);
  assert.deepEqual(filterAdminEvents(items, { q: "BRAND" }).map((e) => e.seq), [2]);
  assert.deepEqual(filterAdminEvents(items, { q: "u-77" }).map((e) => e.seq), [1]);
  assert.deepEqual(filterAdminEvents(items, { q: "robin" }, name).map((e) => e.seq), [1]);
  assert.equal(joinCsvPages(["h\r\na\r\n", "h\r\nb\r\n"]), "h\r\na\r\nb\r\n");
});

test("a member's profile choice: built-in by name, custom by id (UXW-07)", async () => {
  const { profileChoices, profileValue } = await import("../adminmodel.js");
  const profiles = [
    { id: "p-a", kind: "admin", builtin: true, name: "Administrator" },
    { id: "p-c", kind: "custom", builtin: false, name: "Author" },
  ];
  assert.deepEqual(profileChoices(profiles, (k) => k.toUpperCase()), [["admin", "ADMIN"], ["sender", "SENDER"], ["viewer", "VIEWER"], ["p-c", "Author"]]);
  assert.equal(profileValue({ permission_profile_id: "p-a" }, {}, profiles), "admin");
  assert.equal(profileValue({ permission_profile_id: "b-s" }, { sender: "b-s" }, profiles), "sender");
  assert.equal(profileValue({ permission_profile_id: "p-c" }, {}, profiles), "p-c");
});
