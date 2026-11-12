// Unit tests of the console UI's pure logic (CON-17): `node --test console-ui/tests/`.

import test from "node:test";
import assert from "node:assert/strict";

import * as M from "../model.js";

const HEALTH = {
  at: "2026-11-13T10:00:00Z",
  database: { status: "up" },
  jobs: [
    { kind: "send_invitation", status: "queued", jobs: 4, oldest_seconds: 40 },
    { kind: "deliver_webhook", status: "queued", jobs: 2, oldest_seconds: 95 },
    { kind: "seal", status: "running", jobs: 1, oldest_seconds: null },
    { kind: "send_invitation", status: "dead", jobs: 1, oldest_seconds: null },
  ],
  dead_letters: 1,
  connections: [{ state: "active", connections: 2 }, { state: "idle", connections: 5 }],
  services: [
    { name: "keyd", role: "keyd", probe: "tcp", status: "up", latency_ms: 3 },
    { name: "worker", role: "worker", probe: "http", status: "down", latency_ms: 2000 },
  ],
  operator_log: { verified: true, events: 12 },
};

test("health tiles show only what the API returned", () => {
  const t = Object.fromEntries(M.healthTiles(HEALTH).map((x) => [x.id, x]));
  assert.equal(t.queue.value, "6");
  assert.match(t.queue.note, /Oldest waiting 1 min · 1 running/);
  assert.equal(t.dead.value, "1");
  assert.equal(t.dead.state, "warn");
  assert.equal(t.database.value, "Up");
  assert.match(t.database.note, /7 connections · 2 active · 5 idle/);
  assert.equal(t.services.value, "1 of 2");
  assert.equal(t.services.state, "bad");
  assert.equal(t.log.value, "Verified");
  assert.match(t.log.note, /12 events/);
});

test("missing health values are shown as absent, never as zero", () => {
  const t = Object.fromEntries(M.healthTiles({}).map((x) => [x.id, x]));
  assert.equal(t.dead.value, "–");
  assert.equal(t.database.value, "–");
  assert.equal(t.database.state, "bad");
  assert.equal(t.services.value, "–");
  assert.equal(t.log.value, "–");
});

test("a broken operator log is bad and names its code", () => {
  const t = M.healthTiles({ ...HEALTH, operator_log: { verified: false, code: "CS-CON-0007" } }).find((x) => x.id === "log");
  assert.equal(t.state, "bad");
  assert.match(t.note, /CS-CON-0007/);
});

test("an alert resolved by a later alert is no longer open", () => {
  const alerts = [
    { id: "b", at: "2026-11-13T10:05:00Z", source: "worker", code: "CS-TSA-0001", resolves: "a" },
    { id: "a", at: "2026-11-13T10:00:00Z", source: "worker", code: "CS-TSA-0001", resolves: null },
    { id: "c", at: "2026-11-13T09:00:00Z", source: "keyd", code: "CS-KEY-0003", resolves: null },
  ];
  assert.deepEqual(M.openAlerts(alerts).map((a) => a.id), ["c"]);
});

test("the summary names what needs attention, worst first", () => {
  assert.deepEqual(M.healthSummary({ ...HEALTH, services: [] , dead_letters: 0 }, []), { tone: "ok", text: "All systems normal" });
  assert.equal(M.healthSummary(HEALTH, []).tone, "bad");
  assert.match(M.healthSummary(HEALTH, []).text, /Services needs attention/);
  const quiet = { ...HEALTH, services: [], dead_letters: 0 };
  assert.deepEqual(M.healthSummary(quiet, [{ id: "x", code: "C", resolves: null }]), { tone: "warn", text: "1 alert needs attention" });
});

test("queue rows group by kind with the oldest queued age", () => {
  const rows = M.queueByKind(HEALTH.jobs);
  assert.deepEqual(rows.map((r) => r.kind), ["deliver_webhook", "seal", "send_invitation"]);
  const inv = rows.find((r) => r.kind === "send_invitation");
  assert.deepEqual([inv.queued, inv.running, inv.dead, inv.oldest], [4, 0, 1, 40]);
});

test("approval state follows the three steps for each operator", () => {
  const now = Date.parse("2026-11-13T10:00:00Z");
  const base = { id: "r", requester: "me", action: "organization.suspend", organization: "o", expires_at: "2026-11-14T09:00:00Z", approvers: [], used: false, live: true };
  assert.equal(M.approvalState(base, "me", now), "waiting");
  assert.equal(M.approvalState(base, "other", now), "grantable");
  const granted = { ...base, approvers: ["other"] };
  assert.equal(M.approvalState(granted, "me", now), "ready");
  assert.equal(M.approvalState(granted, "other", now), "granted");
  assert.equal(M.approvalState(granted, "third", now), "grantable");
  assert.equal(M.approvalState({ ...granted, used: true }, "me", now), "applied");
  assert.equal(M.approvalState({ ...base, expires_at: "2026-11-13T09:59:00Z" }, "me", now), "expired");
  assert.equal(M.approvalState({ ...base, live: false }, "other", now), "expired");
  // A requester's own grant (refused by the server) never makes it ready.
  assert.equal(M.approvalState({ ...base, approvers: ["me"] }, "me", now), "waiting");
});

test("myRequest finds the live request for this organization and action", () => {
  const now = Date.parse("2026-11-13T10:00:00Z");
  const list = [
    { id: "1", requester: "me", action: "organization.resume", organization: "o", expires_at: "2026-11-14T00:00:00Z", approvers: [], used: false },
    { id: "2", requester: "me", action: "organization.suspend", organization: "o", expires_at: "2026-11-14T00:00:00Z", approvers: ["x"], used: true },
    { id: "3", requester: "me", action: "organization.suspend", organization: "o", expires_at: "2026-11-14T00:00:00Z", approvers: ["x"], used: false },
  ];
  assert.deepEqual(M.myRequest(list, "o", "organization.suspend", "me", now), { approval: list[2], state: "ready" });
  assert.equal(M.myRequest(list, "p", "organization.suspend", "me", now), null);
  assert.equal(M.grantableCount(list, "x", now), 1);
});

test("org actions follow the status", () => {
  assert.equal(M.orgAction("active"), "organization.suspend");
  assert.equal(M.orgAction("suspended"), "organization.resume");
  assert.equal(M.orgAction("closed"), null);
});

test("region labels are checked as the API checks them", () => {
  assert.deepEqual(M.parseRegions("eu-west, us  eu-west"), { labels: ["eu-west", "us"], bad: [] });
  assert.deepEqual(M.parseRegions("EU, -bad, ok").bad, ["-bad"]);
  assert.deepEqual(M.parseRegions("").labels, []);
  const many = Array.from({ length: 17 }, (_, i) => `r${i}`).join(",");
  assert.equal(M.parseRegions(many).bad.length, 1);
  assert.equal(M.parseRegions("a".repeat(33)).bad.length, 1);
});

test("names, passwords and codes are checked before sending", () => {
  assert.equal(M.checkName("  ").ok, false);
  assert.equal(M.checkName("x".repeat(256)).ok, false);
  assert.deepEqual(M.checkName(" Acme "), { ok: true, value: "Acme" });
  assert.equal(M.checkPassword("short", "short"), "Use at least 12 characters.");
  assert.equal(M.checkPassword("long enough pw", "long enough pX"), "The two passwords differ.");
  assert.equal(M.checkPassword("long enough pw", "long enough pw"), null);
  assert.equal(M.cleanCode("123 456"), "123456");
  assert.equal(M.cleanCode("12345"), null);
  assert.equal(M.cleanCode("abcdef"), null);
});

test("the otpauth secret is extracted and grouped", () => {
  assert.equal(M.otpSecret("otpauth://totp/OpenSeal:abc?secret=JBSWY3DPEHPK3PXP&issuer=OpenSeal"), "JBSW Y3DP EHPK 3PXP");
  assert.equal(M.otpSecret("nonsense"), "");
});

test("problems become plain sentences, naming the field or the wait", () => {
  assert.match(M.problemMessage({ code: "CS-CON-0002" }), /authenticator/);
  assert.equal(M.problemMessage({ code: "CS-CON-0010", field: "data_regions" }), "The data regions is not valid.");
  assert.equal(M.problemMessage({ code: "CS-CON-0012", retry_after: 30 }), "Too many attempts. Try again in 30 s.");
  assert.match(M.problemMessage({ network: true }), /cannot be reached/);
  assert.match(M.problemMessage({ status: 418 }), /418/);
});

test("roles map to screens as the API's x-roles do", () => {
  assert.deepEqual(M.access(["observer"]), { health: true, organizations: true, manage: false, approvals: false, log: false, operators: false });
  assert.equal(M.access(["operator"]).approvals, true);
  assert.equal(M.access(["operator"]).operators, false);
  assert.equal(M.access(["platform_owner"]).operators, true);
});

test("formatting", () => {
  assert.equal(M.count(1284), "1,284");
  assert.equal(M.count(undefined), "–");
  assert.equal(M.duration(40), "40 s");
  assert.equal(M.duration(3 * 3600 + 300), "3 h 5 min");
  assert.equal(M.duration(5 * 86400), "5 d");
  const now = Date.parse("2026-11-13T10:00:00Z");
  assert.equal(M.ago("2026-11-13T09:59:56Z", now), "4 s ago");
  assert.equal(M.ago("2026-11-13T09:54:00Z", now), "6 min ago");
  assert.equal(M.until("2026-11-14T09:00:00Z", now), "in 23 h");
  assert.equal(M.until("2026-11-13T09:00:00Z", now), "expired");
  assert.equal(M.shortDate("2026-11-13T14:05:00Z"), "13 Nov 2026, 14:05 UTC");
  assert.equal(M.eventLabel("operator.organization.suspended"), "Organization suspended");
  assert.deepEqual(M.eventDetails({ event: { details: { organization_id: "x" } } }), [["organization id", "x"]]);
});
