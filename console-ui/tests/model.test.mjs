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
  assert.equal(M.healthSummary(HEALTH, []).text, "Needs attention: Services");
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
  assert.deepEqual(M.access(["observer"]), { health: true, organizations: true, keys: true, keysLog: false, custodian: false, manage: false, approvals: false, plans: true, log: false, operators: false });
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

// Plans (PLAN-02) ----------------------------------------------------------------------

const METERS = [
  { name: "envelopes_sent", kind: "counter", approximate: false },
  { name: "seats", kind: "gauge", approximate: false },
  { name: "api_calls", kind: "counter", approximate: true },
  { name: "workspaces", kind: "gauge", approximate: false },
];

test("the plan form refuses hard on an approximate meter, as the server does (CS-PLAN-0006)", () => {
  const base = { key: "team", name: "Team", features: ["api"] };
  const hard = M.checkPlan({ ...base, quotas: [{ meter: "api_calls", limit: "1000", period: "month", enforcement: "hard", level: "organization" }] }, METERS);
  assert.equal(hard.ok, false);
  assert.match(hard.message, /approximately/);
  const soft = M.checkPlan({ ...base, quotas: [{ meter: "api_calls", limit: "1000", period: "month", enforcement: "soft", level: "organization" }] }, METERS);
  assert.equal(soft.ok, true);
  assert.deepEqual(soft.value, {
    key: "team", name: "Team", seat_rule: "can_send", entitlements: { api: true },
    quotas: [{ meter: "api_calls", limit: 1000, period: "month", enforcement: "soft", level: "organization" }],
  });
});

test("the plan form checks key, name, gauges, levels, limits and duplicates", () => {
  const q = (o) => ({ meter: "envelopes_sent", limit: "10", period: "month", enforcement: "hard", level: "organization", ...o });
  const bad = (plan) => M.checkPlan({ key: "team", name: "Team", ...plan }, METERS).ok;
  assert.equal(bad({ key: "Team" }), false);
  assert.equal(bad({ key: "9team" }), false);
  assert.equal(bad({ key: "a".repeat(65) }), false);
  assert.equal(bad({ name: "  " }), false);
  assert.equal(bad({ name: "x".repeat(121) }), false);
  assert.equal(bad({ quotas: [q({ meter: "seats", period: "month" })] }), false);
  assert.equal(bad({ quotas: [q({ meter: "seats", period: "none" })] }), true);
  assert.equal(bad({ quotas: [q({ meter: "workspaces", period: "none", level: "workspace" })] }), false);
  assert.equal(bad({ quotas: [q({ limit: "-1" })] }), false);
  assert.equal(bad({ quotas: [q({ limit: "1e3" })] }), false);
  assert.equal(bad({ quotas: [q(), q({ limit: "5" })] }), false);
  assert.equal(bad({ quotas: [q(), q({ level: "workspace" })] }), true);
});

test("plan versions group by key, newest first, current skips archived", () => {
  const g = M.planGroups([
    { key: "team", version: 1, name: "Team", archived: true },
    { key: "team", version: 3, name: "Team", archived: true },
    { key: "team", version: 2, name: "Team", archived: false },
    { key: "basic", version: 1, name: "Basic", archived: false },
  ]);
  assert.deepEqual(g.map((x) => x.key), ["basic", "team"]);
  assert.deepEqual(g[1].versions.map((v) => v.version), [3, 2, 1]);
  assert.equal(g[1].latest.version, 3);
  assert.equal(g[1].current.version, 2);
});

test("override keys follow the effective plan; a workspace may change only workspace quotas", () => {
  const cat = { features: ["api", "bulk_send"], meters: METERS };
  const eff = { quotas: [
    { meter: "envelopes_sent", level: "organization" },
    { meter: "api_calls", level: "workspace" },
  ] };
  const org = M.overrideKeys(cat, eff).map((k) => k.key);
  assert.deepEqual(org, [
    "feature.api", "feature.bulk_send",
    "quota.envelopes_sent.organization.limit", "quota.envelopes_sent.organization.enforcement",
    "quota.api_calls.workspace.limit", "quota.api_calls.workspace.enforcement",
    "seat_rule",
  ]);
  const ws = M.overrideKeys(cat, eff, true);
  assert.deepEqual(ws.map((k) => k.key), ["quota.api_calls.workspace.limit", "quota.api_calls.workspace.enforcement"]);
  assert.equal(ws[1].approximate, true);
  assert.equal(M.checkOverrideValue("enforcement", "hard", true).ok, false);
  assert.equal(M.checkOverrideValue("enforcement", "notify", true).value, "notify");
  assert.equal(M.checkOverrideValue("limit", "0012").value, "12");
  assert.equal(M.checkOverrideValue("limit", "1.5").ok, false);
  assert.equal(M.checkOverrideValue("flag", "yes").ok, false);
  assert.equal(M.overrideKeyLabel("quota.seats.organization.limit"), "Seats per organization: limit");
  assert.equal(M.overrideValueLabel("feature.api", "false"), "Off");
  assert.equal(M.quotaText({ limit: 1000, period: "month", enforcement: "hard", level: "workspace" }), "1,000 per month · hard · per workspace");
  assert.equal(M.quotaText({ limit: 5, period: "none", enforcement: "soft", level: "organization" }), "5 · soft · per organization");
  assert.equal(M.problemMessage({ status: 422, code: "CS-PLAN-0006", field: "expires_at" }), "The expires at is not valid.");
  assert.equal(M.localToIso(""), null);
  assert.equal(M.localToIso("not a date"), undefined);
});

test("a key's status says how long it has left or since when it expired (CON-06)", () => {
  assert.deepEqual(M.keyStatus({ status: "valid", days_left: 400 }), { label: "Valid", tone: "ok", note: "400 days left" });
  assert.deepEqual(M.keyStatus({ status: "expiring", days_left: 1 }), { label: "Expiring", tone: "warn", note: "1 day left" });
  assert.deepEqual(M.keyStatus({ status: "expired", days_left: -3 }), { label: "Expired", tone: "bad", note: "expired 3 days ago" });
  assert.equal(M.keyStatus({ status: "not_yet_valid", days_left: 900 }).note, "");
  assert.equal(M.keyStatus({}).label, "Unknown");
});

test("keyd's tile reads its health and names the refusal (CON-06)", () => {
  assert.equal(M.keydTile({ status: "up", log_seq: 12, keys: [{ alias: "platform", ok: true }] }).note, "1 key · log at 12");
  const deg = M.keydTile({ status: "degraded", keys: [{ alias: "platform", ok: false }, { alias: "b", ok: true }] });
  assert.equal(deg.state, "warn");
  assert.match(deg.note, /^platform not answering$/);
  const down = M.keydTile({ status: "down", code: "CS-CON-0008" });
  assert.equal(down.state, "bad");
  assert.match(down.note, /admin allow-list/);
  assert.equal(M.keydTile({ status: "not_configured" }).value, "Not set");
  assert.equal(M.access(["observer"]).keys, true);
  assert.equal(M.access(["observer"]).keysLog, false);
  assert.equal(M.access(["operator"]).keysLog, true);
});

test("a TSA change reads as what it sets, for the approver (CON-07)", () => {
  const set = { action: "tsa.set", endpoint: "0192aaaa-bbbb-7ccc-8ddd-eeeeffff0000", payload: { url: "https://tsa.example/tsr", priority: 10, enabled: true, policy_oid: "1.2.3", cert_sha256: "ab".repeat(32) } };
  assert.equal(M.tsaChangeText(set), "https://tsa.example/tsr · priority 10 · enabled · policy 1.2.3 · certificate abababababab…");
  assert.match(M.tsaChangeText({ action: "tsa.remove", endpoint: "0192aaaa-bbbb-7ccc-8ddd-eeeeffff0000" }), /^Remove /);
  assert.equal(M.access(["key_custodian"]).custodian, true);
  assert.equal(M.access(["operator"]).custodian, false);
  assert.equal(M.actionLabel("tsa.set"), "Set time-stamping authority");
});

test("the keyd log card asks for the latest records, not the first ever (CON-06)", () => {
  assert.equal(M.keydLogFrom(0), 1);
  assert.equal(M.keydLogFrom(42), 1);
  assert.equal(M.keydLogFrom(100), 1);
  assert.equal(M.keydLogFrom(101), 2);
  assert.equal(M.keydLogFrom(5000), 4901);
  assert.equal(M.keydLogFrom(5000, 10), 4991);
  assert.equal(M.keydLogFrom(undefined), 1);
});
