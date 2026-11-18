// A person's own sessions and step-up re-authentication (ASVS-06, ASVS-07): the rules in
// authmodel.js, the API client's ask-and-repeat on `403 CS-AUTH-0013`, and the mock's
// behaving as the server does.
// Run: cd webapp && node --test tests/sessions.test.mjs
import test from "node:test";
import assert from "node:assert/strict";

import { EN } from "../strings.en.js";
import { stepUpNeedsCode, stepUpFailure, sessionRows } from "../authmodel.js";
import { createMockFetch, MOCK } from "../mock.js";
import { createClient, ApiError } from "../api.js";

/// A mock whose clock the test moves.
function clocked() {
  let at = Date.parse("2026-11-19T09:00:00Z");
  const fetch = createMockFetch({ now: () => new Date(at) });
  return { fetch, advance: (ms) => { at += ms; } };
}

const MIN = 60_000;

test("the code is asked only of a person with a second factor", () => {
  assert.equal(stepUpNeedsCode({ second_factor: "passed" }), true);
  assert.equal(stepUpNeedsCode({ second_factor: "none" }), false);
  assert.equal(stepUpNeedsCode(null), false);
});

test("a refused re-authentication names the field to fix", () => {
  assert.deepEqual(stepUpFailure(new ApiError({ code: "CS-AUTH-0007" })), { field: "password", key: "stepup.password-wrong" });
  assert.deepEqual(stepUpFailure(new ApiError({ code: "CS-AUTH-0012" })), { field: "code", key: "stepup.code-wrong" });
  assert.deepEqual(stepUpFailure(new ApiError({ code: "CS-API-0001", errors: [{ pointer: "/code" }] })), { field: "code", key: "stepup.code-missing" });
  assert.equal(stepUpFailure(new ApiError({ code: "CS-API-0003" })), null);
  for (const k of ["stepup.password-wrong", "stepup.code-wrong", "stepup.code-missing", "error.CS-AUTH-0013"]) assert.ok(EN[k], k);
});

test("the list shows this session first, then the most recently active, never trusting the shape", () => {
  const rows = sessionRows([
    { id: "a", client: "Firefox on Linux", workspace: { name: "Legal" }, last_seen_at: "2026-11-19T08:00:00Z" },
    { id: "b", client: "", workspace: { name: "Main" }, last_seen_at: "2026-11-19T08:30:00Z" },
    { id: "c", client: "Safari on iOS", workspace: { name: "Main" }, current: true, last_seen_at: "2026-11-19T07:00:00Z" },
    null,
    { client: "no id" },
  ]);
  assert.deepEqual(rows.map((r) => r.id), ["c", "b", "a"]);
  assert.equal(rows[1].client, null, "an unnamed browser is said as unknown by the view");
  assert.equal(rows[0].current, true);
  assert.deepEqual(sessionRows(undefined), []);
});

test("a stale session's sensitive call asks for the password, then is made again (mock)", async () => {
  const { fetch, advance } = clocked();
  const c = createClient({ fetch });
  await c.login(MOCK.email, MOCK.password);
  const key = { name: "k", kind: "api_key", scopes: ["envelopes:read"] };
  // Just signed in: served without asking.
  let asked = 0;
  c.setStepUp(async () => { asked += 1; await c.reauthenticate({ password: MOCK.password }); return true; });
  await c.apiClients.create(key);
  assert.equal(asked, 0);
  assert.ok((await c.session()).reauthenticated_until);
  // Six minutes later: asked once, and the call goes through.
  advance(6 * MIN);
  assert.equal((await c.session()).reauthenticated_until, null);
  const made = await c.apiClients.create(key);
  assert.equal(asked, 1);
  assert.ok(made.key);
  // Cancelled: the refusal stands, with its code.
  advance(6 * MIN);
  c.setStepUp(async () => false);
  await assert.rejects(c.apiClients.create(key), (e) => e.status === 403 && e.code === "CS-AUTH-0013" && e.detail === "reauthenticate");
  // Not sensitive: never asked.
  c.setStepUp(async () => { throw new Error("asked"); });
  await c.apiClients.list();
  // Without a handler the refusal is the caller's.
  c.setStepUp(null);
  await assert.rejects(c.endOtherSessions(), (e) => e.code === "CS-AUTH-0013");
});

test("a wrong password is refused and leaves the window closed (mock)", async () => {
  const { fetch, advance } = clocked();
  const c = createClient({ fetch });
  await c.login(MOCK.email, MOCK.password);
  advance(6 * MIN);
  await assert.rejects(c.reauthenticate({ password: "not the password" }), (e) => e.status === 401 && e.code === "CS-AUTH-0007");
  assert.equal((await c.session()).reauthenticated_until, null);
  await c.reauthenticate({ password: MOCK.password });
  assert.ok((await c.session()).reauthenticated_until);
});

test("the person lists their sessions, ends one and then the rest (mock)", async () => {
  const { fetch } = clocked();
  const c = createClient({ fetch });
  await c.login(MOCK.email, MOCK.password);
  const first = sessionRows((await c.sessions()).items);
  assert.equal(first.length, 3);
  assert.equal(first.filter((r) => r.current).length, 1);
  assert.equal(first[0].current, true);
  const other = first.find((r) => !r.current);
  await c.endSession(other.id);
  await assert.rejects(c.endSession(other.id), (e) => e.status === 404);
  await assert.rejects(c.endSession(first[0].id), (e) => e.status === 422, "not this session");
  const r = await c.endOtherSessions();
  assert.equal(r.ended, 1);
  assert.equal((await c.sessions()).items.length, 1);
});
