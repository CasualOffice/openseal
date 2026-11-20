// Insights (FG-141): the dashboard's figures from `GET /insights`, made drawable by
// insightsmodel.js, and the mock answering as the server. Run: node --test webapp/tests/
import test from "node:test";
import assert from "node:assert/strict";

import { completionRate, duration, series, weekOf, windowDays, niceMax, seriesCsvRows, WEEKLY_AFTER, MAX_POINTS } from "../insightsmodel.js";
import { createMockFetch, MOCK } from "../mock.js";
import { createClient } from "../api.js";

test("the completion rate is completed over sent, none when nothing was sent", () => {
  assert.equal(completionRate({ sent: 8, completed: 6 }), 75);
  assert.equal(completionRate({ sent: 3, completed: 1 }), 33);
  assert.equal(completionRate({ sent: 0, completed: 0 }), null);
  assert.equal(completionRate(null), null);
});

test("durations read in minutes, hours or days", () => {
  assert.deepEqual(duration(59), { n: 1, unit: "minutes" });
  assert.deepEqual(duration(1800), { n: 30, unit: "minutes" });
  assert.deepEqual(duration(10_800), { n: 3, unit: "hours" });
  assert.deepEqual(duration(33_840), { n: 9.4, unit: "hours" });
  assert.deepEqual(duration(3 * 86_400 + 43_200), { n: 3.5, unit: "days" });
  assert.equal(duration(null), null);
  assert.equal(duration(-5), null);
});

test("the series fills every day of the window with zeros", () => {
  const s = series([{ day: "2026-11-02", sent: 2, completed: 1 }, { day: "2026-11-05", sent: 1, completed: 0 }], { first: "2026-11-01", last: "2026-11-06" });
  assert.equal(s.unit, "day");
  assert.deepEqual(s.points.map((p) => p.day), ["2026-11-01", "2026-11-02", "2026-11-03", "2026-11-04", "2026-11-05", "2026-11-06"]);
  assert.deepEqual(s.points.map((p) => p.sent), [0, 2, 0, 0, 1, 0]);
  assert.deepEqual(s.points.map((p) => p.completed), [0, 1, 0, 0, 0, 0]);
  // Without bounds, from the first day to the last present.
  assert.equal(series([{ day: "2026-11-03", sent: 1, completed: 0 }, { day: "2026-11-01", sent: 1, completed: 1 }]).points.length, 3);
  assert.deepEqual(series([]).points, []);
  // Malformed days are ignored, never thrown on.
  assert.deepEqual(series([{ day: "nope", sent: 1 }]).points, []);
});

test("a long window is drawn by week, Monday first, and capped", () => {
  assert.equal(weekOf("2026-11-04"), "2026-11-02"); // a Wednesday → its Monday
  assert.equal(weekOf("2026-11-02"), "2026-11-02");
  assert.equal(weekOf("2026-11-08"), "2026-11-02"); // Sunday
  const days = [{ day: "2026-01-05", sent: 3, completed: 1 }, { day: "2026-01-07", sent: 2, completed: 2 }, { day: "2026-06-01", sent: 1, completed: 0 }];
  const s = series(days, { first: "2026-01-01", last: "2026-06-30" });
  assert.equal(s.unit, "week");
  const jan5 = s.points.find((p) => p.day === "2026-01-05");
  assert.deepEqual(jan5, { day: "2026-01-05", sent: 5, completed: 3 });
  assert.equal(s.points.reduce((a, p) => a + p.sent, 0), 6);
  // Exactly WEEKLY_AFTER days stays daily; one more goes weekly.
  const end = (n) => new Date(Date.parse("2026-01-01T00:00:00Z") + (n - 1) * 86_400_000).toISOString().slice(0, 10);
  assert.equal(series([], { first: "2026-01-01", last: end(WEEKLY_AFTER) }).unit, "day");
  assert.equal(series([], { first: "2026-01-01", last: end(WEEKLY_AFTER + 1) }).unit, "week");
  // An open window from 1970 keeps the newest points only, and stops quickly.
  const open = series([{ day: "2026-11-01", sent: 1, completed: 1 }], { first: "1970-01-01", last: "2026-11-01" });
  assert.equal(open.points.length, MAX_POINTS);
  assert.equal(open.points.at(-1).sent, 1);
});

test("the window's days follow the caller's offset", () => {
  const now = Date.parse("2026-11-20T23:30:00Z");
  assert.deepEqual(windowDays({ from: "2026-11-01T00:00:00Z", to: "2026-11-08T00:00:00Z" }, 0, now), { first: "2026-11-01", last: "2026-11-07" });
  assert.deepEqual(windowDays({}, 60, now), { first: null, last: "2026-11-21" });
});

test("the axis rounds up to 1, 2 or 5 times a power of ten", () => {
  assert.deepEqual([0, 1, 3, 7, 12, 99, 101, 450].map(niceMax), [1, 1, 5, 10, 20, 100, 200, 500]);
});

test("the series exports one row per day or week", () => {
  assert.deepEqual(seriesCsvRows({ unit: "day", points: [{ day: "2026-11-01", sent: 1, completed: 0 }] }), [{ day: "2026-11-01", sent: 1, completed: 0 }]);
  assert.deepEqual(Object.keys(seriesCsvRows({ unit: "week", points: [{ day: "2026-11-02", sent: 1, completed: 0 }] })[0]), ["week_of", "sent", "completed"]);
});

test("the mock answers GET /insights as the server: counts, continuous percentiles, days in the caller's day, senders", async () => {
  const store = new Map();
  const sessionLike = { getItem: (k) => store.get(k) ?? null, setItem: (k, v) => store.set(k, String(v)), removeItem: (k) => store.delete(k) };
  const c = createClient({ fetch: createMockFetch({ store: sessionLike }), store: sessionLike });
  await c.login(MOCK.email, MOCK.password);
  const before = await c.insights({});
  assert.equal(before.scope, "workspace");
  // Three envelopes completed in 1, 3 and 11 hours, sent on 2026-11-01 at 10:00 UTC.
  const db = JSON.parse(store.get("openseal.mock.v1"));
  const base = { sender_user_id: "user-demo", recipients: [], documents: [], fields: [], created_at: "2026-11-01T09:00:00.000Z", sent_at: "2026-11-01T10:00:00.000Z" };
  for (const [i, h] of [[1, 1], [2, 3], [3, 11]]) db.envelopes.push({ ...base, id: `ins-${i}`, subject: "x", status: "completed", ended_at: `2026-11-01T${String(10 + h).padStart(2, "0")}:00:00.000Z` });
  store.set("openseal.mock.v1", JSON.stringify(db));
  const c2 = createClient({ fetch: createMockFetch({ store: sessionLike }), store: sessionLike });
  const win = { from: "2026-11-01T00:00:00Z", to: "2026-11-02T00:00:00Z" };
  const v = await c2.insights(win);
  assert.deepEqual(v.totals, { created: 3, sent: 3, completed: 3, declined: 0, voided: 0, expired: 0, in_progress: 0 });
  assert.equal(v.time_to_complete.median_seconds, 10_800);
  assert.equal(v.time_to_complete.p90_seconds, 33_840);
  assert.deepEqual(v.days, [{ day: "2026-11-01", sent: 3, completed: 3 }]);
  const east = await c2.insights({ ...win, utc_offset_minutes: 180 });
  assert.deepEqual(east.days, [{ day: "2026-11-01", sent: 3, completed: 2 }, { day: "2026-11-02", sent: 0, completed: 1 }]);
  assert.deepEqual(v.top_senders, [{ sender_user_id: "user-demo", sent: 3, completed: 3 }]);
  await assert.rejects(c2.insights({ utc_offset_minutes: 900 }), (e) => e.status === 422);
});
