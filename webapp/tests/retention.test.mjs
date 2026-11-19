// ASVS-16 and ASVS-18 in the web app: the retention rules' pure model, and the client's
// calls for the personal-data export, erasure and retention against the mock (which
// answers as the server's `tests/privacy.rs` shows it does). Run: npm test (in webapp/).
import test from "node:test";
import assert from "node:assert/strict";

import { createMockFetch, MOCK } from "../mock.js";
import { createClient } from "../api.js";
import { CLASSES, parseDays, daysText, rulesPatch, previewLines } from "../retentionmodel.js";

test("days are whole numbers from 1 to the maximum, or empty for kept for ever", () => {
  assert.deepEqual(parseDays(""), { ok: true, days: null });
  assert.deepEqual(parseDays("  30 "), { ok: true, days: 30 });
  for (const bad of ["0", "-1", "1.5", "abc", "36501", "1e3"]) assert.equal(parseDays(bad).ok, false, bad);
  assert.equal(parseDays("366", 365).ok, false);
  assert.equal(daysText(null), "");
  assert.equal(daysText(90), "90");
});

test("only changed rules are sent, and a bad field names its class", () => {
  const stored = { draft: 90, ended: null, completed: null, sessions: 30 };
  assert.deepEqual(rulesPatch(stored, { draft: "90", ended: "30", completed: "", sessions: "" }),
    { patch: { ended: 30, sessions: null } });
  assert.deepEqual(rulesPatch(stored, { draft: "x", ended: "", completed: "0", sessions: "30" }), { bad: ["draft", "completed"] });
  assert.deepEqual(CLASSES, ["draft", "ended", "completed", "sessions"]);
});

test("the dry run reads as one line per class, then sessions and holds", () => {
  const lines = previewLines({ counts: { draft: 1, ended: 2, completed: 0 }, sessions: 4, held: 1 });
  assert.deepEqual(lines.map((l) => [l.key, l.n]), [["draft", 1], ["ended", 2], ["completed", 0], ["sessions", 4], ["held", 1]]);
});

test("export, erasure refusal and retention rules through the client", async () => {
  const c = createClient({ fetch: createMockFetch() });
  await c.login(MOCK.email, MOCK.password);
  const x = await c.exportMe();
  assert.equal(x.format, "openseal.personal-data-export");
  assert.equal(x.user.email, MOCK.email);
  await c.exportMe();
  await c.exportMe();
  await assert.rejects(c.exportMe(), (e) => e.status === 429);
  await assert.rejects(c.eraseMe(), (e) => e.code === "CS-API-0018");
  const r0 = await c.retention();
  assert.deepEqual(r0.keep_days, { draft: null, ended: null, completed: null, sessions: null });
  const r1 = await c.setRetention({ ended: 30 });
  assert.equal(r1.keep_days.ended, 30);
  await assert.rejects(c.setRetention({ bogus: 3 }), (e) => e.status === 422);
  const p = await c.retentionPreview();
  assert.ok("counts" in p && "held" in p);
});
