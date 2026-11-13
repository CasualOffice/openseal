// Organization admin (ORG-06): the pure rules (orgmodel.js) and the mock's
// `/organizations/me` routes as the client calls them. Run: npm test (in webapp/).
import test from "node:test";
import assert from "node:assert/strict";

import { createMockFetch, MOCK } from "../mock.js";
import { createClient } from "../api.js";
import { EN } from "../strings.en.js";
import { ORG_NAV, ORG_ACTIONS, orgRouteFrom, orgHref, orgCan, workspaceCounts, adminCounts, auditRow, filterAudit, shortId } from "../orgmodel.js";

async function signedIn() {
  const c = createClient({ fetch: createMockFetch() });
  await c.login(MOCK.email, MOCK.password);
  return c;
}

test("org nav: five pages, Overview by default, hrefs round-trip", () => {
  assert.deepEqual([...ORG_NAV], ["overview", "workspaces", "users", "admins", "audit"]);
  assert.equal(orgRouteFrom(new URLSearchParams("")), "overview");
  assert.equal(orgRouteFrom(new URLSearchParams("section=nope")), "overview");
  for (const id of ORG_NAV) assert.equal(orgRouteFrom(new URLSearchParams(orgHref(id).split("?")[1] || "")), id);
  for (const id of ORG_NAV) assert.ok(`admin.org.nav.${id}` in EN, id);
  for (const a of ORG_ACTIONS) assert.ok(`admin.org.act.${a}` in EN, a);
});

test("org roles: owners manage admins, admins do not, delegated and unknown only read", () => {
  assert.ok(orgCan("owner", "admins"));
  assert.ok(orgCan("admin", "workspaces") && !orgCan("admin", "admins"));
  assert.ok(orgCan("delegated", "read") && !orgCan("delegated", "workspaces"));
  assert.ok(!orgCan("superuser", "read") && !orgCan(null, "read"));
});

test("org counts and audit rows tolerate missing data", () => {
  assert.deepEqual(workspaceCounts([{ status: "active" }, { status: "archived" }, null]), { active: 2, archived: 1, total: 3 });
  assert.deepEqual(adminCounts([{ role: "owner" }, { role: "admin" }, { role: "x" }]), { owner: 1, admin: 1, delegated: 0 });
  const r = auditRow({ seq: 3, at: "2026-11-13T00:00:00Z", action: "workspace.created", event: { actor: { kind: "user", id: "u1" }, target: { workspace: "w1" }, changes: [{ key: "name", old: null, new: "x" }, { nokey: 1 }] } });
  assert.equal(r.known, true);
  assert.deepEqual(r.targets, [["workspace", "w1"]]);
  assert.equal(r.changes.length, 1);
  assert.equal(auditRow({ action: "future.thing" }).known, false);
  assert.deepEqual(auditRow(null).targets, []);
  assert.deepEqual(filterAudit([r], "W1").length, 1);
  assert.deepEqual(filterAudit([r], "ana", (id) => (id === "u1" ? "Ana" : "")).length, 1);
  assert.deepEqual(filterAudit([r], "zzz").length, 0);
  assert.equal(shortId("0123456789abcdef"), "01234567…");
});

test("mock org routes: owner role, create, join, archive, admins, last owner, chained log", async () => {
  const c = await signedIn();
  const o = await c.org.get();
  assert.equal(o.role, "owner");
  assert.equal((await c.org.rename("Acme")).name, "Acme");
  const w = await c.org.createWorkspace("Finance");
  await c.org.joinWorkspace(w.id, "sender");
  assert.ok((await c.workspaces()).organizations[0].workspaces.some((x) => x.id === w.id));
  assert.equal((await c.org.archiveWorkspace(w.id)).status, "archived");
  await assert.rejects(c.org.joinWorkspace(w.id, "admin"), (e) => e.status === 409 && e.code === "CS-ORG-0010");
  await assert.rejects(c.org.addAdmin("user-demo", "admin"), (e) => e.code === "CS-ORG-0005");
  await assert.rejects(c.org.addAdmin("nobody", "admin"), (e) => e.status === 422 && e.code === "CS-ORG-0018");
  await c.org.addAdmin("user-robin", "admin");
  assert.equal((await c.org.setAdminRole("user-robin", "owner")).role, "owner");
  await c.org.removeAdmin("user-robin");
  await assert.rejects(c.org.removeAdmin("user-demo"), (e) => e.status === 409 && e.code === "CS-ORG-0008");
  const log = await c.org.audit();
  assert.deepEqual(log.items.map((e) => e.action), [
    "organization.created", "organization.renamed", "workspace.created", "org.workspace_joined", "workspace.archived",
    "organization.admin_added", "organization.admin_role_changed", "organization.admin_removed",
  ]);
  for (let i = 1; i < log.items.length; i++) assert.equal(log.items[i].prev, log.items[i - 1].hash);
  const page = await c.org.audit({ limit: 3 });
  assert.equal(page.next_cursor, 2);
  assert.equal((await c.org.audit({ cursor: page.next_cursor, limit: 100 })).items[0].seq, 3);
});
