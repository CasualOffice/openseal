// Bulk send from a template (UXW-04): reading and checking a CSV list as the server
// does, the calls api.js makes, and the mock sending a batch to the end. Run: npm test.
import test from "node:test";
import assert from "node:assert/strict";

import { createMockFetch, MOCK } from "../mock.js";
import { createClient } from "../api.js";
import { makePdf } from "../mockpdf.js";
import { csvRecords, csvCell, sampleCsv, checkList, columnsOf, progressOf, sending } from "../bulkmodel.js";

const ROLES = [{ name: "Tenant", type: "signer", routing_order: 1 }, { name: "Landlord", type: "signer", routing_order: 2 }];
const CSV = "Tenant::name,Tenant::email,Landlord::name,Landlord::email\r\n"
  + "Ann Lee,ann@example.test,Lou Park,lou@example.test\r\n"
  + "\"Bo, Jr.\",bo@example.test,Lou Park,lou@example.test\r\n"
  + "Cy Moe,not-an-email,Lou Park,lou@example.test\r\n"
  + ",dee@example.test,Lou Park,lou@example.test\r\n";

test("CSV is read as the server reads it: quotes, CRLF, a BOM, blank lines; an open quote is refused", () => {
  assert.deepEqual(csvRecords("﻿a,\"b, \"\"c\"\"\"\r\n\r\nx,y\n"), [["a", "b, \"c\""], ["x", "y"]]);
  assert.equal(csvRecords("a,\"b\n"), null);
  assert.equal(csvRecords("a\nb\nc\n", 2), null);
  assert.equal(csvCell("Bo, \"Jr\""), "\"Bo, \"\"Jr\"\"\"");
  const sample = sampleCsv(ROLES);
  assert.deepEqual(csvRecords(sample)[0], columnsOf(ROLES));
  assert.equal(checkList(ROLES, { csv: sample }).rows[0].status, "pending", "the sample checks clean");
});

test("each row is checked with its column and code; a header that does not fit refuses the list", () => {
  const c = checkList(ROLES, { csv: CSV });
  assert.deepEqual(c.rows.map((r) => r.status), ["pending", "pending", "failed", "failed"]);
  assert.deepEqual(c.rows[1].recipients[0], { role: "Tenant", name: "Bo, Jr.", email: "bo@example.test" });
  assert.deepEqual(c.rows[2].problems, [{ column: "Tenant::email", code: "CS-BLK-0002" }]);
  assert.deepEqual(c.rows[3].problems, [{ column: "Tenant::name", code: "CS-BLK-0001" }]);
  assert.deepEqual(checkList(ROLES, { csv: "Tenant::name,Tenant::email,Owner::email\nA,a@x.test,b@x.test\n" }).error,
    [{ pointer: "/columns/2", code: "CS-BLK-0005" }, { pointer: "/columns", code: "CS-BLK-0004" }]);
  assert.deepEqual(checkList(ROLES, { csv: `${columnsOf(ROLES).join(",")}\n` }).error, [{ pointer: "/csv", code: "CS-BLK-0007" }]);
  assert.equal(checkList(ROLES, { csv: "TENANT::Name ,Tenant::email,Landlord::name,Landlord::email\nA,a@x.test,L,l@x.test,extra\n" }).rows[0].problems[0].code, "CS-BLK-0006");
});

test("progress counts settled rows", () => {
  const b = { status: "sending", row_count: 4, counts: { pending: 1, sent: 2, failed: 1, cancelled: 0 } };
  assert.deepEqual(progressOf(b), { done: 3, total: 4, percent: 75 });
  assert.equal(sending(b), true);
  assert.equal(sending({ ...b, status: "cancelled" }), false);
});

test("the bulk calls reach the server as it serves them", async () => {
  const seen = [];
  const fake = async (url, init = {}) => {
    seen.push(`${init.method || "GET"} ${url} ${init.body || ""}`.trim());
    return new Response(JSON.stringify({ items: [] }), { status: 200 });
  };
  const c = createClient({ fetch: fake });
  await c.bulk.list();
  await c.bulk.check("t1", { csv: "x" });
  await c.bulk.create("t1", { csv: "x" }, "Spring");
  await c.bulk.get("b1");
  await c.bulk.send("b1");
  await c.bulk.cancel("b1");
  assert.deepEqual(seen, [
    "GET /api/v1/bulk-sends",
    "POST /api/v1/bulk-sends {\"template_id\":\"t1\",\"csv\":\"x\",\"validate_only\":true}",
    "POST /api/v1/bulk-sends {\"template_id\":\"t1\",\"csv\":\"x\",\"name\":\"Spring\"}",
    "GET /api/v1/bulk-sends/b1",
    "POST /api/v1/bulk-sends/b1/send",
    "POST /api/v1/bulk-sends/b1/cancel",
  ]);
});

test("the mock checks a list, sends a batch to the end as envelopes from the template, and cancels another", async () => {
  const c = createClient({ fetch: createMockFetch() });
  await c.login(MOCK.email, MOCK.password);
  const tp = await c.templates.create({ name: "Lease", email_subject: "Please sign the lease", roles: ROLES });
  const withDoc = await c.templates.addDocument(tp.id, "lease.pdf", makePdf([{ title: "Lease" }]));
  const doc = withDoc.documents[0].id;
  await c.templates.addFields(tp.id, withDoc.roles.map((r, i) => ({ role_id: r.id, document_id: doc, type: "signature", required: true, placement: { page: 1, x: "72", y: String(100 + 100 * i), width: "160", height: "36" } })));
  const checked = await c.bulk.check(tp.id, { csv: CSV });
  assert.equal(checked.valid, 2);
  await assert.rejects(c.bulk.check(tp.id, { csv: "Tenant::name\nA\n" }), (e) => e.status === 422 && e.errors.some((x) => x.code === "CS-BLK-0004"));
  let b = await c.bulk.create(tp.id, { csv: CSV }, "Spring leases");
  assert.equal(b.status, "queued");
  assert.deepEqual(b.counts, { pending: 2, sent: 0, failed: 2, cancelled: 0 });
  while (sending(b)) b = await c.bulk.send(b.id);
  assert.equal(b.status, "completed");
  assert.deepEqual(b.counts, { pending: 0, sent: 2, failed: 2, cancelled: 0 });
  const { envelope } = await c.getEnvelope(b.rows[1].envelope_id);
  assert.equal(envelope.status, "sent");
  assert.equal(envelope.subject, "Please sign the lease");
  assert.deepEqual(envelope.recipients.map((r) => [r.name, r.routing_order]), [["Bo, Jr.", 1], ["Lou Park", 2]]);
  assert.equal(envelope.fields.length, 2);
  const other = await c.bulk.create(tp.id, { csv: CSV });
  const stopped = await c.bulk.cancel(other.id);
  assert.equal(stopped.status, "cancelled");
  assert.equal(stopped.counts.cancelled, 2);
  await assert.rejects(c.bulk.cancel(other.id), (e) => e.status === 409);
  assert.deepEqual((await c.bulk.list()).items.map((x) => x.id), [other.id, b.id]);
});
