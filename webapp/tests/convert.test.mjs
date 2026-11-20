// Word uploads (ADR-042, VS-06C): the editor's preview of a .docx (`POST /conversions`)
// and its upload, as the mock answers them; the server's own handling is tested in
// server/casual-sign-server/tests/convert.rs. Run: npm test (in webapp/).
import test from "node:test";
import assert from "node:assert/strict";

import { createMockFetch, MOCK } from "../mock.js";
import { createClient, isPdfBytes, isZipBytes, isUploadFile, docBaseName, UPLOAD_ACCEPT, DOCX_TYPE } from "../api.js";
import { countPages } from "../mockpdf.js";

const docx = () => new TextEncoder().encode("PK\u0003\u0004word/document.xml");
const docm = () => new TextEncoder().encode("PK\u0003\u0004word/vbaProject.bin");

async function client() {
  const c = createClient({ fetch: createMockFetch() });
  await c.login(MOCK.email, MOCK.password);
  return c;
}

test("an upload takes PDF and Word files, by type or name, and nothing else", () => {
  assert.ok(isUploadFile({ type: "application/pdf", name: "x" }));
  assert.ok(isUploadFile({ type: "", name: "Contract.DOCX" }));
  assert.ok(isUploadFile({ type: DOCX_TYPE, name: "x" }));
  assert.ok(!isUploadFile({ type: "application/vnd.ms-word.document.macroEnabled.12", name: "a.docm" }));
  assert.ok(!isUploadFile({ type: "image/png", name: "a.png" }));
  assert.ok(UPLOAD_ACCEPT.includes(".docx") && UPLOAD_ACCEPT.includes(".pdf"));
  assert.ok(isZipBytes(docx()) && !isPdfBytes(docx()));
  assert.equal(docBaseName("Lease.docx"), "Lease");
  assert.equal(docBaseName("Lease.pdf"), "Lease");
});

test("a Word document's preview is a PDF, and its upload gives a document of the same pages", async () => {
  const c = await client();
  const preview = await c.convertDocument(docx());
  assert.ok(isPdfBytes(preview));
  const env = await c.createEnvelope({ subject: "Word", documents: [{ name: "lease.docx", content_base64: Buffer.from(docx()).toString("base64") }], recipients: [] });
  assert.equal(env.documents[0].name, "lease.docx");
  assert.equal(env.documents[0].pages, countPages(preview), "the pages the fields were placed on");
  const added = await c.addDocument(env.id, "annex.docx", docx());
  assert.equal(added.pages, countPages(preview));
});

test("a macro-enabled document or a PDF is refused by the preview with the server's codes", async () => {
  const c = await client();
  await assert.rejects(c.convertDocument(docm()), (e) => e.code === "CS-CNV-0004");
  await assert.rejects(c.convertDocument(new TextEncoder().encode("%PDF-1.7")), (e) => e.code === "CS-CNV-0002");
});
