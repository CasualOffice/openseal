// Word uploads (ADR-042, owner instruction 76; VS-06C): a .docx is added in the send
// editor, converted to PDF for the pages shown, sent, and kept as the document's
// original; a macro-enabled one is refused with the server's message. Mock mode answers
// a placeholder PDF (mock.js `mockConvert`); against the Compose stack
// (OPENSEAL_E2E_BASE_URL) convertd converts it for real and the original is downloaded
// back as the Word document.
import { test, expect } from "@playwright/test";
import { signIn, app, placingFor, expectAccessible, REAL } from "./helpers.mjs";

/// CRC-32 (IEEE), for the ZIP entries below.
function crc32(bytes) {
  let c = ~0;
  for (const b of bytes) {
    c ^= b;
    for (let k = 0; k < 8; k++) c = (c >>> 1) ^ (0xedb88320 & -(c & 1));
  }
  return ~c >>> 0;
}

/// A ZIP of stored (uncompressed) entries.
function zip(entries) {
  const files = [];
  const central = [];
  let offset = 0;
  for (const [name, text] of entries) {
    const n = Buffer.from(name, "utf8");
    const data = Buffer.from(text, "utf8");
    const crc = crc32(data);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0); local.writeUInt16LE(20, 4); local.writeUInt16LE(0, 6); local.writeUInt16LE(0, 8);
    local.writeUInt32LE(0, 10); local.writeUInt32LE(crc, 14); local.writeUInt32LE(data.length, 18); local.writeUInt32LE(data.length, 22);
    local.writeUInt16LE(n.length, 26); local.writeUInt16LE(0, 28);
    files.push(local, n, data);
    const cd = Buffer.alloc(46);
    cd.writeUInt32LE(0x02014b50, 0); cd.writeUInt16LE(20, 4); cd.writeUInt16LE(20, 6); cd.writeUInt16LE(0, 8); cd.writeUInt16LE(0, 10);
    cd.writeUInt32LE(0, 12); cd.writeUInt32LE(crc, 16); cd.writeUInt32LE(data.length, 20); cd.writeUInt32LE(data.length, 24);
    cd.writeUInt16LE(n.length, 28); cd.writeUInt16LE(0, 30); cd.writeUInt16LE(0, 32); cd.writeUInt16LE(0, 34); cd.writeUInt16LE(0, 36);
    cd.writeUInt32LE(0, 38); cd.writeUInt32LE(offset, 42);
    central.push(cd, n);
    offset += 30 + n.length + data.length;
  }
  const cdBytes = Buffer.concat(central);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0); end.writeUInt16LE(entries.length, 8); end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(cdBytes.length, 12); end.writeUInt32LE(offset, 16);
  return Buffer.concat([...files, cdBytes, end]);
}

const W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main";
const para = (text) => `<w:p><w:r><w:t xml:space="preserve">${text}</w:t></w:r></w:p>`;

/// A Word document of two pages (a page break between them), as Word writes its parts.
function docxFile(name, title, extra = []) {
  const types = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
    + '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/>'
    + '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>';
  const rels = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
    + '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>';
  const body = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:document xmlns:w="${W}"><w:body>`
    + para(title) + para("This lease is between the parties named below.")
    + '<w:p><w:r><w:br w:type="page"/></w:r></w:p>' + para("Signed by the parties on the dates shown.")
    + '<w:sectPr><w:pgSz w:w="12240" w:h="15840"/><w:pgMar w:top="1440" w:right="1440" w:bottom="1440" w:left="1440" w:header="720" w:footer="720" w:gutter="0"/></w:sectPr></w:body></w:document>';
  return {
    name,
    mimeType: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    buffer: zip([["[Content_Types].xml", types], ["_rels/.rels", rels], ["word/document.xml", body], ...extra]),
  };
}

async function addRecipient(page, { name, email }) {
  await page.getByRole("button", { name: "Add recipient" }).first().click();
  const row = page.locator(".os-rcpt").first();
  await row.getByTestId("recipient-name").fill(name);
  await row.getByTestId("recipient-email").fill(email);
  await row.getByTestId("recipient-email").blur();
}

test("VS-06C: a Word document is converted in the editor, sent, and kept as the original; one with macros is refused", async ({ page }, testInfo) => {
  test.skip(!REAL && testInfo.project.name !== "chromium" && testInfo.project.name !== "webkit", "desktop browsers");
  test.setTimeout(REAL ? 180_000 : 90_000);
  const subject = `Lease from Word ${Date.now()}-${testInfo.project.name}`;
  await signIn(page);
  await page.goto(app("#/prepare"), { waitUntil: "domcontentloaded" });
  await expect(page.getByTestId("empty-documents")).toBeVisible();
  await expect(page.getByTestId("pdf-input")).toHaveAttribute("accept", /\.docx/);

  // A macro-enabled document: refused with the server's message, nothing added.
  await page.getByTestId("pdf-input").setInputFiles(docxFile("macro.docx", "Macro", [["word/vbaProject.bin", "VBA"]]));
  await expect(page.getByText("Word documents with macros are not accepted").first()).toBeVisible({ timeout: 30_000 });
  await expect(page.getByTestId("doc-card")).toHaveCount(0);

  // The Word document: converted for the pages shown, then placed and sent.
  await page.getByTestId("pdf-input").setInputFiles(docxFile("lease.docx", "Residential lease"));
  await expect(page.getByTestId("doc-card")).toHaveCount(1, { timeout: 30_000 });
  await expect(page.getByTestId("doc-card")).toContainText("lease.docx");
  if (REAL) await expect(page.getByTestId("doc-card")).toContainText("2 pages");
  if (!REAL) await expectAccessible(page, "editor with a converted Word document");
  await page.getByTestId("wizard-next").click();
  await addRecipient(page, { name: "Lee Lessee", email: `lee-${Date.now()}@example.com` });
  await page.getByTestId("wizard-next").click();
  await expect(page.locator(".os-page").first()).toBeVisible();
  await expect(page.locator(".os-page.is-loading")).toHaveCount(0);
  await placingFor(page, "1. Lee Lessee");
  await page.locator(".os-palette").getByRole("button", { name: "Add Signature field" }).press("Enter");
  await expect(page.locator(".os-field")).toHaveCount(1);
  await page.getByTestId("wizard-next").click();
  await page.getByLabel("Subject").fill(subject);
  await page.getByRole("button", { name: "Send", exact: true }).first().click();
  await page.getByRole("dialog", { name: "Send this envelope?" }).getByRole("button", { name: "Send" }).click();
  await expect(page.getByRole("heading", { name: "Recipients" })).toBeVisible({ timeout: 30_000 });
  await expect(page.locator(".os-page-head .os-badge")).toHaveText("Sent");

  if (REAL) {
    // The envelope's document: its original is the Word document, its delivered version
    // the converted PDF of two pages.
    const id = decodeURIComponent(new URL(page.url()).hash.split("/")[2] || "");
    const got = await page.evaluate(async (id) => {
      const env = await (await fetch(`/api/v1/envelopes/${encodeURIComponent(id)}`, { credentials: "same-origin" })).json();
      const d = env.documents[0];
      const original = await fetch(`/api/v1/envelopes/${encodeURIComponent(id)}/documents/${encodeURIComponent(d.id)}/content?version=original`, { credentials: "same-origin" });
      const head = new Uint8Array(await original.arrayBuffer()).slice(0, 4);
      return { name: d.name, pages: d.pages, type: original.headers.get("content-type"), head: [...head] };
    }, id);
    expect(got.name).toBe("lease.docx");
    expect(got.pages).toBe(2);
    expect(got.type).toBe("application/vnd.openxmlformats-officedocument.wordprocessingml.document");
    expect(got.head).toEqual([0x50, 0x4b, 3, 4]);
  }
});
