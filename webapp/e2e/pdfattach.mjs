// A one-page PDF with files attached as embedded files (WEB-02), for the Verify page's
// audit-trail timeline. Unsigned; cross-reference offsets correct.

/// `files`: `{name: string}` (contents as Latin-1 text, which JSON in ASCII is).
export function pdfWithAttachments(files) {
  const objs = [];
  const add = (s) => { objs.push(s); return objs.length; };
  const catalog = add(null);
  const pages = add(null);
  const ops = "BT /F1 12 Tf 72 720 Td (Attachment test) Tj ET";
  const content = add(`<< /Length ${ops.length} >>\nstream\n${ops}\nendstream`);
  const font = add("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>");
  const page = add(`<< /Type /Page /Parent ${pages} 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 ${font} 0 R >> >> /Contents ${content} 0 R >>`);
  const names = [];
  for (const [name, body] of Object.entries(files)) {
    const ef = add(`<< /Type /EmbeddedFile /Length ${Buffer.byteLength(body, "latin1")} >>\nstream\n${body}\nendstream`);
    const spec = add(`<< /Type /Filespec /F (${name}) /UF (${name}) /EF << /F ${ef} 0 R >> >>`);
    names.push(`(${name}) ${spec} 0 R`);
  }
  objs[catalog - 1] = `<< /Type /Catalog /Pages ${pages} 0 R /Names << /EmbeddedFiles << /Names [${names.join(" ")}] >> >> >>`;
  objs[pages - 1] = `<< /Type /Pages /Kids [${page} 0 R] /Count 1 >>`;
  let out = "%PDF-1.7\n";
  const offsets = [];
  objs.forEach((o, i) => { offsets.push(Buffer.byteLength(out, "latin1")); out += `${i + 1} 0 obj\n${o}\nendobj\n`; });
  const xref = Buffer.byteLength(out, "latin1");
  out += `xref\n0 ${objs.length + 1}\n0000000000 65535 f \n${offsets.map((o) => `${String(o).padStart(10, "0")} 00000 n \n`).join("")}`;
  out += `trailer\n<< /Size ${objs.length + 1} /Root ${catalog} 0 R >>\nstartxref\n${xref}\n%%EOF\n`;
  return Buffer.from(out, "latin1");
}
