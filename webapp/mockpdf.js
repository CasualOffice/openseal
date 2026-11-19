// A tiny PDF writer for mock mode and tests (WEB-01): text pages in Helvetica, a
// correct cross-reference table, nothing else. It stands in for documents the mock
// "server" holds; the real server's documents come from the PDF engine.

const enc = new TextEncoder();

function esc(s) {
  return String(s).replace(/[—–]/g, "-").replace(/[^\x20-\x7e]/g, "?").replace(/[\\()]/g, "\\$&");
}

/// A PDF with one page per entry: `{title, lines, width = 612, height = 792, form}`.
/// Text starts at the top-left margin; a signature line is drawn near the bottom.
export function makePdf(pages) {
  const objs = [];
  const add = (s) => { objs.push(s); return objs.length; };
  const catalog = add(null);
  const pagesObj = add(null);
  const font = add("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>");
  const bold = add("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>");
  const kids = [];
  const fields = [];
  for (const p of pages) {
    const w = p.width || 612;
    const hgt = p.height || 792;
    let ops = `BT /F2 18 Tf 72 ${hgt - 90} Td (${esc(p.title || "")}) Tj ET\n`;
    let y = hgt - 130;
    for (const line of p.lines || []) {
      ops += `BT /F1 11 Tf 72 ${y} Td (${esc(line)}) Tj ET\n`;
      y -= 18;
    }
    ops += `0.6 G 1 w 72 150 m 300 150 l S 340 150 m 520 150 l S\n`;
    ops += `BT /F1 9 Tf 72 136 Td (Signature) Tj ET BT /F1 9 Tf 340 136 Td (Date) Tj ET\n`;
    const content = add(`<< /Length ${enc.encode(ops).length} >>\nstream\n${ops}endstream`);
    // VS-04F: the page's own form fields, `{name, type: text | checkbox | signature,
    // rect: [x1, y1, x2, y2]}` in PDF user space, as AcroForm widgets (no /P: viewers
    // and the engine find the page through /Annots).
    const widgets = (p.form || []).map((f) => add(`<< /Type /Annot /Subtype /Widget /FT /${{ checkbox: "Btn", signature: "Sig" }[f.type] || "Tx"} /T (${esc(f.name)}) /Rect [${f.rect.join(" ")}] /F 4 >>`));
    fields.push(...widgets);
    const annots = widgets.length ? ` /Annots [${widgets.map((x) => `${x} 0 R`).join(" ")}]` : "";
    kids.push(add(`<< /Type /Page /Parent ${pagesObj} 0 R /MediaBox [0 0 ${w} ${hgt}] /Resources << /Font << /F1 ${font} 0 R /F2 ${bold} 0 R >> >> /Contents ${content} 0 R${annots} >>`));
  }
  const acro = fields.length ? ` /AcroForm << /Fields [${fields.map((x) => `${x} 0 R`).join(" ")}] >>` : "";
  objs[catalog - 1] = `<< /Type /Catalog /Pages ${pagesObj} 0 R${acro} >>`;
  objs[pagesObj - 1] = `<< /Type /Pages /Kids [${kids.map((k) => `${k} 0 R`).join(" ")}] /Count ${kids.length} >>`;

  let out = "%PDF-1.7\n%\xe2\xe3\xcf\xd3\n";
  const offsets = [];
  const parts = [];
  let length = 0;
  const push = (s) => { const b = latin1(s); parts.push(b); length += b.length; };
  push(out);
  objs.forEach((o, i) => { offsets.push(length); push(`${i + 1} 0 obj\n${o}\nendobj\n`); });
  const xref = length;
  let table = `xref\n0 ${objs.length + 1}\n0000000000 65535 f \n`;
  for (const off of offsets) table += `${String(off).padStart(10, "0")} 00000 n \n`;
  push(`${table}trailer\n<< /Size ${objs.length + 1} /Root ${catalog} 0 R >>\nstartxref\n${xref}\n%%EOF\n`);
  const bytes = new Uint8Array(length);
  let at = 0;
  for (const p of parts) { bytes.set(p, at); at += p.length; }
  return bytes;
}

function latin1(s) {
  const b = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) b[i] = s.charCodeAt(i) & 0xff;
  return b;
}

/// The page count of a PDF this module wrote (or any PDF with a plain `/Count`): for
/// the mock's document records. Not a parser; the real server uses the engine.
export function countPages(bytes) {
  const s = new TextDecoder("latin1").decode(bytes.subarray(0, Math.min(bytes.length, 4 << 20)));
  const m = [...s.matchAll(/\/Type\s*\/Pages\b[^>]*?\/Count\s+(\d+)/g)];
  if (m.length) return Number(m[m.length - 1][1]);
  const n = (s.match(/\/Type\s*\/Page\b(?!s)/g) || []).length;
  return n || 1;
}
