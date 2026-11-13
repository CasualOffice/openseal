// Bulk send from a template (UXW-04): the list's columns, a sample CSV to fill in,
// reading CSV as the server reads it (RFC 4180), each row's check, and the progress of a
// batch. Pure functions: the screen (bulk.js) and the mock (mock.js) share them, and
// the server's own check (`POST /bulk-sends` with `validate_only`) is the one that counts.

/// The most rows one bulk send takes (docs/21).
export const MAX_ROWS = 1000;

/// A template's columns: two per role, in role order (`<role>::name`, `<role>::email`).
export function columnsOf(roles) {
  return (roles || []).flatMap((r) => [`${r.name}::name`, `${r.name}::email`]);
}

/// One CSV value, quoted when it has a comma, a quote or a line break.
export function csvCell(v) {
  const s = String(v ?? "");
  return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

/// A sample list for a template: its header and one example row.
export function sampleCsv(roles) {
  const cols = columnsOf(roles);
  const example = (roles || []).flatMap((r, i) => [`${r.name} ${i + 1}`, `person${i + 1}@example.com`]);
  return `${cols.map(csvCell).join(",")}\r\n${example.map(csvCell).join(",")}\r\n`;
}

/// RFC 4180 records: commas, double-quoted values with `""` for a quote, CRLF or LF
/// line ends, a leading byte-order mark ignored, lines with no value in any cell skipped. `null` when a quote
/// is never closed or there are more than `max` records.
export function csvRecords(text, max = MAX_ROWS + 1) {
  const src = String(text ?? "").replace(/^﻿/, "");
  const out = [];
  let record = [];
  let cell = "";
  let quoted = false;
  const finish = () => {
    // A line of empty cells (",,," as a spreadsheet writes its unused rows) is blank.
    const blank = record.every((c) => !c.trim());
    if (!blank) {
      if (out.length >= max) return false;
      out.push(record);
    }
    record = [];
    return true;
  };
  for (let i = 0; i < src.length; i++) {
    const ch = src[i];
    if (quoted) {
      if (ch === '"') {
        if (src[i + 1] === '"') { cell += '"'; i++; } else quoted = false;
      } else cell += ch;
      continue;
    }
    if (ch === '"' && cell === "") quoted = true;
    else if (ch === ",") { record.push(cell); cell = ""; }
    else if (ch === "\r" && src[i + 1] === "\n") { /* the \n ends it */ }
    else if (ch === "\n" || ch === "\r") { record.push(cell); cell = ""; if (!finish()) return null; }
    else cell += ch;
  }
  if (quoted) return null;
  if (cell !== "" || record.length) { record.push(cell); if (!finish()) return null; }
  return out;
}

const badEmail = (e) => {
  const parts = e.split("@");
  return parts.length !== 2 || !parts[0] || !parts[1] || new TextEncoder().encode(e).length > 320 || /[\s\p{Cc}]/u.test(e);
};
const badName = (n) => [...n].length > 255 || /\p{Cc}/u.test(n);

/// Check a list against a template's roles, as the server does: `{columns, rows}` with
/// each row `{row, status: "pending" | "failed", recipients, problems}`, or `{error:
/// {pointer, code}[]}` when the whole list is refused (`CS-BLK-0004`, `0005`, `0007`).
export function checkList(roles, { csv, rows } = {}) {
  const columns = columnsOf(roles);
  const key = (s) => String(s).trim().toLowerCase();
  const want = new Map(columns.map((c, i) => [key(c), i]));
  const place = (header, at) => {
    const seen = new Set();
    const map = [];
    const errors = [];
    header.forEach((h, i) => {
      const k = want.get(key(h));
      if (k === undefined || seen.has(k)) { errors.push({ pointer: `${at}/${i}`, code: "CS-BLK-0005" }); map.push(null); } else { seen.add(k); map.push(k); }
    });
    if (seen.size < columns.length) errors.push({ pointer: "/columns", code: "CS-BLK-0004" });
    return { map, errors };
  };
  const spread = (map, cells) => {
    const out = columns.map(() => "");
    cells.forEach((c, j) => { if (map[j] != null) out[map[j]] = c; });
    return out;
  };
  let list;
  if (typeof csv === "string" && rows == null) {
    const recs = csvRecords(csv);
    if (!recs || !recs.length) return { error: [{ pointer: "/csv", code: "CS-BLK-0007" }] };
    const [header, ...body] = recs;
    const { map, errors } = place(header, "/columns");
    if (errors.length) return { error: errors };
    list = body.map((cells) => ({ values: spread(map, cells), shape: cells.length <= header.length }));
  } else if (Array.isArray(rows) && csv == null) {
    if (rows.length > MAX_ROWS) return { error: [{ pointer: "/rows", code: "CS-BLK-0007" }] };
    list = [];
    for (const [i, r] of rows.entries()) {
      const keys = Object.keys(r || {}).sort();
      const { map, errors } = place(keys, `/rows/${i}`);
      if (errors.length) return { error: errors };
      list.push({ values: spread(map, keys.map((k) => String(r[k] ?? ""))), shape: true });
    }
  } else return { error: [{ pointer: "/csv", code: "CS-API-0001" }] };
  if (!list.length || list.length > MAX_ROWS) return { error: [{ pointer: csv != null ? "/csv" : "/rows", code: "CS-BLK-0007" }] };
  return {
    columns,
    rows: list.map(({ values, shape }, row) => {
      const problems = shape ? [] : [{ column: null, code: "CS-BLK-0006" }];
      const recipients = (roles || []).map((r, i) => {
        const name = (values[2 * i] || "").trim();
        const email = (values[2 * i + 1] || "").trim();
        const np = !name ? "CS-BLK-0001" : badName(name) ? "CS-BLK-0003" : null;
        const ep = !email ? "CS-BLK-0001" : badEmail(email) ? "CS-BLK-0002" : null;
        if (np) problems.push({ column: columns[2 * i], code: np });
        if (ep) problems.push({ column: columns[2 * i + 1], code: ep });
        return { role: r.name, name, email };
      });
      return { row, status: problems.length ? "failed" : "pending", recipients, problems };
    }),
  };
}

/// How far a batch is: `{done, total, percent}`, rows settled out of all rows.
export function progressOf(b) {
  const c = b?.counts || {};
  const total = Number(b?.row_count) || 0;
  const done = (c.sent || 0) + (c.failed || 0) + (c.cancelled || 0);
  return { done, total, percent: total ? Math.round((done * 100) / total) : 0 };
}

/// Whether a batch still has rows to send.
export const sending = (b) => !!b && ["queued", "sending"].includes(b.status) && (b.counts?.pending || 0) > 0;
