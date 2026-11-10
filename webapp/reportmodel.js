// Report figures (WEB-02 Reports). Pure: no DOM, so Node tests it.

/// `{status: n}` over envelope summaries.
export function statusCounts(rows) {
  const out = {};
  for (const r of rows || []) out[r.status] = (out[r.status] || 0) + 1;
  return out;
}

/// Median hours from `sent_at` to `ended_at` over completed envelopes, to one decimal;
/// null when none has both times.
export function medianHours(envelopes) {
  const hours = (envelopes || [])
    .map((e) => (Date.parse(e?.ended_at) - Date.parse(e?.sent_at)) / 3_600_000)
    .filter((x) => Number.isFinite(x) && x >= 0)
    .sort((a, b) => a - b);
  if (!hours.length) return null;
  const mid = Math.floor(hours.length / 2);
  const m = hours.length % 2 ? hours[mid] : (hours[mid - 1] + hours[mid]) / 2;
  return Math.round(m * 10) / 10;
}

/// RFC 4180 CSV with a header row from the first object's keys. A cell that starts
/// with = + - @ is prefixed with ' so a spreadsheet never runs it as a formula
/// (CSV injection, OWASP).
export function toCsv(objects) {
  if (!objects?.length) return "";
  const keys = Object.keys(objects[0]);
  const cell = (v) => {
    let s = v == null ? "" : String(v);
    if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
    return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
  };
  return [keys.join(","), ...objects.map((o) => keys.map((k) => cell(o[k])).join(","))].join("\r\n") + "\r\n";
}
