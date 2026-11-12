// Report figures (WEB-02 Reports). Pure: no DOM, so Node tests it.

/// `{status: n}` over envelope summaries.
export function statusCounts(rows) {
  const out = {};
  for (const r of rows || []) out[r.status] = (out[r.status] || 0) + 1;
  return out;
}

/// Median hours from `sent_at` to completion over completed envelopes, to one decimal;
/// null when none has both times. Completion is the list summary's `completed_at`
/// (UX-08), or a full envelope's `ended_at`.
export function medianHours(envelopes) {
  const hours = (envelopes || [])
    .map((e) => (Date.parse(e?.completed_at || e?.ended_at) - Date.parse(e?.sent_at)) / 3_600_000)
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

/// Whether a list summary carries its completion time (the server's does, UX-08), so
/// the median needs no read per envelope.
export const hasTimes = (r) => r != null && "sent_at" in r && "completed_at" in r;

/// The rows created in a period (UX-08): `range` "all", a number of days ("7", "30", …)
/// back from `now` (ms), or "custom" with `from` and `to` as yyyy-mm-dd, inclusive local
/// days, either one open.
export function inWindow(rows, { range = "all", from = "", to = "" } = {}, now = Date.now()) {
  if (range === "all") return rows;
  if (range === "custom") {
    const lo = from ? new Date(`${from}T00:00:00`).getTime() : -Infinity;
    const hi = to ? new Date(`${to}T00:00:00`).getTime() + 86_400_000 : Infinity;
    return rows.filter((r) => { const at = Date.parse(r.created_at); return at >= lo && at < hi; });
  }
  const since = now - Number(range) * 86_400_000;
  return rows.filter((r) => Date.parse(r.created_at) >= since);
}

/// The CSV's rows (UX-08): every summary field the list gives, the sender by name or
/// email where `senderName(id)` knows it, else the id.
export function csvRows(rows, senderName = () => "") {
  return (rows || []).map((r) => ({
    id: r.id,
    subject: r.subject || "",
    status: r.status,
    sender: senderName(r.sender_user_id) || r.sender_user_id || "",
    created_at: r.created_at || "",
    sent_at: r.sent_at || "",
    completed_at: r.completed_at || "",
    expires_at: r.expires_at || "",
    updated_at: r.updated_at || "",
  }));
}
