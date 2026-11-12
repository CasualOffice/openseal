// The pure rules of the manage screens (UX-07): which actions an envelope offers in
// each state, the Agreements address, "expiring soon", and CSV export. No DOM, so the
// unit tests load it under Node; envelope.js, dashboard.js, home.js and envactions.js
// use it.

/// Statuses a sender may delete (A-03): a draft, or an envelope that ended without
/// completing. A completed agreement is evidence and stays (retention decides, docs/32).
export const DELETABLE = new Set(["draft", "voided", "declined", "expired"]);
export const ACTIVE = new Set(["sent", "delivered"]);
/// Ended without completing: each is downloadable as it ended, and copied and sent
/// again from its primary action.
export const ENDED = new Set(["declined", "voided", "expired"]);

const DAY = 86_400_000;
/// "Expiring soon": within this many days.
export const SOON_DAYS = 7;

/// The actions the envelope page offers in `status` (DocuSign's hierarchy: one primary,
/// one secondary, the rest in More): `{primary, secondary, more}` as action ids, `more`
/// in groups with the destructive group last. `cert`: whether the certificate can be
/// had (a completed one's; an ended one's once the server serves it, UXW-30).
export function envelopeActions(status, { cert = false } = {}) {
  if (status === "draft") return { primary: "edit", secondary: null, more: [["copy", "template"], ["delete"]] };
  if (ACTIVE.has(status)) return { primary: "correct", secondary: "resend", more: [["download-current", "copy", "template", "history"], ["void"]] };
  if (status === "completed") return { primary: "download", secondary: "certificate", more: [["copy", "template", "history"]] };
  if (ENDED.has(status)) return { primary: "copy-resend", secondary: "download-ended", more: [[...(cert ? ["certificate"] : []), "template", "history"], ["delete"]] };
  return { primary: null, secondary: null, more: [["copy", "template"]] };
}

/// The Agreements row menu's groups for `status`, separated in the menu and with the
/// destructive group last: open or edit | correct, resend, download | copy, save as
/// template, history | void, delete.
export function rowActions(status, { cert = false } = {}) {
  const groups = [[status === "draft" ? "edit" : "open"]];
  const work = [];
  if (ACTIVE.has(status)) work.push("correct", "resend", "download-current");
  if (status === "completed") work.push("download", "certificate");
  if (ENDED.has(status)) work.push("copy-resend", "download-ended", ...(cert ? ["certificate"] : []));
  if (work.length) groups.push(work);
  groups.push([...(ENDED.has(status) ? [] : ["copy"]), "template", ...(status === "draft" ? [] : ["history"])]);
  const danger = [];
  if (ACTIVE.has(status)) danger.push("void");
  if (DELETABLE.has(status)) danger.push("delete");
  if (danger.length) groups.push(danger);
  return groups;
}

/// The address of a folder with a search: `#/agreements?folder=…&q=…` ("all" and an
/// empty search are left out).
export function agreementsHash(folder = "all", q = "") {
  const p = new URLSearchParams();
  if (folder && folder !== "all") p.set("folder", folder);
  if (q) p.set("q", q);
  const s = p.toString();
  return s ? `#/agreements?${s}` : "#/agreements";
}

/// Whether an envelope expiring at `iso` does so within `days` of `now` and has not
/// yet passed.
export function expiringSoon(iso, now = Date.now(), days = SOON_DAYS) {
  const at = Date.parse(iso || "");
  return Number.isFinite(at) && at >= now && at <= now + days * DAY;
}

/// One CSV cell (RFC 4180): quoted when it holds a comma, quote or line break; a cell
/// a spreadsheet would run as a formula (= + - @, tab, CR) gets a leading apostrophe.
export function csvCell(v) {
  let s = v == null ? "" : String(v);
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
  return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

/// Rows of cells as CSV text, CRLF line ends.
export function toCsv(rows) {
  return `${rows.map((r) => r.map(csvCell).join(",")).join("\r\n")}\r\n`;
}
