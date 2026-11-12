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

// ---- Agreements list and inspector (WEB-17, WEB-18; canvas Main.dc.html) ----------------
//
// The list is grouped by where each agreement stands, and the views (the header's pill
// tabs, the sidebar's Views) are filters over the same loaded rows. Everything below is
// pure: rows in, rows or plain values out.

/// The status groups, in list order, with the tone of their dot and pill.
export const GROUPS = Object.freeze([
  { id: "you", tone: "you" },
  { id: "wait", tone: "wait" },
  { id: "done", tone: "done" },
  { id: "draft", tone: "draft" },
  { id: "ended", tone: "danger" },
]);

/// The views. `tab`: one of the header's pill tabs; `nav`: listed under Views in the
/// sidebar, with `dot` its tone. `groups`: the groups it keeps (none = all);
/// `statuses`: the envelope statuses it keeps (none = all); `soon`: only those expiring
/// within `SOON_DAYS`. `inbox`: needs the server's Inbox (hidden where it has none).
/// The last four have no tab: older addresses and Home's "Declined or expired" open them.
export const VIEWS = Object.freeze([
  { id: "all", tab: true },
  { id: "me", tab: true, nav: true, dot: "you", groups: ["you"], inbox: true },
  { id: "waiting", tab: true, nav: true, dot: "wait", groups: ["wait"] },
  { id: "completed", tab: true, nav: true, dot: "done", groups: ["done"] },
  { id: "drafts", tab: true, nav: true, dot: "draft", groups: ["draft"] },
  { id: "expiring", tab: true, nav: true, dot: "draft", groups: ["you", "wait"], soon: true },
  { id: "action", statuses: ["declined", "expired"] },
  { id: "declined", statuses: ["declined"] },
  { id: "voided", statuses: ["voided"] },
  { id: "expired", statuses: ["expired"] },
]);
const LEGACY_STATUS = { draft: "drafts", sent: "waiting", delivered: "waiting", completed: "completed", declined: "declined", voided: "voided", expired: "expired" };

/// The view a route's parameters name: `?folder=`, or the older `?status=`; else "all".
export function viewFrom(params) {
  const f = params?.get?.("folder");
  if (VIEWS.some((v) => v.id === f)) return f;
  return LEGACY_STATUS[params?.get?.("status")] || "all";
}

/// The group of a list row. `mine`: the ids of envelopes waiting for this user's
/// signature (the Inbox), which go first whatever their status says.
export function groupOf(row, mine = new Set()) {
  if (mine.has(row?.id)) return "you";
  switch (row?.status) {
    case "draft": return "draft";
    case "sent": case "delivered": case "completing": case "created": return "wait";
    case "completed": return "done";
    default: return "ended";
  }
}

/// The tone of a row's status pill: its group's; a voided or expired one is grey.
export function toneOf(row, mine = new Set()) {
  const g = groupOf(row, mine);
  if (g === "ended") return row.status === "declined" ? "danger" : "draft";
  return GROUPS.find((x) => x.id === g).tone;
}

/// Whether `row` belongs in view `id` at `now` (ms).
export function inView(row, id, mine = new Set(), now = Date.now()) {
  const v = VIEWS.find((x) => x.id === id) || VIEWS[0];
  if (v.groups && !v.groups.includes(groupOf(row, mine))) return false;
  if (v.statuses && !v.statuses.includes(row.status)) return false;
  if (v.soon && !expiringSoon(row.expires_at, now)) return false;
  return true;
}

/// How many rows each view holds: `{all, me, waiting, …}`.
export function viewCounts(rows, mine = new Set(), now = Date.now()) {
  const out = {};
  for (const v of VIEWS) out[v.id] = (rows || []).filter((r) => inView(r, v.id, mine, now)).length;
  return out;
}

const newestFirst = (a, b) => String(b.updated_at || b.created_at || "").localeCompare(String(a.updated_at || a.created_at || ""));

/// The rows of view `id`, grouped: `[{group, tone, items}]` in `GROUPS` order, empty
/// groups left out. `order(a, b)` sorts within a group (latest change first by default).
export function groupRows(rows, id = "all", mine = new Set(), { now = Date.now(), order = newestFirst } = {}) {
  const kept = (rows || []).filter((r) => inView(r, id, mine, now));
  return GROUPS.map((g) => ({ group: g.id, tone: g.tone, items: kept.filter((r) => groupOf(r, mine) === g.id).sort(order) }))
    .filter((g) => g.items.length);
}

/// The ids of grouped rows in display order (what ↑ and ↓ move through).
export const flatIds = (groups) => groups.flatMap((g) => g.items.map((r) => r.id));

/// The id ↑, ↓, Home or End moves to from `current` in `ids`; `current` itself for any
/// other key, and the first id when nothing is selected yet.
export function moveSelection(ids, current, key) {
  if (!ids.length) return null;
  const i = ids.indexOf(current);
  if (i < 0) return ids[0];
  if (key === "ArrowDown") return ids[Math.min(ids.length - 1, i + 1)];
  if (key === "ArrowUp") return ids[Math.max(0, i - 1)];
  if (key === "Home") return ids[0];
  if (key === "End") return ids[ids.length - 1];
  return current;
}

const SIGNERS = new Set(["signer", "in_person_signer", "approver"]);

/// Signing progress: `{signed, total}` over the recipients who sign or approve; null
/// without the envelope's recipients.
export function signingProgress(env) {
  if (!env || !Array.isArray(env.recipients)) return null;
  const s = env.recipients.filter((r) => SIGNERS.has(r.type));
  return { signed: s.filter((r) => r.status === "completed").length, total: s.length };
}

/// The inspector's primary action: "sign" (it waits for this user), "remind" (it waits
/// for someone else), "download" (completed), "edit" (a draft) or "copy-resend" (it
/// ended without completing); null for anything else.
export function primaryVerb(status, mine = false) {
  if (ACTIVE.has(status)) return mine ? "sign" : "remind";
  if (status === "completed") return "download";
  if (status === "draft") return "edit";
  if (ENDED.has(status)) return "copy-resend";
  return null;
}

/// How long ago `iso` was, as the list shows it: `{kind, n?}` with kind "now" (under a
/// minute), "min" (under an hour), "hours" (under 6 hours), "time" (earlier today),
/// "yesterday", "date" (this year) or "year" (an older year); "none" without a date.
export function relativeWhen(iso, now = Date.now()) {
  const at = Date.parse(iso || "");
  if (!Number.isFinite(at)) return { kind: "none" };
  const d = now - at;
  if (d < 60_000 && d > -60_000) return { kind: "now" };
  if (d > 0 && d < 3_600_000) return { kind: "min", n: Math.floor(d / 60_000) };
  if (d > 0 && d < 6 * 3_600_000) return { kind: "hours", n: Math.floor(d / 3_600_000) };
  const a = new Date(at);
  const b = new Date(now);
  const day = (x) => new Date(x.getFullYear(), x.getMonth(), x.getDate()).getTime();
  const days = Math.round((day(b) - day(a)) / DAY);
  if (days === 0) return { kind: "time" };
  if (days === 1) return { kind: "yesterday" };
  return { kind: a.getFullYear() === b.getFullYear() ? "date" : "year" };
}

/// A recipient's badge in the signing order (canvas Recipients): `{kind, mark}` with
/// kind "done" (✓), "declined" (✕), "you" (this user's turn), "wait" (their turn: sent
/// or opened) or "next" (not reached yet), and `mark` the routing step, or "cc" for a
/// copy.
export function recipientBadge(r, { mineId = null } = {}) {
  const cc = !SIGNERS.has(r?.type) && r?.type !== "viewer";
  const mark = cc ? "cc" : String(r?.routing_order ?? "");
  if (r?.status === "completed") return { kind: "done", mark: cc ? "cc" : "✓" };
  if (r?.status === "declined") return { kind: "declined", mark: "✕" };
  if (r?.status === "sent" || r?.status === "delivered") return { kind: r.id === mineId ? "you" : "wait", mark };
  return { kind: "next", mark };
}

/// The personal data among `suggestions` (kind `personal_data`, not dismissed):
/// `{items: [{label, n}], pages: [page], total}`, labels in first-seen order.
export function piiSummary(suggestions) {
  const list = (suggestions || []).filter((s) => s.kind === "personal_data" && s.state !== "dismissed");
  const by = new Map();
  for (const s of list) by.set(s.label || "", (by.get(s.label || "") || 0) + 1);
  const pages = [...new Set(list.map((s) => s.page).filter((p) => Number.isInteger(p)))].sort((a, b) => a - b);
  return { items: [...by].map(([label, n]) => ({ label, n })), pages, total: list.length };
}

/// The audit trail's links as the API returns them (`GET …/audit`): `seq` dense from 0,
/// each `prev` the hash before it, and `chain_head` the last hash. It checks the links
/// only and recomputes no hash (that needs the canonical event bytes, docs/32), so a
/// screen may say "linked", never "verified" or "unchanged". `{ok, n, problems}`.
export function auditLinks(audit) {
  const items = Array.isArray(audit?.items) ? audit.items : [];
  const problems = [];
  items.forEach((a, i) => {
    if (a?.seq !== i) problems.push({ seq: i, problem: "seq" });
    if (typeof a?.hash !== "string" || !/^[0-9a-f]{64}$/.test(a.hash)) problems.push({ seq: i, problem: "hash" });
    const want = i === 0 ? null : items[i - 1]?.hash ?? null;
    const prev = a?.prev !== undefined ? a.prev : a?.event?.prev ?? null;
    if (prev !== want) problems.push({ seq: i, problem: "prev" });
  });
  if (items.length && audit?.chain_head != null && audit.chain_head !== items[items.length - 1].hash) problems.push({ seq: items.length, problem: "head" });
  return { ok: problems.length === 0, n: items.length, problems };
}

/// The SHA-256 the server recorded for a document, when it returns one: the delivered
/// file's, else the uploaded one's; null otherwise (and nothing is shown).
export function documentFingerprint(doc) {
  const v = doc?.delivered_sha256 || doc?.upload_sha256 || doc?.sha256 || null;
  const hex = typeof v === "string" ? v.replace(/^sha256:/, "") : null;
  return hex && /^[0-9a-f]{64}$/i.test(hex) ? hex.toLowerCase() : null;
}

/// A fingerprint in groups of four, to compare by eye.
export const groupHex = (hex) => String(hex || "").match(/.{1,4}/g)?.join(" ") || "";
