// Pure logic of the platform console UI (CON-17): no DOM, no fetch, so it runs under
// `node --test` (console-ui/tests/model.test.mjs). Everything here turns what the
// console API returned into what a screen shows; nothing is invented: a value the API
// did not return is shown as absent, never estimated.

/// Roles that may manage organizations and approvals (the API's `operators`).
export const MANAGERS = ["platform_owner", "operator"];

/// What an operator's roles let them open, mirroring the API's `x-roles`
/// (api/console-openapi.yaml). Hiding a screen is a convenience; the server decides.
export function access(roles = []) {
  const has = (r) => roles.includes(r);
  const manager = MANAGERS.some(has);
  return {
    health: true,
    organizations: true,
    manage: manager,
    approvals: manager,
    log: manager,
    operators: has("platform_owner"),
  };
}

const ROLE_LABELS = {
  platform_owner: "Platform owner",
  operator: "Operator",
  key_custodian: "Key custodian",
  observer: "Observer",
};

/// A role's label.
export function roleLabel(role) {
  return ROLE_LABELS[role] || role;
}

/// Integer with grouping (1,284), or an en dash for a missing value.
export function count(n) {
  if (typeof n !== "number" || !Number.isFinite(n)) return "–";
  return Math.round(n).toLocaleString("en-US");
}

/// A duration in seconds, short: "40 s", "3 min", "2 h 5 min", "3 d".
export function duration(seconds) {
  if (typeof seconds !== "number" || !Number.isFinite(seconds) || seconds < 0) return "–";
  const s = Math.round(seconds);
  if (s < 60) return `${s} s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m} min`;
  const h = Math.floor(m / 60);
  if (h < 48) return m % 60 ? `${h} h ${m % 60} min` : `${h} h`;
  return `${Math.floor(h / 24)} d`;
}

/// "4 s ago", "6 min ago", "3 h ago", or a date, relative to `now` (ms).
export function ago(iso, now = Date.now()) {
  const t = Date.parse(iso);
  if (!Number.isFinite(t)) return "–";
  const s = Math.max(0, Math.round((now - t) / 1000));
  if (s < 60) return `${s} s ago`;
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  return shortDate(iso);
}

/// "in 23 h", "in 4 min", or "expired", relative to `now`.
export function until(iso, now = Date.now()) {
  const t = Date.parse(iso);
  if (!Number.isFinite(t)) return "–";
  const s = Math.round((t - now) / 1000);
  if (s <= 0) return "expired";
  return `in ${duration(s)}`;
}

/// "13 Nov 2026, 14:05" in UTC (operators work across zones; the log is in UTC).
export function shortDate(iso) {
  const t = Date.parse(iso);
  if (!Number.isFinite(t)) return "–";
  const d = new Date(t);
  const mon = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"][d.getUTCMonth()];
  const p = (n) => String(n).padStart(2, "0");
  return `${d.getUTCDate()} ${mon} ${d.getUTCFullYear()}, ${p(d.getUTCHours())}:${p(d.getUTCMinutes())} UTC`;
}

/// The first eight characters of an id, for display beside its full value in a title.
export function shortId(id) {
  return typeof id === "string" ? id.slice(0, 8) : "–";
}

/// Plural: `plural(1, "job")` → "1 job", `plural(3, "job")` → "3 jobs".
export function plural(n, one, many = `${one}s`) {
  return `${count(n)} ${n === 1 ? one : many}`;
}

// Health -------------------------------------------------------------------------------

/// The health tiles from `GET /console/v1/health`. Only metrics the API returns; no
/// series, so no sparklines or usual ranges (those need history the API does not keep).
/// Each tile: `{id, label, value, unit, note, state}` with `state` one of `ok`, `warn`,
/// `bad`.
export function healthTiles(h) {
  const jobs = Array.isArray(h?.jobs) ? h.jobs : [];
  const queued = jobs.filter((j) => j.status === "queued");
  const running = jobs.filter((j) => j.status === "running");
  const depth = queued.reduce((a, j) => a + (Number(j.jobs) || 0), 0);
  const oldest = queued.reduce((a, j) => (typeof j.oldest_seconds === "number" && j.oldest_seconds > a ? j.oldest_seconds : a), -1);
  const runningN = running.reduce((a, j) => a + (Number(j.jobs) || 0), 0);
  const dead = typeof h?.dead_letters === "number" ? h.dead_letters : null;
  const conns = Array.isArray(h?.connections) ? h.connections : [];
  const connTotal = conns.reduce((a, c) => a + (Number(c.connections) || 0), 0);
  const connNote = conns.length
    ? conns.map((c) => `${count(c.connections)} ${c.state || "unknown"}`).join(" · ")
    : "No connections reported";
  const db = h?.database?.status;
  const log = h?.operator_log || {};
  const services = Array.isArray(h?.services) ? h.services : [];
  const down = services.filter((s) => s.status !== "up").length;
  return [
    {
      id: "queue",
      label: "Job queue depth",
      value: count(depth),
      unit: depth === 1 ? "job queued" : "jobs queued",
      note: oldest >= 0 ? `Oldest waiting ${duration(oldest)} · ${count(runningN)} running` : `${count(runningN)} running`,
      state: "ok",
    },
    {
      id: "dead",
      label: "Dead letters",
      value: count(dead),
      unit: dead === 1 ? "job" : "jobs",
      note: dead ? "Jobs that ran out of attempts" : "No job has run out of attempts",
      state: dead ? "warn" : "ok",
    },
    {
      id: "database",
      label: "Database",
      value: db === "up" ? "Up" : db === "down" ? "Down" : "–",
      unit: "",
      note: `${count(connTotal)} connections · ${connNote}`,
      state: db === "up" ? "ok" : "bad",
    },
    {
      id: "services",
      label: "Services",
      value: services.length ? `${count(services.length - down)} of ${count(services.length)}` : "–",
      unit: services.length ? "up" : "",
      note: services.length ? (down ? `${plural(down, "service")} not answering` : "Every probe answered") : "No service targets configured",
      state: down ? "bad" : "ok",
    },
    {
      id: "log",
      label: "Operator log",
      value: log.verified === true ? "Verified" : log.verified === false ? "Broken" : "–",
      unit: "",
      note: log.verified === true ? `${plural(log.events, "event")}, hash chain intact` : log.code ? `Does not verify (${log.code})` : "",
      state: log.verified === true ? "ok" : "bad",
    },
  ];
}

/// Alerts still open: not a resolution, and not resolved by a later alert.
export function openAlerts(alerts = []) {
  const resolved = new Set(alerts.map((a) => a.resolves).filter(Boolean));
  return alerts.filter((a) => !a.resolves && !resolved.has(a.id));
}

/// The one-line summary beside the Health title, and its tone (`ok`, `warn`, `bad`).
export function healthSummary(h, alerts = []) {
  const tiles = healthTiles(h);
  const bad = tiles.filter((t) => t.state === "bad");
  const open = openAlerts(alerts).length;
  const warn = tiles.filter((t) => t.state === "warn").length;
  if (bad.length) return { tone: "bad", text: `${bad.map((t) => t.label).join(", ")} need${bad.length === 1 ? "s" : ""} attention` };
  if (open) return { tone: "warn", text: `${plural(open, "alert")} need${open === 1 ? "s" : ""} attention` };
  if (warn) return { tone: "warn", text: "Dead letters need a look" };
  return { tone: "ok", text: "All systems normal" };
}

/// Queue rows by kind: `{kind, queued, running, dead, oldest}` sorted by kind.
export function queueByKind(jobs = []) {
  const by = new Map();
  for (const j of jobs) {
    const r = by.get(j.kind) || { kind: j.kind, queued: 0, running: 0, dead: 0, oldest: null };
    if (j.status in r) r[j.status] += Number(j.jobs) || 0;
    if (j.status === "queued" && typeof j.oldest_seconds === "number") r.oldest = Math.max(r.oldest ?? 0, j.oldest_seconds);
    by.set(j.kind, r);
  }
  return [...by.values()].sort((a, b) => String(a.kind).localeCompare(String(b.kind)));
}

// Organizations ------------------------------------------------------------------------

/// A data-region label as the API accepts it.
export const REGION = /^[a-z0-9][a-z0-9-]{0,31}$/;

/// Parse a comma- or space-separated list of region labels. Returns `{labels, bad}`:
/// `bad` lists what is not a label, so the form can say which; duplicates are dropped.
export function parseRegions(text) {
  const parts = String(text || "").split(/[\s,]+/).map((s) => s.trim().toLowerCase()).filter(Boolean);
  const labels = [];
  const bad = [];
  for (const p of parts) {
    if (!REGION.test(p)) bad.push(p);
    else if (!labels.includes(p)) labels.push(p);
  }
  if (labels.length > 16) bad.push(`more than 16 labels (${labels.length})`);
  return { labels, bad };
}

/// The name an organization may be renamed to, or an error message.
export function checkName(name) {
  const n = String(name ?? "").trim();
  if (!n) return { ok: false, message: "Enter a name." };
  if ([...n].length > 255) return { ok: false, message: "At most 255 characters." };
  return { ok: true, value: n };
}

/// Filter loaded organizations by name or id (the API pages; it has no search yet).
export function filterOrgs(orgs = [], q = "") {
  const s = String(q).trim().toLowerCase();
  if (!s) return orgs;
  return orgs.filter((o) => String(o.name).toLowerCase().includes(s) || String(o.id).startsWith(s));
}

// Two-person actions --------------------------------------------------------------------

/// The state of an approval request for the signed-in operator `me`:
/// - `applied`: spent; `expired`: lapsed unspent;
/// - `ready`: mine, granted by another operator: I can apply it;
/// - `waiting`: mine, no grant yet;
/// - `grantable`: someone else's, live, and I have not granted it;
/// - `granted`: someone else's that I (or another) granted, waiting for its requester.
export function approvalState(a, me, now = Date.now()) {
  if (a.used) return "applied";
  const live = a.live !== false && Date.parse(a.expires_at) > now;
  if (!live) return "expired";
  const approvers = Array.isArray(a.approvers) ? a.approvers : [];
  const others = approvers.filter((x) => x !== a.requester);
  if (a.requester === me) return others.length ? "ready" : "waiting";
  if (approvers.includes(me)) return "granted";
  return "grantable";
}

const ACTION_LABELS = {
  "organization.suspend": "Suspend organization",
  "organization.resume": "Resume organization",
};

/// An approval action's label.
export function actionLabel(action) {
  return ACTION_LABELS[action] || action;
}

/// The two-person action an organization's status allows: suspend an active one,
/// resume a suspended one; none for a closed one.
export function orgAction(status) {
  if (status === "active") return "organization.suspend";
  if (status === "suspended") return "organization.resume";
  return null;
}

/// The newest live request for `action` on `org` that `me` made, with its state.
export function myRequest(approvals = [], org, action, me, now = Date.now()) {
  for (const a of approvals) {
    if (a.organization !== org || a.action !== action || a.requester !== me) continue;
    const st = approvalState(a, me, now);
    if (st === "ready" || st === "waiting") return { approval: a, state: st };
  }
  return null;
}

/// Approvals another operator can grant now: the badge in the sidebar.
export function grantableCount(approvals = [], me, now = Date.now()) {
  return approvals.filter((a) => approvalState(a, me, now) === "grantable").length;
}

// Errors -------------------------------------------------------------------------------

const MESSAGES = {
  "CS-CON-0001": "Your session has ended. Sign in again.",
  "CS-CON-0002": "Enter a fresh code from your authenticator app to continue.",
  "CS-CON-0003": "Your role does not allow this.",
  "CS-CON-0004": "This needs a second operator's approval first.",
  "CS-CON-0007": "The operator log does not verify. Changes are refused until it is repaired.",
  "CS-CON-0010": "Check the value and try again.",
  "CS-CON-0011": "Not found. It may have been removed, or the link has expired.",
  "CS-CON-0012": "Too many attempts. Wait a moment and try again.",
  "CS-CON-0013": "This page's session token is out of date. Sign in again.",
  "CS-CON-0014": "The console failed internally. Try again; if it persists, check the console's log.",
  "CS-CON-0015": "The database is not answering. Try again shortly.",
  "CS-CON-0016": "An operator with this e-mail already exists.",
};

/// What to tell the operator about a problem `{status, code, field, retry_after}`.
export function problemMessage(p) {
  if (!p) return "Something went wrong.";
  if (p.network) return "The console cannot be reached. Check the connection and try again.";
  let m = MESSAGES[p.code] || `The request failed (${p.status || "no answer"}).`;
  if (p.code === "CS-CON-0010" && p.field) m = `The ${String(p.field).replace(/_/g, " ")} is not valid.`;
  if (p.code === "CS-CON-0012" && typeof p.retry_after === "number") m = `Too many attempts. Try again in ${duration(p.retry_after)}.`;
  return m;
}

// Enrolment ----------------------------------------------------------------------------

/// The base32 secret of an `otpauth://` URI, grouped in fours for typing, or "".
export function otpSecret(uri) {
  const m = /[?&]secret=([A-Z2-7]+)/i.exec(String(uri || ""));
  return m ? m[1].toUpperCase().replace(/(.{4})(?=.)/g, "$1 ") : "";
}

/// A TOTP code as the API accepts it (6 digits), or null.
export function cleanCode(text) {
  const c = String(text || "").replace(/\s+/g, "");
  return /^[0-9]{6}$/.test(c) ? c : null;
}

/// An enrolment password the API accepts (12 characters to 1 KiB), or a message.
export function checkPassword(pw, again) {
  const n = new TextEncoder().encode(String(pw || "")).length;
  if ([...String(pw || "")].length < 12) return "Use at least 12 characters.";
  if (n > 1024) return "At most 1 KiB.";
  if (pw !== again) return "The two passwords differ.";
  return null;
}

// Operator log -------------------------------------------------------------------------

/// Readable label for an operator-log action: `operator.organization.suspended` →
/// "Organization suspended".
export function eventLabel(action) {
  const rest = String(action || "").replace(/^operator\./, "").replace(/[._]/g, " ").trim();
  return rest ? rest[0].toUpperCase() + rest.slice(1) : "–";
}

/// The details of a canonical event as `[key, value]` pairs (ids, codes, labels and
/// counts only, by the log's own rule), without the fields shown elsewhere.
export function eventDetails(ev) {
  const body = ev?.event && typeof ev.event === "object" ? ev.event : {};
  const details = body.details && typeof body.details === "object" ? body.details : {};
  return Object.entries(details).map(([k, v]) => [k.replace(/_/g, " "), typeof v === "object" ? JSON.stringify(v) : String(v)]);
}
