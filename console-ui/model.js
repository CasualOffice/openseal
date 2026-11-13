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
    keys: true,
    keysLog: manager,
    custodian: has("key_custodian"),
    manage: manager,
    approvals: manager,
    plans: true,
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
  if (bad.length) return { tone: "bad", text: `Needs attention: ${bad.map((t) => t.label).join(", ")}` };
  if (open) return { tone: "warn", text: `${plural(open, "alert")} need${open === 1 ? "s" : ""} attention` };
  if (warn) return { tone: "warn", text: "Dead letters need a look" };
  return { tone: "ok", text: "All systems normal" };
}

// Keys (CON-06) ------------------------------------------------------------------------

const KEY_STATUS = {
  valid: { label: "Valid", tone: "ok" },
  expiring: { label: "Expiring", tone: "warn" },
  expired: { label: "Expired", tone: "bad" },
  not_yet_valid: { label: "Not yet valid", tone: "warn" },
};

/// A key's certificate state as the Keys page shows it: `{label, tone, note}`, with the
/// days left (or since expiry) from the API's `days_left`.
export function keyStatus(k) {
  const s = KEY_STATUS[k?.status] || { label: "Unknown", tone: "" };
  const d = typeof k?.days_left === "number" ? k.days_left : null;
  let note = "";
  if (d != null && k.status === "expired") note = `expired ${plural(-d, "day")} ago`;
  else if (d != null && k.status !== "not_yet_valid") note = `${plural(d, "day")} left`;
  return { ...s, note };
}

/// A proposed TSA change's text for the approver: what it sets or removes, from the
/// stored payload (`GET /tsa`).
export function tsaChangeText(c) {
  const p = c?.payload || {};
  if (c?.action === "tsa.remove") return `Remove ${shortId(c.endpoint)}`;
  const parts = [p.url || "?", `priority ${p.priority ?? "?"}`, p.enabled === false ? "disabled" : "enabled"];
  if (p.policy_oid) parts.push(`policy ${p.policy_oid}`);
  if (p.cert_sha256) parts.push(`certificate ${String(p.cert_sha256).slice(0, 12)}…`);
  return parts.join(" · ");
}

/// keyd's health as a tile: up, degraded (a key's backend does not answer), down with
/// keyd's code, or not configured.
export function keydTile(keyd) {
  const st = keyd?.status;
  if (st === "up") return { id: "keyd", label: "keyd", value: "Up", unit: "", note: `${plural((keyd.keys || []).length, "key")} · log at ${count(keyd.log_seq)}`, state: "ok" };
  if (st === "degraded") return { id: "keyd", label: "keyd", value: "Degraded", unit: "", note: `${(keyd.keys || []).filter((k) => !k.ok).map((k) => k.alias).join(", ")} not answering`, state: "warn" };
  if (st === "down") return { id: "keyd", label: "keyd", value: "Down", unit: "", note: problemMessage({ code: keyd.code }), state: "bad" };
  return { id: "keyd", label: "keyd", value: "Not set", unit: "", note: "No keyd address configured", state: "ok" };
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
  "tsa.set": "Set time-stamping authority",
  "tsa.remove": "Remove time-stamping authority",
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
  "CS-PLAN-0006": "The plan, quota or override is not valid.",
  "CS-CON-0008": "keyd refused the console: its certificate must be on keyd's admin allow-list, not its signing list.",
  "CS-KEY-0001": "keyd does not know the console's certificate. Add its fingerprint to keyd's admin allow-list.",
  "CS-KEY-0011": "keyd cannot be reached. Check that it is running and the console's keyd settings.",
};

/// What to tell the operator about a problem `{status, code, field, retry_after}`.
export function problemMessage(p) {
  if (!p) return "Something went wrong.";
  if (p.network) return "The console cannot be reached. Check the connection and try again.";
  let m = MESSAGES[p.code] || `The request failed (${p.status || "no answer"}).`;
  if ((p.code === "CS-CON-0010" || p.code === "CS-PLAN-0006") && p.field) m = `The ${String(p.field).replace(/_/g, " ")} is not valid.`;
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

// Plans (PLAN-02; docs/23 §7.1) ----------------------------------------------------------

const FEATURE_LABELS = {
  bulk_send: "Bulk send",
  sso_saml: "SAML single sign-on",
  scim: "SCIM provisioning",
  api: "API access",
  webhooks: "Webhooks",
  sms_auth: "SMS authentication",
  conditional_routing: "Conditional routing",
  payments: "Payments",
  branding_multi: "Several brands",
  seal_b_lta: "Long-term seals (B-LTA)",
  ml_suggestions: "Field suggestions (ML)",
};

const METER_LABELS = {
  envelopes_sent: "Envelopes sent",
  seats: "Seats",
  storage_bytes: "Storage (bytes)",
  api_calls: "API calls",
  sms_sent: "SMS sent",
  phone_calls: "Phone calls",
  idv_checks: "ID verifications",
  kba_checks: "KBA checks",
  timestamps: "Timestamps",
  seals: "Seals",
  bulk_send_rows: "Bulk-send rows",
  signing_link_submissions: "Signing-link submissions",
  webhook_deliveries: "Webhook deliveries",
  workspaces: "Workspaces",
  templates: "Templates",
};

const SEAT_RULE_LABELS = {
  can_send: "Members who can send",
  every_member: "Every member",
};

/// A plan feature's label; an unknown name is shown as sent.
export function featureLabel(f) {
  return FEATURE_LABELS[f] || String(f || "–");
}

/// A meter's label; an unknown name is shown as sent.
export function meterLabel(m) {
  return METER_LABELS[m] || String(m || "–");
}

/// A seat rule's label.
export function seatRuleLabel(r) {
  return SEAT_RULE_LABELS[r] || String(r || "–");
}

/// A plan key as the API accepts it: a lower-case letter, then lower-case letters,
/// digits, `_` or `-`, at most 64 in all.
export const PLAN_KEY = /^[a-z][a-z0-9_-]{0,63}$/;

/// One quota as a sentence: "1,000 per month · hard · per workspace".
export function quotaText(q) {
  const period = q.period === "none" ? "" : ` per ${q.period}`;
  return `${count(q.limit)}${period} · ${q.enforcement} · per ${q.level}`;
}

/// Plan versions grouped by key, keys in name order, each with its versions newest
/// first; `current` is the newest version not archived (or null).
export function planGroups(plans = []) {
  const by = new Map();
  for (const p of plans) {
    if (!by.has(p.key)) by.set(p.key, []);
    by.get(p.key).push(p);
  }
  return [...by.entries()]
    .map(([key, versions]) => {
      versions.sort((a, b) => b.version - a.version);
      return { key, versions, current: versions.find((v) => !v.archived) || null, latest: versions[0] };
    })
    .sort((a, b) => a.latest.name.localeCompare(b.latest.name) || a.key.localeCompare(b.key));
}

/// Check a plan form against the rules the server applies (docs/23 §7.1, CS-PLAN-0006),
/// so the operator sees the reason before sending. `meters` is the catalogue's list
/// (`{name, kind, approximate}`). Returns `{ok: true, value}` (the request body) or
/// `{ok: false, message}`.
export function checkPlan({ key, name, seatRule, features = [], quotas = [] }, meters = []) {
  const k = String(key || "").trim();
  if (!PLAN_KEY.test(k)) return { ok: false, message: "The key starts with a lower-case letter, then lower-case letters, digits, - or _; at most 64." };
  const n = String(name || "").trim();
  if (!n || [...n].length > 120 || /[\u0000-\u001f\u007f]/.test(n)) return { ok: false, message: "The name is 1 to 120 characters." };
  if (quotas.length > 64) return { ok: false, message: "At most 64 quotas." };
  const info = new Map(meters.map((m) => [m.name, m]));
  const seen = new Set();
  const out = [];
  for (const q of quotas) {
    const m = info.get(q.meter);
    const label = meterLabel(q.meter);
    const raw = String(q.limit ?? "").trim();
    if (!/^[0-9]{1,16}$/.test(raw) || Number(raw) > Number.MAX_SAFE_INTEGER) return { ok: false, message: `${label}: the limit is a whole number.` };
    if (m?.approximate && q.enforcement === "hard") return { ok: false, message: `${label} is counted approximately, so it cannot be hard: use soft or notify.` };
    if (m?.kind === "gauge" && q.period !== "none") return { ok: false, message: `${label} is a count of what exists now: its period is none.` };
    if (q.meter === "workspaces" && q.level === "workspace") return { ok: false, message: "Workspaces are counted per organization." };
    const dup = `${q.meter}/${q.level}`;
    if (seen.has(dup)) return { ok: false, message: `${label} has two quotas per ${q.level}.` };
    seen.add(dup);
    out.push({ meter: q.meter, limit: Number(raw), period: q.period, enforcement: q.enforcement, level: q.level });
  }
  const entitlements = Object.fromEntries(features.map((f) => [f, true]));
  return { ok: true, value: { key: k, name: n, seat_rule: seatRule || "can_send", entitlements, quotas: out } };
}

/// The override keys an operator can choose for an effective plan: each feature, each of
/// the plan's quotas' limit and enforcement, and the seat rule. `workspace` limits it to
/// workspace-level quotas (the only thing a workspace override may change).
export function overrideKeys(catalogue, effective, workspace = false) {
  const keys = [];
  if (!workspace) {
    for (const f of catalogue?.features || []) keys.push({ key: `feature.${f}`, label: `${featureLabel(f)} (feature)`, kind: "flag" });
  }
  for (const q of effective?.quotas || []) {
    if (workspace && q.level !== "workspace") continue;
    const base = `${meterLabel(q.meter)} per ${q.level}`;
    keys.push({ key: `quota.${q.meter}.${q.level}.limit`, label: `${base}: limit`, kind: "limit" });
    keys.push({ key: `quota.${q.meter}.${q.level}.enforcement`, label: `${base}: enforcement`, kind: "enforcement", approximate: !!(catalogue?.meters || []).find((m) => m.name === q.meter)?.approximate });
  }
  if (!workspace) keys.push({ key: "seat_rule", label: "Seat rule", kind: "seat_rule" });
  return keys;
}

/// An override's key as words: `quota.seats.organization.limit` → "Seats per
/// organization: limit".
export function overrideKeyLabel(key) {
  const k = String(key || "");
  if (k === "seat_rule") return "Seat rule";
  if (k.startsWith("feature.")) return featureLabel(k.slice(8));
  const m = /^quota\.([a-z_]+)\.([a-z]+)\.(limit|enforcement)$/.exec(k);
  return m ? `${meterLabel(m[1])} per ${m[2]}: ${m[3]}` : k;
}

/// An override's value as words.
export function overrideValueLabel(key, value) {
  if (String(key).startsWith("feature.")) return value === "true" ? "On" : value === "false" ? "Off" : value;
  if (key === "seat_rule") return seatRuleLabel(value);
  if (String(key).endsWith(".limit") && /^[0-9]+$/.test(value)) return count(Number(value));
  return String(value);
}

/// The override form's value check, by kind; returns the string to send or a message.
export function checkOverrideValue(kind, value, approximate = false) {
  const v = String(value ?? "").trim();
  if (kind === "flag") return v === "true" || v === "false" ? { ok: true, value: v } : { ok: false, message: "Choose on or off." };
  if (kind === "limit") return /^[0-9]{1,16}$/.test(v) && Number(v) <= Number.MAX_SAFE_INTEGER ? { ok: true, value: String(Number(v)) } : { ok: false, message: "The limit is a whole number." };
  if (kind === "enforcement") {
    if (!["hard", "soft", "notify"].includes(v)) return { ok: false, message: "Choose hard, soft or notify." };
    if (v === "hard" && approximate) return { ok: false, message: "This meter is counted approximately, so it cannot be hard." };
    return { ok: true, value: v };
  }
  if (kind === "seat_rule") return SEAT_RULE_LABELS[v] ? { ok: true, value: v } : { ok: false, message: "Choose a seat rule." };
  return { ok: false, message: "Choose what to override." };
}

/// A `datetime-local` value (the operator's local time) as RFC 3339 UTC, or null when
/// empty; `undefined` when it does not parse.
export function localToIso(text) {
  const t = String(text || "").trim();
  if (!t) return null;
  const d = new Date(t);
  return Number.isNaN(d.getTime()) ? undefined : d.toISOString().replace(/\.\d{3}Z$/, "Z");
}
