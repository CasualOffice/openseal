// Mock mode (WEB-01): an in-memory fake of the OpenSeal API, shaped as `fetch`, so
// the app runs and is tested without the server (`?mock=1`). It implements the
// endpoints the app calls, with the server's status codes, problem details (docs/20
// codes), ETags, CSRF and routing rules as `api/openapi.yaml` and docs/24 describe
// them. It is not evidence of anything: hashes are SHA-256 of the mock's own JSON, the
// "sealed" PDF is the delivered one, and nothing is signed. The UI shows a banner.
//
// State lives in memory and, when a `store` (sessionStorage) is given, survives
// reloads and navigation within the tab, so the sender app and the signing page share
// one fake server. Each test or Playwright context starts from the same seed.

import { makePdf, countPages, stampPdf } from "./mockpdf.js";

const DOCX_MEDIA = "application/vnd.openxmlformats-officedocument.wordprocessingml.document";
import { checkText } from "./signfields.js";
import { rulesFor, finishProblems } from "./fieldrules.js";
import { checkList } from "./bulkmodel.js";
import { mergeTemplates, roleKey } from "./templatemodel.js";
import { redirectUriOk, publicKeyProblem } from "./adminmodel.js";

/// Fixed demo values; the e2e specs read them from here.
export const MOCK = {
  email: "demo@openseal.test",
  password: "openseal-demo-1",
  ersd: "2026-1",
  ceremonyToken: "demo-sign",
  declineToken: "demo-decline",
  fieldsToken: "demo-fields",
  // The demo user's own link to an envelope another member sent them (the Inbox, UX-03).
  inboxToken: "demo-inbox",
  accessCode: "2468",
  // The emailed one-time code every mock `POST /s/{token}/otp` "sends" (SEC-A02).
  emailCode: "135790",
  // Recipient sign-in (`sso`, RAUTH-01): the one provider the mock lists, and the code
  // its "provider" sends the browser back with (straight back, no real sign-in).
  ssoProvider: { id: "demo", name: "Demo identity provider" },
  ssoCode: "mock-sso-code",
  // A member with this email also belongs to another account (SEC-ID-01): only they may
  // change their name or password, so an administrator's change is 403 CS-API-0015.
  sharedEmail: "shared@openseal.test",
};

const KEY = "openseal.mock.v1";
const TERMINAL = new Set(["completed", "declined", "voided", "expired"]);
/// The events every recipient may see in their history (server ceremony.rs `MILESTONES`).
const MILESTONES = new Set(["envelope.sent", "envelope.corrected", "envelope.voided", "envelope.declined", "envelope.expired", "envelope.completing", "envelope.completed"]);
/// Recipients the envelope waits for: everyone but a copy (the engine's
/// `has_required_action`); routing reaches them in order.
const ACTING = (r) => r.type !== "cc";
/// Recipient types that sign (the engine's `signs()`): they may hold any field, and the
/// mock asks each for at least one before sending.
const SIGNS = new Set(["signer", "in_person_signer", "editor", "witness", "seal", "notary"]);
/// Who names later recipients in the ceremony (the engine's `edits_recipients`).
const NAMES_LATER = new Set(["editor", "intermediary", "agent"]);
const INPUT_TYPES = new Set(["signature", "initials", "text", "checkbox", "company", "title", "number", "radio_group", "dropdown", "attachment",
  // VS-04A: every engine kind that takes input but payment.
  "date", "email_address", "phone", "ssn", "zip", "multi_select", "stamp", "drawing"]);
const RECIPIENT_TYPES = ["signer", "in_person_signer", "approver", "viewer", "cc", "editor", "intermediary", "agent", "witness", "seal", "notary"];
const FIELD_TYPES = new Set([
  "signature", "initials", "stamp", "date_signed", "name", "first_name", "last_name", "email", "company", "title",
  "envelope_id", "text", "number", "date", "email_address", "phone", "ssn", "zip", "checkbox", "radio_group",
  "dropdown", "multi_select", "formula", "attachment", "note", "approve", "decline", "hyperlink", "payment", "drawing",
  // FG-080 (ADR-044): an editor's strike-through.
  "strikethrough",
]);
/// The members of an engine `Field` besides its ids, type and place (api.js `FIELD_MEMBERS`).
const FIELD_MEMBERS = ["required", "read_only", "locked", "label", "value", "default", "validation", "format", "group", "conditional", "formula", "options", "allow_custom", "tooltip", "placeholder"];
/// Which fields a recipient type may hold (the engine's `field_allowed`).
function fieldAllowed(rtype, ftype) {
  if (SIGNS.has(rtype)) return true;
  if (rtype === "approver") return !["signature", "initials", "stamp", "date_signed"].includes(ftype);
  return ftype === "note" || ftype === "hyperlink";
}
const WEBHOOK_EVENTS = [
  "envelope.sent", "envelope.delivered", "envelope.completed", "envelope.declined", "envelope.voided", "envelope.expired",
  "envelope.corrected", "envelope.purged", "recipient.sent", "recipient.delivered", "recipient.auth_failed",
  "recipient.completed", "recipient.declined", "recipient.reassigned", "recipient.finish_later", "recipient.bounced",
  "template.created", "template.updated", "template.deleted", "bulk_send.completed",
];
/// Whether a value is a whole workflow policy as the server's `Policy` deserializes it
/// (casual-sign-workflow, no defaults): every member present and of its type; others ignored.
const POLICY_INTS = { max_auth_attempts: 0xffffffff, max_recipients: Number.MAX_SAFE_INTEGER, max_fields: Number.MAX_SAFE_INTEGER, max_documents: Number.MAX_SAFE_INTEGER, expiry_warning_days: 0xffff, seal_retry_ms: 0xffffffff };
const DATE_FORMATS = ["yyyy_mm_dd", "mm_dd_yyyy", "dd_mm_yyyy", "dd_mm_yyyy_dot", "d_mmm_yyyy"];
function policyOk(p) {
  if (!p || typeof p !== "object" || Array.isArray(p)) return false;
  for (const [k, max] of Object.entries(POLICY_INTS)) if (!Number.isInteger(p[k]) || p[k] < 0 || p[k] > max) return false;
  return DATE_FORMATS.includes(p.date_format) && (p.ersd == null || (typeof p.ersd === "object" && typeof p.ersd.version === "string" && typeof p.ersd.hash === "string"));
}

/// The demo disclosure (ERSD) every mock recipient consents to. Not legal text.
export const MOCK_DISCLOSURE = [
  "Electronic record and signature disclosure (mock mode demo text).",
  "",
  "Demo account will send you agreements electronically. You may ask for a paper copy, and withdraw your consent to",
  "electronic records at any time, from the signing page's Other actions menu or by writing to the sender; withdrawing",
  "declines the agreement. There is no fee. You need a current web browser and a way to keep or print a PDF.",
].join("\n");

let counter = 0;
/// The account's built-in permission profiles as `GET /permission-profiles` lists them
/// (server `auth.rs` `profile_scopes`).
const builtinProfiles = () => [
  { id: "profile-admin", name: "Administrator", kind: "admin", builtin: true, permissions: ["envelopes:read", "envelopes:write", "envelopes:send", "templates:read", "templates:write", "bulk:send", "webhooks:manage", "admin:users", "admin:account", "audit:read", "view_all_envelopes"] },
  { id: "profile-sender", name: "Sender", kind: "sender", builtin: true, permissions: ["envelopes:read", "envelopes:write", "envelopes:send", "templates:read", "templates:write", "bulk:send", "audit:read"] },
  { id: "profile-viewer", name: "Viewer", kind: "viewer", builtin: true, permissions: ["envelopes:read", "templates:read", "audit:read"] },
];
const uid = () => (typeof crypto !== "undefined" && crypto.randomUUID ? crypto.randomUUID() : `id-${Date.now()}-${++counter}`);

function b64(bytes) {
  let s = "";
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(s);
}
/// The decoded size of base64 `s`, without decoding it.
function b64Size(s) {
  const n = String(s || "").length;
  const pad = s?.endsWith("==") ? 2 : s?.endsWith("=") ? 1 : 0;
  return Math.floor((n * 3) / 4) - pad;
}

/// As the server (docs/21, `FG-006`): a document over 50 MiB, or an envelope whose
/// documents come to over 200 MiB however they arrive, is refused with `413
/// CS-API-0006` before anything is decoded or kept.
const MAX_DOCUMENT_BYTES = 50 * 1024 * 1024;
const MAX_ENVELOPE_BYTES = 200 * 1024 * 1024;
function checkSizes(held, contents) {
  let total = held;
  for (const c of contents) {
    const n = b64Size(c);
    if (n > MAX_DOCUMENT_BYTES) fail(413, "CS-API-0006", "Request too large");
    total += n;
  }
  if (total > MAX_ENVELOPE_BYTES) fail(413, "CS-API-0006", "Request too large");
}

function unb64(s) {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
async function sha256hex(text) {
  const d = await crypto.subtle.digest("SHA-256", typeof text === "string" ? new TextEncoder().encode(text) : text);
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/// CRC-32 (IEEE 802.3, as ZIP uses) of `bytes`.
const CRC_TABLE = Array.from({ length: 256 }, (_, n) => {
  let c = n;
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  return c >>> 0;
});
function crc32(bytes) {
  let c = 0xffffffff;
  for (const b of bytes) c = CRC_TABLE[(c ^ b) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

/// A ZIP of stored entries `[[name, bytes]]`, as the server's `storezip` writes it
/// (VS-06D): local headers and bytes, the central directory, the end record; UTF-8
/// names, the fixed 1980-01-01 date.
function storeZip(entries) {
  const enc = new TextEncoder();
  const parts = [];
  const central = [];
  let offset = 0;
  const head = (sig, fields) => {
    const b = new Uint8Array(4 + fields.reduce((n, [w]) => n + w, 0));
    const v = new DataView(b.buffer);
    v.setUint32(0, sig, true);
    let at = 4;
    for (const [w, x] of fields) { if (w === 2) v.setUint16(at, x, true); else v.setUint32(at, x, true); at += w; }
    return b;
  };
  for (const [name, bytes] of entries) {
    const n = enc.encode(name);
    const crc = crc32(bytes);
    const local = head(0x04034b50, [[2, 10], [2, 0x0800], [2, 0], [2, 0], [2, 0x21], [4, crc], [4, bytes.length], [4, bytes.length], [2, n.length], [2, 0]]);
    parts.push(local, n, bytes);
    central.push([head(0x02014b50, [[2, 20], [2, 10], [2, 0x0800], [2, 0], [2, 0], [2, 0x21], [4, crc], [4, bytes.length], [4, bytes.length], [2, n.length], [2, 0], [2, 0], [2, 0], [2, 0], [4, 0], [4, offset]]), n]);
    offset += local.length + n.length + bytes.length;
  }
  const start = offset;
  for (const [h, n] of central) { parts.push(h, n); offset += h.length + n.length; }
  parts.push(head(0x06054b50, [[2, 0], [2, 0], [2, entries.length], [2, entries.length], [4, offset - start], [4, start], [2, 0]]));
  const out = new Uint8Array(parts.reduce((x, p) => x + p.length, 0));
  let at = 0;
  for (const p of parts) { out.set(p, at); at += p.length; }
  return out;
}

class Problem extends Error {
  constructor(status, code, title, errors, detail) {
    super(code);
    this.status = status;
    this.code = code;
    this.title = title;
    this.errors = errors;
    this.detail = detail;
  }
}
const fail = (status, code, title, errors, detail) => { throw new Problem(status, code, title, errors, detail); };

/// Make the fake. Returns `fetch(url, init)` answering `Response`s, plus `state()` for tests.
export function createMockFetch({ store = null, now = () => new Date() } = {}) {
  let db = null;
  let ersdSha = null;

  /// ERSD-01, as the server: the disclosure the policy names. The last one published
  /// through `POST /ersd-versions`, else the demo text as version `MOCK.ersd`.
  const disclosure = () => {
    const d = db?.ersd?.at(-1);
    return d ? { version: d.label, sha256: d.sha256, text: d.text } : { version: MOCK.ersd, sha256: ersdSha, text: MOCK_DISCLOSURE };
  };

  const save = () => {
    if (!store) return;
    try { store.setItem(KEY, JSON.stringify(db)); } catch { /* full or off: memory only */ }
  };
  const fill = () => { db.templates ||= []; db.groups ||= []; db.profiles ||= builtinProfiles(); for (const g of db.groups) g.user_ids ||= []; db.users ||= []; db.apiClients ||= []; db.webhooks ||= []; db.deliveries ||= {}; db.folders ||= []; db.bulk ||= []; db.ersd ||= []; db.adminLog ||= []; };
  async function load() {
    ersdSha ||= `sha256:${await sha256hex(MOCK_DISCLOSURE)}`;
    if (db) return;
    if (store) {
      try {
        const s = store.getItem(KEY);
        if (s) { db = JSON.parse(s); fill(); return; }
      } catch { db = null; }
    }
    db = { session: null, envelopes: [], audit: {}, blobs: {}, tokens: {}, opened: [], adoptions: {}, attempts: {}, templates: [], groups: [], profiles: builtinProfiles(), users: [], apiClients: [], webhooks: [], deliveries: {}, folders: [], bulk: [], ersd: [], adminLog: [] };
    await seed();
    save();
  }
  const account = () => {
    // The demo account opted out of the second factor (`mfa_policy: "optional"`), so the
    // demo signs in with a password alone; unset, the server's default asks the demo
    // administrator to enrol (ASVS-31).
    db.account ||= { id: "acct-demo", name: "Demo account", settings: { mfa_policy: "optional" }, data_region: null, created_at: iso(-60 * 24 * 30) };
    return db.account;
  };

  const iso = (offsetMin = 0) => new Date(now().getTime() + offsetMin * 60000).toISOString();

  /// Append an event to the envelope's chain, shaped as the server's `GET …/audit` item
  /// (WEB-12): `{seq, type, at, hash, prev, event}`, `seq` from 0, `type` casual-sign-audit's
  /// dotted name, `event` the whole event of docs/32 §2 (`v`, `envelope_id`, `seq`, `prev`,
  /// `at`, `type`, `actor {kind, id?, name?, email?}`, `context`, `data`), the recipient it
  /// concerns in `data.recipient_id`. `by` is who acted: `sender`, `user`, `recipient`
  /// (the default for a `recipient.*` event naming one) or `system`. The hash is SHA-256
  /// of the mock's own JSON, not RFC 8785: the mock is not evidence.
  async function audit(env, type, data = {}, { by, at, location } = {}) {
    const list = (db.audit[env.id] ||= []);
    const prev = list.length ? list[list.length - 1].hash : null;
    const seq = list.length;
    const kind = by || (type.startsWith("recipient.") && data.recipient_id ? "recipient" : "system");
    const actor = { kind };
    if (kind === "sender") actor.id = env.sender_user_id;
    else if (kind === "user") actor.id = "user-demo";
    else if (kind === "recipient") {
      // As the engine's `actor_for`: a recipient is named as they were at the time.
      const r = env.recipients.find((x) => x.id === data.recipient_id);
      actor.id = data.recipient_id;
      if (r) { actor.name = r.name; actor.email = r.email; }
    }
    const when = at || iso();
    const event = { v: 1, envelope_id: env.id, seq, prev, at: when, type, actor, context: location ? { location } : {}, data };
    // Written as the server writes it (`Hash256`): `sha256:` and the hex (S1-10).
    const hash = `sha256:${await sha256hex(JSON.stringify(event))}`;
    list.push({ seq, type, at: when, hash, prev, event });
    notify(env, type);
  }
  /// Append an event to the workspace's admin log (ORG-05), shaped as the server's `GET
  /// /admin-events` item: `{seq, at, action, hash, prev, event}`, `event` the canonical
  /// event (`v`, `account`, `seq`, `prev`, `at` in ms, `actor {kind, id?}`, `action`,
  /// `target`, `changes [{key, old, new}]`, `request_id`). As `audit`, the hash is over
  /// the mock's own JSON. `by`: a user id, `{api_client: id}`, or "system".
  async function adminEvent(action, { target = {}, changes = [], by = "user-demo", at = null } = {}) {
    const log = (db.adminLog ||= []);
    const prev = log.length ? log[log.length - 1].hash : null;
    const seq = log.length;
    const when = at || iso();
    const actor = by === "system" ? { kind: "system" } : by?.api_client ? { kind: "api_client", id: by.api_client } : { kind: "user", id: by };
    const event = { v: 1, account: "acct-demo", seq, prev, at: Date.parse(when), actor, action, target, changes, request_id: `mock-${uid().slice(0, 8)}` };
    const hash = (await sha256hex(JSON.stringify(event))).toLowerCase();
    log.push({ seq, at: when, action, hash, prev, event });
  }
  /// `GET /admin-events?cursor&limit&format&verify`, as the server (ORG-05): oldest first,
  /// `next_cursor` the last `seq` of a full page; CSV with the next cursor in
  /// `X-Next-Cursor`; `verify=full` re-checks every link.
  async function adminEvents(query) {
    const limit = query.has("limit") ? Number(query.get("limit")) : 100;
    if (!Number.isInteger(limit) || limit < 1 || limit > 1000) fail(422, "CS-API-0001", "Malformed request", [{ pointer: "/query/limit", code: "CS-API-0001" }]);
    const format = query.get("format") || "json";
    if (!["json", "csv"].includes(format)) fail(422, "CS-API-0001", "Malformed request", [{ pointer: "/query/format", code: "CS-API-0001" }]);
    const verify = query.get("verify") || "page";
    if (!["page", "full"].includes(verify)) fail(422, "CS-API-0001", "Malformed request", [{ pointer: "/query/verify", code: "CS-API-0001" }]);
    const log = db.adminLog || [];
    if (verify === "full") {
      for (const [i, e] of log.entries()) {
        if (e.prev !== (i ? log[i - 1].hash : null) || e.hash !== await sha256hex(JSON.stringify(e.event))) fail(500, "CS-DB-0014", "Admin log chain broken");
      }
    }
    const cursor = query.has("cursor") ? Number(query.get("cursor")) : null;
    const page = log.filter((e) => cursor == null || e.seq > cursor).slice(0, limit);
    const next = page.length === limit ? page[page.length - 1].seq : null;
    if (format === "csv") {
      const field = (v) => (/[",\r\n]/.test(v) ? `"${v.replace(/"/g, '""')}"` : v);
      const text = ["seq,at,action,hash,prev,event", ...page.map((e) => [e.seq, e.at, field(e.action), e.hash, e.prev || "", field(JSON.stringify(e.event))].join(","))].join("\r\n") + "\r\n";
      return new Response(text, { status: 200, headers: { "Content-Type": "text/csv; charset=utf-8", ...(next == null ? {} : { "X-Next-Cursor": String(next) }) } });
    }
    return json(200, { items: page, next_cursor: next });
  }
  const blobHash = (id, salt = "") => sha256hex(`${db.blobs[id] || ""}${salt}`);
  const docHashes = async (env) => Promise.all(env.documents.map(async (d) => ({ document_id: d.id, hash: await blobHash(d.id) })));
  /// A webhook delivery to every active subscription that names the topic (the worker's
  /// `deliver_webhook`; the mock "delivers" at once, answered 200).
  function notify(env, topic) {
    if (!WEBHOOK_EVENTS.includes(topic)) return;
    for (const w of db.webhooks || []) {
      if (!w.active || !w.event_types.includes(topic) || (w.envelope_id && w.envelope_id !== env.id)) continue;
      // A receiver at `…/fail-first` answers its first delivery 500; like the server, the
      // delivery stays pending with a retry due (the slice 8 spec's
      // stand-in for the real stack's receiver, told to fail), so it can be delivered again.
      const fails = /\/fail-first(?:$|[/?])/.test(w.url) && !(db.deliveries[w.id] || []).length;
      (db.deliveries[w.id] ||= []).unshift({ id: uid(), event_id: uid(), event_type: topic, status: fails ? "pending" : "delivered", attempts: 1, last_status_code: fails ? 500 : 200 });
    }
  }

  // ---- Model helpers -----------------------------------------------------------
  /// The seal profiles an envelope or the account's default may name (docs/22 §3).
  const SEAL_PROFILES = ["pades-b-t", "pades-b-lt", "pades-b-lta"];
  /// Signing options as the server answers them: `stamp_envelope_id` absent when off.
  function stampOff(o) {
    if (!o.stamp_envelope_id) delete o.stamp_envelope_id;
    return o;
  }

  function newEnvelope({ subject = "", message = "", signing_options = {}, created_at } = {}) {
    const env = {
      id: uid(), status: "draft", version: 1, sender_user_id: "user-demo", subject, message,
      created_at: created_at || iso(), sent_at: null, send_at: null, ended_at: null, expires_at: null, void_reason: null,
      reminders: {}, signing_options: { ...signing_options }, seal_profile: "pades-b-t",
      documents: [], recipients: [], fields: [], sealed: false,
    };
    db.envelopes.push(env);
    return env;
  }
  /// The server converts a Word document with convertd (ADR-042); mock mode answers a
  /// placeholder PDF for any ZIP, so the editor's preview and the upload agree, and
  /// refuses one naming a VBA project as the server does (CS-CNV-0004).
  function mockConvert(bytes) {
    if (!(bytes instanceof Uint8Array) || bytes.length < 4 || bytes[0] !== 0x50 || bytes[1] !== 0x4b || bytes[2] !== 3 || bytes[3] !== 4) {
      fail(415, "CS-CNV-0002", "Format not supported");
    }
    if (new TextDecoder("latin1").decode(bytes).toLowerCase().includes("vbaproject")) fail(415, "CS-CNV-0004", "Macro-enabled document refused");
    return makePdf([{ title: "Converted Word document", lines: ["Mock mode: the server converts .docx files to PDF with docxide-pdf.", "This page stands in for the converted document."] }]);
  }
  function addDocument(env, name, upload) {
    const zip = upload instanceof Uint8Array && upload.length >= 4 && upload[0] === 0x50 && upload[1] === 0x4b;
    const bytes = zip ? mockConvert(upload) : upload;
    if (!(bytes instanceof Uint8Array) || bytes.length < 8 || String.fromCharCode(...bytes.subarray(0, 5)) !== "%PDF-") {
      fail(422, "CS-PDF-0001", "Not a PDF");
    }
    const id = uid();
    db.blobs[id] = b64(bytes);
    const doc = { id, name: String(name || "document.pdf").slice(0, 255), pages: countPages(bytes), bytes: upload.length, upload_sha256: null, delivered_sha256: null, admission_findings: 0, fixed: false };
    env.documents.push(doc);
    return doc;
  }
  function addRecipient(env, r) {
    if (!r || typeof r.name !== "string" || !r.name.trim()) fail(400, "CS-API-0001", "Recipient name required", [{ pointer: "/name", code: "required" }]);
    const type = r.type || "signer";
    // Every engine `RecipientType`, as the server takes them (UX-03).
    if (!RECIPIENT_TYPES.includes(type)) fail(400, "CS-API-0001", "Unknown recipient type", [{ pointer: "/type", code: "enum" }]);
    if (r.email && !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(r.email)) fail(400, "CS-API-0001", "Invalid email", [{ pointer: "/email", code: "format" }]);
    if (r.routing_order != null && (!Number.isInteger(r.routing_order) || r.routing_order < 1 || r.routing_order > 999)) fail(422, "CS-WF-0004", "Routing order out of range", [{ pointer: "/routing_order", code: "range" }]);
    if (Array.isArray(r.auth) && (r.auth.includes("sms_otp") || r.auth.includes("voice_otp")) && !/^\+[1-9][0-9 .()-]{7,}$/.test(r.phone || "")) fail(422, "CS-API-0001", "Malformed request", [{ pointer: "/phone", code: "CS-API-0001" }]);
    if (r.delivery != null && !["email", "sms", "none"].includes(r.delivery)) fail(400, "CS-API-0001", "Unknown delivery", [{ pointer: "/delivery", code: "enum" }]);
    const rec = {
      id: r.id || uid(), type, routing_order: Number.isInteger(r.routing_order) ? r.routing_order : 1, name: r.name.trim(), email: r.email || "",
      delivery: r.delivery || "email", auth: Array.isArray(r.auth) ? r.auth : [], status: "created", completed_at: null, declined_reason: null,
      consented: false, authenticated: false, auth_passed: [], access_code: r.access_code || null,
    };
    for (const k of ["phone", "embedded_client_user_id", "date_format", "witness_for"]) if (r[k] != null && r[k] !== "") rec[k] = r[k];
    if (Number.isInteger(r.time_zone_offset_minutes)) rec.time_zone_offset_minutes = r.time_zone_offset_minutes;
    visibilityAndDelay(env, rec, r);
    env.recipients.push(rec);
    return rec;
  }
  /// Document visibility and delayed routing (WF-02), as the server takes them: hidden
  /// documents by id (or, in a create, the index of a document of the same request), and
  /// hours routing waits once the recipient's turn comes. The mock records them; its
  /// ceremony does not hold or hide (the server's engine does).
  function visibilityAndDelay(env, rec, r) {
    if (r.route_delay_hours != null) {
      if (!Number.isInteger(r.route_delay_hours) || r.route_delay_hours < 0 || r.route_delay_hours > 65535) fail(400, "CS-API-0001", "Malformed request", [{ pointer: "/route_delay_hours", code: "CS-API-0001" }]);
      rec.route_delay_hours = r.route_delay_hours;
    }
    if (r.excluded_documents != null) {
      if (!Array.isArray(r.excluded_documents)) fail(400, "CS-API-0001", "Malformed request", [{ pointer: "/excluded_documents", code: "CS-API-0001" }]);
      rec.excluded_documents = r.excluded_documents.map((d) => (Number.isInteger(d) ? env.documents[d]?.id : d)).filter(Boolean);
    }
  }
  function placementOf(f) {
    const p = f.placement || f;
    const n = (v) => (typeof v === "number" ? v : Number.parseFloat(v));
    const out = { page: Number(p.page), x: n(p.x), y: n(p.y), width: n(p.width), height: n(p.height) };
    if (!Number.isInteger(out.page) || out.page < 1 || ![out.x, out.y, out.width, out.height].every((v) => Number.isFinite(v) && v >= 0) || !out.width || !out.height) {
      fail(422, "CS-FLD-0001", "Placement out of range", [{ pointer: "/placement", code: "range" }]);
    }
    const s = (v) => String(Math.round(v * 100) / 100);
    return { page: out.page, x: s(out.x), y: s(out.y), width: s(out.width), height: s(out.height) };
  }
  function addField(env, f, refs = {}, docIds = []) {
    const rid = refs[f.recipient] || f.recipient || f.recipient_id;
    if (!env.recipients.some((r) => r.id === rid)) fail(422, "CS-WF-0008", "Unknown recipient", [{ pointer: "/recipient", code: "unknown" }]);
    let did = f.document ?? f.document_id;
    if (Number.isInteger(did)) did = docIds[did];
    if (!env.documents.some((d) => d.id === did)) fail(422, "CS-WF-0008", "Unknown document", [{ pointer: "/document", code: "unknown" }]);
    const field = { id: f.id || uid(), document_id: did, recipient_id: rid, type: fieldType(f.type), placement: placementOf(f) };
    setMembers(field, f);
    // VS-04D, as the server: shared with other recipients, named as the owner is.
    const shared = (Array.isArray(f.shared_with) ? f.shared_with : []).map((x) => refs[x] || x);
    if (shared.length) field.shared_with = shared;
    env.fields.push(field);
    return field;
  }
  function fieldType(t) {
    const type = String(t || "text");
    if (!FIELD_TYPES.has(type)) fail(422, "CS-FLD-0002", "Unknown field type", [{ pointer: "/type", code: "CS-FLD-0002" }]);
    return type;
  }
  /// The engine field's members from a request (UX-03; the WEB-06 kinds' options,
  /// validation, a sender's value, locked, read-only, and format, group, conditional,
  /// formula, tooltip, placeholder, default). Unset, null, false or empty members are
  /// absent, as the server writes them; a given one is checked for its JSON kind only.
  function setMembers(field, f, at = "") {
    const kinds = { options: "array", validation: "object", value: "object", default: "object", format: "object", group: "object", conditional: "object", formula: "object" };
    for (const k of FIELD_MEMBERS) {
      if (!(k in f)) continue;
      const v = f[k];
      if (v == null || v === false || v === "" || (Array.isArray(v) && !v.length)) { delete field[k]; continue; }
      const want = kinds[k] || (["required", "read_only", "locked", "allow_custom"].includes(k) ? "boolean" : "string");
      const got = Array.isArray(v) ? "array" : typeof v;
      // A conditional's `when` may be a bare string ("checked"); the object holds it.
      if (got !== want) fail(422, "CS-FLD-0002", "Malformed field", [{ pointer: `${at}/${k}`, code: "CS-FLD-0002" }]);
      field[k] = want === "array" ? v.map(String) : want === "object" ? structuredClone(v) : v;
    }
  }
  function signersAt(env) {
    const pending = env.recipients.filter((r) => ACTING(r) && !["completed", "reassigned"].includes(r.status));
    if (!pending.length) return null;
    return Math.min(...pending.map((r) => r.routing_order));
  }
  /// Send to everyone routing has reached (`invitation.sent`, as the worker records it
  /// once the email is out). Answers the routing order reached, `null` when none is left.
  async function route(env, at = null) {
    const order = signersAt(env);
    for (const r of env.recipients) {
      if (ACTING(r) && r.routing_order === order && r.status === "created") {
        r.status = "sent";
        const token = r.token || `tok-${r.id}`;
        r.token = token;
        db.tokens[token] = { env: env.id, rid: r.id };
        await audit(env, "invitation.sent", { recipient_id: r.id, channel: "email" }, { by: "system", at });
      }
    }
    return order;
  }
  /// Whether recipient `rid` fills field `f`: theirs, or shared with them (VS-04D).
  const holds = (f, rid) => f.recipient_id === rid || (f.shared_with || []).includes(rid);
  const viewedAll = (env, rec) => env.documents.every((d) => (rec.viewed_to_end || []).includes(d.id));
  /// Required input fields of this recipient left empty refuse finishing or approving.
  function checkRequired(env, rec) {
    // VS-04C: a hidden field is never required; a linked field's mirrored value counts.
    const rules = rulesFor(env.fields, rec.id);
    const has = (f) => { const v = f.value || rules.values[f.id]; return !(v == null || v.text === "" || v.choice === "" || v.checked === false || (Array.isArray(v.choices) && !v.choices.length)); };
    const missing = env.fields.filter((f) => f.recipient_id === rec.id && f.required && INPUT_TYPES.has(f.type) && !rules.hidden.includes(f.id) && !has(f));
    if (missing.length) fail(422, "CS-WF-0004", "Required fields are empty", missing.map((f) => ({ pointer: `/fields/${f.id}`, code: "required" })));
    const problems = finishProblems(env.fields, rec.id);
    if (problems.length) fail(422, "CS-FLD-0001", "Field rules refused the value", problems);
  }
  /// A recipient finished their part: routing moves on, and when nobody is left the
  /// envelope completes and is "sealed".
  /// As the engine: a signer's `recipient.signed` (documents and value hashes) or an
  /// approver's `recipient.approved`, then `recipient.completed`; a viewer only the last.
  async function complete(env, rec, loc = {}, how = "signed", at = null) {
    rec.status = "completed"; rec.completed_at = at || iso();
    const opts = { ...loc, at: rec.completed_at };
    if (how === "signed") {
      const field_value_hashes = {};
      for (const f of env.fields) if (f.recipient_id === rec.id && f.value != null) field_value_hashes[f.id] = await sha256hex(JSON.stringify(f.value));
      await audit(env, "recipient.signed", { recipient_id: rec.id, documents: await docHashes(env), field_value_hashes }, opts);
    } else if (how === "approved") await audit(env, "recipient.approved", { recipient_id: rec.id, documents: await docHashes(env) }, opts);
    await audit(env, "recipient.completed", { recipient_id: rec.id }, { at: rec.completed_at });
    const next = await route(env, rec.completed_at);
    if (next == null) await seal(env, rec.completed_at);
    env.version++;
  }
  /// Every required recipient finished: completing, each document flattened and sealed
  /// (the seal job), completed. The mock's "sealed" document is the delivered one.
  async function seal(env, at = null) {
    env.status = "completed"; env.ended_at = at || iso(); env.sealed = true;
    for (const r of env.recipients) if (r.type === "cc") { r.status = "completed"; r.completed_at ||= env.ended_at; }
    const when = { at: env.ended_at };
    await audit(env, "envelope.completing", {}, when);
    const sealed = [];
    for (const d of env.documents) {
      await audit(env, "document.flattened", { document_id: d.id, flattened_hash: await blobHash(d.id, ":flattened") }, when);
      const sealed_hash = await blobHash(d.id, ":sealed");
      await audit(env, "document.sealed", { document_id: d.id, sealed_hash, profile: env.seal_profile, certificate_fingerprint: await sha256hex("mock-certificate") }, when);
      sealed.push({ document_id: d.id, hash: sealed_hash });
    }
    await audit(env, "envelope.completed", { sealed }, when);
  }
  async function decline(env, rec, reason, loc = {}, at = null) {
    rec.status = "declined"; rec.declined_reason = reason || null;
    env.status = "declined"; env.ended_at = at || iso(); env.version++;
    await audit(env, "recipient.declined", { recipient_id: rec.id, ...(reason ? { reason } : {}) }, { ...loc, at: env.ended_at });
    await audit(env, "envelope.declined", { recipient_id: rec.id }, { by: "recipient", at: env.ended_at });
  }
  async function send(env, at = null) {
    const violations = [];
    if (!env.documents.length) violations.push({ pointer: "/documents", code: "required" });
    if (!env.recipients.some(ACTING)) violations.push({ pointer: "/recipients", code: "no_signer" });
    for (const r of env.recipients) if (!r.email) violations.push({ pointer: `/recipients/${r.id}/email`, code: "required" });
    for (const s of env.recipients.filter((r) => SIGNS.has(r.type))) if (!env.fields.some((f) => f.recipient_id === s.id)) violations.push({ pointer: `/recipients/${s.id}`, code: "no_fields" });
    // A field its recipient's type may not hold (the engine's `FieldNotAllowedForType`):
    // an approver never signs; a viewer or copy holds only notes and links.
    for (const f of env.fields) {
      const r = env.recipients.find((x) => x.id === f.recipient_id);
      if (r && !fieldAllowed(r.type, f.type)) violations.push({ pointer: `/fields/${f.id}`, code: "field_not_allowed" });
    }
    for (const r of env.recipients) {
      if ((r.route_delay_hours || 0) > 720) violations.push({ pointer: `/recipients/${r.id}`, code: "CS-WF-0023" });
      const hidden = r.excluded_documents || [];
      if (env.documents.length && env.documents.every((d) => hidden.includes(d.id))) violations.push({ pointer: `/recipients/${r.id}`, code: "CS-WF-0004" });
    }
    for (const f of env.fields) {
      const r = env.recipients.find((x) => x.id === f.recipient_id);
      if (r && (r.excluded_documents || []).includes(f.document_id)) violations.push({ pointer: `/fields/${f.id}`, code: "CS-WF-0021" });
    }
    if (violations.length) fail(422, "CS-WF-0004", "Envelope invalid for sending", violations);
    env.send_at = null;
    env.status = "sent";
    env.sent_at = at || iso();
    env.version++;
    for (const d of env.documents) d.fixed = true;
    await audit(env, "envelope.sent", { recipients: env.recipients.length, documents: env.documents.length }, { by: "sender", at: env.sent_at });
    for (const d of env.documents) await audit(env, "document.fixed", { document_id: d.id, delivered_hash: await blobHash(d.id), pages: d.pages }, { by: "sender", at: env.sent_at });
    await route(env, env.sent_at);
  }
  /// The ceremony view (docs/40 §6), as the server's `view_of`, with (UXW-34) `sender`
  /// {name, email, organisation}, `envelope.expires_at` and the disclosure's `url`.
  function view(env, rec, token) {
    const sender = db.users.find((u) => u.id === env.sender_user_id);
    const acct = account();
    // SEC-CER-01: no document and no field until every authentication is passed.
    const shown = rec.auth.every((m) => rec.auth_passed.includes(m));
    return {
      envelope: { id: env.id, status: env.status, subject: env.subject, message: env.message, signing_options: env.signing_options, documents: shown ? env.documents : [], expires_at: env.expires_at },
      recipient: publicRecipient(rec),
      fields: shown ? env.fields.filter((f) => holds(f, rec.id)) : [],
      // VS-04C, as the server: the rules over every field, named for this recipient's.
      rules: shown ? rulesFor(env.fields, rec.id) : null,
      capture_location: !!env.signing_options?.capture_location,
      consent_required: { version: disclosure().version, sha256: disclosure().sha256, url: `/s/${encodeURIComponent(token)}/disclosure` },
      auth_required: rec.auth.filter((m) => !rec.auth_passed.includes(m)),
      ...(rec.auth.includes("sso") && !rec.auth_passed.includes("sso") ? { sso_providers: [MOCK.ssoProvider] } : {}),
      sender: { name: sender?.name || "", email: sender?.email || "", organisation: acct.settings?.branding?.name || acct.name },
      // ADR-041: an envelope sent from a sandbox workspace.
      sandbox: env.sandbox === true,
      // VS-02, as the server: an agent, intermediary or editor sees the later
      // recipients not yet reached, which `POST /s/{token}/recipients` may name.
      ...(shown && NAMES_LATER.has(rec.type) ? { later_recipients: laterOf(env, rec) } : {}),
      // FG-080, as the server: every strike-through on a document they see, whoever drew it.
      ...(shown ? { strikes: env.fields.filter((f) => f.type === "strikethrough" && !(rec.excluded_documents || []).includes(f.document_id)).map((f) => ({ id: f.id, document_id: f.document_id, placement: f.placement, recipient_id: f.recipient_id })) } : {}),
      // VS-06A, as the server: an editor also sees the later recipients' fields, which
      // `PATCH`/`DELETE /s/{token}/editor/fields/{field}` may change.
      ...(shown && rec.type === "editor" ? { editable_fields: env.fields.filter((f) => !holds(f, rec.id) && editableField(env, rec, f)) } : {}),
    };
  }
  /// VS-06A, as the server's `editable_owner`: an editor changes their own fields and
  /// those of recipients later in the order not yet reached.
  const editableOwner = (rec, q) => q.id === rec.id || ((q.routing_order || 1) > (rec.routing_order || 1) && q.status === "created");
  const editableField = (env, rec, f) => !!f.recipient_id && !(rec.excluded_documents || []).includes(f.document_id)
    && [f.recipient_id, ...(f.shared_with || [])].every((r) => { const q = env.recipients.find((x) => x.id === r); return q && editableOwner(rec, q); });
  const laterOf = (env, rec) => env.recipients
    .filter((q) => (q.routing_order || 1) > (rec.routing_order || 1) && q.status === "created")
    .map((q) => ({ id: q.id, type: q.type, routing_order: q.routing_order || 1, name: q.name || "", email: q.email || "", phone: q.phone || null, auth: [...(q.auth || [])] }));
  const publicRecipient = (r) => {
    const { access_code, auth_passed, token, otp_open, sso_state, viewed_to_end, hosted, ...rest } = r;
    void access_code; void auth_passed; void token; void otp_open; void sso_state; void viewed_to_end; void hosted;
    return { ...rest, authenticated: r.auth.every((m) => r.auth_passed.includes(m)) };
  };
  const publicEnvelope = (e) => ({ ...e, recipients: e.recipients.map((r) => ({ ...publicRecipient(r), mock_token: r.token || null })) });

  // ---- Seed ------------------------------------------------------------------
  async function seed({ fieldKinds = false } = {}) {
    const doc = (title, n = 2) => makePdf(Array.from({ length: n }, (_, i) => ({
      title: i === 0 ? title : `${title} (continued)`,
      lines: [
        "This agreement is made between the parties named below.",
        "1. Scope. The parties agree to the terms set out in this document.",
        "2. Term. This agreement starts on the date of the last signature.",
        "3. Confidentiality. Each party keeps the other's information confidential.",
        `Page ${i + 1} of ${n}. Demo document generated in mock mode.`,
      ],
    })));
    const mk = async (subject, minutesAgo, recipients, fieldsFor, after) => {
      const env = newEnvelope({ subject, message: "Please review and sign.", created_at: iso(-minutesAgo) });
      await audit(env, "envelope.created", { subject_hash: await sha256hex(subject) }, { by: "sender", at: iso(-minutesAgo) });
      addDocument(env, `${subject.split(" ")[0].toLowerCase()}.pdf`, doc(subject));
      const recs = recipients.map((r) => addRecipient(env, r));
      for (const [i, list] of fieldsFor.entries()) for (const f of list) addField(env, { ...f, recipient: recs[i].id, document: env.documents[0].id });
      const when = { by: "sender", at: iso(-minutesAgo) };
      for (const d of env.documents) {
        await audit(env, "document.added", { document_id: d.id, upload_hash: await blobHash(d.id), bytes: d.bytes }, when);
        await audit(env, "document.admitted", { document_id: d.id, report_hash: await blobHash(d.id, ":admission"), findings: 0 }, when);
      }
      await audit(env, "envelope.corrected", { changed: [...env.documents.map((d) => `documents.${d.id}`), ...recs.map((r) => `recipients.${r.id}`), ...env.fields.map((f) => `fields.${f.id}`)] }, when);
      if (after) await after(env, recs);
      return env;
    };
    const sigFields = (y = 600) => [
      { type: "signature", page: 1, x: 72, y, width: 160, height: 44, required: true },
      { type: "date_signed", page: 1, x: 340, y: y + 22, width: 110, height: 22 },
    ];
    // Every field kind a signer fills or reads (WEB-06), made only when its link is
    // first opened, so the sender's seeded lists and counts stay as they were.
    if (fieldKinds) {
      await mk("Order form — Northwind", 60 * 3,
        [{ name: "Morgan Diaz", email: "morgan@northwind.example", routing_order: 1 }],
        [[
          { type: "note", page: 1, x: 72, y: 300, width: 300, height: 22, label: "Note", value: { text: "Read clause 4 before signing." }, read_only: true, locked: true },
          { type: "text", page: 1, x: 72, y: 340, width: 160, height: 22, label: "PO number", value: { text: "PO-7781" }, locked: true },
          { type: "company", page: 1, x: 72, y: 380, width: 200, height: 22, required: true, label: "Company" },
          { type: "title", page: 1, x: 300, y: 380, width: 160, height: 22, label: "Title" },
          { type: "number", page: 1, x: 72, y: 420, width: 100, height: 22, required: true, label: "Quantity", validation: { kind: "number", min: "1", max: "100", decimals: 0 } },
          { type: "text", page: 1, x: 200, y: 420, width: 200, height: 22, label: "Email", validation: { kind: "email" } },
          { type: "text", page: 1, x: 72, y: 460, width: 160, height: 22, label: "Phone", validation: { kind: "phone" } },
          { type: "text", page: 1, x: 260, y: 460, width: 100, height: 22, label: "ZIP", validation: { kind: "zip" } },
          { type: "radio_group", page: 1, x: 72, y: 500, width: 160, height: 22, required: true, label: "Plan", options: ["Basic", "Pro"] },
          { type: "dropdown", page: 1, x: 260, y: 500, width: 160, height: 22, label: "Term", options: ["12 months", "24 months"] },
          { type: "attachment", page: 1, x: 72, y: 540, width: 160, height: 26, label: "Proof of ID" },
          { type: "signature", page: 1, x: 72, y: 600, width: 160, height: 44, required: true },
        ]],
        async (env, recs) => { recs[0].token = MOCK.fieldsToken; await send(env); });
      return;
    }
    // Seeded histories carry their own times (WEB-06 E-05): the audit trail's dates
    // agree with the envelope's sent, opened, signed and ended dates.
    const completeAll = async (env, recs) => {
      await send(env, iso(-60 * 24 * 2)); // sent two days before it was signed
      let at = -60 * 24 * 2;
      for (const r of recs.filter((x) => ACTING(x))) {
        at += 60 * 3;
        r.status = "delivered";
        await audit(env, "recipient.delivered", { recipient_id: r.id }, { at: iso(at) });
        at += 20;
        r.consented = true;
        await complete(env, r, {}, "signed", iso(at));
      }
    };
    await mk("Mutual NDA — Acme and Globex", 60 * 24 * 3,
      [{ name: "Avery Chen", email: "avery@acme.example", routing_order: 1 }, { name: "Sam Patel", email: "sam@globex.example", routing_order: 2 }],
      [sigFields(560), sigFields(640)], completeAll);
    const offer = await mk("Offer letter — Jordan Rivera", 60 * 5,
      [
        { name: "Jordan Rivera", email: "jordan@example.com", routing_order: 1, auth: ["access_code"], access_code: MOCK.accessCode },
        { name: "People Ops", email: "people@example.com", type: "cc", routing_order: 2 },
      ],
      [[
        { type: "text", page: 1, x: 72, y: 470, width: 200, height: 22, required: true, label: "Job title" },
        { type: "checkbox", page: 1, x: 72, y: 510, width: 16, height: 16, label: "Relocation package" },
        { type: "signature", page: 1, x: 72, y: 600, width: 160, height: 44, required: true },
        { type: "date_signed", page: 1, x: 340, y: 622, width: 110, height: 22 },
      ], []],
      async (env, recs) => {
        env.signing_options = { capture_location: true, allow_decline: true, allow_finish_later: true, allow_reassign: true };
        env.expires_at = iso(60 * 24 * 3);
        recs[0].token = MOCK.ceremonyToken;
        await send(env, iso(-60 * 4));
      });
    void offer;
    await mk("Vendor services agreement", 60 * 26,
      [{ name: "Riley Morgan", email: "riley@vendor.example", routing_order: 1 }],
      [sigFields(600)],
      async (env, recs) => { recs[0].token = MOCK.declineToken; env.signing_options = { allow_decline: true }; await send(env, iso(-60 * 25)); });
    await mk("Lease renewal 2027", 60 * 2,
      [{ name: "Taylor Kim", email: "taylor@example.com", routing_order: 1 }], [sigFields(600)]);
    await mk("Consulting SOW — Q1", 60 * 24 * 6,
      [{ name: "Casey Lee", email: "casey@example.com", routing_order: 1 }], [sigFields(600)],
      async (env) => { await send(env, iso(-60 * 24 * 6 + 60)); env.status = "voided"; env.void_reason = "Replaced by a new version"; env.ended_at = iso(-60 * 24 * 5); env.version++; await audit(env, "envelope.voided", { reason: env.void_reason }, { by: "sender", at: env.ended_at }); });
    await mk("Board consent — November", 60 * 24 * 2,
      [{ name: "Morgan Diaz", email: "morgan@example.com", routing_order: 1 }], [sigFields(600)],
      async (env, recs) => {
        await send(env, iso(-60 * 24 * 2 + 30));
        recs[0].status = "delivered";
        await audit(env, "recipient.delivered", { recipient_id: recs[0].id }, { at: iso(-60 * 25) });
        await decline(env, recs[0], "Wrong meeting date", {}, iso(-60 * 24));
      });

    // Templates (WEB-02): one with a document and fields, one with roles only.
    const nda = newTemplate({ name: "Mutual NDA", email_subject: "Mutual NDA for signature", email_message: "Please review and sign this NDA.", roles: [{ name: "Company", type: "signer", routing_order: 1 }, { name: "Counterparty", type: "signer", routing_order: 2 }, { name: "Legal", type: "cc", routing_order: 3 }] }, iso(-60 * 24 * 10));
    const ndaBytes = doc("Mutual non-disclosure agreement");
    const ndaDoc = { id: uid(), name: "mutual-nda.pdf", ord: 0, pages: 2, sha256: null };
    db.blobs[ndaDoc.id] = b64(ndaBytes);
    nda.documents.push(ndaDoc);
    for (const [role, y] of [["Company", 560], ["Counterparty", 640]]) {
      const roleId = nda.roles.find((r) => r.name === role).id;
      for (const f of sigFields(y)) nda.fields.push({ id: uid(), document_id: ndaDoc.id, role_id: roleId, type: f.type, placement: placementOf(f), ...(f.required ? { required: true } : {}) });
    }
    nda.last_used_at = iso(-60 * 24 * 3);
    newTemplate({ name: "Contractor onboarding", email_subject: "Welcome aboard: documents to sign", roles: [{ name: "Contractor", type: "signer", routing_order: 1 }] }, iso(-60 * 24 * 4));

    db.users.push(
      { id: "user-demo", email: MOCK.email, name: "Demo Admin", login_kind: "local", permission_profile_id: "profile-admin", disabled: false },
      { id: "user-robin", email: "sender@openseal.test", name: "Robin Sender", login_kind: "local", permission_profile_id: "profile-sender", disabled: false },
    );
    // UXW-06: a group to share templates with.
    db.groups.push({ id: "group-legal", name: "Legal", members: 1, user_ids: ["user-robin"] });
    db.apiClients.push({ id: uid(), kind: "api_key", name: "CRM integration", owner_user_id: "user-demo", key_prefix: "osk_3f9a12c0", scopes: ["envelopes:read", "envelopes:write", "envelopes:send"], expires_at: null, revoked: false });
    // One webhook subscription with a delivered and a failed delivery (UX-03), so the
    // Admin webhooks screen has rows to show.
    const hook = { id: uid(), envelope_id: null, url: "https://hooks.example.com/openseal", event_types: ["envelope.completed", "envelope.declined", "recipient.completed"], secret_refs: ["crm_signing_secret"], active: true };
    db.webhooks.push(hook);
    db.deliveries[hook.id] = [
      { id: uid(), event_id: uid(), event_type: "envelope.declined", status: "failed", attempts: 6, last_status_code: 503 },
      { id: uid(), event_id: uid(), event_type: "envelope.completed", status: "delivered", attempts: 1, last_status_code: 200 },
    ];
    // The workspace's admin log (UXW-09): made by the server, its first admin added, a
    // member added and a setting changed.
    await adminEvent("workspace.created", { by: "system", target: { account: "acct-demo" }, at: iso(-60 * 24 * 30) });
    await adminEvent("member.added", { by: "system", target: { user: "user-demo" }, changes: [{ key: "profile", old: null, new: "profile-admin" }], at: iso(-60 * 24 * 30) });
    await adminEvent("member.added", { target: { user: "user-robin" }, changes: [{ key: "profile", old: null, new: "profile-sender" }], at: iso(-60 * 24 * 20) });
    await adminEvent("workspace.settings_changed", { target: { account: "acct-demo" }, changes: [{ key: "first_reminder_days", old: null, new: 3 }], at: iso(-60 * 24 * 10) });
  }

  // ---- HTTP plumbing ---------------------------------------------------------
  const json = (status, body, headers = {}) =>
    new Response(body == null ? null : JSON.stringify(body), { status, headers: { "Content-Type": "application/json", ...headers } });
  const problem = (p) =>
    new Response(JSON.stringify({ type: "about:blank", title: p.title || p.code, status: p.status, code: p.code, request_id: `mock-${uid().slice(0, 8)}`, ...(p.errors ? { errors: p.errors } : {}), ...(p.detail ? { detail: p.detail } : {}) }),
      { status: p.status, headers: { "Content-Type": "application/problem+json" } });
  const pdf = (bytes) => new Response(bytes, { status: 200, headers: { "Content-Type": "application/pdf" } });

  function envOr404(id) {
    const e = db.envelopes.find((x) => x.id === id);
    if (!e) fail(404, "CS-API-0002", "Not found");
    return e;
  }
  function checkIfMatch(env, headers) {
    const v = headers["if-match"];
    if (!v) fail(428, "CS-API-0008", "Precondition required");
    if (v !== `"v${env.version}"`) fail(412, "CS-WF-0002", "Stale version");
  }
  const draftOnly = (env) => { if (env.status !== "draft") fail(409, "CS-WF-0001", "Not allowed in the current state"); };
  /// A scheduled draft sends as it was scheduled (WF-02).
  const notScheduled = (env) => { if (env.send_at) fail(409, "CS-WF-0022", "The draft is scheduled to send"); };
  const withEtag = (env, status = 200) => json(status, publicEnvelope(env), { ETag: `"v${env.version}"` });

  // ---- Corrections (docs/24 §6; the engine's `apply_changes` in the Correct scope) -------
  /// Whether a change to recipients or fields corrects a sent envelope (`true`) or edits a
  /// draft (`false`); any other state refuses it.
  function editable(env) {
    if (env.status === "draft") return false;
    if (["sent", "delivered"].includes(env.status)) return true;
    fail(409, "CS-WF-0001", "Not allowed in the current state");
  }
  /// A recipient no correction may change: completed, declined or handed over.
  const settled = (r) => ["completed", "declined", "reassigned"].includes(r.status);
  /// A correction may touch a field of a recipient who has not declined or handed over;
  /// one who completed acts again (the engine's `redo`).
  function fieldOwnerOk(env, rid) {
    const r = env.recipients.find((x) => x.id === rid);
    if (!r) return;
    if (["declined", "reassigned"].includes(r.status)) fail(409, "CS-WF-0001", "Recipient has already acted");
    if (r.status === "completed") { r.status = "created"; r.completed_at = null; r.redo = true; }
  }
  function removeRecipient(env, r) {
    if (r.token) delete db.tokens[r.token];
    env.recipients = env.recipients.filter((x) => x !== r);
    env.fields = env.fields.filter((f) => f.recipient_id !== r.id);
  }
  /// After a correction: the version, `envelope.corrected` with the paths changed, and
  /// routing (a recipient added or put back at the current order is invited).
  async function corrected(env, changed) {
    env.version++;
    await audit(env, "envelope.corrected", { changed }, { by: "sender" });
    for (const r of env.recipients) if (r.redo) { delete r.redo; if (r.token) delete db.tokens[r.token]; r.token = null; }
    await route(env);
  }
  /// A draft's edit: the server's `Edit` records `envelope.corrected` too (engine.rs).
  async function edited(env, changed) {
    env.version++;
    if (changed.length) await audit(env, "envelope.corrected", { changed }, { by: "sender" });
  }
  /// An uploaded document, as `AddDocument` records it: added, then admitted.
  async function documentAdded(env, d) {
    await audit(env, "document.added", { document_id: d.id, upload_hash: await blobHash(d.id), bytes: d.bytes }, { by: "sender" });
    await audit(env, "document.admitted", { document_id: d.id, report_hash: await blobHash(d.id, ":admission"), findings: d.admission_findings }, { by: "sender" });
  }
  const SPEC = ["id", "type", "routing_order", "name", "email", "phone", "delivery", "auth", "embedded_client_user_id", "time_zone_offset_minutes", "date_format", "witness_for", "excluded_documents", "route_delay_hours"];
  /// An engine `RecipientSpec`: its members only, the four it needs present.
  function checkSpec(n, at) {
    if (!n || typeof n !== "object") fail(400, "CS-API-0001", "Malformed request", [{ pointer: at, code: "type" }]);
    for (const k of Object.keys(n)) if (!SPEC.includes(k)) fail(400, "CS-API-0001", "Unknown member", [{ pointer: `${at}/${k}`, code: "unknown" }]);
    for (const k of ["id", "type", "routing_order", "name", "email"]) if (!(k in n)) fail(400, "CS-API-0001", "Malformed request", [{ pointer: `${at}/${k}`, code: "required" }]);
    if (typeof n.id !== "string" || !/^[A-Za-z0-9_-]{1,64}$/.test(n.id)) fail(422, "CS-FLD-0005", "Invalid id", [{ pointer: `${at}/id`, code: "CS-FLD-0005" }]);
    if (typeof n.name !== "string" || !n.name.trim()) fail(400, "CS-API-0001", "Recipient name required", [{ pointer: `${at}/name`, code: "required" }]);
    if (typeof n.email !== "string" || (n.email && !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(n.email))) fail(400, "CS-API-0001", "Invalid email", [{ pointer: `${at}/email`, code: "format" }]);
    if (!RECIPIENT_TYPES.includes(n.type)) fail(400, "CS-API-0001", "Unknown recipient type", [{ pointer: `${at}/type`, code: "enum" }]);
  }
  /// One `Change` of a correction (the engine's `apply_changes`, `Scope::Correct`).
  function applyChange(env, c, at, changed) {
    const unknownId = (kind) => fail(422, "CS-WF-0008", `Unknown ${kind}`, [{ pointer: `${at}/id`, code: "unknown" }]);
    switch (c?.op) {
      case "add_recipient": {
        checkSpec(c.recipient, `${at}/recipient`);
        if (env.recipients.some((r) => r.id === c.recipient.id)) fail(409, "CS-WF-0010", "Id already used", [{ pointer: `${at}/recipient/id`, code: "duplicate" }]);
        addRecipient(env, c.recipient);
        changed.push(`recipients.${c.recipient.id}`);
        return;
      }
      case "update_recipient": {
        const n = c.recipient;
        checkSpec(n, `${at}/recipient`);
        const r = env.recipients.find((x) => x.id === n.id) || unknownId("recipient");
        // Not one who has acted, and never a change of type (the engine's `refused`).
        if (settled(r) || r.type !== n.type) fail(409, "CS-WF-0001", "Recipient has already acted", [{ pointer: `${at}/recipient/id`, code: "acted" }]);
        Object.assign(r, { routing_order: n.routing_order, name: n.name.trim(), email: n.email, delivery: n.delivery || "email", auth: Array.isArray(n.auth) ? n.auth : [] });
        for (const k of ["phone", "embedded_client_user_id", "date_format", "witness_for", "time_zone_offset_minutes", "excluded_documents", "route_delay_hours"]) { if (n[k] != null) r[k] = n[k]; else delete r[k]; }
        if (!r.auth.includes("access_code")) r.access_code = null;
        changed.push(`recipients.${r.id}`);
        return;
      }
      case "remove_recipient": {
        const r = env.recipients.find((x) => x.id === c.id) || unknownId("recipient");
        if (settled(r)) fail(409, "CS-WF-0001", "Recipient has already acted", [{ pointer: `${at}/id`, code: "acted" }]);
        removeRecipient(env, r);
        changed.push(`recipients.${r.id}`);
        return;
      }
      case "add_field":
      case "update_field": {
        const f = c.field;
        if (!f || typeof f !== "object" || typeof f.id !== "string" || !f.placement) fail(400, "CS-API-0001", "Malformed request", [{ pointer: `${at}/field`, code: "type" }]);
        const i = env.fields.findIndex((x) => x.id === f.id);
        if (c.op === "add_field" && i >= 0) fail(409, "CS-WF-0010", "Id already used", [{ pointer: `${at}/field/id`, code: "duplicate" }]);
        if (c.op === "update_field" && i < 0) unknownId("field");
        if (i >= 0) fieldOwnerOk(env, env.fields[i].recipient_id);
        fieldOwnerOk(env, f.recipient_id);
        const { placement, ...rest } = f;
        const made = addField(env, { ...rest, ...placement });
        env.fields.pop();
        if (i >= 0) env.fields[i] = made; else env.fields.push(made);
        changed.push(`fields.${f.id}`);
        return;
      }
      case "remove_field": {
        const i = env.fields.findIndex((x) => x.id === c.id);
        if (i < 0) unknownId("field");
        fieldOwnerOk(env, env.fields[i].recipient_id);
        env.fields.splice(i, 1);
        changed.push(`fields.${c.id}`);
        return;
      }
      case "remove_document": {
        if (!env.documents.some((d) => d.id === c.id)) unknownId("document");
        env.documents = env.documents.filter((d) => d.id !== c.id);
        env.fields = env.fields.filter((f) => f.document_id !== c.id);
        changed.push(`documents.${c.id}`);
        return;
      }
      case "set_subject": env.subject = String(c.subject ?? ""); changed.push("subject"); return;
      case "set_message": env.message = String(c.message ?? ""); changed.push("message"); return;
      case "set_expiry": {
        if (c.expires_at != null && !(new Date(c.expires_at).getTime() > now().getTime())) fail(422, "CS-WF-0004", "Envelope invalid", [{ pointer: `${at}/expires_at`, code: "expiry_in_past" }]);
        env.expires_at = c.expires_at == null ? null : new Date(c.expires_at).toISOString();
        changed.push("expires_at");
        return;
      }
      case "set_reminders": {
        const r = c.reminders || {};
        const ok = (v) => v == null || (Number.isInteger(v) && v >= 0 && v <= 999);
        if (!ok(r.first_after_days) || !ok(r.then_every_days)) fail(422, "CS-WF-0004", "Reminder step out of range", [{ pointer: `${at}/reminders`, code: "range" }]);
        env.reminders = { first_after_days: r.first_after_days || 0, then_every_days: r.then_every_days || 0 };
        changed.push("reminders");
        return;
      }
      case "set_signing_options":
        // As the engine (FG-009, ADR-045): the envelope id stamp is fixed once sent.
        if (!!c.options?.stamp_envelope_id !== !!env.signing_options?.stamp_envelope_id) fail(409, "CS-WF-0001", "Not allowed in the current state");
        env.signing_options = stampOff({ ...(c.options || {}) }); changed.push("signing_options"); return;
      case "set_seal_profile": fail(409, "CS-WF-0001", "Not allowed in the current state", [{ pointer: `${at}/op`, code: "draft_only" }]);
      // falls through: fail throws
      default: fail(422, "CS-API-0001", "Malformed request", [{ pointer: `${at}/op`, code: "CS-API-0001" }]);
    }
  }

  // ---- The envelope list (WEB-04, WEB-08, UX-03) --------------------------------------
  const LIFECYCLE = ["draft", "sent", "delivered", "completing", "completed", "declined", "voided", "expired"];
  /// The last change, as the server's `updated_at`: the latest of its dates and events.
  function updatedAt(e) {
    const last = (db.audit[e.id] || []).at(-1)?.at;
    return [e.created_at, e.sent_at, e.ended_at, e.deleted_at, last].filter(Boolean).sort().at(-1);
  }
  /// The recipient the signed-in user is, when routing has reached them (the Inbox).
  function myRecipient(e) {
    const me = db.users.find((u) => u.id === "user-demo");
    if (!me || !["sent", "delivered"].includes(e.status) || e.deleted_at) return null;
    return e.recipients.find((r) => r.email.toLowerCase() === me.email.toLowerCase() && ["sent", "delivered"].includes(r.status) && r.token) || null;
  }
  /// One envelope sent to the demo user by another member, made the first time the
  /// Inbox is asked for, so the seeded lists and counts stay as they were.
  async function seedInbox() {
    if (db.inboxSeeded) return;
    db.inboxSeeded = true;
    const env = newEnvelope({ subject: "Expense policy acknowledgement", message: "Please read and sign by Friday.", created_at: iso(-90) });
    env.sender_user_id = "user-robin";
    await audit(env, "envelope.created", { subject_hash: await sha256hex(env.subject) }, { by: "sender", at: iso(-90) });
    addDocument(env, "expense-policy.pdf", makePdf([{ title: "Expense policy", lines: ["Demo document generated in mock mode."] }]));
    const r = addRecipient(env, { name: "Demo Admin", email: MOCK.email, routing_order: 1 });
    addField(env, { type: "signature", page: 1, x: 72, y: 600, width: 160, height: 44, required: true, recipient: r.id, document: env.documents[0].id });
    r.token = MOCK.inboxToken;
    await send(env, iso(-80));
  }
  async function listEnvelopes(query) {
    const limit = Math.min(Math.max(Number(query.get("limit")) || 50, 1), 200);
    const start = Number(query.get("cursor") || 0) || 0;
    const bad = (k) => fail(422, "CS-API-0001", "Malformed request", [{ pointer: `/query/${k}`, code: "CS-API-0001" }]);
    // `status`: one or several, comma-separated (WEB-08).
    const statuses = (query.get("status") || "").split(",").filter(Boolean);
    if (statuses.some((x) => !LIFECYCLE.includes(x))) bad("status");
    // `q` (WEB-04): the subject or a recipient's name or email contains it, any case.
    const text = (query.get("q") || "").trim().toLowerCase();
    const has = (v, t) => (v || "").toLowerCase().includes(t);
    const matches = (e) => !text || [e.subject, ...(e.recipients || []).flatMap((r) => [r.name, r.email])].some((v) => has(v, text));
    const sort = query.get("sort") || "created_at";
    if (!["created_at", "updated_at", "expires_at", "subject", "status"].includes(sort)) bad("sort");
    const order = query.get("order") || (["subject", "status"].includes(sort) ? "asc" : "desc");
    if (!["asc", "desc"].includes(order)) bad("order");
    const senderQ = query.get("sender");
    const sender = senderQ === "me" ? "user-demo" : senderQ;
    // As the server (UXW-01/02/03): `recipient`, `date_field`, `folder`, `deleted`,
    // `waiting_for=me`.
    const recipient = (query.get("recipient") || "").trim().toLowerCase();
    const dateField = query.get("date_field") || "updated_at";
    if (!["updated_at", "created_at", "sent_at", "completed_at"].includes(dateField)) bad("date_field");
    const folder = query.get("folder");
    const deleted = query.get("deleted") === "true";
    const waiting = query.get("waiting_for");
    if (waiting != null && waiting !== "me") bad("waiting_for");
    if (waiting) await seedInbox();
    // VS-06: the Authentication failed view, Expiring soon, custom fields.
    const authFailedQ = query.get("auth_failed");
    if (authFailedQ != null && !["true", "false"].includes(authFailedQ)) bad("auth_failed");
    const authFailed = authFailedQ === "true";
    const expiresBefore = query.get("expires_before");
    if (expiresBefore != null && Number.isNaN(Date.parse(expiresBefore))) bad("expires_before");
    const cfName = (query.get("custom_field") || "").trim();
    const cfValue = (query.get("custom_value") || "").trim().toLowerCase();
    if (cfValue && !cfName) bad("custom_value");
    const failedAuth = (e) => ["sent", "delivered"].includes(e.status)
      && (e.recipients || []).some((r) => (r.auth_failures || 0) > 0 && ["sent", "delivered"].includes(r.status));
    const hasCustom = (e) => (e.custom_fields || []).some((f) => f.name === cfName && (!cfValue || has(f.value, cfValue)));
    const dateOf = (e) => (dateField === "updated_at" ? updatedAt(e) : dateField === "completed_at" ? (e.status === "completed" ? e.ended_at : null) : e[dateField]);
    const from = query.get("from");
    const to = query.get("to");
    const inRange = (e) => {
      if (!from && !to) return true;
      const d = dateOf(e);
      return !!d && (!from || d >= new Date(from).toISOString()) && (!to || d < new Date(to).toISOString());
    };
    const key = (e) => (sort === "updated_at" ? updatedAt(e) : sort === "status" ? LIFECYCLE.indexOf(e.status) : sort === "subject" ? (e.subject || "").toLowerCase() : e[sort]);
    const cmp = (a, b) => {
      const x = key(a);
      const y = key(b);
      // No expiry sorts after every date, whichever the direction.
      if (x == null || y == null) return x == null && y == null ? a.id.localeCompare(b.id) : x == null ? 1 : -1;
      const c = x < y ? -1 : x > y ? 1 : a.id.localeCompare(b.id);
      return order === "asc" ? c : -c;
    };
    const all = db.envelopes.filter((e) => !!e.deleted_at === deleted
      && (!statuses.length || statuses.includes(e.status)) && matches(e)
      && (!sender || e.sender_user_id === sender)
      && (!recipient || (e.recipients || []).some((r) => has(r.name, recipient) || has(r.email, recipient)))
      && (folder == null || (e.folder_id || null) === (folder === "none" ? null : folder))
      && (!waiting || myRecipient(e))
      && (!authFailed || failedAuth(e))
      && (!expiresBefore || (!!e.expires_at && e.expires_at < new Date(expiresBefore).toISOString()))
      && (!cfName || hasCustom(e))
      && inRange(e)).sort(cmp);
    const page = all.slice(start, start + limit);
    return json(200, {
      items: page.map((e) => ({
        id: e.id, status: e.status, subject: e.subject, sender_user_id: e.sender_user_id, created_at: e.created_at,
        updated_at: updatedAt(e), expires_at: e.expires_at,
        // As the server's summary (envelopes.rs list): when it was sent and completed (UX-08).
        sent_at: e.sent_at || null, completed_at: e.status === "completed" ? e.ended_at || null : null,
        ...(e.folder_id ? { folder_id: e.folder_id } : {}), ...(waiting ? { my_recipient_id: myRecipient(e).id } : {}),
        // As the server (ADR-031): the Deleted view says when each was removed.
        ...(e.deleted_at ? { deleted_at: e.deleted_at } : {}),
      })),
      next_cursor: start + limit < all.length ? String(start + limit) : null,
    });
  }

  // ---- Reports (VS-06, server api/reports.rs) ---------------------------------------------
  /// `GET /reports/{envelopes|recipients|usage}` as the server: envelopes created in
  /// `[from, to)`, of `sender`, newest first, not deleted; JSON or formula-safe CSV.
  /// `GET /insights` (FG-141), as the server: over the envelopes created in the window
  /// (Deleted left out), counts by how they stand, the median and 90th percentile
  /// (continuous, as PostgreSQL's `percentile_cont`) of sent → completed in seconds,
  /// sent and completed per day in the caller's day, and the top ten senders. The demo
  /// user is an administrator (`reports.read`), so the scope is the workspace.
  function insights(query) {
    const bad = (k) => fail(422, "CS-API-0001", "Malformed request", [{ pointer: `/query/${k}`, code: "CS-API-0001" }]);
    const from = query.get("from");
    const to = query.get("to");
    if (from && Number.isNaN(Date.parse(from))) bad("from");
    if (to && Number.isNaN(Date.parse(to))) bad("to");
    if (from && to && Date.parse(to) <= Date.parse(from)) bad("to");
    const off = query.get("utc_offset_minutes") == null ? 0 : Number(query.get("utc_offset_minutes"));
    if (!Number.isInteger(off) || Math.abs(off) > 840) bad("utc_offset_minutes");
    const senderQ = query.get("sender");
    const sender = senderQ === "me" ? "user-demo" : senderQ;
    const envs = db.envelopes.filter((e) => !e.deleted_at && e.status !== undefined
      && (!from || Date.parse(e.created_at) >= Date.parse(from)) && (!to || Date.parse(e.created_at) < Date.parse(to))
      && (!sender || e.sender_user_id === sender));
    const doneAt = (e) => (e.status === "completed" ? e.completed_at || e.ended_at || null : null);
    const n = (f) => envs.filter(f).length;
    const secs = envs.filter((e) => e.sent_at && doneAt(e)).map((e) => (Date.parse(doneAt(e)) - Date.parse(e.sent_at)) / 1000).sort((a, b) => a - b);
    const pct = (p) => {
      if (!secs.length) return null;
      const at = p * (secs.length - 1);
      const lo = Math.floor(at);
      return Math.round(secs[lo] + (secs[Math.min(lo + 1, secs.length - 1)] - secs[lo]) * (at - lo));
    };
    const day = (iso) => new Date(Date.parse(iso) + off * 60_000).toISOString().slice(0, 10);
    const days = new Map();
    const bump = (d, k) => { const v = days.get(d) || { day: d, sent: 0, completed: 0 }; v[k]++; days.set(d, v); };
    for (const e of envs) {
      if (e.sent_at) bump(day(e.sent_at), "sent");
      if (doneAt(e)) bump(day(doneAt(e)), "completed");
    }
    const by = new Map();
    for (const e of envs.filter((x) => x.sent_at)) {
      const u = by.get(e.sender_user_id) || { sender_user_id: e.sender_user_id, sent: 0, completed: 0 };
      u.sent++;
      if (e.status === "completed") u.completed++;
      by.set(e.sender_user_id, u);
    }
    const completed = n((e) => e.status === "completed");
    return json(200, {
      scope: "workspace", from: from || null, to: to || null, sender: sender || null, utc_offset_minutes: off,
      totals: {
        created: envs.length, sent: n((e) => !!e.sent_at), completed,
        declined: n((e) => e.status === "declined"), voided: n((e) => e.status === "voided"), expired: n((e) => e.status === "expired"),
        in_progress: n((e) => ["sent", "delivered", "completing"].includes(e.status)),
      },
      time_to_complete: { completed, median_seconds: pct(0.5), p90_seconds: pct(0.9) },
      days: [...days.values()].sort((a, b) => a.day.localeCompare(b.day)),
      top_senders: [...by.values()].sort((a, b) => b.sent - a.sent || a.sender_user_id.localeCompare(b.sender_user_id)).slice(0, 10),
    });
  }

  function report(kind, query) {
    const bad = (k) => fail(422, "CS-API-0001", "Malformed request", [{ pointer: `/query/${k}`, code: "CS-API-0001" }]);
    const from = query.get("from");
    const to = query.get("to");
    if (from && Number.isNaN(Date.parse(from))) bad("from");
    if (to && Number.isNaN(Date.parse(to))) bad("to");
    if (from && to && Date.parse(to) <= Date.parse(from)) bad("to");
    const format = query.get("format") || "json";
    if (!["json", "csv"].includes(format)) bad("format");
    const senderQ = query.get("sender");
    const sender = senderQ === "me" ? "user-demo" : senderQ;
    const envs = db.envelopes.filter((e) => !e.deleted_at && e.status !== undefined
      && (!from || Date.parse(e.created_at) >= Date.parse(from)) && (!to || Date.parse(e.created_at) < Date.parse(to))
      && (!sender || e.sender_user_id === sender))
      .sort((a, b) => String(b.created_at).localeCompare(String(a.created_at)));
    let head;
    let rows;
    if (kind === "envelopes") {
      head = ["envelope_id", "subject", "status", "sender_user_id", "created_at", "sent_at", "completed_at", "voided_at", "expires_at", "recipients"];
      rows = envs.map((e) => ({ envelope_id: e.id, subject: e.subject, status: e.status, sender_user_id: e.sender_user_id, created_at: e.created_at, sent_at: e.sent_at || null, completed_at: e.status === "completed" ? e.ended_at || null : null, voided_at: e.status === "voided" ? e.ended_at || null : null, expires_at: e.expires_at || null, recipients: (e.recipients || []).length }));
    } else if (kind === "recipients") {
      head = ["envelope_id", "subject", "envelope_status", "routing_order", "name", "email", "type", "status"];
      rows = envs.flatMap((e) => [...(e.recipients || [])].sort((a, b) => a.routing_order - b.routing_order).map((r) => ({ envelope_id: e.id, subject: e.subject, envelope_status: e.status, routing_order: r.routing_order, name: r.name, email: r.email || null, type: r.type, status: r.status })));
    } else if (kind === "usage") {
      head = ["sender_user_id", "created", "sent", "completed", "declined", "voided", "expired"];
      const by = new Map();
      for (const e of envs) {
        const u = by.get(e.sender_user_id) || { sender_user_id: e.sender_user_id, created: 0, sent: 0, completed: 0, declined: 0, voided: 0, expired: 0 };
        u.created++;
        if (e.status !== "draft") u.sent++;
        if (["completed", "declined", "voided", "expired"].includes(e.status)) u[e.status]++;
        by.set(e.sender_user_id, u);
      }
      rows = [...by.values()].sort((a, b) => b.created - a.created);
    } else {
      fail(404, "CS-API-0002", "Not found");
    }
    if (format === "csv") {
      const cell = (v) => {
        let s = v == null ? "" : String(v);
        if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
        return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
      };
      const text = [head.join(","), ...rows.map((r) => head.map((k) => cell(r[k])).join(","))].join("\r\n") + "\r\n";
      return new Response(text, { status: 200, headers: { "Content-Type": "text/csv; charset=utf-8" } });
    }
    return json(200, { items: rows, truncated: false });
  }

  // ---- Webhooks (docs/40 §4, server api/webhooks.rs) --------------------------------------
  /// The server's registration check (SEC-W01): https://, a host, no credentials, not a
  /// local name or a private, loopback or link-local address.
  function webhookUrlOk(url) {
    const m = /^https:\/\/([^/?#]*)/.exec(url);
    if (!m || url.length > 2048 || /[\s\x00-\x1f]/.test(url)) return false;
    const authority = m[1];
    if (!authority || authority.includes("@")) return false;
    let host = authority.startsWith("[") ? authority.slice(1, authority.indexOf("]")) : authority.replace(/:\d*$/, "");
    host = host.replace(/\.$/, "").toLowerCase();
    if (host.includes(":")) return !/^(::1?|fe[89ab]|f[cd]|::ffff:)/.test(host);
    const v4 = host.split(".").map(Number);
    if (host.split(".").every((l) => /^\d+$/.test(l))) {
      if (v4.length !== 4) return false;
      const [a, b] = v4;
      return !(a === 10 || a === 127 || a === 0 || a >= 224 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b < 32) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b < 128) || (a === 198 && (b === 18 || b === 19)));
    }
    return host.includes(".") && !/(^|\.)(localhost|local|internal)$/.test(host);
  }
  const publicWebhook = (w) => ({ id: w.id, envelope_id: w.envelope_id, url: w.url, event_types: w.event_types, secret_refs: w.secret_refs, active: w.active });
  function webhooks(method, id, sub, subId, subSub, body) {
    const checkEvents = (types) => {
      if (!Array.isArray(types) || !types.length || types.length > WEBHOOK_EVENTS.length || types.some((e) => !WEBHOOK_EVENTS.includes(e))) fail(422, "CS-API-0001", "Malformed request", [{ pointer: "/event_types", code: "CS-API-0001" }]);
    };
    const checkUrl = (url) => { if (typeof url !== "string" || !webhookUrlOk(url)) fail(422, "CS-API-0013", "Webhook URL refused", [{ pointer: "/url", code: "CS-API-0013" }]); };
    if (!id) {
      if (method === "GET") return json(200, { items: db.webhooks.map(publicWebhook) });
      if (method === "POST") {
        for (const k of Object.keys(body || {})) if (!["url", "event_types", "secret_refs", "envelope_id"].includes(k)) fail(400, "CS-API-0001", "Unknown member", [{ pointer: `/${k}`, code: "unknown" }]);
        checkUrl(body?.url);
        checkEvents(body.event_types);
        const refs = body.secret_refs;
        if (!Array.isArray(refs) || !refs.length || refs.length > 4 || refs.some((r) => typeof r !== "string" || !/^[A-Za-z0-9_-]{1,64}$/.test(r))) fail(422, "CS-API-0001", "Malformed request", [{ pointer: "/secret_refs", code: "CS-API-0001" }]);
        if (body.envelope_id != null && !db.envelopes.some((e) => e.id === body.envelope_id)) fail(422, "CS-API-0001", "Malformed request", [{ pointer: "/envelope_id", code: "CS-API-0001" }]);
        const w = { id: uid(), envelope_id: body.envelope_id ?? null, url: body.url, event_types: [...body.event_types], secret_refs: [...refs], active: true };
        db.webhooks.push(w);
        return json(201, publicWebhook(w));
      }
    }
    const w = db.webhooks.find((x) => x.id === id);
    if (!w) fail(404, "CS-API-0002", "Not found");
    if (!sub) {
      if (method === "GET") return json(200, publicWebhook(w));
      if (method === "DELETE") { w.active = false; return json(204, null); }
      // UX-03, served since UXW-31: edit, pause, resume.
      if (method === "PATCH") {
        for (const k of Object.keys(body || {})) if (!["url", "event_types", "active"].includes(k)) fail(400, "CS-API-0001", "Unknown member", [{ pointer: `/${k}`, code: "unknown" }]);
        if (body && "url" in body) checkUrl(body.url);
        if (body && "event_types" in body) checkEvents(body.event_types);
        if (body && "active" in body && typeof body.active !== "boolean") fail(422, "CS-API-0001", "Malformed request", [{ pointer: "/active", code: "CS-API-0001" }]);
        if (body?.url) w.url = body.url;
        if (body?.event_types) w.event_types = [...body.event_types];
        if (body && "active" in body) w.active = body.active;
        return json(200, publicWebhook(w));
      }
    }
    if (sub === "deliveries" && !subId && method === "GET") return json(200, { items: (db.deliveries[w.id] || []).slice(0, 100) });
    // UX-03, served since UXW-32 and UXW-33. As the server: a paused subscription is
    // 409 CS-API-0009, and a stored URL no longer acceptable is refused (SEC-W01). The
    // server's worker sends it later (the answer is `pending`); the mock delivers at once.
    const sendable = () => {
      if (!w.active) fail(409, "CS-API-0009", "Not available in the current state");
      checkUrl(w.url);
    };
    if (sub === "test" && method === "POST") {
      sendable();
      const d = { id: uid(), event_id: uid(), event_type: "webhook.test", status: "delivered", attempts: 1, last_status_code: 200 };
      (db.deliveries[w.id] ||= []).unshift(d);
      return json(202, d);
    }
    if (sub === "deliveries" && subId && subSub === "redeliver" && method === "POST") {
      const d = (db.deliveries[w.id] || []).find((x) => x.id === subId);
      if (!d) fail(404, "CS-API-0002", "Not found");
      sendable();
      Object.assign(d, { status: "delivered", attempts: d.attempts + 1, last_status_code: 200 });
      return json(202, d);
    }
    fail(405, "CS-API-0012", "Method not allowed");
  }

  /// `POST /envelopes` (and each row of a bulk send, UXW-04, as the server): create, and
  /// send when `b.status` is `sent`.
  async function createEnvelopeFrom(body) {
    const b = body || {};
    checkSizes(0, (b.documents || []).map((d) => d.content_base64 || ""));
    // As the server (FG-009): a request that does not say takes the account's stamp default.
    const opts = { ...(b.signing_options || {}) };
    if (!("stamp_envelope_id" in opts) && account().settings?.stamp_envelope_id === true) opts.stamp_envelope_id = true;
    const env = newEnvelope({ subject: b.subject || "", message: b.message || "", signing_options: stampOff(opts) });
    if (inSandbox()) env.sandbox = true;
    if (b.reminders) env.reminders = b.reminders;
    if (Number.isInteger(b.expires_in_days)) env.expires_at = iso(b.expires_in_days * 24 * 60);
    // As the server (VS-07): the envelope's own seal profile, else the account's default.
    const profile = b.seal_profile || account().settings?.default_seal_profile;
    if (SEAL_PROFILES.includes(profile)) env.seal_profile = profile;
    const docIds = (b.documents || []).map((d) => addDocument(env, d.name, unb64(d.content_base64 || "")).id);
    const refs = {};
    for (const r of b.recipients || []) { const rec = addRecipient(env, r); if (r.ref) refs[r.ref] = rec.id; }
    for (const f of b.fields || []) addField(env, f, refs, docIds);
    // As the server: `Create`, then one `Edit` with every change the body made.
    await audit(env, "envelope.created", { subject_hash: await sha256hex(env.subject) }, { by: "sender" });
    const changed = [
      ...docIds.map((d) => `documents.${d}`), ...env.recipients.map((r) => `recipients.${r.id}`), ...env.fields.map((f) => `fields.${f.id}`),
      ...(b.reminders ? ["reminders"] : []), ...(Number.isInteger(b.expires_in_days) ? ["expires_at"] : []), ...(b.signing_options ? ["signing_options"] : []),
    ];
    for (const d of env.documents) await documentAdded(env, d);
    if (changed.length) await audit(env, "envelope.corrected", { changed }, { by: "sender" });
    if (b.status === "sent") await send(env);
    return env;
  }

  // ---- Using templates (as the server's api/usetemplates.rs, slice 3) ---------------------
  // `POST /envelopes/from-templates`: the templates' documents in order, roles matched by
  // name across them (templatemodel.js `mergeTemplates`, the server's rule), every role
  // filled once, people beyond the roles after them; then `createEnvelopeFrom`.
  async function envelopeFromTemplates(body) {
    const b = body || {};
    const bad = (pointer) => fail(422, "CS-API-0001", "Malformed request", [{ pointer, code: "CS-API-0001" }]);
    for (const k of Object.keys(b)) if (!["template_ids", "recipients", "subject", "message", "status"].includes(k)) bad(`/${k}`);
    if (b.status != null && !["draft", "sent"].includes(b.status)) bad("/status");
    const ids = b.template_ids;
    if (!Array.isArray(ids) || !ids.length || ids.length > 10) bad("/template_ids");
    const tps = ids.map((x, i) => {
      if (ids.indexOf(x) !== i) bad(`/template_ids/${i}`);
      return db.templates.find((tp) => tp.id === x && !tp.deleted_at) || bad(`/template_ids/${i}`);
    });
    const { roles, roleOf, conflict } = mergeTemplates(tps);
    if (conflict >= 0) bad(`/template_ids/${conflict}`);
    const filled = new Map();
    const extra = [];
    (Array.isArray(b.recipients) ? b.recipients : []).forEach((p, i) => {
      if (p?.role != null) {
        const key = roleKey(p.role);
        if (!roles.some((r) => r.key === key) || filled.has(key) || p.type != null) bad(`/recipients/${i}/role`);
        filled.set(key, p);
      } else {
        if (p?.type != null && !["cc", "signer"].includes(p.type)) bad(`/recipients/${i}/type`);
        extra.push(p);
      }
    });
    if (roles.some((r) => !filled.has(r.key))) bad("/recipients");
    const last = Math.max(0, ...roles.map((r) => r.routing_order));
    const refOf = new Map(roles.map((r, i) => [r.key, `role${i}`]));
    const recipients = [
      ...roles.map((r, i) => ({ ref: `role${i}`, type: r.type, name: filled.get(r.key).name || "", email: filled.get(r.key).email || "", routing_order: r.routing_order })),
      ...extra.map((p, i) => ({ ref: `extra${i}`, type: p.type === "signer" ? "signer" : "cc", name: p.name || "", email: p.email || "", routing_order: last + 1 })),
    ];
    const documents = [];
    const fields = [];
    for (const tp of tps) {
      const docIndex = new Map(tp.documents.map((d, i) => [d.id, documents.length + i]));
      documents.push(...tp.documents.map((d) => ({ name: d.name, content_base64: db.blobs[d.id] })));
      for (const { id: _id, role_id, document_id, ...f } of tp.fields || []) {
        const key = roleOf.get(role_id);
        if (key == null || !docIndex.has(document_id)) continue;
        fields.push({ ...f, recipient: refOf.get(key), document: docIndex.get(document_id) });
      }
      tp.last_used_at = iso();
    }
    const first = tps[0];
    return createEnvelopeFrom({
      subject: b.subject ?? (first.email_subject || first.name), message: b.message ?? (first.email_message || ""),
      status: b.status || "draft", documents, recipients, fields,
    });
  }

  // ---- Bulk send from a template (as the server, UXW-04) ---------------------------------
  // The list is checked by bulkmodel.js's `checkList`, the server's rules; each sent row
  // is one `createEnvelopeFrom`, the template's documents, roles and fields with the
  // row's people. Ten rows per `…/send`, as the server.
  async function bulkSends(method, id, sub, body) {
    const counts = (b) => {
      const n = (s) => b.rows.filter((r) => r.status === s).length;
      return { pending: n("pending"), sent: n("sent"), failed: n("failed"), cancelled: n("cancelled") };
    };
    const out = (b, rows = true) => {
      const { rows: list, ...rest } = b;
      return { ...rest, row_count: list.length, counts: counts(b), ...(rows ? { rows: list } : {}) };
    };
    const rolesOfTpl = (tp) => [...(tp.roles || [])].sort((a, b) => a.routing_order - b.routing_order || a.name.localeCompare(b.name));
    if (!id) {
      if (method === "GET") return json(200, { items: db.bulk.slice().reverse().map((b) => out(b, false)) });
      if (method === "POST") {
        for (const k of Object.keys(body || {})) if (!["template_id", "name", "csv", "rows", "validate_only"].includes(k)) fail(422, "CS-API-0001", "Malformed request", [{ pointer: `/${k}`, code: "CS-API-0001" }]);
        const tp = db.templates.find((x) => x.id === body?.template_id && !x.deleted_at);
        if (!tp || !(tp.documents || []).length || !(tp.roles || []).length) fail(422, "CS-API-0001", "Malformed request", [{ pointer: "/template_id", code: "CS-API-0001" }]);
        const roles = rolesOfTpl(tp);
        const checked = checkList(roles, { csv: body.csv ?? undefined, rows: body.rows ?? undefined });
        if (checked.error) fail(422, "CS-API-0001", "Malformed request", checked.error);
        if (body.validate_only) {
          return json(200, { columns: checked.columns, row_count: checked.rows.length, valid: checked.rows.filter((r) => r.status === "pending").length, rows: checked.rows });
        }
        const name = (typeof body.name === "string" && body.name.trim()) || tp.name;
        const b = {
          id: uid(), name, template_id: tp.id, sender_user_id: "user-demo", status: "queued", created_at: iso(), finished_at: null,
          rows: checked.rows.map((r) => ({ ...r, envelope_id: null, error_code: r.problems[0]?.code || null })),
        };
        db.bulk.push(b);
        return json(201, out(b), { Location: `/api/v1/bulk-sends/${b.id}` });
      }
      fail(405, "CS-API-0012", "Method not allowed");
    }
    const b = db.bulk.find((x) => x.id === id);
    if (!b) fail(404, "CS-API-0002", "Not found");
    if (!sub && method === "GET") return json(200, out(b));
    if (sub === "cancel" && method === "POST") {
      if (!["queued", "sending"].includes(b.status)) fail(409, "CS-WF-0001", "Not allowed in the current state");
      for (const r of b.rows) if (r.status === "pending") r.status = "cancelled";
      Object.assign(b, { status: "cancelled", finished_at: iso() });
      return json(200, out(b));
    }
    if (sub === "send" && method === "POST") {
      const tp = db.templates.find((x) => x.id === b.template_id && !x.deleted_at);
      for (const r of b.rows.filter((x) => x.status === "pending").slice(0, 10)) {
        try {
          if (!tp) fail(404, "CS-API-0002", "Not found");
          const roles = rolesOfTpl(tp);
          const docIndex = new Map(tp.documents.map((d, i) => [d.id, i]));
          const fields = (tp.fields || []).filter((f) => docIndex.has(f.document_id) && roles.some((x) => x.id === f.role_id))
            .map(({ id: _id, role_id, document_id, ...f }) => ({ ...f, recipient: `role${roles.findIndex((x) => x.id === role_id)}`, document: docIndex.get(document_id) }));
          const env = await createEnvelopeFrom({
            subject: tp.email_subject || tp.name, message: tp.email_message || "", status: "sent",
            documents: tp.documents.map((d) => ({ name: d.name, content_base64: db.blobs[d.id] })),
            recipients: roles.map((x, i) => ({ ref: `role${i}`, type: x.type, name: r.recipients[i]?.name || "", email: r.recipients[i]?.email || "", routing_order: x.routing_order })),
            fields,
          });
          env.bulk_send_id = b.id;
          Object.assign(r, { status: "sent", envelope_id: env.id });
        } catch (e) {
          if (!(e instanceof Problem)) throw e;
          Object.assign(r, { status: "failed", error_code: e.code });
        }
      }
      const left = b.rows.some((x) => x.status === "pending");
      if (["queued", "sending"].includes(b.status)) Object.assign(b, left ? { status: "sending" } : { status: "completed", finished_at: iso() });
      return json(200, out(b));
    }
    fail(405, "CS-API-0012", "Method not allowed");
  }

  // ---- Folders (as the server, UXW-02: each member's own) --------------------------------
  // Template folders (TSH-03): `kind: "templates"`, holding templates by their own
  // `folder_id` (the demo member's filing), never envelopes.
  function folders(method, id, sub, body, query) {
    const kindOf = (k, at) => {
      if (k == null) return "envelopes";
      if (k !== "envelopes" && k !== "templates") fail(422, "CS-API-0001", "Malformed request", [{ pointer: at, code: "CS-API-0001" }]);
      return k;
    };
    const named = (kind) => {
      const name = typeof body?.name === "string" ? body.name.trim() : "";
      if (!name || name.length > 100) fail(422, "CS-API-0001", "Malformed request", [{ pointer: "/name", code: "CS-API-0001" }]);
      if (db.folders.some((f) => f.id !== id && (f.kind || "envelopes") === kind && f.name.toLowerCase() === name.toLowerCase())) fail(422, "CS-API-0001", "Malformed request", [{ pointer: "/name", code: "exists" }]);
      return name;
    };
    const out = (f) => (f.kind === "templates"
      ? { ...f, count: db.templates.filter((tp) => tp.folder_id === f.id && !tp.deleted_at).length }
      : { ...f, kind: "envelopes", count: db.envelopes.filter((e) => e.folder_id === f.id && !e.deleted_at).length });
    if (!id) {
      if (method === "GET") {
        const kind = kindOf(query?.get("kind") ?? null, "/query/kind");
        return json(200, { items: db.folders.filter((f) => (f.kind || "envelopes") === kind).map(out) });
      }
      if (method === "POST") {
        const kind = kindOf(body?.kind ?? null, "/kind");
        const f = { id: uid(), name: named(kind), ...(kind === "templates" ? { kind } : {}) };
        db.folders.push(f);
        return json(201, out(f));
      }
    }
    if (sub === "templates" && method === "POST") {
      const target = id === "none" ? null : db.folders.find((f) => f.id === id && f.kind === "templates");
      if (target === undefined) fail(404, "CS-API-0002", "Not found");
      const ids = body?.template_ids;
      if (!Array.isArray(ids) || !ids.length || ids.length > 200) fail(422, "CS-API-0001", "Malformed request", [{ pointer: "/template_ids", code: "CS-API-0001" }]);
      const tps = ids.map((x) => db.templates.find((tp) => tp.id === x && !tp.deleted_at) || fail(404, "CS-API-0002", "Not found"));
      for (const tp of tps) { if (target) tp.folder_id = target.id; else delete tp.folder_id; }
      return json(200, { moved: new Set(ids).size });
    }
    if (sub === "envelopes" && method === "POST") {
      const target = id === "none" ? null : db.folders.find((f) => f.id === id && f.kind !== "templates");
      if (target === undefined) fail(404, "CS-API-0002", "Not found");
      const ids = body?.envelope_ids;
      if (!Array.isArray(ids) || !ids.length || ids.length > 200) fail(422, "CS-API-0001", "Malformed request", [{ pointer: "/envelope_ids", code: "CS-API-0001" }]);
      const envs = ids.map((x) => envOr404(x));
      for (const e of envs) { if (target) e.folder_id = target.id; else delete e.folder_id; }
      return json(200, { moved: envs.length });
    }
    const f = db.folders.find((x) => x.id === id);
    if (!f) fail(404, "CS-API-0002", "Not found");
    if (method === "PATCH") { if (body && "kind" in body) fail(422, "CS-API-0001", "Malformed request", [{ pointer: "/kind", code: "CS-API-0001" }]); f.name = named(f.kind || "envelopes"); return json(200, out(f)); }
    if (method === "DELETE") {
      for (const e of db.envelopes) if (e.folder_id === f.id) delete e.folder_id;
      for (const tp of db.templates) if (tp.folder_id === f.id) delete tp.folder_id;
      db.folders = db.folders.filter((x) => x !== f);
      return json(204, null);
    }
    fail(405, "CS-API-0012", "Method not allowed");
  }

  // ---- Document intelligence (WEB-18; docs/33 §6, ahead of the server: WEB-19) -------
  // All four features on, with the canvas's examples: an offer letter's start date,
  // salary and notice period; a vendor agreement's payment terms and a governing law at
  // 64 % ("check this"); personal data with page references; the draft "Lease renewal
  // 2027" matching the template "MSA v4" at 96 % with its last page scanned (read by
  // OCR). Analysis of a draft reports `running` for about 2 s after it is requested.
  // The server serves these since WEB-19 (docs/33 §6); the shapes below are its shapes.
  // Test hook: `sessionStorage["openseal.mock.ml"] = "off"` makes every ML call answer
  // 404, as a server without the routes does; `"no-plan"` answers `403 CS-ML-0011`.
  const ML_FEATURE_KEYS = ["ocr", "template_matching", "extraction", "personal_data"];
  /// What a run does for each feature, in the server's fixed order (docs/33 §2).
  const ML_USES = { ocr: "ocr", template_matching: "template", extraction: "entities", personal_data: "personal_data" };
  function mlMode() {
    try { return store?.getItem("openseal.mock.ml") || "on"; } catch { return "on"; }
  }
  function mlGate() {
    const mode = mlMode();
    if (mode === "off") fail(404, "CS-API-0002", "Not found");
    if (mode === "no-plan") fail(403, "CS-ML-0011", "Document intelligence is not in this workspace's plan");
  }
  function mlState() {
    db.ml ||= {
      settings: { ocr: true, template_matching: true, extraction: true, personal_data: true, personal_data_model: "gliner-multi-pii", ocr_scripts: ["latin"], reread_scanner_text: false },
      suggestions: {},
      analysis: {},
    };
    return db.ml;
  }
  function mlSettings(method, body) {
    mlGate();
    const ml = mlState();
    if (method === "PATCH") {
      for (const [k, v] of Object.entries(body || {})) {
        if (ML_FEATURE_KEYS.includes(k) || k === "reread_scanner_text") {
          if (typeof v !== "boolean") fail(400, "CS-API-0001", "Malformed request", [{ pointer: `/${k}`, code: "type" }]);
          ml.settings[k] = v;
        } else if (k === "ocr_scripts" && Array.isArray(v)) ml.settings.ocr_scripts = v.map(String);
        else if (k === "personal_data_model" && typeof v === "string") ml.settings.personal_data_model = v;
        else fail(400, "CS-API-0001", "Unknown member", [{ pointer: `/${k}`, code: "unknown" }]);
      }
    } else if (method !== "GET") fail(405, "CS-API-0012", "Method not allowed");
    return json(200, { ...ml.settings, not_in_plan: [], installed: true, ...mlInstalled() });
  }
  /// WEB-18 Admin › Document intelligence (lane D): the additive, read-only members the
  /// settings answer carries about this server, as the canvas lists them: the models the
  /// operator installed and the OCR script packs. Hashes are made-up placeholders.
  function mlInstalled() {
    const sha = (a, b) => a + "0".repeat(56) + b;
    return {
      models: [
        { id: "pp-ocrv6-small", name: "PP-OCRv6 small (detect + recognise)", profile: "ocr", status: "ready", licence: "Apache-2.0", bytes: 30_000_000, sha256: sha("9c41", "e07a") },
        { id: "arabic-pp-ocrv5", name: "Arabic OCR pack (PP-OCRv5)", profile: "ocr-pack", status: "installing", licence: "Apache-2.0", bytes: 11_000_000 },
        { id: "e5-small", name: "multilingual-e5-small", profile: "templates", status: "ready", licence: "MIT", bytes: 470_000_000, sha256: sha("1f8b", "44d2") },
        { id: "gliner-multi", name: "gliner_multi-v2.1 (int8)", profile: "extraction", status: "ready", licence: "Apache-2.0", bytes: 700_000_000, sha256: sha("a03e", "9b15") },
        { id: "gliner-pii-base", name: "gliner-pii-base-v1.0", profile: "personal_data", status: "ready", licence: "Apache-2.0", bytes: 197_000_000, sha256: sha("5d27", "c3f0") },
      ],
      ocr_packs: [
        { script: "latin", state: "installed" }, { script: "cyrillic", state: "installed" }, { script: "greek", state: "installed" }, { script: "cjk", state: "installed" },
        { script: "arabic", state: "installing" }, { script: "devanagari", state: "missing" },
      ],
    };
  }
  /// The canvas's suggestions for a seeded envelope, by its subject; ids stable per run.
  function mlSeed(env) {
    const doc = env.documents[0];
    if (!doc) return [];
    const last = Math.max(1, doc.pages || 1);
    const at = (p) => Math.min(p, last);
    const s = env.subject || "";
    const ent = (label, value, score, page) => ({ kind: "entity", label, value, score, page: at(page) });
    const pii = (label, value, score, page) => ({ kind: "personal_data", label, value, score, page: at(page) });
    let list = [];
    if (/^Offer letter/.test(s)) list = [ent("Start date", "December 1, 2026", 0.97, 1), ent("Annual salary", "EUR 84,000", 0.95, 1), ent("Notice period", "1 month", 0.88, 2), pii("Home address", "12 Example Street, Springfield", 0.93, 1), pii("Phone number", "+1 555 0142", 0.9, 1), pii("Date of birth", "1990-04-12", 0.86, 2)];
    else if (/^Vendor services/.test(s)) list = [ent("Parties", "Initech and Riley Morgan (Vendor)", 0.98, 1), ent("Payment terms", "Net 30 from receipt", 0.91, 2), ent("Governing law", "Portugal", 0.64, 2), pii("Bank account", "IBAN ending 4417", 0.89, 2), pii("Phone number", "+44 20 7946 0958", 0.84, 2)];
    else if (/^Mutual NDA/.test(s)) list = [ent("Parties", "Acme and Globex", 0.98, 1), ent("Confidentiality period", "3 years", 0.95, 2), pii("Email address", "avery@acme.example", 0.97, 1), pii("Email address", "sam@globex.example", 0.97, 1)];
    else if (/^Board consent/.test(s)) list = [ent("Resolution", "Approve FY2027 budget", 0.9, 1), ent("Effective date", "November 12, 2026", 0.93, 1)];
    else if (/^Lease renewal/.test(s)) {
      const tpl = (db.templates || []).find((x) => !x.deleted_at);
      list = [
        // As the server (WEB-19): a template suggestion's label is the template's name, it
        // has no span value, and `pages_matched` of `pages_total` are numbers.
        { kind: "template", label: "MSA v4", value: null, score: 0.96, page: 1, template_id: tpl?.id || null, pages_matched: last, pages_total: last },
        ent("Term", "24 months from the last signature", 0.96, 1),
        pii("Email address", "taylor@example.com", 0.97, at(3)),
        pii("Phone number", "+1 555 0199", 0.88, at(3)),
      ];
    }
    return list.map((x, i) => ({
      id: `sug-${env.id.slice(0, 8)}-${i}`, document_id: doc.id, rect: null, normalized: null,
      model: { id: x.kind === "personal_data" ? "gliner-multi-pii" : x.kind === "template" ? "fingerprint-v1" : "gliner-multi-v2.1", sha256: "0".repeat(64) },
      state: "open", ...x,
    }));
  }
  function mlSuggestions(env) {
    const ml = mlState();
    ml.suggestions[env.id] ||= mlSeed(env);
    return ml.suggestions[env.id];
  }
  function mlEnvelope(env, method, sub, subId, subSub, query) {
    mlGate();
    if (sub === "suggestions") {
      const list = mlSuggestions(env);
      if (!subId && method === "GET") {
        const kind = query.get("kind");
        const state = query.get("state");
        const limit = Math.min(Math.max(Number(query.get("limit")) || 50, 1), 200);
        const start = Number(query.get("cursor") || 0) || 0;
        const all = list.filter((x) => (!kind || x.kind === kind) && (!state || x.state === state));
        const items = all.slice(start, start + limit);
        return json(200, { items, next_cursor: start + limit < all.length ? String(start + limit) : null });
      }
      const sug = list.find((x) => x.id === subId);
      if (!sug) fail(404, "CS-API-0002", "Not found");
      if (method === "POST" && (subSub === "accept" || subSub === "dismiss")) {
        if (sug.state !== "open") fail(409, "CS-ML-0012", "Suggestion already decided");
        sug.state = subSub === "accept" ? "accepted" : "dismissed";
        sug.decided_by = "user-demo";
        sug.decided_at = iso();
        return json(200, sug);
      }
      return null;
    }
    // …/documents/{doc}/analysis
    const doc = env.documents.find((d) => d.id === subId);
    if (!doc) fail(404, "CS-API-0002", "Not found");
    const ml = mlState();
    const last = Math.max(1, doc.pages || 1);
    const scanned = /^Lease renewal/.test(env.subject || "") ? [Math.min(3, last)] : [];
    const out = (status) => ({ id: `run-${doc.id.slice(0, 8)}`, document_id: doc.id, status, uses: ML_FEATURE_KEYS.filter((k) => ml.settings[k]).map((k) => ML_USES[k]), ocr_pages: status === "done" ? scanned : [], truncated: false, bundle_id: status === "done" ? "bundle-demo" : null });
    if (method === "POST") {
      if (env.status !== "draft") fail(409, "CS-WF-0001", "Not allowed in the current state");
      ml.analysis[doc.id] ||= { requested_at: now().getTime() };
      const run = ml.analysis[doc.id];
      return json(202, out(now().getTime() - run.requested_at < 2000 ? "running" : "done"));
    }
    if (method === "GET") {
      const run = ml.analysis[doc.id];
      // Seeded documents were analysed when they were added; a requested run takes ~2 s.
      return json(200, out(!run || now().getTime() - run.requested_at >= 2000 ? "done" : "running"));
    }
    return null;
  }
  /// Search by meaning (planned, docs/33 §6, WEB-19): the canvas's two payment-terms
  /// matches for a question about paying, else every clause sharing a word stem.
  function mlSearch(query) {
    mlGate();
    const q = String(query.get("q") || "").trim().toLowerCase();
    if (query.get("mode") !== "meaning") fail(422, "CS-API-0001", "Malformed request", [{ pointer: "/query/mode", code: "enum" }]);
    if (!q) return json(200, { items: [] });
    const find = (re) => db.envelopes.find((e) => re.test(e.subject || "") && !e.deleted_at);
    const clauses = [
      [find(/^Vendor services/), 2, ["…invoices are ", { text: "settled net thirty", mark: true }, " from receipt…"], ["pay", "invoice", "net", "thirty", "30", "days", "fee", "settle"]],
      [find(/^Offer letter/), 1, ["…the company will ", { text: "pay an annual salary", mark: true }, " of EUR 84,000 in twelve instalments…"], ["pay", "salary", "wage", "compens", "money"]],
      [find(/^Mutual NDA/), 2, ["…each party ", { text: "keeps the other's information confidential", mark: true }, " for three years…"], ["confiden", "secret", "disclos", "privacy", "nda"]],
      [find(/^Lease renewal/), 1, ["…this agreement ", { text: "renews for 24 months", mark: true }, " from the last signature…"], ["renew", "term", "durat", "month", "year", "expir"]],
    ];
    const words = q.split(/\s+/).filter(Boolean);
    const items = [];
    for (const [env, page, parts, stems] of clauses) {
      if (!env) continue;
      const hits = words.filter((w) => stems.some((s) => w.startsWith(s) || s.startsWith(w.slice(0, 4)))).length;
      if (!hits) continue;
      items.push({
        envelope_id: env.id, document_id: env.documents[0]?.id || null, subject: env.subject, status: env.status, page,
        snippet: parts.map((p) => (typeof p === "string" ? { text: p } : p)), score: Math.min(0.99, 0.6 + hits * 0.12),
      });
    }
    items.sort((a, b) => b.score - a.score);
    return json(200, { items: items.slice(0, Math.min(20, Number(query.get("limit")) || 8)) });
  }

  /// ERSD-01, as the server's `GET/POST /ersd-versions`: publish a text as the next
  /// version of its language and require it in one step; read the one required (with its
  /// text) and the history (without). The seed requires the demo text, which no row
  /// holds, so `current.version` is null until something is published.
  async function ersdVersions(method, body) {
    const row = (d) => ({ id: d.id, version: d.version, label: d.label, language: d.language, sha256: d.sha256, published_at: d.published_at });
    if (method === "POST") {
      for (const k of Object.keys(body || {})) if (k !== "text" && k !== "language") fail(422, "CS-API-0001", "Malformed request", [{ pointer: `/${k}`, code: "unknown" }]);
      const text = body?.text;
      if (typeof text !== "string") fail(422, "CS-API-0001", "Malformed request", [{ pointer: "/text", code: "CS-API-0001" }]);
      if (new TextEncoder().encode(text).length > 100000) fail(413, "CS-API-0006", "Request body too large");
      if (!text.trim() || text.includes("\0")) fail(422, "CS-API-0001", "Malformed request", [{ pointer: "/text", code: "CS-API-0001" }]);
      const language = body?.language ?? "en";
      if (typeof language !== "string" || !/^[A-Za-z][A-Za-z0-9-]{1,34}$/.test(language)) fail(422, "CS-API-0001", "Malformed request", [{ pointer: "/language", code: "CS-API-0001" }]);
      const version = 1 + Math.max(0, ...db.ersd.filter((d) => d.language === language).map((d) => d.version));
      const d = { id: `ersd-${db.ersd.length + 1}`, version, label: String(version), language, sha256: `sha256:${await sha256hex(text)}`, published_at: now().toISOString(), text };
      db.ersd.push(d);
      save();
      return json(201, row(d));
    } else if (method !== "GET") fail(405, "CS-API-0012", "Method not allowed");
    const last = db.ersd.at(-1);
    const current = last
      ? { label: last.label, sha256: last.sha256, version: last.version, language: last.language, published_at: last.published_at, text: last.text }
      : { label: MOCK.ersd, sha256: ersdSha, version: null, language: null, published_at: null, text: MOCK_DISCLOSURE };
    return json(200, { current, items: db.ersd.slice(-100).reverse().map(row) });
  }

  // ---- The organization (ORG-03, ORG-05, ORG-06) ----------------------------------------
  //
  // `/organizations/me…` as the server's api/org.rs: the demo user is the owner of one
  // organization of two workspaces; every change appends an event to the organization's
  // log (`{seq, at, action, hash, prev, event}`, the event as docs/23 §2.5's canonical
  // object; the hash is SHA-256 of the mock's JSON, not RFC 8785: the mock is not
  // evidence). The role is read per call, so a test can take it away.
  function organization() {
    db.org ||= {
      id: "org-demo", name: "Demo organization", status: "active", created_at: iso(-60 * 24 * 30),
      workspaces: [
        { id: "acct-demo", name: null, status: "active", member: true },
        { id: "acct-legal", name: "Legal", status: "active", member: true },
      ],
      admins: [{ user_id: "user-demo", role: "owner", permission_set_id: null, workspace_scope: null, created_at: iso(-60 * 24 * 30) }],
      events: [],
    };
    return db.org;
  }
  const workspaceRow = (w) => ({ id: w.id, name: w.id === "acct-demo" ? account().name || "Demo workspace" : w.name, status: w.status, sandbox: w.sandbox === true });
  const adminRow = (a) => ({ user_id: a.user_id, role: a.role, permission_set_id: a.permission_set_id, workspace_scope: a.workspace_scope, created_at: a.created_at });

  async function orgEvent(action, target = {}, changes = [], actor = { kind: "user", id: "user-demo" }) {
    const o = organization();
    const last = o.events.at(-1);
    const seq = last ? last.seq + 1 : 0;
    const at = now();
    const event = { v: 1, organization: o.id, seq, prev: last?.hash ?? null, at: at.getTime(), actor, action, target, changes };
    const hash = await sha256hex(JSON.stringify(event));
    o.events.push({ seq, at: at.toISOString(), action, hash, prev: last?.hash ?? null, event });
  }

  async function orgRoutes(method, sub, wsId, verb, query, body) {
    const o = organization();
    if (!o.events.length) await orgEvent("organization.created", { organization: o.id }, [], { kind: "system" });
    const me = o.admins.find((a) => a.user_id === "user-demo");
    const holds = (action) => me && (me.role === "owner" || (me.role === "admin" && action !== "admins") || action === "read");
    const need = (action) => { if (!holds(action)) fail(403, "CS-AUTH-0006", "Forbidden"); };
    const only = (...keys) => { for (const k of Object.keys(body || {})) if (!keys.includes(k)) fail(400, "CS-API-0001", "Unknown member", [{ pointer: `/${k}`, code: "unknown" }]); };
    const nameOf = () => {
      const n = typeof body?.name === "string" ? body.name.trim() : "";
      if (!n || n.length > 255) fail(422, "CS-API-0001", "Malformed request", [{ pointer: "/name", code: "CS-API-0001" }]);
      return n;
    };
    const roleOf = () => {
      if (!["owner", "admin"].includes(body?.role)) fail(422, "CS-API-0001", "Malformed request", [{ pointer: "/role", code: "CS-API-0001" }]);
      return body.role;
    };
    need("read");
    const done = (status, v) => { save(); return json(status, v); };
    if (!sub) {
      if (method === "GET") return json(200, { id: o.id, name: o.name, status: o.status, role: me.role, created_at: o.created_at });
      if (method !== "PATCH") fail(405, "CS-API-0012", "Method not allowed");
      need("settings");
      only("name");
      const name = nameOf();
      const old = o.name;
      o.name = name;
      await orgEvent("organization.renamed", { organization: o.id }, [{ key: "name", old, new: name }]);
      return done(200, { id: o.id, name: o.name, status: o.status });
    }
    if (sub === "workspaces") {
      if (!wsId) {
        if (method === "GET") return json(200, { items: o.workspaces.map(workspaceRow) });
        if (method !== "POST") fail(405, "CS-API-0012", "Method not allowed");
        need("workspaces");
        only("name", "sandbox");
        if (body.sandbox != null && typeof body.sandbox !== "boolean") fail(422, "CS-API-0001", "Malformed request", [{ pointer: "/sandbox", code: "CS-API-0001" }]);
        // ADR-041: a sandbox workspace, for good.
        const w = { id: uid(), name: nameOf(), status: "active", member: false, sandbox: body.sandbox === true };
        o.workspaces.push(w);
        await orgEvent("workspace.created", { workspace: w.id });
        return done(201, workspaceRow(w));
      }
      const w = o.workspaces.find((x) => x.id === wsId);
      if (!w) fail(404, "CS-API-0002", "Not found");
      if (!verb && method === "GET") return json(200, workspaceRow(w));
      if (verb === "archive" && method === "POST") {
        need("workspaces");
        if (w.status !== "archived") {
          w.status = "archived";
          await orgEvent("workspace.archived", { workspace: w.id });
        }
        return done(200, workspaceRow(w));
      }
      if (verb === "join" && method === "POST") {
        if (!["owner", "admin"].includes(me.role)) fail(403, "CS-AUTH-0006", "Forbidden");
        only("profile");
        if (w.status === "archived") fail(409, "CS-ORG-0010", "Workspace archived");
        if (!["admin", "sender", "viewer"].includes(body?.profile)) fail(422, "CS-API-0001", "Malformed request", [{ pointer: "/profile", code: "CS-API-0001" }]);
        w.member = true;
        await orgEvent("org.workspace_joined", { workspace: w.id, user: "user-demo" });
        return done(201, { workspace_id: w.id, user_id: "user-demo", permission_profile_id: `profile-${body.profile}` });
      }
      fail(405, "CS-API-0012", "Method not allowed");
    }
    if (sub === "admins") {
      if (!wsId) {
        if (method === "GET") return json(200, { items: o.admins.map(adminRow) });
        if (method !== "POST") fail(405, "CS-API-0012", "Method not allowed");
        need("admins");
        only("user_id", "role");
        const role = roleOf();
        if (typeof body?.user_id !== "string") fail(422, "CS-API-0001", "Malformed request", [{ pointer: "/user_id", code: "CS-API-0001" }]);
        if (body.user_id === "user-demo") fail(403, "CS-ORG-0005", "Grant refused");
        if (!db.users.some((u) => u.id === body.user_id && !u.disabled)) fail(422, "CS-ORG-0018", "Not a member of the organization");
        if (o.admins.some((a) => a.user_id === body.user_id)) fail(409, "CS-DB-0006", "Already exists");
        const a = { user_id: body.user_id, role, permission_set_id: null, workspace_scope: null, created_at: now().toISOString() };
        o.admins.push(a);
        await orgEvent("organization.admin_added", { user: a.user_id }, [{ key: "role", old: null, new: role }]);
        return done(201, adminRow(a));
      }
      const a = o.admins.find((x) => x.user_id === wsId);
      need("admins");
      if (!a) fail(404, "CS-API-0002", "Not found");
      const owners = () => o.admins.filter((x) => x.role === "owner").length;
      if (method === "PATCH") {
        only("role");
        const role = roleOf();
        if (a.user_id === "user-demo") fail(403, "CS-ORG-0005", "Grant refused");
        if (a.role === "owner" && role !== "owner" && owners() === 1) fail(409, "CS-ORG-0008", "The organization must keep an owner");
        if (a.role !== role) {
          await orgEvent("organization.admin_role_changed", { user: a.user_id }, [{ key: "role", old: a.role, new: role }]);
          a.role = role;
        }
        return done(200, adminRow(a));
      }
      if (method === "DELETE") {
        if (a.role === "owner" && owners() === 1) fail(409, "CS-ORG-0008", "The organization must keep an owner");
        o.admins = o.admins.filter((x) => x !== a);
        await orgEvent("organization.admin_removed", { user: a.user_id }, [{ key: "role", old: a.role, new: null }]);
        return done(200, { user_id: a.user_id });
      }
      fail(405, "CS-API-0012", "Method not allowed");
    }
    if (sub === "audit" && !wsId && method === "GET") {
      need("audit");
      const limit = query.has("limit") ? Number(query.get("limit")) : 100;
      if (!Number.isInteger(limit) || limit < 1 || limit > 1000) fail(422, "CS-API-0001", "Malformed request", [{ pointer: "/query/limit", code: "CS-API-0001" }]);
      if (!["", "page", "full"].includes(query.get("verify") || "")) fail(422, "CS-API-0001", "Malformed request", [{ pointer: "/query/verify", code: "CS-API-0001" }]);
      const cursor = query.has("cursor") ? Number(query.get("cursor")) : -1;
      const page = o.events.filter((e) => e.seq > cursor).slice(0, limit);
      save();
      return json(200, { items: page, next_cursor: page.length === limit ? page.at(-1).seq : null });
    }
    fail(404, "CS-API-0002", "Not found");
  }

  /// What the session owes (the server's `SecondFactor`): `passed`, `verify` (the demo
  /// user enrolled), `enrol` (the account's `mfa_policy` asks for one: `administrators`
  /// when unset, ASVS-31, and the demo user is an administrator) or `none`.
  function secondFactor() {
    if (db.session?.mfa) return "passed";
    if (hasFactor()) return "verify";
    return account().settings?.mfa_policy === "optional" ? "none" : "enrol";
  }

  /// Whether the demo user has a second factor: the TOTP app or a passkey (CON-13).
  function hasFactor() {
    return !!db.mfa?.confirmed || (db.passkeys || []).length > 0;
  }

  /// `GET /auth/session`'s `factors`, as the server.
  function factorsOf() {
    return { totp: !!db.mfa?.confirmed, passkeys: (db.passkeys || []).length, recovery_codes_left: (db.mfa?.recovery || []).length, reset_by_admin: false, passkeys_available: true };
  }

  const b64url = (bytes) => btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const unb64url = (s) => { try { return atob(String(s).replace(/-/g, "+").replace(/_/g, "/")); } catch { return null; } };

  /// Ten recovery codes as the server shows them, kept canonical.
  function newRecoveryCodes(tag) {
    const codes = Array.from({ length: 10 }, (_, n) => `${tag}${n}`.padEnd(23, "A"));
    db.mfa ||= { confirmed: false, secret: null, used: [], recovery: [] };
    db.mfa.recovery = codes.slice();
    return codes.map((c) => c.match(/.{1,5}/g).join("-"));
  }

  /// A WebAuthn answer's client data, as the server checks it (the mock cannot check
  /// the signature, the server's tests and the real-server e2e do): the ceremony type
  /// and the session's outstanding challenge for `purpose`, which it spends.
  function passkeyClientData(cd, type, purpose) {
    const want = db.session?.webauthn;
    if (db.session) db.session.webauthn = null;
    let c = null;
    try { c = JSON.parse(unb64url(cd) ?? ""); } catch { c = null; }
    if (!want || want.purpose !== purpose || !c || c.type !== type || c.challenge !== want.challenge) fail(401, "CS-AUTH-0012", "Second factor refused");
  }

  /// The person's passkeys (CON-13), as the server.
  function passkeys(method, subId, body) {
    db.passkeys ||= [];
    const view = (k) => ({ id: k.id, name: k.name, created_at: k.created_at, last_used_at: k.last_used_at, backup_eligible: false });
    if (subId === "options" && method === "POST") {
      const purpose = body?.purpose;
      if (!["register", "verify", "reauthenticate"].includes(purpose)) fail(422, "CS-API-0001", "Invalid request", [{ pointer: "/purpose", code: "CS-API-0001" }]);
      const challenge = b64url(crypto.getRandomValues(new Uint8Array(32)));
      const rpId = globalThis.location?.hostname || "localhost";
      const allow = db.passkeys.map((k) => ({ type: "public-key", id: k.credential_id, transports: k.transports || [] }));
      let publicKey;
      if (purpose === "register") {
        if (hasFactor() && !db.session?.mfa) fail(403, "CS-AUTH-0011", "Second factor required", undefined, "verify");
        if (hasFactor() && !recentUntil()) fail(403, "CS-AUTH-0013", "Recent re-authentication required", undefined, "reauthenticate");
        publicKey = {
          rp: { id: rpId, name: "OpenSeal" }, user: { id: b64url(new TextEncoder().encode("user-demo")), name: MOCK.email, displayName: "Demo User" },
          challenge, pubKeyCredParams: [-7, -8, -257].map((alg) => ({ type: "public-key", alg })), timeout: 300000,
          excludeCredentials: allow, authenticatorSelection: { residentKey: "discouraged", requireResidentKey: false, userVerification: "preferred" }, attestation: "none",
        };
      } else {
        if (!db.passkeys.length) fail(409, "CS-API-0009", "Not available", undefined, "no passkey");
        publicKey = { challenge, rpId, allowCredentials: allow, userVerification: "preferred", timeout: 300000 };
      }
      db.session.webauthn = { purpose, challenge };
      save();
      return json(200, { purpose, public_key: publicKey });
    }
    if (!subId && method === "POST") {
      if (hasFactor() && !db.session?.mfa) fail(403, "CS-AUTH-0011", "Second factor required", undefined, "verify");
      if (hasFactor() && !recentUntil()) fail(403, "CS-AUTH-0013", "Recent re-authentication required", undefined, "reauthenticate");
      const c = body?.credential || {};
      passkeyClientData(c.client_data_json, "webauthn.create", "register");
      if (typeof c.id !== "string" || !c.public_key || db.passkeys.some((k) => k.credential_id === c.id)) fail(409, "CS-API-0009", "Not available", undefined, "passkey not added");
      if (db.passkeys.length >= 10) fail(409, "CS-API-0009", "Not available", undefined, "too many passkeys");
      const first = !hasFactor();
      const k = { id: uid(), credential_id: c.id, transports: Array.isArray(c.transports) ? c.transports : [], name: String(body?.name || "Passkey").trim().slice(0, 64) || "Passkey", created_at: iso(), last_used_at: null };
      db.passkeys.push(k);
      db.session.mfa = true;
      const out = { passkey: view(k), second_factor: "passed" };
      if (first) out.recovery_codes = newRecoveryCodes("PASS");
      save();
      return json(201, out);
    }
    if (secondFactor() === "verify" || secondFactor() === "enrol") fail(403, "CS-AUTH-0011", "Second factor required", undefined, secondFactor());
    if (!subId && method === "GET") return json(200, { items: db.passkeys.map(view) });
    const k = db.passkeys.find((x) => x.id === subId);
    if (!k) fail(404, "CS-API-0002", "Not found");
    if (!recentUntil()) fail(403, "CS-AUTH-0013", "Recent re-authentication required", undefined, "reauthenticate");
    if (method === "PATCH") {
      const name = typeof body?.name === "string" ? body.name.trim() : "";
      if (!name || name.length > 64) fail(422, "CS-API-0001", "Invalid request", [{ pointer: "/name", code: "CS-API-0001" }]);
      k.name = name;
      save();
      return json(200, view(k));
    }
    if (method === "DELETE") {
      db.passkeys = db.passkeys.filter((x) => x !== k);
      if (!hasFactor()) { db.mfa.recovery = []; db.session.mfa = false; }
      save();
      return json(204, null);
    }
    fail(404, "CS-API-0002", "Not found");
  }

  /// A passkey answer to the step (`verify`) or step-up (`reauthenticate`).
  function passkeyAnswer(a, purpose) {
    passkeyClientData(a?.client_data_json, "webauthn.get", purpose);
    const k = (db.passkeys || []).find((x) => x.credential_id === a?.credential_id);
    if (!k) fail(401, "CS-AUTH-0012", "Second factor refused");
    k.last_used_at = iso();
  }

  function mfa(method, sub, subId, body) {
    db.mfa ||= { confirmed: false, secret: null, used: [], recovery: [] };
    const sixDigits = (c) => typeof c === "string" && /^[0-9]{6}$/.test(c.trim());
    const fresh = (c) => sixDigits(c) && !db.mfa.used.includes(c.trim());
    if (sub === "passkeys") return passkeys(method, subId, body);
    if (sub === "verify" && method === "POST") {
      for (const k of Object.keys(body || {})) if (!["code", "recovery_code", "passkey"].includes(k)) fail(400, "CS-API-0001", "Unknown member", [{ pointer: `/${k}`, code: "unknown" }]);
      if (body?.passkey) {
        passkeyAnswer(body.passkey, "verify");
        db.session.mfa = true;
        save();
        return json(200, { second_factor: "passed" });
      }
      if (!hasFactor()) fail(401, "CS-AUTH-0012", "Second factor refused");
      if (typeof body?.recovery_code === "string") {
        const canon = body.recovery_code.replace(/[\s-]/g, "").toUpperCase();
        const i = db.mfa.recovery.indexOf(canon);
        if (i < 0) fail(401, "CS-AUTH-0012", "Second factor refused");
        db.mfa.recovery.splice(i, 1);
        db.session.mfa = true;
        return json(200, { second_factor: "passed", recovery_codes_left: db.mfa.recovery.length });
      }
      if (!db.mfa.confirmed || !fresh(body?.code)) fail(401, "CS-AUTH-0012", "Second factor refused");
      db.mfa.used.push(body.code.trim());
      db.session.mfa = true;
      return json(200, { second_factor: "passed" });
    }
    // ASVS-32: the person removes the app, or replaces their recovery codes, after a
    // recent re-authentication.
    if ((sub === "totp" && !subId && method === "DELETE") || (sub === "recovery-codes" && method === "POST")) {
      if (secondFactor() === "verify" || secondFactor() === "enrol") fail(403, "CS-AUTH-0011", "Second factor required", undefined, secondFactor());
      if (!recentUntil()) fail(403, "CS-AUTH-0013", "Recent re-authentication required", undefined, "reauthenticate");
      if (sub === "totp") {
        if (!db.mfa.confirmed) fail(409, "CS-API-0009", "Not available", undefined, "no authenticator app");
        db.mfa = { ...db.mfa, confirmed: false, secret: null };
        if (!hasFactor()) { db.mfa.recovery = []; db.session.mfa = false; }
        save();
        return json(204, null);
      }
      if (!hasFactor()) fail(409, "CS-API-0009", "Not available", undefined, "no second factor");
      const shown = newRecoveryCodes("NEW");
      save();
      return json(200, { recovery_codes: shown });
    }
    if (sub === "totp" && subId === "enrol" && method === "POST") {
      if (db.mfa.confirmed) fail(409, "CS-API-0009", "Not available", undefined, "already enrolled");
      db.mfa.secret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
      return json(200, { otpauth_uri: `otpauth://totp/OpenSeal:user-demo?secret=${db.mfa.secret}&issuer=OpenSeal&algorithm=SHA1&digits=6&period=30`, secret: db.mfa.secret });
    }
    if (sub === "totp" && subId === "confirm" && method === "POST") {
      if (db.mfa.confirmed) fail(409, "CS-API-0009", "Not available", undefined, "already enrolled");
      if (!db.mfa.secret) fail(409, "CS-API-0009", "Not available", undefined, "enrol first");
      if (!fresh(body?.code)) fail(401, "CS-AUTH-0012", "Second factor refused");
      const codes = Array.from({ length: 10 }, (_, n) => `DEMO${n}`.padEnd(23, "A"));
      db.mfa = { ...db.mfa, confirmed: true, used: [body.code.trim()], recovery: codes.slice() };
      db.session.mfa = true;
      const shown = codes.map((c) => c.match(/.{1,5}/g).join("-"));
      return json(200, { second_factor: "passed", recovery_codes: shown });
    }
    fail(404, "CS-API-0002", "Not found");
  }

  /// Until when the session's sensitive actions are served (ASVS-07): five minutes after
  /// its sign-in or last re-authentication, as an RFC 3339 instant; null once passed.
  function recentUntil() {
    const at = db.session?.reauth;
    if (typeof at !== "number") return null;
    const until = at + 5 * 60_000;
    return now().getTime() < until ? new Date(until).toISOString() : null;
  }

  /// Whether the session's workspace is a sandbox (ADR-041), as the server says it.
  function inSandbox() {
    const here = db.session?.account || "acct-demo";
    return organization().workspaces.some((w) => w.id === here && w.sandbox === true);
  }

  /// The calls the server asks a recent re-authentication for (docs/40 §2, ASVS-07).
  function sensitive(method, res, id, sub, body) {
    if (res === "api-clients" && !id && method === "POST") return true;
    if (res === "users" && id && id !== "me" && method === "PATCH" && body && ("profile" in body || "password" in body)) return true;
    if (res === "users" && !id && method === "POST" && body?.profile === "admin") return true;
    if (res === "webhooks" && !id && method === "POST") return true;
    if (res === "webhooks" && id && !sub && method === "PATCH" && body && "url" in body) return true;
    if (res === "accounts" && id === "me" && method === "PATCH" && body?.settings
      && ["mfa_policy", "session_idle", "session_max_age"].some((k) => k in body.settings)) return true;
    if (res === "organizations" && id === "me" && !sub && method === "PATCH" && body && "policy" in body) return true;
    if (res === "organizations" && id === "me" && sub === "admins" && (method === "POST" || method === "PATCH")) return true;
    if (res === "permission-profiles" && (method === "POST" || method === "PATCH")) return true;
    if (res === "auth" && id === "sessions" && (method === "DELETE" || (method === "POST" && sub === "end-others"))) return true;
    if (res === "users" && id && sub === "second-factor") return true;
    if (res === "users" && id === "me" && !sub && method === "DELETE") return true;
    if (res === "retention" && !id && method === "PUT") return true;
    return false;
  }

  /// `POST /auth/reauthenticate`, as the server: the demo password, and a fresh six-digit
  /// code when the demo user has a second factor.
  function reauthenticate(body) {
    for (const k of Object.keys(body || {})) if (!["password", "code", "recovery_code", "passkey"].includes(k)) fail(400, "CS-API-0001", "Unknown member", [{ pointer: `/${k}`, code: "unknown" }]);
    if (body?.password !== MOCK.password) fail(401, "CS-AUTH-0007", "Invalid credentials");
    if (body?.passkey && (db.passkeys || []).length) {
      passkeyAnswer(body.passkey, "reauthenticate");
    } else if (hasFactor() && !db.mfa?.confirmed) {
      fail(422, "CS-API-0001", "Malformed or invalid request", [{ pointer: "/code", code: "CS-API-0001" }]);
    } else if (db.mfa?.confirmed) {
      const c = typeof body?.code === "string" ? body.code.trim() : null;
      if (c == null) fail(422, "CS-API-0001", "Malformed or invalid request", [{ pointer: "/code", code: "CS-API-0001" }]);
      if (!/^[0-9]{6}$/.test(c) || db.mfa.used.includes(c)) fail(401, "CS-AUTH-0012", "Second factor refused");
      db.mfa.used.push(c);
    }
    db.session.reauth = now().getTime();
    save();
    return json(200, { reauthenticated_until: recentUntil() });
  }

  /// The demo user's sessions (ASVS-06): this one, and two others seeded the first time
  /// the list is asked for (a phone in this workspace, a laptop in the other one).
  function ownSessions(method, sub, here) {
    db.otherSessions ||= [
      { id: "session-phone", workspace: { id: "acct-demo", name: "Demo account" }, method: "password", client: "Safari on iOS", created_at: iso(-180), last_seen_at: iso(-12) },
      { id: "session-laptop", workspace: { id: "acct-legal", name: "Legal" }, method: "password", client: "Firefox on Windows", created_at: iso(-300), last_seen_at: iso(-25) },
    ];
    if (!db.session.id) db.session.id = uid();
    const workspaces = organization().workspaces;
    const mine = {
      id: db.session.id,
      workspace: { id: here, name: here === "acct-demo" ? account().name : workspaces.find((w) => w.id === here)?.name || here },
      method: "password", client: db.session.client || null,
      created_at: db.session.at || iso(), last_seen_at: iso(),
      current: true,
    };
    const row = (s) => ({ ...s, idle_expires_at: new Date(Date.parse(s.last_seen_at) + 30 * 60_000).toISOString(), expires_at: new Date(Date.parse(s.created_at) + 8 * 3600_000).toISOString(), current: false });
    if (method === "GET" && !sub) {
      const cur = { ...mine, idle_expires_at: iso(30), expires_at: new Date(Date.parse(mine.created_at) + 8 * 3600_000).toISOString() };
      return json(200, { items: [cur, ...db.otherSessions.map(row)] });
    }
    if (method === "POST" && sub === "end-others") {
      const n = db.otherSessions.length;
      db.otherSessions = [];
      save();
      return json(200, { ended: n });
    }
    if (method === "DELETE" && sub) {
      if (sub === db.session.id) fail(422, "CS-API-0001", "Malformed or invalid request", [{ pointer: "/id", code: "CS-API-0001" }]);
      const before = db.otherSessions.length;
      db.otherSessions = db.otherSessions.filter((s) => s.id !== sub);
      if (db.otherSessions.length === before) fail(404, "CS-API-0002", "Not found");
      save();
      return json(204, null);
    }
    fail(405, "CS-API-0012", "Method not allowed");
  }

  async function staff(method, parts, query, headers, body) {
    if (!db.session) fail(401, "CS-AUTH-0001", "Not authenticated");
    if (method !== "GET" && headers["x-csrf-token"] !== db.session.csrf) fail(403, "CS-AUTH-0008", "CSRF token missing or wrong");
    const [, , , res, id, sub, subId, subSub] = parts; // "", api, v1, res, …
    // Workspace switching (ORG-04), as the server: the demo user belongs to two
    // workspaces of one organization. The mock keeps one set of envelopes for both; the
    // server's isolation is tested in server/casual-sign-server/tests/workspaces.rs.
    // The organization's workspaces (ORG-06) are its list; the ones the demo user is a
    // member of (`member`) are the switcher's.
    // As the server's `GET /auth/workspaces`: no sandbox member (the org listing has it).
    const spaces = organization().workspaces.filter((w) => w.member).map(workspaceRow).map(({ sandbox: _s, ...w }) => w);
    const here = db.session.account || "acct-demo";
    // ADR-042: the editor's preview of a Word document, nothing stored.
    if (res === "conversions" && !id && method === "POST") {
      if (headers["content-type"] !== DOCX_MEDIA) fail(415, "CS-API-0007", "Unsupported media type");
      return pdf(mockConvert(body));
    }
    if (res === "auth" && id === "workspaces" && method === "GET") {
      return json(200, {
        current: here,
        organizations: [{ id: "org-demo", name: "Demo organization", workspaces: spaces.map((w) => ({ ...w, current: w.id === here })) }],
      });
    }
    if (res === "auth" && id === "switch" && method === "POST") {
      for (const k of Object.keys(body || {})) if (k !== "account_id") fail(400, "CS-API-0001", "Unknown member", [{ pointer: `/${k}`, code: "unknown" }]);
      if (typeof body?.account_id !== "string") fail(422, "CS-API-0001", "Invalid request", [{ pointer: "/account_id", code: "type" }]);
      if (!spaces.some((w) => w.id === body.account_id)) fail(403, "CS-ORG-0001", "Not a member of that workspace");
      db.session = { csrf: uid(), account: body.account_id, mfa: db.session.mfa === true, id: uid(), reauth: db.session.reauth ?? null, at: db.session.at || iso(), client: db.session.client || null };
      return json(200, { account_id: body.account_id, user_id: "user-demo", csrf_token: db.session.csrf, expires_at: iso(60 * 12) });
    }
    if (res === "auth" && id === "session" && method === "GET") {
      return json(200, { account_id: here, user_id: "user-demo", credential: "session", client_id: null, scopes: ["envelopes:read", "envelopes:write", "envelopes:send", "templates:read", "templates:write", "admin:users", "admin:account"], admin: true, second_factor: secondFactor(), factors: factorsOf(), reauthenticated_until: recentUntil(), sandbox: inSandbox() });
    }
    if (res === "auth" && id === "logout" && method === "POST") { db.session = null; return json(204, null); }
    // The staff second factor (ASVS-01), as the server: a TOTP code is six digits (the
    // mock takes any, once each, as it has no clock), recovery codes are spent.
    if (res === "auth" && id === "mfa") return mfa(method, sub, subId, body);
    const owed = secondFactor();
    if (owed === "verify" || owed === "enrol") fail(403, "CS-AUTH-0011", "Second factor required", undefined, owed);
    // ASVS-06, ASVS-07, as the server: the person's own sessions and re-authentication.
    if (res === "auth" && id === "reauthenticate" && method === "POST") return reauthenticate(body);
    if (sensitive(method, res, id, sub, body) && !recentUntil()) fail(403, "CS-AUTH-0013", "Recent re-authentication required", undefined, "reauthenticate");
    if (res === "auth" && id === "sessions") return ownSessions(method, sub, here);
    if (res === "accounts" && id === "me") {
      // Settings and branding (WEB-06 AD-01), as the server (`AccountPatch`): `PATCH
      // {settings}` only, merged, `null` removing a key; answers `{settings}`. The
      // server's own `builtin_profiles` (profile name → id) cannot be changed.
      account();
      db.account.settings.builtin_profiles ||= { admin: "profile-admin", sender: "profile-sender", viewer: "profile-viewer" };
      if (method === "PATCH") {
        for (const k of Object.keys(body || {})) if (k !== "settings") fail(400, "CS-API-0001", "Unknown member", [{ pointer: `/${k}`, code: "unknown" }]);
        if (!body?.settings || typeof body.settings !== "object" || Array.isArray(body.settings)) fail(400, "CS-API-0001", "Malformed request", [{ pointer: "/settings", code: "type" }]);
        if ("builtin_profiles" in body.settings) fail(422, "CS-API-0001", "Malformed request", [{ pointer: "/settings/builtin_profiles", code: "CS-API-0001" }]);
        // As the server: `workflow_policy` is taken only as a whole `Policy` (RTE-03).
        if ("workflow_policy" in body.settings && body.settings.workflow_policy !== null && !policyOk(body.settings.workflow_policy)) fail(422, "CS-API-0001", "Malformed request", [{ pointer: "/settings/workflow_policy", code: "CS-API-0001" }]);
        // As the server (FG-009): the envelope id stamp default is true or false.
        if ("stamp_envelope_id" in body.settings && body.settings.stamp_envelope_id !== null && typeof body.settings.stamp_envelope_id !== "boolean") fail(422, "CS-API-0001", "Malformed request", [{ pointer: "/settings/stamp_envelope_id", code: "CS-API-0001" }]);
        // As the server (VS-07): the default seal profile is one of the three PAdES levels.
        if ("default_seal_profile" in body.settings && body.settings.default_seal_profile !== null && !SEAL_PROFILES.includes(body.settings.default_seal_profile)) fail(422, "CS-API-0001", "Malformed request", [{ pointer: "/settings/default_seal_profile", code: "CS-API-0001" }]);
        const before = db.account.settings;
        const next = { ...before };
        for (const [k, v] of Object.entries(body.settings)) { if (v === null) delete next[k]; else next[k] = v; }
        db.account.settings = next;
        // ORG-05: the change and its admin event together, one change per key that moved.
        const changes = Object.keys(body.settings).filter((k) => JSON.stringify(before[k] ?? null) !== JSON.stringify(next[k] ?? null))
          .map((k) => ({ key: k, old: before[k] ?? null, new: next[k] ?? null }));
        if (changes.length) await adminEvent("workspace.settings_changed", { target: { account: "acct-demo" }, changes });
        return json(200, { settings: next });
      } else if (method !== "GET") fail(405, "CS-API-0012", "Method not allowed");
      return json(200, here === "acct-demo" ? db.account : { ...db.account, id: here, name: spaces.find((w) => w.id === here)?.name });
    }
    if (res === "organizations" && id === "me") return orgRoutes(method, sub, subId, subSub, query, body);
    if (res === "ersd-versions" && !id) return ersdVersions(method, body);
    if (res === "admin-events" && !id && method === "GET") return adminEvents(query);
    if (res === "reports" && id && !sub && method === "GET") return report(id, query);
    if (res === "insights" && !id && method === "GET") return insights(query);
    // WEB-06: recipient autocomplete, as the server's GET /contacts.
    if (res === "contacts" && method === "GET") {
      const q = (query.get("q") || "").trim().toLowerCase();
      const limit = Math.min(50, Math.max(1, Number(query.get("limit")) || 10));
      const seen = new Map();
      for (const e of [...db.envelopes].sort((a, b) => b.created_at.localeCompare(a.created_at))) {
        for (const r of e.recipients || []) {
          const key = (r.email || "").toLowerCase();
          if (!key || seen.has(key)) continue;
          if (q && !key.includes(q) && !(r.name || "").toLowerCase().includes(q)) continue;
          seen.set(key, { name: r.name, email: r.email, last_used_at: e.created_at });
        }
      }
      return json(200, { items: [...seen.values()].slice(0, limit) });
    }
    // WEB-18, ahead of the server (docs/33 §6, WEB-19): the workspace's model settings
    // and search by meaning.
    if (res === "account" && id === "settings" && sub === "ml") return mlSettings(method, body);
    if (res === "search" && !id && method === "GET") return mlSearch(query);
    if (res === "templates") return templates(method, id, sub, subId, subSub, headers, body, query);
    if (res === "users" && id === "me" && sub === "export" && method === "GET") return exportMe();
    if (res === "users" && id === "me" && !sub && method === "DELETE") return eraseMe();
    if (res === "retention") return retention(method, id, body);
    if (res === "users" && id === "me" && !sub) return me(method, body);
    if (res === "users") return users(method, id, body, sub);
    if (res === "api-clients") return apiClients(method, id, body);
    if (res === "oauth") return oauth(method, id, sub, body, query);
    if (res === "webhooks") return webhooks(method, id, sub, subId, subSub, body);
    if (res === "folders") return folders(method, id, sub, body, query);
    if (res === "bulk-sends") return bulkSends(method, id, sub, body);
    if (res === "groups") return groups(method, id, sub, body);
    if (res === "permission-profiles") return profiles(method, id, body);
    if (res !== "envelopes") fail(404, "CS-API-0002", "Not found");
    // Slice 3: one envelope from one template or several, as the server makes it.
    if (id === "from-templates" && !sub) {
      if (method !== "POST") fail(405, "CS-API-0012", "Method not allowed");
      return withEtag(await envelopeFromTemplates(body), 201);
    }

    if (!id) {
      if (method === "GET") return listEnvelopes(query);
      if (method === "POST") {
        const env = await createEnvelopeFrom(body);
        return withEtag(env, 201);
      }
    }
    const env = envOr404(id);
    if (!sub) {
      if (method === "GET") return withEtag(env);
      if (method === "PATCH") {
        checkIfMatch(env, headers); draftOnly(env); notScheduled(env);
        const changed = [];
        for (const k of ["subject", "message", "signing_options", "reminders"]) if (body && k in body) { env[k] = k === "signing_options" ? stampOff({ ...body[k] }) : body[k]; changed.push(k); }
        if (body && "expires_in_days" in body) { env.expires_at = Number.isInteger(body.expires_in_days) ? iso(body.expires_in_days * 24 * 60) : null; changed.push("expires_at"); }
        await edited(env, changed);
        return withEtag(env);
      }
      if (method === "DELETE") {
        // As the server (WEB-08): a draft is removed; an envelope that ended without
        // completing leaves every list and stays readable by id with its chain
        // (`envelope.deleted`); a completed or in-flight one, or a second delete, is 409.
        checkIfMatch(env, headers);
        if (!["draft", "voided", "declined", "expired"].includes(env.status) || env.deleted_at) fail(409, "CS-WF-0001", "Not allowed in the current state");
        if (env.status === "draft") db.envelopes = db.envelopes.filter((e) => e !== env);
        else { env.deleted_at = iso(); env.version++; await audit(env, "envelope.deleted", {}, { by: "sender" }); }
        return json(204, null);
      }
    }
    // As the server (ADR-031, `POST /envelopes/{id}/restore`): back to the lists, with
    // `envelope.restored` after the `envelope.deleted`; not deleted (or purged) is 409.
    if (sub === "restore" && method === "POST") {
      if (!env.deleted_at) fail(409, "CS-WF-0001", "Not allowed in the current state");
      if (headers["if-match"] && headers["if-match"] !== `"v${env.version}"`) fail(412, "CS-WF-0002", "Stale version");
      delete env.deleted_at;
      env.version++;
      await audit(env, "envelope.restored", {}, { by: "sender" });
      return withEtag(env);
    }
    // WEB-18, ahead of the server (docs/33 §6, WEB-19): analysis and suggestions.
    if (sub === "suggestions" || (sub === "documents" && subSub === "analysis")) {
      const res = mlEnvelope(env, method, sub, subId, subSub, query);
      if (res) return res;
    }
    // As the server (UXW-01): the signing page for the signed-in user, when routing has
    // reached them.
    if (sub === "sign-link" && method === "POST") {
      const r = myRecipient(env);
      if (!r) fail(409, "CS-WF-0007", "Routing has not reached the recipient yet");
      return json(201, { url: `/s/${encodeURIComponent(r.token)}`, expires_at: iso(5) });
    }
    if (sub === "correct" && method === "POST") {
      // `POST …/correct {changes}` (docs/40, docs/24 §6), as the server: the engine's change
      // list (casual-sign-workflow `Change`, api.js `corrections`), all or none, If-Match.
      checkIfMatch(env, headers);
      if (!["sent", "delivered"].includes(env.status)) fail(409, "CS-WF-0001", "Not allowed in the current state");
      for (const k of Object.keys(body || {})) if (k !== "changes") fail(400, "CS-API-0001", "Unknown member", [{ pointer: `/${k}`, code: "unknown" }]);
      const changes = body?.changes;
      if (!Array.isArray(changes) || !changes.length) fail(400, "CS-API-0001", "Malformed request", [{ pointer: "/changes", code: "required" }]);
      if (changes.length > 500) fail(422, "CS-WF-0004", "Too many changes", [{ pointer: "/changes", code: "too_many" }]);
      // Documents arrive through `/documents`, which admits them (as the server).
      if (changes.some((c) => ["add_document", "replace_document"].includes(c?.op))) fail(422, "CS-API-0001", "Malformed request", [{ pointer: "/changes", code: "CS-API-0001" }]);
      const before = structuredClone(env);
      const changed = [];
      try {
        changes.forEach((c, i) => applyChange(env, c, `/changes/${i}`, changed));
      } catch (e) {
        for (const k of Object.keys(env)) delete env[k];
        Object.assign(env, before);
        throw e;
      }
      await corrected(env, changed);
      return withEtag(env);
    }
    if (sub === "send" && method === "POST") { draftOnly(env); await send(env); return withEtag(env); }
    // Scheduled sending (WF-02): a sendable draft sends itself at `send_at`, which is
    // after now and within a year (`422 CS-WF-0023`); it is not edited meanwhile
    // (`409 CS-WF-0022`). The mock records the schedule; sending it is the server's.
    if (sub === "schedule" && method === "PUT") {
      draftOnly(env);
      const at = Date.parse(body?.send_at || "");
      if (!Number.isFinite(at)) fail(400, "CS-API-0001", "Malformed request", [{ pointer: "/send_at", code: "CS-API-0001" }]);
      if (at <= now().getTime() || at > now().getTime() + 365 * 86_400_000) fail(422, "CS-WF-0023", "The schedule time is out of range");
      env.send_at = new Date(at).toISOString();
      await edited(env, ["send_at"]);
      return withEtag(env);
    }
    if (sub === "schedule" && method === "DELETE") {
      draftOnly(env);
      if (env.send_at) { env.send_at = null; await edited(env, ["send_at"]); }
      return withEtag(env);
    }
    if (sub === "void" && method === "POST") {
      if (TERMINAL.has(env.status) || env.status === "draft") fail(409, "CS-WF-0001", "Not allowed in the current state");
      if (!body?.reason) fail(400, "CS-API-0001", "Reason required", [{ pointer: "/reason", code: "required" }]);
      env.status = "voided"; env.void_reason = body.reason; env.ended_at = iso(); env.version++;
      await audit(env, "envelope.voided", { reason: body.reason }, { by: "sender" });
      return withEtag(env);
    }
    // ORG-09 as the server (envelopes.rs transfer): another enabled member of this
    // workspace becomes the sender; any state but purged; `envelope.transferred`.
    if (sub === "transfer" && method === "POST") {
      for (const k of Object.keys(body || {})) if (!["to_user", "to_workspace"].includes(k)) fail(400, "CS-API-0001", "Unknown member", [{ pointer: `/${k}`, code: "unknown" }]);
      if (body?.to_workspace && body.to_workspace !== "acct-demo") fail(422, "CS-ORG-0009", "Envelopes stay in their workspace");
      const to = db.users.find((u) => u.id === body?.to_user && !u.disabled);
      if (!to) fail(422, "CS-ORG-0009", "Envelopes stay in their workspace");
      const from = env.sender_user_id;
      env.sender_user_id = to.id;
      env.version++;
      await audit(env, "envelope.transferred", { from_user: from, to_user: to.id }, { by: "user" });
      return withEtag(env);
    }
    if (sub === "custom-fields" && method === "GET") return json(200, { items: [...(env.custom_fields || [])].sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0)) });
    if (sub === "custom-fields" && method === "PUT") {
      const items = body?.items;
      if (!Array.isArray(items) || items.length > 100) fail(422, "CS-API-0001", "Malformed request", [{ pointer: "/items", code: "CS-API-0001" }]);
      const out = [];
      items.forEach((f, i) => {
        const name = typeof f?.name === "string" ? f.name.trim() : "";
        // eslint-disable-next-line no-control-regex
        if (!name || name.length > 100 || /[\x00-\x1f\x7f]/.test(name)) fail(422, "CS-API-0001", "Malformed request", [{ pointer: `/items/${i}/name`, code: "CS-API-0001" }]);
        // eslint-disable-next-line no-control-regex
        if (typeof f.value !== "string" || f.value.length > 1000 || /[\x00-\x1f\x7f]/.test(f.value)) fail(422, "CS-API-0001", "Malformed request", [{ pointer: `/items/${i}/value`, code: "CS-API-0001" }]);
        if (out.some((x) => x.name === name)) fail(422, "CS-API-0001", "Malformed request", [{ pointer: `/items/${i}/name`, code: "exists" }]);
        out.push({ name, value: f.value });
      });
      env.custom_fields = out;
      return json(200, { items: out });
    }
    if (sub === "resend" && method === "POST") {
      if (!["sent", "delivered"].includes(env.status)) fail(409, "CS-WF-0001", "Not allowed in the current state");
      const ids = body?.recipient_ids || env.recipients.filter((r) => ["sent", "delivered"].includes(r.status)).map((r) => r.id);
      for (const rid of ids) await audit(env, "reminder.sent", { recipient_id: rid, channel: "email" }, { by: "sender" });
      // As the engine (docs/24 §3): a resend clears the recipient's failures and lock.
      for (const r of env.recipients) if (ids.includes(r.id)) {
        r.auth_failures = 0;
        if (r.token) delete db.attempts[r.token];
      }
      return withEtag(env);
    }
    if (sub === "status" && method === "GET") return json(200, { id: env.id, status: env.status, version: env.version, recipients: env.recipients.map((r) => ({ id: r.id, status: r.status })) });
    if (sub === "audit" && method === "GET") {
      const items = db.audit[env.id] || [];
      return json(200, { items, chain_head: items.length ? items[items.length - 1].hash : null });
    }
    if (sub === "evidence-package" && method === "GET") {
      // As the server (VS-06D, `GET …/evidence-package`): an envelope that is over, its
      // export recorded first (`envelope.exported`), then one ZIP: manifest.json, each
      // document (the mock's delivered bytes), certificate.pdf, audit-trail.json.
      if (!["completed", "declined", "voided", "expired"].includes(env.status)) fail(409, "CS-WF-0001", "Not allowed in the current state");
      await audit(env, "envelope.exported", { by: env.sender_user_id }, { by: "sender" });
      const enc = new TextEncoder();
      const files = env.documents.map((d, i) => {
        const base = (d.name || "document").replace(/\.pdf$/i, "").replace(/[^A-Za-z0-9._-]/g, "_").slice(0, 80) || "document";
        return [`documents/${String(i + 1).padStart(2, "0")}-${base}.pdf`, unb64(db.blobs[d.id]), { kind: "document", document_id: d.id, sealed: env.status === "completed" }];
      });
      const certLines = [`Envelope ${env.id}`, `Subject: ${env.subject}`, `Outcome: ${env.status}`, "", "Mock mode: not a real certificate."];
      files.push(["certificate.pdf", makePdf([{ title: env.status === "completed" ? "Certificate of completion" : "Envelope certificate", lines: certLines }]), { kind: "certificate" }]);
      const items = db.audit[env.id] || [];
      const trail = { items, chain_head: items.length ? items[items.length - 1].hash : null };
      files.push(["audit-trail.json", enc.encode(JSON.stringify(trail, null, 2)), { kind: "audit_trail" }]);
      const listed = [];
      for (const [path, bytes, about] of files) listed.push({ path, sha256: await sha256hex(bytes), size: bytes.length, ...about });
      const manifest = { format: "openseal.evidence-package", version: 1, envelope_id: env.id, status: env.status, exported_at: iso(), exported_by: env.sender_user_id, chain_head: trail.chain_head, entries: listed };
      save();
      const zip = storeZip([["manifest.json", enc.encode(JSON.stringify(manifest, null, 2))], ...files.map(([p, b]) => [p, b])]);
      return new Response(zip, { status: 200, headers: { "Content-Type": "application/zip", "Content-Disposition": `attachment; filename="evidence-${env.id}.zip"` } });
    }
    if (sub === "anchor-proof" && method === "GET") {
      // FG-158: the mock has no anchor job (no time-stamping authority), so nothing is
      // ever anchored here; the server's answer before the first anchor.
      fail(404, "CS-API-0017", "Not anchored yet");
    }
    if (sub === "certificate" && method === "GET") {
      // A completed envelope's; a declined, voided or expired one's envelope
      // certificate (UXW-30), as the server once its worker has made it.
      if (!["completed", "declined", "voided", "expired"].includes(env.status)) fail(409, "CS-API-0009", "Not available in the object's state");
      const lines = [`Envelope ${env.id}`, `Subject: ${env.subject}`, `Outcome: ${env.status}`, ""];
      for (const r of env.recipients) lines.push(`${r.name} <${r.email}> - ${r.type} - ${r.status} ${r.completed_at || ""}`);
      lines.push("", "Mock mode: not a real certificate.");
      return pdf(makePdf([{ title: env.status === "completed" ? "Certificate of completion" : "Envelope certificate", lines }]));
    }
    if (sub === "documents") {
      if (!subId && method === "POST") {
        // A draft's edit, or a sent envelope's correction (docs/24 §6, VS-06).
        const correcting = editable(env);
        checkSizes(env.documents.reduce((n, x) => n + (x.bytes || 0), 0), [body?.content_base64 || ""]);
        const d = addDocument(env, body?.name, unb64(body?.content_base64 || ""));
        await documentAdded(env, d);
        await (correcting ? corrected : edited)(env, [`documents.${d.id}`]);
        return json(201, d);
      }
      if (!subId && method === "GET") return json(200, { items: env.documents });
      const d = env.documents.find((x) => x.id === subId);
      if (!d) fail(404, "CS-API-0002", "Not found");
      if (subSub === "detect-fields" && method === "POST") {
        // As `POST …/detect-fields` (nothing changed or recorded): the mock's documents
        // put their signature lines low on each page, so it suggests a signature, a date
        // and a name there, ordered by page, top, left. As the server's detector does
        // (casual-sign-fields detect.rs), a field on a line sits on it: its bottom is the
        // line (mockpdf.js draws them at PDF y 150, so 642 from the top of a 792 page;
        // UX-05, they were below the lines).
        const items = [];
        for (let page = 1; page <= d.pages; page++) {
          items.push(
            { document_id: d.id, type: "signature", page, x: "72", y: "602", width: "180", height: "40", source: "underline", cue: "Signature", confidence: 82 },
            { document_id: d.id, type: "date_signed", page, x: "340", y: "620", width: "120", height: "22", source: "underline", cue: "Date", confidence: 74 },
            { document_id: d.id, type: "name", page, x: "72", y: "730", width: "180", height: "22", source: "label", cue: "Print name", confidence: 61 },
          );
        }
        // VS-04E, VS-04F, as the server: the document's own form fields (source
        // `acroform`) and its text tags (source `tag`), read from what mockpdf.js
        // writes (not a parser: the real server reads them with the engine).
        const text = new TextDecoder("latin1").decode(unb64(db.blobs[d.id]));
        const kind = { Tx: "text", Btn: "checkbox", Sig: "signature" };
        const pageAt = (at) => Math.max(1, (text.slice(0, at).match(/\/Type \/Page\b(?!s)/g) || []).length + 1);
        for (const m of text.matchAll(/\/Subtype \/Widget \/FT \/(Tx|Btn|Sig) \/T \(([^)]*)\) \/Rect \[([\d.]+) ([\d.]+) ([\d.]+) ([\d.]+)\]/g)) {
          const [x1, y1, x2, y2] = m.slice(3, 7).map(Number);
          items.push({ document_id: d.id, type: kind[m[1]], page: pageAt(m.index), x: String(x1), y: String(792 - y2), width: String(x2 - x1), height: String(y2 - y1), source: "acroform", cue: m[2], confidence: 100 });
        }
        let page = 0;
        for (const m of text.matchAll(/\/Type \/Page\b(?!s)|BT \/F\d+ [\d.]+ Tf ([\d.]+) ([\d.]+) Td \(\{\{([a-z_]+):([A-Za-z0-9_-]+)(?::(req|required))?(?::([^:}]+))?\}\}\) Tj ET/g)) {
          if (!m[1]) { page++; continue; }
          const type = { s: "signature", i: "initials", t: "text", d: "date", c: "checkbox", a: "attachment" }[m[3]] || m[3];
          items.push({ document_id: d.id, type, page: Math.max(1, page), x: m[1], y: String(792 - Number(m[2]) - 11), width: "160", height: "22", source: "tag", cue: m[6] || m[4], confidence: 100 });
        }
        return json(200, { items, truncated: false });
      }
      if (subSub === "content" && method === "GET") {
        if (query.get("version") === "sealed" && !env.sealed) fail(409, "CS-API-0009", "Not available in the object's state");
        // `version=current` (WEB-06 E-02): the document as it stands, fields filled so
        // far. The mock has no flattening, so it is the delivered file.
        if (query.get("version") === "current" && env.status === "draft") fail(409, "CS-API-0009", "Not available in the object's state");
        // FG-009 (ADR-045): the current and sealed documents carry the envelope id stamp.
        const bytes = unb64(db.blobs[d.id]);
        if (env.signing_options?.stamp_envelope_id && ["current", "sealed"].includes(query.get("version"))) return pdf(stampPdf(bytes, `Envelope ID: ${env.id}`));
        return pdf(bytes);
      }
      if (!subSub && method === "DELETE") {
        checkIfMatch(env, headers);
        const correcting = editable(env);
        // As the engine (docs/24 §6): who finished on a removed document acts again.
        if (correcting) for (const f of env.fields.filter((x) => x.document_id === d.id)) fieldOwnerOk(env, f.recipient_id);
        env.documents = env.documents.filter((x) => x !== d);
        env.fields = env.fields.filter((f) => f.document_id !== d.id);
        await (correcting ? corrected : edited)(env, [`documents.${d.id}`]);
        return json(204, null);
      }
    }
    if (sub === "recipients") {
      if (!subId && method === "POST") {
        const correcting = editable(env);
        const items = body?.items || [body];
        const out = items.map((r) => addRecipient(env, r));
        if (correcting) await corrected(env, out.map((r) => `recipients.${r.id}`));
        else await edited(env, out.map((r) => `recipients.${r.id}`));
        return json(201, { items: out.map(publicRecipient) });
      }
      if (!subId && method === "GET") return json(200, { items: env.recipients.map(publicRecipient) });
      const r = env.recipients.find((x) => x.id === subId);
      if (!r) fail(404, "CS-API-0002", "Not found");
      // A staff user hosts an in-person signer once routing has reached them, on this
      // device (UXW-36). The server mints a new one-hour link acting as the host; the
      // mock answers the signer's own token.
      if (subSub === "host" && method === "POST") {
        if (r.type !== "in_person_signer" || !["sent", "delivered"].includes(r.status) || !r.token) fail(409, "CS-WF-0001", "Not allowed in the current state");
        r.hosted = "user-demo";
        await audit(env, "recipient.in_person_hosted", { recipient_id: r.id, host_user_id: "user-demo" }, { by: "user" });
        return json(201, { url: `/s/${encodeURIComponent(r.token)}`, expires_at: iso(60) });
      }
      if (method === "PATCH") {
        // As the server: a draft, or a correction of a sent envelope for a recipient who
        // has not acted. The access code follows the methods: one given needs
        // `access_code` among them; newly requiring it needs one; dropping it clears it.
        checkIfMatch(env, headers);
        const correcting = editable(env);
        if (correcting && settled(r)) fail(409, "CS-WF-0001", "Recipient has already acted");
        for (const k of Object.keys(body || {})) if (!["name", "email", "routing_order", "type", "auth", "access_code", "route_delay_hours", "excluded_documents"].includes(k)) fail(400, "CS-API-0001", "Unknown member", [{ pointer: `/${k}`, code: "unknown" }]);
        // A type change is a draft's only (UX-12): a correction keeps the type.
        if (body?.type != null && body.type !== r.type && correcting) fail(409, "CS-WF-0001", "Not allowed in the current state");
        if (body?.name != null && !String(body.name).trim()) fail(422, "CS-API-0001", "Malformed request", [{ pointer: "/name", code: "CS-API-0001" }]);
        if (body?.email != null && !String(body.email).includes("@")) fail(422, "CS-API-0001", "Malformed request", [{ pointer: "/email", code: "CS-API-0001" }]);
        const had = r.auth.includes("access_code");
        const auth = Array.isArray(body?.auth) ? body.auth : r.auth;
        const wants = auth.includes("access_code");
        const code = body?.access_code || null;
        if (code ? !wants : wants && !had) fail(422, "CS-API-0001", "Malformed request", [{ pointer: "/access_code", code: "CS-API-0001" }]);
        if (body?.name != null) r.name = String(body.name).trim();
        if (body?.email != null) r.email = String(body.email);
        if (body?.routing_order != null) r.routing_order = body.routing_order;
        if (body?.type != null) r.type = String(body.type);
        visibilityAndDelay(env, r, body || {});
        r.auth = auth;
        if (code) { r.access_code = code; r.auth_passed = []; } else if (had && !wants) r.access_code = null;
        if (correcting) await corrected(env, [`recipients.${r.id}`]);
        else await edited(env, [`recipients.${r.id}`]);
        return json(200, publicRecipient(r), { ETag: `"v${env.version}"` });
      }
      if (method === "DELETE") {
        checkIfMatch(env, headers);
        const correcting = editable(env);
        if (!correcting && env.fields.some((f) => f.recipient_id === r.id)) fail(409, "CS-WF-0001", "Recipient still has fields");
        if (correcting) {
          // As the engine's `RemoveRecipient`: not one who has acted; their fields go too.
          if (settled(r)) fail(409, "CS-WF-0001", "Recipient has already acted");
          removeRecipient(env, r);
          await corrected(env, [`recipients.${r.id}`]);
        } else {
          env.recipients = env.recipients.filter((x) => x !== r);
          await edited(env, [`recipients.${r.id}`]);
        }
        return json(204, null);
      }
    }
    if (sub === "fields") {
      if (!subId && method === "POST") {
        const correcting = editable(env);
        const items = body?.items || [body];
        if (correcting) for (const f of items) fieldOwnerOk(env, f?.recipient ?? f?.recipient_id);
        const out = items.map((f) => addField(env, f));
        if (correcting) await corrected(env, out.map((f) => `fields.${f.id}`));
        else await edited(env, out.map((f) => `fields.${f.id}`));
        return json(201, { items: out });
      }
      if (!subId && method === "GET") return json(200, { items: env.fields });
      const f = env.fields.find((x) => x.id === subId);
      if (!f) fail(404, "CS-API-0002", "Not found");
      if (method === "PATCH") {
        checkIfMatch(env, headers);
        const correcting = editable(env);
        if (correcting) fieldOwnerOk(env, f.recipient_id);
        if (body && "id" in body) fail(400, "CS-API-0001", "Malformed request", [{ pointer: "/id", code: "read_only" }]);
        if (body?.placement || body?.page) f.placement = placementOf(body);
        if (body?.type != null) f.type = fieldType(body.type);
        // Every member the engine's `Field` has (UX-03); null, false or empty removes one.
        setMembers(f, body || {});
        if (body?.recipient_id) {
          if (!env.recipients.some((r) => r.id === body.recipient_id)) fail(422, "CS-WF-0008", "Unknown recipient");
          if (correcting) fieldOwnerOk(env, body.recipient_id);
          f.recipient_id = body.recipient_id;
        }
        if (correcting) await corrected(env, [`fields.${f.id}`]);
        else await edited(env, [`fields.${f.id}`]);
        return json(200, f);
      }
      if (method === "DELETE") {
        checkIfMatch(env, headers);
        const correcting = editable(env);
        if (correcting) fieldOwnerOk(env, f.recipient_id);
        env.fields = env.fields.filter((x) => x !== f);
        if (correcting) await corrected(env, [`fields.${f.id}`]);
        else await edited(env, [`fields.${f.id}`]);
        return json(204, null);
      }
    }
    fail(405, "CS-API-0012", "Method not allowed");
  }

  // ---- Templates (WEB-02, WEB-09, WEB-10) ---------------------------------------
  // As the server (server/…/api/templates.rs, api/openapi.yaml): roles with ids; a
  // single-template read, and adding a document or a role, answer the whole template
  // (roles, documents, fields); fields are bound to `role_id` (or `role`, also an id);
  // every change bumps the version, and the changes that name one object need If-Match.
  function publicTemplate(tp, whole = true) {
    const { documents, fields, created_at: _c, last_used_at: _l, shares: _s, favourite, edit_share: _e, folder_id: _f, ...rest } = tp;
    const access = tp.owner_user_id === "user-demo" ? "owner" : (tp.edit_share ? "edit" : "use");
    return whole ? { ...rest, documents, fields, access, favourite: !!favourite } : rest;
  }
  const ROLE_TYPES = ["signer", "cc", "approver", "viewer", "in_person_signer"];
  function checkRole(r, at) {
    if (!r || typeof r.name !== "string" || !r.name.trim() || r.name.trim().length > 255) fail(400, "CS-API-0001", "Role name required", [{ pointer: `${at}/name`, code: "required" }]);
    for (const k of Object.keys(r)) if (!["name", "type", "routing_order"].includes(k)) fail(400, "CS-API-0001", "Unknown member", [{ pointer: `${at}/${k}`, code: "unknown" }]);
    if (!ROLE_TYPES.includes(r.type)) fail(400, "CS-API-0001", "Unknown recipient type", [{ pointer: `${at}/type`, code: "enum" }]);
    const order = r.routing_order ?? 1;
    if (!Number.isInteger(order) || order < 1 || order > 999) fail(400, "CS-API-0001", "Malformed request", [{ pointer: `${at}/routing_order`, code: "range" }]);
    return { id: uid(), name: r.name.trim(), type: r.type, routing_order: order };
  }
  function checkRoles(roles) {
    if (roles == null) return [];
    if (!Array.isArray(roles)) fail(400, "CS-API-0001", "Malformed request", [{ pointer: "/roles", code: "type" }]);
    return roles.map((r, i) => checkRole(r, `/roles/${i}`));
  }
  function newTemplate(b, createdAt) {
    if (!b || typeof b.name !== "string" || !b.name.trim()) fail(400, "CS-API-0001", "Template name required", [{ pointer: "/name", code: "required" }]);
    for (const k of Object.keys(b)) if (!["name", "email_subject", "email_message", "roles"].includes(k)) fail(400, "CS-API-0001", "Unknown member", [{ pointer: `/${k}`, code: "unknown" }]);
    const tp = { id: uid(), owner_user_id: "user-demo", name: b.name.trim().slice(0, 255), version: 1, email_subject: b.email_subject ?? null, email_message: b.email_message ?? null, roles: checkRoles(b.roles), documents: [], fields: [], created_at: createdAt || iso() };
    db.templates.push(tp);
    return tp;
  }
  function tplIfMatch(tp, headers, required = true) {
    const v = headers["if-match"];
    if (!v) { if (required) fail(428, "CS-API-0008", "Precondition required"); return; }
    if (v !== `"v${tp.version}"`) fail(412, "CS-WF-0002", "Stale version");
  }
  /// A template field from the API's shape: `role_id` (or `role`), `document_id`, `type`,
  /// and the placement flat or as `placement`; checked against the roles and documents.
  function templateField(tp, f, at, id = uid()) {
    if (!f || typeof f !== "object") fail(400, "CS-API-0001", "Malformed request", [{ pointer: at, code: "type" }]);
    if ("recipient" in f) fail(400, "CS-API-0001", "Malformed request", [{ pointer: `${at}/recipient`, code: "unknown" }]);
    const role = f.role_id ?? f.role;
    if (!tp.roles.some((r) => r.id === role)) fail(400, "CS-API-0001", "Unknown role", [{ pointer: `${at}/role_id`, code: "unknown" }]);
    const doc = tp.documents.find((d) => d.id === f.document_id);
    if (!doc) fail(400, "CS-API-0001", "Unknown document", [{ pointer: `${at}/document_id`, code: "unknown" }]);
    const placement = placementOf(f.placement || f);
    if (placement.page > doc.pages) fail(400, "CS-API-0001", "Page out of range", [{ pointer: `${at}/page`, code: "range" }]);
    const field = { id, document_id: doc.id, role_id: role, type: fieldType(f.type), placement };
    // The envelope field's members (UX-03), as the server's template fields take them.
    setMembers(field, f, at);
    return field;
  }
  const tplWhole = (tp, status = 200) => json(status, publicTemplate(tp), { ETag: `"v${tp.version}"` });
  function templates(method, id, sub, subId, subSub, headers, body, query) {
    if (!id) {
      if (method === "GET") {
        // UXW-02, as the server: `deleted=true` is the Deleted view, most recently
        // deleted first; without it, the live templates.
        const del = query?.get("deleted") ?? null;
        if (del != null && del !== "true" && del !== "false") fail(422, "CS-API-0001", "Malformed request", [{ pointer: "/query/deleted", code: "CS-API-0001" }]);
        const deleted = del === "true";
        // UXW-06: `view` narrows the live list. The demo member owns every template the
        // mock makes, so Shared with me holds the ones another owner shared.
        const view = query?.get("view") ?? "all";
        if (!["all", "owned", "shared", "favourites"].includes(view)) fail(422, "CS-API-0001", "Malformed request", [{ pointer: "/query/view", code: "CS-API-0001" }]);
        const me = "user-demo";
        const inView = (tp) => deleted || view === "all" || (view === "owned" && tp.owner_user_id === me) || (view === "shared" && tp.owner_user_id !== me) || (view === "favourites" && !!tp.favourite);
        // TSH-03: `folder` narrows to one of the member's template folders, or `none`.
        const folder = query?.get("folder") ?? null;
        const inFolder = (tp) => deleted || folder == null || (folder === "none" ? !tp.folder_id : tp.folder_id === folder);
        const items = db.templates.filter((tp) => !!tp.deleted_at === deleted && inView(tp) && inFolder(tp))
          .sort((a, b) => (deleted ? b.deleted_at.localeCompare(a.deleted_at) : b.created_at.localeCompare(a.created_at)))
          .map((tp) => ({ ...publicTemplate(tp, false), roles: tp.roles, last_used_at: tp.last_used_at || null, access: tp.owner_user_id === me ? "owner" : (tp.edit_share ? "edit" : "use"), favourite: !!tp.favourite, shared: (tp.shares || []).length > 0, ...(deleted ? {} : { folder_id: tp.folder_id || null }) }));
        return json(200, { items });
      }
      if (method === "POST") return tplWhole(newTemplate(body), 201);
    }
    const found = db.templates.find((x) => x.id === id);
    // UXW-02: a deleted template answers only a restore or a second delete (for good).
    if (found?.deleted_at) {
      if (sub === "restore" && method === "POST") {
        tplIfMatch(found, headers, false);
        delete found.deleted_at;
        found.version++;
        return tplWhole(found);
      }
      if (!sub && method === "DELETE") {
        tplIfMatch(found, headers);
        db.templates = db.templates.filter((x) => x !== found);
        return json(204, null);
      }
      fail(404, "CS-API-0002", "Not found");
    }
    const tp = found;
    if (!tp) fail(404, "CS-API-0002", "Not found");
    if (sub === "restore") fail(404, "CS-API-0002", "Not found");
    if (!sub) {
      if (method === "GET") return tplWhole(tp);
      if (method === "PATCH") {
        tplIfMatch(tp, headers);
        for (const k of Object.keys(body || {})) if (!["name", "email_subject", "email_message"].includes(k)) fail(400, "CS-API-0001", "Unknown member", [{ pointer: `/${k}`, code: "unknown" }]);
        if (body?.name != null && (typeof body.name !== "string" || !body.name.trim())) fail(400, "CS-API-0001", "Template name required", [{ pointer: "/name", code: "required" }]);
        if (body?.name != null) tp.name = body.name.trim().slice(0, 255);
        for (const k of ["email_subject", "email_message"]) if (body && k in body) tp[k] = body[k] == null ? null : String(body[k]).slice(0, k === "email_subject" ? 255 : 10000);
        tp.version++;
        return tplWhole(tp);
      }
      if (method === "DELETE") {
        // UXW-02: to the Deleted view, kept whole and restorable.
        tplIfMatch(tp, headers);
        tp.deleted_at = iso();
        tp.version++;
        return json(204, null);
      }
    }
    // UXW-06: shares (the owner's) and the demo member's star, as the server.
    if (sub === "shares") {
      if (method === "GET") return json(200, { items: tp.shares || [] });
      if (method === "PUT") {
        const items = body?.items;
        if (!Array.isArray(items) || items.length > 500) fail(422, "CS-API-0001", "Malformed request", [{ pointer: "/items", code: "CS-API-0001" }]);
        const seen = new Set();
        tp.shares = items.map((it, i) => {
          const named = ["user_id", "email", "group_id", "account"].filter((k) => it?.[k] != null);
          const bad = () => fail(422, "CS-API-0001", "Malformed request", [{ pointer: `/items/${i}`, code: "CS-API-0001" }]);
          if (named.length !== 1) bad();
          let target;
          if (it.account === true) target = { account: true };
          else if (it.group_id) { const g = db.groups.find((x) => x.id === it.group_id); if (!g) bad(); target = { group: { id: g.id, name: g.name } }; }
          else {
            const u = db.users.find((x) => (it.user_id && x.id === it.user_id) || (it.email && (x.email || "").toLowerCase() === String(it.email).trim().toLowerCase()));
            if (!u || u.id === tp.owner_user_id) bad();
            target = { user: { id: u.id, name: u.name || null, email: u.email } };
          }
          const key = JSON.stringify(target.user?.id ?? target.group?.id ?? "account");
          if (seen.has(key)) bad();
          seen.add(key);
          return { id: uid(), can_edit: !!it.can_edit, ...target };
        });
        return json(200, { items: tp.shares });
      }
    }
    if (sub === "favourite" && (method === "PUT" || method === "DELETE")) {
      tp.favourite = method === "PUT";
      return json(204, null);
    }
    if (sub === "duplicate" && method === "POST") {
      // `POST /templates/{id}/duplicate {name?}`: "Copy of <name>" unless named.
      const name = typeof body?.name === "string" && body.name.trim() ? body.name.trim() : `Copy of ${tp.name}`;
      const copy = newTemplate({ name: name.slice(0, 255), ...(tp.email_subject != null ? { email_subject: tp.email_subject } : {}), ...(tp.email_message != null ? { email_message: tp.email_message } : {}), roles: tp.roles.map(({ name: n, type, routing_order }) => ({ name: n, type, routing_order })) });
      const roleIds = new Map(tp.roles.map((r, i) => [r.id, copy.roles[i].id]));
      const ids = new Map();
      for (const d of tp.documents) { const nd = { ...d, id: uid() }; db.blobs[nd.id] = db.blobs[d.id]; ids.set(d.id, nd.id); copy.documents.push(nd); }
      for (const f of tp.fields) copy.fields.push({ ...f, id: uid(), document_id: ids.get(f.document_id), role_id: roleIds.get(f.role_id) });
      return tplWhole(copy, 201);
    }
    if (sub === "documents") {
      if (!subId && method === "POST") {
        tplIfMatch(tp, headers, false);
        for (const k of Object.keys(body || {})) if (!["name", "content_base64"].includes(k)) fail(400, "CS-API-0001", "Unknown member", [{ pointer: `/${k}`, code: "unknown" }]);
        const upload = unb64(body?.content_base64 || "");
        // A Word document is converted first, as the server does (ADR-042).
        const bytes = upload.length >= 4 && upload[0] === 0x50 && upload[1] === 0x4b ? mockConvert(upload) : upload;
        if (bytes.length < 8 || String.fromCharCode(...bytes.subarray(0, 5)) !== "%PDF-") fail(422, "CS-PDF-0001", "Not a PDF");
        const d = { id: uid(), name: String(body?.name || "document.pdf").slice(0, 255), ord: tp.documents.length, pages: countPages(bytes), sha256: null };
        db.blobs[d.id] = b64(bytes);
        tp.documents.push(d);
        tp.version++;
        return tplWhole(tp, 201);
      }
      const d = tp.documents.find((x) => x.id === subId);
      if (!d) fail(404, "CS-API-0002", "Not found");
      if (subSub === "content" && method === "GET") return pdf(unb64(db.blobs[d.id]));
      if (!subSub && method === "DELETE") {
        tplIfMatch(tp, headers);
        tp.documents = tp.documents.filter((x) => x !== d);
        tp.fields = tp.fields.filter((f) => f.document_id !== d.id);
        tp.version++;
        return json(204, null);
      }
    }
    if (sub === "roles") {
      if (!subId && method === "POST") {
        tplIfMatch(tp, headers, false);
        tp.roles.push(checkRole(body, ""));
        tp.version++;
        return tplWhole(tp, 201);
      }
      const r = tp.roles.find((x) => x.id === subId);
      if (!r) fail(404, "CS-API-0002", "Not found");
      if (method === "PATCH") {
        tplIfMatch(tp, headers);
        const next = checkRole({ name: r.name, type: r.type, routing_order: r.routing_order, ...(body || {}) }, "");
        Object.assign(r, { name: next.name, type: next.type, routing_order: next.routing_order });
        tp.version++;
        return tplWhole(tp);
      }
      if (method === "DELETE") {
        tplIfMatch(tp, headers);
        tp.roles = tp.roles.filter((x) => x !== r);
        tp.fields = tp.fields.filter((f) => f.role_id !== r.id);
        tp.version++;
        return json(204, null);
      }
    }
    if (sub === "fields") {
      if (!subId && method === "GET") return json(200, { items: tp.fields }, { ETag: `"v${tp.version}"` });
      if (!subId && method === "POST") {
        tplIfMatch(tp, headers, false);
        const items = Array.isArray(body?.items) ? body.items : body?.items != null ? fail(400, "CS-API-0001", "Malformed request", [{ pointer: "/items", code: "type" }]) : [body];
        if (!items.length) fail(400, "CS-API-0001", "Malformed request", [{ pointer: "/items", code: "required" }]);
        const out = items.map((f, i) => templateField(tp, f, body?.items ? `/items/${i}` : ""));
        tp.fields.push(...out);
        tp.version++;
        return json(201, { items: out }, { ETag: `"v${tp.version}"` });
      }
      const f = tp.fields.find((x) => x.id === subId);
      if (!f) fail(404, "CS-API-0002", "Not found");
      if (method === "PATCH") {
        tplIfMatch(tp, headers);
        if (body && "id" in body) fail(400, "CS-API-0001", "Malformed request", [{ pointer: "/id", code: "read_only" }]);
        const merged = { ...f, ...f.placement, ...(body || {}), ...(body?.placement || {}) };
        delete merged.placement;
        if (body && "required" in body && !body.required) delete merged.required;
        if (body && "label" in body && !body.label) delete merged.label;
        const next = templateField(tp, merged, "", f.id);
        Object.keys(f).forEach((k) => delete f[k]);
        Object.assign(f, next);
        tp.version++;
        return json(200, f, { ETag: `"v${tp.version}"` });
      }
      if (method === "DELETE") {
        tplIfMatch(tp, headers);
        tp.fields = tp.fields.filter((x) => x !== f);
        tp.version++;
        return json(204, null);
      }
    }
    fail(405, "CS-API-0012", "Method not allowed");
  }

  // ---- Users and API clients (WEB-02 Admin) ------------------------------------------
  /// Mint an invitation token for `u` (the server emails `…/app.html#/accept-invite?token=`);
  /// the mock keeps it in `db.invites` for the tests to read.
  function mintInvite(u) {
    db.invites ||= {};
    for (const [k, v] of Object.entries(db.invites)) if (v === u.id) delete db.invites[k];
    db.invites[`inv-${uid()}`] = u.id;
  }
  /// The signed-in user's own profile (UX-04; served by the server since UXW-37, whose
  /// statuses these follow): name, email (only an administrator changes it), notification
  /// choices, a saved signature and initials, and a password change that needs the
  /// current password.
  /// `GET /users/me/export` (ASVS-16), as the server: the demo user's own data in this
  /// workspace, three a minute.
  function exportMe() {
    const u = db.users.find((x) => x.id === "user-demo");
    if (!u) fail(404, "CS-API-0002", "Not found");
    const minute = Math.floor(now().getTime() / 60_000);
    db.exports = db.exports?.minute === minute ? db.exports : { minute, n: 0 };
    db.exports.n += 1;
    if (db.exports.n > 3) fail(429, "CS-API-0003", "Too many requests");
    const p = db.profiles?.[u.id] || { notifications: { completed: true, declined: true, viewed: false }, signature: null, initials: null };
    return json(200, {
      format: "openseal.personal-data-export", v: 1, exported_at: iso(),
      workspace: { id: "acct-demo", name: account().name },
      user: { id: u.id, name: u.name, email: u.email, ...p },
      login_kind: "local", profile: null, sessions: [], api_clients: [],
      envelopes: db.envelopes.filter((e) => !e.sender_user_id || e.sender_user_id === u.id).map((e) => ({ id: e.id, status: e.status, subject: e.subject })),
      templates: [], kept: "Audit events and the admin log are kept unchanged.",
    });
  }

  /// `DELETE /users/me` (ASVS-16), as the server: the demo user owns the organization,
  /// so the mock answers as the server does for them.
  function eraseMe() {
    fail(409, "CS-API-0018", "Not erasable now", [], "organization administrator");
  }

  /// `GET/PUT /retention`, `GET /retention/preview` (ASVS-18), as the server.
  async function retention(method, id, body) {
    const CLASSES = ["draft", "ended", "completed", "sessions"];
    const rules = (db.retention ||= { draft: null, ended: null, completed: null, sessions: null });
    const out = () => json(200, { keep_days: { ...rules }, max_keep_days: 36500 });
    if (id === "preview" && method === "GET") {
      const ended = db.envelopes.filter((e) => ["declined", "voided", "expired"].includes(e.status));
      return json(200, { at: iso(), counts: { draft: 0, ended: rules.ended ? ended.length : 0, completed: 0 }, sessions: 0, held: 0, envelopes: [] });
    }
    if (id) fail(404, "CS-API-0002", "Not found");
    if (method === "GET") return out();
    if (method !== "PUT") fail(405, "CS-API-0012", "Method not allowed");
    const k = body?.keep_days;
    if (!k || typeof k !== "object") fail(422, "CS-API-0001", "Malformed request", [{ pointer: "/keep_days", code: "CS-API-0001" }]);
    for (const [c, d] of Object.entries(k)) {
      if (!CLASSES.includes(c) || (d !== null && !(Number.isInteger(d) && d >= 1 && d <= 36500))) fail(422, "CS-API-0001", "Malformed request", [{ pointer: `/keep_days/${c}`, code: "CS-API-0001" }]);
    }
    for (const [c, d] of Object.entries(k)) {
      if (rules[c] !== d) {
        await adminEvent("retention.rule_set", { changes: [{ key: c, old: rules[c], new: d }] });
        rules[c] = d;
      }
    }
    save();
    return out();
  }

  function me(method, body) {
    const u = db.users.find((x) => x.id === "user-demo");
    if (!u) fail(404, "CS-API-0002", "Not found");
    // Kept beside the member record, so the admin list keeps the server's shape. The demo
    // password itself never changes (sign-in stays MOCK.password).
    db.profiles ||= {};
    const p = (db.profiles[u.id] ||= { notifications: { completed: true, declined: true, viewed: false }, signature: null, initials: null });
    const out = () => ({ id: u.id, name: u.name, email: u.email, notifications: { ...p.notifications }, signature: p.signature, initials: p.initials });
    if (method === "GET") return json(200, out());
    if (method !== "PATCH") fail(405, "CS-API-0012", "Method not allowed");
    const b = body || {};
    for (const k of Object.keys(b)) if (!["name", "notifications", "signature", "initials", "password", "current_password"].includes(k)) fail(400, "CS-API-0001", "Unknown member", [{ pointer: `/${k}`, code: "unknown" }]);
    if ("name" in b && (typeof b.name !== "string" || !b.name.trim() || b.name.trim().length > 255)) fail(422, "CS-API-0001", "Name required", [{ pointer: "/name", code: "required" }]);
    if ("notifications" in b) {
      const n = b.notifications;
      if (!n || typeof n !== "object" || Object.entries(n).some(([k, v]) => !["completed", "declined", "viewed"].includes(k) || typeof v !== "boolean")) fail(422, "CS-API-0001", "Malformed request", [{ pointer: "/notifications", code: "type" }]);
    }
    for (const m of ["signature", "initials"]) {
      if (m in b && b[m] !== null && (typeof b[m]?.image_base64 !== "string" || !b[m].image_base64 || b[m].image_base64.length > 2_000_000)) fail(422, "CS-API-0001", "Malformed request", [{ pointer: `/${m}`, code: "type" }]);
    }
    if ("current_password" in b && !("password" in b)) fail(422, "CS-API-0001", "Malformed request", [{ pointer: "/current_password", code: "CS-API-0001" }]);
    if ("password" in b) {
      if (typeof b.password !== "string" || b.password.length < 12 || b.password.length > 256) fail(422, "CS-API-0001", "Password too short", [{ pointer: "/password", code: "min_length" }]);
      if (b.current_password !== MOCK.password) fail(401, "CS-AUTH-0007", "Invalid credentials");
    }
    if ("name" in b) u.name = b.name.trim();
    if ("notifications" in b) p.notifications = { ...p.notifications, ...b.notifications };
    for (const m of ["signature", "initials"]) if (m in b) p[m] = b[m];
    return json(200, out());
  }

  async function users(method, id, body, sub) {
    if (id && sub === "second-factor" && method === "POST") {
      // ASVS-32, as the server: a member who lost every factor, after the administrator
      // says how they proved who it is. The demo has no other member with a factor.
      const u = db.users.find((x) => x.id === id);
      if (!u) fail(404, "CS-API-0002", "Not found");
      if (u.id === "user-demo") fail(422, "CS-API-0001", "Malformed request", [{ pointer: "/id", code: "CS-API-0001" }]);
      if (!["in_person", "video_call", "phone_callback", "manager_confirmation", "identity_document"].includes(body?.identity_verified_by)) fail(422, "CS-API-0001", "Invalid request", [{ pointer: "/identity_verified_by", code: "CS-API-0001" }]);
      await adminEvent("member.factors_reset", { target: { user: u.id }, changes: [{ key: "identity_verified_by", old: null, new: body.identity_verified_by }] });
      return json(200, { user_id: u.id, removed: { totp: false, passkeys: 0 }, identity_verified_by: body.identity_verified_by, enrol_at_next_sign_in: true });
    }
    if (!id && method === "POST" && body?.invite === true) {
      // `POST /users` with `invite: true` (WEB-06 AD-01): a member who sets up their own
      // sign-in from the emailed link. As the server: `invitation` (the latest one's
      // state) is on single reads and invites, not on the list; a name is required.
      for (const k of Object.keys(body)) if (!["email", "name", "profile", "password", "invite"].includes(k)) fail(400, "CS-API-0001", "Unknown member", [{ pointer: `/${k}`, code: "unknown" }]);
      if (typeof body.name !== "string" || !body.name.trim()) fail(400, "CS-API-0001", "Name required", [{ pointer: "/name", code: "required" }]);
      if (typeof body?.email !== "string" || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(body.email)) fail(400, "CS-API-0001", "Invalid email", [{ pointer: "/email", code: "format" }]);
      const pid = profileIdOf(body.profile);
      if (db.users.some((u) => u.email.toLowerCase() === body.email.toLowerCase())) fail(400, "CS-API-0001", "Already a member", [{ pointer: "/email", code: "exists" }]);
      const u = { id: uid(), email: body.email, name: body.name.trim(), login_kind: "local", permission_profile_id: pid, disabled: false, invitation: "sent" };
      db.users.push(u);
      mintInvite(u);
      await adminEvent("member.added", { target: { user: u.id }, changes: [{ key: "profile", old: null, new: u.permission_profile_id }] });
      return json(201, u);
    }
    if (id && sub === "invite" && method === "POST") {
      const u = db.users.find((x) => x.id === id);
      if (!u) fail(404, "CS-API-0002", "Not found");
      if (u.disabled || u.login_kind !== "local") fail(422, "CS-API-0001", "Malformed request", [{ pointer: "/id", code: "CS-API-0001" }]);
      mintInvite(u);
      u.invitation = "sent";
      return json(202, u);
    }
    if (!id) {
      if (method === "GET") return json(200, { items: db.users.map(({ invitation: _i, ...rest }) => rest) });
      if (method === "POST") {
        if (!body || typeof body.name !== "string" || !body.name.trim()) fail(400, "CS-API-0001", "Name required", [{ pointer: "/name", code: "required" }]);
        if (typeof body.email !== "string" || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(body.email)) fail(400, "CS-API-0001", "Invalid email", [{ pointer: "/email", code: "format" }]);
        const pid = profileIdOf(body.profile);
        if (body.password != null && (typeof body.password !== "string" || body.password.length < 12)) fail(400, "CS-API-0001", "Password too short", [{ pointer: "/password", code: "min_length" }]);
        const u = { id: uid(), email: body.email, name: body.name.trim(), login_kind: "local", permission_profile_id: pid, disabled: false };
        db.users.push(u);
        await adminEvent("member.added", { target: { user: u.id }, changes: [{ key: "profile", old: null, new: u.permission_profile_id }] });
        return json(201, u);
      }
    }
    const u = db.users.find((x) => x.id === id);
    if (!u) fail(404, "CS-API-0002", "Not found");
    if (method === "GET") return json(200, { ...u, invitation: u.invitation ?? null });
    if (method === "PATCH") {
      // As the server (SEC-ID-01): nothing in the request is applied.
      if ((body?.name != null || body?.password != null) && u.id !== "user-demo" && u.email.toLowerCase() === MOCK.sharedEmail) {
        fail(403, "CS-API-0015", "The user belongs to another account too");
      }
      if (body?.name != null) {
        if (!String(body.name).trim()) fail(400, "CS-API-0001", "Name required", [{ pointer: "/name", code: "required" }]);
        u.name = String(body.name).trim();
      }
      // Permission profile and disabling (WEB-06 AD-01); nobody disables or demotes themselves.
      if (body?.profile != null) {
        const pid = profileIdOf(body.profile);
        if (u.id === "user-demo" && pid !== "profile-admin") fail(400, "CS-API-0001", "Malformed request", [{ pointer: "/profile", code: "self" }]);
        u.permission_profile_id = pid;
      }
      if (body?.disabled != null) {
        if (typeof body.disabled !== "boolean") fail(400, "CS-API-0001", "Malformed request", [{ pointer: "/disabled", code: "type" }]);
        if (u.id === "user-demo" && body.disabled) fail(400, "CS-API-0001", "Malformed request", [{ pointer: "/disabled", code: "self" }]);
        u.disabled = body.disabled;
      }
      return json(200, u);
    }
    if (method === "DELETE") {
      if (u.id === "user-demo") fail(400, "CS-API-0001", "Malformed request", [{ pointer: "/id", code: "self" }]);
      db.users = db.users.filter((x) => x !== u);
      // As 0033: their places in groups go with them.
      for (const g of db.groups) { g.user_ids = (g.user_ids || []).filter((x) => x !== u.id); g.members = g.user_ids.length; }
      await adminEvent("member.removed", { target: { user: u.id } });
      return json(204, null);
    }
    fail(405, "CS-API-0012", "Method not allowed");
  }
  /// `profile` as the server reads it: a built-in name or a profile id (422 otherwise).
  function profileIdOf(name) {
    if (["admin", "sender", "viewer"].includes(name)) return `profile-${name}`;
    if (db.profiles.some((p) => p.id === name)) return name;
    return fail(422, "CS-API-0001", "Unknown profile", [{ pointer: "/profile", code: "CS-API-0001" }]);
  }

  /// Groups (UXW-06 list; UXW-07 management), as the server: a name used once
  /// (`exists`), members only from the account, a group's template shares go with it.
  async function groups(method, id, sub, body) {
    const named = () => {
      const n = typeof body?.name === "string" ? body.name.trim() : "";
      if (!n || n.length > 255) fail(422, "CS-API-0001", "Malformed request", [{ pointer: "/name", code: "CS-API-0001" }]);
      return n;
    };
    const out = (g, full = false) => { const { user_ids: ids, ...rest } = g; return full ? { ...rest, user_ids: [...(ids || [])] } : rest; };
    if (!id) {
      if (method === "GET") return json(200, { items: db.groups.slice().sort((a, b) => a.name.localeCompare(b.name)).map((g) => out(g)) });
      if (method === "POST") {
        const n = named();
        if (db.groups.some((g) => g.name === n)) fail(422, "CS-API-0001", "Malformed request", [{ pointer: "/name", code: "exists" }]);
        const g = { id: uid(), name: n, members: 0, user_ids: [] };
        db.groups.push(g);
        await adminEvent("group.created", { target: { group: g.id }, changes: [{ key: "name", old: null, new: n }] });
        return json(201, out(g, true));
      }
      fail(405, "CS-API-0012", "Method not allowed");
    }
    const g = db.groups.find((x) => x.id === id);
    if (!g) fail(404, "CS-API-0002", "Not found");
    if (sub === "members" && method === "PUT") {
      if (!Array.isArray(body?.user_ids)) fail(422, "CS-API-0001", "Malformed request", [{ pointer: "/user_ids", code: "CS-API-0001" }]);
      const want = [];
      body.user_ids.forEach((u, i) => {
        if (!db.users.some((x) => x.id === u)) fail(422, "CS-API-0001", "Malformed request", [{ pointer: `/user_ids/${i}`, code: "CS-API-0001" }]);
        if (!want.includes(u)) want.push(u);
      });
      for (const u of g.user_ids.filter((x) => !want.includes(x))) await adminEvent("group.member_removed", { target: { group: g.id, user: u } });
      for (const u of want.filter((x) => !g.user_ids.includes(x))) await adminEvent("group.member_added", { target: { group: g.id, user: u } });
      g.user_ids = want;
      g.members = want.length;
      return json(200, out(g, true));
    }
    if (sub) fail(404, "CS-API-0002", "Not found");
    if (method === "GET") return json(200, out(g, true));
    if (method === "PATCH") {
      const n = named();
      if (db.groups.some((x) => x !== g && x.name === n)) fail(422, "CS-API-0001", "Malformed request", [{ pointer: "/name", code: "exists" }]);
      await adminEvent("group.renamed", { target: { group: g.id }, changes: [{ key: "name", old: g.name, new: n }] });
      g.name = n;
      return json(200, out(g, true));
    }
    if (method === "DELETE") {
      db.groups = db.groups.filter((x) => x !== g);
      for (const tp of db.templates) if (Array.isArray(tp.shares)) tp.shares = tp.shares.filter((sh) => sh.group?.id !== g.id);
      await adminEvent("group.deleted", { target: { group: g.id } });
      return json(204, null);
    }
    fail(405, "CS-API-0012", "Method not allowed");
  }

  /// Permission profiles (UXW-07), as the server: built-in ones fixed and listed first,
  /// custom ones of known permissions only, a held one not deleted (409).
  async function profiles(method, id, body) {
    const KNOWN = ["envelopes:read", "envelopes:write", "envelopes:send", "templates:read", "templates:write", "bulk:send", "webhooks:manage", "admin:users", "admin:account", "audit:read", "view_all_envelopes"];
    const out = (p) => ({ ...p, members: db.users.filter((u) => u.permission_profile_id === p.id).length });
    const perms = (list) => {
      if (!Array.isArray(list)) fail(422, "CS-API-0001", "Malformed request", [{ pointer: "/permissions", code: "CS-API-0001" }]);
      list.forEach((x, i) => { if (!KNOWN.includes(x)) fail(422, "CS-API-0001", "Malformed request", [{ pointer: `/permissions/${i}`, code: "CS-API-0001" }]); });
      return KNOWN.filter((k) => list.includes(k));
    };
    const named = (n, self = null) => {
      const v = typeof n === "string" ? n.trim() : "";
      if (!v || v.length > 255) fail(422, "CS-API-0001", "Malformed request", [{ pointer: "/name", code: "CS-API-0001" }]);
      if (db.profiles.some((p) => p !== self && p.name === v)) fail(422, "CS-API-0001", "Malformed request", [{ pointer: "/name", code: "exists" }]);
      return v;
    };
    if (!id) {
      if (method === "GET") return json(200, { items: [...db.profiles.filter((p) => p.builtin), ...db.profiles.filter((p) => !p.builtin).sort((a, b) => a.name.localeCompare(b.name))].map(out) });
      if (method === "POST") {
        const p = { id: uid(), name: named(body?.name), kind: "custom", builtin: false, permissions: perms(body?.permissions) };
        db.profiles.push(p);
        await adminEvent("profile.created", { target: { profile: p.id }, changes: [{ key: "permissions", old: null, new: p.permissions }] });
        return json(201, out(p));
      }
      fail(405, "CS-API-0012", "Method not allowed");
    }
    const p = db.profiles.find((x) => x.id === id);
    if (!p) fail(404, "CS-API-0002", "Not found");
    if (method === "GET") return json(200, out(p));
    if (p.builtin && (method === "PATCH" || method === "DELETE")) fail(409, "CS-WF-0001", "A built-in profile cannot be changed");
    if (method === "PATCH") {
      const name = body?.name != null ? named(body.name, p) : p.name;
      const permissions = body?.permissions != null ? perms(body.permissions) : p.permissions;
      await adminEvent("profile.changed", { target: { profile: p.id }, changes: [{ key: "permissions", old: p.permissions, new: permissions }] });
      Object.assign(p, { name, permissions });
      return json(200, out(p));
    }
    if (method === "DELETE") {
      if (out(p).members > 0) fail(409, "CS-WF-0001", "Members hold this profile");
      db.profiles = db.profiles.filter((x) => x !== p);
      await adminEvent("profile.deleted", { target: { profile: p.id } });
      return json(204, null);
    }
    fail(405, "CS-API-0012", "Method not allowed");
  }

  function apiClients(method, id, body) {
    if (!id) {
      if (method === "GET") return json(200, { items: db.apiClients });
      if (method === "POST") {
        if (!body || typeof body.name !== "string" || !body.name.trim()) fail(400, "CS-API-0001", "Name required", [{ pointer: "/name", code: "required" }]);
        if (!["api_key", "oauth_app", "jwt_integration"].includes(body.kind)) fail(400, "CS-API-0001", "Unknown kind", [{ pointer: "/kind", code: "enum" }]);
        if (!Array.isArray(body.scopes) || !body.scopes.length) fail(400, "CS-API-0001", "Scopes required", [{ pointer: "/scopes", code: "required" }]);
        // VS-08A, VS-08B: as the server checks redirect URIs and a JWT integration's key.
        const redirects = Array.isArray(body.redirect_uris) ? body.redirect_uris : [];
        if (redirects.length > 10 || (body.kind === "api_key" && redirects.length)) fail(422, "CS-API-0001", "Malformed request", [{ pointer: "/redirect_uris", code: "CS-API-0001" }]);
        const bad = redirects.findIndex((u) => !redirectUriOk(u));
        if (bad >= 0) fail(422, "CS-API-0001", "Malformed request", [{ pointer: `/redirect_uris/${bad}`, code: "CS-API-0001" }]);
        const jwt = body.kind === "jwt_integration";
        if (jwt ? publicKeyProblem(body.public_key) : body.public_key != null) fail(422, "CS-API-0001", "Malformed request", [{ pointer: "/public_key", code: "CS-API-0001" }]);
        const days = Number.isInteger(body.expires_in_days) ? body.expires_in_days : null;
        const secret = uid().replace(/-/g, "");
        const keyPrefix = inSandbox() ? "osk_test_" : "osk_";
        const c = { id: uid(), kind: body.kind, name: body.name.trim(), owner_user_id: body.owner_user_id || "user-demo", key_prefix: body.kind === "api_key" ? `${keyPrefix}${secret.slice(0, 8)}` : null, scopes: body.scopes, expires_at: days ? iso(days * 24 * 60) : null, revoked: false, redirect_uris: body.kind === "api_key" ? [] : redirects, has_public_key: jwt };
        db.apiClients.push(c);
        const shown = body.kind === "api_key" ? { key: `${c.key_prefix}_${secret}` } : jwt ? { client_id: c.id } : { client_id: c.id, client_secret: `oss_${secret}` };
        return json(201, { ...c, ...shown });
      }
    }
    const c = db.apiClients.find((x) => x.id === id);
    if (!c) fail(404, "CS-API-0002", "Not found");
    if (method === "GET") return json(200, c);
    if (method === "DELETE") { c.revoked = true; return json(204, null); }
    fail(405, "CS-API-0012", "Method not allowed");
  }

  /// OAuth consent (VS-08A, server api/oauth.rs): the checked request, the member's
  /// answer with a code in the redirect, and their consents. Codes are not exchanged
  /// here (the token endpoint is the server's); the redirect carries one so the screen
  /// can be followed to its end.
  function oauth(method, id, sub, body, query) {
    const SCOPES = ["envelopes:read", "envelopes:write", "envelopes:send", "templates:read", "templates:write", "bulk:send", "webhooks:manage", "admin:users", "admin:account", "audit:read"];
    db.consents ||= [];
    const bad = (pointer) => fail(422, "CS-API-0001", "Malformed request", [{ pointer, code: "CS-API-0001" }]);
    const check = (q) => {
      const c = db.apiClients.find((x) => x.id === q.client_id);
      if (!c || c.revoked || !["oauth_app", "jwt_integration"].includes(c.kind)) bad("/client_id");
      if (!(c.redirect_uris || []).includes(q.redirect_uri)) bad("/redirect_uri");
      if (q.response_type !== "code") bad("/response_type");
      if (q.code_challenge_method !== "S256" || !/^[A-Za-z0-9_-]{43,128}$/.test(q.code_challenge || "")) bad("/code_challenge");
      const scopes = [...new Set(String(q.scope || "").split(" ").filter(Boolean))];
      if (!scopes.length || scopes.some((s) => !c.scopes.includes(s) || !SCOPES.includes(s))) bad("/scope");
      return { c, scopes };
    };
    if (id === "authorize" && sub === "request" && method === "GET") {
      const q = Object.fromEntries(query.entries());
      const { c, scopes } = check(q);
      return json(200, { client: { id: c.id, name: c.name, kind: c.kind }, scopes, redirect_uri: q.redirect_uri });
    }
    if (id === "authorize" && !sub && method === "POST") {
      const { c, scopes } = check(body || {});
      const back = new URL(body.redirect_uri);
      if (body.decision === "deny") back.searchParams.set("error", "access_denied");
      else if (body.decision === "allow") {
        const live = db.consents.find((k) => k.client.id === c.id && !k.revoked);
        if (live) live.scopes = [...new Set([...live.scopes, ...scopes])];
        else db.consents.unshift({ id: uid(), client: { id: c.id, name: c.name }, scopes, granted_at: iso() });
        back.searchParams.set("code", uid().replace(/-/g, ""));
      } else bad("/decision");
      if (body.state) back.searchParams.set("state", body.state);
      back.searchParams.set("iss", "https://openseal.mock");
      return json(200, { redirect_to: back.toString() });
    }
    if (id === "consents" && !sub && method === "GET") return json(200, { items: db.consents.filter((k) => !k.revoked).map(({ revoked: _r, ...k }) => k) });
    if (id === "consents" && sub && method === "DELETE") {
      const k = db.consents.find((x) => x.id === sub && !x.revoked);
      if (!k) fail(404, "CS-API-0002", "Not found");
      k.revoked = true;
      return json(204, null);
    }
    fail(404, "CS-API-0002", "Not found");
  }

  async function ceremony(method, parts, body, query = null) {
    const token = decodeURIComponent(parts[2] || "");
    const sub = parts[3];
    if (token === MOCK.fieldsToken && !db.tokens[token]) await seed({ fieldKinds: true });
    const t = db.tokens[token];
    if (!t) fail(404, "CS-API-0002", "Not found");
    const env = envOr404(t.env);
    const rec = env.recipients.find((r) => r.id === t.rid);
    if (!rec) fail(404, "CS-API-0002", "Not found");
    const loc = body?.location ? { location: body.location } : {};
    if (!sub && method === "GET") return json(200, view(env, rec, token));
    if (sub === "session" && method === "POST") {
      if (!db.opened.includes(token)) db.opened.push(token);
      if (rec.status === "sent") {
        rec.status = "delivered";
        if (env.status === "sent") env.status = "delivered";
        await audit(env, "recipient.delivered", { recipient_id: rec.id });
      }
      return json(200, view(env, rec, token));
    }
    if (!db.opened.includes(token)) fail(403, "CS-AUTH-0009", "Ceremony link not opened in this browser");
    // UXW-34, as the server: the full disclosure the view's `consent_required` names,
    // readable once every authentication has passed (consent's rule), while the link is
    // valid.
    if (sub === "disclosure" && method === "GET") {
      if (rec.auth.some((m) => !rec.auth_passed.includes(m))) fail(401, "CS-AUTH-0003", "Recipient authentication required");
      return json(200, disclosure());
    }
    // WEB-06: the signer's copy (`GET /s/{token}/document`; in the mock the first
    // document) and history stay available after finishing or declining.
    if (((sub === "document" || sub === "certificate") && parts.length === 4) || sub === "history") {
      if (method !== "GET") fail(405, "CS-API-0012", "Method not allowed");
      if (rec.auth.some((m) => !rec.auth_passed.includes(m))) fail(401, "CS-AUTH-0003", "Recipient authentication required");
      if (sub === "history") {
        // As the server (WEB-07, ceremony.rs `history`): `{seq, type, at, by}`, the events
        // this recipient made or that name them in `data.recipient_id`, and the milestones;
        // `by` without names.
        const by = (a) => (a.kind === "recipient" ? (a.id === rec.id ? "you" : "recipient") : ["sender", "user", "host"].includes(a.kind) ? a.kind : "system");
        const shown = (db.audit[env.id] || []).filter((e) => by(e.event.actor) === "you" || e.event.data?.recipient_id === rec.id || MILESTONES.has(e.type));
        return json(200, { events: shown.map((e) => ({ seq: e.seq, type: e.type, at: e.at, by: by(e.event.actor) })) });
      }
      // As the server: only after this recipient finished (409 before), `doc` optional
      // for one document; the mock serves the delivered bytes (no preview banner).
      if (rec.status !== "completed") fail(409, "CS-API-0009", "Not available before finishing");
      // VS-01, as the server: the certificate of completion once the envelope completes.
      if (sub === "certificate") {
        if (env.status !== "completed") fail(409, "CS-API-0009", "Not available in the object's state");
        const lines = [`Envelope ${env.id}`, `Subject: ${env.subject}`, "Outcome: completed", ""];
        for (const r of env.recipients) lines.push(`${r.name} <${r.email}> - ${r.type} - ${r.status} ${r.completed_at || ""}`);
        lines.push("", "Mock mode: not a real certificate.");
        return pdf(makePdf([{ title: "Certificate of completion", lines }]));
      }
      const want = query?.get("doc");
      const d = want ? env.documents.find((x) => x.id === want) : env.documents[0];
      if (!d) fail(404, "CS-API-0002", "Not found");
      return pdf(unb64(db.blobs[d.id]));
    }
    if (TERMINAL.has(env.status) || rec.status === "completed" || rec.status === "declined") fail(409, "CS-WF-0001", "Not allowed in the current state");
    if (sub === "authenticate" && method === "POST") {
      const n = (db.attempts[token] || 0);
      if (n >= 5) fail(423, "CS-AUTH-0004", "Locked after too many attempts");
      if (body?.method !== "access_code" || body?.code !== rec.access_code) {
        db.attempts[token] = n + 1;
        rec.auth_failures = (rec.auth_failures || 0) + 1;
        await audit(env, "recipient.auth_failed", { recipient_id: rec.id, method: "access_code", attempt: n + 1 });
        fail(401, "CS-AUTH-0003", "Recipient authentication failed");
      }
      if (!rec.auth_passed.includes("access_code")) rec.auth_passed.push("access_code");
      await audit(env, "recipient.auth_passed", { recipient_id: rec.id, method: "access_code" });
      return json(200, view(env, rec, token));
    }
    // A sent one-time code (SEC-A02) by email, SMS or voice call (slice 5): "sent" is
    // MOCK.emailCode whatever the channel; a wrong code answers 403 with the view, as
    // the server does; five failures lock. The open code's method is what a pass meets.
    if (sub === "otp" && !parts[4] && method === "POST") {
      const m = body?.method || "email_otp";
      if (!["email_otp", "sms_otp", "voice_otp"].includes(m) || !rec.auth.includes(m)) fail(409, "CS-API-0014", "Method not available");
      if (rec.auth_passed.includes(m)) fail(409, "CS-API-0009", "Already authenticated");
      rec.otp_open = m;
      await audit(env, "recipient.auth_challenged", { recipient_id: rec.id, method: m });
      return json(202, view(env, rec, token));
    }
    if (sub === "otp" && parts[4] === "verify" && method === "POST") {
      const n = (db.attempts[token] || 0);
      if (n >= 5) fail(423, "CS-AUTH-0004", "Locked after too many attempts");
      const m = typeof rec.otp_open === "string" ? rec.otp_open : (body?.method || "email_otp");
      if (!rec.auth.includes(m) || !rec.otp_open || (body?.method && body.method !== m) || body?.code !== MOCK.emailCode) {
        db.attempts[token] = n + 1;
        rec.auth_failures = (rec.auth_failures || 0) + 1;
        await audit(env, "recipient.auth_failed", { recipient_id: rec.id, method: m, attempt: n + 1 });
        return json(403, view(env, rec, token));
      }
      rec.otp_open = false;
      if (!rec.auth_passed.includes(m)) rec.auth_passed.push(m);
      await audit(env, "recipient.auth_passed", { recipient_id: rec.id, method: m });
      return json(200, view(env, rec, token));
    }
    // Sign-in through an identity provider (`sso`, RAUTH-01), as the server: start
    // answers the view with `sso_authorization_url` (here straight back to the signing
    // page, a relative `?state=…&code=MOCK.ssoCode`); verify takes `{state, code}`, the state works once, and a
    // failure answers 403 with the view and counts.
    if (sub === "sso" && !parts[4] && method === "POST") {
      if (!rec.auth.includes("sso")) fail(409, "CS-API-0014", "Method not available");
      if (rec.auth_passed.includes("sso")) fail(409, "CS-API-0009", "Already authenticated");
      if (body?.provider !== MOCK.ssoProvider.id) fail(422, "CS-API-0001", "Malformed request", [{ pointer: "/provider", code: "CS-API-0001" }]);
      rec.sso_state = uid();
      await audit(env, "recipient.auth_challenged", { recipient_id: rec.id, method: "sso" });
      return json(200, { ...view(env, rec, token), sso_authorization_url: `?state=${encodeURIComponent(rec.sso_state)}&code=${encodeURIComponent(MOCK.ssoCode)}` });
    }
    if (sub === "sso" && parts[4] === "verify" && method === "POST") {
      if (!rec.auth.includes("sso")) fail(409, "CS-API-0014", "Method not available");
      if (rec.auth_passed.includes("sso")) fail(409, "CS-API-0009", "Already authenticated");
      const n = (db.attempts[token] || 0);
      if (n >= 5) fail(423, "CS-AUTH-0004", "Locked after too many attempts");
      const open = rec.sso_state;
      rec.sso_state = null;
      if (!open || body?.state !== open || body?.code !== MOCK.ssoCode) {
        db.attempts[token] = n + 1;
        rec.auth_failures = (rec.auth_failures || 0) + 1;
        await audit(env, "recipient.auth_failed", { recipient_id: rec.id, method: "sso", attempt: n + 1 });
        return json(403, view(env, rec, token));
      }
      rec.auth_passed.push("sso");
      await audit(env, "recipient.auth_passed", { recipient_id: rec.id, method: "sso", identity: { issuer: "https://idp.mock.test", subject_sha256: `sha256:${"0".repeat(64)}` } });
      return json(200, view(env, rec, token));
    }
    if (rec.auth.some((m) => !rec.auth_passed.includes(m))) fail(401, "CS-AUTH-0003", "Recipient authentication required");
    // An in-person signer signs only in a session a staff user hosts (the engine's `gate_in`).
    if (rec.type === "in_person_signer" && !rec.hosted) fail(409, "CS-WF-0001", "Not allowed in the current state");
    if (sub === "consent" && method === "POST") {
      const want = disclosure();
      if (body?.ersd_version !== want.version) fail(400, "CS-API-0001", "Unknown disclosure version", [{ pointer: "/ersd_version", code: "mismatch" }]);
      rec.consented = true;
      await audit(env, "recipient.consented", { recipient_id: rec.id, ersd_version: body.ersd_version, ersd_hash: want.sha256 }, loc);
      return json(200, view(env, rec, token));
    }
    // Withdrawing consent declines a required action, whatever `allow_decline` says (the
    // engine's `WithdrawConsent`: a right, ESIGN §7001(c)(1)(B)).
    if (sub === "withdraw-consent" && method === "POST") {
      if (!rec.consented) fail(409, "CS-WF-0001", "Not allowed in the current state");
      rec.consented = false;
      await audit(env, "recipient.consent_withdrawn", { recipient_id: rec.id, ersd_version: disclosure().version }, loc);
      if (ACTING(rec)) await decline(env, rec, null, loc);
      return json(200, view(env, rec, token));
    }
    if (sub === "decline" && method === "POST") {
      if (!ACTING(rec)) fail(409, "CS-WF-0001", "Not allowed in the current state");
      if (env.signing_options?.allow_decline === false) fail(409, "CS-WF-0012", "Decline not allowed");
      await decline(env, rec, body?.reason, loc);
      return json(200, view(env, rec, token));
    }
    if (!rec.consented) fail(403, "CS-AUTH-0005", "Consent required");
    const order = signersAt(env);
    if (rec.routing_order !== order) fail(409, "CS-WF-0007", "Routing has not reached the recipient yet");
    if (sub === "documents") {
      const d = env.documents.find((x) => x.id === parts[4]);
      if (!d) fail(404, "CS-API-0002", "Not found");
      if (parts[5] === "content" && method === "GET") return pdf(unb64(db.blobs[d.id]));
      if (parts[5] === "viewed" && method === "POST") {
        const seen = body?.pages_seen || [];
        if (!Array.isArray(seen) || seen.some((n) => !Number.isInteger(n) || n < 1 || n > d.pages)) fail(422, "CS-WF-0015", "Viewed document does not match", [{ pointer: "/pages_seen", code: "range" }]);
        await audit(env, "recipient.viewed_document", { recipient_id: rec.id, document: { document_id: d.id, hash: await blobHash(d.id) }, pages_seen: [...new Set(seen)].sort((x, y) => x - y) }, loc);
        // A viewer completes by viewing every document to the end (docs/24 §3).
        if (seen.includes(d.pages)) rec.viewed_to_end = [...new Set([...(rec.viewed_to_end || []), d.id])];
        if (rec.type === "viewer" && viewedAll(env, rec)) await complete(env, rec, loc, "viewed");
        return json(200, view(env, rec, token));
      }
    }
    if (sub === "adopt" && method === "POST") {
      if (!["signature", "initials", "stamp", "drawing"].includes(body?.mark) || !["draw", "type", "upload"].includes(body?.method)) fail(400, "CS-API-0001", "Malformed request");
      let bytes;
      try { bytes = unb64(body.image_base64 || ""); } catch { fail(400, "CS-API-0001", "Malformed request", [{ pointer: "/image_base64", code: "base64" }]); }
      const isPng = bytes.length > 8 && bytes[0] === 0x89 && bytes[1] === 0x50;
      const isJpeg = bytes.length > 3 && bytes[0] === 0xff && bytes[1] === 0xd8;
      if (!(isPng || isJpeg) || bytes.length > 5 * 1024 * 1024) fail(400, "CS-API-0001", "Malformed request", [{ pointer: "/image_base64", code: "image" }]);
      const id = uid();
      db.adoptions[id] = { rid: rec.id, mark: body.mark };
      await audit(env, "recipient.signature_adopted", { recipient_id: rec.id, mark: body.mark, method: body.method, image_hash: await sha256hex(body.image_base64) }, loc);
      return json(200, { ...view(env, rec, token), adoption_id: id });
    }
    if (sub === "fields" && parts[5] === "attachment" && method === "PUT") {
      const f = env.fields.find((x) => x.id === parts[4]);
      if (!f) fail(404, "CS-API-0002", "Not found");
      if (f.recipient_id !== rec.id || f.type !== "attachment") fail(409, "CS-WF-0016", "Field not editable by this recipient");
      let bytes;
      try { bytes = unb64(body?.content_base64 || ""); } catch { fail(400, "CS-API-0001", "Malformed request"); }
      const isPdf = bytes.length > 4 && bytes[0] === 0x25 && bytes[1] === 0x50 && bytes[2] === 0x44 && bytes[3] === 0x46;
      const isPng = bytes.length > 8 && bytes[0] === 0x89 && bytes[1] === 0x50;
      const isJpeg = bytes.length > 3 && bytes[0] === 0xff && bytes[1] === 0xd8;
      if (!(isPdf || isPng || isJpeg) || bytes.length > 10 * 1024 * 1024) fail(422, "CS-WF-0015", "Attachment refused", [{ pointer: "/content_base64", code: "type" }]);
      const sha = await sha256hex(body.content_base64);
      (db.attachments ||= {})[`${rec.id}:${sha}`] = true;
      f.value = { attachment: sha };
      await audit(env, "recipient.field_completed", { recipient_id: rec.id, field_id: f.id, value_hash: await sha256hex(JSON.stringify(f.value)) });
      return json(200, view(env, rec, token));
    }
    if (sub === "fields" && method === "PUT") {
      const f = env.fields.find((x) => x.id === parts[4]);
      if (!f) fail(404, "CS-API-0002", "Not found");
      if (!holds(f, rec.id) || !INPUT_TYPES.has(f.type) || f.locked || f.read_only) fail(409, "CS-WF-0016", "Field not editable by this recipient");
      const v = body?.value;
      const bad = (code) => fail(422, "CS-WF-0015", "Field value refused", [{ pointer: "/value", code }]);
      if (f.type === "signature" || f.type === "initials" || f.type === "stamp" || f.type === "drawing") {
        const a = v && db.adoptions[v.signature];
        if (!a || a.rid !== rec.id) fail(409, "CS-WF-0013", "Signature or initials not adopted before use");
        // VS-04A, as the server: a stamp or drawing capture fills only its own kind.
        const kinds = f.type === "stamp" || f.type === "drawing" ? [f.type] : ["signature", "initials"];
        if (!kinds.includes(a.mark)) bad("invalid");
      } else if (f.type === "multi_select") {
        if (!v || !Array.isArray(v.choices)) bad("wrong_kind");
        if (!(f.options || []).length || v.choices.some((c) => !(f.options || []).includes(c))) bad("not_an_option");
      } else if (f.type === "checkbox") {
        if (!v || typeof v.checked !== "boolean") fail(400, "CS-API-0001", "Malformed request", [{ pointer: "/value", code: "type" }]);
      } else if (f.type === "radio_group" || f.type === "dropdown") {
        if (!v || typeof v.choice !== "string") bad("wrong_kind");
        if (v.choice && !(f.options || []).includes(v.choice) && !(f.type === "dropdown" && f.allow_custom)) bad("not_an_option");
      } else if (f.type === "attachment") {
        if (!v || !db.attachments?.[`${rec.id}:${v.attachment}`]) bad("not_uploaded");
      } else {
        if (!v || typeof v.text !== "string") bad("wrong_kind");
        // The same rules as the engine, by the signer's own module (tests/signfields).
        if (checkText(f, v.text)) bad("invalid");
      }
      f.value = v;
      await audit(env, "recipient.field_completed", { recipient_id: rec.id, field_id: f.id, value_hash: await sha256hex(JSON.stringify(f.value)) });
      return json(200, view(env, rec, token));
    }
    // As the server (FG-013, ADR-043, `POST /s/{token}/paper`): a signer, where the
    // envelope allows it, completes with the scan of the documents printed and signed by
    // hand; the scan joins the envelope fixed (sealed with it) and is recorded.
    if (sub === "paper" && method === "POST") {
      if (env.signing_options?.allow_sign_on_paper !== true) fail(409, "CS-WF-0012", "Sign on paper not allowed");
      if (rec.type !== "signer") fail(409, "CS-WF-0001", "Not allowed for this recipient");
      const bytes = unb64(String(body?.content_base64 || ""));
      if (bytes.length < 8 || String.fromCharCode(...bytes.subarray(0, 5)) !== "%PDF-") fail(422, "CS-API-0001", "Malformed or invalid request", [{ pointer: "/content_base64", code: "invalid" }]);
      const printed = await docHashes(env);
      const d = addDocument(env, "Signed on paper.pdf", bytes);
      d.fixed = true;
      await audit(env, "document.added", { document_id: d.id, upload_hash: await blobHash(d.id), bytes: d.bytes }, loc);
      await audit(env, "document.admitted", { document_id: d.id, report_hash: await blobHash(d.id, ":admission"), findings: 0 }, loc);
      await audit(env, "document.fixed", { document_id: d.id, delivered_hash: await blobHash(d.id), pages: d.pages }, loc);
      await audit(env, "recipient.signed_on_paper", { recipient_id: rec.id, documents: printed, document_id: d.id, upload_hash: await blobHash(d.id) }, loc);
      await complete(env, rec, loc, "paper");
      return json(200, view(env, rec, token));
    }
    if (sub === "finish" && method === "POST") {
      // As the engine's `finish`: an approver approves and a copy has nothing to finish;
      // a viewer finishes once every document was viewed to the end.
      if (rec.type === "approver" || rec.type === "cc") fail(409, "CS-WF-0001", "Not allowed for this recipient");
      if (rec.type === "viewer" && !viewedAll(env, rec)) fail(409, "CS-WF-0014", "Viewer has not viewed every document to the end");
      checkRequired(env, rec);
      for (const f of env.fields) if (f.recipient_id === rec.id && f.type === "date_signed") f.value = { text: iso().slice(0, 10) };
      // As the engine at finish: the envelope's id, computed formulas, mirrored values
      // and hidden values dropped (VS-04A, VS-04C).
      const rules = rulesFor(env.fields, rec.id);
      for (const f of env.fields) {
        if (f.recipient_id !== rec.id) continue;
        if (f.type === "envelope_id") f.value = { text: env.id };
        else if (f.type === "formula" && rules.computed[f.id]?.ok) f.value = { text: rules.computed[f.id].ok };
        else if (rules.hidden.includes(f.id)) delete f.value;
        else if (!f.value && rules.values[f.id]) f.value = rules.values[f.id];
      }
      await complete(env, rec, loc, rec.type === "viewer" ? "viewed" : "signed");
      return json(200, view(env, rec, token));
    }
    // An approver approves (`recipient.approved`, then completed), their own data fields
    // checked as at finish.
    if (sub === "approve" && method === "POST") {
      if (rec.type !== "approver") fail(409, "CS-WF-0001", "Not allowed for this recipient");
      checkRequired(env, rec);
      await complete(env, rec, loc, "approved");
      return json(200, view(env, rec, token));
    }
    // UX-03, not on the server yet (NOT_ON_SERVER.clearField): a signer removes a value
    // they gave, before finishing; recorded as a new event (no value, no hash).
    if (sub === "fields" && parts[4] && !parts[5] && method === "DELETE") {
      const f = env.fields.find((x) => x.id === parts[4]);
      if (!f) fail(404, "CS-API-0002", "Not found");
      if (f.recipient_id !== rec.id || f.locked || f.read_only || f.type === "date_signed" || f.type === "note") fail(409, "CS-WF-0016", "Field not editable by this recipient");
      if (f.value == null) fail(409, "CS-WF-0001", "Not allowed in the current state");
      delete f.value;
      // Not a casual-sign-audit type yet: the clear-field row adds it (NOT_ON_SERVER.clearField).
      await audit(env, "recipient.field_cleared", { recipient_id: rec.id, field_id: f.id });
      return json(200, view(env, rec, token));
    }
    if (sub === "reassign" && method === "POST") {
      if (env.signing_options?.allow_reassign !== true) fail(409, "CS-WF-0001", "Not allowed in the current state");
      const name = String(body?.name || "").trim();
      const email = String(body?.email || "").trim();
      if (!name || !/^[^@\s]+@[^@\s]+$/.test(email)) fail(400, "CS-API-0001", "Malformed request", [{ pointer: name ? "/email" : "/name", code: "required" }]);
      rec.status = "reassigned";
      const nr = { ...rec, id: uid(), name, email, status: "sent", auth: [], auth_passed: [], consented: false, token: null };
      env.recipients.push(nr);
      for (const f of env.fields) if (f.recipient_id === rec.id) f.recipient_id = nr.id;
      await audit(env, "recipient.reassigned", { recipient_id: rec.id, to_recipient_id: nr.id, ...(body?.reason ? { reason: String(body.reason) } : {}) }, loc);
      return json(200, view(env, rec, token));
    }
    // VS-06A, as the server: an editor adds, moves and removes their own fields and those
    // of later recipients not yet reached; anyone else, or a reached recipient's field,
    // is refused (409 CS-WF-0001). Recorded as `envelope.corrected`.
    if (sub === "editor" && parts[4] === "fields") {
      if (rec.type !== "editor" || !["sent", "delivered"].includes(rec.status)) fail(409, "CS-WF-0001", "Not allowed for this recipient");
      const refuse = () => fail(409, "CS-WF-0001", "Not allowed for this recipient");
      const check = (f) => { if (!editableField(env, rec, f)) refuse(); };
      if (!parts[5] && method === "POST") {
        const list = Array.isArray(body?.fields) ? body.fields : [];
        if (!list.length || list.length > 100) fail(422, "CS-API-0001", "Malformed or invalid request", [{ pointer: "/fields", code: "invalid" }]);
        const before = env.fields.length;
        const added = [];
        try {
          for (const f of list) {
            const q = env.recipients.find((x) => x.id === f?.recipient_id);
            if (!q) fail(422, "CS-API-0001", "Malformed or invalid request", [{ pointer: "/fields/recipient_id", code: "invalid" }]);
            if (!editableOwner(rec, q)) refuse();
            added.push(addField(env, f));
          }
        } catch (e) { env.fields.length = before; throw e; }
        await audit(env, "envelope.corrected", { changed: added.map((f) => `fields.${f.id}`) }, loc);
        return json(201, view(env, rec, token));
      }
      const f = env.fields.find((x) => x.id === parts[5] && !(rec.excluded_documents || []).includes(x.document_id));
      if (!f || parts[6]) fail(404, "CS-API-0002", "Not found");
      check(f);
      if (method === "PATCH") {
        const next = structuredClone(f);
        const flat = ["page", "x", "y", "width", "height"];
        const patch = body && typeof body === "object" ? body : {};
        if (flat.some((k) => k in patch)) next.placement = placementOf({ ...f.placement, ...Object.fromEntries(flat.filter((k) => k in patch).map((k) => [k, patch[k]])) });
        if (patch.recipient_id) next.recipient_id = patch.recipient_id;
        setMembers(next, patch);
        check(next);
        Object.assign(f, next);
        await audit(env, "envelope.corrected", { changed: [`fields.${f.id}`] }, loc);
        return json(200, view(env, rec, token));
      }
      if (method === "DELETE") {
        env.fields.splice(env.fields.indexOf(f), 1);
        await audit(env, "envelope.corrected", { changed: [`fields.${f.id}`] }, loc);
        return json(200, view(env, rec, token));
      }
    }
    // VS-02, as the server's `RecipientEdit`: an agent or intermediary names later
    // recipients not yet reached (names and addresses only); anyone else is refused.
    if (sub === "recipients" && method === "POST") {
      if (!NAMES_LATER.has(rec.type)) fail(409, "CS-WF-0001", "Not allowed for this recipient");
      const list = Array.isArray(body?.recipients) ? body.recipients : [];
      if (!list.length || list.length > 100) fail(422, "CS-API-0001", "Malformed or invalid request", [{ pointer: "/recipients", code: "invalid" }]);
      const later = laterOf(env, rec).map((q) => q.id);
      const bad = (i, k) => fail(422, "CS-API-0001", "Malformed or invalid request", [{ pointer: `/recipients/${i}/${k}`, code: "CS-API-0001" }]);
      for (const [i, n] of list.entries()) {
        const q = env.recipients.find((x) => x.id === n?.id);
        if (!q) fail(404, "CS-API-0002", "Not found");
        if (!later.includes(q.id)) fail(403, "CS-WF-0003", "Not permitted");
        if (n.name != null && !String(n.name).trim()) bad(i, "name");
        if (n.email != null && !/^[^@\s]+@[^@\s]+$/.test(String(n.email).trim())) bad(i, "email");
        // VS-06A, as the server: an intermediary or editor sets the number, the methods
        // and an access code (kept, never answered); an agent changing the methods is refused.
        if (n.phone != null && !/^\+[1-9][0-9 .()-]{7,}$/.test(String(n.phone).trim())) bad(i, "phone");
        const auth = Array.isArray(n.auth) ? n.auth : q.auth || [];
        if (n.auth != null && rec.type === "agent" && JSON.stringify(n.auth) !== JSON.stringify(q.auth || [])) fail(403, "CS-WF-0003", "Not permitted");
        const email = n.email != null ? String(n.email).trim() : q.email;
        const phone = n.phone != null ? String(n.phone).trim() : q.phone;
        if ((auth.includes("email_otp") || auth.includes("sso")) && !email) bad(i, "auth");
        if ((auth.includes("sms_otp") || auth.includes("voice_otp")) && !phone) bad(i, "auth");
        const code = n.access_code ? String(n.access_code) : "";
        if (code ? !auth.includes("access_code") || code.length > 255 : auth.includes("access_code") && !q.access_code) bad(i, "access_code");
      }
      for (const n of list) {
        const q = env.recipients.find((x) => x.id === n.id);
        if (n.name != null) q.name = String(n.name).trim();
        if (n.email != null) q.email = String(n.email).trim();
        if (n.phone != null) q.phone = String(n.phone).trim();
        if (Array.isArray(n.auth)) q.auth = [...n.auth];
        if (n.access_code) q.access_code = String(n.access_code);
        else if (!q.auth.includes("access_code")) delete q.access_code;
      }
      await audit(env, "envelope.corrected", { changed: list.map((n) => `recipients.${n.id}`) }, loc);
      return json(200, view(env, rec, token));
    }
    if (sub === "finish-later" && method === "POST") {
      await audit(env, "recipient.finish_later", { recipient_id: rec.id });
      return json(200, view(env, rec, token));
    }
    fail(405, "CS-API-0012", "Method not allowed");
  }

  async function handle(input, init = {}) {
    // Test hook: `sessionStorage["openseal.mock.offline"] = "1"` makes every call fail as
    // a lost connection does (the e2e offline state).
    let offline = false;
    try { offline = store?.getItem("openseal.mock.offline") === "1"; } catch { offline = false; }
    if (offline) throw new TypeError("Failed to fetch");
    const url = new URL(typeof input === "string" ? input : input.url, "http://mock.invalid");
    const method = (init.method || "GET").toUpperCase();
    // UX-04, served by the server since UXW-39 (empty until SSO): no session and no state,
    // so answered before the state is loaded; the sign-in form asks on arrival, and an
    // early load would let this tab's copy go stale under another writer (the e2e seed).
    if (url.pathname === "/api/v1/auth/providers" && method === "GET") {
      // Test hook: `sessionStorage["openseal.mock.idp"] = "Acme SSO"` configures one.
      let idp = null;
      try { idp = store?.getItem("openseal.mock.idp") || null; } catch { idp = null; }
      return json(200, { items: idp ? [{ id: "idp-demo", name: idp, url: "/sso/idp-demo/start" }] : [] });
    }
    // Test hook (E2E-13): `globalThis.__opensealMockHold(method, path)`, when a page sets
    // it, may answer a promise that holds this call until the test lets it go, as a slow
    // network does: the e2e edits the draft while its save is on the way.
    const hold = globalThis.__opensealMockHold;
    if (typeof hold === "function") await hold(method, url.pathname);
    await load();
    const headers = {};
    for (const [k, v] of Object.entries(init.headers || {})) headers[k.toLowerCase()] = v;
    let body = null;
    if (init.body instanceof Uint8Array) body = init.body; // a file sent as itself (ADR-042)
    else if (init.body) {
      try { body = JSON.parse(init.body); } catch { return problem({ status: 400, code: "CS-API-0001", title: "Malformed request" }); }
    }
    const parts = url.pathname.split("/");
    try {
      if (url.pathname === "/api/v1/auth/login" && method === "POST") {
        if (body?.email?.toLowerCase() !== MOCK.email || body?.password !== MOCK.password) fail(401, "CS-AUTH-0007", "Invalid credentials");
        db.session = { csrf: uid(), id: uid(), reauth: now().getTime(), at: iso(), client: "Chrome on macOS" };
        save();
        return json(200, { account_id: "acct-demo", user_id: "user-demo", csrf_token: db.session.csrf, expires_at: iso(60 * 12) });
      }
      if (url.pathname === "/api/v1/auth/accept-invite" && method === "POST") {
        // WEB-06 AD-01: the invited member sets a password with the emailed token (no
        // session needed). The token works once.
        const uidOf = db.invites?.[body?.token];
        for (const k of Object.keys(body || {})) if (!["token", "password"].includes(k)) fail(400, "CS-API-0001", "Unknown member", [{ pointer: `/${k}`, code: "unknown" }]);
        if (typeof body?.token !== "string" || !uidOf) fail(401, "CS-AUTH-0002", "Invitation not valid");
        if (typeof body.password !== "string" || body.password.length < 12) fail(400, "CS-API-0001", "Password too short", [{ pointer: "/password", code: "min_length" }]);
        const u = db.users.find((x) => x.id === uidOf);
        if (!u) fail(401, "CS-AUTH-0002", "Invitation not valid");
        u.invitation = "accepted";
        delete db.invites[body.token];
        save();
        return json(200, { account_id: "acct-demo", user_id: u.id });
      }
      // UX-04, served by the server since UXW-38: no session needed. The answer is the
      // same for any address (no enumeration); the address check is the server's.
      if (url.pathname === "/api/v1/auth/password-reset" && method === "POST") {
        for (const k of Object.keys(body || {})) if (k !== "email") fail(400, "CS-API-0001", "Unknown member", [{ pointer: `/${k}`, code: "unknown" }]);
        const email = typeof body?.email === "string" ? body.email.trim() : "";
        if (email.length < 3 || email.length > 320 || !email.includes("@")) fail(422, "CS-API-0001", "Invalid email", [{ pointer: "/email", code: "CS-API-0001" }]);
        return json(202, {});
      }
      let res;
      if (parts[1] === "api" && parts[2] === "v1") res = await staff(method, parts, url.searchParams, headers, body);
      else if (parts[1] === "s") res = await ceremony(method, parts, body, url.searchParams);
      else fail(404, "CS-API-0002", "Not found");
      if (method !== "GET") save();
      return res;
    } catch (e) {
      if (e instanceof Problem) { if (method !== "GET") save(); return problem(e); }
      return problem({ status: 500, code: "CS-API-0010", title: "Internal error" });
    }
  }

  /// This backend also serves the calls api.js lists in `NOT_ON_SERVER` (UX-03).
  handle.ahead = true;
  handle.state = () => db;
  handle.reset = () => { db = null; try { store?.removeItem(KEY); } catch { /* off */ } };
  return handle;
}
