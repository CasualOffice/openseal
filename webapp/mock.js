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

import { makePdf, countPages } from "./mockpdf.js";
import { checkText } from "./signfields.js";

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
const INPUT_TYPES = new Set(["signature", "initials", "text", "checkbox", "company", "title", "number", "radio_group", "dropdown", "attachment"]);
const RECIPIENT_TYPES = ["signer", "in_person_signer", "approver", "viewer", "cc", "editor", "intermediary", "agent", "witness", "seal", "notary"];
const FIELD_TYPES = new Set([
  "signature", "initials", "stamp", "date_signed", "name", "first_name", "last_name", "email", "company", "title",
  "envelope_id", "text", "number", "date", "email_address", "phone", "ssn", "zip", "checkbox", "radio_group",
  "dropdown", "multi_select", "formula", "attachment", "note", "approve", "decline", "hyperlink", "payment", "drawing",
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
/// The demo disclosure (ERSD) every mock recipient consents to. Not legal text.
export const MOCK_DISCLOSURE = [
  "Electronic record and signature disclosure (mock mode demo text).",
  "",
  "Demo account will send you agreements electronically. You may ask for a paper copy, and withdraw your consent to",
  "electronic records at any time, from the signing page's Other actions menu or by writing to the sender; withdrawing",
  "declines the agreement. There is no fee. You need a current web browser and a way to keep or print a PDF.",
].join("\n");

let counter = 0;
const uid = () => (typeof crypto !== "undefined" && crypto.randomUUID ? crypto.randomUUID() : `id-${Date.now()}-${++counter}`);

function b64(bytes) {
  let s = "";
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(s);
}
function unb64(s) {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
async function sha256hex(text) {
  const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

class Problem extends Error {
  constructor(status, code, title, errors) {
    super(code);
    this.status = status;
    this.code = code;
    this.title = title;
    this.errors = errors;
  }
}
const fail = (status, code, title, errors) => { throw new Problem(status, code, title, errors); };

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
  const fill = () => { db.templates ||= []; db.users ||= []; db.apiClients ||= []; db.webhooks ||= []; db.deliveries ||= {}; db.folders ||= []; db.ersd ||= []; };
  async function load() {
    ersdSha ||= `sha256:${await sha256hex(MOCK_DISCLOSURE)}`;
    if (db) return;
    if (store) {
      try {
        const s = store.getItem(KEY);
        if (s) { db = JSON.parse(s); fill(); return; }
      } catch { db = null; }
    }
    db = { session: null, envelopes: [], audit: {}, blobs: {}, tokens: {}, opened: [], adoptions: {}, attempts: {}, templates: [], users: [], apiClients: [], webhooks: [], deliveries: {}, folders: [], ersd: [] };
    await seed();
    save();
  }
  const account = () => {
    db.account ||= { id: "acct-demo", name: "Demo account", settings: {}, data_region: null, created_at: iso(-60 * 24 * 30) };
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
    const hash = await sha256hex(JSON.stringify(event));
    list.push({ seq, type, at: when, hash, prev, event });
    notify(env, type);
  }
  const blobHash = (id, salt = "") => sha256hex(`${db.blobs[id] || ""}${salt}`);
  const docHashes = async (env) => Promise.all(env.documents.map(async (d) => ({ document_id: d.id, hash: await blobHash(d.id) })));
  /// A webhook delivery to every active subscription that names the topic (the worker's
  /// `deliver_webhook`; the mock "delivers" at once, answered 200).
  function notify(env, topic) {
    if (!WEBHOOK_EVENTS.includes(topic)) return;
    for (const w of db.webhooks || []) {
      if (!w.active || !w.event_types.includes(topic) || (w.envelope_id && w.envelope_id !== env.id)) continue;
      (db.deliveries[w.id] ||= []).unshift({ id: uid(), event_id: uid(), event_type: topic, status: "delivered", attempts: 1, last_status_code: 200 });
    }
  }

  // ---- Model helpers -----------------------------------------------------------
  function newEnvelope({ subject = "", message = "", signing_options = {}, created_at } = {}) {
    const env = {
      id: uid(), status: "draft", version: 1, sender_user_id: "user-demo", subject, message,
      created_at: created_at || iso(), sent_at: null, ended_at: null, expires_at: null, void_reason: null,
      reminders: {}, signing_options: { ...signing_options }, seal_profile: "pades-b-t",
      documents: [], recipients: [], fields: [], sealed: false,
    };
    db.envelopes.push(env);
    return env;
  }
  function addDocument(env, name, bytes) {
    if (!(bytes instanceof Uint8Array) || bytes.length < 8 || String.fromCharCode(...bytes.subarray(0, 5)) !== "%PDF-") {
      fail(422, "CS-PDF-0001", "Not a PDF");
    }
    const id = uid();
    db.blobs[id] = b64(bytes);
    const doc = { id, name: String(name || "document.pdf").slice(0, 255), pages: countPages(bytes), bytes: bytes.length, upload_sha256: null, delivered_sha256: null, admission_findings: 0, fixed: false };
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
    if (r.delivery != null && !["email", "sms", "none"].includes(r.delivery)) fail(400, "CS-API-0001", "Unknown delivery", [{ pointer: "/delivery", code: "enum" }]);
    const rec = {
      id: r.id || uid(), type, routing_order: Number.isInteger(r.routing_order) ? r.routing_order : 1, name: r.name.trim(), email: r.email || "",
      delivery: r.delivery || "email", auth: Array.isArray(r.auth) ? r.auth : [], status: "created", completed_at: null, declined_reason: null,
      consented: false, authenticated: false, auth_passed: [], access_code: r.access_code || null,
    };
    for (const k of ["phone", "embedded_client_user_id", "date_format", "witness_for"]) if (r[k] != null && r[k] !== "") rec[k] = r[k];
    if (Number.isInteger(r.time_zone_offset_minutes)) rec.time_zone_offset_minutes = r.time_zone_offset_minutes;
    env.recipients.push(rec);
    return rec;
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
  const viewedAll = (env, rec) => env.documents.every((d) => (rec.viewed_to_end || []).includes(d.id));
  /// Required input fields of this recipient left empty refuse finishing or approving.
  function checkRequired(env, rec) {
    const missing = env.fields.filter((f) => f.recipient_id === rec.id && f.required && INPUT_TYPES.has(f.type) && (f.value == null || f.value.text === "" || f.value.choice === "" || f.value.checked === false));
    if (missing.length) fail(422, "CS-WF-0004", "Required fields are empty", missing.map((f) => ({ pointer: `/fields/${f.id}`, code: "required" })));
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
    if (violations.length) fail(422, "CS-WF-0004", "Envelope invalid for sending", violations);
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
      fields: shown ? env.fields.filter((f) => f.recipient_id === rec.id) : [],
      capture_location: !!env.signing_options?.capture_location,
      consent_required: { version: disclosure().version, sha256: disclosure().sha256, url: `/s/${encodeURIComponent(token)}/disclosure` },
      auth_required: rec.auth.filter((m) => !rec.auth_passed.includes(m)),
      sender: { name: sender?.name || "", email: sender?.email || "", organisation: acct.settings?.branding?.name || acct.name },
    };
  }
  const publicRecipient = (r) => {
    const { access_code, auth_passed, token, otp_open, viewed_to_end, hosted, ...rest } = r;
    void access_code; void auth_passed; void token; void otp_open; void viewed_to_end; void hosted;
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
    db.apiClients.push({ id: uid(), kind: "api_key", name: "CRM integration", owner_user_id: "user-demo", key_prefix: "osk_3f9a12c0", scopes: ["envelopes:read", "envelopes:write", "envelopes:send"], expires_at: null, revoked: false });
    // One webhook subscription with a delivered and a failed delivery (UX-03), so the
    // Admin webhooks screen has rows to show.
    const hook = { id: uid(), envelope_id: null, url: "https://hooks.example.com/openseal", event_types: ["envelope.completed", "envelope.declined", "recipient.completed"], secret_refs: ["crm_signing_secret"], active: true };
    db.webhooks.push(hook);
    db.deliveries[hook.id] = [
      { id: uid(), event_id: uid(), event_type: "envelope.declined", status: "failed", attempts: 6, last_status_code: 503 },
      { id: uid(), event_id: uid(), event_type: "envelope.completed", status: "delivered", attempts: 1, last_status_code: 200 },
    ];
  }

  // ---- HTTP plumbing ---------------------------------------------------------
  const json = (status, body, headers = {}) =>
    new Response(body == null ? null : JSON.stringify(body), { status, headers: { "Content-Type": "application/json", ...headers } });
  const problem = (p) =>
    new Response(JSON.stringify({ type: "about:blank", title: p.title || p.code, status: p.status, code: p.code, request_id: `mock-${uid().slice(0, 8)}`, ...(p.errors ? { errors: p.errors } : {}) }),
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
  const SPEC = ["id", "type", "routing_order", "name", "email", "phone", "delivery", "auth", "embedded_client_user_id", "time_zone_offset_minutes", "date_format", "witness_for"];
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
        for (const k of ["phone", "embedded_client_user_id", "date_format", "witness_for", "time_zone_offset_minutes"]) { if (n[k] != null) r[k] = n[k]; else delete r[k]; }
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
      case "set_signing_options": env.signing_options = { ...(c.options || {}) }; changed.push("signing_options"); return;
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
      && inRange(e)).sort(cmp);
    const page = all.slice(start, start + limit);
    return json(200, {
      items: page.map((e) => ({
        id: e.id, status: e.status, subject: e.subject, sender_user_id: e.sender_user_id, created_at: e.created_at,
        updated_at: updatedAt(e), expires_at: e.expires_at,
        // As the server's summary (envelopes.rs list): when it was sent and completed (UX-08).
        sent_at: e.sent_at || null, completed_at: e.status === "completed" ? e.ended_at || null : null,
        ...(e.folder_id ? { folder_id: e.folder_id } : {}), ...(waiting ? { my_recipient_id: myRecipient(e).id } : {}),
      })),
      next_cursor: start + limit < all.length ? String(start + limit) : null,
    });
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

  // ---- Folders (as the server, UXW-02: each member's own) --------------------------------
  function folders(method, id, sub, body) {
    const named = () => {
      const name = typeof body?.name === "string" ? body.name.trim() : "";
      if (!name || name.length > 100) fail(422, "CS-API-0001", "Malformed request", [{ pointer: "/name", code: "CS-API-0001" }]);
      if (db.folders.some((f) => f.id !== id && f.name.toLowerCase() === name.toLowerCase())) fail(422, "CS-API-0001", "Malformed request", [{ pointer: "/name", code: "exists" }]);
      return name;
    };
    const out = (f) => ({ ...f, count: db.envelopes.filter((e) => e.folder_id === f.id && !e.deleted_at).length });
    if (!id) {
      if (method === "GET") return json(200, { items: db.folders.map(out) });
      if (method === "POST") { const f = { id: uid(), name: named() }; db.folders.push(f); return json(201, out(f)); }
    }
    if (sub === "envelopes" && method === "POST") {
      const target = id === "none" ? null : db.folders.find((f) => f.id === id);
      if (target === undefined) fail(404, "CS-API-0002", "Not found");
      const ids = body?.envelope_ids;
      if (!Array.isArray(ids) || !ids.length || ids.length > 200) fail(422, "CS-API-0001", "Malformed request", [{ pointer: "/envelope_ids", code: "CS-API-0001" }]);
      const envs = ids.map((x) => envOr404(x));
      for (const e of envs) { if (target) e.folder_id = target.id; else delete e.folder_id; }
      return json(200, { moved: envs.length });
    }
    const f = db.folders.find((x) => x.id === id);
    if (!f) fail(404, "CS-API-0002", "Not found");
    if (method === "PATCH") { f.name = named(); return json(200, out(f)); }
    if (method === "DELETE") {
      for (const e of db.envelopes) if (e.folder_id === f.id) delete e.folder_id;
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

  async function staff(method, parts, query, headers, body) {
    if (!db.session) fail(401, "CS-AUTH-0001", "Not authenticated");
    if (method !== "GET" && headers["x-csrf-token"] !== db.session.csrf) fail(403, "CS-AUTH-0008", "CSRF token missing or wrong");
    const [, , , res, id, sub, subId, subSub] = parts; // "", api, v1, res, …
    // Workspace switching (ORG-04), as the server: the demo user belongs to two
    // workspaces of one organization. The mock keeps one set of envelopes for both; the
    // server's isolation is tested in server/casual-sign-server/tests/workspaces.rs.
    const spaces = [
      { id: "acct-demo", name: account().name || "Demo workspace", status: "active" },
      { id: "acct-legal", name: "Legal", status: "active" },
    ];
    const here = db.session.account || "acct-demo";
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
      db.session = { csrf: uid(), account: body.account_id };
      return json(200, { account_id: body.account_id, user_id: "user-demo", csrf_token: db.session.csrf, expires_at: iso(60 * 12) });
    }
    if (res === "auth" && id === "session" && method === "GET") {
      return json(200, { account_id: here, user_id: "user-demo", credential: "session", client_id: null, scopes: ["envelopes:read", "envelopes:write", "envelopes:send", "templates:read", "templates:write", "admin:users", "admin:account"], admin: true });
    }
    if (res === "auth" && id === "logout" && method === "POST") { db.session = null; return json(204, null); }
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
        const next = { ...db.account.settings };
        for (const [k, v] of Object.entries(body.settings)) { if (v === null) delete next[k]; else next[k] = v; }
        db.account.settings = next;
        return json(200, { settings: next });
      } else if (method !== "GET") fail(405, "CS-API-0012", "Method not allowed");
      return json(200, here === "acct-demo" ? db.account : { ...db.account, id: here, name: spaces.find((w) => w.id === here)?.name });
    }
    if (res === "ersd-versions" && !id) return ersdVersions(method, body);
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
    if (res === "users" && id === "me" && !sub) return me(method, body);
    if (res === "users") return users(method, id, body, sub);
    if (res === "api-clients") return apiClients(method, id, body);
    if (res === "webhooks") return webhooks(method, id, sub, subId, subSub, body);
    if (res === "folders") return folders(method, id, sub, body);
    if (res !== "envelopes") fail(404, "CS-API-0002", "Not found");

    if (!id) {
      if (method === "GET") return listEnvelopes(query);
      if (method === "POST") {
        const b = body || {};
        const env = newEnvelope({ subject: b.subject || "", message: b.message || "", signing_options: b.signing_options || {} });
        if (b.reminders) env.reminders = b.reminders;
        if (Number.isInteger(b.expires_in_days)) env.expires_at = iso(b.expires_in_days * 24 * 60);
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
        return withEtag(env, 201);
      }
    }
    const env = envOr404(id);
    if (!sub) {
      if (method === "GET") return withEtag(env);
      if (method === "PATCH") {
        checkIfMatch(env, headers); draftOnly(env);
        const changed = [];
        for (const k of ["subject", "message", "signing_options", "reminders"]) if (body && k in body) { env[k] = body[k]; changed.push(k); }
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
    // UX-03, not on the server yet (api.js NOT_ON_SERVER.restoreEnvelope): back to the lists.
    if (sub === "restore" && method === "POST") {
      if (!env.deleted_at) fail(409, "CS-WF-0001", "Not allowed in the current state");
      delete env.deleted_at;
      env.version++;
      // Not a casual-sign-audit type yet: ADR-031 (Proposed) adds it (NOT_ON_SERVER.restoreEnvelope).
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
    if (sub === "void" && method === "POST") {
      if (TERMINAL.has(env.status) || env.status === "draft") fail(409, "CS-WF-0001", "Not allowed in the current state");
      if (!body?.reason) fail(400, "CS-API-0001", "Reason required", [{ pointer: "/reason", code: "required" }]);
      env.status = "voided"; env.void_reason = body.reason; env.ended_at = iso(); env.version++;
      await audit(env, "envelope.voided", { reason: body.reason }, { by: "sender" });
      return withEtag(env);
    }
    if (sub === "resend" && method === "POST") {
      if (!["sent", "delivered"].includes(env.status)) fail(409, "CS-WF-0001", "Not allowed in the current state");
      const ids = body?.recipient_ids || env.recipients.filter((r) => ["sent", "delivered"].includes(r.status)).map((r) => r.id);
      for (const rid of ids) await audit(env, "reminder.sent", { recipient_id: rid, channel: "email" }, { by: "sender" });
      return withEtag(env);
    }
    if (sub === "status" && method === "GET") return json(200, { id: env.id, status: env.status, version: env.version, recipients: env.recipients.map((r) => ({ id: r.id, status: r.status })) });
    if (sub === "audit" && method === "GET") {
      const items = db.audit[env.id] || [];
      return json(200, { items, chain_head: items.length ? items[items.length - 1].hash : null });
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
        draftOnly(env);
        const d = addDocument(env, body?.name, unb64(body?.content_base64 || ""));
        await documentAdded(env, d);
        await edited(env, [`documents.${d.id}`]);
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
        return json(200, { items, truncated: false });
      }
      if (subSub === "content" && method === "GET") {
        if (query.get("version") === "sealed" && !env.sealed) fail(409, "CS-API-0009", "Not available in the object's state");
        // `version=current` (WEB-06 E-02): the document as it stands, fields filled so
        // far. The mock has no flattening, so it is the delivered file.
        if (query.get("version") === "current" && env.status === "draft") fail(409, "CS-API-0009", "Not available in the object's state");
        return pdf(unb64(db.blobs[d.id]));
      }
      if (!subSub && method === "DELETE") {
        checkIfMatch(env, headers); draftOnly(env);
        env.documents = env.documents.filter((x) => x !== d);
        env.fields = env.fields.filter((f) => f.document_id !== d.id);
        await edited(env, [`documents.${d.id}`]);
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
        for (const k of Object.keys(body || {})) if (!["name", "email", "routing_order", "type", "auth", "access_code"].includes(k)) fail(400, "CS-API-0001", "Unknown member", [{ pointer: `/${k}`, code: "unknown" }]);
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
    const { documents, fields, created_at: _c, last_used_at: _l, ...rest } = tp;
    return whole ? { ...rest, documents, fields } : rest;
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
        const items = db.templates.filter((tp) => !!tp.deleted_at === deleted)
          .sort((a, b) => (deleted ? b.deleted_at.localeCompare(a.deleted_at) : b.created_at.localeCompare(a.created_at)))
          .map((tp) => ({ ...publicTemplate(tp, false), roles: tp.roles, last_used_at: tp.last_used_at || null }));
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
        const bytes = unb64(body?.content_base64 || "");
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

  function users(method, id, body, sub) {
    if (!id && method === "POST" && body?.invite === true) {
      // `POST /users` with `invite: true` (WEB-06 AD-01): a member who sets up their own
      // sign-in from the emailed link. As the server: `invitation` (the latest one's
      // state) is on single reads and invites, not on the list; a name is required.
      for (const k of Object.keys(body)) if (!["email", "name", "profile", "password", "invite"].includes(k)) fail(400, "CS-API-0001", "Unknown member", [{ pointer: `/${k}`, code: "unknown" }]);
      if (typeof body.name !== "string" || !body.name.trim()) fail(400, "CS-API-0001", "Name required", [{ pointer: "/name", code: "required" }]);
      if (typeof body?.email !== "string" || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(body.email)) fail(400, "CS-API-0001", "Invalid email", [{ pointer: "/email", code: "format" }]);
      if (!["admin", "sender", "viewer"].includes(body.profile)) fail(400, "CS-API-0001", "Unknown profile", [{ pointer: "/profile", code: "enum" }]);
      if (db.users.some((u) => u.email.toLowerCase() === body.email.toLowerCase())) fail(400, "CS-API-0001", "Already a member", [{ pointer: "/email", code: "exists" }]);
      const u = { id: uid(), email: body.email, name: body.name.trim(), login_kind: "local", permission_profile_id: `profile-${body.profile}`, disabled: false, invitation: "sent" };
      db.users.push(u);
      mintInvite(u);
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
        if (!["admin", "sender", "viewer"].includes(body.profile)) fail(400, "CS-API-0001", "Unknown profile", [{ pointer: "/profile", code: "enum" }]);
        if (body.password != null && (typeof body.password !== "string" || body.password.length < 12)) fail(400, "CS-API-0001", "Password too short", [{ pointer: "/password", code: "min_length" }]);
        const u = { id: uid(), email: body.email, name: body.name.trim(), login_kind: "local", permission_profile_id: `profile-${body.profile}`, disabled: false };
        db.users.push(u);
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
        if (!["admin", "sender", "viewer"].includes(body.profile)) fail(400, "CS-API-0001", "Unknown profile", [{ pointer: "/profile", code: "enum" }]);
        if (u.id === "user-demo" && body.profile !== "admin") fail(400, "CS-API-0001", "Malformed request", [{ pointer: "/profile", code: "self" }]);
        u.permission_profile_id = `profile-${body.profile}`;
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
      return json(204, null);
    }
    fail(405, "CS-API-0012", "Method not allowed");
  }
  function apiClients(method, id, body) {
    if (!id) {
      if (method === "GET") return json(200, { items: db.apiClients });
      if (method === "POST") {
        if (!body || typeof body.name !== "string" || !body.name.trim()) fail(400, "CS-API-0001", "Name required", [{ pointer: "/name", code: "required" }]);
        if (!["api_key", "oauth_app"].includes(body.kind)) fail(400, "CS-API-0001", "Unknown kind", [{ pointer: "/kind", code: "enum" }]);
        if (!Array.isArray(body.scopes) || !body.scopes.length) fail(400, "CS-API-0001", "Scopes required", [{ pointer: "/scopes", code: "required" }]);
        const days = Number.isInteger(body.expires_in_days) ? body.expires_in_days : null;
        const secret = uid().replace(/-/g, "");
        const c = { id: uid(), kind: body.kind, name: body.name.trim(), owner_user_id: body.owner_user_id || null, key_prefix: body.kind === "api_key" ? `osk_${secret.slice(0, 8)}` : null, scopes: body.scopes, expires_at: days ? iso(days * 24 * 60) : null, revoked: false };
        db.apiClients.push(c);
        const shown = body.kind === "api_key" ? { key: `${c.key_prefix}_${secret}` } : { client_id: `osc_${c.id.slice(0, 8)}`, client_secret: secret };
        return json(201, { ...c, ...shown });
      }
    }
    const c = db.apiClients.find((x) => x.id === id);
    if (!c) fail(404, "CS-API-0002", "Not found");
    if (method === "GET") return json(200, c);
    if (method === "DELETE") { c.revoked = true; return json(204, null); }
    fail(405, "CS-API-0012", "Method not allowed");
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
        await audit(env, "recipient.auth_failed", { recipient_id: rec.id, method: "access_code", attempt: n + 1 });
        fail(401, "CS-AUTH-0003", "Recipient authentication failed");
      }
      if (!rec.auth_passed.includes("access_code")) rec.auth_passed.push("access_code");
      await audit(env, "recipient.auth_passed", { recipient_id: rec.id, method: "access_code" });
      return json(200, view(env, rec, token));
    }
    // The emailed one-time code (SEC-A02): "sent" is MOCK.emailCode; a wrong code answers
    // 403 with the view, as the server does; five failures lock.
    if (sub === "otp" && method === "POST") {
      if (!rec.auth.includes("email_otp")) fail(409, "CS-API-0014", "Method not available");
      if (rec.auth_passed.includes("email_otp")) fail(409, "CS-API-0009", "Already authenticated");
      rec.otp_open = true;
      await audit(env, "recipient.auth_challenged", { recipient_id: rec.id, method: "email_otp" });
      return json(202, view(env, rec, token));
    }
    if (sub === "otp" && parts[4] === "verify" && method === "POST") {
      const n = (db.attempts[token] || 0);
      if (n >= 5) fail(423, "CS-AUTH-0004", "Locked after too many attempts");
      if (!rec.auth.includes("email_otp") || !rec.otp_open || body?.code !== MOCK.emailCode) {
        db.attempts[token] = n + 1;
        await audit(env, "recipient.auth_failed", { recipient_id: rec.id, method: "email_otp", attempt: n + 1 });
        return json(403, view(env, rec, token));
      }
      rec.otp_open = false;
      if (!rec.auth_passed.includes("email_otp")) rec.auth_passed.push("email_otp");
      await audit(env, "recipient.auth_passed", { recipient_id: rec.id, method: "email_otp" });
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
      if (!["signature", "initials"].includes(body?.mark) || !["draw", "type", "upload"].includes(body?.method)) fail(400, "CS-API-0001", "Malformed request");
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
      if (f.recipient_id !== rec.id || !INPUT_TYPES.has(f.type) || f.locked || f.read_only) fail(409, "CS-WF-0016", "Field not editable by this recipient");
      const v = body?.value;
      const bad = (code) => fail(422, "CS-WF-0015", "Field value refused", [{ pointer: "/value", code }]);
      if (f.type === "signature" || f.type === "initials") {
        const a = v && db.adoptions[v.signature];
        if (!a || a.rid !== rec.id) fail(409, "CS-WF-0013", "Signature or initials not adopted before use");
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
    if (sub === "finish" && method === "POST") {
      // As the engine's `finish`: an approver approves and a copy has nothing to finish;
      // a viewer finishes once every document was viewed to the end.
      if (rec.type === "approver" || rec.type === "cc") fail(409, "CS-WF-0001", "Not allowed for this recipient");
      if (rec.type === "viewer" && !viewedAll(env, rec)) fail(409, "CS-WF-0014", "Viewer has not viewed every document to the end");
      checkRequired(env, rec);
      for (const f of env.fields) if (f.recipient_id === rec.id && f.type === "date_signed") f.value = { text: iso().slice(0, 10) };
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
    await load();
    const headers = {};
    for (const [k, v] of Object.entries(init.headers || {})) headers[k.toLowerCase()] = v;
    let body = null;
    if (init.body) {
      try { body = JSON.parse(init.body); } catch { return problem({ status: 400, code: "CS-API-0001", title: "Malformed request" }); }
    }
    const parts = url.pathname.split("/");
    try {
      if (url.pathname === "/api/v1/auth/login" && method === "POST") {
        if (body?.email?.toLowerCase() !== MOCK.email || body?.password !== MOCK.password) fail(401, "CS-AUTH-0007", "Invalid credentials");
        db.session = { csrf: uid() };
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
