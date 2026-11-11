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
  accessCode: "2468",
};

const KEY = "openseal.mock.v1";
const TERMINAL = new Set(["completed", "declined", "voided", "expired"]);
const SIGNING_TYPES = new Set(["signer", "in_person_signer", "approver"]);
const INPUT_TYPES = new Set(["signature", "initials", "text", "checkbox", "company", "title", "number", "radio_group", "dropdown", "attachment"]);

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

  const save = () => {
    if (!store) return;
    try { store.setItem(KEY, JSON.stringify(db)); } catch { /* full or off: memory only */ }
  };
  async function load() {
    if (db) return;
    if (store) {
      try {
        const s = store.getItem(KEY);
        if (s) { db = JSON.parse(s); db.templates ||= []; db.users ||= []; db.apiClients ||= []; return; }
      } catch { db = null; }
    }
    db = { session: null, envelopes: [], audit: {}, blobs: {}, tokens: {}, opened: [], adoptions: {}, attempts: {}, templates: [], users: [], apiClients: [] };
    await seed();
    save();
  }
  const flag = (name) => { try { return store?.getItem(`openseal.mock.${name}`) === "1"; } catch { return false; } };

  const iso = (offsetMin = 0) => new Date(now().getTime() + offsetMin * 60000).toISOString();

  async function audit(env, type, extra = {}) {
    const list = (db.audit[env.id] ||= []);
    const prev = list.length ? list[list.length - 1].hash : null;
    const event = { type, at: extra.at || iso(), envelope_id: env.id, ...extra };
    delete event.at_override;
    const hash = await sha256hex(JSON.stringify({ prev, event }));
    list.push({ seq: list.length + 1, type, at: event.at, hash, prev, event });
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
    if (!["signer", "cc", "approver", "viewer", "in_person_signer"].includes(type)) fail(400, "CS-API-0001", "Unknown recipient type", [{ pointer: "/type", code: "enum" }]);
    if (r.email && !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(r.email)) fail(400, "CS-API-0001", "Invalid email", [{ pointer: "/email", code: "format" }]);
    const rec = {
      id: uid(), type, routing_order: Number.isInteger(r.routing_order) ? r.routing_order : 1, name: r.name.trim(), email: r.email || "",
      delivery: "email", auth: Array.isArray(r.auth) ? r.auth : [], status: "created", completed_at: null, declined_reason: null,
      consented: false, authenticated: false, auth_passed: [], access_code: r.access_code || null,
    };
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
    const field = { id: uid(), document_id: did, recipient_id: rid, type: String(f.type || "text"), placement: placementOf(f) };
    if (f.required) field.required = true;
    if (f.label) field.label = String(f.label);
    // WEB-06 field kinds: options, validation, a sender's value, locked, read-only.
    if (Array.isArray(f.options)) field.options = f.options.map(String);
    if (f.allow_custom) field.allow_custom = true;
    if (f.validation && typeof f.validation === "object") field.validation = { ...f.validation };
    if (f.value && typeof f.value === "object") field.value = { ...f.value };
    if (f.locked) field.locked = true;
    if (f.read_only) field.read_only = true;
    env.fields.push(field);
    return field;
  }
  function signersAt(env) {
    const pending = env.recipients.filter((r) => SIGNING_TYPES.has(r.type) && r.status !== "completed");
    if (!pending.length) return null;
    return Math.min(...pending.map((r) => r.routing_order));
  }
  function route(env) {
    const order = signersAt(env);
    for (const r of env.recipients) {
      if (SIGNING_TYPES.has(r.type) && r.routing_order === order && r.status === "created") {
        r.status = "sent";
        const token = r.token || `tok-${r.id}`;
        r.token = token;
        db.tokens[token] = { env: env.id, rid: r.id };
      }
    }
    return order;
  }
  async function send(env, at = null) {
    const violations = [];
    if (!env.documents.length) violations.push({ pointer: "/documents", code: "required" });
    const signers = env.recipients.filter((r) => SIGNING_TYPES.has(r.type));
    if (!signers.length) violations.push({ pointer: "/recipients", code: "no_signer" });
    for (const r of env.recipients) if (!r.email) violations.push({ pointer: `/recipients/${r.id}/email`, code: "required" });
    for (const s of signers) if (!env.fields.some((f) => f.recipient_id === s.id)) violations.push({ pointer: `/recipients/${s.id}`, code: "no_fields" });
    if (violations.length) fail(422, "CS-WF-0004", "Envelope invalid for sending", violations);
    env.status = "sent";
    env.sent_at = at || iso();
    env.version++;
    for (const d of env.documents) d.fixed = true;
    await audit(env, "envelope_sent", { actor: "sender", at: env.sent_at });
    route(env);
  }
  function view(env, rec) {
    return {
      envelope: { id: env.id, status: env.status, subject: env.subject, message: env.message, signing_options: env.signing_options, documents: env.documents },
      recipient: publicRecipient(rec),
      fields: env.fields.filter((f) => f.recipient_id === rec.id),
      consent_required: { version: MOCK.ersd, sha256: "0".repeat(64) },
      auth_required: rec.auth.filter((m) => !rec.auth_passed.includes(m)),
    };
  }
  const publicRecipient = (r) => {
    const { access_code, auth_passed, token, ...rest } = r;
    void access_code; void auth_passed; void token;
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
      await audit(env, "envelope_created", { actor: "sender", at: iso(-minutesAgo) });
      addDocument(env, `${subject.split(" ")[0].toLowerCase()}.pdf`, doc(subject));
      const recs = recipients.map((r) => addRecipient(env, r));
      for (const [i, list] of fieldsFor.entries()) for (const f of list) addField(env, { ...f, recipient: recs[i].id, document: env.documents[0].id });
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
    const complete = async (env, recs) => {
      await send(env, iso(-60 * 24 * 2)); // sent two days before it was signed
      let at = -60 * 24 * 2;
      for (const r of recs.filter((x) => SIGNING_TYPES.has(x.type))) {
        at += 60 * 3;
        await audit(env, "recipient_opened", { recipient_id: r.id, actor: "recipient", at: iso(at) });
        at += 20;
        r.status = "completed"; r.completed_at = iso(at); r.consented = true;
        await audit(env, "recipient_completed", { recipient_id: r.id, actor: "recipient", at: iso(at) });
        route(env);
      }
      env.status = "completed"; env.ended_at = iso(at); env.sealed = true; env.version++;
      for (const r of recs) if (r.type === "cc") { r.status = "completed"; r.completed_at = iso(at); }
      await audit(env, "envelope_completed", { actor: "system", at: iso(at) });
      await audit(env, "seal_applied", { actor: "system", profile: "pades-b-t", at: iso(at) });
    };
    await mk("Mutual NDA — Acme and Globex", 60 * 24 * 3,
      [{ name: "Avery Chen", email: "avery@acme.example", routing_order: 1 }, { name: "Sam Patel", email: "sam@globex.example", routing_order: 2 }],
      [sigFields(560), sigFields(640)], complete);
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
      async (env) => { await send(env, iso(-60 * 24 * 6 + 60)); env.status = "voided"; env.void_reason = "Replaced by a new version"; env.ended_at = iso(-60 * 24 * 5); env.version++; await audit(env, "envelope_voided", { actor: "sender", reason: env.void_reason, at: env.ended_at }); });
    await mk("Board consent — November", 60 * 24 * 2,
      [{ name: "Morgan Diaz", email: "morgan@example.com", routing_order: 1 }], [sigFields(600)],
      async (env, recs) => {
        await send(env, iso(-60 * 24 * 2 + 30));
        await audit(env, "recipient_opened", { recipient_id: recs[0].id, actor: "recipient", at: iso(-60 * 25) });
        recs[0].status = "declined"; recs[0].declined_reason = "Wrong meeting date";
        env.status = "declined"; env.ended_at = iso(-60 * 24); env.version++;
        await audit(env, "recipient_declined", { recipient_id: recs[0].id, actor: "recipient", reason: recs[0].declined_reason, at: env.ended_at });
      });

    // Templates (WEB-02): one with a document and fields, one with roles only.
    const nda = newTemplate({ name: "Mutual NDA", email_subject: "Mutual NDA for signature", email_message: "Please review and sign this NDA.", roles: [{ name: "Company", type: "signer", routing_order: 1 }, { name: "Counterparty", type: "signer", routing_order: 2 }, { name: "Legal", type: "cc", routing_order: 3 }] }, iso(-60 * 24 * 10));
    const ndaBytes = doc("Mutual non-disclosure agreement");
    const ndaDoc = { id: uid(), name: "mutual-nda.pdf", pages: 2, bytes: ndaBytes.length };
    db.blobs[ndaDoc.id] = b64(ndaBytes);
    nda.documents.push(ndaDoc);
    for (const [role, y] of [["Company", 560], ["Counterparty", 640]]) {
      for (const f of sigFields(y)) nda.fields.push({ id: uid(), document_id: ndaDoc.id, role, type: f.type, placement: placementOf(f), ...(f.required ? { required: true } : {}) });
    }
    nda.last_used_at = iso(-60 * 24 * 3);
    newTemplate({ name: "Contractor onboarding", email_subject: "Welcome aboard: documents to sign", roles: [{ name: "Contractor", type: "signer", routing_order: 1 }] }, iso(-60 * 24 * 4));

    db.users.push(
      { id: "user-demo", email: MOCK.email, name: "Demo Admin", login_kind: "local", permission_profile_id: "profile-admin", disabled: false },
      { id: uid(), email: "sender@openseal.test", name: "Robin Sender", login_kind: "local", permission_profile_id: "profile-sender", disabled: false },
    );
    db.apiClients.push({ id: uid(), kind: "api_key", name: "CRM integration", owner_user_id: "user-demo", key_prefix: "osk_3f9a12c0", scopes: ["envelopes:read", "envelopes:write", "envelopes:send"], expires_at: null, revoked: false });
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

  async function staff(method, parts, query, headers, body) {
    if (!db.session) fail(401, "CS-AUTH-0001", "Not authenticated");
    if (method !== "GET" && headers["x-csrf-token"] !== db.session.csrf) fail(403, "CS-AUTH-0008", "CSRF token missing or wrong");
    const [, , , res, id, sub, subId, subSub] = parts; // "", api, v1, res, …
    if (res === "auth" && id === "session" && method === "GET") {
      return json(200, { account_id: "acct-demo", user_id: "user-demo", credential: "session", client_id: null, scopes: ["envelopes:read", "envelopes:write", "envelopes:send", "templates:read", "templates:write", "admin:users", "admin:account"], admin: true });
    }
    if (res === "auth" && id === "logout" && method === "POST") { db.session = null; return json(204, null); }
    if (res === "accounts" && id === "me") {
      // Settings and branding (WEB-06 AD-01): `PATCH` merges `name` and `settings`.
      db.account ||= { id: "acct-demo", name: "Demo account", settings: {}, data_region: null, created_at: iso(-60 * 24 * 30) };
      if (method === "PATCH") {
        if (body?.name != null) {
          if (typeof body.name !== "string" || !body.name.trim()) fail(400, "CS-API-0001", "Name required", [{ pointer: "/name", code: "required" }]);
          db.account.name = body.name.trim().slice(0, 255);
        }
        if (body?.settings != null) {
          if (typeof body.settings !== "object" || Array.isArray(body.settings)) fail(400, "CS-API-0001", "Malformed request", [{ pointer: "/settings", code: "type" }]);
          db.account.settings = { ...db.account.settings, ...body.settings };
        }
      } else if (method !== "GET") fail(405, "CS-API-0012", "Method not allowed");
      return json(200, db.account);
    }
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
    if (res === "templates") return templates(method, id, sub, subId, subSub, headers, body);
    if (res === "users") return users(method, id, body, sub);
    if (res === "api-clients") return apiClients(method, id, body);
    if (res !== "envelopes") fail(404, "CS-API-0002", "Not found");

    if (!id) {
      if (method === "GET") {
        const limit = Math.min(Math.max(Number(query.get("limit")) || 50, 1), 200);
        const status = query.get("status");
        const start = Number(query.get("cursor") || 0) || 0;
        // `q` (WEB-04): the subject or a recipient's name or email contains it, any case.
        const text = (query.get("q") || "").trim().toLowerCase();
        const matches = (e) => !text || [e.subject, ...(e.recipients || []).flatMap((r) => [r.name, r.email])].some((v) => (v || "").toLowerCase().includes(text));
        const all = db.envelopes.filter((e) => (!status || e.status === status) && matches(e)).sort((a, b) => b.created_at.localeCompare(a.created_at));
        const page = all.slice(start, start + limit);
        return json(200, {
          items: page.map((e) => ({ id: e.id, status: e.status, subject: e.subject, sender_user_id: e.sender_user_id, created_at: e.created_at })),
          next_cursor: start + limit < all.length ? String(start + limit) : null,
        });
      }
      if (method === "POST") {
        const b = body || {};
        const env = newEnvelope({ subject: b.subject || "", message: b.message || "", signing_options: b.signing_options || {} });
        if (b.reminders) env.reminders = b.reminders;
        if (Number.isInteger(b.expires_in_days)) env.expires_at = iso(b.expires_in_days * 24 * 60);
        const docIds = (b.documents || []).map((d) => addDocument(env, d.name, unb64(d.content_base64 || "")).id);
        const refs = {};
        for (const r of b.recipients || []) { const rec = addRecipient(env, r); if (r.ref) refs[r.ref] = rec.id; }
        for (const f of b.fields || []) addField(env, f, refs, docIds);
        await audit(env, "envelope_created", { actor: "sender" });
        if (b.status === "sent") await send(env);
        return withEtag(env, 201);
      }
    }
    const env = envOr404(id);
    if (!sub) {
      if (method === "GET") return withEtag(env);
      if (method === "PATCH") {
        checkIfMatch(env, headers); draftOnly(env);
        for (const k of ["subject", "message", "signing_options", "reminders"]) if (body && k in body) env[k] = body[k];
        if (body && "expires_in_days" in body) env.expires_at = Number.isInteger(body.expires_in_days) ? iso(body.expires_in_days * 24 * 60) : null;
        env.version++;
        return withEtag(env);
      }
      if (method === "DELETE") {
        // A draft, or an envelope that ended without completing (WEB-06 A-03; today's
        // server deletes drafts only). A completed agreement is never deleted here.
        checkIfMatch(env, headers);
        if (!["draft", "voided", "declined", "expired"].includes(env.status)) fail(409, "CS-WF-0001", "Not allowed in the current state");
        db.envelopes = db.envelopes.filter((e) => e !== env);
        return json(204, null);
      }
    }
    if (sub === "correct" && method === "POST") {
      // `POST …/correct` (docs/40, WEB-06 E-01): the engine's change list, all or none.
      // The mock takes `update_recipient` for a recipient who has not acted yet.
      checkIfMatch(env, headers);
      if (!["sent", "delivered"].includes(env.status)) fail(409, "CS-WF-0001", "Not allowed in the current state");
      const changes = body?.changes;
      if (!Array.isArray(changes) || !changes.length) fail(400, "CS-API-0001", "Malformed request", [{ pointer: "/changes", code: "required" }]);
      const plan = changes.map((c, i) => {
        if (c?.op !== "update_recipient" || !c.recipient?.id) fail(422, "CS-WF-0008", "Unsupported change", [{ pointer: `/changes/${i}/op`, code: "unsupported" }]);
        const r = env.recipients.find((x) => x.id === c.recipient.id);
        if (!r) fail(422, "CS-WF-0008", "Unknown recipient", [{ pointer: `/changes/${i}/recipient/id`, code: "unknown" }]);
        if (["completed", "declined"].includes(r.status)) fail(409, "CS-WF-0001", "Recipient has already acted", [{ pointer: `/changes/${i}/recipient/id`, code: "acted" }]);
        const n = c.recipient;
        if (typeof n.name !== "string" || !n.name.trim()) fail(400, "CS-API-0001", "Recipient name required", [{ pointer: `/changes/${i}/recipient/name`, code: "required" }]);
        if (typeof n.email !== "string" || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(n.email)) fail(400, "CS-API-0001", "Invalid email", [{ pointer: `/changes/${i}/recipient/email`, code: "format" }]);
        const auth = Array.isArray(n.auth) ? n.auth : r.auth;
        if (auth.includes("access_code") && !r.auth.includes("access_code") && !n.access_code) fail(400, "CS-API-0001", "Access code required", [{ pointer: `/changes/${i}/recipient/access_code`, code: "required" }]);
        return [r, { name: n.name.trim(), email: n.email.trim(), auth, access_code: n.access_code || null }];
      });
      for (const [r, n] of plan) {
        r.name = n.name; r.email = n.email; r.auth = n.auth;
        if (n.access_code) { r.access_code = n.access_code; r.auth_passed = []; }
        if (!n.auth.includes("access_code")) r.access_code = null;
      }
      env.version++;
      await audit(env, "envelope_corrected", { actor: "sender", recipient_ids: plan.map(([r]) => r.id) });
      return withEtag(env);
    }
    if (sub === "send" && method === "POST") { draftOnly(env); await send(env); return withEtag(env); }
    if (sub === "void" && method === "POST") {
      if (TERMINAL.has(env.status) || env.status === "draft") fail(409, "CS-WF-0001", "Not allowed in the current state");
      if (!body?.reason) fail(400, "CS-API-0001", "Reason required", [{ pointer: "/reason", code: "required" }]);
      env.status = "voided"; env.void_reason = body.reason; env.ended_at = iso(); env.version++;
      await audit(env, "envelope_voided", { actor: "sender", reason: body.reason });
      return withEtag(env);
    }
    if (sub === "resend" && method === "POST") {
      if (!["sent", "delivered"].includes(env.status)) fail(409, "CS-WF-0001", "Not allowed in the current state");
      const ids = body?.recipient_ids || env.recipients.filter((r) => ["sent", "delivered"].includes(r.status)).map((r) => r.id);
      for (const rid of ids) await audit(env, "notification_resent", { actor: "sender", recipient_id: rid });
      return withEtag(env);
    }
    if (sub === "status" && method === "GET") return json(200, { id: env.id, status: env.status, version: env.version, recipients: env.recipients.map((r) => ({ id: r.id, status: r.status })) });
    if (sub === "audit" && method === "GET") {
      const items = db.audit[env.id] || [];
      return json(200, { items, chain_head: items.length ? items[items.length - 1].hash : null });
    }
    if (sub === "certificate" && method === "GET") {
      if (env.status !== "completed") fail(409, "CS-API-0009", "Not available in the object's state");
      const lines = [`Envelope ${env.id}`, `Subject: ${env.subject}`, ""];
      for (const r of env.recipients) lines.push(`${r.name} <${r.email}> - ${r.type} - ${r.status} ${r.completed_at || ""}`);
      lines.push("", "Mock mode: not a real certificate.");
      return pdf(makePdf([{ title: "Certificate of completion", lines }]));
    }
    if (sub === "documents") {
      if (!subId && method === "POST") { draftOnly(env); const d = addDocument(env, body?.name, unb64(body?.content_base64 || "")); env.version++; return json(201, d); }
      if (!subId && method === "GET") return json(200, { items: env.documents });
      const d = env.documents.find((x) => x.id === subId);
      if (!d) fail(404, "CS-API-0002", "Not found");
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
        env.version++;
        return json(204, null);
      }
    }
    if (sub === "recipients") {
      if (!subId && method === "POST") {
        draftOnly(env);
        const items = body?.items || [body];
        const out = items.map((r) => addRecipient(env, r));
        env.version++;
        return json(201, { items: out.map(publicRecipient) });
      }
      if (!subId && method === "GET") return json(200, { items: env.recipients.map(publicRecipient) });
      const r = env.recipients.find((x) => x.id === subId);
      if (!r) fail(404, "CS-API-0002", "Not found");
      if (method === "PATCH") {
        checkIfMatch(env, headers); draftOnly(env);
        for (const k of ["name", "email", "routing_order", "auth"]) if (body && k in body) r[k] = body[k];
        if (body && "access_code" in body) r.access_code = body.access_code;
        env.version++;
        return json(200, publicRecipient(r));
      }
      if (method === "DELETE") {
        checkIfMatch(env, headers); draftOnly(env);
        if (env.fields.some((f) => f.recipient_id === r.id)) fail(409, "CS-WF-0001", "Recipient still has fields");
        env.recipients = env.recipients.filter((x) => x !== r);
        env.version++;
        return json(204, null);
      }
    }
    if (sub === "fields") {
      if (!subId && method === "POST") {
        draftOnly(env);
        const items = body?.items || [body];
        const out = items.map((f) => addField(env, f));
        env.version++;
        return json(201, { items: out });
      }
      if (!subId && method === "GET") return json(200, { items: env.fields });
      const f = env.fields.find((x) => x.id === subId);
      if (!f) fail(404, "CS-API-0002", "Not found");
      if (method === "PATCH") {
        checkIfMatch(env, headers); draftOnly(env);
        if (body?.placement || body?.page) f.placement = placementOf(body);
        for (const k of ["required", "label", "type"]) if (body && k in body) { if (body[k] === null || body[k] === false || body[k] === "") delete f[k]; else f[k] = body[k]; }
        if (body?.recipient_id) {
          if (!env.recipients.some((r) => r.id === body.recipient_id)) fail(422, "CS-WF-0008", "Unknown recipient");
          f.recipient_id = body.recipient_id;
        }
        env.version++;
        return json(200, f);
      }
      if (method === "DELETE") {
        checkIfMatch(env, headers); draftOnly(env);
        env.fields = env.fields.filter((x) => x !== f);
        env.version++;
        return json(204, null);
      }
    }
    fail(405, "CS-API-0012", "Method not allowed");
  }

  // ---- Templates (WEB-02) ------------------------------------------------------
  // `GET/POST /templates`, `GET/PATCH /templates/{id}` as api/openapi.yaml. Documents
  // and fields of a template are docs/40's slice-3 design ("as envelopes"), ahead of
  // the server: `sessionStorage["openseal.mock.no-template-docs"] = "1"` turns them
  // off, so the browser tests also cover today's server, which keeps roles only.
  const templateDocs = () => !flag("no-template-docs");
  function publicTemplate(tp) {
    // The server's shape (server/…/api/templates.rs): no creation time; the list
    // carries no roles.
    const { documents, fields, created_at: _c, ...rest } = tp;
    return templateDocs() ? { ...rest, documents, fields } : rest;
  }
  function checkRoles(roles) {
    if (roles == null) return [];
    if (!Array.isArray(roles)) fail(400, "CS-API-0001", "Malformed request", [{ pointer: "/roles", code: "type" }]);
    return roles.map((r, i) => {
      if (!r || typeof r.name !== "string" || !r.name.trim()) fail(400, "CS-API-0001", "Role name required", [{ pointer: `/roles/${i}/name`, code: "required" }]);
      if (!["signer", "cc", "approver", "viewer", "in_person_signer"].includes(r.type)) fail(400, "CS-API-0001", "Unknown recipient type", [{ pointer: `/roles/${i}/type`, code: "enum" }]);
      return { id: uid(), name: r.name.trim().slice(0, 255), type: r.type, routing_order: Number.isInteger(r.routing_order) ? r.routing_order : 1 };
    });
  }
  function newTemplate(b, createdAt) {
    if (!b || typeof b.name !== "string" || !b.name.trim()) fail(400, "CS-API-0001", "Template name required", [{ pointer: "/name", code: "required" }]);
    for (const k of Object.keys(b)) if (!["name", "email_subject", "email_message", "roles"].includes(k)) fail(400, "CS-API-0001", "Unknown member", [{ pointer: `/${k}`, code: "unknown" }]);
    const tp = { id: uid(), owner_user_id: "user-demo", name: b.name.trim().slice(0, 255), version: 1, email_subject: b.email_subject || "", email_message: b.email_message || "", roles: checkRoles(b.roles), documents: [], fields: [], created_at: createdAt || iso() };
    db.templates.push(tp);
    return tp;
  }
  function templates(method, id, sub, subId, subSub, headers, body) {
    if (!id) {
      if (method === "GET") {
        const items = [...db.templates].sort((a, b) => b.created_at.localeCompare(a.created_at))
          .map((tp) => ({ id: tp.id, owner_user_id: tp.owner_user_id, name: tp.name, email_subject: tp.email_subject, email_message: tp.email_message, version: tp.version, roles: [], last_used_at: tp.last_used_at || null }));
        return json(200, { items });
      }
      if (method === "POST") { const tp = newTemplate(body); return json(201, publicTemplate(tp), { ETag: `"v${tp.version}"` }); }
    }
    const tp = db.templates.find((x) => x.id === id);
    if (!tp) fail(404, "CS-API-0002", "Not found");
    if (!sub) {
      if (method === "GET") return json(200, publicTemplate(tp), { ETag: `"v${tp.version}"` });
      if (method === "PATCH") {
        const v = headers["if-match"];
        if (!v) fail(428, "CS-API-0008", "Precondition required");
        if (v !== `"v${tp.version}"`) fail(412, "CS-WF-0002", "Stale version");
        // Name, and (WEB-06 T-01) the email subject and message.
        if (!body || (body.name != null && (typeof body.name !== "string" || !body.name.trim())) || (body.name == null && !("email_subject" in body) && !("email_message" in body))) fail(400, "CS-API-0001", "Template name required", [{ pointer: "/name", code: "required" }]);
        if (body.name != null) tp.name = body.name.trim().slice(0, 255);
        for (const k of ["email_subject", "email_message"]) if (k in body) tp[k] = String(body[k] ?? "").slice(0, k === "email_subject" ? 255 : 10000);
        tp.version++;
        return json(200, publicTemplate(tp), { ETag: `"v${tp.version}"` });
      }
      if (method === "DELETE") {
        const v = headers["if-match"];
        if (!v) fail(428, "CS-API-0008", "Precondition required");
        if (v !== `"v${tp.version}"`) fail(412, "CS-WF-0002", "Stale version");
        db.templates = db.templates.filter((x) => x !== tp);
        return json(204, null);
      }
    }
    if (sub === "duplicate" && method === "POST") {
      // `POST /templates/{id}/duplicate` (WEB-06 T-01): a copy named "… (copy)".
      const copy = newTemplate({ name: `${tp.name} (copy)`.slice(0, 255), email_subject: tp.email_subject, email_message: tp.email_message, roles: tp.roles.map(({ name, type, routing_order }) => ({ name, type, routing_order })) });
      const ids = new Map();
      for (const d of tp.documents) { const nd = { ...d, id: uid() }; db.blobs[nd.id] = db.blobs[d.id]; ids.set(d.id, nd.id); copy.documents.push(nd); }
      for (const f of tp.fields) copy.fields.push({ ...f, id: uid(), document_id: ids.get(f.document_id) || f.document_id });
      return json(201, publicTemplate(copy), { ETag: `"v${copy.version}"` });
    }
    if (!templateDocs()) fail(404, "CS-API-0002", "Not found");
    if (sub === "documents") {
      if (!subId && method === "POST") {
        const bytes = unb64(body?.content_base64 || "");
        if (bytes.length < 8 || String.fromCharCode(...bytes.subarray(0, 5)) !== "%PDF-") fail(422, "CS-PDF-0001", "Not a PDF");
        const d = { id: uid(), name: String(body?.name || "document.pdf").slice(0, 255), pages: countPages(bytes), bytes: bytes.length };
        db.blobs[d.id] = b64(bytes);
        tp.documents.push(d);
        tp.version++;
        return json(201, d);
      }
      const d = tp.documents.find((x) => x.id === subId);
      if (!d) fail(404, "CS-API-0002", "Not found");
      if (subSub === "content" && method === "GET") return pdf(unb64(db.blobs[d.id]));
    }
    if (sub === "fields" && !subId && method === "POST") {
      const items = body?.items || [body];
      const out = items.map((f, i) => {
        if (!tp.roles.some((r) => r.name === f?.role)) fail(422, "CS-WF-0008", "Unknown role", [{ pointer: `/items/${i}/role`, code: "unknown" }]);
        if (!tp.documents.some((d) => d.id === f.document_id)) fail(422, "CS-WF-0008", "Unknown document", [{ pointer: `/items/${i}/document_id`, code: "unknown" }]);
        const field = { id: uid(), document_id: f.document_id, role: f.role, type: String(f.type || "text"), placement: placementOf(f.placement || f) };
        if (f.required) field.required = true;
        if (f.label) field.label = String(f.label);
        tp.fields.push(field);
        return field;
      });
      tp.version++;
      return json(201, { items: out });
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
  function users(method, id, body, sub) {
    if (!id && method === "POST" && body?.invite === true) {
      // `POST /users` with `invite: true` (WEB-06 AD-01): a member who sets up their own
      // sign-in from the emailed link; listed as invited until then.
      if (typeof body?.email !== "string" || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(body.email)) fail(400, "CS-API-0001", "Invalid email", [{ pointer: "/email", code: "format" }]);
      if (!["admin", "sender", "viewer"].includes(body.profile)) fail(400, "CS-API-0001", "Unknown profile", [{ pointer: "/profile", code: "enum" }]);
      if (db.users.some((u) => u.email.toLowerCase() === body.email.toLowerCase())) fail(400, "CS-API-0001", "Already a member", [{ pointer: "/email", code: "exists" }]);
      const u = { id: uid(), email: body.email, name: typeof body.name === "string" ? body.name.trim() : "", login_kind: "local", permission_profile_id: `profile-${body.profile}`, disabled: false, invited: true };
      db.users.push(u);
      mintInvite(u);
      return json(201, u);
    }
    if (id && sub === "invite" && method === "POST") {
      const u = db.users.find((x) => x.id === id);
      if (!u) fail(404, "CS-API-0002", "Not found");
      if (!u.invited) fail(409, "CS-WF-0001", "Not allowed in the current state");
      mintInvite(u);
      return json(200, u);
    }
    if (!id) {
      if (method === "GET") return json(200, { items: db.users });
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
    if (method === "GET") return json(200, u);
    if (method === "PATCH") {
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
    if (!sub && method === "GET") return json(200, view(env, rec));
    if (sub === "session" && method === "POST") {
      if (!db.opened.includes(token)) db.opened.push(token);
      if (rec.status === "sent") {
        rec.status = "delivered";
        if (env.status === "sent") env.status = "delivered";
        await audit(env, "recipient_opened", { recipient_id: rec.id });
      }
      return json(200, view(env, rec));
    }
    if (!db.opened.includes(token)) fail(403, "CS-AUTH-0009", "Ceremony link not opened in this browser");
    // WEB-06: the signer's copy (`GET /s/{token}/document`; in the mock the first
    // document) and history stay available after finishing or declining.
    if ((sub === "document" && parts.length === 4) || sub === "history") {
      if (method !== "GET") fail(405, "CS-API-0012", "Method not allowed");
      if (rec.auth.some((m) => !rec.auth_passed.includes(m))) fail(401, "CS-AUTH-0003", "Recipient authentication required");
      if (sub === "history") {
        const mine = (db.audit[env.id] || []).filter((e) => !e.event.recipient_id || e.event.recipient_id === rec.id);
        return json(200, { events: mine.map((e) => ({ seq: e.seq, type: e.type, at: e.at })) });
      }
      // As the server: only after this recipient finished (409 before), `doc` optional
      // for one document; the mock serves the delivered bytes (no preview banner).
      if (rec.status !== "completed") fail(409, "CS-API-0009", "Not available before finishing");
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
        await audit(env, "recipient_auth_failed", { recipient_id: rec.id, method: "access_code" });
        fail(401, "CS-AUTH-0003", "Recipient authentication failed");
      }
      if (!rec.auth_passed.includes("access_code")) rec.auth_passed.push("access_code");
      await audit(env, "recipient_authenticated", { recipient_id: rec.id, method: "access_code" });
      return json(200, view(env, rec));
    }
    if (rec.auth.some((m) => !rec.auth_passed.includes(m))) fail(401, "CS-AUTH-0003", "Recipient authentication required");
    if (sub === "consent" && method === "POST") {
      if (body?.ersd_version !== MOCK.ersd) fail(400, "CS-API-0001", "Unknown disclosure version", [{ pointer: "/ersd_version", code: "mismatch" }]);
      rec.consented = true;
      await audit(env, "recipient_consented", { recipient_id: rec.id, ersd_version: body.ersd_version, ...loc });
      return json(200, view(env, rec));
    }
    if (sub === "decline" && method === "POST") {
      if (env.signing_options?.allow_decline === false) fail(409, "CS-WF-0012", "Decline not allowed");
      rec.status = "declined"; rec.declined_reason = body?.reason || null;
      env.status = "declined"; env.ended_at = iso(); env.version++;
      await audit(env, "recipient_declined", { recipient_id: rec.id, reason: body?.reason || null, ...loc });
      return json(200, view(env, rec));
    }
    if (!rec.consented) fail(403, "CS-AUTH-0005", "Consent required");
    const order = signersAt(env);
    if (rec.routing_order !== order) fail(409, "CS-WF-0007", "Routing has not reached the recipient yet");
    if (sub === "documents") {
      const d = env.documents.find((x) => x.id === parts[4]);
      if (!d) fail(404, "CS-API-0002", "Not found");
      if (parts[5] === "content" && method === "GET") return pdf(unb64(db.blobs[d.id]));
      if (parts[5] === "viewed" && method === "POST") {
        await audit(env, "document_viewed", { recipient_id: rec.id, document_id: d.id, pages_seen: body?.pages_seen || [], ...loc });
        return json(200, view(env, rec));
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
      await audit(env, "signature_adopted", { recipient_id: rec.id, mark: body.mark, method: body.method, image_sha256: await sha256hex(body.image_base64), ...loc });
      return json(200, { ...view(env, rec), adoption_id: id });
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
      await audit(env, "field_filled", { recipient_id: rec.id, field_id: f.id });
      return json(200, view(env, rec));
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
      await audit(env, "field_filled", { recipient_id: rec.id, field_id: f.id });
      return json(200, view(env, rec));
    }
    if (sub === "finish" && method === "POST") {
      const missing = env.fields.filter((f) => f.recipient_id === rec.id && f.required && INPUT_TYPES.has(f.type) && (f.value == null || f.value.text === "" || f.value.choice === "" || f.value.checked === false));
      if (missing.length) fail(422, "CS-WF-0004", "Required fields are empty", missing.map((f) => ({ pointer: `/fields/${f.id}`, code: "required" })));
      for (const f of env.fields) if (f.recipient_id === rec.id && f.type === "date_signed") f.value = { text: iso().slice(0, 10) };
      rec.status = "completed"; rec.completed_at = iso();
      await audit(env, "recipient_completed", { recipient_id: rec.id, ...loc });
      const next = route(env);
      if (next == null) {
        env.status = "completed"; env.ended_at = iso(); env.sealed = true;
        for (const r of env.recipients) if (r.type === "cc") r.status = "completed";
        await audit(env, "envelope_completed");
        await audit(env, "seal_applied", { profile: env.seal_profile });
      }
      env.version++;
      return json(200, view(env, rec));
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
      await audit(env, "recipient_reassigned", { recipient_id: rec.id, new_recipient_id: nr.id, ...loc });
      return json(200, view(env, rec));
    }
    if (sub === "finish-later" && method === "POST") {
      await audit(env, "recipient_finish_later", { recipient_id: rec.id });
      return json(200, view(env, rec));
    }
    fail(405, "CS-API-0012", "Method not allowed");
  }

  async function handle(input, init = {}) {
    // Test hook: `sessionStorage["openseal.mock.offline"] = "1"` makes every call fail as
    // a lost connection does (the e2e offline state).
    let offline = false;
    try { offline = store?.getItem("openseal.mock.offline") === "1"; } catch { offline = false; }
    if (offline) throw new TypeError("Failed to fetch");
    await load();
    const url = new URL(typeof input === "string" ? input : input.url, "http://mock.invalid");
    const method = (init.method || "GET").toUpperCase();
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
        if (typeof body?.token !== "string" || !uidOf) fail(401, "CS-AUTH-0002", "Invitation not valid");
        if (typeof body.password !== "string" || body.password.length < 12) fail(400, "CS-API-0001", "Password too short", [{ pointer: "/password", code: "min_length" }]);
        const u = db.users.find((x) => x.id === uidOf);
        if (!u) fail(401, "CS-AUTH-0002", "Invitation not valid");
        if (typeof body.name === "string" && body.name.trim()) u.name = body.name.trim().slice(0, 255);
        u.invited = false;
        delete db.invites[body.token];
        save();
        return json(200, { email: u.email, name: u.name });
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

  handle.state = () => db;
  handle.reset = () => { db = null; try { store?.removeItem(KEY); } catch { /* off */ } };
  return handle;
}
