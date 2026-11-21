// The OpenSeal REST client (WEB-01), over `fetch`, for `api/openapi.yaml` (docs/40).
//
// - Staff calls (`/api/v1/…`) use the session cookie from `POST /api/v1/auth/login`;
//   every changing request carries `X-CSRF-Token` (CS-AUTH-0008 otherwise).
// - Every POST carries a fresh `Idempotency-Key`; edits that need `If-Match` take the
//   envelope's `ETag` (`"v<version>"`).
// - Errors are RFC 9457 problem details; they surface as `ApiError` with the stable
//   `code` (docs/20), and `errorMessage()` gives people a sentence for each code.
// - Ceremony calls (`/s/{token}/…`) carry no CSRF token: they are bound to the
//   browser by the server's HttpOnly, SameSite=Strict cookie.
//
// `createClient({fetch})` takes any fetch-shaped function: the browser's, the mock
// (`mock.js`, `?mock=1`), or a test's. No DOM here, so tests run it under Node.

import { t, has } from "./i18n.js";

/// A problem-details error from the API, a network failure (`code` CS-NET-0001), or a
/// call the server does not serve yet (`CS-NET-0002`, status 501, `detail` the call's
/// name in `NOT_ON_SERVER`). Both `CS-NET` codes are client-side only, never sent by
/// the server.
export class ApiError extends Error {
  constructor({ status = 0, code = "CS-NET-0001", title = "", detail = "", request_id = null, errors = [] } = {}) {
    super(`${code}${title ? `: ${title}` : ""}`);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
    this.title = title;
    this.detail = detail;
    this.requestId = request_id;
    this.errors = Array.isArray(errors) ? errors : [];
  }
}

/// The sentence to show for an error: the code's own message when we have one, else
/// the server's title, always with the code (and request id) so support can find it.
export function errorMessage(err) {
  if (!(err instanceof ApiError)) return t("error.unexpected");
  const key = `error.${err.code}`;
  const base = has(key) ? t(key) : err.title || t("error.unexpected");
  return err.requestId ? `${base} (${err.code}, ${err.requestId})` : `${base} (${err.code})`;
}

/// A Word document's media type: uploads take PDF and Word (.docx, ADR-042).
export const DOCX_TYPE = "application/vnd.openxmlformats-officedocument.wordprocessingml.document";
/// The file pickers' `accept` for a document upload.
export const UPLOAD_ACCEPT = `application/pdf,.pdf,${DOCX_TYPE},.docx`;
/// Whether bytes are a PDF.
export const isPdfBytes = (b) => b.length >= 5 && String.fromCharCode(...b.subarray(0, 5)) === "%PDF-";
/// Whether bytes are a ZIP archive, as a Word document is.
export const isZipBytes = (b) => b.length >= 4 && b[0] === 0x50 && b[1] === 0x4b && b[2] === 3 && b[3] === 4;
/// Whether a picked or dropped file is one a document upload takes (by type or name).
export const isUploadFile = (f) =>
  f.type === "application/pdf" || /\.pdf$/i.test(f.name) || f.type === DOCX_TYPE || /\.docx$/i.test(f.name);
/// A document's name without its file extension (`.pdf` or `.docx`).
export const docBaseName = (name) => String(name || "").replace(/\.(pdf|docx)$/i, "");

const random = () =>
  typeof crypto !== "undefined" && crypto.randomUUID ? crypto.randomUUID() : `${Date.now()}-${Math.random().toString(16).slice(2)}`;

/// Base64 of bytes (for `content_base64` and `image_base64`), chunked so large files
/// do not overflow the argument limit of `String.fromCharCode`.
export function toBase64(bytes) {
  const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let s = "";
  for (let i = 0; i < u8.length; i += 0x8000) s += String.fromCharCode(...u8.subarray(i, i + 0x8000));
  return btoa(s);
}

// ---- Shapes the UI builds (UX-03) ------------------------------------------------------

/// Every recipient type the API takes: the engine's `RecipientType` (docs/22 §5,
/// casual-sign-model `envelope.rs`), in wire spelling.
export const RECIPIENT_TYPES = Object.freeze(["signer", "in_person_signer", "approver", "viewer", "cc", "editor", "intermediary", "agent", "witness", "seal", "notary"]);
/// The types a recipient can complete end to end today: through the ceremony (`signer`,
/// `approver` by `POST /s/{token}/approve`, `viewer` by viewing every document to the
/// end, `in_person_signer` on the link a staff user's `hostInPerson` returns, UXW-36),
/// `agent` naming later recipients by `POST /s/{token}/recipients` then finishing, VS-02),
/// or none (`cc`); the others are the engine's, their ceremony a later slice (editor and
/// intermediary, slice 6; witness 16, seal 18, notary 31).
export const RECIPIENT_TYPES_READY = Object.freeze(["signer", "in_person_signer", "approver", "viewer", "agent", "editor", "intermediary", "cc"]);

/// Every field type the API takes: the engine's `FieldType` (docs/22 §6), in wire spelling.
export const FIELD_TYPES = Object.freeze([
  "signature", "initials", "stamp", "date_signed", "name", "first_name", "last_name", "email", "company", "title",
  "envelope_id", "text", "number", "date", "email_address", "phone", "ssn", "zip", "checkbox", "radio_group",
  "dropdown", "multi_select", "formula", "attachment", "note", "approve", "decline", "hyperlink", "payment", "drawing",
  // FG-080 (ADR-044): an editor's strike-through, placed at the ceremony.
  "strikethrough",
]);
/// The types the ceremony fills or shows and the flattener draws today (docs/40 As built,
/// `WEB-06`); the rest are taken and stored, their signer side a later row.
export const FIELD_TYPES_READY = Object.freeze([
  "signature", "initials", "date_signed", "name", "first_name", "last_name", "email", "company", "title", "text", "number", "checkbox",
  "radio_group", "dropdown", "attachment", "note",
  // VS-04A: every other kind but payment (slice 13).
  "date", "email_address", "phone", "ssn", "zip", "multi_select", "formula", "stamp", "drawing", "envelope_id", "hyperlink", "approve", "decline",
]);

/// The members of a field the API takes besides its place and owner, as the engine's
/// `Field` names them (casual-sign-model `field.rs`): `label` is the data label formulas
/// and conditions refer to; `value` a sender's value (`{text}`, `{checked}`, `{choice}`),
/// with `locked` nobody changes it; `validation` `{kind: email|phone|zip|ssn|regex|length|
/// number|date, …, message?}`; `format` `{font_family, font_size, color, align,
/// date_format, mask, multiline}`; `group` `{id, rule: {rule: select_at_least|…, min|max|count}}`;
/// `conditional` `{parent_label, when: {value: "…"} | "checked" | "unchecked" | "any"}`;
/// `formula` `{expression, precision}`; `options` for radio groups, dropdowns and
/// multi-selects, `allow_custom` for a dropdown.
export const FIELD_MEMBERS = Object.freeze([
  "required", "read_only", "locked", "label", "value", "default", "validation", "format", "group", "conditional",
  "formula", "options", "allow_custom", "tooltip", "placeholder", "shared_with",
]);
const PLACE = ["page", "x", "y", "width", "height"];

const blank = (v) => v == null || v === false || v === "" || (Array.isArray(v) && !v.length);

/// A field as `POST …/fields` (and an envelope's `fields` on create) takes it: the owner
/// as `recipient` (an id, or a `ref` in the same create) and `document` (an id, or an
/// index in the same create), the rectangle flat, and the members of `FIELD_MEMBERS`
/// that are set. Unset, false and empty members are left out, as the server's own
/// output leaves them out. A template field takes `role_id` instead of `recipient`.
export function fieldWire(f) {
  const out = {};
  if (f.role_id != null) out.role_id = f.role_id;
  else if (f.recipient != null || f.recipient_id != null) out.recipient = f.recipient ?? f.recipient_id;
  if (f.document != null || f.document_id != null) out[f.role_id != null ? "document_id" : "document"] = f.document ?? f.document_id;
  out.type = f.type;
  const p = f.placement || f;
  for (const k of PLACE) if (p[k] != null) out[k] = p[k];
  for (const k of FIELD_MEMBERS) if (!blank(f[k])) out[k] = f[k];
  return out;
}

/// A recipient as `POST …/recipients` (and an envelope's `recipients` on create) takes
/// it. `access_code` only with `access_code` among `auth`; `ref` names it for fields in
/// the same create.
export function recipientWire(r) {
  const out = { type: r.type || "signer", name: r.name, email: r.email || "" };
  for (const k of ["ref", "phone", "routing_order", "delivery", "auth", "access_code", "embedded_client_user_id", "time_zone_offset_minutes", "date_format", "route_delay_hours", "excluded_documents", "signature"]) {
    if (!blank(r[k])) out[k] = r[k];
  }
  return out;
}

const newId = () => (typeof crypto !== "undefined" && crypto.randomUUID ? crypto.randomUUID() : null);
const instantOf = (d) => (d instanceof Date ? d.toISOString() : d);
const RECIPIENT_SPEC = ["id", "type", "routing_order", "name", "email", "phone", "delivery", "auth", "embedded_client_user_id", "time_zone_offset_minutes", "date_format", "witness_for", "excluded_documents", "route_delay_hours", "signature"];

/// The engine's `RecipientSpec` from a recipient as the API shows it (or a new one): only
/// the members it has, since it refuses any other (no `status`, no `access_code`; an
/// access code is set by `patchRecipient`).
export function recipientSpec(r) {
  const out = { id: r.id, type: r.type || "signer", routing_order: r.routing_order ?? 1, name: r.name, email: r.email || "" };
  for (const k of RECIPIENT_SPEC) if (!(k in out) && !blank(r[k])) out[k] = r[k];
  return out;
}

/// The engine's `Field` (whole, with its `id`, `document_id`, `recipient_id` and a
/// nested `placement`) from a field as the API shows it, or a new one.
export function fieldSpec(f) {
  const p = f.placement || f;
  const out = { id: f.id, document_id: f.document_id ?? f.document, type: f.type, placement: {} };
  if (f.recipient_id != null || f.recipient != null) out.recipient_id = f.recipient_id ?? f.recipient;
  for (const k of PLACE) out.placement[k] = p[k];
  for (const k of FIELD_MEMBERS) if (!blank(f[k])) out[k] = f[k];
  return out;
}

/// The change list `POST /envelopes/{id}/correct` takes: casual-sign-workflow `Change`,
/// tagged by `op`, applied all or none (docs/24 §6). A correction may change recipients
/// who have not completed, declined or handed over (not their type), their fields,
/// documents (removal only: new ones arrive through `/documents`), subject, message,
/// expiry, reminders and signing options; never the seal profile. New recipients and
/// fields get an id minted here (a UUID, as the server's projection needs).
export const corrections = Object.freeze({
  addRecipient: (r) => ({ op: "add_recipient", recipient: recipientSpec({ ...r, id: r.id || newId() }) }),
  updateRecipient: (r) => ({ op: "update_recipient", recipient: recipientSpec(r) }),
  removeRecipient: (id) => ({ op: "remove_recipient", id }),
  addField: (f) => ({ op: "add_field", field: fieldSpec({ ...f, id: f.id || newId() }) }),
  updateField: (f) => ({ op: "update_field", field: fieldSpec(f) }),
  removeField: (id) => ({ op: "remove_field", id }),
  removeDocument: (id) => ({ op: "remove_document", id }),
  setSubject: (subject) => ({ op: "set_subject", subject }),
  setMessage: (message) => ({ op: "set_message", message }),
  /// A Date or RFC 3339 instant; `null` clears the expiry.
  setExpiry: (at) => ({ op: "set_expiry", expires_at: at == null ? null : instantOf(at) }),
  setReminders: ({ first_after_days = 0, then_every_days = 0 } = {}) => ({ op: "set_reminders", reminders: { first_after_days, then_every_days } }),
  setSigningOptions: (options) => ({ op: "set_signing_options", options }),
});

/// The webhook event types a subscription may name (server `api/webhooks.rs` `EVENT_TYPES`,
/// docs/40 §4).
export const WEBHOOK_EVENT_TYPES = Object.freeze([
  "envelope.sent", "envelope.delivered", "envelope.completed", "envelope.declined", "envelope.voided", "envelope.expired",
  "envelope.corrected", "envelope.purged", "recipient.sent", "recipient.delivered", "recipient.auth_failed",
  "recipient.completed", "recipient.declined", "recipient.reassigned", "recipient.finish_later", "recipient.bounced",
  "template.created", "template.updated", "template.deleted", "bulk_send.completed",
]);

/// Calls the UI may make that the server does not serve yet (UX-03), each with the
/// tracker row that builds it and what it needs.
/// The mock serves them as designed; against a server they fail at once with
/// `CS-NET-0002` (501), so the UI can say "not available yet" instead of hiding the
/// control. `client.available(name)` tells which.
export const NOT_ON_SERVER = Object.freeze({
  clearField: { row: "UXW-35", needs: "DELETE /s/{token}/fields/{field} (a signer removes a value; a new audit type recipient.field_cleared, ADR-032 Proposed)" },
});

/// Make a client. `baseUrl` is prepended to every path ("" = same origin). `store`
/// keeps the CSRF token across reloads of this tab (sessionStorage in the browser).
/// `ahead`: the backend also serves `NOT_ON_SERVER` (the mock says so itself).
export function createClient({ baseUrl = "", fetch: fetchImpl = globalThis.fetch?.bind(globalThis), store = null, ahead = fetchImpl?.ahead === true } = {}) {
  let csrf = null;
  try { csrf = store?.getItem("openseal.csrf") || null; } catch { csrf = null; }
  const setCsrf = (v) => {
    csrf = v;
    try { if (v) store?.setItem("openseal.csrf", v); else store?.removeItem("openseal.csrf"); } catch { /* storage off */ }
  };

  /// VS-09: an embedded view's credentials, kept in memory only. `bearer`: a prepare or
  /// correct view's session (`osv_…`), sent on staff calls instead of the cookie a
  /// cross-site frame does not get; `binding`: an embedded signing view's binding, sent
  /// on ceremony calls in `X-OpenSeal-Binding` for the same reason.
  let bearer = null;
  let binding = null;

  /// Asked when a sensitive call answers `403 CS-AUTH-0013` (ASVS-07): resolves true once
  /// the person has re-authenticated (the call is then made again, once), false or null
  /// when they cancelled (the refusal stands). Set by the app with `setStepUp`.
  let stepUp = null;

  /// Make a call; a sensitive one refused for want of a recent re-authentication asks
  /// `stepUp` and, when it succeeds, is made again with a fresh idempotency key.
  async function request(method, path, opts = {}) {
    try {
      return await send(method, path, opts);
    } catch (err) {
      if (!(err instanceof ApiError) || err.code !== "CS-AUTH-0013" || !stepUp || opts.ceremony) throw err;
      if (!(await stepUp(err))) throw err;
      return send(method, path, opts);
    }
  }

  async function send(method, path, { body, bytes, contentType, query, ifMatch, raw = false, ceremony = false, signal, accept = null } = {}) {
    let url = baseUrl + path;
    if (query) {
      const q = new URLSearchParams();
      for (const [k, v] of Object.entries(query)) if (v != null && v !== "") q.set(k, String(v));
      const s = q.toString();
      if (s) url += `?${s}`;
    }
    const headers = { Accept: accept || (raw ? "application/pdf, application/problem+json" : "application/json") };
    if (body !== undefined) headers["Content-Type"] = "application/json";
    // A file sent as itself (a Word document to convert, ADR-042), not as JSON.
    if (bytes !== undefined) headers["Content-Type"] = contentType || "application/octet-stream";
    if (method !== "GET" && !ceremony && csrf) headers["X-CSRF-Token"] = csrf;
    if (bearer && !ceremony) headers.Authorization = `Bearer ${bearer}`;
    if (binding && ceremony) headers["X-OpenSeal-Binding"] = binding;
    if (method === "POST") headers["Idempotency-Key"] = random();
    if (ifMatch) headers["If-Match"] = ifMatch;
    let res;
    try {
      res = await fetchImpl(url, {
        method,
        headers,
        body: bytes !== undefined ? bytes : body === undefined ? undefined : JSON.stringify(body),
        credentials: baseUrl ? "include" : "same-origin",
        ...(signal ? { signal } : {}),
      });
    } catch (err) {
      if (signal?.aborted || err?.name === "AbortError") throw err;
      throw new ApiError({ code: "CS-NET-0001", title: "Network error" });
    }
    if (!res.ok) {
      let problem = {};
      try { problem = await res.json(); } catch { problem = {}; }
      throw new ApiError({
        status: res.status,
        code: typeof problem.code === "string" ? problem.code : `HTTP-${res.status}`,
        title: typeof problem.title === "string" ? problem.title : "",
        detail: typeof problem.detail === "string" ? problem.detail : "",
        request_id: typeof problem.request_id === "string" ? problem.request_id : null,
        errors: problem.errors,
      });
    }
    if (raw) return { blob: await res.blob(), etag: res.headers.get("ETag"), next: res.headers.get("X-Next-Cursor"), truncated: res.headers.get("X-Truncated") === "true" };
    if (res.status === 204) return { data: null, etag: res.headers.get("ETag") };
    const text = await res.text();
    return { data: text ? JSON.parse(text) : null, etag: res.headers.get("ETag") };
  }

  const data = async (p) => (await p).data;
  const E = (id) => `/api/v1/envelopes/${encodeURIComponent(id)}`;
  const S = (token) => `/s/${encodeURIComponent(token)}`;
  const T = (tp) => `/api/v1/templates/${encodeURIComponent(tp)}`;
  const etagOf = (env) => (env && Number.isInteger(env.version) ? `"v${env.version}"` : null);
  const W = (w) => `/api/v1/webhooks/${encodeURIComponent(w)}`;
  const F = (f) => `/api/v1/folders/${encodeURIComponent(f)}`;
  const available = (name) => ahead || !Object.hasOwn(NOT_ON_SERVER, name);
  /// A call in `NOT_ON_SERVER`: made when the backend serves it, else refused here.
  const unbuilt = (name, call) => (...args) => (available(name)
    ? call(...args)
    : Promise.reject(new ApiError({ status: 501, code: "CS-NET-0002", title: "Not available on this server yet", detail: name })));
  const list = (query) => data(request("GET", "/api/v1/envelopes", { query }));

  return {
    request,
    hasCsrf: () => !!csrf,
    /// VS-09: act as an embedded prepare or correct view's session (null: stop).
    setBearer(v) { bearer = typeof v === "string" && v ? v : null; },
    /// VS-09: the binding an embedded signing view's first answer carried.
    setBinding(v) { binding = typeof v === "string" && v ? v : null; },
    /// Set what asks the person to re-authenticate before a sensitive call (ASVS-07):
    /// `async (err) => boolean`; null turns it off.
    setStepUp(fn) { stepUp = typeof fn === "function" ? fn : null; },
    /// Whether a call of `NOT_ON_SERVER` (by its name there) works on this backend.
    available,

    // ---- Session -----------------------------------------------------------
    async login(email, password) {
      const r = await data(request("POST", "/api/v1/auth/login", { body: { email, password } }));
      setCsrf(r?.csrf_token || null);
      return r;
    },
    async logout() {
      try { await request("POST", "/api/v1/auth/logout"); } finally { setCsrf(null); }
    },
    session: () => data(request("GET", "/api/v1/auth/session")),
    /// The signed-in person's workspaces (ORG-04, docs/23 §2.3): `{current,
    /// organizations: [{id, name, workspaces: [{id, name, status, current}]}]}`.
    workspaces: () => data(request("GET", "/api/v1/auth/workspaces")),
    /// Move this session to another of the person's workspaces: the server ends this
    /// session and sets a new cookie; the new CSRF token replaces the old one.
    async switchWorkspace(accountId) {
      const r = await data(request("POST", "/api/v1/auth/switch", { body: { account_id: accountId } }));
      setCsrf(r?.csrf_token || null);
      return r;
    },
    account: () => data(request("GET", "/api/v1/accounts/me")),
    /// The signed-in user's own profile (UX-04, UXW-37): `{id, name, email,
    /// notifications: {completed, declined, viewed}, signature, initials}`, the marks as
    /// `{image_base64}` or null.
    me: () => data(request("GET", "/api/v1/users/me")),
    /// Change one's own profile: `{name?, notifications?, signature?, initials?,
    /// password?, current_password?}` (a new password needs the current one, `401
    /// CS-AUTH-0007` when wrong, and ends the user's other sessions).
    patchMe: (body) => data(request("PATCH", "/api/v1/users/me", { body })),
    /// The person's own data in this workspace as one JSON document (ASVS-16):
    /// `{format: "openseal.personal-data-export", v, exported_at, workspace, user, …}`.
    /// At most three a minute (`429`).
    exportMe: () => data(request("GET", "/api/v1/users/me/export")),
    /// Erase one's own identity in this workspace (ASVS-16; needs a recent
    /// re-authentication). `409 CS-API-0018` for the last administrator or an
    /// organization administrator; `403 CS-API-0015` for a member of another workspace.
    eraseMe: () => data(request("DELETE", "/api/v1/users/me")),
    /// An administrator erases a member's identity (ASVS-16; recent re-authentication).
    eraseUser: (id) => data(request("POST", `/api/v1/users/${encodeURIComponent(id)}/erase`)),
    /// The account's retention rules (ASVS-18): `{keep_days: {draft, ended, completed,
    /// sessions}, max_keep_days}`, each days or null (kept for ever).
    retention: () => data(request("GET", "/api/v1/retention")),
    /// Set or remove rules: `{draft?: days|null, …}` (recent re-authentication).
    setRetention: (keepDays) => data(request("PUT", "/api/v1/retention", { body: { keep_days: keepDays } })),
    /// The retention job's dry run: `{at, counts, sessions, held, envelopes}`.
    retentionPreview: () => data(request("GET", "/api/v1/retention/preview")),
    /// Place or release an envelope's legal hold (ASVS-18).
    setLegalHold: (id, hold) => data(request(hold ? "PUT" : "DELETE", `/api/v1/envelopes/${encodeURIComponent(id)}/legal-hold`)),
    /// Ask for a password-reset email (UX-04, UXW-38); no session. `202 {}` whether or
    /// not the address has an account.
    requestPasswordReset: (email) => data(request("POST", "/api/v1/auth/password-reset", { body: { email } })),
    /// The SSO identity providers this server offers on sign-in (UX-04, UXW-39):
    /// `{items: [{id, name, url}]}`, empty until SSO exists (FG-173); no session.
    authProviders: () => data(request("GET", "/api/v1/auth/providers")),
    /// Pass the session's second factor (ASVS-01): `{code}` from the authenticator, or
    /// `{recovery_code}`; `401 CS-AUTH-0012` when wrong or already used.
    verifySecondFactor: (body) => data(request("POST", "/api/v1/auth/mfa/verify", { body })),
    /// Prove the password again before a sensitive action (ASVS-07): `{password, code?}`
    /// or `{password, recovery_code?}`; `{reauthenticated_until}`. `401 CS-AUTH-0007`
    /// for a wrong password, `401 CS-AUTH-0012` for a wrong code, `422` (`/code`) when the
    /// person has a second factor and sent no code. Never itself asks `stepUp`.
    reauthenticate: (body) => data(send("POST", "/api/v1/auth/reauthenticate", { body })),
    /// The person's own live sessions in every workspace (ASVS-06): `{items: [{id,
    /// workspace: {id, name}, method, client, created_at, last_seen_at, idle_expires_at,
    /// expires_at, current}]}`.
    sessions: () => data(request("GET", "/api/v1/auth/sessions")),
    /// End one of the person's other sessions (needs a recent re-authentication).
    endSession: (id) => data(request("DELETE", `/api/v1/auth/sessions/${encodeURIComponent(id)}`)),
    /// End every other session of the person: `{ended}` (needs a recent re-authentication).
    endOtherSessions: () => data(request("POST", "/api/v1/auth/sessions/end-others")),
    /// Start TOTP enrolment: `{otpauth_uri, secret}`, shown once.
    enrolTotp: () => data(request("POST", "/api/v1/auth/mfa/totp/enrol")),
    /// Confirm enrolment with a first code: `{second_factor, recovery_codes}`, shown once.
    confirmTotp: (code) => data(request("POST", "/api/v1/auth/mfa/totp/confirm", { body: { code } })),
    /// Passkeys (CON-13): the options for one ceremony, `purpose` `register`, `verify`
    /// or `reauthenticate`: `{purpose, public_key}` (binary members base64url).
    passkeyOptions: (purpose) => data(request("POST", "/api/v1/auth/mfa/passkeys/options", { body: { purpose } })),
    /// Register a passkey (passkey.js `registrationBody`): `{passkey, second_factor,
    /// recovery_codes?}` (the codes when it is the person's first factor, shown once).
    registerPasskey: (body) => data(request("POST", "/api/v1/auth/mfa/passkeys", { body })),
    /// The person's passkeys: `{items: [{id, name, created_at, last_used_at, backup_eligible}]}`.
    passkeys: () => data(request("GET", "/api/v1/auth/mfa/passkeys")),
    /// Rename or remove one (each needs a recent re-authentication).
    renamePasskey: (id, name) => data(request("PATCH", `/api/v1/auth/mfa/passkeys/${encodeURIComponent(id)}`, { body: { name } })),
    removePasskey: (id) => data(request("DELETE", `/api/v1/auth/mfa/passkeys/${encodeURIComponent(id)}`)),
    /// Remove the authenticator app, to set up another (needs a recent re-authentication).
    removeTotp: () => data(request("DELETE", "/api/v1/auth/mfa/totp")),
    /// Ten new recovery codes, replacing the earlier ones: `{recovery_codes}`, shown once.
    replaceRecoveryCodes: () => data(request("POST", "/api/v1/auth/mfa/recovery-codes")),

    // ---- Envelopes ---------------------------------------------------------
    /// `q`: text the subject or a recipient's name or email contains (WEB-04).
    /// WEB-08: `status` one status or an array of them (any of); `sort` one of
    /// `created_at`, `updated_at` (last change), `expires_at`, `subject`, `status`, with
    /// `order` `asc` or `desc` (the server's default when left out); `sender` a user id
    /// or `"me"`; `from`/`to` a last-change range (Date or RFC 3339; `to` exclusive).
    /// A `cursor` is only valid with the sort and order it came with.
    /// UXW-02/03: `recipient` (a recipient's email or name contains it), `date_field`
    /// (which date `from`/`to` bound: `updated_at`, the default, `created_at`,
    /// `sent_at`, `completed_at`), `folder` (one of the user's folder ids) and
    /// `deleted: true` (the Deleted view).
    /// VS-06: `auth_failed: true` (the Authentication failed quick view), `expires_before`
    /// (Date or RFC 3339), `custom_field` (a custom field's exact name) with
    /// `custom_value` (text its value contains).
    listEnvelopes: ({ status, cursor, limit = 25, q, sort, order, sender, from, to, recipient, date_field, folder, deleted, auth_failed, expires_before, custom_field, custom_value } = {}) => {
      const query = {
        status: Array.isArray(status) ? status.join(",") : status,
        cursor, limit, q, sort, order, sender, from: instantOf(from), to: instantOf(to),
      };
      for (const [k, v] of Object.entries({ recipient, date_field, folder, deleted: deleted ? "true" : null, auth_failed: auth_failed ? "true" : null, expires_before: instantOf(expires_before), custom_field, custom_value: custom_field ? custom_value : null })) {
        if (!blank(v)) query[k] = v;
      }
      return list(query);
    },
    /// Envelopes waiting for the signed-in user to sign, approve or view (the Inbox,
    /// UXW-01): `{items, next_cursor}` as `listEnvelopes`, each item with
    /// `my_recipient_id`, the recipient the user is.
    inbox: ({ cursor, limit = 25 } = {}) => list({ waiting_for: "me", cursor, limit }),
    /// The signing page for the signed-in user on an Inbox envelope, `{url}` (UXW-01);
    /// 409 `CS-WF-0007` before routing reaches them.
    signLink: (id) => data(request("POST", `${E(id)}/sign-link`)),
    /// `{envelope, etag}`; the ETag falls back to the version when a proxy drops it.
    async getEnvelope(id) {
      const r = await request("GET", E(id));
      return { envelope: r.data, etag: r.etag || etagOf(r.data) };
    },
    createEnvelope: (body) => data(request("POST", "/api/v1/envelopes", { body })),
    /// The envelope's custom fields `{items: [{name, value}]}` (VS-06, FG-139): sender
    /// metadata, searchable, never part of the agreement.
    customFields: (id) => data(request("GET", `${E(id)}/custom-fields`)),
    /// Pass the envelope to another member of this workspace (ORG-09, ORG-41): answers
    /// the envelope with its new `sender_user_id`; `envelopes.transfer` on the server.
    transferEnvelope: (id, etag, toUser) => data(request("POST", `${E(id)}/transfer`, { body: { to_user: toUser }, ifMatch: etag })),
    /// Replace them; answers them as stored.
    setCustomFields: (id, items) => data(request("PUT", `${E(id)}/custom-fields`, { body: { items } })),
    patchEnvelope: (id, etag, body) => data(request("PATCH", E(id), { body, ifMatch: etag })),
    deleteEnvelope: (id, etag) => data(request("DELETE", E(id), { ifMatch: etag })),
    /// Bring a deleted envelope back to the lists (ADR-031, recorded as
    /// `envelope.restored`); answers the envelope. `etag` is checked when given.
    restoreEnvelope: (id, etag) => data(request("POST", `${E(id)}/restore`, { ifMatch: etag || undefined })),
    sendEnvelope: (id) => data(request("POST", `${E(id)}/send`)),
    /// Schedule a sendable draft to send itself at `sendAt` (an ISO instant, WF-02);
    /// answers the draft with `send_at`. A scheduled draft is not edited (`CS-WF-0022`).
    scheduleSend: (id, sendAt) => data(request("PUT", `${E(id)}/schedule`, { body: { send_at: sendAt } })),
    /// Cancel a draft's schedule (WF-02); answers the draft.
    unscheduleSend: (id) => data(request("DELETE", `${E(id)}/schedule`)),
    voidEnvelope: (id, reason) => data(request("POST", `${E(id)}/void`, { body: { reason } })),
    resend: (id, recipientIds) => data(request("POST", `${E(id)}/resend`, { body: recipientIds ? { recipient_ids: recipientIds } : {} })),
    status: (id) => data(request("GET", `${E(id)}/status`)),
    /// `{items: [{seq, type, at, hash, prev, event}], chain_head}`: `type` the dotted
    /// audit type (`recipient.delivered`), `event` the whole event of docs/32 §2 with
    /// `actor {kind, id?, name?}` and `data` (its `recipient_id`, …); `seq` from 0.
    audit: (id) => data(request("GET", `${E(id)}/audit`)),
    /// The certificate of completion of a completed envelope; of a declined, voided or
    /// expired one, the envelope certificate saying how it ended (UXW-30; 409 until the
    /// worker has made it).
    certificate: async (id) => (await request("GET", `${E(id)}/certificate`, { raw: true })).blob,
    /// One ZIP with everything that proves the agreement (VS-06D): each document as
    /// sealed or as it ended, the certificate, the audit trail and a manifest of SHA-256s.
    /// Recorded on the server as `envelope.exported`; an envelope still in flight is 409.
    evidencePackage: async (id) => (await request("GET", `${E(id)}/evidence-package`, { raw: true })).blob,
    /// The anchor proof of the envelope's latest anchored chain head (`FG-158`), as a
    /// Blob of `openseal.anchor-proof` JSON; null while nothing is anchored (`404
    /// CS-API-0017`). Other refusals throw.
    anchorProof: async (id) => {
      try {
        return (await request("GET", `${E(id)}/anchor-proof`, { raw: true, accept: "application/json, application/problem+json" })).blob;
      } catch (e) {
        if (e instanceof ApiError && e.code === "CS-API-0017") return null;
        throw e;
      }
    },
    /// WEB-08: a signer's attachment by the SHA-256 its field's value names (recorded
    /// in the audit trail as `attachment.downloaded`).
    attachment: async (id, sha256) =>
      (await request("GET", `${E(id)}/attachments/${encodeURIComponent(sha256)}`, { raw: true })).blob,
    documentContent: async (id, doc, version = "normalized") =>
      (await request("GET", `${E(id)}/documents/${encodeURIComponent(doc)}/content`, { raw: true, query: { version } })).blob,
    addDocument: (id, name, bytes) => data(request("POST", `${E(id)}/documents`, { body: { name, content_base64: toBase64(bytes) } })),
    /// A Word document (.docx) converted to PDF and admitted as its upload would be,
    /// nothing stored (ADR-042): the editor's preview while fields are placed. Answers
    /// the PDF's bytes; the upload itself sends the .docx, kept as the original.
    convertDocument: async (bytes) =>
      new Uint8Array(await (await request("POST", "/api/v1/conversions", { bytes, contentType: DOCX_TYPE, raw: true })).blob.arrayBuffer()),
    /// Remove a document and its fields: a draft's edit, or a sent envelope's correction
    /// (who finished on it acts again, docs/24 §6).
    deleteDocument: (id, doc, etag) => data(request("DELETE", `${E(id)}/documents/${encodeURIComponent(doc)}`, { ifMatch: etag })),
    addRecipients: (id, items) => data(request("POST", `${E(id)}/recipients`, { body: { items } })),
    patchRecipient: (id, r, etag, body) => data(request("PATCH", `${E(id)}/recipients/${encodeURIComponent(r)}`, { body, ifMatch: etag })),
    deleteRecipient: (id, r, etag) => data(request("DELETE", `${E(id)}/recipients/${encodeURIComponent(r)}`, { ifMatch: etag })),
    addFields: (id, items) => data(request("POST", `${E(id)}/fields`, { body: { items } })),
    patchField: (id, f, etag, body) => data(request("PATCH", `${E(id)}/fields/${encodeURIComponent(f)}`, { body, ifMatch: etag })),
    deleteField: (id, f, etag) => data(request("DELETE", `${E(id)}/fields/${encodeURIComponent(f)}`, { ifMatch: etag })),

    /// How many envelopes have `status`, counting at most `cap` (one page of the list;
    /// the API has no count). `{n, more}`: `more` when the list goes on past `cap`.
    async countEnvelopes(status, cap = 200) {
      const page = await data(request("GET", "/api/v1/envelopes", { query: { status, limit: cap } }));
      return { n: (page?.items || []).length, more: !!page?.next_cursor };
    },

    // ---- Correct, preview, detection, contacts (WEB-06 server) ----------------
    /// `POST …/correct {changes}` (If-Match): the engine's change list (casual-sign-workflow
    /// `Change`, tagged by `op`, built with `corrections`), all or none. The per-element
    /// recipient and field calls (`addRecipients`, `deleteRecipient`, `addFields`, …)
    /// correct a sent envelope too, one change each. `update_recipient` replaces the whole
    /// `RecipientSpec`, which refuses unknown members (so no `access_code`), and the API
    /// does not show every member of it (`date_format`); a correction of one recipient's
    /// name, email or access code is therefore `patchRecipient`, which keeps the rest and
    /// stores the code (it corrects a sent envelope as this does).
    correctEnvelope: (id, etag, changes) => data(request("POST", `${E(id)}/correct`, { body: { changes }, ifMatch: etag })),
    /// The document as it stands: sealed once sealed, else a "not signed" preview.
    currentDocument: async (id, doc) =>
      (await request("GET", `${E(id)}/documents/${encodeURIComponent(doc)}/content`, { raw: true, query: { version: "current" } })).blob,
    /// Suggested fields `{items: [{document_id, type, page, x, y, width, height, source,
    /// cue?, confidence}], truncated}`; nothing is changed or recorded on the server.
    detectFields: (id, doc) => data(request("POST", `${E(id)}/documents/${encodeURIComponent(doc)}/detect-fields`)),
    /// Past recipients for autocomplete, `{items: [{name, email, last_used_at}]}`, most
    /// recently used first; `limit` 1 to 50.
    contacts: (q, limit = 10) => data(request("GET", "/api/v1/contacts", { query: { q, limit } })),
    listContacts: ({ q, limit = 10 } = {}) => data(request("GET", "/api/v1/contacts", { query: { q, limit } })),
    /// A staff user hosts an in-person signer (UXW-36): answers `{url, expires_at}`, a
    /// one-time signing page to open on this device, acting as this user hosting them.
    hostInPerson: (id, r) => data(request("POST", `${E(id)}/recipients/${encodeURIComponent(r)}/host`)),

    // ---- Document intelligence (docs/33 §6; WEB-18, served since WEB-19) -------
    // With no feature in effect the server answers `403 CS-ML-0011` (and a server
    // without the routes 404); `ml.js` reads either as "unavailable" and every ML
    // surface hides.
    /// The workspace's model features, `{ocr, template_matching, extraction,
    /// personal_data, personal_data_model?, ocr_scripts?, reread_scanner_text?,
    /// not_in_plan?: [feature], installed?: false}`. Workspace admin only.
    getMlSettings: () => data(request("GET", "/api/v1/account/settings/ml")),
    /// Turn features on or off: `{ocr?, template_matching?, extraction?, personal_data?, …}`;
    /// a feature the plan lacks is refused with `403 CS-ML-0011`. Answers the settings.
    patchMlSettings: (body) => data(request("PATCH", "/api/v1/account/settings/ml", { body })),
    /// Ask for a draft's document to be analysed (idempotent): `202 {id, document_id,
    /// status: queued|running|done|failed|unavailable, uses: [ocr|template|entities|
    /// personal_data], ocr_pages, truncated, bundle_id}`.
    requestAnalysis: (id, doc) => data(request("POST", `${E(id)}/documents/${encodeURIComponent(doc)}/analysis`)),
    /// The newest run, as `requestAnalysis` answers it; `ocr_pages` are 1-based.
    getAnalysis: (id, doc) => data(request("GET", `${E(id)}/documents/${encodeURIComponent(doc)}/analysis`)),
    /// `{items: [{id, kind: template|entity|personal_data, document_id, page?, rect?, label,
    /// value?, normalized?, score, model: {id, sha256}, state: open|accepted|dismissed,
    /// template_id?, pages_matched?, pages_total?}], next_cursor}`; `kind` and `state`
    /// filter, `limit` 1 to 200.
    listSuggestions: (id, { kind, state, cursor, limit } = {}) => data(request("GET", `${E(id)}/suggestions`, { query: { kind, state, cursor, limit } })),
    /// Record that a person accepted a suggestion (`decided_by`, `decided_at`); the action
    /// itself is the caller's own edit through the ordinary endpoints (docs/33 §6).
    /// `409 CS-ML-0012` when already decided or its document left the envelope.
    acceptSuggestion: (id, s) => data(request("POST", `${E(id)}/suggestions/${encodeURIComponent(s)}/accept`)),
    dismissSuggestion: (id, s) => data(request("POST", `${E(id)}/suggestions/${encodeURIComponent(s)}/dismiss`)),
    /// Search agreements by meaning (`ML-07B`, planned in docs/33 §6, `WEB-19`): `{items:
    /// [{envelope_id, document_id, subject, page, snippet: [{text, mark?}], score}]}`.
    /// `signal` aborts a stale search.
    searchByMeaning: (q, { signal, limit } = {}) => data(request("GET", "/api/v1/search", { query: { q, mode: "meaning", limit }, signal })),

    // ---- Folders (UXW-02: each member's own) ---------------------------------
    /// The signed-in user's folders, `{items: [{id, name, kind, count}]}`; `kind`
    /// `templates` lists their template folders (TSH-03).
    listFolders: (kind) => data(request("GET", "/api/v1/folders", kind && kind !== "envelopes" ? { query: { kind } } : {})),
    createFolder: (name, kind) => data(request("POST", "/api/v1/folders", { body: kind && kind !== "envelopes" ? { name, kind } : { name } })),
    renameFolder: (f, name) => data(request("PATCH", F(f), { body: { name } })),
    /// Remove a folder; its envelopes go back to no folder.
    deleteFolder: (f) => data(request("DELETE", F(f))),
    /// File envelopes in a folder (`null`: in none).
    moveEnvelopes: (f, envelopeIds) =>
      data(request("POST", f == null ? "/api/v1/folders/none/envelopes" : `${F(f)}/envelopes`, { body: { envelope_ids: envelopeIds } })),
    /// File templates in a template folder (`null`: in none; TSH-03).
    moveTemplates: (f, templateIds) =>
      data(request("POST", f == null ? "/api/v1/folders/none/templates" : `${F(f)}/templates`, { body: { template_ids: templateIds } })),

    // ---- Bulk send from a template (UXW-04; bulkmodel.js) ------------------------
    bulk: {
      /// The caller's bulk sends, newest first: `{items: [{id, name, template_id,
      /// status: queued|sending|completed|cancelled, row_count, counts: {pending, sent,
      /// failed, cancelled}, created_at, finished_at}]}`.
      list: () => data(request("GET", "/api/v1/bulk-sends")),
      /// Check a list (`{csv}` text or `{rows}` of column → value) against a template;
      /// nothing stored: `{columns, row_count, valid, rows: [{row, status, recipients:
      /// [{role, name, email}], problems: [{column, code}]}]}`. A list whose columns do
      /// not fit is `422` with `errors` (`CS-BLK-0004`, `0005`, `0007`).
      check: (templateId, list) => data(request("POST", "/api/v1/bulk-sends", { body: { template_id: templateId, ...list, validate_only: true } })),
      /// Make the batch (`queued`): as `list`'s item, with `rows` (a row with problems is
      /// `failed` and never sent).
      create: (templateId, list, name) => data(request("POST", "/api/v1/bulk-sends", { body: { template_id: templateId, ...list, ...(name ? { name } : {}) } })),
      get: (id) => data(request("GET", `/api/v1/bulk-sends/${encodeURIComponent(id)}`)),
      /// Send the next rows (at most 10); repeat while `counts.pending` > 0.
      send: (id) => data(request("POST", `/api/v1/bulk-sends/${encodeURIComponent(id)}/send`)),
      /// Stop: the pending rows are not sent.
      cancel: (id) => data(request("POST", `/api/v1/bulk-sends/${encodeURIComponent(id)}/cancel`)),
    },

    // ---- Signing providers (RSP-01, ADR-046) ------------------------------------
    /// `{items: [{id, name, kind, enabled}]}`: the operator's providers offered to the
    /// account; a signer may be given an enabled one (`signature.provider_id`).
    listSigningProviders: () => data(request("GET", "/api/v1/signing-providers")),
    /// One provider's options for the account (`admin:account`).
    getSigningProvider: (id) => data(request("GET", `/api/v1/signing-providers/${encodeURIComponent(id)}`)),
    /// `{enabled, required_qualifiers?, refuse_name_mismatch?, session_minutes?, client_secret?}`.
    putSigningProvider: (id, body) => data(request("PUT", `/api/v1/signing-providers/${encodeURIComponent(id)}`, { body })),
    // ---- Webhooks (docs/40 §4; scope webhooks:manage) ---------------------------
    /// `{items: [{id, envelope_id, url, event_types, secret_refs, active}]}`.
    listWebhooks: () => data(request("GET", "/api/v1/webhooks")),
    getWebhook: (w) => data(request("GET", W(w))),
    /// `{url, event_types, secret_refs, envelope_id?}`: `url` https:// to a public address
    /// (`422 CS-API-0013` otherwise); `event_types` from `WEBHOOK_EVENT_TYPES`;
    /// `secret_refs` 1 to 4 names of signing secrets the operator provisioned (the secret
    /// never passes through the API, so there is nothing to show once).
    createWebhook: (body) => data(request("POST", "/api/v1/webhooks", { body })),
    /// Disable a subscription (`active: false`); its deliveries stay readable.
    deleteWebhook: (w) => data(request("DELETE", W(w))),
    /// The latest 100 deliveries, `{items: [{id, event_id, event_type, status: pending|
    /// delivered|failed, attempts, last_status_code}]}`.
    listDeliveries: (w) => data(request("GET", `${W(w)}/deliveries`)),
    /// `{url?, event_types?, active?}`: edit, pause or resume (UXW-31).
    updateWebhook: (w, body) => data(request("PATCH", W(w), { body })),
    /// Queue a `webhook.test` event (UXW-32): `202` with the delivery; a paused
    /// subscription is `409 CS-API-0009`.
    testWebhook: (w) => data(request("POST", `${W(w)}/test`)),
    /// Deliver one delivery's event again, through the worker (UXW-33).
    redeliver: (w, d) => data(request("POST", `${W(w)}/deliveries/${encodeURIComponent(d)}/redeliver`)),

    // ---- Admin audit log (ORG-05, docs/40; scope admin:account) -----------------------
    /// A page of the workspace's admin log, oldest first, verified as read: `{items: [{seq,
    /// at, action, hash, prev, event}], next_cursor}`; `event` the canonical event (`actor
    /// {kind: user|api_client|system, id?}`, `target`, `changes [{key, old, new}]`,
    /// `request_id`, `ip`). `verify: "full"` re-verifies the whole log first (a broken
    /// chain is `500 CS-DB-0014`). `limit` 1 to 1000.
    adminEvents: ({ cursor, limit, verify } = {}) => data(request("GET", "/api/v1/admin-events", { query: { cursor, limit, verify } })),
    /// The same page as the server's CSV (`seq,at,action,hash,prev,event`): `{text, next}`,
    /// `next` the cursor of the page after it, or null on the last.
    /// A workspace report (VS-06, `reports.read`): `kind` `envelopes`, `recipients` or
    /// `usage`, over envelopes created in `[from, to)` of `sender` (an id or "me");
    /// `{items, truncated}`.
    report: (kind, { from, to, sender } = {}) => data(request("GET", `/api/v1/reports/${encodeURIComponent(kind)}`, { query: { from, to, sender } })),
    /// The same report as the server's CSV: `{text, truncated}`.
    /// `GET /insights` (FG-141): the dashboard's figures for the window, the workspace's
    /// with `reports.read`, else the caller's own.
    insights: ({ from, to, sender, utc_offset_minutes } = {}) => data(request("GET", "/api/v1/insights", { query: { from, to, sender, utc_offset_minutes } })),
    reportCsv: async (kind, { from, to, sender } = {}) => {
      const r = await request("GET", `/api/v1/reports/${encodeURIComponent(kind)}`, { query: { from, to, sender, format: "csv" }, raw: true, accept: "text/csv, application/problem+json" });
      return { text: await r.blob.text(), truncated: !!r.truncated };
    },
    adminEventsCsv: async ({ cursor, limit } = {}) => {
      const r = await request("GET", "/api/v1/admin-events", { query: { cursor, limit, format: "csv" }, raw: true, accept: "text/csv, application/problem+json" });
      return { text: await r.blob.text(), next: r.next == null || r.next === "" ? null : Number(r.next) };
    },

    // ---- Account and members (Admin) -------------------------------------------
    /// `PATCH /accounts/me {settings}`: merged into the account's settings (`null`
    /// removes a key). Answers `{settings}`. The API has no way to rename the account.
    patchAccountSettings: (settings) => data(request("PATCH", "/api/v1/accounts/me", { body: { settings } })),
    /// The electronic disclosure (ERSD-01): `GET /ersd-versions` answers `{current,
    /// items}` (`current` the one recipients must accept, with its text, or null);
    /// `publish({text, language?})` makes `text` the next version and requires it in
    /// one step, answering the new version without its text.
    ersd: {
      get: () => data(request("GET", "/api/v1/ersd-versions")),
      publish: ({ text, language }) => data(request("POST", "/api/v1/ersd-versions", { body: language ? { text, language } : { text } })),
    },
    /// An invited member sets their password with the emailed token (no session).
    acceptInvite: (token, password) => data(request("POST", "/api/v1/auth/accept-invite", { body: { token, password } })),
    /// The session workspace's organization (ORG-03, docs/40 §2): every call needs an
    /// organization role, read by the server per request (`403 CS-AUTH-0006` without).
    org: {
      /// `{id, name, status, role, created_at}`; `role` is the caller's.
      get: () => data(request("GET", "/api/v1/organizations/me")),
      /// `{name}` (`org.settings.update`).
      rename: (name) => data(request("PATCH", "/api/v1/organizations/me", { body: { name } })),
      /// `{items: [{id, name, status}]}`.
      workspaces: () => data(request("GET", "/api/v1/organizations/me/workspaces")),
      /// `sandbox`: a sandbox workspace, for good (ADR-041, `VS-08D`).
      createWorkspace: (name, { sandbox = false } = {}) => data(request("POST", "/api/v1/organizations/me/workspaces", { body: sandbox ? { name, sandbox: true } : { name } })),
      archiveWorkspace: (id) => data(request("POST", `/api/v1/organizations/me/workspaces/${encodeURIComponent(id)}/archive`)),
      /// Become a member of that workspace with `profile` (`admin`, `sender`, `viewer`);
      /// owners and admins only; written to both admin logs.
      joinWorkspace: (id, profile) => data(request("POST", `/api/v1/organizations/me/workspaces/${encodeURIComponent(id)}/join`, { body: { profile } })),
      /// `{items: [{user_id, role, permission_set_id, workspace_scope, created_at}]}`.
      admins: () => data(request("GET", "/api/v1/organizations/me/admins")),
      addAdmin: (userId, role) => data(request("POST", "/api/v1/organizations/me/admins", { body: { user_id: userId, role } })),
      setAdminRole: (userId, role) => data(request("PATCH", `/api/v1/organizations/me/admins/${encodeURIComponent(userId)}`, { body: { role } })),
      removeAdmin: (userId) => data(request("DELETE", `/api/v1/organizations/me/admins/${encodeURIComponent(userId)}`)),
      /// A page of the organization's admin log, oldest first: `{items: [{seq, at, action,
      /// hash, prev, event}], next_cursor}`; `verify: "full"` re-verifies the whole chain
      /// first (a broken link is `500 CS-DB-0014`).
      audit: ({ cursor = null, limit = null, verify = null } = {}) => data(request("GET", "/api/v1/organizations/me/audit", { query: { cursor, limit, verify } })),
    },

    users: {
      list: () => data(request("GET", "/api/v1/users")),
      /// One member, with `invitation` (the latest invitation's state; the list has none).
      get: (u) => data(request("GET", `/api/v1/users/${encodeURIComponent(u)}`)),
      /// `{email, name, profile, password?}`.
      create: (body) => data(request("POST", "/api/v1/users", { body })),
      /// `{email, name, profile}`: the server emails a one-time link to set a password.
      invite: (body) => data(request("POST", "/api/v1/users", { body: { ...body, invite: true } })),
      /// A new link for a member who has not set up their sign-in; earlier links stop working.
      reinvite: (u) => data(request("POST", `/api/v1/users/${encodeURIComponent(u)}/invite`)),
      /// `{name?, password?, profile?, disabled?}`.
      patch: (u, body) => data(request("PATCH", `/api/v1/users/${encodeURIComponent(u)}`, { body })),
      remove: (u) => data(request("DELETE", `/api/v1/users/${encodeURIComponent(u)}`)),
      /// Reset the second factors of a member who lost them all (ASVS-32; needs a recent
      /// re-authentication): `how` is how their identity was proved (`in_person`,
      /// `video_call`, `phone_callback`, `manager_confirmation`, `identity_document`).
      resetSecondFactor: (u, how) => data(request("POST", `/api/v1/users/${encodeURIComponent(u)}/second-factor/reset`, { body: { identity_verified_by: how } })),
    },
    apiClients: {
      list: () => data(request("GET", "/api/v1/api-clients")),
      /// `{name, kind: "api_key" | "oauth_app" | "jwt_integration", scopes, owner_user_id?,
      /// expires_in_days?, redirect_uris?, public_key?}`: an OAuth app or a JWT
      /// integration names where consent sends the member back; a JWT integration also
      /// its public key PEM (VS-08A, VS-08B).
      create: (body) => data(request("POST", "/api/v1/api-clients", { body })),
      revoke: (c) => data(request("DELETE", `/api/v1/api-clients/${encodeURIComponent(c)}`)),
    },

    /// OAuth 2.1 consent (VS-08A, docs/40 §2): the consent screen reads the checked
    /// authorization request (`params`: the query `GET /oauth/authorize` handed over) and
    /// answers it; a member lists and withdraws the apps acting as them.
    oauth: {
      request: (params) => data(request("GET", `/api/v1/oauth/authorize/request?${new URLSearchParams(params)}`)),
      /// `decision`: `allow` or `deny`; answers `{redirect_to}`, where the browser goes next.
      answer: (params, decision) => data(request("POST", "/api/v1/oauth/authorize", { body: { ...params, decision } })),
      consents: () => data(request("GET", "/api/v1/oauth/consents")),
      revoke: (id) => data(request("DELETE", `/api/v1/oauth/consents/${encodeURIComponent(id)}`)),
    },

    /// The account's groups, `{items: [{id, name, members}]}`, to share a template with
    /// (UXW-06), and their management by an administrator (UXW-07, `admin:users`): one
    /// group is `{id, name, members, user_ids}`.
    groups: {
      list: () => data(request("GET", "/api/v1/groups")),
      get: (g) => data(request("GET", `/api/v1/groups/${encodeURIComponent(g)}`)),
      create: (name) => data(request("POST", "/api/v1/groups", { body: { name } })),
      rename: (g, name) => data(request("PATCH", `/api/v1/groups/${encodeURIComponent(g)}`, { body: { name } })),
      remove: (g) => data(request("DELETE", `/api/v1/groups/${encodeURIComponent(g)}`)),
      /// The group's members become exactly `userIds`.
      setMembers: (g, userIds) => data(request("PUT", `/api/v1/groups/${encodeURIComponent(g)}/members`, { body: { user_ids: userIds } })),
    },
    /// Permission profiles (UXW-07, `admin:users`): `{id, name, kind, builtin,
    /// permissions, members}`; built-in ones are fixed, a custom one is a set of scopes
    /// and `view_all_envelopes`, never beyond the caller's own (403 CS-AUTH-0006).
    profiles: {
      list: () => data(request("GET", "/api/v1/permission-profiles")),
      get: (p) => data(request("GET", `/api/v1/permission-profiles/${encodeURIComponent(p)}`)),
      /// `{name, permissions}`.
      create: (body) => data(request("POST", "/api/v1/permission-profiles", { body })),
      /// `{name?, permissions?}`.
      patch: (p, body) => data(request("PATCH", `/api/v1/permission-profiles/${encodeURIComponent(p)}`, { body })),
      remove: (p) => data(request("DELETE", `/api/v1/permission-profiles/${encodeURIComponent(p)}`)),
    },

    // ---- Templates (docs/40: roles, documents and fields, as on envelopes) -----
    // A single-template read, and the document and role calls, answer the whole
    // template: `roles` with ids, `documents`, and `fields` bound to `role_id`. The
    // ETag is `"v<version>"`; every change bumps the version.
    templates: {
      /// The templates the caller may use (UXW-06); `view`: `all` (default), `owned`,
      /// `shared` (Shared with me) or `favourites`. Each item has `access` (owner, edit or
      /// use), `favourite` and `shared`.
      /// `folder` (TSH-03): one of the caller's template folders, or `none`; each item
      /// carries the caller's `folder_id`.
      list: (view, folder) => data(request("GET", "/api/v1/templates", (view && view !== "all") || folder ? { query: { view: view && view !== "all" ? view : null, folder: folder || null } } : {})),
      /// One envelope from one template or several (slice 3, composite templates):
      /// `{template_ids, recipients: [{role, name, email} | {name, email, type}],
      /// subject?, message?, status}`; answers the envelope.
      use: (body) => data(request("POST", "/api/v1/envelopes/from-templates", { body })),
      /// Whom a template is shared with (UXW-06; its owner's): `{items: [{id, can_edit,
      /// user?: {id, name, email}, group?: {id, name}, account?: true}]}`.
      shares: (tp) => data(request("GET", `${T(tp)}/shares`)),
      /// Replace the shares: `[{user_id | email | group_id | account: true, can_edit?}]`;
      /// answers the shares as `shares` does.
      setShares: (tp, items) => data(request("PUT", `${T(tp)}/shares`, { body: { items } })),
      /// Star (`on`) or unstar a template for the caller (Favourites).
      favourite: (tp, on) => data(request(on ? "PUT" : "DELETE", `${T(tp)}/favourite`)),
      /// `{template, etag}`; the ETag falls back to the version when a proxy drops it.
      async get(tp) {
        const r = await request("GET", T(tp));
        return { template: r.data, etag: r.etag || etagOf(r.data) };
      },
      /// `{name, email_subject?, email_message?, roles?: [{name, type, routing_order}]}`.
      create: (body) => data(request("POST", "/api/v1/templates", { body })),
      /// `{name?, email_subject?, email_message?}` (If-Match).
      patch: (tp, etag, body) => data(request("PATCH", T(tp), { body, ifMatch: etag })),
      /// A live template moves to the Deleted view, kept whole (UXW-02); one already
      /// there is removed for good.
      remove: (tp, etag) => data(request("DELETE", T(tp), { ifMatch: etag })),
      /// The Deleted view (UXW-02): `{items}`, most recently deleted first.
      listDeleted: () => data(request("GET", "/api/v1/templates", { query: { deleted: "true" } })),
      /// Bring a deleted template back, whole; answers the whole template.
      restore: (tp) => data(request("POST", `${T(tp)}/restore`)),
      duplicate: (tp, name) => data(request("POST", `${T(tp)}/duplicate`, { body: name ? { name } : {} })),
      /// Answers the whole template: the new document is the one that was not there.
      addDocument: (tp, name, bytes) => data(request("POST", `${T(tp)}/documents`, { body: { name, content_base64: toBase64(bytes) } })),
      removeDocument: (tp, doc, etag) => data(request("DELETE", `${T(tp)}/documents/${encodeURIComponent(doc)}`, { ifMatch: etag })),
      documentContent: async (tp, doc) => (await request("GET", `${T(tp)}/documents/${encodeURIComponent(doc)}/content`, { raw: true })).blob,
      /// `{name, type, routing_order}`; answers the whole template.
      addRole: (tp, role) => data(request("POST", `${T(tp)}/roles`, { body: role })),
      /// `{name?, type?, routing_order?}` (If-Match); answers the whole template.
      patchRole: (tp, role, etag, body) => data(request("PATCH", `${T(tp)}/roles/${encodeURIComponent(role)}`, { body, ifMatch: etag })),
      removeRole: (tp, role, etag) => data(request("DELETE", `${T(tp)}/roles/${encodeURIComponent(role)}`, { ifMatch: etag })),
      fields: (tp) => data(request("GET", `${T(tp)}/fields`)),
      /// `[{role_id, document_id, type, placement, required?, label?}]` → `{items}`.
      addFields: (tp, items) => data(request("POST", `${T(tp)}/fields`, { body: { items } })),
      /// The members given replace the field's (If-Match).
      patchField: (tp, f, etag, body) => data(request("PATCH", `${T(tp)}/fields/${encodeURIComponent(f)}`, { body, ifMatch: etag })),
      removeField: (tp, f, etag) => data(request("DELETE", `${T(tp)}/fields/${encodeURIComponent(f)}`, { ifMatch: etag })),
    },

    // ---- Ceremony (docs/40 §6; not public API) ----------------------------
    // The view: `{envelope (with expires_at), recipient, fields, capture_location,
    // consent_required: {version, sha256, url?} | null, auth_required, sender: {name,
    // email, organisation}}` (UXW-34). `url` is there only when the account has
    // published the disclosure's text; `sender.name` and `.email` are null once the
    // sending user has left the account.
    /// VS-09, docs/40 §5: embedded views. The integrator's calls (`signing`, `prepare`,
    /// `correct`: `{url, expires_at}`, a link spent once) and the embedded page's own
    /// (`session`: spend a prepare or correct link for its session).
    views: {
      signing: (id, body) => data(request("POST", `${E(id)}/views/signing`, { body })),
      prepare: (id, body = {}) => data(request("POST", `${E(id)}/views/prepare`, { body })),
      correct: (id, body = {}) => data(request("POST", `${E(id)}/views/correct`, { body })),
      session: (token) => data(request("POST", `/e/${encodeURIComponent(token)}/session`, { body: {}, ceremony: true })),
    },
    ceremony: {
      view: (token) => data(request("GET", S(token), { ceremony: true })),
      /// An approver approves (`recipient.approved`); a signer is refused (409).
      approve: (token, location) => data(request("POST", `${S(token)}/approve`, { body: withLocation({}, location), ceremony: true })),
      /// Withdraw consent to electronic records: declines a required action.
      withdrawConsent: (token, location) => data(request("POST", `${S(token)}/withdraw-consent`, { body: withLocation({}, location), ceremony: true })),
      /// The full disclosure the recipient consents to, `{version, sha256, text}` (`sha256`
      /// over the text's UTF-8; the one `consent_required` names), once every
      /// authentication has passed (UXW-34; 404 when the account published no text).
      disclosure: (token) => data(request("GET", `${S(token)}/disclosure`, { ceremony: true })),
      /// Remove this recipient's value from a field before finishing (`NOT_ON_SERVER.clearField`).
      clearField: unbuilt("clearField", (token, field) => data(request("DELETE", `${S(token)}/fields/${encodeURIComponent(field)}`, { ceremony: true }))),
      open: (token) => data(request("POST", `${S(token)}/session`, { body: {}, ceremony: true })),
      /// RSP-01: start signing with the recipient's remote provider (the view with
      /// `remote_authorization_url`), the provider's return, the session's state, the
      /// prepared documents' authorization, and cancel.
      /// RSP-02: an India eSign start carries `esign {consent, accepted, auth_mode}`.
      remoteStart: (token, location, esign) => data(request("POST", `${S(token)}/remote-signing`, { body: withLocation(esign ? { esign } : {}, location), ceremony: true })),
      remoteCallback: (token, state, code, error) => data(request("POST", `${S(token)}/remote-signing/callback`, { body: error ? { state, error } : { state, code }, ceremony: true })),
      remoteStatus: (token) => data(request("GET", `${S(token)}/remote-signing`, { ceremony: true })),
      remoteAuthorize: (token) => data(request("POST", `${S(token)}/remote-signing/authorize`, { body: {}, ceremony: true })),
      remoteCancel: (token) => data(request("POST", `${S(token)}/remote-signing/cancel`, { body: {}, ceremony: true })),
      consent: (token, ersdVersion, location) =>
        data(request("POST", `${S(token)}/consent`, { body: withLocation({ ersd_version: ersdVersion }, location), ceremony: true })),
      authenticate: (token, method, code) =>
        data(request("POST", `${S(token)}/authenticate`, { body: { method, code }, ceremony: true })),
      /// Send a one-time code (SEC-A02) by `method`: `email_otp` (the default),
      /// `sms_otp` or `voice_otp` (slice 5); `otpVerify` checks it.
      otpSend: (token, method) => data(request("POST", `${S(token)}/otp`, { body: method && method !== "email_otp" ? { method } : {}, ceremony: true })),
      otpVerify: (token, code, method) => data(request("POST", `${S(token)}/otp/verify`, { body: method && method !== "email_otp" ? { code, method } : { code }, ceremony: true })),
      /// Sign in through one of the server's identity providers (`sso`, RAUTH-01):
      /// `ssoStart` answers the view with `sso_authorization_url`, where the page sends
      /// the browser; `ssoVerify` finishes with the `state` and `code` it came back with.
      ssoStart: (token, provider) => data(request("POST", `${S(token)}/sso`, { body: { provider }, ceremony: true })),
      ssoVerify: (token, state, code) => data(request("POST", `${S(token)}/sso/verify`, { body: { state, code }, ceremony: true })),
      document: async (token, doc) =>
        (await request("GET", `${S(token)}/documents/${encodeURIComponent(doc)}/content`, { raw: true, ceremony: true })).blob,
      viewed: (token, doc, pages, location) =>
        data(request("POST", `${S(token)}/documents/${encodeURIComponent(doc)}/viewed`, { body: withLocation({ pages_seen: pages }, location), ceremony: true })),
      adopt: (token, mark, method, imageBase64, location) =>
        data(request("POST", `${S(token)}/adopt`, { body: withLocation({ mark, method, image_base64: imageBase64 }, location), ceremony: true })),
      fill: (token, field, value) =>
        data(request("PUT", `${S(token)}/fields/${encodeURIComponent(field)}`, { body: { value }, ceremony: true })),
      finish: (token, values, location) =>
        data(request("POST", `${S(token)}/finish`, { body: withLocation(values?.length ? { values } : {}, location), ceremony: true })),
      decline: (token, reason, location) =>
        data(request("POST", `${S(token)}/decline`, { body: withLocation(reason ? { reason } : {}, location), ceremony: true })),
      finishLater: (token) => data(request("POST", `${S(token)}/finish-later`, { body: {}, ceremony: true })),
      /// Sign on paper (FG-013, ADR-043): the scan (a PDF, base64) of the documents the
      /// signer printed and signed by hand; answers the view, this recipient completed.
      signOnPaper: (token, contentBase64, location) =>
        data(request("POST", `${S(token)}/paper`, { body: withLocation({ content_base64: contentBase64 }, location), ceremony: true })),
      /// An agent (or intermediary) names later recipients before finishing (VS-02):
      /// `[{id, name?, email?}]`, ids from the view's `later_recipients`.
      nameRecipients: (token, recipients, location) =>
        data(request("POST", `${S(token)}/recipients`, { body: withLocation({ recipients }, location), ceremony: true })),
      /// VS-06A: an editor adds fields (the API's wire form: recipient_id, document_id,
      /// type, page, x, y, width, height) for themself or a later recipient not yet
      /// reached; moves or changes one (a merge, `x`/`y`/… flat); removes one. Each
      /// answers the view, whose `editable_fields` lists the later recipients' fields.
      placeFields: (token, fields, location) =>
        data(request("POST", `${S(token)}/editor/fields`, { body: withLocation({ fields }, location), ceremony: true })),
      editField: (token, field, patch) =>
        data(request("PATCH", `${S(token)}/editor/fields/${encodeURIComponent(field)}`, { body: patch, ceremony: true })),
      removeField: (token, field) =>
        data(request("DELETE", `${S(token)}/editor/fields/${encodeURIComponent(field)}`, { body: {}, ceremony: true })),
      /// WEB-06: attach a file (PDF, PNG or JPEG) to an attachment field.
      attach: (token, field, bytes) =>
        data(request("PUT", `${S(token)}/fields/${encodeURIComponent(field)}/attachment`, { body: { content_base64: toBase64(bytes) }, ceremony: true })),
      /// WEB-06: after finishing, the sealed copy once complete, else a preview.
      download: async (token, doc) =>
        (await request("GET", `${S(token)}/document`, { raw: true, ceremony: true, query: doc ? { doc } : undefined })).blob,
      /// VS-01: after finishing, the certificate of completion once the envelope completes.
      certificate: async (token) =>
        (await request("GET", `${S(token)}/certificate`, { raw: true, ceremony: true })).blob,
      // WEB-06 (G-S2): the envelope's history as this recipient may see it, and
      // reassignment when the envelope allows it (WEB-07). History events are
      // `{seq, type, at, by}`, `type` the audit event type (`recipient.signed`, …).
      history: (token) => data(request("GET", `${S(token)}/history`, { ceremony: true })),
      reassign: (token, { name, email, reason }, location) =>
        data(request("POST", `${S(token)}/reassign`, { body: withLocation({ name, email, ...(reason ? { reason } : {}) }, location), ceremony: true })),
    },
  };
}

/// Add the GEO-01 `location` member when there is one: `{latitude, longitude,
/// accuracy_m}` or `{declined: true}`.
export function withLocation(body, location) {
  return location ? { ...body, location } : body;
}

/// The location member from a Geolocation position or error (GEO-01): a fix with its
/// accuracy, or a decline (refused, unavailable or timed out). Rounded to 6 places
/// (≈ 0.1 m), which is all the device can claim.
export function locationFrom(position) {
  const c = position?.coords;
  if (!c || !Number.isFinite(c.latitude) || !Number.isFinite(c.longitude)) return { declined: true };
  const r6 = (n) => Math.round(n * 1e6) / 1e6;
  return {
    latitude: r6(Math.max(-90, Math.min(90, c.latitude))),
    longitude: r6(Math.max(-180, Math.min(180, c.longitude))),
    accuracy_m: Math.max(0, Math.round(Number.isFinite(c.accuracy) ? c.accuracy : 0)),
  };
}

/// Which backend: the in-memory fake with `?mock=1`, otherwise the server at the
/// `<meta name="openseal-api-base">` origin (empty = this origin).
///
/// The fake exists only for development and the browser tests while the server is
/// being integrated: it is honoured on a loopback host only, so a deployed OpenSeal
/// can never be made to show fake agreements by a crafted link.
///
/// Once `?mock=1` is seen on a loopback host, the tab remembers it (sessionStorage,
/// `openseal.mock`), so links that drop the query stay in mock mode; `?mock=0` forgets.
///
/// The one other case is the public demo (SITE-04): the website publishes a copy of
/// this app with `<meta name="openseal-demo" content="static">` in each page
/// (`tools/build-site.py --publish`), and that copy is always in mock mode, on any host,
/// because no server stands behind it. The marker is in the served HTML, which only
/// whoever publishes the files controls; no link or query can set it.
export function isMockMode(loc = globalThis.location, store = safeSessionStorage(), doc = globalThis.document) {
  try {
    if (isDemoBuild(doc)) return true;
    if (!isLoopback(loc)) return false;
    const q = new URLSearchParams(loc?.search || "").get("mock");
    if (q === "1" || q === "0") {
      try { if (q === "1") store?.setItem("openseal.mock", "1"); else store?.removeItem("openseal.mock"); } catch { /* storage off */ }
      return q === "1";
    }
    try { return store?.getItem("openseal.mock") === "1"; } catch { return false; }
  } catch { return false; }
}

/// Whether this page is the website's static demo copy of the app (SITE-04): its HTML
/// carries `<meta name="openseal-demo" content="static">`. Never true for a deployment.
export function isDemoBuild(doc = globalThis.document) {
  try { return doc?.querySelector?.('meta[name="openseal-demo"]')?.getAttribute("content") === "static"; } catch { return false; }
}

/// Whether the page is served from this machine (development and tests).
export function isLoopback(loc = globalThis.location) {
  const host = (loc?.hostname || "").replace(/^\[|\]$/g, "");
  return host === "localhost" || host === "::1" || /^127\./.test(host);
}

/// On loopback without mock mode, an error that means "no OpenSeal server here": the
/// dev server answers API paths with 404 or 501, or nothing answers at all.
export function isNoServer(err, loc = globalThis.location) {
  return isLoopback(loc) && !!err && (err.code === "CS-NET-0001" || err.code === "HTTP-404" || err.code === "HTTP-501");
}

function safeSessionStorage() {
  try { return globalThis.sessionStorage || null; } catch { return null; }
}
