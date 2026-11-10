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

/// A problem-details error from the API, or a network failure (`code` CS-NET-0001,
/// client-side only, never sent by the server).
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

/// Make a client. `baseUrl` is prepended to every path ("" = same origin). `store`
/// keeps the CSRF token across reloads of this tab (sessionStorage in the browser).
export function createClient({ baseUrl = "", fetch: fetchImpl = globalThis.fetch?.bind(globalThis), store = null } = {}) {
  let csrf = null;
  try { csrf = store?.getItem("openseal.csrf") || null; } catch { csrf = null; }
  const setCsrf = (v) => {
    csrf = v;
    try { if (v) store?.setItem("openseal.csrf", v); else store?.removeItem("openseal.csrf"); } catch { /* storage off */ }
  };

  async function request(method, path, { body, query, ifMatch, raw = false, ceremony = false } = {}) {
    let url = baseUrl + path;
    if (query) {
      const q = new URLSearchParams();
      for (const [k, v] of Object.entries(query)) if (v != null && v !== "") q.set(k, String(v));
      const s = q.toString();
      if (s) url += `?${s}`;
    }
    const headers = { Accept: raw ? "application/pdf, application/problem+json" : "application/json" };
    if (body !== undefined) headers["Content-Type"] = "application/json";
    if (method !== "GET" && !ceremony && csrf) headers["X-CSRF-Token"] = csrf;
    if (method === "POST") headers["Idempotency-Key"] = random();
    if (ifMatch) headers["If-Match"] = ifMatch;
    let res;
    try {
      res = await fetchImpl(url, {
        method,
        headers,
        body: body === undefined ? undefined : JSON.stringify(body),
        credentials: baseUrl ? "include" : "same-origin",
      });
    } catch {
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
    if (raw) return { blob: await res.blob(), etag: res.headers.get("ETag") };
    if (res.status === 204) return { data: null, etag: res.headers.get("ETag") };
    const text = await res.text();
    return { data: text ? JSON.parse(text) : null, etag: res.headers.get("ETag") };
  }

  const data = async (p) => (await p).data;
  const E = (id) => `/api/v1/envelopes/${encodeURIComponent(id)}`;
  const S = (token) => `/s/${encodeURIComponent(token)}`;
  const etagOf = (env) => (env && Number.isInteger(env.version) ? `"v${env.version}"` : null);

  return {
    request,
    hasCsrf: () => !!csrf,

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
    account: () => data(request("GET", "/api/v1/accounts/me")),

    // ---- Envelopes ---------------------------------------------------------
    listEnvelopes: ({ status, cursor, limit = 25 } = {}) =>
      data(request("GET", "/api/v1/envelopes", { query: { status, cursor, limit } })),
    /// `{envelope, etag}`; the ETag falls back to the version when a proxy drops it.
    async getEnvelope(id) {
      const r = await request("GET", E(id));
      return { envelope: r.data, etag: r.etag || etagOf(r.data) };
    },
    createEnvelope: (body) => data(request("POST", "/api/v1/envelopes", { body })),
    patchEnvelope: (id, etag, body) => data(request("PATCH", E(id), { body, ifMatch: etag })),
    deleteEnvelope: (id, etag) => data(request("DELETE", E(id), { ifMatch: etag })),
    sendEnvelope: (id) => data(request("POST", `${E(id)}/send`)),
    voidEnvelope: (id, reason) => data(request("POST", `${E(id)}/void`, { body: { reason } })),
    resend: (id, recipientIds) => data(request("POST", `${E(id)}/resend`, { body: recipientIds ? { recipient_ids: recipientIds } : {} })),
    status: (id) => data(request("GET", `${E(id)}/status`)),
    audit: (id) => data(request("GET", `${E(id)}/audit`)),
    certificate: async (id) => (await request("GET", `${E(id)}/certificate`, { raw: true })).blob,
    documentContent: async (id, doc, version = "normalized") =>
      (await request("GET", `${E(id)}/documents/${encodeURIComponent(doc)}/content`, { raw: true, query: { version } })).blob,
    addDocument: (id, name, bytes) => data(request("POST", `${E(id)}/documents`, { body: { name, content_base64: toBase64(bytes) } })),
    addRecipients: (id, items) => data(request("POST", `${E(id)}/recipients`, { body: { items } })),
    patchRecipient: (id, r, etag, body) => data(request("PATCH", `${E(id)}/recipients/${encodeURIComponent(r)}`, { body, ifMatch: etag })),
    deleteRecipient: (id, r, etag) => data(request("DELETE", `${E(id)}/recipients/${encodeURIComponent(r)}`, { ifMatch: etag })),
    addFields: (id, items) => data(request("POST", `${E(id)}/fields`, { body: { items } })),
    patchField: (id, f, etag, body) => data(request("PATCH", `${E(id)}/fields/${encodeURIComponent(f)}`, { body, ifMatch: etag })),
    deleteField: (id, f, etag) => data(request("DELETE", `${E(id)}/fields/${encodeURIComponent(f)}`, { ifMatch: etag })),

    // ---- Ceremony (docs/40 §6; not public API) ----------------------------
    ceremony: {
      view: (token) => data(request("GET", S(token), { ceremony: true })),
      open: (token) => data(request("POST", `${S(token)}/session`, { body: {}, ceremony: true })),
      consent: (token, ersdVersion, location) =>
        data(request("POST", `${S(token)}/consent`, { body: withLocation({ ersd_version: ersdVersion }, location), ceremony: true })),
      authenticate: (token, method, code) =>
        data(request("POST", `${S(token)}/authenticate`, { body: { method, code }, ceremony: true })),
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
export function isMockMode(loc = globalThis.location) {
  try { return new URLSearchParams(loc?.search || "").get("mock") === "1"; } catch { return false; }
}
