// The OpenSeal API client for JavaScript and TypeScript (slice 8, `VS-08E`, docs/40 §7).
// One method per operation of api/openapi.yaml, built from the generated table in
// operations.js (tools/build-sdks.py); types in index.d.ts. ES module, no dependencies:
// it runs wherever `fetch` and Web Crypto do (Node 20+, Deno, Bun, browsers).
//
//   import { OpenSeal } from "@openseal/sdk";
//   const os = new OpenSeal({ baseUrl: "https://sign.example.com", apiKey: process.env.OPENSEAL_API_KEY });
//   const env = await os.createEnvelope({ body: { subject: "NDA", status: "sent", documents, recipients, fields } });
//
// Errors are `OpenSealError` with the problem's stable `code` (docs/20), `status`,
// `requestId` and field `errors`; never document content. Also here: the OAuth helpers
// (PKCE, the authorization URL, the token grants) and Standard Webhooks verification.

import { OPERATIONS } from "./operations.js";

export { OPERATIONS };

/// A refusal from the API: RFC 9457 problem details with a stable code (docs/40 §1), or
/// an OAuth token error (RFC 6749 §5.2, its `CS-*` code in `error_description`).
export class OpenSealError extends Error {
  constructor({ status = 0, code = "", title = "", detail = "", request_id = null, errors = [], error = null } = {}) {
    super(`${code || error || "OpenSeal error"}${title ? `: ${title}` : ""}`);
    this.name = "OpenSealError";
    this.status = status;
    this.code = code;
    this.title = title;
    this.detail = detail;
    this.requestId = request_id;
    this.errors = Array.isArray(errors) ? errors : [];
    this.oauthError = error;
  }
}

const enc = new TextEncoder();

function b64url(bytes) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/// The client. `apiKey` (`osk_…`) or `accessToken` authenticates every call; `fetch`
/// may be supplied (tests, proxies).
export class OpenSeal {
  constructor({ baseUrl, apiKey = null, accessToken = null, fetch: f = globalThis.fetch, userAgent = null } = {}) {
    if (!baseUrl) throw new TypeError("baseUrl is required");
    this.baseUrl = String(baseUrl).replace(/\/+$/, "");
    this.credential = apiKey || accessToken || null;
    this.fetch = f;
    this.userAgent = userAgent;
    for (const [id, op] of Object.entries(OPERATIONS)) {
      // `token` (the token endpoint) is the form-encoded `token()` below, not a JSON call.
      if (id in OpenSeal.prototype) continue;
      Object.defineProperty(this, id, { value: (params = {}) => this.call(op, params), enumerable: false });
    }
  }

  /// Call one operation of the table: path parameters substituted (encoded), the rest of
  /// `params` the query, `params.body` the JSON body, `params.idempotencyKey` and
  /// `params.ifMatch` the headers of the same name. Answers the JSON, `null` for 204, or
  /// the bytes of a file.
  async call(op, params = {}) {
    const { body, idempotencyKey, ifMatch, ...rest } = params || {};
    let path = op.path;
    for (const p of op.path_params) {
      if (rest[p] == null || rest[p] === "") throw new TypeError(`${p} is required`);
      path = path.replace(`{${p}}`, encodeURIComponent(String(rest[p])));
    }
    const query = new URLSearchParams();
    for (const q of op.query) if (rest[q] != null) query.set(q, String(rest[q]));
    const qs = query.toString();
    const headers = { accept: "application/json" };
    if (this.credential) headers.authorization = `Bearer ${this.credential}`;
    if (this.userAgent) headers["user-agent"] = this.userAgent;
    if (idempotencyKey) headers["idempotency-key"] = String(idempotencyKey);
    if (ifMatch) headers["if-match"] = String(ifMatch);
    let payload;
    if (op.body && body !== undefined) {
      headers["content-type"] = "application/json";
      payload = JSON.stringify(body);
    } else if (op.body_required) {
      throw new TypeError("body is required");
    }
    const res = await this.fetch(`${this.baseUrl}${path}${qs ? `?${qs}` : ""}`, { method: op.method, headers, body: payload, redirect: "manual" });
    return answer(res);
  }

  /// OAuth 2.1 (docs/40 §2): the authorization URL to send a member's browser to, with a
  /// fresh PKCE verifier and `state` to keep until the redirect comes back.
  async authorizationUrl({ clientId, redirectUri, scope, state = null }) {
    const verifier = b64url(crypto.getRandomValues(new Uint8Array(48)));
    const challenge = b64url(new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(verifier))));
    const st = state || b64url(crypto.getRandomValues(new Uint8Array(16)));
    const q = new URLSearchParams({ response_type: "code", client_id: clientId, redirect_uri: redirectUri, scope: Array.isArray(scope) ? scope.join(" ") : scope, state: st, code_challenge: challenge, code_challenge_method: "S256" });
    return { url: `${this.baseUrl}/api/v1/oauth/authorize?${q}`, verifier, state: st };
  }

  /// The token endpoint: `{grant_type: "authorization_code", code, redirect_uri,
  /// code_verifier}`, `{grant_type: "refresh_token", refresh_token}`,
  /// `{grant_type: "client_credentials", scope?}` with the app's `clientId` and
  /// `clientSecret`; or the JWT bearer grant with `{assertion}` alone. Answers the token
  /// response; the access token is used for later calls of this client.
  async token({ clientId = null, clientSecret = null, ...form }) {
    const headers = { "content-type": "application/x-www-form-urlencoded", accept: "application/json" };
    if (clientId && clientSecret) headers.authorization = `Basic ${btoa(`${clientId}:${clientSecret}`)}`;
    if (form.assertion && !form.grant_type) form.grant_type = "urn:ietf:params:oauth:grant-type:jwt-bearer";
    const res = await this.fetch(`${this.baseUrl}/api/v1/oauth/token`, { method: "POST", headers, body: new URLSearchParams(form).toString() });
    const t = await answer(res);
    if (t?.access_token) this.credential = t.access_token;
    return t;
  }
}

async function answer(res) {
  if (res.status === 204) return null;
  const type = res.headers.get("content-type") || "";
  if (res.ok) {
    if (type.includes("json")) return res.json();
    return new Uint8Array(await res.arrayBuffer());
  }
  let p = {};
  try { p = await res.json(); } catch { p = {}; }
  if (p.error && !p.code) p.code = p.error_description || "";
  throw new OpenSealError({ status: res.status, ...p });
}

/// Verify a webhook delivery (docs/40 §4, the Standard Webhooks scheme): `secret` is the
/// `whsec_…` value your operator gave you; `headers` the request's (`webhook-id`,
/// `webhook-timestamp`, `webhook-signature`); `body` its raw bytes or text, exactly as
/// received. Refuses a timestamp more than `toleranceSeconds` (5 minutes) from `now`.
/// Answers the parsed event; throws `OpenSealError` (`webhook_signature`) otherwise.
export async function verifyWebhook(secret, headers, body, { toleranceSeconds = 300, now = Date.now() } = {}) {
  const get = (k) => (typeof headers?.get === "function" ? headers.get(k) : headers?.[k] ?? headers?.[k.toLowerCase()]);
  const id = get("webhook-id");
  const ts = get("webhook-timestamp");
  const sig = get("webhook-signature");
  const refuse = (detail) => { throw new OpenSealError({ code: "webhook_signature", detail }); };
  if (!id || !ts || !sig) refuse("missing headers");
  if (!/^\d+$/.test(ts) || Math.abs(now / 1000 - Number(ts)) > toleranceSeconds) refuse("timestamp outside the tolerance");
  if (typeof secret !== "string" || !secret.startsWith("whsec_")) refuse("not a whsec_ secret");
  const key = Uint8Array.from(atob(secret.slice(6)), (c) => c.charCodeAt(0));
  const raw = typeof body === "string" ? enc.encode(body) : new Uint8Array(body);
  const signed = new Uint8Array([...enc.encode(`${id}.${ts}.`), ...raw]);
  const k = await crypto.subtle.importKey("raw", key, { name: "HMAC", hash: "SHA-256" }, false, ["verify"]);
  for (const entry of String(sig).split(" ")) {
    const [version, value] = entry.split(",");
    if (version !== "v1" || !value) continue;
    let mac;
    try { mac = Uint8Array.from(atob(value), (c) => c.charCodeAt(0)); } catch { continue; }
    // Web Crypto's verify compares in constant time.
    if (await crypto.subtle.verify("HMAC", k, mac, signed)) return JSON.parse(new TextDecoder().decode(raw));
  }
  return refuse("no signature matches");
}
