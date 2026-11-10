// API calls for the WEB-02 screens (Home, Templates, Admin), over the client that
// `api.js` builds: same CSRF, Idempotency-Key, If-Match and problem-details handling,
// because every call goes through its `request`. Kept apart from api.js so the two
// can change independently (WEB-02 brief).
//
// - Templates: `GET/POST /api/v1/templates`, `GET/PATCH /api/v1/templates/{id}`
//   (api/openapi.yaml; the server keeps name, email subject and message, and roles).
// - Template documents and fields are docs/40's slice-3 design ("as envelopes"):
//   `POST /templates/{id}/documents`, `GET …/documents/{doc}/content`,
//   `POST /templates/{id}/fields`. Today's server answers them with 404 or 405;
//   `templateDocsUnsupported(err)` tells a caller that this is "not yet", not a failure.
// - Users: `GET/POST /api/v1/users`, `PATCH/DELETE /api/v1/users/{id}`.
// - API clients: `GET/POST /api/v1/api-clients`, `DELETE /api/v1/api-clients/{id}`.
//
// No DOM here, so Node's tests run it.

import { toBase64 } from "./api.js";

/// Add the WEB-02 calls to `api` (a client from `createClient`). Returns `api`.
export function extend(api) {
  const data = async (p) => (await p).data;
  const T = (id) => `/api/v1/templates/${encodeURIComponent(id)}`;
  const etagOf = (v) => (v && Number.isInteger(v.version) ? `"v${v.version}"` : null);
  const req = api.request;

  api.templates = {
    list: () => data(req("GET", "/api/v1/templates")),
    /// `{template, etag}`.
    async get(id) {
      const r = await req("GET", T(id));
      return { template: r.data, etag: r.etag || etagOf(r.data) };
    },
    create: (body) => data(req("POST", "/api/v1/templates", { body })),
    rename: (id, etag, name) => data(req("PATCH", T(id), { body: { name }, ifMatch: etag })),
    // Slice 3 (docs/40): not in api/openapi.yaml yet.
    addDocument: (id, name, bytes) => data(req("POST", `${T(id)}/documents`, { body: { name, content_base64: toBase64(bytes) } })),
    addFields: (id, items) => data(req("POST", `${T(id)}/fields`, { body: { items } })),
    documentContent: async (id, doc) => (await req("GET", `${T(id)}/documents/${encodeURIComponent(doc)}/content`, { raw: true })).blob,
  };

  api.users = {
    list: () => data(req("GET", "/api/v1/users")),
    create: (body) => data(req("POST", "/api/v1/users", { body })),
    patch: (id, body) => data(req("PATCH", `/api/v1/users/${encodeURIComponent(id)}`, { body })),
    remove: (id) => data(req("DELETE", `/api/v1/users/${encodeURIComponent(id)}`)),
  };

  api.apiClients = {
    list: () => data(req("GET", "/api/v1/api-clients")),
    create: (body) => data(req("POST", "/api/v1/api-clients", { body })),
    revoke: (id) => data(req("DELETE", `/api/v1/api-clients/${encodeURIComponent(id)}`)),
  };

  /// How many envelopes have `status`, counting at most `cap` (one page of the list;
  /// the API has no count). `{n, more}`: `more` when the list goes on past `cap`.
  api.countEnvelopes = async (status, cap = 200) => {
    const page = await api.listEnvelopes({ status, limit: cap });
    return { n: (page.items || []).length, more: !!page.next_cursor };
  };

  return api;
}

/// Whether an error from a slice-3 template call means "this server does not have the
/// endpoint yet" (404 Not found, 405 Method not allowed), as opposed to a failure.
export function templateDocsUnsupported(err) {
  return !!err && (err.status === 404 || err.status === 405);
}
