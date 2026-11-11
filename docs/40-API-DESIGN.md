# 40 — Public API, embedding and webhooks

**Status: Draft for owner.** The REST API every client uses, including our own web app. The OpenAPI 3.1 document
`api/openapi.yaml` (created in Phase 2) is the contract; this page is its design. Domain types are
[22](22-DATA-MODEL.md); state rules are [24](24-ENVELOPE-LIFECYCLE-AND-ROUTING.md).

## 1. Principles

- **API-first, dogfooded.** The web app calls only public endpoints (plus the ceremony endpoints of §6). Nothing the UI
  does is impossible through the API.
- **Resource-oriented JSON over HTTPS**, versioned in the path (`/api/v1`). Additive changes within a version;
  breaking changes need `/v2` and a 12-month overlap.
- **Envelope-centric** (DocuSign's root), with document-centric conveniences (SignNow's): a one-call
  `POST /envelopes` with documents, recipients and fields inline, and fine-grained sub-resources for editing.
- **Per-element edits.** Fields, recipients and documents are added, changed and removed by id; never "replace all"
  ([49](49-SIGNNOW-STUDY.md) §3).
- **Idempotency**: every `POST` accepts `Idempotency-Key`; replays within 24 h return the first response.
- **Optimistic concurrency**: `ETag` on envelopes; `If-Match` required on updates of drafts and corrections.
- **Errors**: RFC 9457 problem details with a stable `code` from [20](20-ERROR-CODE-REGISTRY.md), a `request_id`, and
  `errors[]` with JSON pointers for field-level problems. Never document content.
- **Pagination**: cursor-based (`?cursor=…&limit=…`), stable under inserts.
- **Time**: RFC 3339 UTC. **Ids**: UUIDv7 strings.
- **Rate limits**: per client and per account; `RateLimit` and `RateLimit-Policy` headers (IETF draft) and
  `Retry-After` on 429.

## 2. Authentication

| Client | Method |
| --- | --- |
| Our web app, staff users | OIDC or SAML login → session cookie (`HttpOnly`, `Secure`, `SameSite=Lax`) + CSRF token |
| Third-party apps acting for a user | OAuth 2.1 authorization code with PKCE; refresh tokens rotate |
| Server-to-server integrations | OAuth client credentials, or **JWT bearer grant (RFC 7523)** with the integration's public key, impersonating a consenting user (DocuSign's JWT grant model) |
| Simple scripts | Personal API keys, scoped, expiring, shown once, stored hashed |
| Recipients | Not API clients. Ceremony tokens only (§6) |

Scopes: `envelopes:read`, `envelopes:write`, `envelopes:send`, `templates:read`, `templates:write`, `bulk:send`,
`webhooks:manage`, `admin:users`, `admin:account`, `audit:read`. Access tokens: 1 h, JWT signed by the server, verified
by JWKS (OpenCalc's docs/59 pattern).

## 3. Resources

```
/api/v1
  /accounts/me                                  GET, PATCH            settings, defaults
  /envelopes                                    GET (search), POST    create draft or send in one call
  /envelopes/{id}                               GET, PATCH, DELETE    DELETE: drafts only
  /envelopes/{id}/send                          POST
  /envelopes/{id}/void                          POST {reason}
  /envelopes/{id}/correct                       POST (open), POST …/commit
  /envelopes/{id}/resend                        POST {recipient_ids?}
  /envelopes/{id}/documents                     GET, POST (multipart or URL import)
  /envelopes/{id}/documents/{doc}               GET (meta), PATCH (name, order), DELETE
  /envelopes/{id}/documents/{doc}/content       GET  ?version=normalized|sealed
  /envelopes/{id}/documents/{doc}/pages/{n}.png GET  (thumbnail)
  /envelopes/{id}/documents/combined            GET  sealed documents + certificate as one PDF
  /envelopes/{id}/certificate                   GET  certificate of completion PDF
  /envelopes/{id}/audit                         GET  audit events (JSON); ?format=pdf
  /envelopes/{id}/recipients                    GET, POST
  /envelopes/{id}/recipients/{r}                GET, PATCH, DELETE
  /envelopes/{id}/fields                        GET, POST (batch)  ?recipient_id=&document_id=
  /envelopes/{id}/fields/{f}                    GET, PATCH, DELETE
  /envelopes/{id}/form-data                     GET  every field's value by data label
  /envelopes/{id}/views/signing                 POST embedded signing URL for a recipient
  /envelopes/{id}/views/prepare                 POST embedded sending/preparing URL
  /envelopes/{id}/views/correct                 POST
  /templates …                                  as envelopes, plus /templates/{id}/envelopes (instantiate)
  /bulk-sends                                   POST {template_id, rows | csv}, GET
  /bulk-sends/{id}                              GET (progress), POST …/cancel
  /signing-links                                CRUD; GET …/{id}/qr.svg
  /webhooks                                     CRUD; POST …/{id}/test; GET …/{id}/deliveries; POST …/deliveries/{d}/redeliver
  /users, /groups, /permission-profiles, /brands, /ersd-versions, /api-clients, /retention-policies   (admin)
  /verify                                       POST a PDF → verification report (same code as offline)
```

### Create and send in one call

```http
POST /api/v1/envelopes
Idempotency-Key: 6f1c…
Content-Type: application/json

{
  "subject": "Please sign: Master Services Agreement",
  "message": "Hi — this is the MSA we discussed.",
  "status": "sent",
  "documents": [{ "name": "MSA.pdf", "content_base64": "…" }],
  "recipients": [
    { "ref": "client", "type": "signer", "name": "A. Client", "email": "a@example.com", "routing_order": 1,
      "auth": [{ "method": "email_otp" }] },
    { "ref": "ceo", "type": "signer", "name": "B. Vendor", "email": "b@example.com", "routing_order": 2 },
    { "type": "cc", "name": "Legal", "email": "legal@example.com", "routing_order": 3 }
  ],
  "fields": [
    { "recipient": "client", "document": 0, "type": "signature", "anchor": { "text": "/sig1/", "offset_y": -4 } },
    { "recipient": "client", "document": 0, "type": "date_signed", "anchor": { "text": "/date1/" } },
    { "recipient": "ceo", "document": 0, "type": "signature", "page": 3, "x": 72, "y": 640, "width": 180, "height": 40 }
  ],
  "reminders": { "first_after_days": 2, "every_days": 3 },
  "expires_in_days": 30
}
```

`ref` and indexes let one call wire recipients and fields before ids exist; the response returns every id.

### Statuses on the wire

The API reports OpenSeal's states ([24](24-ENVELOPE-LIFECYCLE-AND-ROUTING.md)). `completing` is reported as itself;
clients that only know DocuSign's set treat it as `signed`. A mapping table is in the API reference.

### Text tags

Uploaded documents may carry tags parsed at send when `"text_tags": true`:
`{{type:recipient_ref[:req][:label][:WxH]}}`, for example `{{signature:client}}`,
`{{text:client:req:company_name}}`, `{{date_signed:ceo}}`. Grammar and limits in `casual-sign-fields`
([30](30-PDF-PIPELINE.md) §5).

## 4. Webhooks

- **Subscriptions** per account (filter by event types, by sender, by template) and per envelope (`event_notification`
  on create, as DocuSign's per-envelope `eventNotification`).
- **Events** mirror the audit types ([32](32-AUDIT-TRAIL-AND-EVIDENCE.md) §3) that matter to integrators:
  `envelope.sent`, `envelope.delivered`, `envelope.completed`, `envelope.declined`, `envelope.voided`,
  `envelope.expired`, `envelope.corrected`, `envelope.purged`, `recipient.sent`, `recipient.delivered`,
  `recipient.auth_failed`, `recipient.completed`, `recipient.declined`, `recipient.reassigned`,
  `recipient.finish_later`, `recipient.bounced`, `template.created`, `template.updated`, `template.deleted`,
  `bulk_send.completed`.
- **Payload**: `{id, type, created_at, account_id, data: {envelope summary, recipient?}}`; documents never inline
  (clients fetch them with their token), which keeps payloads small and avoids pushing signed documents to a URL that
  may be misconfigured.
- **Signing**: the **Standard Webhooks** scheme: headers `webhook-id`, `webhook-timestamp`, `webhook-signature`
  (`v1,<base64 HMAC-SHA256 of id.timestamp.body>`); several active secrets for rotation; replay window 5 minutes.
  Optional mTLS to the receiver.
- **Delivery**: at-least-once; 10 s timeout; exponential backoff with jitter for 3 days (≈ 15 attempts); then the
  delivery is `failed` and visible in the API; manual redeliver; a subscription failing for 5 consecutive days is
  disabled with an email to its owner. Per-endpoint ordering is not guaranteed; every event carries the envelope
  `version` so receivers can discard stale ones.
- **SSRF**: webhook URLs must be HTTPS to public addresses; private, loopback, link-local and metadata ranges are refused
  at registration **and** at connect time (DNS rebinding) ([07](07-SECURITY-THREAT-MODEL.md) `SEC-W*`).

**As built (stage 2D, `T-2D`, delivery side; registration is the API's, `T-2C`).** `casual-sign-worker` delivers one
`deliver_webhook` job per `DeliverWebhook` effect to every active subscription of the account whose event types name
the event (or `*`) and whose envelope, if set, is this one.

- **Headers**: `webhook-id` is the job's id, the same on every attempt and every subscription, so receivers dedupe on
  it; `webhook-timestamp` is the attempt's Unix time; `webhook-signature` is `v1,<base64 HMAC-SHA256>` over
  `id.timestamp.body` for each of the subscription's secrets, space-separated (checked against the Standard Webhooks
  specification's published example). A secret is `whsec_` and base64 of at least 16 bytes, found by the reference
  the subscription stores (an environment variable or `_FILE`; `CS-WRK-0010`).
- **Body**: `{"id", "type", "created_at", "account_id", "data": {"envelope_id", "status", "version",
  "recipient_id"?}}`. `created_at`, `status` and `version` are the decision's, fixed when the effect was enqueued, so
  every attempt sends the same bytes. No names, addresses, subjects, values or documents.
- **Event types** are the engine's topics with the first underscore made a dot (`envelope.completed`), except
  `recipient.auth_failed` (the engine's lock topic) and `recipient.bounced` (its `auto_responded`) as listed above.
  The engine also emits `envelope.completing`, delivered under that name. Not emitted yet: `recipient.finish_later`,
  `template.*`, `bulk_send.completed` (no engine topic; rows proposed).
- **Delivery**: 10 s for the whole exchange, no redirects, 64 KiB of the answer read; 2xx is delivered. A failure is
  retried with exponential back-off (30 s doubling, capped at 12 h, equal jitter) for 15 attempts, about three days;
  each attempt is in `webhook_deliveries` (`pending`, then `delivered` or `failed` with the last status). A
  subscription delivered to is recorded as a job step, so a retry or a re-run after a crash skips it; the window
  between a receiver's answer and that record is the at-least-once repeat, with the same `webhook-id` and body.
- **SSRF**: only `https://` without user information; the host is resolved and every address checked before the
  request, and again by the HTTP client's resolver at connect time. Refused: private, loopback, link-local (the metadata
  address included), CGNAT, documentation, benchmarking, multicast, reserved, unspecified, IPv4-mapped and NAT64 IPv6
  of any of those, ULA and site-local IPv6, unless the operator allow-lists a range (`OPENSEAL_WEBHOOK_ALLOW`). A
  refused URL dead-letters the job (`CS-WRK-0008`) and logs the delivery `failed`; no byte reaches the address
  (integration test seen red only with both checks removed).
- **Not built here**: manual redeliver and disabling a subscription after five failing days (the API's, `T-2C`);
  sender and template filters (the subscription repository does not expose them yet); optional mTLS to receivers.

## 5. Embedding

**Views** return a single-use URL valid for 5 minutes that opens a session:

| View | Who | Returns to |
| --- | --- | --- |
| `signing` | A recipient with `embedded_client_user_id` | `return_url?event=completed|declined|cancelled|finish_later|auth_failed|session_timeout|expired` |
| `prepare` | A staff user (the API client's user) to add recipients and fields, then send | `return_url?event=sent|saved|cancelled` |
| `correct` | Same, for an in-flight envelope | As prepare |
| `template_edit` | Edit a template | As prepare |

The host may also use the **custom elements** from `sdk/` (`<openseal-signing>`, `<openseal-prepare>`), which wrap
the views in an iframe with a typed `postMessage` protocol (events, resize, theme tokens), as OpenCalc's
`<opencalc-sheet>` does for its editor (OpenCalc's docs/55). An iframe, not a shadow root, because the ceremony must
run on the OpenSeal origin: the signer's session and its evidence must not be reachable by the host page's scripts.
`frame-ancestors` is set per account from its allowed embedding origins.

An embedded recipient's authentication is the host's: the view request may carry `auth_asserted: {method, at}`, which
is recorded as `auth.asserted_by_host` ([49](49-SIGNNOW-STUDY.md) §5). Additional OpenSeal authentication can still be
required on top.

## 6. Ceremony endpoints (not public API)

Under `/s/{token}`: load the envelope for that recipient, authenticate, consent, fetch documents, save progress,
upload attachments, adopt signature, finish, decline, reassign. The token is opaque, single recipient, revocable,
expiring (default with the envelope), and exchanged on first use for a short session bound to the browser. These
endpoints are rate-limited per token and per IP and audited on every state change.

## 7. SDKs

- **TypeScript** client generated from the OpenAPI document, plus the custom elements (`sdk/`).
- **Rust**: `casual-sign-sdk` is the engine (fill, seal, verify without a server); the API client is generated.
- **Python, Java, C#, Go, PHP, Ruby** clients generated in CI from the same document (slice 8 ships TypeScript and
  Python; the rest follow).

## 8. Compatibility shims

A DocuSign-shaped compatibility endpoint (`/compat/docusign/v2.1/…`, envelopes, recipients, tabs, views, Connect
payloads) would make migration a configuration change for integrators. It is attractive and has trademark and legal
questions; `DEC-10` decides, and nothing is built before the owner answers.

## As built (stage 2C, `casual-sign-server`)

The OpenAPI 3.1 document is [`api/openapi.yaml`](../api/openapi.yaml): 68 operations, each with its `x-permission`
(the scope it needs, SEC-A05). The router is built from one table (`routes::table`), and a contract test keeps the
table and the document equal in both directions, scope by scope.

**Built.** Every row of §3 below is served, with these differences:

| §3 resource | As built |
| --- | --- |
| `/accounts/me` | `GET`; `PATCH {settings}` merges (the account's `workflow_policy` is validated as the engine's `Policy`) |
| `/envelopes` … `/form-data` | All, plus `GET /envelopes/{id}/status`. `GET /envelopes?q=` (`WEB-04`) finds envelopes whose subject, or a recipient's name or email, contains the text (any case; `%`, `_`, `\` literal; at most 200 characters), within the caller's account and, without `view_all`, their own. `PATCH …/recipients/{r}` takes `access_code` (Argon2id at rest, never returned): needed when `auth` gains `access_code`, refused when the resulting `auth` lacks it, deleted when `access_code` leaves `auth`; allowed while the engine allows the change (a draft, or a correction while sent; never once voided or completed). `/correct` is one call with the engine's change list (docs/24 As built); `…/commit` is not needed; the per-element recipient and field endpoints correct a sent envelope too (`tests/correct.rs`: email and authentication changed, the old link `401` at once and a new invitation queued, a recipient not reached removed and another added, fields added, a signer who acted refused `409`). Documents enter through `/documents` (JSON base64 or raw `application/pdf`), admitted and normalized by `casual-sign-sdk`; signed PDFs are kept as uploaded |
| `/documents/{doc}` `PATCH` | **Not built**: the engine has no rename change (row proposed) |
| `/documents/{doc}/pages/{n}.png` | **Not built** (thumbnails are rendered by pdf.js in the browser, ADR-007; a server thumbnail needs a renderer) |
| `/certificate`, `/documents/combined`, `/audit?format=pdf`, `content?version=sealed` | Answer `409 CS-API-0009` until the seal job (stage 2D) stores them; `GET /audit` (JSON) re-verifies the chain on every read |
| `/views/signing` | Built; only the API client that created the envelope may ask (WF-05, `CS-AUTH-0010`); `auth_asserted` records the host's opening and `auth.asserted_by_host` |
| `/views/prepare`, `/views/correct` | **Not built** (slice 9) |
| `/templates` | `GET`, `POST` (with roles), `GET /{id}`, `PATCH /{id}` (rename, `If-Match`); template documents, fields and `/templates/{id}/envelopes` are slice 3 |
| `/bulk-sends`, `/signing-links`, `/groups`, `/permission-profiles`, `/brands`, `/ersd-versions`, `/retention-policies`, `/verify` | **Not built** (their slices) |
| `/webhooks` | `GET`, `POST`, `GET /{id}`, `DELETE /{id}` (disable), `GET /{id}/deliveries`; `secret_refs` name secrets the operator provisioned. `…/test` and `…/redeliver` need the worker (2D) |
| `/users`, `/api-clients` | `GET`, `POST`, `GET /{id}`, `PATCH /users/{id}`, `DELETE` (remove member; revoke client) |
| §6 ceremony | `GET /s/{token}` (JSON; with `Accept: text/html` and not `application/json`, the web app's `sign.html`, which reads nothing and records nothing, `WEB-04`), `POST …/session`, `…/consent`, `…/authenticate` (access code), `GET …/documents/{doc}/content`, `POST …/documents/{doc}/viewed`, `…/adopt`, `PUT …/fields/{field}`, `POST …/finish`, `…/approve`, `…/decline`, `…/finish-later`, `…/reassign` |

**Authentication (§2).** Local login (`POST /auth/login`, Argon2id, an unknown email costs a wrong password's time)
gives an `HttpOnly`, `Secure`, `SameSite=Lax` session cookie (8 h) and a CSRF token every changing request echoes in
`X-CSRF-Token`; `POST /auth/logout`; `GET /auth/session`. API keys are `osk_` + 256 random bits, stored as SHA-256,
scoped and optionally expiring. OAuth clients use the client-credentials grant at `POST /oauth/token` (form or
JSON, HTTP Basic or body credentials, RFC 6749 errors) and get a one-hour ES256 JWT (`iss` the public URL, `aud`
`openseal-api`), verified by `GET /.well-known/jwks.json`; the signing key comes from the secrets crate
(`OPENSEAL_JWT_SIGNING_KEY`). Every request re-checks the credential: a revoked key or client, an expired token, a
removed member or a disabled user is refused on its next request. A credential acts as a member and holds at most the
scopes of that member's permission profile, narrowed by its own. **Not built:** OIDC and SAML login, WebAuthn
(`webauthn-rs` is MPL-2.0, outside `deny.toml`), OAuth authorization code with PKCE, the JWT bearer grant.

**Requests.** RFC 9457 problems with `code`, `request_id` (also `X-Request-Id`) and JSON-pointer `errors`; the
router's own refusals (no route, wrong method, too large) are problems too. `Idempotency-Key` on any guarded `POST`:
the first response is stored in the same account (a response holding a secret is not stored, and its replay answers
`409 CS-API-0009`), a replay answers it with `Idempotency-Replayed: true`, a different body is `CS-API-0004`, a
request still running is `CS-API-0011`, and engine command ids derive from the key so a replayed command is the
engine's replay too. `ETag: "v<version>"` on envelopes; `If-Match` is required on `PATCH` and `DELETE` of envelopes,
recipients, fields and documents, and on `/correct` (`428 CS-API-0008` without, `412 CS-WF-0002` stale). Cursor
pagination on `GET /envelopes` (stable under inserts). Rate limits per principal, per ceremony token, per client
address and per login name, with `RateLimit`, `RateLimit-Policy` and `Retry-After`. Every response carries a strict
CSP (`default-src 'none'; frame-ancestors 'none'`), `nosniff`, `no-referrer`, HSTS, `X-Frame-Options: DENY` and
`Cache-Control: no-store`. Body limits per route (docs/21 §API).

**The web app (`WEB-04`).** With `OPENSEAL_WEBAPP_DIR` set, the server reads `webapp/` once at start into memory
(only the web app's file kinds by extension; `e2e/`, `tests/`, Node manifests and symlinks skipped; at most 4,096
files and 64 MiB) and answers any `GET` no route matched from it, `/` being `index.html`; a request can name only a
file read then, so no request path reaches the file system. Pages carry docs/47's Content Security Policy with
`frame-ancestors 'none'` and `Permissions-Policy: geolocation=(self)`; other files keep the strict API policy.
`vendor/` and `fonts/` are `Cache-Control: public, max-age=31536000, immutable`; the rest `no-cache`; `sign.html`
`no-store`. Without the setting the server is API-only, as before.

**Evidence.** Every command's events carry the client address (the socket peer; `Forwarded` / `X-Forwarded-For`
only from configured trusted proxies, right-most untrusted hop), the user agent (512 bytes), the authentication
method (`email_link` for the ceremony plus methods passed; `account_login` for staff credentials, as the audit
vocabulary has no API-key or OAuth-client method yet) and a SHA-256 naming the session, token record or client.
Downloads by staff record `document.downloaded` (`certificate.downloaded` for the certificate). Logs carry the
request id, method, route template, status and duration only. **Signer location (GEO-01).** The envelope's
`signing_options.capture_location` (absent when off) is part of the envelope API. The ceremony view answers
`capture_location`, and the page asks the device only when it is true. With it on, the session, consent, viewed,
adopt, finish, approve, decline and withdraw-consent requests record `context.location` (docs/32 §2): the device's
fix from the body's `location` (`{latitude, longitude, accuracy_m}`); else the approximation of the client address
in the operator-supplied GeoIP database (`OPENSEAL_GEOIP_DB`, named by its type and build date) with the reason,
`declined` when the body says `{declined: true}` and `unavailable` otherwise (the opening, before the page knows the
setting, is `unavailable`); else, with no database, no address or no record, the reason alone. Never omitted, so a
refusal never blocks signing. With it off nothing is recorded, whatever the body says.

**Persistence.** Each request's commands run in one transaction through the one decide-and-record path the worker
uses too, `casual_sign_host` (docs/24 §As built: effects): the engine's state is the envelope's authority
(`envelope_states`, migration 0008, row-locked for the request), the envelope, recipient and document rows are its
projection, events are appended through `PendingEvent::into_audit`, `RevokeTokens` is performed in the transaction,
and every other effect becomes a job under the job contract of docs/24 (`kind`, `idempotency_key`
`effect:<envelope>:<command>:<index>`, `payload` `{envelope_id, effect, decided_at, version, status}`, `run_at`).
Migration 0009 adds the API's own tables and columns. Invitation tokens are minted by the worker as it sends
(`issue_invitation_token` remains for tests); embedded view tokens by `/views/signing`.

**Sealed outputs.** `GET /certificate` serves the certificate of completion the seal job rendered on its own (trail
embedded) and sealed (`envelopes.certificate_sha256`); `GET /documents/combined` serves, for an envelope of one
document, its sealed version (the certificate is appended before sealing); `content?version=sealed` the sealed
version. Each answers `409 CS-API-0009` until the seal is stored; `combined` also for an envelope of several
documents, which needs a PDF merge the engine does not have (proposed row). `GET /audit?format=pdf` is not built.

**Ceremony.** The first `POST /s/{token}/session` binds the link to the browser (a second secret, SHA-256 at rest, in
an `HttpOnly`, `SameSite=Strict`, `Secure` cookie, `Secure` dropped only with the staff cookie's development
setting `OPENSEAL_DEV_INSECURE_KEY=1`, since WebKit keeps no `Secure` cookie over `http://localhost`); any other
browser is `403 CS-AUTH-0009`. Changing calls must be
`application/json`. Access codes are Argon2id (SEC-A03); one-time codes by email or SMS answer `CS-API-0014` until
slice 5. `POST /s/{token}/adopt` stores the image, then the capture document the seal job reads
(`{"kind":"image","image":"<hex>"}`), and answers its hash as `adoption_id`; a signature or initials value must name
a capture this recipient adopted (`422 CS-API-0001` otherwise), so no value can draw another person's capture.
`POST /s/{token}/withdraw-consent` withdraws consent to electronic records (declining a required action).

**Tests** (`server/casual-sign-server/tests/`, PostgreSQL 17 through `OPENSEAL_TEST_DATABASE_URL`): the document and
the table agree; one scenario calls every operation and drives a two-signer sequential envelope through the ceremony
to `completing` with its `seal_envelope` job enqueued, and withdraws consent on another; `tests/location.rs` records
location on, off, declined, unavailable, with and without a GeoIP database (built in the test), seen red with the
capture removed (`CS-WF-0019`); the worker's `tests/end_to_end.rs` takes a two-signer envelope through this API and
the worker to `completed` and verifies the sealed PDF and the certificate with ours and pyHanko; tenant isolation generated from the document, every operation
with an id called by another account (and with another envelope's sub-ids), `404 CS-API-0002`, with RLS on and
disabled; authentication and authorization refusals; evidence capture and trusted-proxy handling; no address, user
agent or token in the logs. Each guard named in the T-2C report was removed once and its test seen red.
`tests/web.rs` (`WEB-04`): the web app's files, types, cache and CSP headers, nothing outside it (tests, manifests,
`..`), the signing page for a browser and JSON for the API at `/s/{token}`; `q` search on subject, names and emails,
wildcards literal (seen red without the escaping), never another account's (RLS on and disabled; seen red with RLS
disabled and the account condition removed); the access code patched on a draft and in a correction, refused once
voided, the link taking the new code and not the old; the ceremony cookie `Secure` unless the server is plain-HTTP
development (seen red when it was always `Secure`, which broke signing in WebKit on the Compose stack). The server
binary's `migrate` and `healthcheck` commands and S3 blob settings are exercised by the Compose stack (docs/65).
