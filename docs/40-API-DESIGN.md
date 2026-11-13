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
  `errors[]` with JSON pointers for field-level problems. Never document content. A plan refusal (`CS-PLAN-0002` to
  `CS-PLAN-0005`, 403; `PLAN-04`) adds `meter`, `limit`, `used` and `period_end` where they apply, nothing else.
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
  /admin-events                                 GET                   workspace admin log (ORG-05), json or csv
  /auth/workspaces                              GET                   the caller's workspaces by organization (ORG-04)
  /auth/switch                                  POST                  {account_id} → a new session in that workspace (ORG-04)
  /organizations/me                             GET, PATCH            the session workspace's organization (ORG-03)
  /organizations/me/workspaces                  GET, POST             ; /{id} GET, POST …/archive, POST …/join
  /organizations/me/admins                      GET, POST             ; /{user} PATCH, DELETE
  /organizations/me/audit                       GET                   organization admin log, json or csv
  /envelopes                                    GET (search), POST    create draft or send in one call
                                                ?waiting_for=me (Inbox), folder=, deleted=true, recipient=, date_field=
  /envelopes/{id}                               GET, PATCH, DELETE    DELETE: drafts; ended uncompleted: from lists
  /envelopes/{id}/send                          POST
  /envelopes/{id}/void                          POST {reason}
  /envelopes/{id}/correct                       POST (open), POST …/commit
  /envelopes/{id}/resend                        POST {recipient_ids?}
  /envelopes/{id}/documents                     GET, POST (multipart or URL import)
  /envelopes/{id}/documents/{doc}               GET (meta), PATCH (name, order), DELETE
  /envelopes/{id}/documents/{doc}/content       GET  ?version=normalized|sealed
  /envelopes/{id}/documents/{doc}/pages/{n}.png GET  (thumbnail)
  /envelopes/{id}/documents/combined            GET  sealed documents + certificate as one PDF
  /envelopes/{id}/certificate                   GET  certificate of completion PDF; envelope certificate once ended
  /envelopes/{id}/sign-link                     POST the signed-in member's own signing link (Inbox)
  /envelopes/{id}/restore                       POST (planned, ADR-031 Proposed)
  /envelopes/{id}/audit                         GET  audit events (JSON); ?format=pdf
  /envelopes/{id}/recipients                    GET, POST
  /envelopes/{id}/recipients/{r}                GET, PATCH, DELETE
  /envelopes/{id}/recipients/{r}/host           POST staff hosts an in-person signer → one-time signing URL
  /envelopes/{id}/fields                        GET, POST (batch)  ?recipient_id=&document_id=
  /envelopes/{id}/fields/{f}                    GET, PATCH, DELETE
  /envelopes/{id}/form-data                     GET  every field's value by data label
  /envelopes/{id}/views/signing                 POST embedded signing URL for a recipient
  /envelopes/{id}/views/prepare                 POST embedded sending/preparing URL
  /envelopes/{id}/views/correct                 POST
  /templates …                                  as envelopes, plus /templates/{id}/envelopes (instantiate);
                                                ?deleted=true, POST …/{id}/restore (Deleted view)
  /folders                                      GET, POST; /folders/{id} PATCH, DELETE; POST …/{id|none}/envelopes
  /bulk-sends                                   POST {template_id, name?, csv | rows, validate_only?}, GET
  /bulk-sends/{id}                              GET (progress and rows), POST …/send (next 10 rows), POST …/cancel
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
- **Manual redeliver and a test event** (`UXW-32`, `UXW-33`) queue the same `send_webhook_delivery` job, so they pass
  the same checks and are recorded the same way.
- **Not built here**: disabling a subscription after five failing days (the API's, `T-2C`);
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
is recorded as `auth.asserted_by_host` ([49](49-SIGNNOW-STUDY.md) §5). Only the API client that created the envelope
acts as its host (`envelopes.host_client_id`, WF-05): any other client of the account or a staff session is refused
`403 CS-AUTH-0010`, another account's client `404` as for an envelope that does not exist. Additional OpenSeal authentication can still be
required on top.

## 6. Ceremony endpoints (not public API)

Under `/s/{token}`: load the envelope for that recipient, authenticate, consent, fetch documents, save progress,
upload attachments, adopt signature, finish, decline, reassign. The token is opaque, single recipient, revocable,
expiring (default with the envelope), and exchanged on first use for a short session bound to the browser. These
endpoints are rate-limited per token and per IP and audited on every state change.

**The view** (`GET /s/{token}`, and the answer of every changing call): `envelope` (`id`, `status`, `subject`,
`message`, `signing_options`, `documents`, `expires_at`), `recipient`, `fields` (this recipient's), `capture_location`,
`consent_required` (`{version, sha256, url}` or `null`), `auth_required`, and `sender`:

| Member | Meaning |
| --- | --- |
| `sender.name` | The sending user's name as the account holds it now (`null` once they are no longer a member) |
| `sender.email` | The sending user's email address (`null` likewise) |
| `sender.organisation` | The account's brand name (`settings.branding.name`), else the account's name |
| `consent_required.url` | Where the full disclosure is read: `GET /s/{token}/disclosure` answers `{version, sha256, text}`, `sha256` over the text's UTF-8, the hash consent records. Present only when the account has published that text (an intact `ersd_versions` row whose hash the policy names) |
| `envelope.expires_at` | When the envelope expires (`null` for never), so the page can say "sign by" |
| `envelope.documents`, `fields` | Empty (`[]`) until the recipient has passed every authentication they need (`auth_required` empty, not locked): the link alone names no document and no field (`SEC-CER-01`). `subject` and `message` stay, as the invitation already carried them |

The signer cannot judge whether a request is genuine without knowing who sent it (UX-01 audit, signer P1). The
members above and `/disclosure` are served (`UXW-34`, As built below); the mock answers them the same way.

## 7. SDKs

- **TypeScript** client generated from the OpenAPI document, plus the custom elements (`sdk/`).
- **Rust**: `casual-sign-sdk` is the engine (fill, seal, verify without a server); the API client is generated.
- **Python, Java, C#, Go, PHP, Ruby** clients generated in CI from the same document (slice 8 ships TypeScript and
  Python; the rest follow).

## 8. Compatibility shims

A DocuSign-shaped compatibility endpoint (`/compat/docusign/v2.1/…`, envelopes, recipients, tabs, views, Connect
payloads) would make migration a configuration change for integrators. It is attractive and has trademark and legal
questions; `DEC-10` decides, and nothing is built before the owner answers.

## Platform console API (not `/api/v1`)

The platform console (docs/23 §5) has its own API, `/console/v1`, served only by the separate `casual-sign-console`
binary on a private listener, with operator sessions (`__Host-os_op`, TOTP) instead of staff sessions or tokens. Its
contract is `api/console-openapi.yaml`, kept equal to the console's route table by its own contract test; nothing in it
is part of the public API or its compatibility promise. As built: docs/23 §5.6.

## As built (stage 2C, `casual-sign-server`)

The OpenAPI 3.1 document is [`api/openapi.yaml`](../api/openapi.yaml): 102 operations (68 at stage 2C, 19 added by `WEB-06`, 9 by `WEB-19`, the rest by later rows), each with its `x-permission`
(the scope it needs, SEC-A05). The router is built from one table (`routes::table`), and a contract test keeps the
table and the document equal in both directions, scope by scope.

**Built.** Every row of §3 below is served, with these differences:

| §3 resource | As built |
| --- | --- |
| `/accounts/me` | `GET`; `PATCH {settings}` merges (the account's `workflow_policy` is validated as the engine's `Policy`); the change and its `workspace.settings_changed` admin event commit together (`ORG-05`) |
| `/admin-events` | `GET ?cursor&limit&format=json\|csv&verify=page\|full` (`admin:account`, `ORG-05`): the workspace's admin audit log, oldest first; each item has `seq`, `at`, `action`, `hash`, `prev` and `event` (the canonical JSON: actor, target ids, changed keys with old and new values, secrets as `"rotated"`, request id, IP; `null` for stored bytes a JSON value cannot hold, such as a number beyond `f64`, which the CSV carries as stored). Each page is verified as read: linked to the event at its cursor, the last page to the stored head, each `at` to its bytes, so walking the log by cursor checks every link once (`verify=page`, the default); `verify=full` re-verifies the whole log first (`500 CS-DB-0014` when broken; another `verify` value is `422 CS-API-0001`); CSV columns `seq,at,action,hash,prev,event`, next cursor in `X-Next-Cursor` |
| `/organizations/me…` | ORG-03 (docs/23 §2.2, §6). Staff session only; the organization is the session workspace's, never a request value, and the caller's `organization_admins` row is read on every request (`SEC-O06`): no role, or an action the role lacks, is `403 CS-AUTH-0006`. `GET`/`PATCH /organizations/me` (name); `/workspaces` lists, creates (`org.workspaces.create`) and reads workspaces, `POST …/{id}/archive` archives one, `POST …/{id}/join {profile}` (owners and admins only, never delegated admins, `SEC-O07`) makes the caller a member, writing `member.added` (`via: organization`) in the workspace's log and `org.workspace_joined` in the organization's in one transaction; an archived workspace is `409 CS-ORG-0010`. `/admins` (owners only to change): add `{user, role}` (the user must be an enabled member of one of the organization's workspaces, else `422 CS-ORG-0018`), change role, remove; leaving no enabled owner is `409 CS-ORG-0008`. `GET /audit?cursor&limit&format=json\|csv&verify=page\|full` answers the organization's log as `/admin-events` does. Every change appends its event through `OrgTx::admin_event`. Another organization's workspace or admin is `404 CS-API-0002` |
| `/envelopes` … `/form-data` | All, plus `GET /envelopes/{id}/status`. `GET /envelopes?q=` (`WEB-04`) finds envelopes whose subject, or a recipient's name or email, contains the text (any case; `%`, `_`, `\` literal; at most 200 characters), within the caller's account and, without `view_all`, their own. `PATCH …/recipients/{r}` takes `type` on a draft only (`UX-12`; a correction keeps the type, `409`; the recipient keeps its id, fields and authentication) and `access_code` (Argon2id at rest, never returned): needed when `auth` gains `access_code`, refused when the resulting `auth` lacks it, deleted when `access_code` leaves `auth`; allowed while the engine allows the change (a draft, or a correction while sent; never once voided or completed). `/correct` is one call with the engine's change list (docs/24 As built); `…/commit` is not needed; the per-element recipient and field endpoints correct a sent envelope too (`tests/correct.rs`: email and authentication changed, the old link `401` at once and a new invitation queued, a recipient not reached removed and another added, fields added, a signer who acted refused `409`). Documents enter through `/documents` (JSON base64 or raw `application/pdf`), admitted and normalized by `casual-sign-sdk`; signed PDFs are kept as uploaded |
| `/documents/{doc}` `PATCH` | **Not built**: the engine has no rename change (row proposed) |
| `/documents/{doc}/pages/{n}.png` | **Not built** (thumbnails are rendered by pdf.js in the browser, ADR-007; a server thumbnail needs a renderer) |
| `/certificate`, `/documents/combined`, `/audit?format=pdf`, `content?version=sealed` | Answer `409 CS-API-0009` until the seal job (stage 2D) stores them; `GET /audit` (JSON) re-verifies the chain on every read |
| `/views/signing` | Built; only the API client that created the envelope may ask (WF-05, `CS-AUTH-0010` to another client of the account or a staff session; `404` to another account's client, nothing recorded; `tests/auth.rs`); `auth_asserted` records the host's opening and `auth.asserted_by_host` |
| `/views/prepare`, `/views/correct` | **Not built** (slice 9) |
| `/templates` | `GET`, `POST` (with roles), `GET /{id}` (with documents and fields), `PATCH /{id}` (name, email subject and message, `If-Match`), and editing (`WEB-06`, below); `/templates/{id}/envelopes` is slice 3 |
| `/ersd-versions` | `ERSD-01`. Scope `admin:account`. `POST {text, language?}` publishes `text` as the next version of `language` (`en` when absent; one more than its highest) and sets `settings.workflow_policy.ersd = {version: "<n>", hash}` in the same transaction, with `ersd.published` and `workspace.settings_changed` on the admin log; answers `201 {id, version, label, language, sha256, published_at}`, never the text. Envelopes already sent then ask for consent to the new version (consent binds version and hash). Published rows are never changed: a new text is a new version. An empty or blank text, one with a NUL, a language tag that is not 2 to 35 letters, digits and `-` starting with a letter, or an unknown member is `422 CS-API-0001`; over 100,000 bytes `413 CS-API-0006`. `GET` answers `{current, items}`: `current` the disclosure the policy names with its text (`text` null when no intact published row has that hash) or null, `items` the published versions newest first, at most 100, without text. `tests/ersd_publish.rs`; seen red without the routes (`404 CS-API-0002`) |
| `/bulk-sends` | `UXW-04`. `POST` (scope `bulk:send`, and `envelopes:write` and `envelopes:send` as `POST /envelopes` with `status: sent` needs; `POST /{id}/send` needs the same; `403` otherwise) checks a list against a template of the account with a document and a role: CSV text (a header, then one row per envelope; a line with no value in any cell is skipped) or JSON rows, columns `<role>::name` and `<role>::email` per role, matched ignoring case and surrounding spaces. A header that does not fit is `422` (`CS-BLK-0004` missing at `/columns`, `CS-BLK-0005` unknown or repeated at `/columns/{i}`); no row, over 1,000 or unreadable CSV `422 CS-BLK-0007`. Each row's problems (`CS-BLK-0001` to `0003`, `0006`) are answered with their column; such a row is stored `failed` and never sent. `validate_only` stores nothing and answers `200 {columns, row_count, valid, rows}`; otherwise `201` the batch with its rows, `queued`. `POST /{id}/send` (its sender only, `403` otherwise) sends the next 10 pending rows, each made and sent as `POST /envelopes` does (the same code path) in its own transaction, the row locked `FOR UPDATE SKIP LOCKED` so two callers never send one row twice; a refused row is `failed` with the refusal's code and the rest go on; the caller repeats it until `counts.pending` is 0, when the batch is `completed`. `POST /{id}/cancel` leaves pending rows unsent (`409 CS-WF-0001` once finished). `GET` and `GET /{id}` (scope `envelopes:read`) show the caller's own, or every one to an administrator or a member who sees every envelope; another account's is `404`. Each sent envelope carries `bulk_send_id`. `bulk_send.completed` is not emitted yet (`UXW-47`). `tests/bulk_send.rs`; seen red without the routes (`404 CS-API-0002`) |
| `/signing-links`, `/groups`, `/permission-profiles`, `/brands`, `/retention-policies`, `/verify` | **Not built** (their slices) |
| `/webhooks` | `GET`, `POST`, `GET /{id}`, `PATCH /{id}`, `DELETE /{id}` (disable), `GET /{id}/deliveries`, `POST /{id}/test`, `POST /{id}/deliveries/{d}/redeliver` (`UXW-31..33`, As built below); `secret_refs` name secrets the operator provisioned |
| `/users`, `/api-clients` | `GET`, `POST`, `GET /{id}`, `PATCH /users/{id}`, `DELETE` (remove member; revoke client); `GET`/`PATCH /users/me` (`UXW-37`, As built below) |
| §6 ceremony | `GET /s/{token}` (JSON; with `Accept: text/html` and not `application/json`, the web app's `sign.html`, which reads nothing and records nothing, `WEB-04`), `POST …/session`, `…/consent`, `…/authenticate` (access code), `…/otp` and `…/otp/verify` (email one-time code, SEC-A02: `recipient.auth_challenged` on sending, `auth_passed` or `auth_failed` on checking, method `email_otp`; the code is drawn and emailed by the worker job `send_email_otp` and stored only as Argon2id), `GET …/documents/{doc}/content`, `POST …/documents/{doc}/viewed`, `…/adopt`, `PUT …/fields/{field}`, `POST …/finish`, `…/approve`, `…/recipients` (an agent, intermediary or editor names later recipients not yet reached, `{recipients: [{id, name?, email?}]}`, at most 100; the engine's `RecipientEdit`, recorded as `envelope.corrected`; their view lists `later_recipients`, nobody else's; `VS-02`), `…/decline`, `…/finish-later`, `…/reassign` |

**Authentication (§2).** Local login (`POST /auth/login`, Argon2id, an unknown email costs a wrong password's time)
gives an `HttpOnly`, `Secure`, `SameSite=Lax` session cookie (8 h) and a CSRF token every changing request echoes in
`X-CSRF-Token`; `POST /auth/logout`; `GET /auth/session`. **Workspace switching (`ORG-04`, docs/23 §2.3):** `GET
/auth/workspaces` lists, by organization, the workspaces the session's person holds an enabled membership in (read
through the session's own hash, `openseal_user_workspaces`), the session's own marked `current`; `POST /auth/switch
{account_id}` ends the session and issues a new cookie and CSRF token in that workspace, carrying the same sign-in
method, time and expiry (a switch never extends a session; two concurrent switches from one session cannot both
succeed). No enabled membership there, or no such workspace, is `403 CS-ORG-0001`; an API key or access token, which
belongs to one workspace, gets `422 CS-API-0001`. The workspace always comes from the credential: no header or
parameter names another (`SEC-O05`). The target organization's sign-in policy check (`CS-ORG-0007`) waits for
organization policy and SSO (`ORG-31`). API keys are `osk_` + 256 random bits, stored as SHA-256,
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
(`issue_invitation_token` remains for tests); embedded view tokens by `/views/signing`; in-person tokens (purpose
`in_person`, naming their host, migration 0014) by `/recipients/{r}/host`.

**Sealed outputs.** `GET /certificate` serves the certificate of completion the seal job rendered on its own (trail
embedded) and sealed (`envelopes.certificate_sha256`); `GET /documents/combined` serves, for an envelope of one
document, its sealed version (the certificate is appended before sealing); `content?version=sealed` the sealed
version. Each answers `409 CS-API-0009` until the seal is stored; `combined` also for an envelope of several
documents, which needs a PDF merge the engine does not have (proposed row). `GET /audit?format=pdf` is not built.

**Ceremony.** The first `POST /s/{token}/session` binds the link to the browser (a second secret, SHA-256 at rest, in
an `HttpOnly`, `SameSite=Strict`, `Secure` cookie, `Secure` dropped only with the staff cookie's development
setting `OPENSEAL_DEV_INSECURE_KEY=1`, since WebKit keeps no `Secure` cookie over `http://localhost`); any other
browser is `403 CS-AUTH-0009`. Changing calls must be
`application/json`. Access codes are Argon2id (SEC-A03). One-time codes (SEC-A02): `POST /s/{token}/otp {method?}`
sends one by email (`email_otp`, the default), SMS (`sms_otp`) or a voice call (`voice_otp`, read digit by digit), the
last two to the recipient's E.164 `phone` (required with them, `422` otherwise) through the worker's `Messenger`
(slice 5, VS-05); `POST /s/{token}/otp/verify {code, method?}` passes the open code's method. `CS-API-0014` for a
method the recipient does not require. Sign-in through an identity provider (`sso`, RAUTH-01): the view lists
the operator's providers as `sso_providers` while `sso` is pending; `POST /s/{token}/sso {provider}` answers the view
with `sso_authorization_url` (authorization code with PKCE S256, `state` and `nonce`; the server keeps the nonce and
verifier, `state` only hashed); the provider sends the browser back to `/s/oidc`, where the page finds its link in the
tab's session storage and calls `POST /s/{token}/sso/verify {state, code}`. The sign-in closes at first use; the ID
token must be signed by the provider's JWKS with an asymmetric algorithm, name its issuer and the client, be unexpired
by the server's clock, carry the nonce and assert a verified email equal to the recipient's. A refusal is `403` with
the view, counted to the lockout; an unreachable provider is `502 CS-API-0016`, counted nothing. `POST /s/{token}/adopt` stores the image, then the capture document the seal job reads
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

## As built (`WEB-06`, server side of the UX audit)

| Endpoint | As built |
| --- | --- |
| `GET /contacts?q=&limit=` | Recipient autocomplete: the account's past recipients, one per email address (any case), the name last used with it, most recently used first, `limit` 1–50 (default 10); `q` matches name or email as `GET /envelopes?q=` does (wildcards literal). From the envelopes the caller may see: a member without `view_all` gets only the people they sent to. Scope `envelopes:read`. `tests/contacts.rs`, RLS on and off; seen red with the account condition removed and RLS off |
| `POST /envelopes/{id}/documents/{doc}/detect-fields` | Suggested fields for the delivered document, by `casual_sign_sdk::Engine::detect_fields` (docs/30 §5 "Field auto-detection"): underscore lines, painted rules and boxes with the labels near them, and the document's AcroForm fields, as `{document_id, type, page, x, y, width, height, source, cue?, confidence}` in the field endpoints' geometry, so a suggestion posted to `/fields` with a `recipient_id` lands where it was suggested; at most 500, `truncated` when a bound was reached. Changes and records nothing. Scope `envelopes:write`. `tests/detect.rs` |
| `GET /envelopes/{id}/documents/{doc}/content?version=current` | The document as it stands: its sealed version once sealed; before, a **preview** made on request by the flattener from the delivered document, with the values of recipients who have completed and the sender's locked values (a recipient's values in progress are not shown), and a red "PREVIEW - NOT SIGNED" banner at the top of every page. A preview is never stored, hashed into the envelope or sealed: the delivered document and its hash are untouched (decision recorded here: a separate document, never a change to the evidence). `X-OpenSeal-Document` says `sealed` or `preview`. Recorded as `document.downloaded` with the SHA-256 of the bytes served once sent. Signatures are drawn from their captures by `casual_sign_host::capture`, the seal job's reader. `tests/preview.rs`; seen red with the in-progress filter removed (the draft value appeared) |
| `POST /users {…, invite: true}`, `POST /users/{id}/invite`, `POST /auth/accept-invite` | An administrator adds a member by email and the worker mails a one-time set-password link (job `send_user_invitation`, no envelope: 256 random bits, base64url, only its SHA-256 stored, 7 days, in the URL fragment `…/#/accept-invite?token=`); sending again revokes the earlier link; `accept-invite {token, password}` spends it once, sets the password (Argon2id), ends the member's sessions in every account (`SEC-ID-01`); an unknown, expired, spent or revoked link, or a disabled member, is `401 CS-AUTH-0002` alike; rate-limited as login. `GET /users/{id}` shows the latest invitation's state. Worker `tests/user_invite.rs`; seen red with the earlier link's revocation removed (the old link was accepted) |
| Template editing: `DELETE /templates/{id}`, `POST …/duplicate`, `POST …/documents`, `DELETE …/documents/{doc}`, `GET …/documents/{doc}/content`, `POST …/roles`, `PATCH`/`DELETE …/roles/{role}`, `GET`/`POST …/fields`, `PATCH`/`DELETE …/fields/{f}` | Every change raises the template's version (`ETag`), checked against `If-Match` (required on `PATCH` and `DELETE`, honoured on `POST`; stale `412`). Documents are admitted and normalized as uploads; their stored PDFs are write-once and shared by copies. Fields take the envelope field shape bound to `role_id` and are checked by the model, against the template's roles and the document's page count; `PATCH` merges the members given, `null` removing one (as an envelope field's `PATCH`; UX-11), and checks the whole field again. Every field setting the editor offers (tooltip, placeholder, value, read-only, options, custom options, validation, format) is kept and read back as sent: `a_template_field_keeps_every_setting_and_a_patch_clears_one_with_null`, seen red (`422` on a `null`) before the merge. Removing a role or document removes its fields. Duplicate copies roles, documents and fields under new ids, owned by the caller (`Copy of <name>` by default). Delete moves a live template to the Deleted view (`UXW-02`, below) and removes one already there for good, with its roles, documents, fields and shares; envelopes made from it are copies. Another account's template is `404` before any body is read. `tests/templates.rs` and the contract scenario; seen red with the page check removed (a field on page 3 of a two-page document accepted) |
| Field types end to end, `PUT /s/{token}/fields/{field}/attachment` | First and last name (filled at finish from the recipient's name, docs/24 §5, `S1-03`), a multi-line text box (`format.multiline`, set from the box's top, `S1-01`), company, title (typed by the signer), number (`validation: {kind: number, min, max, decimals}`), radio group and dropdown (`options`; a value outside them refused unless `allow_custom` on a dropdown), note (sender's `value`, `read_only` and `locked`), any field pre-filled by the sender (`value` with `locked`: no one changes it), text presets (`validation.kind` `email`, `phone`, `zip`, `length` with `max`) are taken by the field endpoints, validated by the engine on every fill and again at finish, and drawn by the flattener (preview and seal). An **attachment** is uploaded to its field (PDF admitted by the bounded reader, or PNG or JPEG by signature, at most 10 MiB), stored write-once; the value `{"attachment": "<sha256>"}` is bound into the chain by `recipient.field_completed` and listed in the certificate of completion ("Signer attachments": recipient, field, kind, size, SHA-256; docs/32 §6). It is not drawn into or appended to the sealed document (decision recorded here: the evidence-safe option). An attachment value given to `/fields` or `/finish` must be one the signer uploaded (`422` otherwise). The seal job reads each file, checks its hash, and lists it. `tests/field_types.rs` (every refusal, read-only and locked refused, preview draws the values); worker `tests/end_to_end.rs` seals an envelope with an attachment; certificate `signer_attachments_are_listed_by_hash`. Seen red: the upload-ownership check removed (a forged attachment value accepted); the certificate section removed |
| `PATCH /users/{id} {profile?, disabled?}` | Change a member's permission profile; disable (sessions and open invitations ended; refused at login, at the session resolver and per request) or enable them in this account only. Not on oneself (`422`) |
| `PATCH /users/{id} {name?, password?}` (`SEC-ID-01`) | The name and password belong to the user in every account. An administrator (or any API key, the user's own included) changes them only for a user whose one membership is this account; a user who also belongs to another account is `403 CS-API-0015`, and nothing in the request is applied. The user changes their own through their own session (`openseal_update_own_user`, which finds the user from the session); a new password ends their sessions in every account. `accept-invite` likewise ends sessions in every account. `tests/shared_users.rs` (server and store); seen red on the code before the fix (`left: (200, "")` `right: (403, "CS-API-0015")`) and with the every-account revocation narrowed to the acting account |
| `GET /s/{token}/document?doc=` | A recipient who has finished downloads the same (`doc` optional for one document), in the browser the link is bound to, while the link is valid: the sealed copy once complete (worker `tests/end_to_end.rs`), else the preview; before finishing `409 CS-API-0009`. Recorded as `document.downloaded` by the recipient |
| `GET /s/{token}/certificate` (`VS-01`) | A recipient who has finished downloads the certificate of completion once the envelope is `completed`: the sealed PDF the sender gets from `GET /envelopes/{id}/certificate`, read from the blob store and checked against its stored hash, in the browser the link is bound to, after every required authentication, while the link is valid (the completion email carries a fresh link). Before finishing or before completion `409 CS-API-0009`. Recorded as `certificate.downloaded` by the recipient. The web app's done screen offers it once the envelope is completed. Worker `tests/end_to_end.rs` `one_signer_gets_the_sealed_pdf_and_the_certificate_from_the_completion_email`, seen red with the route removed |

## As built (`WEB-07`, `WEB-08`)

| Endpoint | As built |
| --- | --- |
| `GET /envelopes?sort=&order=&status=&sender=&from=&to=` | `sort` is `created_at` (default), `updated_at` (last change: the last command that changed the envelope; a download or the sender viewing is not a change), `expires_at` (none after every date), `subject` (ignoring case) or `status` (lifecycle order); `order` `asc` or `desc` (default newest first for times, ascending for subject and status); ties by id. `status` is one status or several separated by commas; `sender` a user id or `me` (without `view_all` the caller's own only: another sender's id answers an empty page); `from` and `to` bound the last change (RFC 3339, `to` exclusive). Keyset paging: one static, parameterized query per sort and direction over an index for each; a cursor names its sort and order, and another sort's cursor is `422` (the earlier creation-time cursor is still read). Items gain `updated_at` and `expires_at`. Envelopes removed from the lists are never listed. Account-scoped as before. `tests/lists.rs`, RLS on and off: every sort paged one at a time, the filters, beta seeing only its own under every sort and filter, a member seeing only their own |
| `DELETE /envelopes/{id}` | A draft as before; now also an envelope that ended without completing (declined, voided, expired): `DeleteEnded` (docs/24 As built) records `envelope.deleted`, the envelope leaves every list and stays readable by id with its documents, chain and evidence; a completed or in-flight envelope, or a second delete, is `409 CS-WF-0001`; `If-Match` required. Deleting a draft with recipients failed with `CS-DB-0008` before (the projection blanked their names); fixed. Seen red: the engine's status check removed (a sent envelope accepted, refused only by the table's check) |
| `GET /envelopes/{id}/attachments/{sha256}` | A signer's attachment for staff who may see the envelope (scope `envelopes:read`): the file an attachment field's value names, read from the blob store and checked against the hash, served as an attachment with the type its leading bytes show (PDF, PNG, JPEG), recorded as `attachment.downloaded` (field, hash, actor). Another hash, another account's envelope, or a member who may not see it is `404` and records nothing |
| `GET /s/{token}/history` | The recipient's view of the chain, verified as it is read: events they acted in or that name them (`data.recipient_id`) and the milestones `envelope.sent`, `.corrected`, `.voided`, `.declined`, `.expired`, `.completing`, `.completed` from the first `envelope.sent` on (a draft's own edits, recorded as `envelope.corrected` until ADR-030, never show as a correction: `WEB-14`), oldest first, each `{seq, type, at, by}` with `by` one of `you`, `sender`, `recipient` (another, never named), `user`, `host`, `system`; no names, addresses, IPs, user agents, locations or values. Bound browser only, after every required authentication and the account's disclosure (`403 CS-AUTH-0003`/`0005` before); available after finishing or declining while the link is valid. Records nothing (decision recorded here: docs/32 §3 has no access event for reading one's own history, and it serves no document). `type` is the audit type (`recipient.signed`), as the mock now records it too (`WEB-12`). `tests/signer_history.rs`; seen red with the filter removed (signer 2's events shown to signer 1) |
| `GET /s/{token}/documents/{doc}/content`, the view, `GET /s/{token}/document` | `SEC-CER-01`. The document is served only in the bound browser, after every required authentication (`403 CS-AUTH-0003`, `CS-AUTH-0004` when locked) and, when the account requires a disclosure, consent to its current version (`403 CS-AUTH-0005`), the rule history has (decision recorded here: the document is the record consent must precede, and `…/viewed` already needs both). Before it served the normalized PDF to whichever browser opened the link first, without the access code or emailed code. The view names no document and no field until authenticated (§6); the signer's copy (`GET …/document`) checks authentication as well as having finished. Every ceremony endpoint audited: the rest are guarded by the engine's gates (`gate_in` for consent, decline, finish later, reassign, withdraw-consent; `gate_ready`, which adds consent, for viewed, adopt, fields, attachment, finish, approve), by `authenticated` (disclosure) or `ready` (history), or serve nothing but the redacted view (`session`, the view, `authenticate`, `otp`, `otp/verify`). Two gaps found by the audit and closed: `withdraw-consent` checked only that the recipient was active, and consent outlives a correction that sends a new link and clears the authentication, so the new link alone could withdraw it and so decline the envelope (the engine now applies `gate_in`); and viewed, adopt, fields and attachment stored the image or file, parsed an attached PDF, and answered `404` for an unknown field or document id before the engine's check, so the server now applies `ready` first (`403` before anything is stored or parsed). `tests/ceremony_auth.rs` (access code, emailed code, disclosure, none, and every endpoint before the code) and the contract scenario; seen red against the server before the change (three of four tests: `left: (200, "")` `right: (403, "CS-AUTH-0003")`; the every-endpoint test `left: (404, "CS-API-0002")` for viewed and `left: (409, "CS-WF-0001")` for withdraw-consent), and `transitions.rs::withdrawing_consent_needs_the_authentication_first` red before the engine change |
| `GET /s/{token}` (view), `GET /s/{token}/disclosure` | `UXW-34`. The view (and every changing call's answer) gains `sender {name, email, organisation}`, `envelope.expires_at` and `consent_required.url` (§6). `/disclosure` answers `{version, sha256, text}`: the account's published `ersd_versions` text whose `text_sha256` is the hash the workflow policy names (the highest version when one text was published under several), re-hashed as it is read; `version` is the policy's label, the one `POST …/consent` takes. `404 CS-API-0002` when the account requires no disclosure or published no text for it (the view then leaves out `url`); `500 CS-API-0010` when the stored text no longer hashes to it (never served; `url` left out). Under consent's rules: bound browser only (`403 CS-AUTH-0009`), after every required authentication (`403 CS-AUTH-0003`, `CS-AUTH-0004` when locked); still readable after finishing or declining while the link is valid. Records nothing (decision recorded here: reading the text is not an access to a document, and accepting it is `recipient.consented`, which binds the hash; no new audit type). Publishing a text is `POST /ersd-versions` (`ERSD-01`, above). `tests/disclosure.rs`; seen red against the server before the change (all three tests), with the authentication check removed (served before the access code), with the hash re-check removed (an altered text served), with the cookie binding check removed (another envelope's session read the text), and with `url` always given |
| `POST /s/{token}/reassign {name, email, reason?, location?}` | The engine's `Reassign` (docs/24): only with `signing_options.allow_reassign` (`409 CS-WF-0012` otherwise) and while this recipient's required action is open (`409` once finished). The new recipient takes the routing order and fields (values cleared) and is invited when their turn comes (`send_invitation` queued); this link is revoked in the same transaction; `recipient.reassigned` records the reason and, with `capture_location`, the device's location (the page's `location` member, refused before `WEB-07` by the strict body). `tests/signer_history.rs` |
| `POST /envelopes/{id}/recipients/{r}/host` | `UXW-36`. A member holding `envelopes:send` who may see the envelope (its sender, an administrator, or a member who sees every envelope; anyone else, and every other account, `404 CS-API-0002`) hosts an in-person signer: the engine's `HostInPerson` runs as `InPersonHost` (docs/24), recording `recipient.in_person_hosted` (`host_user_id`, actor `user`, the caller's sign-in as `account_login`; the type is in docs/32 §2 and casual-sign-audit already, no new type). A recipient who is not an `in_person_signer`, whose turn has not come or who has finished is `409 CS-WF-0001`. Every earlier link of that recipient is revoked, and a one-time ceremony link is minted (purpose `in_person`, `host_user_id` the caller, migration 0014) and answered `201 {url, expires_at}` to the caller only (never stored as an idempotent body): one hour, checked on every call, bound to the first browser like every link. Every ceremony command on it runs as `InPersonHost` with the caller, so each step of the signer names the host as actor and records `account_login`, not `email_link`; the link is refused (`401 CS-AUTH-0002`) once its host is no longer an enabled member. Hosting again (by anyone) supersedes the earlier link. The signer's own emailed link cannot act for them before or after (`403 CS-WF-0003`). Not built: the in-person host downloading the finished document through the link (the engine refuses `RecordAccess` to `InPersonHost`); the completion copy reaches the signer by email. `tests/in_person.rs` (an in-person signer completes through the API and the envelope moves to the next signer and its seal job; another account, a read-only key, a remote signer, a superseded link and a disabled host refused); seen red with the ceremony's principal left as the recipient, with the host's membership check removed, and with the revocation removed |

## As built (`UXW-31` to `UXW-33`, `UXW-37` to `UXW-39`)

| Endpoint | As built |
| --- | --- |
| `PATCH /webhooks/{id} {url?, event_types?, active?}` | `UXW-31`. Scope `webhooks:manage`, this account's subscriptions only (another's `404 CS-API-0002`). A new `url` passes the registration check (`422 CS-API-0013`, SEC-W01), `event_types` the list of `POST`; `active: false` pauses, `true` resumes. Answers the subscription |
| `POST /webhooks/{id}/test` | `UXW-32`. Records a `webhook.test` delivery (payload `{id, type, created_at, account_id, data: {subscription_id}}`, ids only) and queues `send_webhook_delivery` for the worker, which signs and sends it as any other and records the answer in the delivery log. `202` with the delivery as recorded (`pending`); a paused or disabled subscription `409 CS-API-0009`; a stored URL that no longer passes the registration check `422 CS-API-0013` |
| `POST /webhooks/{id}/deliveries/{d}/redeliver` | `UXW-33`. The same event id and payload again, through the worker; the delivery goes back to `pending`. The SSRF refusal is kept: the URL is checked again here and every resolved address at connect time (SEC-W01). A delivery of another subscription or account `404`; paused `409 CS-API-0009` |
| `GET /users/me` | `UXW-37`. The caller's own `{id, name, email, notifications {completed, declined, viewed}, signature, initials}`, each mark `{image_base64}` or null; notices and marks are this account's (`member_profiles`, migration 0023) |
| `PATCH /users/me {name?, notifications?, signature?, initials?, password?, current_password?}` | `UXW-37`. Unknown members `400`; a mark is a PNG or JPEG of at most 5 MiB, `null` removes it. The name and the password are the user's in every account and change only through the user's own session (`422 CS-API-0001` with an API key). A new password (12 to 256 characters) needs the current one (`401 CS-AUTH-0007` when wrong, rate limited as login) and ends every other session of the user in every account; this one stays |
| `POST /auth/password-reset {email}` | `UXW-38`. No session. `202 {}` for any well-formed address, so the answer never tells whether it has an account. For a local, enabled user it records a reset (`password_resets`, migration 0023; earlier open resets of the user are revoked) and queues `send_password_reset` in the same statement (no extra round trip for a known address, `UXW-38C`); the worker draws a 256-bit token, stores only its SHA-256 with a one-hour expiry (a retry after a refused email mints a fresh link) and emails `<base_url>/#/reset-password?token=…`. Rate limited as login per address and per client, and at most one email a minute per user |
| `POST /auth/password-reset/confirm {token, password}` | `UXW-38`. Spends the link once and sets the password; the user's sessions end in every account and their other open resets are revoked. An unknown, expired, spent or revoked link is `401 CS-AUTH-0002`, all alike. The web app's page for the link is `UXW-38A` |
| `GET /auth/providers` | `UXW-39`. No session. `{items: [{id, name, url}]}`, the SSO identity providers sign-in offers: empty until SSO is built (FG-173) |

## As built (`UXW-01`, `UXW-02`, `UXW-03`, `UXW-30`)

| Endpoint | As built |
| --- | --- |
| `GET /envelopes?waiting_for=me` | The Inbox (`UXW-01`): sent envelopes of this account, whoever sent them, in which the caller is, by their account email ignoring case, a recipient whose turn it is and who acts through a link (not a copy, an in-person signer, whose link only a host obtains, or an embedded recipient); each item has `my_recipient_id`. Any other value is `422`. Sorts, filters and paging as the list. Scope `envelopes:read`. `tests/inbox_folders.rs`, RLS on and off: another account's envelope addressed to the same email, a recipient whose turn has not come or passed, a copy and a finished recipient are never listed |
| `POST /envelopes/{id}/sign-link` | A signed-in member signs, approves or views an Inbox envelope from inside the app: the caller must be, by account email, a recipient whose turn it is and who acts through a link, through their own signed-in session (an API key or OAuth client is `403`). `201 {url, expires_at}`, a one-time ceremony link of purpose `account` naming the member (migration 0022), five minutes, `SecretBearing` (never stored as an idempotent body), bound to the first browser like every link; opening it records the member's sign-in (`account_login`) as how the link was obtained, and every authentication the sender required still applies. An envelope the caller may neither see nor is a recipient of, and every other account's, is `404`; a recipient whose turn has not come or has passed is `409 CS-WF-0007`. Issuing a link changes nothing in the envelope and records nothing (opening it does, as any link). `tests/inbox_folders.rs`; seen red with the email match removed (another member's envelope linked) |
| `GET /envelopes?recipient=&date_field=` | `UXW-03`: `recipient` is text a recipient's name or email contains (wildcards literal, at most 200 characters, no control characters); `date_field` is which date `from` and `to` bound: `updated_at` (default), `created_at`, `sent_at`, `completed_at` (an envelope without that date is not in a bounded range). With `status`, `sender`, `q`, `sort` and `order` of `WEB-08`, all server-side |
| `GET /envelopes?folder=` | `UXW-02`: one of the caller's own folders, or `none` (filed in none of theirs); another member's or another account's folder id answers an empty page. Every item has `folder_id`, the caller's own filing or null |
| `GET`/`POST /folders`, `PATCH`/`DELETE /folders/{id}`, `POST /folders/{id\|none}/envelopes {envelope_ids}` | `UXW-02`: each member's own folders (`folders.owner_user_id`, migration 0022): `{items: [{id, name, count}]}` by name, `count` the envelopes filed there that are not deleted; a name is 1–100 characters, trimmed, unique among the member's own ignoring case (`422 CS-API-0001` with code `exists` at `/name`), at most 500 folders a member. Removing a folder unfiles its envelopes. Filing (1–200 ids) is the member's own view: an envelope is in at most one of each member's folders, and another member files the same envelope independently; every id must be an envelope the caller may see (`404` otherwise, nothing filed). Filing is not an act on the agreement and records nothing in the chain. Another member's or account's folder is `404`. Scopes `envelopes:read` to list, `envelopes:write` to change |
| `GET /envelopes?deleted=true` | The Deleted view (`UXW-02`): exactly the envelopes removed from the lists (`DELETE` of an envelope that ended without completing, `envelope.deleted`), readable by id as before. Restoring one is `NOT_ON_SERVER.restoreEnvelope` (ADR-031 Proposed) |
| `DELETE /templates/{id}`, `GET /templates?deleted=true`, `POST /templates/{id}/restore` | Templates' Deleted view (`UXW-02`): deleting a live template (`If-Match` required) moves it there, kept with its roles, documents and fields (`templates.deleted_at`, migration 0022); it leaves `GET /templates` and every read and edit (`404`). `?deleted=true` lists them, most recently deleted first (any value but `true` or `false` is `422`). `restore` (`If-Match` honoured) brings it back whole, `200` with the whole template; a live template or none is `404`. Deleting it again in the Deleted view removes it for good. A template has no audit chain, so neither step is evidence. Another account's is `404`. `tests/inbox_folders.rs` `deleted_templates_*`, RLS on and off; seen red with delete removing at once (the Deleted view was empty) |
| `GET /envelopes/{id}/certificate` (declined, voided, expired) | `UXW-30`: when an envelope is declined, voided or expires, the server queues `seal_ended_certificate`; the worker renders the envelope certificate (docs/32 §6), which says how the envelope ended and never claims completion, seals it on its own with the platform key, stores it, reads it back and verifies it, and records it as the envelope's certificate; the chain is not extended. The endpoint then serves it, recorded as `certificate.downloaded`; before it exists `409 CS-API-0009`, and the read queues the job again (idempotent per envelope, so a repeated `GET` adds no second job; the only write a `GET` makes, under the read scope). Worker `tests/flow.rs`; server `tests/inbox_folders.rs` |

## As built (`WEB-19`, document analysis; docs/33 §6, §7 As built)

Advisory only: nothing here changes an envelope's state, its audit chain, a document or the evidence. Every feature is
off by default at every level; one is in effect only when the server runs with `OPENSEAL_ML_BUNDLE_ID` (the operator
deployed modeld), the plan entitles the workspace (`ml_entitlements`, set by the operator) and its administrator turned
it on. With none in effect an upload enqueues nothing and every response is unchanged (`ML-01`); every route below but
the settings answers `403 CS-ML-0011`, which the web app reads as "hide every ML surface". Another account's envelope,
template, document or suggestion is `404` before anything else.

| Endpoint | As built |
| --- | --- |
| `GET`/`PATCH /account/settings/ml` | `{ocr, template_matching, extraction, personal_data, personal_data_model, ocr_scripts, reread_scanner_text, not_in_plan: [feature], installed}`. Scope `admin:account` (workspace administrators). `PATCH` merges the members given (an unknown member is refused); turning on a feature the plan lacks, or any feature while `installed` is false, is `403 CS-ML-0011` and changes nothing; turning one off is always allowed; `ocr_scripts` from `latin`, `cyrillic`, `greek`, `cjk`, `arabic`, `devanagari`. A change appends `workspace.ml_settings_changed` to the admin log (`GET /admin-events`, ORG-05) |
| `POST /envelopes/{id}/documents/{doc}/analysis` | `202` and the run `{id, document_id, status: queued\|running\|done\|failed\|unavailable, uses: [ocr\|template\|entities\|personal_data], ocr_pages, truncated, bundle_id}`, the uses being the features in effect. Idempotent on the job key (account, document, its SHA-256, the uses, the bundle): asking again finds the same run. A draft only (`409 CS-WF-0001`); the sender or an administrator. Scope `envelopes:write`. An upload to a draft with a feature in effect enqueues the same in its own transaction |
| `GET /envelopes/{id}/documents/{doc}/analysis` | The newest run of the document; `404` when none. Scope `envelopes:read` |
| `GET /envelopes/{id}/suggestions?kind=&state=&cursor=&limit=` | `{items: [{id, kind: template\|entity\|personal_data, document_id, page?, rect?, label, value?, normalized?, score, model: {id, sha256}, state, decided_by?, decided_at?, template_id?, pages_matched?, pages_total?}], next_cursor}`, by id, `limit` 1 to 200 (default 50), only the kinds whose feature is in effect. `value` is read from the stored text at request time (no span text is stored); a template suggestion has none. Scope `envelopes:read` |
| `POST /envelopes/{id}/suggestions/{s}/accept`, `…/dismiss` | Records the decision (`state`, `decided_by`, `decided_at`) and answers the suggestion. Accept does **not** itself perform the action docs/33 §6 describes: the caller makes the ordinary edit through the ordinary endpoints (the web app applies a matched template as an undoable edit of the draft), and it is recorded as that edit always is (finding row returned for the owner, docs/33 §7 As built). `409 CS-ML-0012` when already decided or its document has left the envelope. The sender or an administrator; scope `envelopes:write` |
| `POST`/`GET /templates/{id}/documents/{doc}/analysis` | The same for a template document: `fingerprint_template` (its page hashes, which later uploads are matched against), needing template matching in effect; also enqueued when a document is added to a template. Scopes `templates:write` and `templates:read` |

Tests: `server/tests/ml.rs` with Postgres and RLS on: every feature off writes no run or job and detect-fields answers
identical bytes (seen red with an enqueue forced while off); settings off by default, `not_in_plan` and `installed`,
refused outside the plan and to non-administrators; identical bytes uploaded by two accounts make two runs
(`SEC-I06`); the analysis and suggestion flow end to end, decided once, and another account refused `404`. Worker
`tests/ml.rs` runs both jobs against a fake modeld. Not built: OCR-sourced members in `detect-fields`, `GET
/search?mode=meaning`, the settings' `models` and `ocr_packs`.

## Web client and mock contract (`UX-03`)

`webapp/api.js` is the web app's one client of this API and `webapp/mock.js` its in-memory fake (`?mock=1` on a
loopback host only). The UI packages of the UX-01 audit call only what these two expose; `webapp/tests/contract.test.mjs`
drives every call below against the mock.

**Served by the server, now in the client.** Webhooks: `listWebhooks`, `getWebhook`, `createWebhook {url, event_types,
secret_refs, envelope_id?}` (the signing secret is provisioned by the operator and named by `secret_refs`; the API never
shows one), `deleteWebhook` (disables; deliveries stay readable), `listDeliveries`; `WEBHOOK_EVENT_TYPES` lists the 20
types the server takes. `listContacts`. The ceremony's `approve`, `withdrawConsent` and `disclosure` (`UXW-34`). `hostInPerson` (`UXW-36`): `{url, expires_at}`, a link acting as the caller hosting the signer; `RECIPIENT_TYPES_READY` now includes `in_person_signer`. `corrections` builds the change
list `POST …/correct` takes (`add_recipient`, `update_recipient`, `remove_recipient`, `add_field`, `update_field`,
`remove_field`, `remove_document`, `set_subject`, `set_message`, `set_expiry`, `set_reminders`, `set_signing_options`),
with `recipientSpec` and `fieldSpec` keeping only the members the engine's `RecipientSpec` and `Field` have, and new ids
minted as UUIDs. `fieldWire` and `recipientWire` build the field and recipient bodies of create and `/fields`
`/recipients`, with every member of the engine's `Field` (`FIELD_MEMBERS`: `read_only`, `locked`, `value`, `default`,
`validation`, `format`, `group`, `conditional`, `formula`, `options`, `allow_custom`, `tooltip`, `placeholder`, …);
`FIELD_TYPES` and `RECIPIENT_TYPES` list the engine's kinds, and `FIELD_TYPES_READY` and `RECIPIENT_TYPES_READY` those
a signer completes end to end today.

**Not on the server yet.** `NOT_ON_SERVER` in `api.js` names each call the UI may make that the server does not serve,
with what it needs and its tracker row. The mock serves them as designed; against a server the client refuses them at
once with `CS-NET-0002` (status 501, client-side only like `CS-NET-0001`; the `detail` names the call), and
`client.available(name)` lets a screen show the control as "not available yet" rather than hide it:

| Name | Needs on the server | Row |
| --- | --- | --- |
| `restoreEnvelope` | `POST /envelopes/{id}/restore`: a deleted envelope back to the lists, a new workflow command recorded by a new audit type `envelope.restored` (ADR-031, Proposed; the Deleted view itself is served) | `UXW-02` |
| `clearField` | `DELETE /s/{token}/fields/{field}`: a signer removes a value before finishing, recorded by a new audit type `recipient.field_cleared` (ADR-032, Proposed) | `UXW-35` |

**The mock follows the server** where it had drifted: every engine recipient type is taken and routed (everyone but a
copy is waited for; an approver approves, a viewer completes by viewing every document to the end, an in-person signer
signs only once hosted); sending refuses a field the recipient's type may not hold; the per-element recipient and field
calls correct a sent envelope as the server's do (`envelope.corrected`); `/correct` takes the whole change list, all or
none; `status` takes several values, and `sort`, `order`, `sender`, `from` and `to` filter as `WEB-08` built them;
deleting an envelope that ended keeps it readable (`envelope.deleted`); a subscribed event records a delivery.

**The audit trail in the mock (`WEB-12`)** has the server's shape, so a screen built on the mock reads a real trail:
`GET …/audit` items are `{seq, type, at, hash, prev, event}` with `seq` from 0, `type` casual-sign-audit's dotted name,
and `event` the whole event of docs/32 §2, the actor as the engine's `actor_for` writes it (`{kind: "sender", id}`, a
recipient with `id`, `name` and `email`, `{kind: "system"}`) and the recipient an event concerns in
`event.data.recipient_id`, never at the top. The events are the engine's, in its order: `envelope.created`, then a
draft's own edits as `envelope.corrected` (the server's `Edit` records them too) with `document.added` and
`document.admitted`; at send `envelope.sent`, `document.fixed` and an `invitation.sent` per recipient reached; a signer's
`recipient.signed` then `recipient.completed`; at the end `envelope.completing`, `document.flattened`, `document.sealed`
and `envelope.completed`; a decline is `recipient.declined` then `envelope.declined`. Two types are the mock's alone,
for calls not on the server: `envelope.restored` and `recipient.field_cleared`. `GET /s/{token}/history` filters as the
server's, except that it still shows a draft's `envelope.corrected` before `envelope.sent` (`WEB-14`'s follow-up). `webapp/tests/audit-shape.test.mjs`.
