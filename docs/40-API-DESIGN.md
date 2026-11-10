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
