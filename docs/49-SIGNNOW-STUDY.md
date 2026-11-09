# 49 — SignNow study

**Status: Live; from public sources, 2026-11-10. No live session.** What airSlate SignNow offers, how its model and API
differ from DocuSign's, and what OpenSeal takes from it. Legend: **[V]** checked against the cited source;
**[M]** from general knowledge, not re-checked; **[?]** uncertain or sources conflict. Nothing here is copied prose;
SignNow's documentation is read for behaviour only (clean room, [CLAUDE.md](../CLAUDE.md)).

## 1. Positioning

SignNow sells on **speed and price**: a single-screen editor where you upload, drop fields and assign roles in place,
then invite, at roughly a third of DocuSign's per-seat price. DocuSign leads with recipients first, then a separate
"prepare" step per recipient. An independent comparison: "DocuSign … add your signers and edit your document …
signNow … first upload the document and start editing it" (https://signaturely.com/?p=4661) [V].

**What OpenSeal takes:** SignNow's *editing* flow (document first, roles assigned in the editor) as an option beside
DocuSign's recipients-first flow ([47](47-UX-AND-FEATURE-MAP.md) §Prepare). Both produce the same envelope.

## 2. Editor

- Upload PDF, DOCX and other formats; upload by URL (`POST /v2/documents/url`); upload with **text tags** that become
  fields (`POST /document/fieldextract`) (https://docs.signnow.com/docs/entities) [V].
- **Document generation**: DOCX templates with tags become signature-ready PDFs (https://docs.signnow.com/docs/text-tags) [V].
- Field palette on the left; field properties ("Advanced options": validation, prefill, payment) in a right-hand panel
  (https://www.signnow.com/help/collect-payments) [V right panel, M left palette].
- "Edit & Sign" annotation tools for self-signing (text, signature, check, line, date) [M], mapped in the API to
  `texts`, `signatures`, `checks`, `lines` [V].

## 3. Field types

From https://docs.signnow.com/docs/fields [V]. Every field has `type`, `required`, `role`, `page_number`, `x`, `y`,
`width`, `height`, optional `name`.

| SignNow | Properties | OpenSeal type ([22](22-DATA-MODEL.md) §6) |
| --- | --- | --- |
| `text` | `prefilled_text`, `lock_to_sign_prefill`, `label`, `validator_id` (date, email, number, currency), `max_chars`, `max_lines`, `stretch_mode`, font, size, colour, alignment, bold/italic/underline | `text`, `number`, `date`, `email_address` with `validation` and `format` |
| date | A `text` with a date validator, not a type | `date` (own type; simpler to validate) |
| `signature` | `allowed_types`: type, draw, upload | `signature` |
| `initials` | type or draw | `initials` |
| `checkbox` + `checkbox_groups` | `validation_type`: at_least, at_most, exactly, none | `checkbox` + `group` rule |
| `radiobutton` | `radio[]` options, each with geometry | `radio_group` |
| `enumeration` | `enumeration_options`, `custom_defined_options` | `dropdown` (custom entry is a flag) |
| `attachment` | Signer uploads | `attachment` |
| `hyperlink` | Disabled by default | `hyperlink` (never followed automatically) |
| `stamp` | | `stamp` |
| calculated | `calculation_formula`, `calculation_precision` 0–15 | `formula` |
| conditional | `dependency`; Enterprise tier [V marketing] | `conditional` |
| payment | Text converted to payment, bindable to a formula; Stripe or CardConnect; no SignNow fee (https://www.signnow.com/help/collect-payments) [V] | `payment` via `PaymentGateway` |

**Behaviour to avoid:** `PUT /document/{id}` with `fields` **replaces all existing fields** [V]. OpenSeal's API edits
fields individually (add, update, delete by id), as the sisters' per-element ops do (OpenPresent's ADR-008).

## 4. Roles, invites, groups

- Roles are named; fields and invites bind to roles. **Copies from a template get new role and field ids**, so
  integrations address roles by name [V]. OpenSeal keeps role names stable and gives each copy new ids too, and the
  API accepts either.
- **Free-form invite** (no fields; the signer places their own signature) versus **role-based field invite**
  (`POST /document/{id}/invite` with `to[]` carrying `role`, `role_id`, `order`) [V]. Sending free-form for a document
  with fields fails ("Cannot send invite for document with fields") [V]. OpenSeal: a **free-form signer** is a
  recipient with no fields placed, allowed by an account setting, and the signer places a signature field during the
  ceremony.
- **Signing order** from `order` per role; equal orders are parallel [M]. Same as DocuSign's routing order.
- Custom subject and message need a paid plan [V]. Not gated in OpenSeal.
- **Document groups**: several documents sent together with ordered **invite steps** and per-document actions (sign,
  view, approve) (`POST /documentgroup/{id}/groupinvite`) [V]. **Document group templates** instantiate groups [V].
  A document must be the caller's, not a template, in no other group and without active invites to be grouped [V].
  **OpenSeal's envelope is the group**: multi-document from the start, with per-document per-recipient actions
  ([22](22-DATA-MODEL.md) §6: a recipient's action on a document is defined by the fields they have on it, plus an
  explicit `view` or `approve` action where they have none).
- **Bulk invite** from a template with a CSV (UI "More › Bulk Invite"; API `POST /template/{id}/bulkinvite` [?]).
- **Signing links** (`POST /link`): a public URL and QR code; each visitor signs their own copy, which lands in the
  owner's documents (https://docs.signnow.com/docs/signing-link/operations/create-signing-link) [V]. Same idea as
  DocuSign PowerForms and Documenso direct links. OpenSeal: §9 of [24](24-ENVELOPE-LIFECYCLE-AND-ROUTING.md), **with
  a QR code**.
- **Kiosk mode**: several people sign the same form in sequence on one device, with an inactivity timeout
  (https://helpcenter.signnow.com/en/articles/13186592-using-kiosk-mode-in-signnow) [V]. OpenSeal slice 14.
- Reminders and expiration per invite; event `user.invite.expired` [V event, M fields].
- **Decline** with a reason, with `decline_redirect_uri` [V]. **Reassign** by signer or sender, logged
  (https://www.signnow.com/features/re-assign-signature-request) [V marketing].
- Approver and viewer recipients (`action: approve|view|sign`) [V].

## 5. Recipient authentication

Per signer: a password shared out of band, an SMS OTP, or a phone-call OTP; API `authentication_type: phone` with
`method: sms|phone_call`, or `password` (https://docs.signnow.com/docs/two-factor-authentication) [V]. ID verification
appears only in marketing [?]. OpenSeal: `access_code`, `sms_otp`, `phone_call`, plus `email_otp`, `idp`, `idv`
([22](22-DATA-MODEL.md) §5).

**Behaviour to avoid:** in SignNow's embedded signing, `auth_method` is **recorded in history only, not enforced** [V].
OpenSeal records only what it enforced; an embedded host asserting it authenticated the signer is recorded as
`auth.asserted_by_host`, with the host's identity, never as an authentication we performed.

## 6. Evidence

"Download with History": the signed PDF plus appended audit pages (UI); `GET /documentgroup/{id}/historyfull` and
document history endpoints (API) [V]. OpenSeal: certificate of completion, embedded audit JSON, and a hash chain
([32](32-AUDIT-TRAIL-AND-EVIDENCE.md)).

## 7. API

From https://docs.signnow.com/docs/authentication, /docs/guides-embedded-signing, /docs/guides-webhooks [V].

- **Auth**: `POST /oauth2/token` with `password` (app owner only), `authorization_code`, `refresh_token`. A per-app
  "Basic token" mints bearer tokens and is used directly on a few endpoints. Default scope `*`. Example lifetime
  30 days [?].
- **The document is the root object**: `pages`, `roles[]`, `fields[]`, completed elements, `field_invites[]`,
  `requests[]`. Templates are documents with a flag.
- **Invites** are sub-resources of a document: field invites and free-form invites, each with cancel and resend.
- **Embedded flows**: embedded invites and their links (`auth_method`, `link_expiration`, `session_expiration`
  15–1440 min, `redirect_uri`, `decline_redirect_uri`, `close_redirect_uri`, `redirect_target`, `language`); embedded
  sending; **embedded editor**. Each also for document groups.
- **Webhooks v2**: `/v2/event-subscriptions` (create, list, delete, delivery log); scopes `user`, `document`,
  `document_group`; dotted events (`document.complete`, `document.fieldinvite.signed`,
  `document.fieldinvite.decline`, `document_group.complete`, `user.invite.expired`, `template.copy`); payload
  `{meta:{timestamp,event,environment,callback_url,initiator_id,metadata}, content:{…ids}}`; header
  `X-SignNow-Signature`, base64 HMAC-SHA256 of the raw body with a secret the user chooses; retries 5 × 10 s then
  every 4 h, 20 s timeout; repeated 4xx unsubscribes; at-least-once.

### SignNow against DocuSign

| | DocuSign | SignNow | OpenSeal ([40](40-API-DESIGN.md)) |
| --- | --- | --- | --- |
| Root | Envelope | Document | **Envelope** with documents; a single-document envelope is the common case |
| Fields belong to | Recipient (`signers[].tabs.signHereTabs`) | Document, pointing at a role | Envelope, pointing at document and recipient; listable both ways |
| Positioning | x/y, anchor text | x/y, text tags | x/y, anchor text, **and** text tags |
| Templates | Server and inline composite templates | Copy into a new document | Copy; composite (several templates into one envelope) |
| Embedding | `clientUserId` + views (recipient, sender, edit) | Embedded-invite resources | Views (sign, prepare, edit), short-lived single-use URLs |
| Webhooks | Connect (account) or per-envelope `eventNotification`, HMAC | Per-event subscriptions, HMAC | Subscriptions per account and per envelope; Standard Webhooks signing |
| Service auth | JWT grant | Password grant | OAuth2 client credentials and JWT bearer grant (RFC 7523); no password grant |

## 8. Admin, integrations, mobile

Organizations and branding guides exist (https://docs.signnow.com/docs/organizations) [V]; SSO and enterprise
controls are in higher tiers [M]. Notarization guide [V existence]. iOS and Android apps with offline signing [M].
Integrations: Salesforce, Microsoft 365 (Word and Excel add-ins), Dynamics 365, Teams, NetSuite, Google Workspace,
HubSpot, Power Automate, Zapier (https://www.signnow.com/integrations) [V].

## 9. Pricing

Annual billing, per user per month: Business **$8**, Business Premium **$15** (adds bulk send and reminders),
Enterprise **$30** (adds conditional logic, advanced security and compliance), Site License custom
(https://helpcenter.signnow.com/en/articles/13258230-pricing-billing) [V]. Third-party figures conflict on monthly
prices, invite caps and per-invite API pricing [?]. A separate API plan has a free sandbox [V/M].

**Takeaway:** what SignNow gates by tier (bulk send, reminders, conditional fields, payments, branding) is the
feature set OpenSeal ships to every self-hosted user; it is the main reason an operator would choose it.

## 10. What OpenSeal takes from SignNow

| Take | Where |
| --- | --- |
| Document-first editor with roles assigned in place | [47](47-UX-AND-FEATURE-MAP.md) §Prepare |
| Text tags in uploaded documents | [30](30-PDF-PIPELINE.md) §Anchors and tags |
| Signing links with QR codes | [24](24-ENVELOPE-LIFECYCLE-AND-ROUTING.md) §9 |
| Kiosk mode | Slice 14 |
| Payment fields bound to formulas | Slice 13 |
| Embedded editor (not only embedded signing and sending) | [40](40-API-DESIGN.md) §Views |
| Webhook delivery log in the API | [40](40-API-DESIGN.md) §Webhooks |

| Avoid | Why |
| --- | --- |
| Replacing all fields on update | Loses concurrent edits; per-element operations instead |
| Recording an auth method that was not enforced | Evidence that overstates is worse than none |
| Password grant | Deprecated in OAuth 2.1 |
| Feature gating by tier | Not applicable to self-hosted open source |
