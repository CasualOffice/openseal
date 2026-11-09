# 22 — Data model

**Status: Draft for owner.** The domain model in `casual-sign-model` and its persistence in PostgreSQL. The state
machines that move it are in [24](24-ENVELOPE-LIFECYCLE-AND-ROUTING.md); the audit events in
[32](32-AUDIT-TRAIL-AND-EVIDENCE.md); the API shapes in [40](40-API-DESIGN.md).

Vocabulary is chosen so a DocuSign or SignNow user recognizes it: **envelope** (DocuSign's word; SignNow's "invite"
plus "document group"), **recipient**, **field** (DocuSign's "tab"; SignNow's "field"), **template**, **role**.

## 1. Entities

```
Account (tenant) ─┬─ User ── membership(role, permission profile) ── Group
                  ├─ Brand, Settings, ERSD (consumer disclosure) versions
                  ├─ Template ─┬─ TemplateDocument ── Field (role-bound)
                  │            └─ Role (name, routing order, defaults)
                  ├─ Envelope ─┬─ Document (ordered) ── DocumentVersion (immutable blob refs)
                  │            ├─ Recipient (ordered by routing) ─┬─ AuthRequirement
                  │            │                                   ├─ Field (placed on a document page)
                  │            │                                   └─ SignatureAdoption
                  │            ├─ RoutingRule (conditional routing)
                  │            ├─ CustomField (envelope metadata)
                  │            ├─ Reminder/Expiry policy
                  │            ├─ AuditEvent (append-only, hash-chained)
                  │            └─ Comment (later)
                  ├─ BulkSend ── BulkSendRow ── Envelope
                  ├─ SigningLink (PowerForm / "link to sign")
                  ├─ WebhookSubscription ── WebhookDelivery
                  ├─ ApiClient (OAuth2 apps, API keys)
                  └─ RetentionPolicy
```

## 2. Identifiers

- Every entity has a **UUIDv7** id (time-ordered, index-friendly), minted by the host and supplied to the engine
  (randomness is supplied, CLAUDE.md). Public ids are the same UUIDs; there are no sequential ids on the wire.
- Recipient invitation tokens are **not** ids: 256-bit random, stored as SHA-256 hashes, bound to one recipient of one
  envelope, revocable, with an expiry (docs/07 `SEC-A*`).
- Documents are additionally addressed by content: `sha256` of their bytes, which is also their blob key.

## 3. Envelope

| Field | Type | Notes |
| --- | --- | --- |
| `id` | uuid | |
| `account_id` | uuid | Tenant; on every tenant row |
| `sender_user_id` | uuid | Owner of the envelope |
| `status` | enum | `draft`, `sent`, `delivered`, `completing`, `completed`, `declined`, `voided`, `expired` ([24](24-ENVELOPE-LIFECYCLE-AND-ROUTING.md)) |
| `subject`, `message` | text | Email subject and body; bounded lengths (docs/21) |
| `routing_mode` | enum | `sequential`, `parallel`, `mixed` (by routing order number) |
| `expires_at` | timestamptz? | |
| `reminder_policy` | json | First after N days, then every M days |
| `signing_options` | json | Allow reassign, allow decline, allow finish-later, signer attachments, in-person, language |
| `seal_profile` | enum | `pades-b-t` default, `pades-b-lt`, `pades-b-lta` |
| `completion_delivery` | json | Attach documents to completion email, combine with certificate |
| `brand_id` | uuid? | |
| `template_ids` | uuid[] | Provenance when created from templates |
| `bulk_send_id` | uuid? | |
| `custom_fields` | json | Integrator metadata, searchable keys |
| `version` | int | Optimistic concurrency for drafts and corrections |
| `sent_at`, `completed_at`, `voided_at`, `void_reason` | | |
| `chain_head` | bytea | Hash of the last audit event (docs/32) |

**Invariant:** after `sent`, the set of documents and the content of each document version are frozen. A **correction**
creates new document versions and records `envelope.corrected`; recipients who already signed re-sign if any document
they signed changed (the engine computes this, [24](24-ENVELOPE-LIFECYCLE-AND-ROUTING.md) §Correct).

## 4. Document and version

| Field | Notes |
| --- | --- |
| `document.id`, `envelope_id`, `order`, `name` | Name is display-only, never used as a path |
| `version.id`, `document_id`, `kind` | `original` (as uploaded), `normalized` (converted/admitted PDF delivered to signers), `flattened`, `sealed` |
| `version.sha256`, `byte_len`, `page_count`, `blob_key` | `blob_key` is the hash |
| `version.admission_report` | json: what was found and neutralized (docs/30) |
| `version.pages` | json: per page `mediabox`, `cropbox`, `rotate`, size in points; the geometry fields are placed against |

The `normalized` version's hash is the one recorded in `document.delivered` events; the `sealed` version's hash is the
one recorded in `envelope.completed`.

## 5. Recipient

| Field | Notes |
| --- | --- |
| `id`, `envelope_id`, `routing_order` | Equal numbers act in parallel |
| `type` | `signer`, `in_person_signer`, `approver`, `viewer` (needs to view), `cc` (receives a copy), `editor` (allowed to edit), `intermediary` (updates recipients), `agent` (specifies recipients), `witness` (later), `seal` (legal-entity seal through `RemoteSigner`, later) |
| `role_name` | From the template, when any |
| `name`, `email`, `phone` | PII, classified (docs/07 §Data) |
| `status` | `created`, `sent`, `delivered`, `authenticated`, `completed`, `declined`, `auto_responded`, `reassigned` |
| `auth` | List of requirements: `access_code` (hash), `email_otp`, `sms_otp`, `phone_call`, `idp` (OIDC issuer), `idv` (provider), `kba` (plugin) |
| `delivery` | `email`, `sms`, `none` (embedded: host delivers) |
| `embedded_client_user_id` | When set, the recipient signs only through the integrator's embedded session |
| `signing_group_id` | Any member may act (later) |
| `consent` | ERSD version accepted, time, from the audit chain |
| `language` | Signer UI and email language |
| `declined_reason`, `reassigned_to` | |

## 6. Field

| Field | Notes |
| --- | --- |
| `id`, `envelope_id`, `document_id`, `recipient_id` | `recipient_id` null only on templates (bound to `role_id`) |
| `type` | See table below |
| `page`, `x`, `y`, `width`, `height` | **PDF user space of the page as displayed** (after `/Rotate` and crop box), points, origin top-left; `-fields` converts to PDF coordinates. Never pixels |
| `anchor` | Optional: `{text, offset_x, offset_y, units, ignore_if_absent, case_sensitive, whole_word, match: first|all}` resolved at send (the engine type is `AnchorSpec` in `-fields`; its API shape lands with Phase 2) |
| `required`, `read_only`, `locked` | |
| `label` (data label) | Unique per envelope for data fields; shared fields share a label |
| `value`, `default` | Typed per `type`; bounded |
| `validation` | `{kind, message}` where `kind` carries its own parameters: `email`, `number {min, max, currency, decimals}`, `date {format}`, `zip`, `ssn`, `phone`, `length {min, max}`, `regex {pattern}` (matches the whole value) |
| `format` | Font family, size, colour, alignment, date format, masking |
| `group` | Checkbox/radio group id and rule (`select_at_least`, `select_at_most`, `select_exactly`, `select_range`) |
| `conditional` | `{parent_label, when: value|checked|unchecked|any}` |
| `formula` | Expression over other labels ([`-fields` formula grammar](30-PDF-PIPELINE.md#formulas)) |
| `options`, `allow_custom` | Dropdown and radio options (500 at most, no repeats); `allow_custom` lets a signer type a value not in the list |
| `tooltip`, `placeholder` | |

| Type | Notes |
| --- | --- |
| `signature`, `initials` | Optional (DocuSign's optional signature) or required |
| `stamp` | Uploaded company stamp image |
| `date_signed` | Filled by the server at the recipient's completion, in the account's format and the signer's time zone |
| `name`, `first_name`, `last_name`, `email`, `company`, `title` | Auto-filled from the recipient, editable per policy |
| `text`, `number`, `date`, `email_address`, `phone`, `ssn`, `zip` | Data fields with validation |
| `envelope_id` | Read-only, the envelope id (DocuSign `envelopeIdTabs`) |
| `checkbox`, `radio_group`, `dropdown` | |
| `formula` | Read-only, computed |
| `attachment` | Signer uploads a file; admitted like any upload |
| `note` | Read-only text shown to the recipient |
| `approve`, `decline` | Buttons that complete or decline |
| `hyperlink` | Shown, never followed automatically |
| `payment` | Amount, currency, line items; via `PaymentGateway` (later) |
| `drawing` | Free drawing area (later) |

## 7. Template

A template is an envelope without people: documents, roles (name, routing order, type, default auth), role-bound
fields, message, settings, and **matching rules** (later: DocuSign's template matching on upload). Creating an envelope
from one or more templates copies, never references, so editing a template never changes a sent envelope. Templates
have owners, sharing (user, group, account), folders and versions.

## 8. Account and identity

- **Account**: tenant; plan limits; settings (default ERSD, allowed auth methods, retention, data region tag, date
  formats, reminder defaults, branding, seal profile, TSA list, signature font set).
- **User**: staff of an account; login through OIDC or SAML, or local password with TOTP/WebAuthn; belongs to one or
  more accounts.
- **Permission profile**: `admin`, `sender`, `viewer`, custom (send, use templates, create templates, bulk send, manage
  users, manage brands, view all envelopes, API access).
- **Group**: sharing unit for templates and envelopes.
- Recipients are **not users**. A recipient who also has an account sees the envelope in their inbox through a match
  on verified email, never through a shared identity.

## 9. Persistence rules

- Every tenant table has `account_id NOT NULL`, a composite index leading with it, and an RLS policy
  `account_id = current_setting('openseal.account_id')::uuid`. The server sets it per transaction from the
  authenticated principal. The repository layer exposes only tenancy-scoped constructors (`Tenant::envelopes()`), so
  forgetting the filter does not compile; RLS catches what does.
- `audit_events` has no `UPDATE` or `DELETE` grant for the application role; a trigger refuses both.
- Document blobs are written once; the application role has no delete on the bucket except through the retention job,
  which records `envelope.purged` before deleting.
- Personal data columns are listed in docs/07 §Data classification with their retention.
- Soft deletes are not used for evidence; "deleted" envelopes are moved to a recycle folder, and purged only by the
  retention policy, with an audit event.

## 10. Engine types versus rows

`casual-sign-model` defines the types above as plain Rust values with invariants checked by constructors
(`Envelope::validate_for_send` returns every violation, each with a code). The server maps rows to these values; the
engine never sees SQL. The same types serialize to the public JSON in [40](40-API-DESIGN.md) through explicit DTOs, so
an internal field never leaks into the API by accident.
