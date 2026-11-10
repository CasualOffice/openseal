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
                  │            └─ Comment (slice 26)
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
| `signing_options` | json | Allow reassign, allow decline, allow finish-later, `capture_location` (GEO-01: record each recipient's location on every action; off by default, absent from the JSON when off; per envelope, see below), signer attachments, in-person, language |
| `seal_profile` | enum | `pades-b-t` default, `pades-b-lt`, `pades-b-lta` |
| `completion_delivery` | json | Attach documents to completion email, combine with certificate |
| `brand_id` | uuid? | |
| `template_ids` | uuid[] | Provenance when created from templates |
| `bulk_send_id` | uuid? | |
| `custom_fields` | json | Integrator metadata, searchable keys |
| `version` | int | Optimistic concurrency for drafts and corrections |
| `sent_at`, `completed_at`, `voided_at`, `void_reason` | | |
| `chain_head` | bytea | Hash of the last audit event (docs/32) |

**`capture_location` is per envelope** (GEO-01; the owner asked for it "per document"). One envelope is one signing
ceremony: a recipient's `recipient.signed` event covers every document of the envelope at once, so a per-document
setting could not say whether that one event needs a location. An envelope with one document is the per-document case.
It sits in `signing_options` (no new column) and may be changed while a draft or by a correction like the other
options; each event states for itself how its location was obtained, so the record stays true across a change.

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
| `type` | `signer`, `in_person_signer`, `approver`, `viewer` (needs to view), `cc` (receives a copy), `editor` (allowed to edit), `intermediary` (updates recipients), `agent` (specifies recipients), `witness` (slice 16), `seal` (legal-entity seal through `RemoteSigner`, slice 18), `notary` (slice 31) |
| `role_name` | From the template, when any |
| `name`, `email`, `phone` | PII, classified (docs/07 §Data) |
| `status` | `created`, `sent`, `delivered`, `authenticated`, `completed`, `declined`, `auto_responded`, `reassigned` |
| `auth` | List of requirements: `access_code` (hash), `email_otp`, `sms_otp`, `phone_call`, `idp` (OIDC issuer), `idv` (provider), `kba` (plugin) |
| `delivery` | `email`, `sms`, `none` (embedded: host delivers) |
| `embedded_client_user_id` | When set, the recipient signs only through the integrator's embedded session |
| `signing_group_id` | Any member may act (slice 29) |
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
| `value`, `default` | Typed per `type`; bounded. A `multi_select` value is `{"choices": [...]}`: at most 500 options, none repeated (`ACRO-02`) |
| `validation` | `{kind, message}` where `kind` carries its own parameters: `email`, `number {min, max, currency, decimals}`, `date {format}`, `zip`, `ssn`, `phone`, `length {min, max}`, `regex {pattern}` (matches the whole value) |
| `format` | Font family, size, colour, alignment, date format, masking |
| `group` | Checkbox/radio group id and rule (`select_at_least`, `select_at_most`, `select_exactly`, `select_range`) |
| `conditional` | `{parent_label, when: value|checked|unchecked|any}` |
| `formula` | Expression over other labels ([`-fields` formula grammar](30-PDF-PIPELINE.md#formulas)) |
| `options`, `allow_custom` | Dropdown, radio and multi-select options (500 at most, no repeats); `allow_custom` lets a signer type a value not in a dropdown's list (it does not apply to a multi-select) |
| `tooltip`, `placeholder` | |

| Type | Notes |
| --- | --- |
| `signature`, `initials` | Optional (DocuSign's optional signature) or required |
| `stamp` | Uploaded company stamp image |
| `date_signed` | Filled by the server at the recipient's completion, in the account's format and the signer's time zone |
| `name`, `first_name`, `last_name`, `email`, `company`, `title` | Auto-filled from the recipient, editable per policy |
| `text`, `number`, `date`, `email_address`, `phone`, `ssn`, `zip` | Data fields with validation |
| `envelope_id` | Read-only, the envelope id (DocuSign `envelopeIdTabs`) |
| `checkbox`, `radio_group`, `dropdown` | A radio group converted from a PDF whose buttons are on several pages is a `radio_group` field on each page sharing one label, so one value (`ACRO-02`) |
| `multi_select` | Any number of options chosen from a list; converted from a PDF multi-select list box (`ACRO-02`) |
| `formula` | Read-only, computed |
| `attachment` | Signer uploads a file; admitted like any upload |
| `note` | Read-only text shown to the recipient |
| `approve`, `decline` | Buttons that complete or decline |
| `hyperlink` | Shown, never followed automatically |
| `payment` | Amount, currency, line items; via `PaymentGateway` (slice 13) |
| `drawing` | Free drawing area (slice 4) |

## 7. Template

A template is an envelope without people: documents, roles (name, routing order, type, default auth), role-bound
fields, message, settings, and **matching rules** (slice 3: DocuSign's template matching on upload). Creating an envelope
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

### As built (stage 2B, `casual-sign-store`)

Migrations `migrations/0001` to `0007`, applied by the crate's own runner (`casual_sign_store::migrate`): each in its
own transaction, recorded with the SHA-256 of its text in `openseal_schema_migrations`; a second run applies nothing;
an applied migration whose text changed is `CS-DB-0002`; a database with an unknown later version is `CS-DB-0011`; an
advisory lock serializes migrators. Thirty-six tables:

| docs/22 entity | Table(s) | Repository |
| --- | --- | --- |
| Account | `accounts` (RLS on `id`) | `TenantTx::account` |
| User, membership, permission profile | `users`, `account_memberships`, `permission_profiles` | `TenantTx::users` |
| Group | `groups`, `group_members` | schema only |
| Brand, Settings, ERSD versions | `brands`, `accounts.settings`, `ersd_versions` | settings only |
| Template, TemplateDocument, Role, role-bound Field, sharing | `templates`, `template_documents`, `template_roles`, `template_fields`, `template_shares` | `TenantTx::templates` (not shares) |
| Envelope, folders and recycle folder | `envelopes`, `folders` | `TenantTx::envelopes` |
| Document, DocumentVersion | `documents`, `document_versions` | `TenantTx::documents` |
| Recipient, AuthRequirement, invitation tokens, SignatureAdoption | `recipients`, `recipient_auth_requirements`, `recipient_tokens`, `signature_adoptions` | `TenantTx::recipients` (recipients, tokens) |
| Field and its value | `fields`, `field_values` | `TenantTx::fields` |
| RoutingRule, CustomField, Comment | `routing_rules`, `envelope_custom_fields`, `comments` | schema only |
| AuditEvent, purge tombstone | `audit_events`, `envelope_tombstones` | `TenantTx::audit` (append, read, verify) |
| BulkSend, BulkSendRow | `bulk_sends`, `bulk_send_rows` | schema only |
| SigningLink | `signing_links` | resolution only |
| WebhookSubscription, WebhookDelivery | `webhook_subscriptions`, `webhook_deliveries` | `TenantTx::webhooks` |
| ApiClient | `api_clients` | `TenantTx::api_clients` |
| RetentionPolicy | `retention_policies` | schema only |
| Jobs (ADR-012) | `jobs` | `TenantTx::jobs`; claim through `EntryPoints` |

**Tenancy as built.** Every table but `accounts` and `users` has `account_id uuid NOT NULL`, `UNIQUE (account_id, id)`
and is declared through `openseal_tenant_table()`, which enables RLS with one policy for every command and grants the
`openseal_app` role. Children reference parents through `(account_id, parent_id)` composite foreign keys, so the
database itself refuses a row pointing at another account's row. Primary keys and unique constraints other than `id`
lead with `account_id`, so a cross-tenant write fails on the reference and never on a collision that would reveal the
other account's row exists. `users` is the one table without `account_id`: a user may belong to several accounts, and
the row is visible only through a membership of the current account; enrolling an existing user needs their
normalized email as well as their id (`add_existing_member`). Repositories are reached only through
`Store::for_account(id)` → `Tenant::begin()` → `TenantTx`, which binds the account into every statement and sets
`openseal.account_id` for the transaction. The only cross-account paths are `SECURITY DEFINER` functions, executable by
the application role alone, that take a secret's hash (recipient token, API key, signing link), a login identity, or a
supplied lease token (job claim) and return ids. The migrator owns every table; `openseal_app` owns nothing, has no
`BYPASSRLS`, no `TRUNCATE` anywhere, and only `SELECT`, `INSERT` on `audit_events` and `envelope_tombstones`.

**Audit as built.** An event is stored as its RFC 8785 canonical bytes, exactly what its hash covers; an insert
trigger recomputes `sha256(canonical)`, refuses a `seq` that is not the next or a `prev` that is not the head
(`CS-DB-0005`), and updates `envelopes.chain_head`. Triggers refuse `UPDATE`, `DELETE` and `TRUNCATE` (including a
`TRUNCATE ... CASCADE` from a parent) for every role (`CS-DB-0004`); the application role also lacks the privileges.
A superuser can still disable triggers: that is the operator boundary `SEC-S07` names, and the chain head in every
sealed document is what detects it. `TenantTx::audit().chain()` rebuilds the chain through `casual-sign-audit`'s
`Chain::append`, re-verifying every link on read. An envelope with events cannot be deleted (the reference).

**Blobs as built.** `BlobStore` keys are the SHA-256 of the bytes, computed by the store; `put` of present bytes is a
no-op; nothing replaces or deletes a blob; `get` re-hashes and refuses a mismatch (`CS-BLOB-0003`); 256 MiB cap both
ways. `FsBlobStore` writes a `create_new` temporary file, syncs it, makes it read-only, and hard-links it into place
(`link` never replaces). `S3BlobStore` presigns with SigV4 and sends `If-None-Match: *`; tested against SeaweedFS (the
MinIO image could not be pulled on the build machine). Bucket object lock or a role without `DeleteObject` is the
operator's second line, recorded for the deployment guide (slice 20).

**Queries.** Every statement is a compile-time checked `sqlx::query!` or `query_as!` with bound parameters (ADR-014,
owner instruction 14), checked against the committed offline cache `server/casual-sign-store/.sqlx/`, so
`SQLX_OFFLINE=true` builds need no database. `server/casual-sign-store/sqlx-prepare.sh` creates a scratch database,
applies every migration, and regenerates the cache, or with `--check` fails when a query or migration changed without
regenerating it. Only the migration files themselves run as unchecked DDL; migration 0001 also declares the
migration ledger so any runner yields the same schema.

**Tests.** `OPENSEAL_TEST_DATABASE_URL` (a superuser URL) gives each test a fresh database, migrated as owner and
exercised as a login role in `openseal_app`; unset, the database tests print `SKIPPED` and pass. Every repository
method is called with another account's ids, with RLS on and with RLS disabled on every table; raw SQL through the
application role, bypassing the repository, sees only its account on every RLS table and nothing when none is set.

**As built (stages 2C and 2D, integrated).** Migration `0008_workflow_state_and_job_steps.sql` adds
`envelope_states` (the engine's `EnvelopeState` as JSON with a row revision: the envelope's authority, the only place
it is stored) and `job_steps` (the worker's insert-only record of acts done outside the database). Migration
`0009_api_server.sql` adds `envelopes.host_client_id` (the API client that created an envelope, WF-05),
`envelopes.certificate_sha256` (the sealed certificate of completion's blob, written once by the seal job),
`recipient_tokens.session_sha256` (a link's browser binding), `idempotency_keys`, `staff_sessions` and
`openseal_resolve_staff_session`. Forty tables. The relational rows of an envelope are the projection
`casual_sign_host::apply` writes from the engine state in the deciding transaction (§10).

**Not built yet:** repositories for the "schema only" rows above; the retention purge (slice 15); a database guard
that freezes an envelope's documents after `sent` (the workflow engine enforces it, docs/24 §6).

**Corrections to the text above.** The setting is `openseal.account_id`, read as
`NULLIF(current_setting('openseal.account_id', true), '')::uuid`, so an unset setting matches no row. Envelope
`custom_fields` is the table `envelope_custom_fields`, searchable by name. A field's value is the table `field_values`
(value, its SHA-256, time), not a column of `fields`; the field properties other than type, geometry, flags and label
are one `spec` JSON object as the model serializes them. "Forgetting the filter does not compile" holds in the sense
that no other door exists; the isolation tests, not the compiler, prove each method filters.

## 10. Engine types versus rows

`casual-sign-model` defines the types above as plain Rust values with invariants checked by constructors
(`Envelope::validate_for_send` returns every violation, each with a code). The server maps rows to these values; the
engine never sees SQL. The same types serialize to the public JSON in [40](40-API-DESIGN.md) through explicit DTOs, so
an internal field never leaks into the API by accident.
