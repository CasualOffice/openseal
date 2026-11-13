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

**Designed (ADR-028); the organization level itself is built (`ORG-02`, migration 0014, §9 As built), the rest not yet:** an **Organization** sits above the account, which the UI calls a **workspace**
(`account` stays in the database and API v1). Every account belongs to exactly one organization, for good:

```
Organization ─┬─ Account (workspace) …as above, plus AdminEvent, ArchivedAgreement, UsageLedger, UsageCounter
              ├─ OrganizationAdmin (owner, admin, delegated + OrgPermissionSet, workspace scope)
              ├─ DomainClaim, IdentityProvider ── UserIdentity (IdP binding of a User), ScimToken
              ├─ OrgAdminEvent, OrgUsageCounter, OrgWorkspaceAllocation
              └─ (platform) PlanAssignment, PlanOverride
Platform (schema `platform`) ── Operator, OperatorEvent, ApprovalRequest/Grant, Plan, TsaEndpoint, TrustAnchor, SealProfile
```

The design and its reasons are in [23](23-ORGANIZATIONS-WORKSPACES-AND-CONSOLE.md); §8 and §9 below carry the
persistence notes.

**Platform schema, as built (`CON-02`, `CON-03`, `CON-04` in part; migrations 0016 to 0019; docs/23 §5.6).** Schema
`platform`, reached only by the role `openseal_console` (no grant on any `public` table): `settings`,
`service_targets`, `alerts` (append-only), `operators`, `operator_mfa`, `operator_enrolments`, `operator_sessions`,
`operator_events` (append-only, hash-chained, head in `operator_chain`), `approval_requests`, `approval_grants`,
`approval_uses` (insert-only; the two-person rule). Tenant metadata reaches the console only
through `platform` definer functions returning ids, names, statuses, labels, counts and times; writes to
`organizations` (name, data-region labels) and `accounts` (data-region label, status) only through session-checked
definer functions; `organizations.status` only through the two-person apply functions. Plans, TSA, trust anchors and
seal profiles are not built yet.

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
| `auth` | List of requirements: `access_code` (hash), `email_otp`, `sms_otp`, `voice_otp` (the phone call; designed as `phone_call`), `sso` (sign-in through one of the operator's OpenID Connect providers, `RAUTH-01`; designed as `idp`), `idv` (provider), `kba` (plugin). `sms_otp` and `voice_otp` need an E.164 `phone`; their codes are rows of `recipient_otp_codes` with `channel` `sms` or `voice` (migration 0029). `sso` needs an `email`, which the provider's verified email must equal; each sign-in is a row of `recipient_sso_challenges` (migration 0030: provider id, SHA-256 of `state`, nonce, PKCE verifier, 10-minute expiry, closed at first use or when superseded, at most one open per recipient, a tenant table under RLS) |
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
| `format` | Font family, size, colour, alignment, date format, masking, `multiline` (a text box of several lines: the signer types line breaks and the value is set from the top of the box, `FG-057`) |
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
| `name`, `first_name`, `last_name`, `email`, `company`, `title` | Auto-filled from the recipient, editable per policy; `first_name` and `last_name` are the name's first word and the rest ([24](24-ENVELOPE-LIFECYCLE-AND-ROUTING.md) §5) |
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
have owners, sharing (user, group, account), folders and versions. **As built (`UXW-06`, migration 0031):** access is
deny by default and decided per request: the owner and the account's administrators hold every right; a share
(`template_shares`, one per member, group or the whole account) lets its members use the template, and edit it with
`can_edit`; deleting, restoring and sharing stay with the owner. Each member stars their own Favourites
(`template_favourites`). Template folders and locking are not built.

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

**Designed (ADR-028), not built** ([23](23-ORGANIZATIONS-WORKSPACES-AND-CONSOLE.md) §2–§4, §7):

- **Organization**: above accounts; status `active` → `suspended` ⇄ `active`, `suspended` → `closed` (read-only after a
  notice period; evidence kept under each workspace's retention, never purged by closing). Typed policy with locked
  and tighten-only keys; data-region labels (no residency claim).
- **Account (workspace)**: gains `organization_id` (never changes; a trigger refuses it) and status `active` →
  `archived` (no new envelopes, members or settings; envelopes already sent still complete and seal). Plan limits leave
  the settings comment; plans live in the `platform` schema.
- **User**: one identity shared by every workspace it belongs to. Its attributes change only by the person, by an
  organization whose verified domain covers the email, or by a workspace admin while that workspace is the only
  membership (`SEC-ID-01` fixes today's code to this rule). IdP bindings move to `UserIdentity` (one per provider).
- **Organization admin** (owner, admin, delegated with a permission set and workspace scope); **permission profiles**
  split into named admin actions, a delegated workspace admin optionally limited to groups.
- **Admin event** (per workspace) and **organization admin event**: append-only, hash-chained like audit events, but
  not envelope evidence.
- **Archived agreement**: an imported evidence package, read-only, verified on import; not an envelope.

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
| Brand, Settings, ERSD versions | `brands`, `accounts.settings`, `ersd_versions` | settings; `TenantTx::account().disclosure` reads a published ERSD text by its hash (`UXW-34`); `publish_disclosure` inserts the next version of a language (the account row locked first, so two publishes never share a number) with its `ersd.published` admin event, and `disclosures` lists the published versions without text (`ERSD-01`); rows are never updated, no migration was needed |
| Template, TemplateDocument, Role, role-bound Field, sharing | `templates`, `template_documents`, `template_roles`, `template_fields`, `template_shares` | `TenantTx::templates` (not shares) |
| Envelope, folders and recycle folder | `envelopes`, `folders` | `TenantTx::envelopes` |
| Document, DocumentVersion | `documents`, `document_versions` | `TenantTx::documents` |
| Recipient, AuthRequirement, invitation tokens, SignatureAdoption | `recipients`, `recipient_auth_requirements`, `recipient_tokens`, `signature_adoptions` | `TenantTx::recipients` (recipients, tokens) |
| Field and its value | `fields`, `field_values` | `TenantTx::fields` |
| RoutingRule, CustomField, Comment | `routing_rules`, `envelope_custom_fields`, `comments` | schema only |
| AuditEvent, purge tombstone | `audit_events`, `envelope_tombstones` | `TenantTx::audit` (append, read, verify) |
| BulkSend, BulkSendRow | `bulk_sends`, `bulk_send_rows` | `TenantTx::bulk_sends` (`UXW-04`): a batch with its rows (`input` holds the row's recipients and problems, personal data); a row is claimed `FOR UPDATE SKIP LOCKED`, marked sent with its envelope (which then names the batch in `envelopes.bulk_send_id`) or failed with a code; `settle` completes a batch once no row is pending; cancel leaves pending rows unsent. No migration was needed |
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
the application role alone, that take a secret's hash (recipient token, API key, signing link), a login identity, a
supplied lease token (job claim), the user's own live session id (`openseal_update_own_user`, 0013) or an open, sent,
unexpired invitation id (`openseal_accept_user_invitation`, 0013); the two 0013 functions may also end that user's
sessions in every account, through `openseal_revoke_user_sessions`, which the application role cannot call. One more,
`openseal_user_in_other_account` (0013), answers only whether a member of the current account also belongs to another
account, and is false for anyone who is not a member of the current account. The migrator owns every table; `openseal_app` owns nothing, has no
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

`0010_user_invitations.sql` (`WEB-06`) adds `account_memberships.disabled_at` (a member disabled in one account only;
`users.disabled_at` stays the platform-wide switch, and a member reads as disabled when either is set),
`user_invitations` (a member's one-time set-password link: the token's SHA-256 and expiry, written by the worker as it
mails it, `sent_at`, `accepted_at`, `revoked_at`, `invited_by`; removed with the membership), the entry point
`openseal_resolve_user_invitation` (an open, unexpired invitation of an enabled member, ids only), and
`openseal_resolve_staff_session` replaced to refuse a member disabled in the session's account. Forty-one tables.
Contacts for autocomplete are a query over `recipients`, not a table.

`0011_envelope_lists.sql` (`WEB-08`) adds `envelopes.updated_at` (last change: the time of the last command that changed
the envelope, projected from the command's context; an access such as a download is not a change; earlier rows take
their state row's last write) and `envelopes.deleted_at` (an envelope that ended without completing removed from the
lists, from the engine state's `deleted_at`; a check allows it only on `declined`, `voided` or `expired`; a soft delete:
the row, documents, state and chain stay), and indexes for each list sort with `id` as the tie-break
(`updated_at`, expiry with no expiry as 9999-12-31, `lower(subject)`). `Envelopes::search` is the list: one static,
parameterized query per sort key and direction (keyset paging on `(key, id)`), filtered by a set of statuses, a sender,
a text and a last-change range, excluding removed envelopes. A purged draft's recipient rows are removed by the
projection instead of being blanked (the name check refused the blanks, so deleting a draft with recipients failed).

`0013_shared_user_guard.sql` (`SEC-ID-01`, docs/07 `SEC-A11`) makes the `users` row the user's own once they belong
to more than one account. 0002's `member_of_current_account` policy now governs `SELECT` only; a new `UPDATE` policy
admits a user who is a member of the current account and of no other, through `openseal_user_in_other_account(user)`
(a `SECURITY DEFINER` boolean, false for a user with no membership here, so it cannot probe other accounts).
`Users::rename` and `Users::set_password_hash` carry the same condition in their statement (so the repository isolates
with RLS off too) and answer `CS-DB-0009` with SQLSTATE `OS003` for a shared user. Two more definer functions are the
user's own doors, each finding the user from something only they hold: `openseal_update_own_user(session, name,
password_hash, now)` from a live session of the current account (`Users::update_own`), and
`openseal_accept_user_invitation(invitation, password_hash, now)` from an open, sent, unexpired invitation
(`Users::accept_invitation_with_password`, which spends it and revokes the member's other open invitations here). A new
password through either ends the user's staff sessions in every account (`openseal_revoke_user_sessions`, not granted
to the application role). No table changes.

`0014_organizations.sql` (`ORG-02`, ADR-028, docs/23 §2.1) puts every account under an **organization**. New tables
`organizations` (RLS on `id = openseal_current_org()`, plus a `FOR SELECT` policy letting a workspace read its own),
`org_permission_sets` and `organization_admins` (declared through `openseal_org_table()`, policy
`organization_id = openseal_current_org()`). `accounts` gains `organization_id` (backfilled with the account's own UUID,
NOT NULL; a trigger refuses any change, SQLSTATE `OS004`, `CS-DB-0013`, except by the NOLOGIN, memberless
`openseal_org_mover`), `status` (`active`, `archived`) and `admin_chain_head`. `openseal_app` lost INSERT on `accounts`
and keeps UPDATE only on `name`, `settings`, `data_region`, and lost SELECT on `users.password_hash` (SELECT is
granted per column; a column added later must be granted). Members holding the built-in `admin` profile, enabled
there, were backfilled as owners; a deferred constraint trigger refuses a commit that removes or demotes an owner and
leaves an active organization without an enabled one (`organization_keeps_an_owner`, `CS-DB-0008`). Organization
scope reads `accounts`, `account_memberships` and `users` of its own workspaces through `FOR SELECT` policies
named `organization_scope`; content tables are untouched. Definer functions: `openseal_create_workspace` and
`openseal_archive_workspace` (organization scope; replaced by ORG-05's event-writing versions, below),
`openseal_bootstrap_organization` and `openseal_bootstrap_owner` (the install's first organization only, in the transaction that created it),
`openseal_login_password_hash` (login) and `openseal_user_workspaces` (switching, from a live session). Store:
`Store::for_organization(org)` → `OrgScope::begin()` → `OrgTx` (`organization`, `workspaces`, `workspace(id) →
WorkspaceOf`, `create_workspace`, `archive_workspace`, `into_workspace(&WorkspaceOf) → TenantTx` in the same transaction); `Store::for_workspace_of(&WorkspaceOf)` → a single-account
`TenantTx` that re-reads the workspace's organization; `Store::bootstrap_organization` and
`Accounts::make_first_owner`; `EntryPoints::user_workspaces`. `Store::create_account` is gone: the application can no
longer create an account outside those functions. Forty-five tables.

`0015_in_person_hosting.sql` (`UXW-36`) lets `recipient_tokens.purpose` be `in_person` and adds
`recipient_tokens.host_user_id` (a user), set exactly when the purpose is `in_person` (a check). An in-person link
acts as its host hosting the signer (docs/40 As built); the host is a user rather than a membership so that removing
the member is not refused, and the server refuses the link once the host is no longer an enabled member.

`0020_admin_events.sql` (`ORG-05`, ADR-028, docs/23 §2.5) adds the **admin audit logs**: `admin_events` (a tenant
table, chained per workspace, head in `accounts.admin_chain_head`) and `org_admin_events` (an organization table,
chained per organization, head in `organizations.admin_chain_head`). Columns: owner id, `seq`, `prev_hash`, `hash`,
`action`, `at`, `canonical` (RFC 8785 bytes, at most 64 KiB), `xact` (the top-level transaction that appended it, set
by the insert trigger) and `recorded_at`; primary key (owner, `seq`). Append-only as `audit_events`: SELECT and INSERT
only for `openseal_app`, triggers refuse UPDATE, DELETE and TRUNCATE for every role (`OS001`, `CS-DB-0004`). A
definer insert trigger refuses an event outside the current scope (`42501`, before the chain is read), then checks
`sha256(canonical) = hash`, that the owner, `seq`, `prev`, `action` and `at` (the bytes' Unix millisecond) columns are what the bytes state, and that
`seq` is next and `prev` the head under `FOR UPDATE` on the head column (`OS005`, `CS-DB-0014`), and moves the head.
Deferred constraint triggers named `*_admin_change_has_event` on `accounts` (insert, or update of `name`, `settings`,
`data_region`, `status`), `account_memberships`, `permission_profiles`, `organizations` (insert, or update of `name`,
`policy`, `status`, `data_regions`), `organization_admins` and `org_permission_sets` refuse an application-role commit
whose transaction appended no event to that workspace's log or its organization's (`admin_change_has_event`,
`CS-DB-0008`); the owner role is outside, as for the audit chain. Definer functions: `openseal_admin_chain_tip()`
(next `seq` and head of the current scope's log, the head row locked in one statement and read in the next so that a transaction that waited sees the other's event), `openseal_org_chain_tip()` and
`openseal_append_org_event(…)` (from a workspace, its organization's log), `openseal_xact_has_admin_event`;
`openseal_create_workspace` and `openseal_archive_workspace` now take the event (`seq`, `prev`, `hash`, `at`,
`canonical`), check that its bytes name that action and workspace, and append it in the same transaction (an already
archived workspace writes none). Store: the repositories append the events themselves (`Accounts::set_settings`,
`Accounts::make_first_owner`, `Users::create_profile`, `create_member`, `add_existing_member`, `rename`,
`set_password_hash`, `set_profile`, `set_disabled`, `remove_member`, `OrgTx::create_workspace`, `archive_workspace`,
`Store::bootstrap_organization`); `TenantTx::act_as` and `OrgTx::act_as` set the actor (`AdminActor`: user, API client
or system, time, request id, IP); `TenantTx::admin_events`, `verified_admin_log`, `verified_admin_events` (one page, verified
against the event at its cursor and the stored head) and the same on `OrgTx` read and re-verify. Forty-seven tables.

`0021_ml_analysis.sql` (`WEB-19`, `ML-01`; docs/33 §7 As built, §13) adds the
advisory document-analysis tables, each with `account_id`, RLS and the repository `TenantTx::ml`
(`casual_sign_store::repo::ml`): `ml_settings` (a workspace's four switches, the personal-data model, OCR script
packs, "re-read scanner text"; no row means every feature off), `ml_entitlements` (the plan's `ml.*` features; the
application role may only read it), `analysis_runs` (one per document and job key: `kind` `analyze_document` or
`fingerprint_template`, `uses`, `document_sha256`, `job_key` unique per account and naming the account and the
document (a retry after a `failed` or `unavailable` run takes `…:retry:{failed run id}`, `ML-24`), `status` `queued`/`running`/`done`/`failed`/`unavailable`, `bundle_id`, `ocr_pages`, `truncated`, `code`;
exactly one of `envelope_id` and `template_id`, each a composite foreign key with `account_id`, `ON DELETE CASCADE`),
`suggestions` (`kind` `template`/`entity`/`personal_data`, page, rect, label, UTF-8 byte span offsets and never the
span text, the matched template and its page counts, score, model id and weights hash, `state`
`open`/`accepted`/`dismissed` with `decided_by`, `decided_at`), `ocr_pages` (a run's OCR words per page: document
content) and `template_fingerprints` (a template page's dHash and pHash, an optional text embedding, the model). None is
read by the seal job, the audit chain or the evidence package (docs/33 invariant 2). Fifty-three tables with `0021`.

`0022_folders_and_deleted.sql` (`UXW-01`, `UXW-02`, `UXW-03`) makes **folders each member's own**: 0002's `folders`
rows of kind `envelopes` with `owner_user_id`, a name unique per member ignoring case (`folders_owner_name`; the API
bounds names to 100 characters and a member to 500 folders), and `UNIQUE (account_id, id, owner_user_id)`. A new tenant
table `folder_envelopes` (`id`, `user_id`, `envelope_id`, `folder_id`, `filed_at`) records where a member filed an
envelope, one folder per member and envelope; its reference `(account_id, folder_id, user_id)` to the folder and its
owner means nobody can file into another member's folder, and removing the folder, the membership or the envelope row
removes the filing. Filing is a member's view of their lists, not a change of the agreement: no audit event, no
`updated_at`. 0004's `envelopes.folder_id` (one folder for every member) stays unused. `TenantTx::folders` lists a
member's folders with the count of filed envelopes not deleted, creates, renames, deletes and files (`file`, all in one
statement). `recipient_tokens.purpose` may also be `account`, a link a signed-in member obtained for the recipient
they are (the Inbox's `sign-link`), and `host_user_id` is set exactly for `in_person` and `account`. A partial index
`recipients_account_live_email` serves the Inbox. `Envelopes::search` also filters by a recipient's name or email, by
which date a range bounds (`updated_at`, `created_at`, `sent_at`, `completed_at`), by the member's folder (or none),
by the Deleted view (`deleted_at` set) and by the Inbox (sent envelopes where the member is, by their email, a
recipient whose turn it is and who acts through a link: not a copy, an in-person signer or an embedded recipient), and
reports the member's filing and, in the Inbox, the recipient they are. Restoring a deleted envelope needs a workflow
command and audit type (ADR-031, Proposed), so 0022 adds nothing for it. `templates` gains `deleted_at`: deleting a
live template sets it (the template keeps its roles, documents and fields, leaves every read, edit and the list, and
`Templates::list_deleted`, `get_deleted` and `restore` serve the Deleted view); deleting it there removes it for good.
A template has no audit chain, so neither step is evidence. Fifty-four tables with `0022`.

`0023_password_reset.sql` (`UXW-37`, `UXW-38`) adds two tenant tables. `password_resets` (`id`, `user_id`,
`requested_at`, `token_sha256`, `sent_at`, `expires_at`, `used_at`, `revoked_at`) records a self-service reset: never
the email or the token, only the token's SHA-256 once the worker has sent it, with a one-hour expiry (a retried send mints a fresh link); a reset is open
until used or revoked, and a new request, a use or a password change revokes the user's other open resets. Definer
functions: `openseal_request_password_reset` (by normalized email, a local enabled user with an enabled membership; at
most one a minute per user; it also queues the email job the caller supplies, in the same statement, so a known address
costs no extra round trip, `UXW-38C`; NULL otherwise, so the caller answers alike), `openseal_resolve_password_reset` (an open,
sent, unexpired reset by its token hash) and `openseal_use_password_reset` (spends it once, sets the password, ends the
user's sessions in every account). `openseal_own_password_hash` and `openseal_change_own_password` let a live session
change its own user's password against the hash the server verified, ending every other session of the user.
`member_profiles` (`notifications` object, `signature_image` and `initials_image` of at most 5 MiB, `updated_at`) holds a
member's own notice choices and saved marks in this account (personal data, never logged); removing the membership
removes both tables' rows. Fifty-six tables with `0023`.

`0026_console_org_events.sql` (`CON-16`, docs/23 §2.5) holds the console role to the admin logs: the
`*_admin_change_has_event` triggers now also refuse an `openseal_console` commit that changed an organization or a
workspace without an `operator.*` event appended to that organization's `org_admin_events` in the same transaction
(`platform.xact_copied_to_org_log`). Definer functions for the console: `platform.org_log_tip` (organization, next
`seq` and head, the head row locked) and `platform.copy_to_org_log` (live operator session with role `operator` or
`platform_owner`, an `operator.*` action, the bytes' actor exactly that operator, their `operator_event` link an existing operator event of that
operator and action, else `OS005`).

`0031_template_sharing.sql` (`UXW-06`) makes **template access deny by default**. `openseal_template_share_right(account,
template, member)` (invoker rights, so RLS still applies) answers what a member's shares give: `edit`, `use` or NULL,
through a share to them, to a group they belong to (`group_members`) or to the whole account. 0003's `template_shares`,
never written before, gains `created_at`, one share per target and template (three partial unique indexes), and
cascades: a share goes with its template, with the membership it names (a removed member keeps none) and with its
group. Every template that existed before 0031 gets a whole-account share with `can_edit`, so nobody loses access on
upgrade; a template made since is its owner's alone until shared. A new tenant table `template_favourites`
(`user_id`, `template_id`, `created_at`; primary key per member and template; cascades with the membership and the
template) holds each member's starred templates; starring changes no version. `Templates::access` (owner or
administrator `Owner`, else the share right), `list_for` (by view: all, owned, shared with me, favourites, with each
row's access, star and whether it is shared), `shares`, `replace_shares`, `set_favourite`, `is_favourite` and
`groups` (names and member counts). Sixty-three tables with `0031`.

**Not built yet:** repositories for the "schema only" rows above; the retention purge of blobs (slice 15; the purge
job already deletes an envelope's analysis runs with their suggestions and OCR pages, `SEC-I07`, `ML-31`); a database guard
that freezes an envelope's documents after `sent` (the workflow engine enforces it, docs/24 §6).

**Corrections to the text above.** The setting is `openseal.account_id`, read as
`NULLIF(current_setting('openseal.account_id', true), '')::uuid`, so an unset setting matches no row. Envelope
`custom_fields` is the table `envelope_custom_fields`, searchable by name. A field's value is the table `field_values`
(value, its SHA-256, time), not a column of `fields`; the field properties other than type, geometry, flags and label
are one `spec` JSON object as the model serializes them. "Forgetting the filter does not compile" holds in the sense
that no other door exists; the isolation tests, not the compiler, prove each method filters.

### Designed (ADR-028): tenancy with organizations

The second scope, the organization tables `organizations`, `organization_admins` and `org_permission_sets`, the
three `FOR SELECT` policies, the tightened grants and `openseal_org_mover` are built (`ORG-02`, As built above);
the rest is not. Each part lands with the row named in [23](23-ORGANIZATIONS-WORKSPACES-AND-CONSOLE.md) §12. What changes in
the rules above, and what does not:

- **Unchanged:** every content table keeps exactly one policy, `account_id = openseal_current_account()`; envelopes,
  their chains and blobs never change account.
- **A second scope.** `openseal.organization_id`, read by `openseal_current_org()`, which is NULL whenever
  `openseal.account_id` is set, so no transaction is in both scopes. `Store::for_organization → OrgTx`; an organization
  reaches a workspace only through a `WorkspaceOf` proof and an ordinary single-account `TenantTx`.
- **Organization tables** (`organizations`, `organization_admins`, `org_permission_sets`, `domain_claims`,
  `identity_providers`, `user_identities`, `scim_tokens`, `org_admin_events`, `org_usage_counters`,
  `org_workspace_allocations`) are declared through `openseal_org_table()` with the policy
  `organization_id = openseal_current_org()`.
- **Organization reach into tenant tables** is three `FOR SELECT` policies only (`accounts`, `account_memberships`,
  `users`); every write goes through `for_workspace_of` or a `SECURITY DEFINER` function.
- **Grants tighten:** `openseal_app` loses INSERT on `accounts` and keeps UPDATE only on `name`, `settings`,
  `data_region`; a trigger refuses any change to `accounts.organization_id` except by `openseal_org_mover`, the role
  owning only ORG-20's two-person operator link; the `users` UPDATE policy admits only a sole member's workspace
  (`SEC-ID-01`, migration 0013), with the other identity rules as definer functions; `openseal_app` loses SELECT on
  `users.password_hash` (read at login through a definer function).
- **New tenant tables:** `admin_events` (append-only, chained per workspace, head `accounts.admin_chain_head`),
  `archived_agreements`, `seal_signatures` (operational hashes for keyd reconciliation), `usage_ledger` (append-only,
  idempotent by source), `usage_counters`.
- **Schema `platform`** (operators, approvals, plans, TSA, trust anchors, seal profiles, alerts) is reached by the
  console's role `openseal_console`, which has no grant on any `public` table.
- **Plans (built, `PLAN-02`, migration 0024):** `platform.plans` (immutable versions of a key; archive only),
  `plan_entitlements`, `plan_quotas`, `plan_seat_rule`, `plan_assignments` (current on `[starts_at, ends_at)`; only
  `ends_at` shortens), `plan_overrides` (`workspace_id`, workspace-level quotas only; only `expires_at` shortens).
  Written only by session-checked definer functions (`OS010` → `CS-PLAN-0006`); constraints refuse `hard` on
  `api_calls` for any writer. The application reads only `openseal_effective_plan(now)` (current assignment and live
  overrides for its organization and workspace, no reasons or operator ids). `accounts.settings` holds no plan limits;
  its column comment says so.
- **Metering (built, `PLAN-03`, migration 0025):** `usage_ledger` (tenant, append-only by trigger, primary key
  `(account_id, meter, source_kind, source_id)` so a retried job or a decision recorded again counts once; `quantity`
  for the workspace and `org_quantity` for the organization, which differ only for `seats`), `usage_counters` (tenant)
  and `org_usage_counters` (organization), `(meter, period_start) → value`, calendar month (UTC) for counters and one
  epoch period for gauges, and `usage_blob_refs` (tenant; references per content-addressed blob, so a blob is counted
  once per workspace). The application role has SELECT only on all four; every write is through the definer
  `openseal_meter_apply`, which writes the ledger row and both counters in one transaction, so each counter equals its
  ledger sum at both levels. The application counts counter meters through `openseal_meter_record` (gauges refused,
  `CS-DB-0008`; `TenantTx::record_usage`); `seats`, `storage_bytes` and `workspaces` are kept by triggers in the
  transaction of the change (docs/23 §7.2).
- **Enforcement (built, `PLAN-04`, migration 0028):** `quota_notices` (organization table, append-only by trigger,
  SELECT only for the application; `workspace_id`, not `account_id`, so the tenant-table catalog rules do not apply;
  unique per `(organization, meter, level, workspace, source)`; ids and counts only), written by `soft` and `notify`
  quotas. `openseal_consume_quota` (counter meters, conditional updates, organization row first) and
  `openseal_quota_gauge_lock`/`_check` (`seats`, `storage_bytes`) are the definer functions the application calls
  (`TenantTx::consume_quota`, `gauge_lock`, `gauge_check`); `openseal_meter_apply` now takes the organization row
  before the workspace's (docs/23 §7.3).
- **Catalog tests** are scoped to `public` and name their exceptions; the `platform` schema has its own.
- **Migration order** is fixed in merge order (docs/23 §12): `SEC-ID-01`'s fix, organizations (with organization admins
  and the owner backfill), admin logs, platform schema, operators, approvals, plans, usage; later schema rows take the
  next free number. Forward-only as ever.

## 10. Engine types versus rows

`casual-sign-model` defines the types above as plain Rust values with invariants checked by constructors
(`Envelope::validate_for_send` returns every violation, each with a code). The server maps rows to these values; the
engine never sees SQL. The same types serialize to the public JSON in [40](40-API-DESIGN.md) through explicit DTOs, so
an internal field never leaks into the API by accident.
