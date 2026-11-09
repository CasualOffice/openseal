# 48 — DocuSign eSignature study

**Status: Live; from public sources, 2026-11-10. No live session.** DocuSign eSignature is **the feature bar and the
workflow vocabulary** OpenSeal is measured against (`DEC-06`). Legend: **[V]** checked against the cited source;
**[M]** long-standing product knowledge, not re-checked; **[?]** unverified or conflicting. Some DocuSign pages could
not be fetched (the pricing page, support.docusign.com, the bulk-send and conditional-routing concept pages); their
sections are marked. Read for behaviour only; no prose is copied (clean room, [52](52-COMPETITOR-STUDY.md)).

## 1. Product surface (web app) [M; labels change periodically]

| Area | What it holds |
| --- | --- |
| **Home** | "Start" (Send an Envelope, Sign a Document, Use a Template); counters: Action Required, Waiting for Others, Expiring Soon, Completed; recent activity |
| **Agreements** (was "Manage") | Folders: Inbox, Sent, Drafts, Deleted (purged after ~24 days [?]), user folders. Quick views: Action Required, Waiting for Others, Expiring Soon, Completed, Authentication Failed. PowerForms and Bulk Send sections. Search and filters (date, status, sender, custom fields). Per-envelope: Correct, Void, Resend, Copy, Save as Template, Move, Download, History, Certificate, Forward, Transfer ownership |
| **Templates** | My Templates, Shared with Me, Favorites, Deleted; sharing with users and groups; folders |
| **Reports** | Envelope, recipient, volume and usage reports; custom reports; CSV export; Insights dashboard |
| **Admin** | Separate "eSignature Admin": users, account, branding, signing and sending, security (§7) |

## 2. Sender flow

From https://www.docusign.com/en-ca/products/electronic-signature/features [V] and product knowledge [M].

1. **Add documents.** Upload or import from cloud storage; PDF, DOCX, XLSX, images and more, converted to PDF on the
   server. Limits: 50 MB per file in the UI, 32 MB via the API, 200 MB per envelope
   (https://developers.docusign.com/docs/esign-rest-api/esign101/rules-and-limits/) [V]. Reorder; apply a template.
2. **Add recipients.** Name, email, action (§3), optional role. Per recipient: private message, language, access code
   or ID verification, SMS or WhatsApp delivery, routing order.
3. **Signing order.** Equal numbers parallel, increasing numbers sequential, both together mixed.
4. **Message.** Subject (default "Complete with Docusign: {doc}") and body.
5. **Advanced options.** Reminders, expiration, recipient permissions (edit, sign on paper), comments, document
   visibility.
6. **Prepare** (tagging). Left palette; the owning recipient chosen from a dropdown; drag and drop onto pages; right
   panel for properties (required, data label, validation, conditional logic, tooltip, font, locked). **AutoPlace**
   puts a field at every occurrence of a text.
7. **Send**, preview as a recipient, schedule, or save a draft.

## 3. Signer flow

1. Email with **Review Document**; the link is a one-time token URL, re-issued on resend.
2. Landing: the ERSD checkbox ("I agree to use electronic records and signatures") and Continue. **Other Actions**:
   Finish Later, Print & Sign, Assign to Someone Else, Decline to Sign, Help & Support, About, View History, View
   Certificate, Session Information.
3. Optional identity step: access code, SMS or phone, KBA, IDV.
4. Documents render; a yellow **Start** flag jumps to the first required field and becomes **Next**. Required fields
   outlined red, optional dashed.
5. First Signature or Initial click opens **Adopt Your Signature**: confirm name and initials; choose a typed style,
   Draw, or Upload; **Adopt and Sign**. Reused for later fields; saved to the user's account if they have one.
6. **Finish**; download or print; account creation offered. Completed documents and the Certificate of Completion
   arrive when the envelope completes.

Exceptions: **Decline** (reason; envelope `declined`; sender notified); **Assign to someone else** (needs the sender
permission; original recipient in the audit trail); **Finish later** (Connect `recipient-finish-later`)
(https://developers.docusign.com/platform/webhooks/connect/event-triggers/) [V]; **In-person** (a user hosts and
confirms identity); **Embedded** (`clientUserId`, short-lived URL from `views/recipient`).

## 4. Recipient types

From https://developers.docusign.com/docs/esign-rest-api/esign101/concepts/recipients/ [V].

| API | UI | Semantics | OpenSeal ([22](22-DATA-MODEL.md) §5) | Slice |
| --- | --- | --- | --- | --- |
| `signers` | Needs to Sign | Signs, initials, fills fields | `signer` | 1 |
| `inPersonSigners` | In Person Signer | A user hosts a present signer | `in_person_signer` | 14 |
| `carbonCopies` | Receives a Copy | No action; copy when reached and at completion | `cc` | 2 |
| `certifiedDeliveries` | Needs to View | Must view to complete | `viewer` | 2 |
| `agents` | Specify Recipients | Supplies later recipients | `agent` | 2 |
| `editors` | Allow to Edit | Sender-like rights; needs an account | `editor` | 6 |
| `intermediaries` | Update Recipients | Adds or updates recipients at same or later levels | `intermediary` | 6 |
| `witnesses` | Signs with Witness | Confirms a signer's signature | `witness` | 16 |
| `notaries` | Signs with Notary | Remote online notarization | `notary` | 31 |
| `seals` | Electronic Seal | Legal-entity certificate seal | `seal` (via `RemoteSigner`) | 18 |

OpenSeal adds `approver` (DocuSign does approval with an `approveTabs` button on a signer; Documenso and SignNow have
an approver type).

## 5. Field (tab) types

From https://developers.docusign.com/docs/esign-rest-api/reference/envelopes/enveloperecipienttabs/ [V].

| Group | DocuSign tabs | OpenSeal |
| --- | --- | --- |
| Signing | `signHereTabs` (`stampType` signature, stamp, seal), `initialHereTabs`, `approveTabs`, `declineTabs` | `signature`, `stamp`, `initials`, `approve`, `decline` |
| Auto-filled | `dateSignedTabs`, `fullNameTabs`, `firstNameTabs`, `lastNameTabs`, `emailAddressTabs`, `companyTabs`, `titleTabs`, `envelopeIdTabs` | Same, plus `envelope_id` |
| Data | `textTabs` (≤4000 bytes, regex `validationPattern`, `maxLength`, `concealValueOnDocument`), `numberTabs`, `numericalTabs` (locale, currency, min, max), `dateTabs`, `emailTabs`, `ssnTabs`, `zipTabs`, `phoneNumberTabs`, `checkboxTabs`, `radioGroupTabs`, `listTabs`, `noteTabs`, `formulaTabs` (with `paymentDetails` becomes Payment), `signerAttachmentTabs`, `drawTabs`, `prefillTabs` | `text` (+ `mask`), `number` (+ locale, currency, min, max), `date`, `email_address`, `ssn`, `zip`, `phone`, `checkbox`, `radio_group`, `dropdown`, `note`, `formula`, `payment`, `attachment`, `drawing`, `prefill` flag |
| Other | `commentThreadTabs`, `polyLineOverlayTabs` (strike-through), `viewTabs`, `smartSectionTabs` (responsive), `tabGroups`, notary tabs | Comments (slice 26), strike-through (with `editor`), responsive signing (slice 23), groups; no notary |

Common properties [M]: position (`documentId`, `pageNumber`, `xPosition`, `yPosition`, `width`, `height`, in points,
top-left origin); `tabLabel` (data label; **same label on one recipient mirrors values**); `required`; `locked`;
`shared`, `requireAll`, `requireInitialOnSharedChange` (shared fields); `value`, `originalValue`, `tooltip`; font;
`templateLocked`, `templateRequired`; **conditional**: `conditionalParentLabel` + `conditionalParentValue`; **groups**:
`tabGroups` with `groupRule` `SelectAtLeast | SelectAtMost | SelectExactly | SelectARange`, `minimumRequired`,
`maximumAllowed`.

**Anchors / AutoPlace** [M]: `anchorString`, `anchorXOffset`, `anchorYOffset`, `anchorUnits` (pixels, inches, mms,
cms), `anchorIgnoreIfNotPresent`, `anchorCaseSensitive`, `anchorMatchWholeWord`, `anchorHorizontalAlignment`; the
text stays in the document, conventionally in white (`/sn1/`); 3,000 anchor tabs per envelope [V limits]. PDF form
fields become tabs through `transformPdfFields`. Account-level presets: **custom tabs**.

## 6. Envelope model and lifecycle

**Hierarchy:** Envelope → Documents[] → Recipients{signers[], carbonCopies[], …} → each recipient's Tabs. Envelope
also has `customFields`, `notification` (reminders, expiry), `emailSubject`, `emailBlurb`, `brandId`,
`eventNotification` (per-envelope webhook), `workflow` (steps, scheduled sending, delayed routing),
`enforceSignerVisibility`, `allowComments`, `allowReassign`, `envelopeIdStamping`.

**Statuses** (https://developers.docusign.com/docs/esign-rest-api/esign101/concepts/envelopes/status-codes/) [V]:
`created` (draft), `sent`, `delivered` (**all** recipients have viewed), `signed` (transient), `completed`,
`declined`, `voided` (by sender, or expired; the reason says which), `correct` (paused while the sender edits),
`template`; `deleted` and `timedout` are legacy. Recipient statuses [M]: `created`, `sent`, `delivered`, `signed`,
`declined`, `completed`, `faxPending`, `autoResponded` (bounce), `authenticationFailed`.

OpenSeal's states ([24](24-ENVELOPE-LIFECYCLE-AND-ROUTING.md)) differ deliberately in three places: `expired` is its own
state rather than a kind of `voided`; `completing` exists so nothing is `completed` before a verified seal; correction
is a mode, not a status. The API maps them for clients that expect DocuSign's set ([40](40-API-DESIGN.md) §Statuses).

**Operations.** **Correct** reopens an in-flight envelope (recipients, emails, tabs, documents; documents only where
nothing is signed yet [?]); embeddable as a correct view. **Void** with a reason; terminal. **Resend**
(`PUT /recipients?resend_envelope=true`). **Reminders** (after N days, every M days) and **expiration** (default 120
days, warning X days before [?]); expiry voids.

**Bulk send** [?]: one template plus a CSV, one envelope per row; role-based headers (`Signer::Name`,
`Signer::Email`, data labels, custom fields); API `bulk_send_lists` → `/test` → `/send` → `bulk_send_batch`; batch
limit 1,000 [?]; bulk envelopes ≤75 MB [V].

**PowerForms**: a public or emailed URL creating a self-service envelope from a template; Direct and Email modes; email
verification; usage limit; Business Pro and above [M].

**Templates**: documents, **roles** (`roleName`), tabs, message, routing, settings; used with `templateId` +
`templateRoles[]`, or **composite templates** (server and inline templates stacked). **Template matching** suggests
templates for an uploaded document [?]. Locking, sharing, edit or use-only permissions.

**Document visibility**: `enforceSignerVisibility`, `excludedDocuments`; a signer sees only documents with their tabs
or explicitly included.

**Routing**: `routingOrder`; **conditional routing** (rules on tab values, Enhanced add-on); **delayed routing** and
**scheduled sending** (`workflow.scheduledSending`).

Also: threaded **comments** during signing; envelope **custom fields** (500 per account, 100 characters); **branding**
(logo and colours on emails and signing UI, resource files, landing pages); **signing groups** (any member signs; 50
per account); **send on behalf** (impersonation via JWT) and **auto-delegate** while away.

## 7. Security and compliance

**Certificate of Completion** [V from public descriptions; exact layout ?] (https://www.docusign.com/blog/what-is-an-audit-trail,
https://docs.oracle.com/cd/E97083_01/en/docusign/tpm_docusign_guide_na.pdf, https://docusign.utexas.edu/verifying-signatures):
envelope summary (id, subject, documents, page, signature and initial counts, originator and IP, status, time zone);
record tracking (holder); **signer events** (name, email, security level, signature adoption method, signature image,
IP, sent, viewed, signed times, ERSD acceptance); sections for in-person, editor, agent, intermediary, certified
delivery, carbon copy, witness and notary events; summary events; payment events; the ERSD text. OpenSeal's version:
[32](32-AUDIT-TRAIL-AND-EVIDENCE.md) §6.

**History**: per action (registered, sent, viewed, signed, declined, voided, corrected, printed, downloaded, ERSD
accepted, authentication passed or failed, reassigned, finish later, reminders), user, IP, time and zone, status.

**Tamper evidence**: a PKI signature on the completed PDF, visible in Adobe; any byte change invalidates it [V]; the
envelope id stamped in the page header. Hash algorithm not documented [?]. **Encryption**: AES-256 at rest, TLS in
transit [V].

**Recipient authentication** (https://developers.docusign.com/docs/esign-rest-api/esign101/concepts/recipients/auth/) [V]:
access code; phone (voice or SMS OTP); KBA (LexisNexis, US only); ID Verification (photo ID and selfie, or eIDs);
federated identity. Delivery by email, SMS, WhatsApp.

**Legal**: ERSD customizable per account; eIDAS SES default, "EU Advanced" (certificate with IDV), "EU Qualified"
(through DocuSign France and TSPs); `seals` recipient type; Standards-Based Signatures add-on [M]. **Part 11 module**:
re-authentication at signing, signing reason printed with name and time
(https://www.docusign.com/sites/default/files/resource_event_files/simplify_21_cfr_part_11_compliance_documentation_2020.pdf) [V].
Certifications: SOC 1/2 Type 2, ISO 27001, PCI DSS [V], FedRAMP Moderate [M].

**Retention, residency**: retention policies purge documents after N days with notice, keeping metadata and the
certificate (`envelope-purge`); data centres in US, EU, CA, AU, JP [?]; an account is bound to one site.

## 8. eSignature REST API v2.1

Base `https://{server}.docusign.net/restapi/v2.1/accounts/{accountId}/…`, the server from `base_uri` in
`/oauth/userinfo` [M].

| Group | Resources [M, consistent with the reference] |
| --- | --- |
| Accounts | Settings, brands, custom fields, permission profiles, consumer disclosure, signature providers, password rules, identity verifications, watermark, seals |
| Envelopes | Create (`status: created|sent`), status changes, get, update (void), audit events, form data |
| Documents | `/documents/{id|combined|certificate|archive}` |
| Recipients, Tabs | CRUD; resend; document visibility |
| Views | `recipient` (embedded signing), `sender`, `edit`, `correct`, `console`, shared recipient view |
| Envelope sub-resources | Custom fields, attachments, **locks** (edit concurrency), workflow, comments, email settings, notification, document generation |
| Templates | As envelopes, plus template views |
| Bulk send | `bulk_send_lists`, `/send`, `/test`, `bulk_send_batch` |
| Connect | Configurations, failures, `republish`, logs |
| Users, Groups, SigningGroups, PowerForms, Folders, Payments, CloudStorage | |

**Auth** (https://developers.docusign.com/platform/auth/) [V]: Authorization Code (confidential, or PKCE), legacy
implicit, **JWT grant** (one-time consent to `signature impersonation`; RSA key on the integration; ~1 h tokens, no
refresh [M]).

**Embedded signing** [M]: `clientUserId` suppresses email; `POST /envelopes/{id}/views/recipient` with `returnUrl`,
`authenticationMethod`, `userName`, `email`, `clientUserId`; single-use URL valid ~5 minutes; return with
`event=signing_complete|cancel|decline|exception|id_check_failed|session_timeout|ttl_expired|viewing_complete`;
"focused view" for chrome-less iframes. Embedded sending and correcting through `views/sender` and `views/correct`
(https://developers.docusign.com/docs/esign-rest-api/esign101/concepts/embedding/) [V].

**Connect webhooks** (https://developers.docusign.com/platform/webhooks/connect/event-triggers/) [V]: envelope events
(`envelope-created`, `-sent`, `-delivered`, `-completed`, `-declined`, `-voided`, `-resent`, `-corrected`, `-purge`,
`-deleted`, `-removed`, `-discard`, `-reminder-sent`); recipient events (`recipient-sent`, `-autoresponded`,
`-delivered`, `-completed`, `-declined`, `-authenticationfailed`, `-resent`, `-delegate`, `-reassign`,
`-finish-later`); template events; click, SMS opt-in, IDV, workflow and notary events. JSON payload with
`data.envelopeSummary`, optional documents. **HMAC-SHA256** of the raw body in `X-DocuSign-Signature-1..N`, up to 100
keys for rotation (https://developers.docusign.com/platform/webhooks/connect/hmac/) [V]; OAuth and mTLS options;
retries with backoff for ~24 h then manual republish [?]; up to 20 account configurations or per-envelope.

**Limits** [V]: 3,000 calls per hour per account; bursts of 500 per 30 s (production); one status poll per envelope per
15 minutes; `X-RateLimit-*` headers; 100 recipients per envelope.

**SDKs**: C#, Java, Node.js, PHP, Python, Ruby, generated from the OpenAPI document published on GitHub [M].

## 9. Admin

Users (add, close, reactivate, CSV import; profile, groups, signature, address book). **Permission profiles** (Viewer,
Sender, Account Administrator, custom): send, use templates, create and share templates, bulk send, sign on paper,
signer attachments, PowerForms, API, Connect, reports, recipient permissions. Groups for sharing, brands and signing
groups. **Organization admin**: domain claims by DNS TXT, SAML 2.0 IdPs, require SSO, just-in-time provisioning, SCIM.
Account settings: password and session policy, ERSD, sending defaults, signing permissions, retention, notifications,
custom fields and tabs, stamps, payment gateways, Connect, integration keys. **Brands**: several per account, per
envelope or group. Envelope transfer when a user leaves; account-wide history.

## 10. Adjacent products

| Product | What | OpenSeal |
| --- | --- | --- |
| CLM | Authoring, redlining, clause library, repository | Add-on module, slice 32 |
| Rooms | Real-estate transaction rooms | Add-on module, slice 33 |
| Click | Clickwrap consent with audit | Slice 27 (small module) |
| Web Forms | Forms that generate agreements; successor to PowerForms | Slice 27 |
| Maestro | No-code workflow orchestration | Add-on module, slice 34 |
| IAM / Navigator | AI agreement repository and extraction | Add-on module, slice 35 |
| Notary, eWitness | Notarization; witnessing | Witness slice 16; notary slice 31 |
| Payments, Document Generation | Add-ons | Slice 13, slice 28 |

## 11. Pricing and gating [?]

The official page could not be fetched; third-party figures, mid to late 2026 (https://signeasy.com/blog/business/docusign-pricing,
https://www.costbench.com/software/e-signature/docusign/):

| Plan | ≈ per month, annual | Gates |
| --- | --- | --- |
| Personal | $11, one user | 5 envelopes a month; basic fields |
| Standard | $30 per user | ~100 envelopes per user per year; shared templates, comments, reminders, limited branding, in-person |
| Business Pro | $45 per user | Bulk Send, PowerForms, payments, signer attachments, conditional fields, formulas, validation, advanced branding |
| Enhanced | Custom | Conditional routing, SSO, advanced admin, retention and residency, Part 11, eIDAS, IDV add-ons |

API plans are separate and gated by volume. Add-ons (SMS, IDV, KBA, phone) are per use.

**Implication:** everything DocuSign gates above Standard ships in OpenSeal's open core. Paid *external services* (SMS,
IDV, KBA, QES, qualified TSA) stay behind provider seams, because they cost money per use whoever runs them.
