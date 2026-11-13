# 96 — Feature fit-gap

**Every feature of DocuSign eSignature and SignNow that a user or integrator would miss**, with a disposition, the
slice that delivers it, and its status. Sources: [48](48-DOCUSIGN-STUDY.md) (DS) and [49](49-SIGNNOW-STUDY.md) (SN).
This is the parity measure: at every slice close, the count of `Build` and `Plugin` rows marked `Works` is reported.

**Status values:** `—` not started, `Designed`, `Engine` (engine built and tested, no UI or API yet), `Works`
(merged, tested, in a browser run where it has UI).

**Disposition:** `Build` — in the core. `Plugin` — the core defines the seam and ships one provider. No row is `Out` or `Later` (owner
instructions 8 and 9). 

**Today: 41 of 168 rows work end to end; 16 more have their engine built and tested; 49 are designed, 20 are partial (`FG-012`, `FG-022`, `FG-023`, `FG-055`, `FG-060`, `FG-062`, `FG-063`, `FG-065`, `FG-066`, `FG-071`, `FG-072`, `FG-073`, `FG-076`, `FG-092`, `FG-131`, `FG-132`, `FG-133`, `FG-140`, `FG-183`, `FG-184`) and 43 are not started** (counted with `grep` over the Status column). Docs are true as of `19518fb` (2026-11-12), after v0.0.1. `Works` here means merged, tested, and exercised in a browser run where it has UI (the Playwright specs in `webapp/e2e`, in mock mode and, for send, sign and download, on the Compose stack in `compose-e2e`); a row that works only in part keeps its earlier status.

## Documents

| ID | Feature | From | Disp. | Slice | Status |
| --- | --- | --- | --- | --- | --- |
| FG-001 | Upload PDF | DS, SN | Build | 1 | Works |
| FG-002 | Upload Word, Excel, PowerPoint, images (converted) | DS, SN | Build | 6 | Designed |
| FG-003 | Import from URL | SN | Build | 8 | — |
| FG-004 | Import from cloud storage (Drive, OneDrive, Dropbox, Box) | DS | Plugin | 24 | — |
| FG-005 | Multiple documents per envelope; reorder | DS, SN (groups) | Build | 2 | Designed |
| FG-006 | Size limits: 50 MB per file, 200 MB per envelope | DS | Build | 1 | Designed |
| FG-007 | Neutralize JavaScript, actions, embedded files; report | — | Build | Phase 1 | Engine |
| FG-008 | Convert existing PDF form fields to fields | DS (`transformPdfFields`) | Build | 4 | Engine |
| FG-014 | Dynamic XFA forms: render, fill and sign | — | Build | 4 | Engine (`XFA-01`; gaps `XFA-02`..`XFA-05`) |
| FG-015 | Fill a PDF's own form fields in place and keep them fillable (alongside flattening) | — | Build | 4 | Engine |
| FG-009 | Envelope id stamping in page header | DS | Build | 6 | — |
| FG-010 | Document visibility per recipient | DS | Build | 6 | — |
| FG-011 | Document generation from DOCX templates | SN, DS add-on | Build | 28 | — |
| FG-012 | Template matching on upload | DS | Build | 3 | Partial: uploads to a draft are matched against the workspace's template page hashes when template matching is on (`WEB-19`); not run on the real stack in a browser |
| FG-013 | Sign on paper (print, sign, upload), with the upload admitted and recorded as evidence | DS | Build | 6 | — |

## Recipients and routing

| ID | Feature | From | Disp. | Slice | Status |
| --- | --- | --- | --- | --- | --- |
| FG-020 | Signer | DS, SN | Build | 1 | Works |
| FG-021 | Carbon copy | DS, SN | Build | 2 | Works |
| FG-022 | Needs to view (viewer) | DS, SN | Build | 2 | Partial: the editor adds viewers, who act in their turn with no fields (`UX-05`); the viewer ceremony is not run end to end |
| FG-023 | Approver | SN | Build | 2 | Partial: the editor adds approvers, who act in their turn with no fields (`UX-05`); the approver ceremony is not run end to end |
| FG-024 | Specify recipients (agent) | DS | Build | 2 | Designed |
| FG-025 | Allow to edit (editor) | DS | Build | 6 | Designed |
| FG-026 | Update recipients (intermediary) | DS | Build | 6 | Designed |
| FG-027 | In-person signer | DS, SN | Build | 14 | Engine (hosting served by `POST /envelopes/{id}/recipients/{r}/host`, `UXW-36`; the editor offers it, `UX-05`) |
| FG-028 | Witness | DS | Build | 16 | — |
| FG-029 | Notary (remote online notarization) | DS, SN | Build, with provider plugins | 31 | — |
| FG-030 | Electronic seal recipient | DS | Plugin | 18 | — |
| FG-031 | Sequential, parallel and mixed routing order | DS, SN | Build | 2 | Works |
| FG-032 | Conditional routing | DS | Build | 29 | Designed |
| FG-033 | Signing groups | DS | Build | 29 | — |
| FG-034 | Scheduled sending; delayed routing | DS | Build | 29 | — |
| FG-035 | Reassign / assign to someone else | DS, SN | Build | 2 | Works (signer's `POST /s/{token}/reassign`, `WEB-07`) |
| FG-036 | Auto-delegate while away | DS | Build | 29 | — |
| FG-037 | Free-form signer (places own signature) | SN | Build | 4 | Designed |
| FG-038 | Per-recipient private message and language | DS | Build | 2 | Designed |
| FG-039 | Delivery by SMS | DS | Plugin | 5 | — |
| FG-040 | Delivery by WhatsApp | DS | Plugin | 5 | — |
| FG-041 | 100 recipients per envelope | DS | Build | 2 | Designed |

## Fields

| ID | Feature | From | Disp. | Slice | Status |
| --- | --- | --- | --- | --- | --- |
| FG-050 | Signature (draw, type, upload) | DS, SN | Build | 1 | Works |
| FG-051 | Initials | DS, SN | Build | 1 | Works |
| FG-052 | Optional signature | DS | Build | 4 | Designed |
| FG-053 | Stamp | DS, SN | Build | 4 | Engine |
| FG-054 | Date signed | DS | Build | 1 | Works |
| FG-055 | Name, first, last, email, company, title (auto-filled) | DS | Build | 1 | Partial: name, email, company and title placed (`UX-05`); first and last name not in the palette |
| FG-056 | Envelope id field | DS | Build | 4 | Designed |
| FG-057 | Text (single, multi-line, max length, mask) | DS, SN | Build | 1 | Engine |
| FG-058 | Number with locale, currency, min, max | DS, SN | Build | 4 | Engine |
| FG-059 | Date with format | DS, SN | Build | 4 | Engine |
| FG-060 | Email, phone, SSN, ZIP validations; regex | DS, SN | Build | 4 | Partial: the editor places and configures it and the mock round-trips it (`UX-05`); the ceremony checks them (`WEB-06`); no real-stack run yet |
| FG-061 | Checkbox; checkbox group rules | DS, SN | Build | 4 | Engine |
| FG-062 | Radio group | DS, SN | Build | 4 | Partial: the editor places and configures it and the mock round-trips it (`UX-05`); the ceremony fills it (`WEB-06`); no real-stack run yet |
| FG-063 | Dropdown (with custom entry) | DS, SN | Build | 4 | Partial: the editor places and configures it and the mock round-trips it (`UX-05`); the ceremony fills it (`WEB-06`); no real-stack run yet |
| FG-064 | Formula / calculated field | DS, SN | Build | 4 | Engine |
| FG-065 | Signer attachment | DS, SN | Build | 4 | Partial: the editor places and configures it and the mock round-trips it (`UX-05`); the ceremony takes the file (`WEB-06`); no real-stack run yet |
| FG-066 | Note | DS | Build | 4 | Partial: the editor places and configures it and the mock round-trips it (`UX-05`); the ceremony shows it (`WEB-06`); no real-stack run yet |
| FG-067 | Approve and decline buttons | DS | Build | 4 | Designed |
| FG-068 | Hyperlink | SN | Build | 4 | Designed |
| FG-069 | Drawing area | DS | Build | 4 | — |
| FG-070 | Payment field | DS, SN | Plugin | 13 | Designed |
| FG-071 | Prefill (sender-filled) fields | DS, SN | Build | 4 | Partial: a sender's value, read only or starting, on text, company, title, number and checkbox (`UX-05`); no real-stack run yet |
| FG-072 | Required, read-only, locked | DS, SN | Build | 1 | Partial: required and read only in the editor (`UX-05`); locked not offered |
| FG-073 | Data labels; linked fields (same label mirrors) | DS | Build | 4 | Partial: the data label is set in the editor (`UX-05`); mirroring is the engine's, not run in a browser |
| FG-074 | Shared fields across signers | DS | Build | 4 | — |
| FG-075 | Conditional fields | DS, SN | Build | 4 | Engine |
| FG-076 | Font, size, colour, alignment | DS, SN | Build | 4 | Partial: font, size and alignment in the editor (`UX-05`); colour not offered |
| FG-077 | Anchor text auto-place | DS | Build | 4 | Engine |
| FG-078 | Text tags in documents | SN | Build | 4 | Engine |
| FG-079 | Custom (saved) field presets | DS | Build | 4 | — |
| FG-080 | Strike-through by editor | DS | Build | 6 | — |
| FG-081 | Responsive signing (smart sections) | DS | Build | 23 | — |
| FG-082 | 3,000 fields per envelope | DS | Build | 4 | Designed |

## Sending

| ID | Feature | From | Disp. | Slice | Status |
| --- | --- | --- | --- | --- | --- |
| FG-090 | Recipients-first preparation | DS | Build | 2 | Works |
| FG-091 | Document-first editor with roles assigned in place | SN | Build | 1 | Works |
| FG-092 | Preview as recipient | DS | Build | 2 | Partial: Review's Preview as shows the recipient's fields on the document (`UX-05`); a preview of their signing page is not built |
| FG-093 | Custom subject and message | DS, SN | Build | 1 | Works |
| FG-094 | Reminders | DS, SN | Build | 2 | Works |
| FG-095 | Expiration and warning | DS, SN | Build | 2 | Designed |
| FG-096 | Templates with roles | DS, SN | Build | 3 | Works |
| FG-097 | Composite templates (several into one envelope) | DS | Build | 3 | Designed |
| FG-098 | Template sharing, folders, favourites, locking | DS | Build | 3 | Designed |
| FG-099 | Document group templates | SN | Build | 3 | Designed |
| FG-100 | Bulk send (CSV, API, test row, progress) | DS, SN | Build | 11 | Designed |
| FG-101 | Signing links / PowerForms | DS, SN | Build | 11 | Designed |
| FG-102 | QR code for signing links | SN | Build | 11 | Designed |
| FG-103 | Self-sign ("Sign a document" for oneself) | DS, SN | Build | 2 | — |
| FG-104 | Send on behalf of another user | DS | Build | 10 | — |

## Signing

| ID | Feature | From | Disp. | Slice | Status |
| --- | --- | --- | --- | --- | --- |
| FG-110 | Email invitation with one-time link | DS, SN | Build | 1 | Works |
| FG-111 | ERSD consent, versioned | DS | Build | 5 | Works |
| FG-112 | Start / Next guided navigation | DS | Build | 1 | Works |
| FG-113 | Adopt signature (style, draw, upload) | DS, SN | Build | 1 | Works |
| FG-114 | Review flattened result before finishing | — (ours) | Build | 1 | Works |
| FG-115 | Finish later | DS | Build | 2 | Works |
| FG-116 | Decline with reason | DS, SN | Build | 2 | Works |
| FG-117 | Access code | DS, SN | Build | 5 | Works |
| FG-118 | Email OTP | — | Build | 5 | Works |
| FG-119 | SMS OTP, phone call | DS, SN | Plugin | 5 | Works: `sms_otp` and `voice_otp` through the worker's `Messenger` with an HTTPS gateway, in the signing page and the editor (VS-05, `tests/sms_otp.rs`; browser run `e2e/recipient-auth.spec.mjs`, mock mode); provider-specific adapters `MSG-01`; the Compose run `RAUTH-02` |
| FG-217 | Signer sign-in through an identity provider (OpenID Connect) | DS | Build | 5 | Works: `sso`, the operator's providers, PKCE, state and nonce, the verified email bound to the recipient, issuer and subject hash in the chain (`RAUTH-01`, ADR-033 Proposed, `tests/ceremony_sso.rs`; browser run `e2e/recipient-auth.spec.mjs`, mock mode); the Compose run `RAUTH-02` |
| FG-120 | Knowledge-based authentication | DS | Plugin | 18 | — |
| FG-121 | ID verification (document + selfie, eID) | DS | Plugin | 18 | — |
| FG-122 | Kiosk mode | SN | Build | 14 | — |
| FG-123 | Mobile-first signing | DS, SN | Build | 1 | Works |
| FG-124 | Accessible signing (WCAG 2.2 AA) | DS | Build | 1 | Designed |
| FG-125 | Signer language choice | DS, SN | Build | 12 | — |
| FG-126 | Comments during signing | DS | Build | 26 | — |
| FG-127 | Account creation and saved signature for returning signers | DS | Build | 10 | — |

## Managing and reporting

| ID | Feature | From | Disp. | Slice | Status |
| --- | --- | --- | --- | --- | --- |
| FG-130 | Inbox, Sent, Drafts, Deleted, folders | DS | Build | 6 | Partial: the Inbox (envelopes waiting for the signed-in member, signed from inside the app, `UXW-01`), each member's own folders, the Deleted view of envelopes and of templates with template restore (`UXW-02`) served; restoring a deleted envelope awaits ADR-031 |
| FG-131 | Quick views: action required, waiting, expiring, completed, auth failed | DS | Build | 6 | Partial: declined or expired, waiting, expiring soon (7 days, filtered in the page), completed, with counts on Home and the rail (`UX-07`); waiting for me from the Inbox (`UXW-01`); auth failed not yet |
| FG-132 | Search and filters incl. custom fields | DS | Build | 6 | Partial: text search (from every screen and on phones, `UX-04`), status set, sender, last-change range, five sorts (`WEB-04`, `WEB-08`); recipient and a range on created, sent, completed or last change, server-side (`UXW-03`); custom fields not yet |
| FG-133 | Correct | DS | Build | 6 | Partial: a side panel changes name, email, access code and signing order of recipients who have not acted, adds and removes them, and sets expiry and reminders (`POST /correct` and `PATCH …/recipients/{r}`; `UX-07`, tested in mock mode); fields and documents are `UXW-19` |
| FG-134 | Void with reason | DS, SN | Build | 2 | Works |
| FG-135 | Resend | DS, SN | Build | 2 | Works |
| FG-136 | Copy; save as template | DS | Build | 6 | Works |
| FG-137 | Transfer ownership | DS | Build | 10 | Designed |
| FG-138 | History view | DS, SN | Build | 6 | Works (staff audit view; the signer's own `GET /s/{token}/history`, `WEB-07`) |
| FG-139 | Envelope custom fields | DS | Build | 6 | Designed |
| FG-140 | Reports and CSV export | DS | Build | 6 | Partial: Agreements exports the selected envelopes as CSV, formula-safe (`UX-07`); server reports are `UXW-25`; Reports page: an envelope report with sample sizes, custom range, sender filter and a nine-column CSV over the newest 1,000, computed in the page, `UX-08`; recipient and usage reports wait for REP-01 |
| FG-141 | Insights dashboard | DS | Build | 6 | — |

## Evidence and verification

| ID | Feature | From | Disp. | Slice | Status |
| --- | --- | --- | --- | --- | --- |
| FG-150 | Certificate of completion | DS, SN | Build | 1 | Works; a declined, voided or expired envelope gets a sealed envelope certificate saying how it ended, never claiming completion (`UXW-30`) |
| FG-151 | Audit trail (history) download | DS, SN | Build | 1 | Works |
| FG-152 | Tamper-evident seal on completed PDF | DS | Build | 1 | Works |
| FG-153 | RFC 3161 trusted time (B-T) | — | Build | 1 | Works |
| FG-154 | Long-term validation (B-LT, B-LTA) | — | Build | 7, 17 | Engine |
| FG-155 | Audit trail embedded in the PDF | — (ours) | Build | 1 | Works |
| FG-156 | Hash-chained audit events | — (ours) | Build | Phase 1 | Works |
| FG-157 | Offline verification page and CLI | — (ours) | Build | 7 | Works |
| FG-158 | Public anchoring of chain heads | — (ours) | Build | 7 | Designed |
| FG-159 | Per-signer seals; certification signature | — | Build | 16 | Engine |
| FG-160 | PDF/A-3 output | — | Build | 17 | Designed |
| FG-161 | AES / QES via QTSP (CSC API) | DS (EU Advanced, Qualified) | Plugin | 18 | Designed |
| FG-162 | 21 CFR Part 11 mode | DS | Build | 19 | Designed |

## Account and admin

| ID | Feature | From | Disp. | Slice | Status |
| --- | --- | --- | --- | --- | --- |
| FG-170 | Users, CSV import, close, reactivate | DS | Build | 10 | Designed |
| FG-171 | Permission profiles (built-in and custom) | DS | Build | 10 | Designed |
| FG-172 | Groups | DS | Build | 10 | Designed |
| FG-173 | SSO: SAML 2.0 and OIDC; require SSO; JIT provisioning | DS, SN | Build | 10 | Designed |
| FG-174 | Domain claims | DS | Build | 10 | Designed |
| FG-175 | SCIM provisioning | DS | Build | 10 | Designed |
| FG-176 | Brands (logo, colours, emails, landing pages) | DS, SN | Build | 12 | — |
| FG-177 | ERSD editing | DS | Build | 5 | Partial: `POST /ersd-versions` publishes and requires a version in one step (`ERSD-01`); the Admin card edits it against the mock; real-stack e2e left (`UXW-12`) |
| FG-178 | Retention and purge policies | DS | Build | 15 | Designed |
| FG-179 | Legal hold | — | Build | 15 | — |
| FG-180 | Data residency (region tags) | DS | Build | 15 | — |
| FG-181 | BYOK per-tenant keys | — | Build | 15 | — |
| FG-182 | Password and session policy; MFA (TOTP, WebAuthn) | DS | Build | 10 | — |
| FG-183 | Admin audit log | DS | Build | 10 | Partial: every settings, member, profile, workspace and organization change writes a hash-chained event in its transaction, and the workspace log lists and exports (JSON, CSV) through `GET /admin-events` (`ORG-05`); the organization's through `GET /organizations/me/audit` (`ORG-03`); screens wait for ORG-06 |
| FG-184 | Organizations / multiple accounts | DS, SN | Build | 10 | Partial: one identity in several workspaces lists them and switches between them (`GET /auth/workspaces`, `POST /auth/switch`, the sidebar's workspace menu; `ORG-04`), organization routes (`ORG-03`); admin screens wait for ORG-06 |

## Developer surface

| ID | Feature | From | Disp. | Slice | Status |
| --- | --- | --- | --- | --- | --- |
| FG-190 | REST API with OpenAPI document | DS, SN | Build | 8 | Works |
| FG-191 | OAuth authorization code with PKCE | DS, SN | Build | 8 | Designed |
| FG-192 | JWT bearer grant (service integrations) | DS | Build | 8 | Designed |
| FG-193 | API keys | — | Build | Phase 2 | Works |
| FG-194 | Webhooks: account and per-envelope, HMAC, rotation | DS, SN | Build | 8 | Works |
| FG-195 | Webhook delivery log and redeliver | DS, SN | Build | 8 | Partial: Admin lists subscriptions and their latest deliveries (`UX-08`); the server edits, pauses and resumes a subscription, sends a test event and redelivers through the worker (`UXW-31` to `UXW-33`). Not checked on the Compose stack yet |
| FG-196 | Embedded signing view | DS, SN | Build | 9 | Designed |
| FG-197 | Embedded sending / prepare view | DS, SN | Build | 9 | Designed |
| FG-198 | Embedded correct and template edit views | DS, SN | Build | 9 | Designed |
| FG-199 | SDKs (TS, Python, then Java, C#, Go, PHP, Ruby) | DS | Build | 8 | Designed |
| FG-200 | Sandbox / demo environment | DS, SN | Build | 8 | — |
| FG-201 | Rate limit headers | DS | Build | Phase 2 | Works |
| FG-202 | DocuSign-compatible API | — | Build, subject to counsel (`DEC-10`) | 25 | — |
| FG-203 | MCP agent access | — (sisters) | Build | 22 | — |
| FG-204 | Integrations: Salesforce, Microsoft 365, Google Workspace, HubSpot, Zapier | DS, SN | Plugin | 24 | — |
| FG-205 | Clickwrap | DS Click | Build | 27 | — |
| FG-206 | Web forms | DS Web Forms | Build | 27 | — |

## Platform

| ID | Feature | From | Disp. | Slice | Status |
| --- | --- | --- | --- | --- | --- |
| FG-210 | Self-hosting: Docker Compose | — | Build | Phase 2 | Works |
| FG-211 | Kubernetes Helm chart, HA | — | Build | 20 | — |
| FG-212 | HSM and cloud KMS key custody | — | Build | Phase 2, 20 | Designed |
| FG-213 | Mobile apps (iOS, Android), with offline signing that syncs | DS, SN | Build | 30 | — |
| FG-214 | Desktop app | — (sisters) | Build | 21 | — |
| FG-215 | Payments through Stripe | DS, SN | Plugin | 13 | Designed |
| FG-216 | CLM, Rooms, Maestro, Navigator equivalents | DS | Build, as add-on modules | 32–35 | — |
