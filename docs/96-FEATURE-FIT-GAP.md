# 96 — Feature fit-gap

**Every feature of DocuSign eSignature and SignNow that a user or integrator would miss**, with a disposition, the
slice that delivers it, and its status. Sources: [48](48-DOCUSIGN-STUDY.md) (DS) and [49](49-SIGNNOW-STUDY.md) (SN).
This is the parity measure: at every slice close, the count of `Build` and `Plugin` rows marked `Works` is reported.

**Status values:** `—` not started, `Designed`, `Engine` (engine built and tested, no UI or API yet), `Works`
(merged, tested, in a browser run where it has UI).

**Disposition:** `Build` — in the core. `Plugin` — the core defines the seam and ships one provider. No row is `Out` or `Later` (owner
instructions 8 and 9). 

**Today: 52 of 168 rows work end to end; 5 more have their engine built and tested; 29 are designed, 45 are partial (`FG-008`, `FG-012`, `FG-025`, `FG-026`, `FG-053`, `FG-056`, `FG-058`, `FG-059`, `FG-060`, `FG-061`, `FG-062`, `FG-063`, `FG-064`, `FG-065`, `FG-066`, `FG-067`, `FG-068`, `FG-069`, `FG-071`, `FG-073`, `FG-074`, `FG-075`, `FG-076`, `FG-077`, `FG-078`, `FG-092`, `FG-095`, `FG-097`, `FG-098`, `FG-100`, `FG-130`, `FG-131`, `FG-132`, `FG-133`, `FG-137`, `FG-139`, `FG-140`, `FG-154`, `FG-171`, `FG-172`, `FG-177`, `FG-182`, `FG-183`, `FG-184`, `FG-195`) and 37 are not started** (counted with `grep` over the Status column; 168 rows; recounted 2026-11-19 for slice 4 (`VS-04`): `FG-053`, `FG-056`, `FG-058`, `FG-059`, `FG-061`, `FG-064`, `FG-067`, `FG-068`, `FG-069`, `FG-075`, then `FG-074`, `FG-077`, `FG-078`, `FG-008` to Partial, built on a branch; the 2026-11-19 slice-3 line said 51 working where the rows counted 52). Counts recounted 2026-11-17: the 2026-11-13 line said 42 not started, which did not add up to the rows (`DOC-008`). `Works` here means merged, tested, and exercised in a browser run where it has UI (the Playwright specs in `webapp/e2e`, in mock mode and, for send, sign and download, on the Compose stack in `compose-e2e`); a row that works only in part keeps its earlier status.

## Documents

| ID | Feature | From | Disp. | Slice | Status |
| --- | --- | --- | --- | --- | --- |
| FG-001 | Upload PDF | DS, SN | Build | 1 | Works |
| FG-002 | Upload Word, Excel, PowerPoint, images (converted) | DS, SN | Build | 6 | Designed |
| FG-003 | Import from URL | SN | Build | 8 | — |
| FG-004 | Import from cloud storage (Drive, OneDrive, Dropbox, Box) | DS | Plugin | 24 | — |
| FG-005 | Multiple documents per envelope; reorder | DS, SN (groups) | Build | 2 | Designed |
| FG-006 | Size limits: 50 MB per file, 200 MB per envelope | DS | Build | 1 | Works: 50 MiB per file in the editor and the API; 200 MiB per envelope in the API, at create and on every later upload (server `tests/threats.rs`, `VS-01`); in the browser a file over 50 MB is refused with its message and the server's `413` for an envelope over 200 MB is said in the editor (`field-kinds.spec.mjs`, both seen red, `S1-05`) |
| FG-007 | Neutralize JavaScript, actions, embedded files; report | — | Build | Phase 1 | Engine |
| FG-008 | Convert existing PDF form fields to fields | DS (`transformPdfFields`) | Build | 4 | Partial: Detect fields suggests a PDF's own form fields (`source: acroform`, named after themselves), placed in the editor for the chosen signer (`fields.spec.mjs`; mock `slice4-mock.test.mjs`); filling in place (`FG-015`) is not offered as a send option; built on a branch (`VS-04`, [75](75-SLICE-4-EVIDENCE.md)); `Works` once `fields.spec.mjs` is green on `main` |
| FG-014 | Dynamic XFA forms: render, fill and sign | — | Build | 4 | Engine (`XFA-01`; gaps `XFA-02`..`XFA-05`) |
| FG-015 | Fill a PDF's own form fields in place and keep them fillable (alongside flattening) | — | Build | 4 | Engine |
| FG-009 | Envelope id stamping in page header | DS | Build | 6 | Built on a branch (`VS-06E1`, ADR-045): per envelope and account default, set in the editor's options and Admin; drawn on every page by the flattener, shown on the signing page, in the in-progress and sealed documents; `Works` once `vs06e-screens.spec.mjs` is green on `main` |
| FG-010 | Document visibility per recipient | DS | Build | 6 | Works: engine, server (a hidden document is neither listed nor served to that recipient, `404`), editor's More options per recipient (`WF-02`) |
| FG-011 | Document generation from DOCX templates | SN, DS add-on | Build | 28 | — |
| FG-012 | Template matching on upload | DS | Build | 3 | Partial: uploads to a draft are matched against the workspace's template page hashes when template matching is on (`WEB-19`); not run on the real stack in a browser |
| FG-013 | Sign on paper (print, sign, upload), with the upload admitted and recorded as evidence | DS | Build | 6 | — |

## Recipients and routing

| ID | Feature | From | Disp. | Slice | Status |
| --- | --- | --- | --- | --- | --- |
| FG-020 | Signer | DS, SN | Build | 1 | Works |
| FG-021 | Carbon copy | DS, SN | Build | 2 | Works |
| FG-022 | Needs to view (viewer) | DS, SN | Build | 2 | Works (the editor adds viewers, `UX-05`; the viewer completes by viewing every document to the end through the ceremony on the server, `VS-02` tests/routing.rs; the signing page ends their turn and the receipt says viewed, browser run `webapp/e2e/recipient-types.spec.mjs`, `RTE-01`) |
| FG-023 | Approver | SN | Build | 2 | Works (the editor adds approvers, `UX-05`; the approver approves through the ceremony on the server, `VS-02` tests/routing.rs; the review step offers Approve and the receipt says approved, browser run `webapp/e2e/recipient-types.spec.mjs`, `RTE-01`) |
| FG-024 | Specify recipients (agent) | DS | Build | 2 | Works (the editor offers the agent; the agent names later recipients through `POST /s/{token}/recipients` and finishes, routing then reaching them, `VS-02` tests/routing.rs; the signing page asks for the names and emails, browser run `webapp/e2e/recipient-types.spec.mjs`, `RTE-01`) |
| FG-025 | Allow to edit (editor) | DS | Build | 6 | Partial: offered in the editor; an editor names later recipients in their turn, then signs (`tests/editor_intermediary.rs`); changing fields at the ceremony is `VS-06A`; built on a branch (`VS-06`, [77](77-SLICE-6-EVIDENCE.md)); `Works` once `manage-correct.spec.mjs` is green on `main` |
| FG-026 | Update recipients (intermediary) | DS | Build | 6 | Partial: offered in the editor; an intermediary updates later recipients' names and emails, then finishes (`tests/editor_intermediary.rs`); changing authentication is `VS-06A`; built on a branch (`VS-06`, [77](77-SLICE-6-EVIDENCE.md)); `Works` once `manage-correct.spec.mjs` is green on `main` |
| FG-027 | In-person signer | DS, SN | Build | 14 | Engine (hosting served by `POST /envelopes/{id}/recipients/{r}/host`, `UXW-36`; the editor offers it, `UX-05`; the envelope page's "Host signing" opens the hosted session in the tab, `UXW-18`, in a mock-mode browser run, `webapp/e2e/recipient-types.spec.mjs`; the Compose spec `real-stack.spec.mjs` green on chromium and webkit in `compose-e2e`, 2026-11-14) |
| FG-028 | Witness | DS | Build | 16 | — |
| FG-029 | Notary (remote online notarization) | DS, SN | Build, with provider plugins | 31 | — |
| FG-030 | Electronic seal recipient | DS | Plugin | 18 | — |
| FG-031 | Sequential, parallel and mixed routing order | DS, SN | Build | 2 | Works |
| FG-032 | Conditional routing | DS | Build | 29 | Designed |
| FG-033 | Signing groups | DS | Build | 29 | Designed |
| FG-034 | Scheduled sending; delayed routing | DS | Build | 29 | Works: engine, server (`PUT/DELETE …/schedule`, `route_delay_hours`), editor's "Send at" and per-recipient wait (`WF-02`); the mock records but does not fire them |
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
| FG-053 | Stamp | DS, SN | Build | 4 | Partial: an uploaded image adopted as a stamp (`mark: stamp`) fills only a stamp field, drawn in the seal (server `tests/every_field.rs`, seen red); built on a branch (`VS-04`, [75](75-SLICE-4-EVIDENCE.md)); `Works` once `fields.spec.mjs` is green on `main` |
| FG-054 | Date signed | DS | Build | 1 | Works |
| FG-055 | Name, first, last, email, company, title (auto-filled) | DS | Build | 1 | Works: name, email, company and title placed (`UX-05`), company and title typed by the signer (pre-filling them from a recipient's account is `S1-07`); first and last name in the palette, shown to the signer and filled at finish from the recipient's name, cut at its first space (docs/24 §5; workflow `transitions.rs` and `field-kinds.spec.mjs`, seen red, `S1-03`) |
| FG-056 | Envelope id field | DS | Build | 4 | Partial: written by the server at finish, shown to the signer, drawn (`tests/every_field.rs`); built on a branch (`VS-04`, [75](75-SLICE-4-EVIDENCE.md)); `Works` once `fields.spec.mjs` is green on `main` |
| FG-057 | Text (single, multi-line, max length, mask) | DS, SN | Build | 1 | Works: single-line text, with max length and mask in the editor, placed, filled on a phone and sealed (`VS-01`); multi-line (`format.multiline`): offered in the editor, typed with line breaks in a text area, drawn line by line from the box's top (flatten `a_multi_line_text_field_draws_each_line_from_the_top_of_its_box`, `field-kinds.spec.mjs`, seen red, `S1-01`) |
| FG-058 | Number with locale, currency, min, max | DS, SN | Build | 4 | Partial: number fields with min, max and decimals filled and refused through the ceremony (`WEB-06`, `tests/field_types.rs`); locale and currency display not in the editor; built on a branch (`VS-04`, [75](75-SLICE-4-EVIDENCE.md)); `Works` once `fields.spec.mjs` is green on `main` |
| FG-059 | Date with format | DS, SN | Build | 4 | Partial: typed in its format (`format.date_format` or a date rule), checked on the page and by the engine, drawn (`tests/every_field.rs`, web `slice4.test.mjs`, seen red); built on a branch (`VS-04`, [75](75-SLICE-4-EVIDENCE.md)); `Works` once `fields.spec.mjs` is green on `main` |
| FG-060 | Email, phone, SSN, ZIP validations; regex | DS, SN | Build | 4 | Partial: email address, phone, SSN and ZIP kinds and the email, phone, ZIP, SSN, length, number, date and regex rules (with the sender's message) checked on the page as the engine checks them and refused by the server (`tests/every_field.rs`, `slice4.test.mjs`); built on a branch (`VS-04`, [75](75-SLICE-4-EVIDENCE.md)); `Works` once `fields.spec.mjs` is green on `main` |
| FG-061 | Checkbox; checkbox group rules | DS, SN | Build | 4 | Partial: checkbox groups set in the editor's Logic panel (at least, at most, exactly); finish refused naming each box until the rule holds (`tests/every_field.rs`); built on a branch (`VS-04`, [75](75-SLICE-4-EVIDENCE.md)); `Works` once `fields.spec.mjs` is green on `main` |
| FG-062 | Radio group | DS, SN | Build | 4 | Partial: the editor places and configures it and the mock round-trips it (`UX-05`); the ceremony fills it (`WEB-06`); no real-stack run yet |
| FG-063 | Dropdown (with custom entry) | DS, SN | Build | 4 | Partial: the editor places and configures it and the mock round-trips it (`UX-05`); the ceremony fills it (`WEB-06`); no real-stack run yet |
| FG-064 | Formula / calculated field | DS, SN | Build | 4 | Partial: set in the editor (expression and decimal places); the signing view shows the server's own result after each fill (`rules.computed`), sealed with it (`tests/every_field.rs`, seen red without `rules`); built on a branch (`VS-04`, [75](75-SLICE-4-EVIDENCE.md)); `Works` once `fields.spec.mjs` is green on `main` |
| FG-065 | Signer attachment | DS, SN | Build | 4 | Partial: the editor places and configures it and the mock round-trips it (`UX-05`); the ceremony takes the file (`WEB-06`); no real-stack run yet |
| FG-066 | Note | DS | Build | 4 | Partial: the editor places and configures it and the mock round-trips it (`UX-05`); the ceremony shows it (`WEB-06`); no real-stack run yet |
| FG-067 | Approve and decline buttons | DS | Build | 4 | Partial: Approve finishes and Decline declines from the field on the page; nothing drawn; built on a branch (`VS-04`, [75](75-SLICE-4-EVIDENCE.md)); `Works` once `fields.spec.mjs` is green on `main` |
| FG-068 | Hyperlink | SN | Build | 4 | Partial: the sender's address, opened in a new tab without an opener, http and https only (`slice4.test.mjs`); built on a branch (`VS-04`, [75](75-SLICE-4-EVIDENCE.md)); `Works` once `fields.spec.mjs` is green on `main` |
| FG-069 | Drawing area | DS | Build | 4 | Partial: drawn on a pad, adopted as a drawing (`mark: drawing`), fills only a drawing field, drawn in the seal (`tests/every_field.rs`); built on a branch (`VS-04`, [75](75-SLICE-4-EVIDENCE.md)); `Works` once `fields.spec.mjs` is green on `main` |
| FG-070 | Payment field | DS, SN | Plugin | 13 | Designed |
| FG-071 | Prefill (sender-filled) fields | DS, SN | Build | 4 | Partial: a sender's value, read only or starting, on text, company, title, number and checkbox (`UX-05`); no real-stack run yet |
| FG-072 | Required, read-only, locked | DS, SN | Build | 1 | Works: required and read only in the editor (`UX-05`); Locked offered in the editor, sent and kept by the API, shown fixed by the ceremony, which refuses a change (`field-kinds.spec.mjs`, seen red, `S1-04`) |
| FG-073 | Data labels; linked fields (same label mirrors) | DS | Build | 4 | Partial: the data label is set in the editor (`UX-05`); same-recipient fields with one label mirror on the signing page as the server says (`rules.values`) and are sealed with one value (`tests/every_field.rs`); built on a branch (`VS-04`, [75](75-SLICE-4-EVIDENCE.md)); `Works` once `fields.spec.mjs` is green on `main` |
| FG-074 | Shared fields across signers | DS | Build | 4 | Partial: `shared_with` on a field (API, editor's "Also filled by"); each shared signer sees and changes it, each change their own event, the last value sealed (server `tests/every_field.rs`, seen red); built on a branch (`VS-04`, [75](75-SLICE-4-EVIDENCE.md)); `Works` once `fields.spec.mjs` is green on `main` |
| FG-075 | Conditional fields | DS, SN | Build | 4 | Partial: set in the editor's Logic panel (parent label; checked, not checked, filled in, or a value); hidden and shown on the signing page as the server says (`rules.hidden`), a hidden field never required and its value dropped (`tests/every_field.rs`, seen red); built on a branch (`VS-04`, [75](75-SLICE-4-EVIDENCE.md)); `Works` once `fields.spec.mjs` is green on `main` |
| FG-076 | Font, size, colour, alignment | DS, SN | Build | 4 | Partial: font, size and alignment in the editor (`UX-05`); colour not offered |
| FG-077 | Anchor text auto-place | DS | Build | 4 | Partial: `anchor` on a field in create and `POST /fields`, one field per match in the delivered document (server `tests/anchors_tags.rs`, seen red); not offered in the editor (the editor places by hand or by Detect fields); built on a branch (`VS-04`, [75](75-SLICE-4-EVIDENCE.md)); `Works` once `fields.spec.mjs` is green on `main` |
| FG-078 | Text tags in documents | SN | Build | 4 | Partial: `"text_tags": true` on create places the tags' fields; Detect fields suggests each tag in the editor (`tests/anchors_tags.rs`, seen red; `fields.spec.mjs`); the tag text stays visible; built on a branch (`VS-04`, [75](75-SLICE-4-EVIDENCE.md)); `Works` once `fields.spec.mjs` is green on `main` |
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
| FG-095 | Expiration and warning | DS, SN | Build | 2 | Partial: an envelope's expiry is set on send or correct; the worker emails the warning (account `workflow_policy.expiry_warning_days`) and expires the envelope on time, telling the sender and the recipients whose turn it was (`VS-02`, worker tests/expiry.rs); an admin sets the warning days on the Organization page (`RTE-03`, `webapp/e2e/admin-screens.spec.mjs`) |
| FG-096 | Templates with roles | DS, SN | Build | 3 | Works |
| FG-097 | Composite templates (several into one envelope) | DS | Build | 3 | Partial: built and tested, not yet on a green `main` run (`VS-03A`): `POST /envelopes/from-templates` makes one envelope from one to ten templates from their stored documents, roles matched by name across them; the Use page's "Add a template"; `tests/use_templates.rs` (RLS on and off), `templates.spec.mjs` in mock mode on chromium and webkit; `Works` once `compose-e2e` runs it green on `main` |
| FG-098 | Template sharing, folders, favourites, locking | DS | Build | 3 | Partial: sharing with members, groups and the whole workspace (use, or edit with Can edit), Shared with me and Favourites served deny-by-default and in the web app (`UXW-06`), run on the Compose stack (`compose-e2e`, 2026-11-14); template folders built and tested, each member's own (`TSH-03`, migration 0047; `templates.spec.mjs` in mock mode), on the Compose stack once `main` runs it; locking not built (`TSH-04`) |
| FG-099 | Document group templates | SN | Build | 3 | Designed (a template already holds several documents, and several templates combine into one envelope, `FG-097`; SignNow's named document group with its own per-document roles and invites is `VS-03C`) |
| FG-100 | Bulk send (CSV, API, test row, progress) | DS, SN | Build | 11 | Partial: `POST /bulk-sends` (CSV or JSON rows, checked with per-row errors, `validate_only` as the test of the list), `…/send` in steps with progress, cancel, and the web app's `#/templates/{id}/bulk` (`UXW-04`); server tests seen red then green; the e2e spec green against the Compose stack (`compose-e2e`, 2026-11-14); no completion webhook (`UXW-47`) |
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
| FG-217 | Signer sign-in through an identity provider (OpenID Connect) | DS | Build | 5 | Works: `sso`, the operator's providers, PKCE, state and nonce, the verified email bound to the recipient, issuer and subject hash in the chain (`RAUTH-01`, ADR-033 Accepted 2026-11-17, `tests/ceremony_sso.rs`; browser run `e2e/recipient-auth.spec.mjs`, mock mode); and on the Compose stack with an OIDC provider stub (`RAUTH-02`, `compose-e2e` on `main` run 44018844840) |
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
| FG-130 | Inbox, Sent, Drafts, Deleted, folders | DS | Build | 6 | Partial: the Inbox (`UXW-01`), each member's own folders, the Deleted view of envelopes and of templates with template restore (`UXW-02`) served; restoring a deleted envelope awaits ADR-031 (owner question 2 in [77](77-SLICE-6-EVIDENCE.md)) |
| FG-131 | Quick views: action required, waiting, expiring, completed, auth failed | DS | Build | 6 | Partial: declined or expired, waiting, expiring soon (now also `?expires_before=` on the server), completed, with counts on Home and the rail (`UX-07`); waiting for me (`UXW-01`); Authentication failed (`?auth_failed=true`, the Agreements view; `tests/manage_views.rs`); built on a branch (`VS-06`, [77](77-SLICE-6-EVIDENCE.md)); `Works` once `manage-correct.spec.mjs` is green on `main` |
| FG-132 | Search and filters incl. custom fields | DS | Build | 6 | Partial: text search (`UX-04`), status set, sender, ranges, five sorts (`WEB-04`, `WEB-08`, `UXW-03`); custom fields (`?custom_field=&custom_value=`, the Agreements filter; `tests/manage_views.rs`); built on a branch (`VS-06`, [77](77-SLICE-6-EVIDENCE.md)); `Works` once `manage-correct.spec.mjs` is green on `main` |
| FG-133 | Correct | DS | Build | 6 | Partial: recipients, expiry and reminders in the Correct panel (`UX-07`); documents and fields in the editor's Correct mode (`UXW-19`, `tests/correct_documents.rs`); built on a branch (`VS-06`, [77](77-SLICE-6-EVIDENCE.md)); `Works` once `manage-correct.spec.mjs` is green on `main` |
| FG-134 | Void with reason | DS, SN | Build | 2 | Works |
| FG-135 | Resend | DS, SN | Build | 2 | Works |
| FG-136 | Copy; save as template | DS | Build | 6 | Works |
| FG-137 | Transfer ownership | DS | Build | 10 | Partial: `POST /envelopes/{id}/transfer` (`ORG-09`); the envelope page's Transfer panel (`ORG-41`, `manage-correct.spec.mjs`); the Users screen's transfer before removal is left |
| FG-138 | History view | DS, SN | Build | 6 | Works (staff audit view; the signer's own `GET /s/{token}/history`, `WEB-07`) |
| FG-139 | Envelope custom fields | DS | Build | 6 | Partial: `GET`/`PUT /envelopes/{id}/custom-fields`, the envelope page's card and panel, searched from Agreements; never in the evidence (`tests/manage_views.rs`); built on a branch (`VS-06`, [77](77-SLICE-6-EVIDENCE.md)); `Works` once `manage-correct.spec.mjs` is green on `main` |
| FG-140 | Reports and CSV export | DS | Build | 6 | Partial: the page's envelope report and CSV (`UX-08`); the server's envelope, recipient and usage reports as formula-safe CSV (`UXW-25`, `tests/reports.rs`, Full reports on the Reports page); built on a branch (`VS-06`, [77](77-SLICE-6-EVIDENCE.md)); `Works` once `manage-correct.spec.mjs` is green on `main` |
| FG-141 | Insights dashboard | DS | Build | 6 | Built on a branch (`VS-06E2`): `GET /insights` (counts, median and 90th-percentile time to complete, per day in the caller's day, top senders; the workspace's with `reports.read`, else one's own) and the Insights page from Reports (tiles, a chart with its table, outcomes, top senders, period and sender filters); `Works` once `vs06e-screens.spec.mjs` is green on `main` |

## Evidence and verification

| ID | Feature | From | Disp. | Slice | Status |
| --- | --- | --- | --- | --- | --- |
| FG-150 | Certificate of completion | DS, SN | Build | 1 | Works; every signer downloads it too, from the completion email's link (`VS-01`); a declined, voided or expired envelope gets a sealed envelope certificate saying how it ended, never claiming completion (`UXW-30`) |
| FG-151 | Audit trail (history) download | DS, SN | Build | 1 | Works |
| FG-152 | Tamper-evident seal on completed PDF | DS | Build | 1 | Works |
| FG-153 | RFC 3161 trusted time (B-T) | — | Build | 1 | Works |
| FG-154 | Long-term validation (B-LT, B-LTA) | — | Build | 7, 17 | Partial: B-LT works end to end through the API and worker: an account's default seal level (`settings.default_seal_profile`, Admin → Organization, `PATCH /accounts/me`) or an envelope's `seal_profile`; the worker seals at B-LT and accepts the DSS-only tail (`VS-07`); `casual-sign-worker/tests/end_to_end.rs` `an_account_defaulting_to_b_lt_gets_long_term_seals_verified_by_pyhanko` verifies the sealed PDF and certificate with ours and pyHanko from the DSS alone (seen red: default not applied; seal stuck `completing` on coverage); the Organization setting is in a browser run in mock mode (`manage.spec.mjs`). B-LTA through the worker is not tested end to end, there is no per-envelope control in the editor, and no Compose run seals at B-LT. Acrobat Reader reads the B-LTA interop packet files valid offline (`HRD-14`, `acrobat` run 44011154004 on the sprint branch; a run on `main` is pending). The account default and the coverage fix are on pull request #18, not yet on `main` |
| FG-155 | Audit trail embedded in the PDF | — (ours) | Build | 1 | Works |
| FG-156 | Hash-chained audit events | — (ours) | Build | Phase 1 | Works |
| FG-157 | Offline verification page and CLI | — (ours) | Build | 7 | Works |
| FG-158 | Public anchoring of chain heads | — (ours) | Build | 7 | Works: built in the worker, store and CLI (docs/32 §5 As built, migration 0041): a daily per-account Merkle tree of changed heads, an RFC 3161 token over its root and size, anchors and proofs stored insert-only, published to `OPENSEAL_ANCHOR_LOG`; `openseal anchor verify` proves a head offline (`casual-sign-worker/tests/anchoring.rs`, `casual-sign-sdk/tests/anchor.rs`, CLI `anchor_verify_proves_a_head_and_detects_a_tampered_one`). Served by `GET /api/v1/envelopes/{id}/anchor-proof` (`tests/anchor_proof.rs`) and checked in the browser by the Verify pages (`casual-sign-wasm` `verify_anchor`; `verify-anchor.spec.mjs`, `site.spec.mjs`): "History anchored on <day> by <TSA>" or why not. Not yet: the proof in the sealed PDF or a signer's downloads; a green CI run of the browser specs |
| FG-159 | Per-signer seals; certification signature | — | Build | 16 | Engine |
| FG-160 | PDF/A-3 output | — | Build | 17 | Designed |
| FG-161 | AES / QES via QTSP (CSC API) | DS (EU Advanced, Qualified) | Plugin | 18 | Designed |
| FG-162 | 21 CFR Part 11 mode | DS | Build | 19 | Designed |

## Account and admin

| ID | Feature | From | Disp. | Slice | Status |
| --- | --- | --- | --- | --- | --- |
| FG-170 | Users, CSV import, close, reactivate | DS | Build | 10 | Designed |
| FG-171 | Permission profiles (built-in and custom) | DS | Build | 10 | Partial: built-in admin, sender, viewer and custom profiles made, changed and deleted by an administrator, enforced on the server per request, never beyond the caller's own rights, in the web app (`UXW-07`); run on the Compose stack (`compose-e2e`, 2026-11-14); delegated workspace admins limited to groups, under one rule against escalation (`ORG-07`, API only) |
| FG-172 | Groups | DS | Build | 10 | Partial: groups made, renamed, deleted and their members set by an administrator, used to share templates, in the web app (`UXW-07`, `UXW-06`); run on the Compose stack (`compose-e2e`, 2026-11-14); a group's permission profile and envelope sharing not built (`PRF-03`) |
| FG-173 | SSO: SAML 2.0 and OIDC; require SSO; JIT provisioning | DS, SN | Build | 10 | Designed |
| FG-174 | Domain claims | DS | Build | 10 | Designed |
| FG-175 | SCIM provisioning | DS | Build | 10 | Designed |
| FG-176 | Brands (logo, colours, emails, landing pages) | DS, SN | Build | 12 | — |
| FG-177 | ERSD editing | DS | Build | 5 | Partial: `POST /ersd-versions` publishes and requires a version in one step (`ERSD-01`); the Admin card edits it against the mock; real-stack e2e left (`UXW-12`) |
| FG-178 | Retention and purge policies (built 2026-11-19, `ASVS-18`: rules per data class, legal holds, daily purge, dry run; blob bytes await `HRD-09`) | DS | Build | 15 | Works |
| FG-179 | Legal hold | — | Build | 15 | — |
| FG-180 | Data residency (region tags) | DS | Build | 15 | — |
| FG-181 | BYOK per-tenant keys | — | Build | 15 | — |
| FG-182 | Password and session policy; MFA (TOTP, WebAuthn) | DS | Build | 10 | Partial: staff TOTP with ten one-time recovery codes and the account policy `settings.mfa_policy` (`administrators`, the default since `ASVS-31`; `everyone`; `optional`), a session that owes a factor refused everywhere but the sign-in steps, enrolment and the code step on the sign-in card (`ASVS-01`, `-server/tests/mfa.rs`); breached and common passwords refused wherever a password is set (`ASVS-02`); an email notice when a password or factor changes (`ASVS-04`); session idle and absolute limits per workspace (`session_idle`, `session_max_age`, tightened by the organization), a list of one's sessions with sign-out of any or all, and re-authentication before sensitive actions (`ASVS-06`, `ASVS-07`, `-server/tests/sessions.rs`, `webapp/e2e/sessions.spec.mjs`); an advisory strength meter on every staff set-password screen (`ASVS-03`); staff password hashes keyed with an operator's pepper held outside the database (`ASVS-29`); staff passkeys (WebAuthn) as a second factor at sign-in and step-up, managed in the profile (`CON-13`, `-server/tests/passkeys.rs`, `webapp/e2e/passkeys.spec.mjs` with Chromium's virtual authenticator against the server); an administrator's audited reset of a member's lost factors, and the user's own replacement of the app and recovery codes (`ASVS-32`). Not yet: a browser run of the TOTP step with a QR code (`ASVS-33`), a settings screen for the session limits (`UXW-13`), passwordless passkey sign-in |
| FG-183 | Admin audit log | DS | Build | 10 | Partial: every settings, member, profile, workspace and organization change writes a hash-chained event in its transaction, and the workspace log lists and exports (JSON, CSV) through `GET /admin-events` (`ORG-05`); the organization's through `GET /organizations/me/audit` (`ORG-03`) and its screen, `#/org?section=audit` (`ORG-06`, newest first, filter, chain verify); the workspace's log has its Admin screen (list, filters over loaded events, details, CSV export, full chain check; `UXW-09`, mock-mode e2e); left: the check on the Compose stack (`UXW-09`), server-side filters (`UXW-44`), the organization log's export (ORG-35) |
| FG-184 | Organizations / multiple accounts | DS, SN | Build | 10 | Partial: one identity in several workspaces lists them and switches between them (`GET /auth/workspaces`, `POST /auth/switch`, the sidebar's workspace menu; `ORG-04`), organization routes (`ORG-03`); organization admin first cut `#/org`: Overview, Workspaces (create, join, archive), Users (session workspace), Administrators, Audit log (`ORG-06`, mock e2e; real stack left) |

## Developer surface

| ID | Feature | From | Disp. | Slice | Status |
| --- | --- | --- | --- | --- | --- |
| FG-190 | REST API with OpenAPI document | DS, SN | Build | 8 | Works |
| FG-191 | OAuth authorization code with PKCE | DS, SN | Build | 8 | Partial: built on the slice 8 branch (`VS-08A`): consent screen, codes with S256, rotating refresh tokens, consents withdrawn from the profile; `tests/oauth.rs`, `api-webhooks.spec.mjs` in mock mode. `Works` once `server-db` and `compose-e2e` are green on `main` with it |
| FG-192 | JWT bearer grant (service integrations) | DS | Build | 8 | Partial: built on the slice 8 branch (`VS-08B`): JWT integrations with a public key, the member's consent once, ES256 and RS256 assertions; `tests/oauth.rs`. `Works` once `server-db` is green on `main` with it |
| FG-193 | API keys | — | Build | Phase 2 | Works |
| FG-194 | Webhooks: account and per-envelope, HMAC, rotation | DS, SN | Build | 8 | Works |
| FG-195 | Webhook delivery log and redeliver | DS, SN | Build | 8 | Partial: Admin lists subscriptions and their latest deliveries (`UX-08`); the server edits, pauses and resumes a subscription, sends a test event and redelivers through the worker (`UXW-31` to `UXW-33`), and the Admin screen edits, pauses, resumes, tests and redelivers (`UXW-10`, mock-mode e2e `webapp/e2e/admin-screens.spec.mjs`). On the Compose stack: `api-webhooks.spec.mjs` (`VS-08C`) sends through a key to the CI receiver, which checks each signature, and delivers a failed one again; `Works` once `compose-e2e` is green on `main` with it |
| FG-196 | Embedded signing view | DS, SN | Build | 9 | Designed |
| FG-197 | Embedded sending / prepare view | DS, SN | Build | 9 | Designed |
| FG-198 | Embedded correct and template edit views | DS, SN | Build | 9 | Designed |
| FG-199 | SDKs (TS, Python, then Java, C#, Go, PHP, Ruby) | DS | Build | 8 | Partial: TypeScript and Python built (`VS-08E`, `sdk/`), generated from the contract, tested offline; not published: owner instruction 70, "Not now" (`VS-08J`). Java, C#, Go, PHP, Ruby: `VS-08H` |
| FG-200 | Sandbox / demo environment | DS, SN | Build | 8 | Partial: built on the slice 8 branch (`VS-08D`, ADR-041): sandbox workspaces sealed with a separate sandbox key, marked everywhere, not metered, `osk_test_` keys; server, worker, keyd, verify and web tests, `api-webhooks.spec.mjs` in mock mode. `Works` once `compose-e2e` is green on `main` with it |
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
