# 01 — Product requirements

**Status: Draft for owner.** What OpenSeal is, for whom, and what "done" means. The sisters call this document the ORD;
it plays the same role. Feature-by-feature disposition is [96](96-FEATURE-FIT-GAP.md); delivery order is
[06](06-ROADMAP-AND-DELIVERY.md).

## 1. Outcome

A DocuSign or SignNow user sends an agreement from OpenSeal, and their signers complete it, **without being taught
anything**. The result is a sealed PDF that every party receives, that any PDF reader shows as unmodified, and that
anyone can verify offline, with a certificate of completion and an audit trail that hold up as evidence.

An integrator replaces DocuSign or SignNow in their product with OpenSeal **through an API they recognize**, self-hosted
under Apache-2.0, with every feature those vendors put behind their top tiers.

## 2. Why

- **Licence.** Every serious open-source e-signature project is AGPL ([52](52-COMPETITOR-STUDY.md)). Companies that
  embed signing into proprietary products cannot use them. An Apache-2.0 engine and server can be embedded anywhere.
- **Cost and gating.** DocuSign gates bulk send, PowerForms, conditional logic, payments, SSO and retention behind
  Business Pro and Enhanced; SignNow gates conditional fields and bulk send ([48](48-DOCUSIGN-STUDY.md) §11,
  [49](49-SIGNNOW-STUDY.md) §9). Self-hosted, these are free.
- **Sovereignty.** Regulated and public-sector operators need agreements and keys in their own jurisdiction and HSM.
- **Evidence quality.** Open projects ship weak evidence (self-signed seals, no LTV, no verifier). An engine built
  evidence-first, with independent validation in CI, is a real differentiator.
- **The CasualOffice suite.** With OpenDoc, OpenCalc and OpenPresent, an organization can author, review and sign
  without leaving its own infrastructure.

## 3. The reference products

**DocuSign eSignature sets the feature bar, the workflow vocabulary and the API's concepts; SignNow's editor sets the
speed of preparing a document** (`DEC-06`). Concretely: envelopes, routing orders, recipient types, tabs and their
properties, Connect-style webhooks and embedded views follow DocuSign; the document-first editor with roles assigned in
place, text tags, signing links with QR codes, kiosk mode and payment fields follow SignNow. Where the two disagree,
the [studies](48-DOCUSIGN-STUDY.md) record which wins and why.

Only what the vendors own is replaced: names, logos, colours, illustrations, wording.

## 4. Users

| Persona | Needs | First served |
| --- | --- | --- |
| **Sender** (sales, HR, legal ops, procurement) | Upload, add people, place fields, send in under two minutes; track; remind; correct; void | Slice 1 |
| **Signer** (anyone, often on a phone, never trained) | Open a link, understand what to do, sign in under a minute, get a copy | Slice 1 |
| **Template author / ops** | Reusable templates with roles and logic; bulk send; signing links | Slices 3, 4, 11 |
| **Account admin** | Users, groups, permissions, SSO, branding, retention, audit | Slices 10, 12, 15 |
| **Integrator** (developer) | REST API, webhooks, embedded signing and sending, SDKs, sandbox | Slices 8, 9 |
| **Operator** (IT running the deployment) | Docker or Kubernetes install, HSM or KMS keys, backups, monitoring, upgrades | Phase 2, slice 20 |
| **Verifier** (court, auditor, counterparty) | Check a completed PDF without an account or our server | Slice 7 |
| **Compliance officer** | ESIGN/UETA consent, eIDAS AES/QES, Part 11, retention, evidence export | Slices 5, 18, 19 |

## 5. Scope

### In scope (the product)

1. **Documents**: PDF; Word, Excel, PowerPoint, images converted; multi-document envelopes; admission that neutralizes
   active content; existing PDF form fields converted to fields.
2. **Recipients**: signer, in-person signer, approver, viewer (needs to view), carbon copy, editor, intermediary,
   agent, witness; routing order (sequential, parallel, mixed); conditional routing; signing groups; reassignment;
   delegation.
3. **Fields**: signature, initials, stamp, date signed, name, first and last name, email, company, title, text, number,
   date, email, phone, SSN, ZIP, checkbox, radio group, dropdown, formula, attachment, note, approve, decline, hyperlink,
   payment, drawing; required, read-only, locked, shared, data labels, linked values, validation, conditional
   visibility, group rules, prefill; anchors (auto-place) and text tags.
4. **Sending**: recipients-first (DocuSign) and document-first (SignNow) preparation; templates (roles, composite,
   sharing, folders); bulk send (CSV and API); signing links (PowerForms) with QR; scheduled sending; reminders;
   expiration; custom email subject and message; per-recipient private messages; document visibility.
5. **Signing**: email, SMS and embedded delivery; ERSD consent; authentication (access code, email OTP, SMS OTP, phone
   call, OIDC IdP, ID verification and KBA through plugins); guided Start/Next; adopt signature by draw, type or
   upload; finish later; decline with reason; assign to someone else; in-person hosting; kiosk; mobile-first and
   accessible (WCAG 2.2 AA); 20+ languages.
6. **Managing**: inbox, sent, drafts, deleted, folders, quick views (action required, waiting for others, expiring
   soon, completed, authentication failed); search and filters; correct, void, resend, copy, save as template, transfer
   ownership; history; reports and CSV export.
7. **Evidence**: flattened documents; certificate of completion; hash-chained audit trail embedded in the PDF; PAdES
   B-T by default, B-LT and B-LTA options; offline verification (web and CLI); optional public anchoring.
8. **Platform**: multi-tenant accounts; users, groups, permission profiles; SSO (OIDC, SAML), SCIM; branding (multiple
   brands, email templates, landing pages); retention and purge; legal hold; data-region tags; BYOK.
9. **Developer surface**: REST API, OpenAPI, OAuth 2.1, JWT grant, API keys, webhooks with signed payloads and delivery
   logs, embedded signing/prepare/correct views, custom elements, generated SDKs, sandbox mode, MCP access for agents.
10. **Deployment**: single-node Docker Compose; Kubernetes Helm chart; HSM and cloud KMS key custody; desktop app for
    senders and offline verification.

### Add-on modules and integrations (owner instruction 9)

- **Remote online notarization** (slice 31): the notary workflow is OpenSeal's; commissioned notaries and per-state
  compliance come through licensed provider integrations.
- **Contract lifecycle management, transaction rooms, a workflow builder and agreement intelligence** (slices 32–35):
  OpenSeal add-on modules built on the public API and event stream, so the signing core stays focused.
- **OpenSeal does not become a trust service provider**: qualified signatures come through QTSPs (slice 18).
- **Hosting a SaaS** is the owner's business decision; the project ships software that can be hosted.

## 6. Functional requirements (summary)

Numbered so tests and tracker rows can cite them. Each maps to features in [96](96-FEATURE-FIT-GAP.md).

| ID | Requirement |
| --- | --- |
| FR-01 | A sender can create an envelope with one or more documents, recipients with routing orders, and fields, and send it, through the UI and through one API call |
| FR-02 | Uploaded files are admitted within the limits of [21](21-PARSER-LIMITS.md); active content is removed and reported to the sender before sending |
| FR-03 | Recipients receive an invitation when routing reaches them, by email, SMS or the host (embedded) |
| FR-04 | A recipient must pass every authentication requirement and accept the current ERSD before seeing documents |
| FR-05 | The signer is guided through required fields; validation, conditional visibility, group rules and formulas behave identically in browser and server |
| FR-06 | A signer adopts a signature by drawing, typing or uploading; the adoption method and image hash are evidence |
| FR-07 | A signer reviews the engine's flattened rendering of what will be sealed before finishing (WYSIWYS) |
| FR-08 | Decline, finish later, reassign (when allowed) and in-person hosting work as in [24](24-ENVELOPE-LIFECYCLE-AND-ROUTING.md) |
| FR-09 | When every required action is complete, documents are flattened, a certificate of completion generated, the audit trail embedded, the result sealed at the account's PAdES level and verified before release |
| FR-10 | Every party receives the completed documents (configurable), and the sender can download documents, certificate and audit trail at any time within retention |
| FR-11 | Anyone can verify a completed document offline and see each signature's verdict and the audit timeline |
| FR-12 | A sender can correct, void, resend and remind; changes to signed documents require re-signing |
| FR-13 | Templates with roles, shared by user, group or account, instantiate envelopes in the UI, by API, by bulk send and by signing link |
| FR-14 | Admins manage users, groups, permission profiles, SSO, branding, ERSD, retention, allowed authentication methods and seal profile |
| FR-15 | Webhooks deliver signed events at least once with retries and a visible delivery log |
| FR-16 | Embedded views let a host run signing, preparing and correcting inside its own product |
| FR-17 | Every legally relevant action is an append-only, hash-chained audit event committed before the action is acknowledged |
| FR-18 | Retention policies purge documents and personal data and keep a tombstone with the chain head and sealed hash |
| FR-19 | Part 11 mode requires account users, re-authentication at signing and a signing reason printed with each signature |
| FR-20 | AES/QES through a QTSP's CSC API, per recipient, when the account enables it |

## 7. Non-functional requirements

Targets, to be confirmed by measurement (none is measured yet). Details and the enterprise bar in
[10](10-ENTERPRISE-REQUIREMENTS.md).

| Area | Target |
| --- | --- |
| Integrity | 100% of sealed outputs pass rungs 1–3 of the verification ladder ([31](31-SEALING-AND-SIGNATURES.md) §7) in CI; zero audit events lost across crash tests |
| Security | Every parser bounded, fuzzed, with hostile fixtures; OWASP ASVS 4.0 Level 2 for the server, Level 3 for the ceremony and key paths |
| Availability | Stateless tiers; 99.9% design target for a two-node cluster; a signer can finish while email is down |
| Performance | Signer page first render < 2 s on a mid-range phone over 4G for a 10-page PDF; finish → completed (B-T) p95 < 10 s excluding TSA latency; API p95 < 200 ms for reads; 50 envelopes/s sustained send on a reference cluster |
| Scale | 10⁸ envelopes per database with partitioned audit tables; 100 recipients and 3,000 fields per envelope; 200 MB per envelope |
| Accessibility | WCAG 2.2 AA for signer and sender UIs; keyboard-only signing; screen-reader announced fields; typed signature as an accessible alternative to drawing |
| Internationalization | UI and emails in 20+ languages, right-to-left scripts, locale date and number formats; signer language per recipient |
| Privacy | No personal data or document content in logs; data minimization; export and purge |
| Determinism | Same inputs, keys and supplied time → same sealed bytes (apart from randomized signature algorithms, recorded) |
| Portability | Linux x86-64 and arm64 containers; PostgreSQL 15+; any S3-compatible store; engine on `wasm32-unknown-unknown` |

## 8. Success measures

- **Signer completion rate** ≥ DocuSign's published-typical rates on the same flows, measured in usability tests
  (`UXR-01`).
- **Time to send** a three-signer document: under 2 minutes for a first-time sender.
- **Validators passed**: Adobe Reader (with operator AATL certificate), EU DSS, pyHanko — all green.
- **Feature parity**: share of [96](96-FEATURE-FIT-GAP.md) "Build" rows working, reported at each slice close.
- **Adoption**: integrators running OpenSeal in production (tracked once released).

## 9. Risks

| Risk | Mitigation |
| --- | --- |
| Overclaiming legal validity or compliance | Rule 25 in [04](04-MISTAKES-AND-RULES.md); counsel review `LEG-02` before release |
| A cryptographic mistake that invalidates every agreement | Independent validators in CI; no hand-rolled crypto; external security review before 1.0 (`SEC-REV-01`) |
| Name collision with OpenSign Labs' AGPL product | Resolved: named OpenSeal (`DEC-01`); trademark search still due (`DEC-07`) |
| AGPL contamination through a contributor | Clean-room rule, DCO, attestation, `deny.toml` |
| Email deliverability (invitations in spam) | SPF, DKIM, DMARC guidance; provider plugins; SMS fallback; operator docs |
| Trust: self-hosted seals show "validity unknown" in Acrobat | Documented AATL path ([09](09-LEGAL-AND-COMPLIANCE.md) §7), HSM and KMS support |
| Scope: DocuSign's surface is enormous | Fit-gap with explicit dispositions; slices ordered by user value |
