# Changelog

All notable changes, by date. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [0.1.0] — 2026-11-19 (pre-release)

The second pre-release. Since v0.0.1, feature work paused for a hardening release (owner instruction 48) and for
milestone M3, "first signature": a sender prepares and sends from the web app, signers on phones authenticate, consent
and sign, everyone gets the sealed PDF and certificate, and anyone verifies it offline (slices 1, 2, 5 and 7).
**Still not for production agreements:** the bundled stack makes its own certificate authority, a software HSM and a
development timestamp authority; the production profile needs your own CA, HSM and timestamp authority (docs/65). This
release states nothing about legal validity, compliance or certification; see docs/09.

This is the first release built by the signed release workflow: every image is signed with keyless cosign and has
SPDX SBOMs and build provenance, and the release carries a CycloneDX SBOM of the Rust workspace, `SHA256SUMS` signed
with cosign, and a Compose override pinning the production profile to the image digests (`REL-01`; v0.0.1 had none
of these, `REL-04`). How to check them: docs/65 §Releases.

### Evidence and signing
- Seals at B-LTA read as valid offline in Adobe Acrobat Reader: the DSS carries a CRL beside each OCSP answer
  (`HRD-14`), checked on a GitHub Windows runner that opens every file of the interoperability packet in Acrobat
  Reader and records the signature panel (`HRD-03`).
- Sealing checked against a real-style CA hierarchy (offline root, issuing CA, served OCSP and CRL) and a production
  RFC 3161 timestamp authority, with our verifier, pyHanko and EU DSS agreeing (`HRD-02`).
- An account can make B-LT its default seal level (Admin → Organization), verified end to end with pyHanko (`VS-07`,
  `FG-154`).
- Public anchoring of audit chain heads (ADR-037, `FG-158`): a daily per-account RFC 6962 Merkle tree of changed
  heads with an RFC 3161 token over its root and size, appended to a public log; `openseal anchor verify` proves a head
  offline, `GET /envelopes/{id}/anchor-proof` serves the proof, and the Verify page checks it in the browser
  (`VS-07B`).
- keyd signs only with a short-lived token the database issues for an envelope that still owes a seal (ADR-036,
  `KEYD-02`), and keyd's operation log is reconciled against the seals recorded (`KEYD-03`, `CON-09`); keyd refuses
  an expired signing certificate (`CON-08`).
- Recipient authentication (ADR-033): access code, email, SMS and voice one-time codes through an HTTPS gateway, and
  sign-in through an OpenID Connect provider the operator lists (`VS-05`, `RAUTH-01`); signers can withdraw consent to
  electronic records from the signing page (`RAUTH-03`).
- Routing and recipient types on the real stack: sequential, parallel and mixed order; carbon copies, viewers,
  approvers and agents acting through their emailed links; decline, void, reminders and expiry (`VS-02`).
- Every party, the signer included, downloads the sealed PDF and the certificate of completion (`VS-01`).
- The envelope page's evidence card and the Verify page read the server's `sha256:` audit hashes; both had shown
  "links do not match" on real envelopes although the evidence itself was right (`S1-10`, `VS-07C`).

### Hardening and operations
- A production Compose profile (`deploy/compose.production.yml`): non-root, read-only file systems, resource limits,
  TLS to PostgreSQL and the object store, secrets from files, checked by `tools/check-deploy.py` (`HRD-06`).
- Failure recovery proven by chaos runs in CI on that profile: the worker paused past its lease or killed mid-seal,
  keyd stopped, PostgreSQL and the object store killed mid-ceremony and mid-seal; every envelope completes once,
  sealed once, with its audit chain intact (`HRD-01`, `HRD-10`).
- Load numbers published from a run on `main` (docs/65 §Load and recovery numbers): about 195 completed envelopes a
  minute on one runner, seal time p95 2.8 s, and recovery times after the worker, keyd and PostgreSQL fail under load
  (`HRD-04`).
- Encrypted, signed backups with a restore drill in CI that verifies the audit chains, admin logs and keyd's operation
  log after restore (`ASVS-14`).
- Two server replicas behind HAProxy in the production profile, each with a readiness check, so a restart or a
  credential rotation drops no request (ADR-038, `HRD-11`); rotation drills for database credentials, the token key,
  keyd's identity and webhook secrets; staff second-factor keys rotate with a previous key (`HRD-12`).
- keyd and the worker log the hash of their security configuration and refuse to start on an unexpected change
  (`ASVS-24`).

### Security (OWASP ASVS)
- Measured against an ASVS 4.0.3 self-assessment ([docs/67](https://github.com/CasualOffice/openseal/blob/main/docs/67-ASVS-SELF-ASSESSMENT.md); a self-assessment, not a
  certification).
- A security event log: one JSON line per event with a closed set of event kinds and pseudonymised principals, shipped
  by the container runtime, with an optional forwarding profile (ADR-034, `ASVS-08`); abnormal-activity alerts on
  request, refusal and authentication-failure bursts, mass downloads and voids (`ASVS-13`).
- Uploads scanned for malware by ClamAV before they are admitted, the verdict recorded in the audit chain (`ASVS-11`).
- Staff second factor (TOTP with recovery codes) required of administrators by default (`ASVS-01`, `ASVS-31`);
  breached and common passwords refused (`ASVS-02`); mail to the user when a password or factor changes
  (`ASVS-04`); a password strength meter on every staff set-password field, advisory only (`ASVS-03`); an optional
  password pepper held outside the database (`ASVS-29`).
- Staff sessions end after 30 minutes idle and 8 hours in all by default, settable per workspace and tightened by the
  organization; a person lists and ends their own sessions; creating API clients, role and policy changes, webhook
  destinations and security settings need the password (and second factor) again within five minutes (`ASVS-06`,
  `ASVS-07`).
- `__Host-` session cookie (`ASVS-05`), JSON-only API bodies against login CSRF (`ASVS-09`), constant-time hash
  comparison from a vetted library (`ASVS-12`), a last-resort panic layer answering problem details (`ASVS-26`).
- Signer content and every ceremony write require the recipient's authentication first (`SEC-CER-01`); shared accounts
  cannot be changed across workspaces (`SEC-ID-01`).
- Dependency audit exceptions removed: the eight `zip` advisories and `ttf-parser`, by vendoring and trimming the OCR
  crates (`DEP-06`, `DEP-07`).

### Web app and site
- A redesigned web app from an audit against DocuSign and SignNow (`UX-01`, all seven packages `UX-02` to `UX-08`):
  - a design system, with destructive actions in a colour distinct from the seal red, and the Inter font bundled;
  - a send editor with click-to-place fields, every field kind the signing page fills with its properties, recipient
    types and per-row options, contacts, a review step, starting from a template, a pages rail and a phone layout;
  - a reworked signing page that names the sender and the expiry and serves the electronic-records disclosure
    (`UXW-34`);
  - Home, Agreements and the envelope page with clearer hierarchy, density and access to the evidence;
  - Templates, Reports (sample sizes, custom ranges) and an Admin section rail with webhooks;
  - an app shell that works on phones, with search on every screen, notifications, profile, account and help menus.
- Organizations above workspaces with organization owners and an organization scope enforced in the database,
  switching between workspaces, hash-chained admin audit logs with JSON and CSV export, and a first cut of the
  organization admin screens (`ORG-02` to `ORG-06`).
- Inbox, each member's own folders, a Deleted view, server-side filters and sorts (`UXW-01` to `UXW-03`); bulk send
  from a template with a CSV list (`UXW-04`); template sharing (`UXW-06`); groups and custom permission profiles
  enforced on the server (`UXW-07`); admin audit log and webhooks screens (`UXW-09`, `UXW-10`, `UXW-31` to `UXW-33`);
  hosting an in-person signer (`UXW-36`).
- Accessibility (axe, WCAG 2.2 AA rules) and string extraction checked on every screen of slices 1, 2, 5 and 7
  (`I18N-01`); recorded demos of each slice in CI (docs/65 §Demos).
- The send editor no longer loses edits made while a save is on its way (`E2E-13`); a recipient's changed type is
  kept on save (`UX-12`).
- The website is redesigned in the web app's design language, with Verify as a primary destination that runs the
  WASM verifier in the browser (your file is not uploaded), an interactive demo in mock mode, and every security claim
  marked as tested or deployment-dependent (`SITE-01`, `SITE-03`, `SITE-04`, `SITE-05`). The roadmap page is built
  from the roadmap and tracker, statuses included.

### API
- `GET /envelopes/{id}/anchor-proof`; `POST /s/{token}/sso` and `/sso/verify` for recipient sign-in; SMS and voice
  code delivery; `POST /bulk-sends`; organization routes; `POST /auth/reauthenticate` and the session list
  (docs/40, `api/openapi.yaml`).
- Problem details carry stable codes for each new refusal (docs/20).

### Built, paused until after M3 (owner instruction 51)
Merged before the freeze, off by default, and not developed further until M3 closes; nothing is removed:
- `casual-sign-modeld`, the separate process that hosts pretrained models (ADR-029): OCR of scanned pages, template
  matching, GLiNER span extraction and personal-data detection; `casual-sign-pii` recognisers. Nothing a model says
  enters the sealed PDF or the audit trail (`ML-*`, `WEB-19`).
- The platform console for operators, with mandatory TOTP, two-person changes, the Keys page and timestamp authorities
  (`CON-*`); plans, metering and quota enforcement (`PLAN-*`). Not yet a Compose service.

### Not yet
SSO and SAML for staff, WebAuthn, payments, B-LTA renewal jobs, Helm and multi-node high availability, the anchor
proof in a signer's own downloads (`VS-07D`), a per-envelope seal level in the editor (`VS-07E`), linux/arm64 images
(`REL-02`), an external penetration test (`HRD-05`), and the slices after M3 on the
[roadmap](https://casualoffice.github.io/openseal/roadmap.html).

### Reporting security issues
Report vulnerabilities as described in `SECURITY.md`. This is pre-release software; do not use it for agreements you
need to rely on.

## [0.0.1] - 2026-11-12 (pre-release)

The first pre-release of OpenSeal: the common send-and-sign case works end to end on one machine. **Not for production
agreements yet:** the bundled stack uses a generated certificate authority, a software HSM and a development timestamp
authority, so seals validate only against that CA.

### What works
- Upload a PDF, add signers in order or in parallel and carbon copies, place signature, initials, date, name, email,
  text and checkbox fields (with field detection), and send. Signers can also fill company, title, number, radio,
  dropdown, attachment and note fields that come from a template or a converted PDF form; the editor cannot yet place
  those (corrected 2026-11-12, `DOC-007`).
- Signing on desktop and phone: access code, consent, guided Start/Next, draw, type or upload a signature, review,
  finish, decline, finish later, reassign when allowed; optional signer location (device or IP approximation).
- Every completed envelope is sealed as PAdES (B-T by default) and verified before it completes; a certificate of
  completion with the hash-chained audit trail embedded. Outputs are checked by pyHanko and EU DSS in CI.
- Agreements, envelope detail with audit trail, Correct, resend, void, downloads in progress and when complete,
  templates, admin (users, invitations, API clients), reports, and Verify in the browser.
- REST API (`/api/v1`, OpenAPI document) with API keys and OAuth client credentials; signed webhooks.
- Engine: bounded PDF reader (417 of 422 real-world PDFs admitted, the rest refused with codes), incremental writer,
  print-to-new for certified PDFs, dynamic XFA forms laid out to static pages, 24 h of fuzzing per target.
- One-command deployment with Docker Compose; images on GitHub Container Registry.

### Not yet
SSO (OIDC, SAML), WebAuthn, SMS authentication, bulk send, payments, B-LTA renewal jobs, production deployment (Helm,
high availability, backups), and the slices after Release 1 on the [roadmap](https://casualoffice.github.io/openseal/roadmap.html).

### Security
Report vulnerabilities as described in `SECURITY.md`. This is pre-release software; do not use it for agreements you
need to rely on.

## 2026-11-10

### Phase 1 opened
- Stage 1G merged: PAdES B-B to B-LTA sealing, self-verified, agreeing with pyHanko and EU DSS (`T-1G`). Stage 1I merged: hash-chained audit trail, RFC 8785, Merkle anchoring, certificate of completion with the trail embedded (`T-1I`).
- Reader completion merged: password-protected PDFs (standard handler R2–R6), LZW, four wrongly refused real PDFs fixed, a public content lexer; 417 of 422 corpus PDFs open (`PDF-ENC-01`, `PDF-LZW-01`, `PDF-REAL-01..03`).
- Stage 1E merged: flattening with subset fonts, drawn, uploaded and typed signatures, and fill-in-place forms (`T-1E`, `FILL-01`), checked by PDFium and pypdf.
- Stage 1H merged: the verifier, with a whitelist revision classifier that catches shadow and incremental-saving attacks, cross-checked against pyHanko and EU DSS (`T-1H`).
- Repository public; first GitHub CI run green on all 8 jobs. Independent doc audit (`DOC-002`): 26 findings fixed.
- Stage 1B merged: incremental writer and normalizer; `PDF-INV-01` holds over the hostile set and the corpus; eight more active-content fixtures (`T-1B`).
- Owner instruction 9: remote online notarization (slice 31) and add-on modules for lifecycle management, rooms, workflow builder and agreement intelligence (slices 32–35, milestone M8).
- Owner instruction 8, not an MVP: no feature is deferred as `Later`; dynamic XFA, fill-in-place forms, mobile apps, template matching, sign on paper, WhatsApp delivery, insights and integrations are planned with slices and rows.
- Stage 1C merged: page geometry, text extraction with positions, anchor text, `{{…}}` text tags and AcroForm conversion (`T-1C`).
- First corpus run of the reader: 422 real PDFs, no panic or hang, 387 admitted with page counts matching the manifest; four wrong refusals tracked as `PDF-REAL-01` to `03`.
- Stage 1A merged: the bounded PDF reader and admission report, with a cargo-fuzz `admit` target (`T-1A`, `F-007`). Fixed after merge: three fixture defects and an object-stream cache that could hold two oversized streams at once.
- Stage 1F merged: `KeyProvider`, CMS builder and verifier, RFC 3161, OCSP and CRL, cross-checked with `cryptography` and pyHanko both ways (`T-1F`).
- Stage 1D merged: field types, validation (linear-time regex), conditional fields, groups, linked fields and a decimal formula language, identical natively and in WASM (`T-1D`).
- Owner instruction 7: private until the pre-release alpha; `tools/ci-local.sh` runs the CI list locally. Phase 1 opened under waiver `W-2`; skeleton crates `casual-sign-model`, `-crypto`, `-fields` for stages 1A, 1D and 1F.

### Phase 0 opened
- EU DSS 6.5.1 validator image (`tools/eu-dss/`) added to the validator self-test and CI, rung 3 of the ladder (`F-006`).
- Hostile PDF fixtures: generator and manifest covering every PDF limit in docs/21 (`F-005`).
- Real-world PDF corpus: a manifest of 422 freely licensed PDFs (URL, SHA-256, licence, producer, features), a fetch
  script that checks them and a byte scanner that describes them ([fixtures/corpus](fixtures/corpus/README.md), `F-004`).
- `SPK-01`: PDF reader spike merged; ADR-005 confirmed (own bounded reader and writer; lopdf as test oracle) ([docs/64](docs/64-SPK-01-PDF-READER.md)); docs/21 and docs/30 corrected from its findings.
- `SPK-02`: crypto stack spike merged; ADR-006 confirmed with amendments; ADR-009 now signs DER signed attributes ([docs/66](docs/66-SPK-02-CRYPTO-STACK.md)).
- ADR-001 to ADR-009 Accepted; Phase 0 opened (owner instruction 6).
- Cargo workspace, `casual-sign-pdf` skeleton, toolchain pin, `deny.toml`, lints; repository gates, commit hooks and CI workflow copied from OpenPresent (`F-002`, `PROVENANCE.md`).
- `tools/verify-sealed.py`: pyHanko validator harness with a self-test (`F-006`).
- `GOVERNANCE.md`, `CODE_OF_CONDUCT.md`.

### Changed
- Roadmap gains milestones M0–M7 with exit evidence, critical path and parallel lanes (`docs/06`, `MS-*`).
- Git workflow decided (`DEC-11`); repository initialized on `main`.
- Product named **OpenSeal** (owner instruction 4, `DEC-01`); skills renamed `openseal-*`.

### Added
- Initial design documentation: PRD, HLD, DocuSign, SignNow and open-source studies, legal and compliance mapping,
  data model, envelope lifecycle, PDF pipeline, sealing, audit trail, API design, threat model, ADR register,
  roadmap, execution tracker, feature fit-gap (`DOC-001`).
- `CLAUDE.md`, `AGENTS.md`, project skills, `LICENSE` (Apache-2.0), `NOTICE`, `SECURITY.md`, `CONTRIBUTING.md`.
