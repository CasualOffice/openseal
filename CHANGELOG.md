# Changelog

All notable changes, by date. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- `casual-sign-modeld`, the separate process that will host pretrained models (ADR-029): mutual TLS, a bounded wire
  protocol, an operation log and a hash-checked model bundle; the server and worker do not call it yet (`ML-09`).
- `casual-sign-pii`: personal-data recognisers that find structured identifiers by pattern plus validation (Luhn,
  IBAN mod-97 and other check digits), with a fuzz target (`ML-08`).
- Normalisation of extracted dates, durations and amounts in `casual-sign-fields`, with a fuzz target (`ML-07`).
- Model manifest and hash-checking fetch script, an offline GLiNER export tool, and synthetic scanned-form fixtures
  (`ML-01`, `ML-02`, `ML-05`).

### Designed
- Organizations above workspaces, delegated administration, a platform console and plans: ADR-028 accepted
  ([docs/23](docs/23-ORGANIZATIONS-WORKSPACES-AND-CONSOLE.md)).
- Pretrained ML models, off by default and never part of the evidence: ADR-029 accepted
  ([docs/33](docs/33-ML-MODELS.md)).
- A UI and workflow pass from an audit against DocuSign and SignNow (`UX-01` to `UX-08`, `UXW-01` to `UXW-29`).

## [0.0.1] - 2026-11-12 (pre-release)

The first pre-release of OpenSeal: the common send-and-sign case works end to end on one machine. **Not for production
agreements yet:** the bundled stack uses a generated certificate authority, a software HSM and a development timestamp
authority, so seals validate only against that CA.

### What works
- Upload a PDF, add signers in order or in parallel and carbon copies, place signature, initials, date, name, email,
  text, checkbox, company, title, number, radio, dropdown, attachment and note fields (with field detection), and send.
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
