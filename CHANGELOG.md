# Changelog

All notable changes, by date. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## 2026-11-10

### Phase 1 opened
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
