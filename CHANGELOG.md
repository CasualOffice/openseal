# Changelog

All notable changes, by date. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## 2026-11-10

### Phase 0 opened
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
