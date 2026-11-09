# 08 — ADR register

ADR ids here are this repository's own; the sisters' are always cited as "OpenCalc's ADR-n" or "OpenPresent's ADR-n".
ADR-001 to ADR-009 are Accepted on the owner's "proceed" of 2026-11-10 (instruction 6); ADR-005 and ADR-006 still have their spikes (`SPK-01`, `SPK-02`) confirm the library choice, and change only by a superseding ADR. **Proposed unless marked.** Status moves to Accepted when the owner agrees, or when the spike named in the row confirms
it.

**Write an ADR when a decision touches:** public API; a crate boundary or the DAG; a persisted or wire format; the
envelope state machine; the audit event schema; cryptographic algorithms, libraries or key custody; what enters the
WASM bundle; a new dependency in the engine; a legal or evidence property.

| ADR | Decision | Status | Reasoning in |
| --- | --- | --- | --- |
| ADR-001 | Crates `casual-sign-*`; product OpenSeal (`DEC-01`) | Accepted | [52](52-COMPETITOR-STUDY.md) §Name collision |
| ADR-002 | Follow the sisters' layered engine and host split; the server is a first-class host | Accepted | [02](02-HLD.md) §2 |
| ADR-003 | Separate repo; copy from OpenCalc and OpenPresent with provenance | Accepted | [19](19-WORKSPACE-SCAFFOLD-DESIGN.md) |
| ADR-004 | Engine purity: time, randomness, keys, fonts, trust lists and network answers are supplied values | Accepted | [02](02-HLD.md) §6 |
| ADR-005 | Our own bounded PDF reader and incremental writer, rather than `lopdf` or `pdf-rs` (MIT) as the product parser; `lopdf` allowed as a test oracle. Decided by `SPK-01` | Accepted; spike confirms | [30](30-PDF-PIPELINE.md) §2 |
| ADR-006 | Crypto: `aws-lc-rs` for private-key operations and hashing in hosts (FIPS option); RustCrypto `der`, `x509-cert`, `cms`, `x509-tsp`, `x509-ocsp` for structures and for WASM verification; no `rsa` private-key ops; no MPL `cryptographic-message-syntax`. Decided by `SPK-02` | Accepted; spike confirms | [31](31-SEALING-AND-SIGNATURES.md) §8 |
| ADR-007 | Browsers render PDFs with vendored pdf.js (Apache-2.0) in a worker, scripting off; the engine never rasterizes | Accepted | [30](30-PDF-PIPELINE.md) §10 |
| ADR-008 | Default seal: one platform PAdES B-T signature at completion over flattened documents, certificate and embedded audit JSON | Accepted | [31](31-SEALING-AND-SIGNATURES.md) §3 |
| ADR-009 | Key custody in a separate `keyd` process that signs digests only | Accepted | [31](31-SEALING-AND-SIGNATURES.md) §5 |
| ADR-010 | Audit events: JCS canonical JSON, SHA-256 hash chain per envelope, committed with the state change | Proposed | [32](32-AUDIT-TRAIL-AND-EVIDENCE.md) |
| ADR-011 | Workflow as a pure command function returning state, events and effects; effects run as idempotent jobs | Proposed | [24](24-ENVELOPE-LIFECYCLE-AND-ROUTING.md) §1 |
| ADR-012 | PostgreSQL as the only required stateful service besides the object store; job queue in Postgres; Redis optional | Proposed | [02](02-HLD.md) §9 |
| ADR-013 | Tenancy: `account_id` on every row, scoped repository, RLS as second line | Proposed | [22](22-DATA-MODEL.md) §9 |
| ADR-014 | Server stack: `axum`, `tokio`, `sqlx` (compile-time checked queries), `tower`; copied conventions from OpenCalc's servers | Proposed | [19](19-WORKSPACE-SCAFFOLD-DESIGN.md) |
| ADR-015 | Public API: envelope-centric REST `/api/v1`, OpenAPI 3.1, RFC 9457 errors, idempotency keys, cursor pagination | Proposed | [40](40-API-DESIGN.md) |
| ADR-016 | Webhooks signed per Standard Webhooks; at-least-once; no documents in payloads | Proposed | [40](40-API-DESIGN.md) §4 |
| ADR-017 | Embedding through iframe views and custom elements wrapping them, not shadow-root mounting | Proposed | [40](40-API-DESIGN.md) §5 |
| ADR-018 | Web app: vanilla ES modules, no framework or bundler, command registry, copied from the sisters | Proposed | [47](47-UX-AND-FEATURE-MAP.md) |
| ADR-019 | Field geometry stored in displayed page space (points, top-left); one conversion function shared by WASM and native | Proposed | [30](30-PDF-PIPELINE.md) §4 |
| ADR-020 | WYSIWYS: signers review engine-flattened output before finishing | Proposed | [02](02-HLD.md) §6 |
| ADR-021 | Document conversion through a sandboxed `Converter` sidecar; sister engines first, LibreOffice container fallback | Proposed | [30](30-PDF-PIPELINE.md) §3 |
| ADR-022 | Formulas: a small total expression language with decimal arithmetic, evaluated identically in browser and server | Proposed | [30](30-PDF-PIPELINE.md) §6 |
