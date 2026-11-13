# 00 — OpenSeal documentation index

`docs/` is the source of truth for the design. Code follows docs. Numbers mirror OpenCalc's and OpenPresent's where a
document plays the same role, so the siblings read alike, and are never reused.

Read in this order: 03 → 01 → 02 → 05 → 06 → 14 → 07. Then the pillar you are working on.

Docs are true as of `19518fb` (2026-11-12). **Phases D, 0, 1 and 2 are closed and v0.0.1 is published:** engine, server, API, worker, keyd, Compose deployment and web app exist; organizations (ADR-028), ML (ADR-029) and the UI pass are in progress. State per row: [14](14-EXECUTION-TRACKER.md). Outside `docs/`: [README](../README.md)
(what it is and its status), [AGENTS.md](../AGENTS.md) (the contract and current state), [CLAUDE.md](../CLAUDE.md)
(working rules and engineering standards).

| Doc | What it is | Status |
| --- | --- | --- |
| [01-PRD](01-PRD.md) | **Product requirements**: outcome, users, scope, functional and non-functional requirements, risks | Draft for owner |
| [02-HLD](02-HLD.md) | **High-level design**: engine and hosts, layers, flows, seams, storage, deployment shapes | Draft for owner |
| [03-OWNER-INSTRUCTIONS](03-OWNER-INSTRUCTIONS.md) | **Everything the owner instructed. Binding, and first in authority** | Live |
| [04-MISTAKES-AND-RULES](04-MISTAKES-AND-RULES.md) | **Mistakes and the rule that stops each**, inherited from the sisters. Binds every session | Live |
| [05-PHASES-AND-TASKS](05-PHASES-AND-TASKS.md) | What a phase, stage, slice and task are; how each opens and closes; Definition of Done | Draft for owner |
| [06-ROADMAP-AND-DELIVERY](06-ROADMAP-AND-DELIVERY.md) | **The only roadmap**: milestones M0–M8, Phases D, 0, 1, 2 and 35 slices, with exit gates and parallel lanes | Draft for owner |
| [07-SECURITY-THREAT-MODEL](07-SECURITY-THREAT-MODEL.md) | Adversaries, threats, controls, data classification | Live; PDF, field and crypto threats Tested, server threats Planned, inference threats (`SEC-I*`) Designed |
| [08-ADR-REGISTER](08-ADR-REGISTER.md) | Decisions ADR-001 to ADR-029 | ADR-001 to ADR-029 Accepted (ADR-028 by owner instruction 29) |
| [09-LEGAL-AND-COMPLIANCE](09-LEGAL-AND-COMPLIANCE.md) | ESIGN, UETA, eIDAS, Part 11, privacy, AATL; requirement → mechanism. Not legal advice | Draft for owner |
| [10-ENTERPRISE-REQUIREMENTS](10-ENTERPRISE-REQUIREMENTS.md) | The enterprise bar | Draft for owner |
| [14-EXECUTION-TRACKER](14-EXECUTION-TRACKER.md) | **The only tracker**, with owner decisions | Live |
| [15-CI-AND-RELEASE-GATES](15-CI-AND-RELEASE-GATES.md) | CI jobs, flake policy, release gates | Workflow written; runs locally (`tools/ci-local.sh`) until the repository is public |
| [19-WORKSPACE-SCAFFOLD-DESIGN](19-WORKSPACE-SCAFFOLD-DESIGN.md) | Crates, dependency DAG, provenance, licence policy | Live; eleven crates: nine built, `-sdk` and `-wasm` in progress |
| [20-ERROR-CODE-REGISTRY](20-ERROR-CODE-REGISTRY.md) | Every diagnostic code | Live; PDF, writer, field, seal and verify codes issued |
| [21-PARSER-LIMITS](21-PARSER-LIMITS.md) | Every input limit, its default and code | Live: PDF and crypto limits built; field limits partly built (marked per row) |
| [22-DATA-MODEL](22-DATA-MODEL.md) | Entities, fields, persistence and tenancy rules | Draft for owner |
| [23-ORGANIZATIONS-WORKSPACES-AND-CONSOLE](23-ORGANIZATIONS-WORKSPACES-AND-CONSOLE.md) | Organizations above workspaces, delegated administration, identity and SSO frame, the platform console, plans, metering and enforcement (ADR-028) | Designed; ADR-028 Accepted 2026-11-12; nothing built |
| [24-ENVELOPE-LIFECYCLE-AND-ROUTING](24-ENVELOPE-LIFECYCLE-AND-ROUTING.md) | Commands, state machines, routing, correction, timers, bulk, links | Draft for owner |
| [30-PDF-PIPELINE](30-PDF-PIPELINE.md) | Admission, normalization, geometry, anchors, formulas, flattening, certificate, writer | Stages 1A–1D built ("As built" notes); flattening and certificate designed |
| [31-SEALING-AND-SIGNATURES](31-SEALING-AND-SIGNATURES.md) | PAdES profiles, sealing algorithm, keyd, timestamps, verification ladder | Crypto structures built (1F); sealing and keyd designed; validators running |
| [32-AUDIT-TRAIL-AND-EVIDENCE](32-AUDIT-TRAIL-AND-EVIDENCE.md) | Event shape and types, hash chain, anchoring, certificate of completion, retention | Draft for owner |
| [33-ML-MODELS](33-ML-MODELS.md) | **Pretrained ML models, no training** (ADR-029): the `casual-sign-modeld` process, OCR for scans, template matching, agreement extraction and search, personal-data detection; protocol, limits, models and licences, weights pinning, threats, fixtures | Accepted (owner, 2026-11-12, instruction 30); built so far: `casual-sign-modeld` skeleton (`ML-09`), `casual-sign-pii` recognisers (`ML-08`), value normalisation (`ML-07`), bundle tooling and fixtures; OCR, template matching and extraction not yet |
| [40-API-DESIGN](40-API-DESIGN.md) | REST API, auth, resources, webhooks, embedding, SDKs | Draft for owner |
| [47-UX-AND-FEATURE-MAP](47-UX-AND-FEATURE-MAP.md) | Screens, signer ceremony, emails, keyboard | Draft; recalled, not measured |
| [assets/design-canvas](assets/design-canvas/README.md) | The approved interactive design canvas: the design of record for the web app (owner instruction 44) | Approved 2026-11-13 |
| [48-DOCUSIGN-STUDY](48-DOCUSIGN-STUDY.md) | DocuSign eSignature: surface, flows, recipients, tabs, lifecycle, evidence, API, admin, pricing | Live; public sources, 2026-11-10 |
| [49-SIGNNOW-STUDY](49-SIGNNOW-STUDY.md) | SignNow: editor, fields, roles and groups, auth, API, comparison with DocuSign | Live; public sources, 2026-11-10 |
| [52-COMPETITOR-STUDY](52-COMPETITOR-STUDY.md) | Open-source competitors, clean-room rule, name collision | Live; public sources, 2026-11-10 |
| [64-SPK-01-PDF-READER](64-SPK-01-PDF-READER.md) | PDF reader spike: lopdf, pdf-rs and an own bounded sketch on hostile PDFs; recovery, incremental writing, WASM size; why we build our own | Measured, 2026-11-10, macOS only |
| [66-SPK-02-CRYPTO-STACK](66-SPK-02-CRYPTO-STACK.md) | Crypto stack spike: PAdES B-B sealed with aws-lc-rs keys and RustCrypto CMS, validated by pyHanko; RustCrypto-only WASM verifier; pitfalls; ADR-006 amendments | Measured, 2026-11-10, macOS only |
| [65-RUNNING-IT](65-RUNNING-IT.md) | Deployment, production checklist, configuration, upgrades | Design; the server does not exist yet (Phase 2) |
| [96-FEATURE-FIT-GAP](96-FEATURE-FIT-GAP.md) | **Every DocuSign and SignNow feature** (168 rows) with disposition, slice and status — the parity measure | Live |

**Website** ([`site/`](../site/), `SITE-01`): the marketing site and user documentation as static files, published by
`.github/workflows/pages.yml`. Page sources are in `site/_src/`; `tools/build-site.py` builds them, the roadmap page from
[06](06-ROADMAP-AND-DELIVERY.md) and [14](14-EXECUTION-TRACKER.md) (`tools/build-roadmap.py`) and the API reference from
`api/openapi.yaml` (`tools/build-api-docs.py`). Preview with `python3 -I tools/serve-site.py`; check links with
`python3 -I tools/check-site-links.py`.
