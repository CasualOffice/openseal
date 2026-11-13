# 00 — OpenSeal documentation index

`docs/` is the source of truth for the design. Code follows docs. Numbers mirror OpenCalc's and OpenPresent's where a
document plays the same role, so the siblings read alike, and are never reused.

Read in this order: 03 → 01 → 02 → 05 → 06 → 14 → 07. Then the pillar you are working on.

Docs are true as of `67ca967` (2026-11-13). **Phases D, 0, 1 and 2 are closed and v0.0.1 is published:** engine, server, API, worker, keyd, Compose deployment and web app exist; since then the redesigned web app, organizations and workspaces, the platform console with plans, metering and quotas (ADR-028), the ML model service (ADR-029), and the `UXW-*` workflows have merged, most waiting for their Compose runs. State per row: [14](14-EXECUTION-TRACKER.md). Outside `docs/`: [README](../README.md)
(what it is and its status), [AGENTS.md](../AGENTS.md) (the contract and current state), [CLAUDE.md](../CLAUDE.md)
(working rules and engineering standards), [NOTICE](../NOTICE) with [THIRD-PARTY.md](../THIRD-PARTY.md) and
[THIRD-PARTY-LICENSES.txt](../THIRD-PARTY-LICENSES.txt) (third-party attributions, inventory and licence texts, generated
by `tools/licence-inventory.py`, `LEG-01`).

| Doc | What it is | Status |
| --- | --- | --- |
| [01-PRD](01-PRD.md) | **Product requirements**: outcome, users, scope, functional and non-functional requirements, risks | Draft for owner |
| [02-HLD](02-HLD.md) | **High-level design**: engine and hosts, layers, flows, seams, storage, deployment shapes | Draft for owner |
| [03-OWNER-INSTRUCTIONS](03-OWNER-INSTRUCTIONS.md) | **Everything the owner instructed. Binding, and first in authority** | Live |
| [04-MISTAKES-AND-RULES](04-MISTAKES-AND-RULES.md) | **Mistakes and the rule that stops each**, inherited from the sisters. Binds every session | Live |
| [05-PHASES-AND-TASKS](05-PHASES-AND-TASKS.md) | What a phase, stage, slice and task are; how each opens and closes; Definition of Done | Draft for owner |
| [06-ROADMAP-AND-DELIVERY](06-ROADMAP-AND-DELIVERY.md) | **The only roadmap**: milestones M0–M8, Phases D, 0, 1, 2 and 35 slices, with exit gates and parallel lanes | Draft for owner |
| [07-SECURITY-THREAT-MODEL](07-SECURITY-THREAT-MODEL.md) | Adversaries, threats, controls, data classification | Live; PDF, field and crypto threats Tested; account, ceremony and webhook threats tested in Phase 2; organization, console and inference threats (`SEC-O*`, `SEC-X*`, `SEC-I*`) part Tested, part Designed; abuse rows Planned |
| [08-ADR-REGISTER](08-ADR-REGISTER.md) | Decisions ADR-001 to ADR-033 | ADR-001 to ADR-029 Accepted (ADR-028 by owner instruction 29); ADR-030 to ADR-033 Proposed |
| [09-LEGAL-AND-COMPLIANCE](09-LEGAL-AND-COMPLIANCE.md) | ESIGN, UETA, eIDAS, Part 11, privacy, AATL; requirement → mechanism. Not legal advice | Draft for owner |
| [10-ENTERPRISE-REQUIREMENTS](10-ENTERPRISE-REQUIREMENTS.md) | The enterprise bar | Draft for owner |
| [14-EXECUTION-TRACKER](14-EXECUTION-TRACKER.md) | **The only tracker**, with owner decisions | Live |
| [15-CI-AND-RELEASE-GATES](15-CI-AND-RELEASE-GATES.md) | CI jobs, flake policy, release gates | Live; CI runs on GitHub since the repository went public, and sessions run only the test that proves their change (docs/04 rule 37) |
| [19-WORKSPACE-SCAFFOLD-DESIGN](19-WORKSPACE-SCAFFOLD-DESIGN.md) | Crates, dependency DAG, provenance, licence policy | Live; 27 workspace members, 15 engine crates in `crates/` and 12 in `server/` |
| [20-ERROR-CODE-REGISTRY](20-ERROR-CODE-REGISTRY.md) | Every diagnostic code | Live; PDF, writer, field, seal and verify codes issued |
| [21-PARSER-LIMITS](21-PARSER-LIMITS.md) | Every input limit, its default and code | Live: PDF and crypto limits built; field limits partly built (marked per row) |
| [22-DATA-MODEL](22-DATA-MODEL.md) | Entities, fields, persistence and tenancy rules | Draft for owner |
| [23-ORGANIZATIONS-WORKSPACES-AND-CONSOLE](23-ORGANIZATIONS-WORKSPACES-AND-CONSOLE.md) | Organizations above workspaces, delegated administration, identity and SSO frame, the platform console, plans, metering and enforcement (ADR-028) | ADR-028 Accepted 2026-11-12; built in part: organizations, routes, switching and admin logs (`ORG-02` to `ORG-05`), console operators, keys and TSAs (`CON-03`, `CON-06`, `CON-07`, `CON-16`), plans, metering and quotas (`PLAN-02` to `PLAN-04`) Done; organization admin screens, console approvals and health in progress; the rest designed |
| [24-ENVELOPE-LIFECYCLE-AND-ROUTING](24-ENVELOPE-LIFECYCLE-AND-ROUTING.md) | Commands, state machines, routing, correction, timers, bulk, links | Draft for owner |
| [30-PDF-PIPELINE](30-PDF-PIPELINE.md) | Admission, normalization, geometry, anchors, formulas, flattening, certificate, writer | Built in Phase 1 (closed 2026-11-11), with "As built" notes per stage |
| [31-SEALING-AND-SIGNATURES](31-SEALING-AND-SIGNATURES.md) | PAdES profiles, sealing algorithm, keyd, timestamps, verification ladder | Built: PAdES B-B to B-LTA, keyd over PKCS#11, timestamps (TSAs in the database since `CON-07`), the verification ladder with pyHanko and EU DSS |
| [32-AUDIT-TRAIL-AND-EVIDENCE](32-AUDIT-TRAIL-AND-EVIDENCE.md) | Event shape and types, hash chain, anchoring, certificate of completion, retention | Draft for owner |
| [33-ML-MODELS](33-ML-MODELS.md) | **Pretrained ML models, no training** (ADR-029): the `casual-sign-modeld` process, OCR for scans, template matching, agreement extraction and search, personal-data detection; protocol, limits, models and licences, weights pinning, threats, fixtures | Accepted (owner, 2026-11-12, instruction 30); built so far: `casual-sign-modeld` with OCR, page hashes and embeddings, GLiNER extraction and personal data (`ML-02`, `ML-05`, `ML-07`, `ML-08`, `ML-09`), `casual-sign-pii` recognisers, value normalisation, the worker's analysis jobs and the server's analysis routes (`WEB-19`), bundle tooling and fixtures; the editor's suggestions on the real stack and `compose --profile ml up` not yet |
| [40-API-DESIGN](40-API-DESIGN.md) | REST API, auth, resources, webhooks, embedding, SDKs | Draft for owner |
| [47-UX-AND-FEATURE-MAP](47-UX-AND-FEATURE-MAP.md) | Screens, signer ceremony, emails, keyboard | Draft; recalled, not measured |
| [assets/design-canvas](assets/design-canvas/README.md) | The approved interactive design canvas: the design of record for the web app (owner instruction 44) | Approved 2026-11-13 |
| [48-DOCUSIGN-STUDY](48-DOCUSIGN-STUDY.md) | DocuSign eSignature: surface, flows, recipients, tabs, lifecycle, evidence, API, admin, pricing | Live; public sources, 2026-11-10 |
| [49-SIGNNOW-STUDY](49-SIGNNOW-STUDY.md) | SignNow: editor, fields, roles and groups, auth, API, comparison with DocuSign | Live; public sources, 2026-11-10 |
| [52-COMPETITOR-STUDY](52-COMPETITOR-STUDY.md) | Open-source competitors, clean-room rule, name collision | Live; public sources, 2026-11-10 |
| [64-SPK-01-PDF-READER](64-SPK-01-PDF-READER.md) | PDF reader spike: lopdf, pdf-rs and an own bounded sketch on hostile PDFs; recovery, incremental writing, WASM size; why we build our own | Measured, 2026-11-10, macOS only |
| [66-SPK-02-CRYPTO-STACK](66-SPK-02-CRYPTO-STACK.md) | Crypto stack spike: PAdES B-B sealed with aws-lc-rs keys and RustCrypto CMS, validated by pyHanko; RustCrypto-only WASM verifier; pitfalls; ADR-006 amendments | Measured, 2026-11-10, macOS only |
| [65-RUNNING-IT](65-RUNNING-IT.md) | Deployment, production checklist, configuration, upgrades | Live: the single-node Compose stack, its services and configuration (the console's included), the production checklist; the cluster (slice 20) is design |
| [67-ASVS-SELF-ASSESSMENT](67-ASVS-SELF-ASSESSMENT.md) | **OWASP ASVS 4.0.3 self-assessment**: every requirement at Level 2 (Level 3 for ceremony, sealing and keyd) with status, the evidence checked and a docs/14 row per gap. Not a certification | Self-assessment, 2026-11-13; 38 findings, 8 closed, `ASVS-01` in progress, 29 open |
| [96-FEATURE-FIT-GAP](96-FEATURE-FIT-GAP.md) | **Every DocuSign and SignNow feature** (168 rows) with disposition, slice and status — the parity measure | Live |

**Website** ([`site/`](../site/), `SITE-01`): the marketing site and user documentation as static files, published by
`.github/workflows/pages.yml`. Page sources are in `site/_src/`; `tools/build-site.py` builds them, the roadmap page from
[06](06-ROADMAP-AND-DELIVERY.md) and [14](14-EXECUTION-TRACKER.md) (`tools/build-roadmap.py`) and the API reference from
`api/openapi.yaml` (`tools/build-api-docs.py`). Preview with `python3 -I tools/serve-site.py`; check links with
`python3 -I tools/check-site-links.py`.
