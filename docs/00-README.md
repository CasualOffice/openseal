# 00 — OpenSeal documentation index

`docs/` is the source of truth for the design. Code follows docs. Numbers mirror OpenCalc's and OpenPresent's where a
document plays the same role, so the siblings read alike, and are never reused.

Read in this order: 03 → 01 → 02 → 05 → 06 → 14 → 07. Then the pillar you are working on.

Docs are true as of the initial commit (2026-11-10); **nothing is built yet.** Outside `docs/`: [README](../README.md)
(what it is and its status), [AGENTS.md](../AGENTS.md) (the contract and current state), [CLAUDE.md](../CLAUDE.md)
(working rules and engineering standards).

| Doc | What it is | Status |
| --- | --- | --- |
| [01-PRD](01-PRD.md) | **Product requirements**: outcome, users, scope, functional and non-functional requirements, risks | Draft for owner |
| [02-HLD](02-HLD.md) | **High-level design**: engine and hosts, layers, flows, seams, storage, deployment shapes | Draft for owner |
| [03-OWNER-INSTRUCTIONS](03-OWNER-INSTRUCTIONS.md) | **Everything the owner instructed. Binding, and first in authority** | Live |
| [04-MISTAKES-AND-RULES](04-MISTAKES-AND-RULES.md) | **Mistakes and the rule that stops each**, inherited from the sisters. Binds every session | Live |
| [05-PHASES-AND-TASKS](05-PHASES-AND-TASKS.md) | What a phase, stage, slice and task are; how each opens and closes; Definition of Done | Draft for owner |
| [06-ROADMAP-AND-DELIVERY](06-ROADMAP-AND-DELIVERY.md) | **The only roadmap**: milestones M0–M7, Phases D, 0, 1, 2 and 29 vertical slices, with exit gates and parallel lanes | Draft for owner |
| [07-SECURITY-THREAT-MODEL](07-SECURITY-THREAT-MODEL.md) | Adversaries, threats, controls, data classification | Draft; every row Planned |
| [08-ADR-REGISTER](08-ADR-REGISTER.md) | Decisions ADR-001 to ADR-022 | All Proposed |
| [09-LEGAL-AND-COMPLIANCE](09-LEGAL-AND-COMPLIANCE.md) | ESIGN, UETA, eIDAS, Part 11, privacy, AATL; requirement → mechanism. Not legal advice | Draft for owner |
| [10-ENTERPRISE-REQUIREMENTS](10-ENTERPRISE-REQUIREMENTS.md) | The enterprise bar | Draft for owner |
| [14-EXECUTION-TRACKER](14-EXECUTION-TRACKER.md) | **The only tracker**, with owner decisions | Live |
| [15-CI-AND-RELEASE-GATES](15-CI-AND-RELEASE-GATES.md) | CI jobs, flake policy, release gates | Draft; nothing runs yet |
| [19-WORKSPACE-SCAFFOLD-DESIGN](19-WORKSPACE-SCAFFOLD-DESIGN.md) | Crates, dependency DAG, provenance, licence policy | Draft; nothing exists yet |
| [20-ERROR-CODE-REGISTRY](20-ERROR-CODE-REGISTRY.md) | Every diagnostic code, reserved | Live; none issued |
| [21-PARSER-LIMITS](21-PARSER-LIMITS.md) | Every input limit, its default and code | Proposed defaults |
| [22-DATA-MODEL](22-DATA-MODEL.md) | Entities, fields, persistence and tenancy rules | Draft for owner |
| [24-ENVELOPE-LIFECYCLE-AND-ROUTING](24-ENVELOPE-LIFECYCLE-AND-ROUTING.md) | Commands, state machines, routing, correction, timers, bulk, links | Draft for owner |
| [30-PDF-PIPELINE](30-PDF-PIPELINE.md) | Admission, normalization, geometry, anchors, formulas, flattening, certificate, writer | Draft for owner |
| [31-SEALING-AND-SIGNATURES](31-SEALING-AND-SIGNATURES.md) | PAdES profiles, sealing algorithm, keyd, timestamps, verification ladder | Draft for owner |
| [32-AUDIT-TRAIL-AND-EVIDENCE](32-AUDIT-TRAIL-AND-EVIDENCE.md) | Event shape and types, hash chain, anchoring, certificate of completion, retention | Draft for owner |
| [40-API-DESIGN](40-API-DESIGN.md) | REST API, auth, resources, webhooks, embedding, SDKs | Draft for owner |
| [47-UX-AND-FEATURE-MAP](47-UX-AND-FEATURE-MAP.md) | Screens, signer ceremony, emails, keyboard | Draft; recalled, not measured |
| [48-DOCUSIGN-STUDY](48-DOCUSIGN-STUDY.md) | DocuSign eSignature: surface, flows, recipients, tabs, lifecycle, evidence, API, admin, pricing | Live; public sources, 2026-11-10 |
| [49-SIGNNOW-STUDY](49-SIGNNOW-STUDY.md) | SignNow: editor, fields, roles and groups, auth, API, comparison with DocuSign | Live; public sources, 2026-11-10 |
| [52-COMPETITOR-STUDY](52-COMPETITOR-STUDY.md) | Open-source competitors, clean-room rule, name collision | Live; public sources, 2026-11-10 |
| [65-RUNNING-IT](65-RUNNING-IT.md) | Deployment, production checklist, configuration, upgrades | Design; nothing runs yet |
| [96-FEATURE-FIT-GAP](96-FEATURE-FIT-GAP.md) | **Every DocuSign and SignNow feature** (165 rows) with disposition, slice and status — the parity measure | Live |
