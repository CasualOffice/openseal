# Governance

Adapted from OpenPresent's `GOVERNANCE.md` (itself from OpenCalc's). The project is maintained under the CasualOffice
GitHub organization, alongside OpenCalc, OpenPresent and OpenDoc.

## Authority

1. **The owner's instructions**, recorded in [docs/03](docs/03-OWNER-INSTRUCTIONS.md), come first. Where a document,
   a design or anyone's judgement disagrees, that page wins, and the disagreement is raised with the owner rather than
   quietly settled.
2. **Accepted ADRs** in [docs/08](docs/08-ADR-REGISTER.md).
3. **The design documents** indexed in [docs/00](docs/00-README.md).

Only the owner closes a phase, slice or milestone ([docs/05](docs/05-PHASES-AND-TASKS.md)).

## Roles

**Owner**: sets direction, decides what is delegated, closes phases and milestones, and holds the decisions that need
a lawyer (`DEC-07`, `LEG-02`).

**Maintainers** own repository administration, releases, security response and key-handling policy. Until named
maintainers are recorded here, before the first public preview, repository write access is the authoritative signal.

**Subsystem owners** review changes in their area (PDF reader and writer, fields and flattening, crypto and sealing,
verification, audit, workflow, server, keyd, web app) and keep its design, tests, fixtures and tracker rows true.

**Contributors**, human or agent, propose designs and changes through [CONTRIBUTING.md](CONTRIBUTING.md). An agent
works under [AGENTS.md](AGENTS.md), and **a worker's report is not evidence**: the main session verifies by running it.

## Decisions

Substantial decisions are designed first: state the outcome and constraints; record research and alternatives; write a
design note, or an ADR if a trigger in docs/08 applies; resolve objections; mark it Accepted; track it in
[docs/14](docs/14-EXECUTION-TRACKER.md); implement and verify.

## Protected areas

A change to these needs maintainer review, because it is expensive or dangerous to reverse:

- public API, webhook payloads and SDK surface ([docs/40](docs/40-API-DESIGN.md));
- the data model, envelope state machine and audit event schema ([docs/22](docs/22-DATA-MODEL.md),
  [docs/24](docs/24-ENVELOPE-LIFECYCLE-AND-ROUTING.md), [docs/32](docs/32-AUDIT-TRAIL-AND-EVIDENCE.md));
- **cryptography, sealing profiles, key custody and trust** ([docs/31](docs/31-SEALING-AND-SIGNATURES.md));
- crate boundaries and the dependency DAG ([docs/19](docs/19-WORKSPACE-SCAFFOLD-DESIGN.md));
- parser limits and security policy ([docs/21](docs/21-PARSER-LIMITS.md), [docs/07](docs/07-SECURITY-THREAT-MODEL.md)),
  and anything that would need `unsafe`, which is forbidden;
- legal and compliance statements ([docs/09](docs/09-LEGAL-AND-COMPLIANCE.md));
- third-party material ([NOTICE](NOTICE)); CI gates and release automation ([docs/15](docs/15-CI-AND-RELEASE-GATES.md)).

## Releases

A release needs every gate in [docs/15](docs/15-CI-AND-RELEASE-GATES.md), an updated [CHANGELOG.md](CHANGELOG.md) and
tracker, compatibility notes and reproducible artifacts. No single contributor may weaken a release gate in order to
publish.
