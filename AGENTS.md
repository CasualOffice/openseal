# AGENTS.md — Agent contract for OpenSeal

Read this in full before doing anything else. Owner instructions are in [docs/03](docs/03-OWNER-INSTRUCTIONS.md) and
come first. Working rules, engineering standards and skills are in [CLAUDE.md](CLAUDE.md). The product is OpenSeal
(`DEC-01`, owner instruction 4); crates use the prefix `casual-sign-`, which does not depend on it.

## Repository boundary

- **This repository is the target.** All work happens here.
- **`../opencalc` and `../openslide` (OpenPresent) are sister repos and are reference-only.** They are the
  architecture this project follows. Read them, copy from them with provenance
  ([19](docs/19-WORKSPACE-SCAFFOLD-DESIGN.md) §Provenance), **do not modify them.**

## Mission

An **enterprise-grade**, Apache-2.0 electronic-signature platform: DocuSign eSignature's feature bar and workflow,
SignNow's speed of preparation, self-hostable, embeddable and API-first, so a DocuSign or SignNow user needs no
teaching and an integrator can replace either through an API they recognize ([01](docs/01-PRD.md)).

**Evidence integrity is the most critical property.** A completed agreement must be provably the document every party
saw, signed by whom, when and how, verifiable offline by anyone, for decades ([31](docs/31-SEALING-AND-SIGNATURES.md),
[32](docs/32-AUDIT-TRAIL-AND-EVIDENCE.md)). Every upload is hostile and every party is a potential adversary of the
record ([07](docs/07-SECURITY-THREAT-MODEL.md)).

## The cycle

Every task, none of it optional:

    design → execute → check → find issues → fix → push, with tests

- **Check** means running the thing, not re-reading it.
- **Find issues** asks what would have to be true for this to be wrong, then goes and looks.
- **With tests** means a test seen to fail without the fix.
- **Discuss and finalize** substantial designs before implementing. An ADR trigger ([08](docs/08-ADR-REGISTER.md))
  needs an Accepted ADR first.
- **Track everything** in [14](docs/14-EXECUTION-TRACKER.md). No untracked work.

## Priorities (the earlier wins)

1. **Integrity of evidence** — never produce a sealed document or audit trail that misstates what happened.
2. **Security and privacy** — every parser bounded; nothing active executed; tenants isolated; keys isolated; no
   personal data in logs.
3. **Correctness of workflow** — the right person acts at the right time, and nothing completes early or twice.
4. **Determinism** — same inputs, keys and supplied time ⇒ same bytes and verdicts.
5. **Long-term verifiability** — standards-based output any validator accepts.
6. **API stability** — public surfaces narrower than internals; versioned.
7. **UX** — DocuSign's flows are the specification; signers need no teaching; accessible.
8. **Performance and maintainability.**

## Design rules

- **The engine is pure.** No I/O, clock, randomness or keys inside `crates/`; hosts supply them.
- **Mutation only through commands.** Every change to an envelope is a workflow command returning state, events and
  effects.
- **Evidence before acknowledgement; append-only evidence; sealed documents never modified.**
- **What you see is what you sign.** Signers review the engine's flattened output.
- **Deny by default, per object, on the server.** Hiding a button is never a control.
- **The host owns policy.** Providers, retention, trust, branding are configuration.
- **No silent loss.** Anything neutralized in an upload is named in the admission report.
- **Never claim legal validity, compliance or certification.** Say "designed to support" ([09](docs/09-LEGAL-AND-COMPLIANCE.md)).
- **A document stating a contract the code does not keep is a tracker row**, not a doc edit.
- **Report outcomes faithfully.** Designed, built, tested and verified are four different words.

## Current state

Docs are true as of `67ca967` (2026-11-13).

**Phases D, 0, 1 and 2 are closed** (owner: D and 0 on 2026-11-11, 1 on 2026-11-11 after clean fuzz run 42907980149,
2 on 2026-11-12), and milestones M0, M1 and M2 are declared reached (instruction 38). **v0.0.1, the first
pre-release, is published** (tag at `4780d84`, GitHub CI run 43123420112 green on all 14 jobs; `REL-01` keeps the GHCR
packages' visibility and the manual walkthrough). The repository is public; GitHub CI on `main` is the full check, and
sessions run only the test that proves their change (docs/04 rule 37). Work runs as one cycling queue whose items
merge and push straight to `main`, with no pull requests (instructions 45 to 47). Lanes use the whole machine,
backing off when free memory falls below about 3 GB (instruction 40); an independent reviewer is used only for risky
pieces (security, evidence, database, server; instruction 41).

- **Built:** the Rust engine (PDF reader, writer and normalizer, fields, flattening, crypto, PAdES sealing B-B to
  B-LTA, verifier, audit chain and certificate, XFA layout, `casual-sign-pii` recognisers, SDK and `openseal` CLI,
  WebAssembly verifier); the workflow engine, Postgres store (migrations 0001 to 0034), API server
  (`api/openapi.yaml`), job worker, `casual-sign-keyd` (PKCS#11) and the single-node Compose deployment; the web app,
  redesigned on the approved design (`UX-02` to `UX-08`, `WEB-17`, `WEB-18`), tested by Playwright in mock mode and
  against the Compose stack (`compose-e2e`). Merged on 2026-11-13 and tested on the server, most rows waiting only for
  their Compose run in CI: Inbox, folders, Deleted views and server filters (`UXW-01` to `UXW-03`); bulk send from a
  template with a CSV list (`UXW-04`); template sharing, Shared with me and Favourites (`UXW-06`); groups and custom
  permission profiles (`UXW-07`); the admin audit log screen and the webhooks screen (`UXW-09`, `UXW-10`,
  `UXW-31` to `UXW-33`); organizations, their routes, workspace switching and admin audit logs (`ORG-02` to `ORG-05`
  Done) and the organization admin screens' first cut (`ORG-06`); the platform console `casual-sign-console` with
  operators and TOTP (`CON-03`), approvals and suspend or resume (`CON-04`), health (`CON-05`), the Keys page over
  keyd's admin interface (`CON-06`), timestamp authorities in the database changed by two key custodians (`CON-07`),
  console writes copied into organization logs (`CON-16`) and its UI (`CON-17`); plans, metering and quota
  enforcement (`PLAN-02` to `PLAN-04` Done); SMS and voice one-time codes and recipient sign-in through an OpenID
  Connect provider (`VS-05`, `RAUTH-01`, ADR-033 Proposed); a staff TOTP second factor (`ASVS-01`), breached-password
  refusal and security notices (`ASVS-02`, `ASVS-04`); malware scanning of uploads through ClamAV (`ASVS-11`); in `casual-sign-modeld`, OCR (`ML-02`), page hashes and
  embeddings (`ML-05`), GLiNER extraction and personal data (`ML-07`, `ML-08`), with the worker's analysis jobs and
  the server's analysis routes (`WEB-19`); the ASVS 4.0.3 self-assessment ([67](docs/67-ASVS-SELF-ASSESSMENT.md),
  `SEC-ASVS-01`) and the licence inventory (`LEG-01`). [96](docs/96-FEATURE-FIT-GAP.md) counts 48 of 168 rows working
  end to end and 25 in part.
- **In progress:** slice 1 (`VS-01`: the browser run on Compose green on GitHub, the demo `S1-02`, accessibility);
  slice 2 (`VS-02`: CI on main with the in-person Compose spec `UXW-18`, the demo `RTE-04`); slice 5 (`VS-05`: the
  Compose run and demo `RAUTH-02`, ADR-033's acceptance); the Compose runs of the `UXW-*` and `ORG-06` rows above;
  the console as a Compose service and its remaining writes (`CON-02`, `CON-04`, `CON-05`); the editor's model
  suggestions and `compose --profile ml up` (`WEB-18`, `ML-09`); the open ASVS findings and `LEG-01` sign-off.
- **Next:** slices 1, 2, 5 and 7 to their end points for M3, then v0.0.2 (organizations and switching, the console with
  health, plans with three meters; instruction 29), then the rest of ADR-028 (`ORG-07` onward, `CON-08` onward,
  `PLAN-05` onward).
