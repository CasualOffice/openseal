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

Docs are true as of `b5f7101` (2026-11-13).

**Phases D, 0, 1 and 2 are closed** (owner: D and 0 on 2026-11-11, 1 on 2026-11-11 after clean fuzz run 42907980149,
2 on 2026-11-12), and milestones M0, M1 and M2 are declared reached (instruction 38). **v0.0.1, the first
pre-release, is published** (tag at `4780d84`, GitHub CI run 43123420112 green on all 14 jobs; `REL-01` keeps the GHCR
packages' visibility and the manual walkthrough). The repository is public; GitHub CI runs, and `tools/ci-local.sh`
runs once per batch, after the batch is merged and before a push, about every 30 minutes (instructions 31, 39, 41).
Lanes use the whole machine, backing off when free memory falls below about 3 GB (instruction 40); an independent
reviewer is used only for risky pieces (security, evidence, database, server; instruction 41).

- **Built:** the Rust engine (PDF reader, writer and normalizer, fields, flattening, crypto, PAdES sealing B-B to
  B-LTA, verifier, audit chain and certificate, SDK and `openseal` CLI, WebAssembly verifier); the workflow engine,
  Postgres store, API server (`api/openapi.yaml`), job worker, `casual-sign-keyd` (PKCS#11) and the single-node Compose
  deployment; the web app, redesigned in all seven `UX-01` packages (`UX-02` to `UX-08`, merged 2026-11-13: design
  system with a distinct destructive colour, send editor with click-to-place and every field kind, signing page,
  Home/Agreements/envelope page, Templates/Reports/Admin rail, app shell with notifications and profile), tested by
  Playwright in mock mode and against the Compose stack (`compose-e2e`); the signer view naming the sender and
  serving the disclosure (`UXW-34`); organizations above workspaces (`ORG-02`, migration 0014); in
  `casual-sign-modeld`, the skeleton and bundle tooling (`ML-09`) and GLiNER spans for extraction and personal data
  (`ML-07`, `ML-08`, fp16 exports equal to the golden spans), beside `casual-sign-pii`'s validated recognisers and
  value normalisation. Security fixes `SEC-ID-01` and `SEC-CER-01` are merged. [96](docs/96-FEATURE-FIT-GAP.md)
  counts 39 of 167 rows working end to end and 17 in part.
- **In progress:** OCR (`ML-02`) and template matching (`ML-05`) on worker branches, not merged; the modeld exit
  (`compose --profile ml up`, `ML-09`); workflows a switching customer expects (`UXW-*`, e.g. in-person hosting
  `UXW-36`); ADR-028 in stages ([23](docs/23-ORGANIZATIONS-WORKSPACES-AND-CONSOLE.md)): admin audit logs (`ORG-05`)
  and switching (`ORG-04`) built, then the organization admin screens (`ORG-06`), delegated admin, console and plans
  (`ORG-*`, `CON-*`, `PLAN-*`); the console's server side (operators with TOTP, the operator log, organization reads
  and first writes, health reads; `CON-02` to `CON-05` in part, docs/23 §5.6) on a worker branch, its screens after
  the UX overhaul. Open: WebKit axe failure on the review step (`E2E-02`).
- **Next:** slices 1, 2, 5 and 7 to their end points for M3, then v0.0.2 (organizations and switching, the console with
  health, plans with three meters; instruction 29).
