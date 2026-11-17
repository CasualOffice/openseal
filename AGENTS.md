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

Docs are true as of 2026-11-17 (`main` at `900d0b6`; pull request #18 open on `sprint1-stabilization`).

**Phases D, 0, 1 and 2 are closed** (owner: D and 0 on 2026-11-11, 1 on 2026-11-11 after clean fuzz run 42907980149,
2 on 2026-11-12), and milestones M0, M1 and M2 are declared reached (instruction 38). **v0.0.1, the first
pre-release, is published** (tag at `4780d84`; `REL-01` keeps the GHCR packages' visibility and the manual
walkthrough). It is not for production agreements. The repository is public; GitHub CI on `main` is the full check,
and sessions run only the test that proves their change (docs/04 rule 37). Work not yet on `main` goes on a branch
with a pull request whose CI must be green before the main session merges it (instructions 53, 56); commits carry no
Claude attribution or e-mail (instruction 57).

- **Focus:** harden one deployment and reach M3 (instructions 48, 51, 54). Feature expansion is paused, nothing
  dropped: ML, the platform console, plans and metering wait until M3 closes (`FRZ-01`). M3 needs slices 1, 2, 5 and
  7 closed by the owner; [73](docs/73-M3-SLICE-EVIDENCE.md) lists every gate item and its evidence.
- **Proven on `main` by CI** (runs 44001061169 and 44018844840, every job green): slice 1's outcome on the Compose stack (`VS-01`);
  failure recovery on the hardened profile (`HRD-01`, `HRD-10`); the real-style CA and TSA validation (`HRD-02`); the
  backup and restore drill (`ASVS-14`); the security event log (`ASVS-08`); anomaly alerting (`ASVS-13`);
  administrators' TOTP by default (`ASVS-31`); the site's verifier and demo (`SITE-03` to `SITE-05`); keyd seal tokens (`KEYD-02`, ADR-036); slice 5 on the real
  stack with its demo (`RAUTH-02`) and slice 2's routing spec there; the slice 1, 2, 5 and 7 demos (run 44023485128) are watched and linked from docs/65 §Demos (2026-11-18).
- **Built, waiting for CI on `main` or the owner:** Acrobat Reader reading B-LTA seals valid offline (`HRD-14`,
  `HRD-03`; green on branch run 44011154004, a run on `main` pending); slice 7 on pull request #18 (WASM verifier in CI,
  B-LT default, Verify accessibility scan and demo, public anchoring `FG-158`, ADR-037). `E2E-11` and `E2E-12` are fixed in part or wait on their gate (`E2E-07` to `E2E-09` closed).
- **Left before production use:** the external penetration test (`HRD-05`), load numbers (`HRD-04`), the rest of
  production hardening (`HRD-06`, `HRD-11`, `HRD-12`), the accessibility audit (`A11Y-01`), counsel's review
  (`LEG-02`), and the open ASVS findings: 12 requirements Not met and 32 Partly in
  [67](docs/67-ASVS-SELF-ASSESSMENT.md), a self-assessment, not a certification.
  [96](docs/96-FEATURE-FIT-GAP.md) counts 50 of 168 rows working end to end, 27 in part and 15 with their engine built.
- **Exact state per item:** [14](docs/14-EXECUTION-TRACKER.md); phases, milestones and the hardening gate:
  [06](docs/06-ROADMAP-AND-DELIVERY.md).
