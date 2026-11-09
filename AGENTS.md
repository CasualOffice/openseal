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

Docs are true as of the Phase 0 foundation commit (2026-11-10).

**Phases D, 0 and 1 are open (Phase 1 under waiver `W-2`); no product behaviour is built yet.** The repository is private until the pre-release alpha (owner instruction 7), so CI runs locally through `tools/ci-local.sh`. Phase 0 so far: a Cargo workspace with a `casual-sign-pdf` skeleton, repository gates and hooks copied from OpenPresent (`PROVENANCE.md`), a CI workflow not yet run on GitHub, and a pyHanko harness that proves it can tell a sealed PDF from a tampered one (`F-006`). The repository is initialized locally on `main`; the GitHub remote waits on the owner (`F-001`). The document set is drafted: PRD, HLD, research studies of DocuSign, SignNow and open-source
competitors, pillar designs, threat model, 22 proposed ADRs, the roadmap (Phases D, 0, 1, 2, 29 slices and milestones M0–M7), the tracker
and a 165-row feature fit-gap with 0 rows working. The product is named **OpenSeal** (`DEC-01`, 2026-11-10). Twelve owner decisions remain open in
[14](docs/14-EXECUTION-TRACKER.md); ADR-001 to ADR-009 are Accepted (instruction 6). What blocks Phase 0 now is the GitHub remote, which only the owner can create (`F-001`), so CI can run (`F-003`).
