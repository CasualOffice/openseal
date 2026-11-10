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

Docs are true as of `40b9429` (2026-11-11).

**Phases D and 0 are closed** (owner, 2026-11-11). **Phase 1 is open; Phase 2 is open early under waiver `W-1`**
(`DEC-13`). `W-2` is retired. The repository is public; GitHub CI runs, and `tools/ci-local.sh` stays the pre-push gate.

- **Phase 1:** built and merged: 1A reader, 1B writer and normalizer, 1C geometry, text, anchors, tags and AcroForm
  conversion, 1D field rules, 1E flattening and fill-in-place, 1F crypto structures, 1G sealing, 1H verifier, 1I
  audit chain and certificate (leftovers in their rows), and reader completion (decryption, LZW, the four wrongly
  refused corpus files), 1J SDK and `openseal` CLI. Exit item 2 met: every admitted corpus PDF passes fill, flatten,
  seal and verify in ours, pyHanko and EU DSS (`P1-GATE-01`); items 4 and 6 met (`VER-03`, `WASM-01`). Left for
  the exit gate: 24 h fuzzing per target, every 6 h on GitHub (`FUZZ-01`), owner sign-off.
- **No server, API or UI exists yet.** The roadmap has 35 slices and milestones M0–M8; the fit-gap has 167 rows, none
  working end to end yet.
