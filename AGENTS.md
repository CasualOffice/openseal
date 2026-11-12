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

Docs are true as of `19518fb` (2026-11-12).

**Phases D, 0, 1 and 2 are closed** (owner: D and 0 on 2026-11-11, 1 on 2026-11-11 after clean fuzz run 42907980149,
2 on 2026-11-12). **v0.0.1, the first pre-release, is published** (tag at `4780d84`, GitHub CI run 43123420112 green on
all 14 jobs; `REL-01` keeps the GHCR packages' visibility and the manual walkthrough). The repository is public; GitHub
CI runs, and `tools/ci-local.sh` runs once per batch before a push (instruction 31). Work runs within this machine's
memory: one Rust build at a time (instruction 37).

- **Built:** the Rust engine (PDF reader, writer and normalizer, fields, flattening, crypto, PAdES sealing B-B to
  B-LTA, verifier, audit chain and certificate, SDK and `openseal` CLI, WebAssembly verifier); the workflow engine,
  Postgres store, API server (`api/openapi.yaml`), job worker, `casual-sign-keyd` (PKCS#11) and the single-node Compose
  deployment; the web app (sign-in, home, agreements, document-first send editor, templates, reports, admin, signer
  ceremony on phone and desktop, verify page), tested by Playwright in mock mode and against the Compose stack
  (`compose-e2e`). [96](docs/96-FEATURE-FIT-GAP.md) counts 39 of 167 rows working end to end.
- **In progress:** the UI pass in packages `UX-02` to `UX-08` (`UX-01`; missing workflows `UXW-01`–`UXW-29`);
  organizations, workspaces, delegated admin, the platform console and plans (ADR-028 Accepted,
  [23](docs/23-ORGANIZATIONS-WORKSPACES-AND-CONSOLE.md), `ORG-*`, `CON-*`, `PLAN-*`); pretrained ML models (ADR-029
  Accepted, [33](docs/33-ML-MODELS.md)): the `casual-sign-modeld` skeleton (`ML-09`), personal-data recognisers
  `casual-sign-pii` (`ML-08`) and value normalisation (`ML-07`) are merged; OCR (`ML-02`), template matching (`ML-05`)
  and extraction (`ML-07`) are being built. The P0 fix `SEC-ID-01` (cross-workspace account takeover) is in progress.
- **Next:** slices 1, 2, 5 and 7 to their end points for M3, then v0.0.2 (organizations and switching, the console with
  health, plans with three meters; instruction 29).
