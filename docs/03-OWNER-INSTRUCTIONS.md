# 03 — Owner instructions

**Binding, and first in authority.** Every instruction from the owner is recorded here, close to their words, with
where it is applied. Work follows these without deviation. Where a document, a design or an agent's judgement disagrees,
this page wins. If an instruction seems wrong or conflicts with another, raise it with the owner; do not quietly choose.

Add a row in the same turn an instruction is given. Rows are never edited away; a later instruction supersedes an earlier one
by saying so.

| # | Date | Instruction | Applied in |
| --- | --- | --- | --- |
| 1 | 2026-11-10 | "As we have our sister repos with architecture, i.e. OpenCalc, OpenPresent … we need to understand SignNow as well as DocuSign, and create an Apache-2.0 licensed clone of it" | [01](01-PRD.md), [02](02-HLD.md), `DEC-02`, `LICENSE` |
| 2 | 2026-11-10 | "Please do deep-dive research" on both products | [48](48-DOCUSIGN-STUDY.md), [49](49-SIGNNOW-STUDY.md), [52](52-COMPETITOR-STUDY.md), [09](09-LEGAL-AND-COMPLIANCE.md) |
| 3 | 2026-11-10 | "Create PRD, HLD, technical documentation, CLAUDE.md, README, as well as other required roadmap trackers and all" | [01](01-PRD.md), [02](02-HLD.md), docs 19–40, [CLAUDE.md](../CLAUDE.md), [README](../README.md), [06](06-ROADMAP-AND-DELIVERY.md), [14](14-EXECUTION-TRACKER.md), [96](96-FEATURE-FIT-GAP.md) |
| 4 | 2026-11-10 | "Let's name it OpenSeal" | `DEC-01`, every document, skills renamed `openseal-*` |
| 5 | 2026-11-10 | "Proceed ahead … create roadmap, phases, milestones" — taken as approving the recommended git workflow (`DEC-11`) | [06](06-ROADMAP-AND-DELIVERY.md) §Milestones, `DEC-11`, `F-001`, `MS-*` in [14](14-EXECUTION-TRACKER.md) |
| 6 | 2026-11-10 | "Proceed" — taken as accepting ADR-001 to ADR-009 and opening Phase 0, as proposed | [08](08-ADR-REGISTER.md), [06](06-ROADMAP-AND-DELIVERY.md) Phase 0, `F-*` in [14](14-EXECUTION-TRACKER.md) |
| 7 | 2026-11-10 | "Proceed … I will make it public when we have a viable demo, and it's pre-release alpha then." The repository stays private until then, so GitHub Actions does not run; the main session runs `tools/ci-local.sh` at every merge instead | `W-2` in [06](06-ROADMAP-AND-DELIVERY.md); [CLAUDE.md](../CLAUDE.md); `F-003`; Phase 1 opened |
| 8 | 2026-11-10 | "It's not an MVP — don't judge this or remove things based on that assumption." Nothing is dropped, refused for good, or left "later" because a minimal product would not need it: every DocuSign and SignNow capability, every real-world PDF construct, and every option offered is planned, with a slice and a row. Order and severity may sequence work; they never remove it | [96](96-FEATURE-FIT-GAP.md) (no `Later` rows), [30](30-PDF-PIPELINE.md) §3, [06](06-ROADMAP-AND-DELIVERY.md) slice 30, `XFA-01`, `FILL-01`, `TAG-02`, `ACRO-02`; [04](04-MISTAKES-AND-RULES.md) rule 28 |
| 9 | 2026-11-10 | "Proceed" on the recommendations: remote online notarization comes in as a slice (notary workflow in OpenSeal, commissioned notaries through licensed provider integrations); contract lifecycle management, Rooms, a workflow builder and AI agreement analysis come in as OpenSeal add-on modules on the public API | `DEC-08`, `DEC-09`, slices 31–35 in [06](06-ROADMAP-AND-DELIVERY.md), [01](01-PRD.md) §5, [96](96-FEATURE-FIT-GAP.md) |
| 10 | 2026-11-10 | "If some decisions are pending on me, just ask me with options; I can choose." Pending owner decisions are put as a multiple-choice question when they arise, never left in a status note | [04](04-MISTAKES-AND-RULES.md) |
| 11 | 2026-11-10 | Chose: Phase 1 gate P1-GATE-01 excludes DocMDP P1-certified files by a recorded rule (refused with a stable code), rather than building NORM-02 first; a seeded-violation draft PR on the public repository proves each CI job fails (Phase 0); FUZZ-01's 24 h per target runs on GitHub Actions on a schedule | `P1-GATE-01`, `F-003`, `FUZZ-01` in [14](14-EXECUTION-TRACKER.md); [06](06-ROADMAP-AND-DELIVERY.md) Phase 0 and 1 |
| 12 | 2026-11-11 | Chose, from options: accept ADR-010 to ADR-024 as proposed; accept the recommendations for `DEC-02` to `DEC-07`, `DEC-10`, `DEC-12`, `DEC-13` (Phase 2 opens early under `W-1`) and `DEC-14`; sign off Phase 0 as closed | [08](08-ADR-REGISTER.md), Owner decisions in [14](14-EXECUTION-TRACKER.md), [06](06-ROADMAP-AND-DELIVERY.md) Phase D, Phase 0, `W-1`, `W-2` |
| 13 | 2026-11-11 | Chose, from options: sign off Phase D as closed | [06](06-ROADMAP-AND-DELIVERY.md) Phase D, [README](../README.md), [AGENTS](../AGENTS.md) |
| 14 | 2026-11-11 | Chose, from options: move to sqlx 0.9 and raise the MSRV from 1.88 to 1.94 (not ignoring the two advisories sqlx 0.8 brings into the lockfile); keep ADR-014's compile-time checked queries, with a committed offline query cache so builds need no database | `Cargo.toml` `rust-version`, `ci.yml` and `tools/ci-local.sh` msrv jobs, [08](08-ADR-REGISTER.md) ADR-014, `T-2B` |
| 15 | 2026-11-11 | Chose, from options: ignore RUSTSEC-2026-0459 only, with its reason and a tracker row (sqlx 0.9's macros list a SQLite driver that is never compiled, and no sqlx release allows the fixed `libsqlite3-sys` yet) | `.cargo/audit.toml`, `DEP-04` |
| 16 | 2026-11-11 | Chose, from options: accept the `multi_select` field type and `Choices` value as ADR-025 | [08](08-ADR-REGISTER.md) ADR-025, `ACRO-02` |
| 17 | 2026-11-11 | "Yes, opt-in per document, and if not approved, even then approximate from his IP; we can use a geo-IP library." Record the signer's location: a per-envelope setting asks the signer's browser for its location; if the signer declines (or the browser cannot), the location is approximated from the request IP with a GeoIP database, and the event records which source it came from | `GEO-01`, [32](32-AUDIT-TRAIL-AND-EVIDENCE.md), [09](09-LEGAL-AND-COMPLIANCE.md) |

## Inherited working rules

The sisters' owner instructions that shaped how work is done (enterprise grade not MVP, one roadmap and one tracker,
decide without asking, parallel sessions, nothing that crashes on the owner's desktop, no tests or scans on the owner's
machine, vertical slices after the foundation, docs true as of a commit) are **adopted here as working practice** in
[CLAUDE.md](../CLAUDE.md) and [04](04-MISTAKES-AND-RULES.md). They are not owner instructions for this repository until
the owner says so; where one matters, it is raised as a `DEC-*` row in [14](14-EXECUTION-TRACKER.md).

## Boundaries set by the environment

| Date | What | Status |
| --- | --- | --- |
| 2026-11-10 | The folder is not a git repository; no remote exists | Resolved: the owner created `CasualOffice/openseal` and made it public on 2026-11-10 (`F-001`) |
| 2026-11-10 | GitHub Actions starts no job on `CasualOffice/openseal`: private repository, and the organization's Actions billing is blocked. Owner informed; acknowledged | Resolved: the owner made the repository public on 2026-11-10; GitHub CI runs |
