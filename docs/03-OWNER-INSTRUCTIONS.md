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

## Inherited working rules

The sisters' owner instructions that shaped how work is done (enterprise grade not MVP, one roadmap and one tracker,
decide without asking, parallel sessions, nothing that crashes on the owner's desktop, no tests or scans on the owner's
machine, vertical slices after the foundation, docs true as of a commit) are **adopted here as working practice** in
[CLAUDE.md](../CLAUDE.md) and [04](04-MISTAKES-AND-RULES.md). They are not owner instructions for this repository until
the owner says so; where one matters, it is raised as a `DEC-*` row in [14](14-EXECUTION-TRACKER.md).

## Boundaries set by the environment

| Date | What | Status |
| --- | --- | --- |
| 2026-11-10 | The folder is not a git repository; no remote exists | Partly resolved: local `git init` done 2026-11-10 on `main`; the GitHub remote `CasualOffice/openseal` is for the owner to create (`F-001`) |
