# 06 — Roadmap and delivery

**The only roadmap.** This is an enterprise product, not an MVP. The rules for opening and closing are in
[05](05-PHASES-AND-TASKS.md); state is recorded in [14](14-EXECUTION-TRACKER.md).

**Order follows the product's critical property:** evidence integrity comes first, so the **PDF and evidence core**
(Phase 1) and the **envelope engine and server** (Phase 2) are built bottom-up. After Phase 2, work runs as **vertical
slices**: thin features a user can use, cut through every layer, then deepened — the sisters' practice after their
foundation phases. **Web and desktop are both supported** (`DEC-05`); web comes first because signers are on the web.

**Validator verification is a phase gate, Acrobat verification is a release gate** (`PV-01`): Phase 1 closes against our
verifier, pyHanko and EU DSS in CI; nothing claims "valid in Adobe Acrobat" before `PV-01` passes.

**No calendar dates.** Sizes are in session-hours once Phase 0 has calibrated throughput, as OpenPresent did. Until
then each milestone carries a relative size (S, M, L, XL), and the first calibrated estimate is due at M1's close.

## Milestones

Phases and slices are the **units of work**; milestones are the **points a user, integrator or operator can feel**.
Each milestone is reached when every phase, slice and gate listed for it is closed. Only the owner declares a
milestone reached, as with phases ([05](05-PHASES-AND-TASKS.md)).

```
 M0 Ready ─▶ M1 Engine ─▶ M2 Service ─▶ M3 First signature ─▶ M4 Team beta ─▶ M5 1.0 GA ─┬─▶ M6 Regulated
 Phase D,0    Phase 1      Phase 2       slices 1, 2, 5, 7     slices 3, 4, 6,   slices 10–12,  │   slices 16–19
                                                               8, 9              15, 20 + gates └─▶ M7 Ecosystem
                                                                                                    slices 13, 14,
                                                                                                    21–29
                    └── W-1: Phase 2 may start once stages 1A and 1B close ──┘
```

| Milestone | Who can do what afterwards | Contains | Exit evidence | Size |
| --- | --- | --- | --- | --- |
| **M0 — Ready to build** | Contributors can land changes that CI checks on three platforms | Phase D closed; Phase 0 closed; ADR-001 to ADR-009 Accepted; `SPK-01`, `SPK-02` reported | Phase 0 exit gate; CI green; validators reject the tampered fixture | M |
| **M1 — Engine alpha** | A developer runs `openseal admit / fill / seal / verify` on any PDF, headless, and gets a PAdES seal that pyHanko and EU DSS accept | Phase 1 (stages 1A–1J) | Phase 1 exit gate: corpus sealed and verified by rungs 1–3; tamper and shadow-attack fixtures detected; native = WASM verdicts | XL |
| **M2 — Service alpha** | An integrator sends a two-signer envelope through the API on a single-node Compose install and downloads a sealed PDF | Phase 2 (stages 2A–2F) | Phase 2 exit gate: end-to-end API test on Compose in CI; crash and tenant-isolation tests | L |
| **M3 — First signature (private preview)** | A sender uploads, places fields and sends from the web app; signers on phones authenticate, consent and sign; everyone gets a sealed PDF and certificate; anyone verifies it offline | Slices 1 send and sign, 2 routing, 5 authentication and consent, 7 verify | Slice end points; browser run on desktop and mobile viewports; axe checks clean; demo recorded | L |
| **M4 — Team beta** | A team replaces DocuSign Standard or SignNow Business for day-to-day work, and a developer embeds signing in their app | Slices 3 templates, 4 every field, 6 manage and correct, 8 API and webhooks, 9 embedding | Slice end points; [96](96-FEATURE-FIT-GAP.md) rows for those slices `Works`; API reference published; TypeScript and Python SDKs released as beta | XL |
| **M5 — 1.0 GA** | An organization runs OpenSeal in production in place of DocuSign Business Pro: SSO, branding, bulk send, signing links, retention, HA operations | Slices 10 admin and SSO, 11 bulk and links, 12 brand and language, 15 data controls, 20 operations; release gates `PV-01`, `SEC-REV-01`, `SEC-ASVS-01`, `A11Y-01`, `LEG-01`, `LEG-02`, `UXR-01` | All listed slices closed; all release gates passed ([15](15-CI-AND-RELEASE-GATES.md)); upgrade test; signed images and SBOM | XL |
| **M6 — Regulated** | Life sciences, finance and EU public sector adopt it: per-signer seals, archives, AES/QES through QTSPs, Part 11 | Slices 16 per-signer seals, 17 archive, 18 advanced and qualified, 19 Part 11 | Slice end points; EU DSS reports B-LTA and QES through a test QTSP; Part 11 validation pack | L |
| **M7 — Ecosystem** | OpenSeal is everywhere agreements happen: payments, kiosks, desktop, mobile apps, AI agents, the CasualOffice suite, integrations, forms, document generation | Slices 13, 14, 21–30 (25 subject to counsel, `DEC-10`) | Each slice closes on its own; M7 is reached when the owner says the set is complete | XL |
| **M8 — Agreement platform** | Notarization and the add-on modules: lifecycle management, rooms, workflow builder, agreement intelligence | Slices 31–35 | Each slice closes on its own; M8 is reached when the owner says the set is complete | XL 
**Critical path:** Phase 0 → stages 1A, 1B → (W-1) Phase 2 → slice 1 → slices 2, 5, 7 → M3. Stages 1C–1J and the
independent slices run beside it in parallel sessions ([CLAUDE.md](../CLAUDE.md) §Working in parallel).

**Parallel lanes after M2**, chosen so no two lanes share an invariant:

| Lane | Owns | Slices in order |
| --- | --- | --- |
| A — Ceremony and UX | `webapp/` sign, prepare, app | 1 → 2 → 5 → 4 → 3 → 6 → 12 → 14 → 23 |
| B — Evidence | `-seal`, `-verify`, `-audit`, `verify.html` | 7 → 16 → 17 → 18 → 19 |
| C — Platform | server, worker, admin, API | 8 → 9 → 10 → 11 → 15 → 20 → 29 |
| D — Ecosystem | `sdk/`, `desktop/`, mobile, MCP, integrations | 21 → 30 → 22 → 24 → 27 → 28 → 13 → 26 → 25 |

## Where things stand

Docs are true as of 2026-11-19 (`main` at `584634d`, the PR #30 merge; CI run 44419251440 green on every job). **M3,
"first signature", is reached:** slices 1, 2, 5 and 7 closed on 2026-11-19 under owner instruction 59 on run 44419251440,
every gate item with its evidence in [73](73-M3-SLICE-EVIDENCE.md). **v0.1.0 is published** (2026-11-20) (§Release 1, v0.1.0;
instruction 61). Since 2026-11-13 feature expansion was paused for the hardening release and M3 (instructions 48, 51,
54; §Freeze, §Hardening release); the paused rows are `Paused` in docs/14 and resume in order (§Freeze). Proven by CI on `main` (runs 44001061169 and 44018844840): `HRD-01`, `HRD-02`, `HRD-10`,
`ASVS-08`, `ASVS-13`, `ASVS-14`, `ASVS-31`, keyd seal tokens (`KEYD-02`), slice 5 on the real stack with its demo
(`RAUTH-02`) and slice 2's routing spec there; the slice 1, 2, 5 and 7 demos of run 44023485128 are watched and linked from [65](65-RUNNING-IT.md) §Demos (2026-11-18). Also proven on `main`: Acrobat Reader reading
B-LTA seals valid offline (`HRD-14`, `HRD-03`; acrobat run 44024248440) and slice 7 with public anchoring (`VS-07`,
`FG-158`; CI run 44023485128).

Before 2026-11-13: phases D, 0, 1 and 2 are closed; **v0.0.1**, the first pre-release,
is published (`REL-01`). Engine, server, API, worker, keyd, Compose deployment and web app exist. Merged since v0.0.1,
most rows waiting only for their Compose run in CI: the redesigned web app (`UX-02` to `UX-08`, `WEB-17`), Inbox,
folders and server filters (`UXW-01` to `UXW-03`), bulk send (`UXW-04`), template sharing (`UXW-06`), groups and
permission profiles (`UXW-07`), the admin audit log and webhooks screens (`UXW-09`, `UXW-10`), organizations and
workspaces (`ORG-02` to `ORG-06`), the platform console with plans, metering and quotas, keys and timestamp
authorities (`CON-03` to `CON-07`, `CON-16`, `CON-17`, `PLAN-02` to `PLAN-04`), the model service (`ML-02`, `ML-05`,
`ML-07`, `ML-08`, `WEB-19`), staff two-factor and breached-password checks (`ASVS-01`, `ASVS-02`, `ASVS-04`).

| Phase or work | State | Note |
| --- | --- | --- |
| D Design | **Closed** 2026-11-11 | Owner, instruction 13 |
| 0 Foundation | **Closed** 2026-11-11 | Owner, instruction 12; `W-2` retired |
| 1 PDF and evidence core | **Closed** 2026-11-11 | Owner, instruction 18, after clean fuzz run 42907980149; stages `T-1A`–`T-1J` done, leftovers in their own rows |
| 2 Envelope engine and server | **Closed** 2026-11-12 | Owner, instruction 23; `compose-e2e`, `P2-CRASH`, `P2-THREATS` |
| Milestones | M0, M1, M2, M3 **reached** | M0–M2: owner, instruction 38; M3 "first signature": 2026-11-19, instruction 59, its slices closed on `main` run 44419251440 (`MS-0`–`MS-3` in [14](14-EXECUTION-TRACKER.md)). Next: M4 team beta |
| Release 1 / v0.0.1 | **Published** 2026-11-12 | Tagged at `4780d84` after GitHub CI run 43123420112 was green on all 14 jobs; images with SBOM and provenance; pre-release on GitHub. Left in `REL-01`: GHCR packages public, the manual walkthrough in [65](65-RUNNING-IT.md); the boxes below are ticked by `REL-01` from evidence |
| v0.1.0 | **Published** 2026-11-20 (tag at `f667422`, release run 44615842313) | The second pre-release: the hardening work and M3 since v0.0.1, the first through the signed release workflow (cosign, SBOMs, provenance, signed checksums; `REL-04`). Its tag is pushed on the green `main` commit after this merges (owner instruction 61, §v0.1.0 below); still not for production agreements |
| Slices 3, 4 | **Closed** 2026-11-20 | Owner, instructions 66 and 68, on `main` run 44610734814 (f667422) green on every job; evidence [74](74-SLICE-3-EVIDENCE.md), [75](75-SLICE-4-EVIDENCE.md) |
| Slices 1, 2, 5, 7 | **Closed** 2026-11-19 | Owner, instruction 59 ("complete M3"), on `main` run 44419251440 green on every job; the readings of instruction 58 applied (slice 7: B-LT as the account default, anchoring served and shown; `VS-07D`, `VS-07E` after M3). Evidence per gate item: [73](73-M3-SLICE-EVIDENCE.md) |
| Other slices | Not closed | Release 1's part of slice 3 is built and in browser runs; slices 3, 4, 6, 8 and 9 lead to M4. [96](96-FEATURE-FIT-GAP.md) counts 50 of 168 rows working, 27 in part and 15 with their engine built |
| Slice 3 templates (`VS-03`) | In progress 2026-11-19 | Every outcome element built and tested ([74](74-SLICE-3-EVIDENCE.md)): roles, save as template, use template and sharing on `main` (run 44419251440); composite templates (`VS-03A`, `POST /envelopes/from-templates`) and template folders (`TSH-03`, migration 0047) built on a branch with `templates.spec.mjs` (real stack and mock), axe and the i18n check. End point not met: merged, a green `main` run, the `slice-3-demo` watched, owner closure. 2026-11-20: `main` run 44605190804 on `6bd9646` finished red in `e2e (2)` and `e2e (6)`, the same stale test (`prepare-layout.spec.mjs:185`, the palette's field-kind count 16 → 29, chromium and webkit), fixed in PR #36; every other job green. Not closed on it: the main session closes it on the first green `main` run after #36 merges |
| Slice 4 every field (`VS-04`) | In progress 2026-11-19 | Every outcome element built and tested on a branch ([75](75-SLICE-4-EVIDENCE.md)): the full field set and validation (`VS-04A`), conditional fields, groups, formulas and linked fields (`VS-04C`: the signing view carries the server's own rules), shared fields (`VS-04D`), anchors and text tags through the API and Detect fields (`VS-04E`), AcroForm fields offered and placed in the editor (`VS-04F`); `fields.spec.mjs`, axe and the i18n check (`VS-04B`). End point not met: a green `main` run, the `slice-4-demo` watched. 2026-11-20: `main` run 44605190804 on `6bd9646` finished red in `e2e (2)` and `e2e (6)`, the same stale test (`prepare-layout.spec.mjs:185`, the palette's field-kind count 16 → 29, chromium and webkit), fixed in PR #36; every other job green. Not closed on it: the main session closes it on the first green `main` run after #36 merges |
| Slice 2 routing (`VS-02`) | **Closed** 2026-11-19 (row above); as of 2026-11-13: | Outcome met by tests: sequential (`E2E-01`); parallel and mixed with a copy, an agent, an approver and a viewer acting through the ceremony (`casual-sign-server` tests/routing.rs); the agent, offered by the editor, names later recipients by `POST /s/{token}/recipients`; decline (worker tests/flow.rs); void; reminders (worker tests/crash.rs); expiry and its warning through the worker (worker tests/expiry.rs). The signing page's approver, viewer and agent steps and the in-person host are in a browser run (`webapp/e2e/recipient-types.spec.mjs`, `RTE-01`), and the receipt says what each type did (`RTE-02`). End point not met: CI green on main after the merge, including the in-person Compose spec (`UXW-18`); the demo (`RTE-04`); owner closure |
| UI pass (`UX-01`) | **Done** 2026-11-13 | All seven packages `UX-02` to `UX-08` merged: design system and a distinct destructive colour, send editor (click-to-place, every field kind, recipient types), signing page, Home/Agreements/envelope, Templates/Reports/Admin rail, app shell with notifications and profile. Signer view names the sender and serves the disclosure (`UXW-34`). Follow-ups and missing workflows are `UXW-*` and `UX-09` onward |
| Organizations; console and plans **paused** | ADR-028 Accepted ([23](23-ORGANIZATIONS-WORKSPACES-AND-CONSOLE.md)) | Done: organizations (`ORG-02`), organization routes (`ORG-03`), switching (`ORG-04`), admin audit logs (`ORG-05`); console operators with TOTP (`CON-03`), the Keys page (`CON-06`), timestamp authorities with two-person changes (`CON-07`), operator actions copied to organization logs (`CON-16`); plans, metering and quota enforcement (`PLAN-02` to `PLAN-04`). In progress: organization admin screens (`ORG-06`), the console as a Compose service (`CON-02`), approvals and suspend or resume (`CON-04`), health (`CON-05`), the console UI (`CON-17`). Done since: workspace actions (`ORG-07`), organization policy with locked and tighten-only keys (`ORG-08`), envelope transfer within a workspace (`ORG-09`). Since 2026-11-19 every console (`CON-*`) and plans (`PLAN-*`) row not Done is `Paused` under instruction 51 (`FRZ-01`) and resumes in order after it; organizations (`ORG-*`) are not paused |
| ML **paused** | ADR-029 Accepted ([33](33-ML-MODELS.md)) | Merged: `casual-sign-modeld` with bundle tooling (`ML-09`), OCR (`ML-02`), page hashes and embeddings for template matching (`ML-05`), GLiNER spans for extraction and personal data with fp16 parity (`ML-07`, `ML-08`), `casual-sign-pii` recognisers, value normalisation, the worker's analysis jobs and the server's analysis routes (`WEB-19`). Left: the worker on modeld's network in Compose (`compose --profile ml up`, `ML-09`) and the editor's suggestions on the real stack (`WEB-18`). Every feature off by default; nothing a model says enters the evidence. Since 2026-11-19 every `ML-*` row not Done and `WEB-19` are `Paused` under instruction 51 (`FRZ-01`) |
| Security | `SEC-ID-01`, `SEC-CER-01`, `ASVS-02`, `ASVS-04`, `ASVS-08`, `ASVS-11`, `ASVS-13`, `ASVS-14`, `ASVS-31` **Done**; `ASVS-01`, `SEC-ASVS-01` in progress | Shared-account changes refused across workspaces (migration 0013); signer content and every ceremony write require the recipient's authentication first; staff TOTP with recovery codes, required of administrators by default (`ASVS-01`, `ASVS-31`; WebAuthn and lost-factor recovery left); breached passwords refused; security event log, anomaly alerting, malware scanning, and a backup restore drill green on CI; the ASVS 4.0.3 self-assessment ([67](67-ASVS-SELF-ASSESSMENT.md), 2026-11-17: 210 Met, 32 Partly, 12 Not met) with 43 finding rows in docs/14, 14 closed. Not a certification |

### Waivers

| ID | Criterion not met | Risk | Accepted | If it fails |
| --- | --- | --- | --- | --- |
| W-2 (retired 2026-11-11: Phase 0 closed) | Phase 1 opens before Phase 0 closes: CI cannot run on GitHub while the repository is private (instruction 7), so "CI green on three platforms" is unmet | Platform-specific failures (Linux, Windows) found late; the local run is macOS only, with Linux only for the validators in Docker | Owner's "proceed", 2026-11-10, with instruction 7 | Phase 0 still closes only on a green GitHub run, at the latest when the repository goes public for the pre-release alpha (M3); failures found then are fixed first |
| W-1 | Phase 2 opens before Phase 1 closes, once stages 1A and 1B are closed | The model or API may need a change when sealing lands | Owner, 2026-11-11 (instruction 12, `DEC-13`); Phase 2 open | Phase 2 work adapts; Phase 2 cannot close before Phase 1 |

## Execution plan (from 2026-11-19; owner instruction 62, `PLN-01`)

**Binding.** Work proceeds one slice at a time, in this order, end to end to closure: server, API, screens,
real-stack browser test, CI green on `main`, demo, docs/96 rows `Works`, closed by the owner. Nothing outside the
current slice starts unless the owner asks for it. Work already started is finished, never abandoned.
`tools/check-plan.py` (in `tools/check-repo.py`) fails if a docs/14 row is `In progress` and is not listed on the
Current, Finishing or Paused line below. A slice moves to Current only when the one before it is closed; its new
rows go on the Current line in the same commit.

- Current: `VS-06` `VS-06A` `VS-06B` `VS-06C` `VS-06D` `VS-06E` `VS-06E1` `VS-06E2` `VS-06F` `UXW-02` `UXW-19` `UXW-20` `UXW-25` `UXW-42` `UXW-43` `ORG-18` `ORG-41` `WEB-07`
- Finishing (started before 2026-11-19; each closes or goes back to Open by 2026-11-21; slice 8's rows await CI on PR #37 and the owner's sign-off): `VS-08` `VS-08A` `VS-08B` `VS-08C` `VS-08D` `VS-08E` `VS-08F` `UXW-10` `UXW-31` `UXW-32` `UXW-33` `VS-03C` `TSH-04` `TSH-05` `TSH-06` `UXW-05` `UXW-15` `UXW-49` `WEB-23` `UX-08C` `UX-08F` `UX-11A` `TSH-02` `VS-01` `VS-02` `VS-05` `VS-07` `VS-07B` `VS-07C` `S1-10` `I18N-01` `E2E-04` `E2E-05` `E2E-10` `E2E-11` `E2E-12` `E2E-13` `WEB-12` `FRZ-01` `REL-01` `LEG-01` `SITE-08` `SITE-09` `HRD-06` `HRD-11` `HRD-12` `DEP-07` `ASVS-01` `ASVS-03` `ASVS-06` `ASVS-07` `ASVS-10` `ASVS-13A` `ASVS-13B` `ASVS-19` `ASVS-22` `ASVS-28` `ASVS-29` `ASVS-16` `ASVS-18` `CON-13` `ASVS-32` `SITE-12`
- Paused (owner instruction 51, until M4): `ML-02` `ML-05` `ML-07` `ML-08` `ML-09` `ML-21` `CON-01` `CON-02` `CON-04` `CON-05` `CON-15` `CON-17` `PLAN-01` `WEB-19`

| Order | Slice | Users it unlocks | Target closed | Includes (returned to Open today, picked up here) |
| --- | --- | --- | --- | --- |
| 0 | M3: 1 send and sign, 2 routing, 5 authentication, 7 verify | Small teams, freelancers, self-hosters | 2026-11-19 (green `main` run) | — |
| 1 | **3 Templates** (finishing: awaits sign-off) | Teams sending the same documents: sales, HR | 2026-11-21 | — |
| 2 | **4 Every field** (finishing: closes on green `main`, instruction 68) | Complex forms: applications, insurance, loans | 2026-11-24 | — |
| 3 | **8 API and webhooks** (finishing: awaits CI on PR #37 and sign-off; [76](76-SLICE-8-EVIDENCE.md)) | Developers integrating signing | 2026-11-27 | `UXW-10` `UXW-31` `UXW-32` `UXW-33` |
| 4 | **6 Manage and correct** (current, 2026-11-20; [77](77-SLICE-6-EVIDENCE.md)) | Daily senders: folders, search, correct, resend | 2026-12-01 | `UXW-02` `UXW-20` `UXW-42` `WEB-07` |
| 5 | 9 Embedding | Developers embedding signing in their app → **M4** | 2026-12-03 | — |
| 5r | Remote signing providers (from slice 18, brought forward; owner instruction 75) | Customers who need a CSC provider (DigiCert Document Trust Manager, A-Trust) or India eSign (Aadhaar OTP or eKYC through a licensed ESP) | after M4 | `RSP-01` `RSP-02` |
| 5a | Production PKI validation (owner instruction 74) | Operators going live: seal chain, OCSP and CRL, TSA, HSM or KMS key checked before go-live | after M4 | `PKI-VAL-01` |
| 5b | Accessibility and mobile checks (owner instruction 74) | Keyboard-only and screen-reader users, phone signers | after M4 | `UX-TEST-01` |
| 6 | 10 Organization admin and SSO | Mid-size and large companies | 2026-12-08 | `ORG-01` `ORG-06` `UXW-09` `UXW-37` `UXW-38` `UXW-39` |
| 7 | 11 Bulk send and signing links | High-volume senders | 2026-12-11 | — |
| 8 | 12 Brand and language | Branded and non-English use | 2026-12-15 | `UXW-12` |
| 9 | 15 Enterprise data controls | Retention, legal hold, BYOK | 2026-12-18 | — |
| 10 | 20 Operations → M5 slices done | Production operators | 2026-12-22 | `F-007` `SEAL-14` |

Then the M5 release gates (`PV-01`, `SEC-REV-01`, `SEC-ASVS-01`, `A11Y-01`, `LEG-02`, `UXR-01`), then M6 slices in
the table's order. Dates are targets; a slip is reported in the next status update with its cause, never hidden.
`WEB-17` (the redesign umbrella), `SITE-01`, `SITE-03`, `SITE-06` and `UXW-37`–`UXW-39` went back to Open on
2026-11-19: their remaining work belongs to the slices above. ML, the console and plans resume after M4.

## Freeze until M3 — engine first (owner instruction 51, `FRZ-01`)

OpenSeal leads with its Apache-2.0 signing and verification engine you embed (Rust engine, WASM verifier, API and
SDK); the web app is the reference product built on it (`POS-01`). Until M3 "first signature" closes and the core flow
runs reliably on the real stack in CI, only these move: the core flow (send → sign → seal → verify), the hardening
release below, the verifier, and the API and SDK. **Paused** (sequenced after M3, nothing removed): ML (`ML-*`,
`WEB-19`), the platform console (`CON-*`), plans and metering (`PLAN-*`). Right after M3: the verifier as a standalone
crate and npm/WASM package (`VER-01`).

**M3 closed on 2026-11-19** (instruction 59), so the freeze's condition is met (`FRZ-01` Done). The paused rows are
marked `Paused` in docs/14 (docs/05) and stay so until each resumes, in order: the dependency exceptions and release
v0.1.0 first (instructions 58, 61), then `VER-01`, then the paused groups.

## Hardening release — one production-grade deployment first (owner instruction 48)

Feature work pauses (sequenced after this, nothing dropped) until one deployment runs send → authenticate → sign →
seal → verify → archive repeatably, survives failures, and is checked from outside. Exit gate, each item proven by
running:

- [x] `HRD-01` The whole path runs on the hardened Compose profile with failure recovery: worker, keyd, database and
      object store killed mid-flow, every envelope still completes or fails safe, nothing sealed twice, audit chain intact.
- [x] `HRD-02` Sealing validated against a real-style CA hierarchy (offline root, issuing CA, OCSP and CRL served) and a
      production RFC 3161 TSA; pyHanko and EU DSS agree; an Acrobat interoperability packet is produced.
- [x] `HRD-03` Acrobat Reader opens the packet's PDFs as valid, signed and unchanged (owner or a named tester; results
      recorded with screenshots). 2026-11-17: every packet file as the checklist expects in the `acrobat` workflow on
      the sprint branch (run 44011154004); ticked when the same workflow is green on `main`.
- [x] `HRD-04` Load and chaos test with published numbers (envelopes per minute, p95 seal time, recovery time).
      Driver and workflow built (`tools/load`, workflow `load`; [65](65-RUNNING-IT.md) §Load and recovery numbers);
      ticked when the first green run on `main` has its numbers published there.
- [ ] `HRD-05` External penetration test commissioned and its findings closed or tracked (owner: vendor and budget).
- [ ] `HRD-06` Production deployment hardening: non-root, read-only file systems, resource limits, TLS everywhere,
      secrets from files or a secret store, documented and tested secret and key rotation.
- [ ] Every ASVS "Not met" in [67](67-ASVS-SELF-ASSESSMENT.md) is Met or has an owner-accepted exception.

## Release 1 — the common case first (owner instruction 19)

Release 1 covers the common 60–70% of use; everything else follows as slices, in order, after it. Nothing is removed.

- **In:** upload PDF (and Word through the converter); place signature, initials, date, text and checkbox fields;
  sequential and parallel signers and carbon copies; email invitations and reminders; decline and void; email link,
  access code and email one-time code; signing on phone and desktop; sealed PDF with certificate of completion and
  audit trail, downloadable and verifiable; simple templates; the sender's dashboard; the API and webhooks; single-node
  Docker deployment (Phase 2F).
- **After Release 1, in slice order:** SSO (OIDC, SAML), WebAuthn, SMS and phone authentication, bulk send and signing
  links, advanced fields and formulas in the editor, XFA editing, payments, brands and languages, archive and B-LTA
  renewal, qualified signatures, notary, desktop and mobile apps, and the rest of the slice table.
- **Work order:** finish Phase 2 to what Release 1 needs (integrate 2C and 2D, 2F Compose, the end-to-end test), then
  slice 1's web app for senders and signers, then the Release 1 gate.

### Release 1 ships as v0.0.1 (owner instruction 23)

v0.0.1 is the first tagged pre-release: usable end to end on a single machine, not yet for production agreements. It
is cut when every box below is ticked, from evidence, not from intent (`REL-01`).

- **Gate**
  - [x] Phase 2 exit items met and signed off: end-to-end on the Compose stack green on GitHub (`compose-e2e`); crash
    tests on the stack (`P2-CRASH`); every SEC-A, SEC-T, SEC-W threat with a test seen red (`P2-THREATS`).
  - [x] GitHub CI fully green on the release commit, every job, no job skipped or cancelled.
  - [ ] Release 1 scope above works on the Compose stack, checked by the Playwright suite against the real server and
    one manual walkthrough recorded in `docs/65` (send, sign on desktop and phone, decline, correct, templates, verify).
  - [ ] Independent validators: the release's sealed outputs accepted by pyHanko and EU DSS.
  - [ ] No open P0 row in docs/14.
- **Artefacts**
  - [ ] Version `0.0.1` in the workspace `Cargo.toml` and `webapp/` (shown in the app footer and `/api/v1` health).
  - [ ] Container images built by a release workflow from the tag, pinned base images, published to GitHub Container
    Registry as `ghcr.io/casualoffice/openseal-{server,worker,keyd}:0.0.1`, with SBOM and provenance attestations.
  - [ ] `docker-compose.yml` able to use the published images (no local build needed).
  - [x] Git tag `v0.0.1` (annotated) and a GitHub pre-release with notes from `CHANGELOG.md`: what works, what does not,
    the development-only security posture (generated CA, SoftHSM, dev TSA), and how to report security issues.
  - [x] Site: Download page and roadmap updated for v0.0.1.
- **Not in v0.0.1** (stays on the roadmap, after it): SSO, SAML and WebAuthn, SMS authentication, bulk send, payments,
  B-LTA renewal jobs, production deployment (Helm, HA), and everything in the slices after Release 1.

### v0.1.0 (owner instruction 61)

The second pre-release, prepared 2026-11-19: the hardening work and M3 since v0.0.1, summarised in `CHANGELOG.md`
§0.1.0, from which the release workflow takes its notes. Version `0.1.0` is in every workspace crate's `Cargo.toml`
(shown by `openseal --version`; the app footer and `/api/v1` health do not show it yet, as for v0.0.1 above), `Cargo.lock`, `webapp/package.json` and `console-ui/package.json`. It is
the first tag through the signed release workflow (docs/65 §Releases): cosign signatures on every image, SPDX and
CycloneDX SBOMs, build provenance and a signed `SHA256SUMS`, which v0.0.1 lacks (`REL-04`). The main session pushes the
tag on the green `main` commit after this merges, verifies the published signatures and SBOMs, and reports; the owner
then makes the three GHCR packages public. Still not for production agreements (the development CA, software HSM and
timestamp authority), and no claim of legal validity, compliance or certification (docs/09).

## Phase D — Design

- **Gives:** an agreed design, so later phases need no do-over.
- **Opens:** project start (2026-11-10).
- **In:** PRD, HLD, research studies, data model, lifecycle, PDF pipeline, sealing, audit, API, threat model, ADRs,
  enterprise requirements, process documents, tracker, fit-gap.
- **Out:** product code.
- **Closes when:**
  - [x] PRD, HLD and pillar documents drafted ([00](00-README.md)).
  - [x] DocuSign, SignNow and open-source studies recorded ([48](48-DOCUSIGN-STUDY.md), [49](49-SIGNNOW-STUDY.md), [52](52-COMPETITOR-STUDY.md)).
  - [x] Every ADR needed by Phases 0–2 is Accepted or has a named spike deciding it ([08](08-ADR-REGISTER.md)). Evidence: ADR-001 to ADR-024 Accepted (owner, 2026-11-11, instruction 12).
  - [x] `DEC-01` to `DEC-07` answered, or marked not blocking with the phase that needs them. Evidence: all answered by the owner (instructions 4 and 12).
  - [x] An independent doc audit's P0 and P1 findings are fixed (`DOC-002`). Evidence: `DOC-002` Done (26 findings fixed).
  - [x] Owner sign-off. **Phase D closed by the owner, 2026-11-11** (instruction 13).

## Phase 0 — Foundation

- **Gives:** a repository where a broken change cannot land unnoticed.
- **Opens:** Phase D's architecture ADRs (ADR-001 to ADR-008) Accepted.
- **In:** `git init` and remote; Cargo workspace with empty crates that have a first consumer planned; `deny.toml`,
  toolchain pin, lints copied from the sisters; CI on Linux, macOS, Windows; `tools/check-repo.py` (tracker ids,
  doc references, crate DAG) copied and adapted; PDF fixture corpus with provenance (generated, producer-written,
  hostile); fuzz workspace; the independent validators (pyHanko, EU DSS) in a CI container. (`casual-sign-secrets` is copied
  in Phase 2, when the server is its first consumer: no crate without a consumer.)
- **Out:** product behaviour.
- **Closes when:**
  - [x] CI green on three platforms; a seeded violation seen failing each job on GitHub's runners. Evidence: green on all 8 jobs at `fd5e8f3` (run 42825291522); every job red on its seeded violation in draft PR #1 (run 42872019361), `F-003`.
  - [x] Fixture corpus: ≥ 200 PDFs from ≥ 10 producers (Word, LibreOffice, Acrobat, Chrome print, macOS Quartz, Ghostscript output used only as a file, scanners, InDesign, LaTeX, Google Docs), each with provenance and licence; ≥ 50 hostile fixtures, one per limit in [21](21-PARSER-LIMITS.md). Evidence: `F-004` (422 PDFs, 40 producer families, licences recorded), `F-005` (50 hostile fixtures, manifest-checked).
  - [x] pyHanko and EU DSS run in CI over a known-good signed PDF and a known-tampered one, and disagree correctly. Evidence: GitHub run 42825291522, job `validators`, at `fd5e8f3` (2026-11-10); `F-006`.
  - [x] `SPK-01` (PDF reader: own versus `lopdf`) and `SPK-02` (crypto stack in WASM) reported; ADR-005 and ADR-006 settled. Evidence: [64](64-SPK-01-PDF-READER.md), [66](66-SPK-02-CRYPTO-STACK.md).
  - [x] Owner sign-off. **Phase 0 closed by the owner, 2026-11-11** (instruction 12).

## Phase 1 — PDF and evidence core

- **Gives:** a headless engine that admits any PDF safely, places and flattens field values, seals at PAdES B-T to
  B-LTA, verifies any signed PDF, and builds an audit chain and certificate of completion. **No server, no UI.**
- **Opens:** Phase 0 closed.
- **In / stages:**

| Stage | Scope | Crates | Opens after |
| --- | --- | --- | --- |
| **1A** | Bounded reader: lexer, objects, xref tables and streams, object streams, revisions, recovery, encryption with password, classification, admission report | `-pdf` | — |
| **1B** | Incremental writer; normalizer (strip actives, rewrite fresh); prefix invariant | `-pdf` | 1A |
| **1C** | Geometry (rotation, crop, UserUnit), text extraction with positions, anchors, text tags, AcroForm conversion | `-fields` | 1A |
| **1D** | Field model: validation, conditions, groups, formulas; identical results native and WASM | `-model`, `-fields`, `-wasm` | — |
| **1E** | Flattening: fonts embedded and subset, text layout in fields, signatures as paths and images, checkmarks | `-flatten` | 1B, 1C |
| **1F** | Crypto structures and `KeyProvider`; CMS SignedData; RFC 3161 request and response; OCSP and CRL parsing | `-crypto` | — |
| **1G** | Sealing B-B, B-T, B-LT (DSS, VRI), B-LTA (DocTimeStamp); placeholder sizing | `-seal` | 1B, 1F |
| **1H** | Verifier: signatures, revisions classification, DocMDP, chains, revocation, timestamps; ETSI-style verdicts | `-verify` | 1A, 1F |
| **1I** | Audit events, JCS canonical form, hash chain, chain verification; certificate of completion PDF; associated-file embedding | `-audit`, `-certificate` | 1B, 1E |
| **1J** | `casual-sign-sdk` facade and `openseal` CLI: `admit`, `fill`, `seal`, `verify`, `audit verify` | `-sdk`, `tools/` | 1A–1I |

- **Out:** persistence, network, email, UI (except the CLI).
- **Per-stage gate:** every limit tested with a hostile fixture and in [21](21-PARSER-LIMITS.md); a fuzz target per
  entry point, run 1 hour in CI without a finding; acceptance tests seen red; docs/96 rows updated.
- **Closes when:**
  - [x] Every corpus PDF is admitted or refused with a coded reason; no panic, hang or unbounded allocation under fuzzing (24 h cumulative per target). Evidence: corpus gate (417 admitted, 5 refused with codes); fuzz run 42907980149 (2026-11-11): 6 targets × 2 jobs × 4 workers × 3 h, no finding, after the `admit` finding of run 42890029431 was fixed (`FUZZ-01`).
  - [x] For every admitted corpus PDF, fill + flatten + seal (B-T) + verify passes rungs 1–3 of the verification ladder; `sealed.starts_with(delivered)` holds. Evidence: `fixtures/corpus/pipeline/` (2026-11-11, main session, EU DSS image pinned by digest): **417 of 417 admitted files pass** ours, pyHanko and EU DSS with the prefix holding, 0 excluded, 0 failed (`P1-GATE-01`). The 32 files certified DocMDP P1 pass as new documents printed from the signed ones (`NORM-02`); the owner's earlier exclusion rule (instruction 11) is no longer needed.
  - [x] B-LT and B-LTA outputs are detected at their level by EU DSS. Evidence: `fixtures/sealed`, `tools/verify-sealed.py fixtures/sealed --dss`, EU DSS 6.5.1 reports PAdES-BASELINE-LT and -LTA (stage 1G, re-run by the main session).
  - [x] Tampering fixtures (byte flip in each revision, appended unsigned revision, shadow attacks: hide, replace, hide-and-replace; incremental saving attack; signature wrapping) are all detected by our verifier and agree with pyHanko and EU DSS. Evidence: `fixtures/signed` (35 rows), `gen.py --check --dss openseal-eu-dss` rerun by the main session 2026-11-11 (`VER-03`).
  - [x] The audit chain verifier detects deletion, insertion, reordering and edit of any event in generated chains. Evidence: `casual-sign-audit` tamper tests and the every-mutation property (1,024 cases); the prev-link check seen red by the main session (stage 1I).
  - [x] The WASM build of `-fields` and `-verify` gives byte-identical verdicts to native over the corpus. Evidence: `tools/wasm-parity.sh`, 2,112 jobs identical, rerun by the main session 2026-11-11; a CI job (`WASM-01`).
  - [x] Owner sign-off. **Phase 1 closed, 2026-11-11** (instruction 18: signed off on condition of a clean fuzz run; run 42907980149 was clean).

## Phase 2 — Envelope engine and server

- **Gives:** an API-only e-signature service: create, send, sign (through API-driven test clients), complete, seal and
  download, with tenancy, persistence, email and webhooks. No production UI.
- **Opens:** Phase 1 stages 1A and 1B closed, under `W-1`, or Phase 1 closed.

| Stage | Scope |
| --- | --- |
| **2A** | `-model` and `-workflow`: envelope and recipient state machines, routing, commands, effects; property tests over random command sequences |
| **2B** | Persistence: PostgreSQL schema and migrations, RLS, tenancy-scoped repository, audit table immutability, blob store (fs, S3) |
| **2C** | `casual-sign-server`: axum, OpenAPI document, staff auth (OIDC, local + WebAuthn), API keys, OAuth client credentials, rate limits, problem details |
| **2D** | `casual-sign-worker`: Postgres job queue, effects (email via SMTP, reminders, expiry, seal jobs, webhooks), idempotency, retries |
| **2E** | `casual-sign-keyd`: PKCS#11 (SoftHSM in CI), file key in dev only, mTLS, its own log |
| **2F** | Single-node deployment: Docker images, Compose with Postgres, MinIO, Mailpit; [65](65-RUNNING-IT.md) |

- **Closes when:**
  - [x] An API-driven end-to-end test sends a two-signer sequential envelope, signs through the ceremony endpoints, and downloads a sealed PDF that passes rungs 1–3, on the Compose deployment in CI. Evidence: GitHub CI `compose-e2e` green (run 43112163812, 2026-11-12): two signers through emailed links on the Compose stack, sealed PDF and certificate accepted by pyHanko (`E2E-01`).
  - [x] Crash tests: killing the server or worker at every effect boundary loses no audit event and never yields `completed` without a verified seal. (`P2-CRASH`: in-process `server/casual-sign-worker/tests/crash.rs` and real-process `tests/process_crash.rs`, SIGKILL at each boundary, docs/24 §As built.)
  - [x] Tenant isolation tests: every endpoint refuses cross-tenant ids (generated from the OpenAPI document), with RLS disabled and enabled. Evidence: `casual-sign-server` isolation tests generated from `api/openapi.yaml` over every id-bearing operation, RLS on and off, green in GitHub CI `server-db` (run 43112163812); store-level guards seen red (`T-2B`, `T-2C`, `P2-THREATS`).
  - [x] Threats `SEC-A*`, `SEC-T*`, `SEC-W*` in [07](07-SECURITY-THREAT-MODEL.md) have tests seen red.
    (2026-11-12, `P2-THREATS`: every `SEC-A01`–`A10` and `SEC-W01`–`W02` row has a test
    seen red, A02 and A07 last; docs/07 has no `SEC-T` rows. Out of scope, with the slice
    each row names: SMS and voice codes (slice 5), per-account `frame-ancestors` (slice 9),
    and the other parts the rows mark "Not built".)
  - [x] Owner sign-off. **Phase 2 closed, 2026-11-12** (instruction 23: signed off once its exit items were met).

## After Phase 2 — vertical slices

Each slice has an **outcome** (what a user can do), an **end point** (merged, CI green including a browser run, docs/96
rows updated, demo recorded) and a box once throughput is calibrated. Accessibility (WCAG 2.2 AA) and i18n string
extraction are part of every UI slice's end point, not a later slice.

| # | Slice | Outcome | Copies from the sisters |
| --- | --- | --- | --- |
| 1 | **Send and sign** | A sender uploads a PDF, adds one signer, places signature, date and text fields (document-first editor), sends; the signer signs on a phone; both get the sealed PDF and certificate | Web app skeleton, command registry, tokens, icons, site (OpenCalc/OpenPresent `webapp/`) |
| 2 | **Routing and recipient types** | Sequential, parallel, mixed; cc, viewer, approver, agent; decline; void; reminders; expiry | — |
| 3 | **Templates** | Roles, save as template, use template, composite templates, sharing, folders | — |
| 4 | **Every field** | Full field set, validation, conditional fields, groups, formulas, linked and shared fields, anchors, text tags, AcroForm conversion | — |
| 5 | **Recipient authentication and consent** | Access code, email OTP, SMS OTP, phone call, OIDC; versioned ERSD; withdraw consent | — |
| 6 | **Manage and correct** | Folders and quick views, search, correct, resend, copy, transfer; editor and intermediary types; Word, Excel, PowerPoint uploads converted; reports and CSV | Converter via sister engines |
| 7 | **Verify** | `verify.html` offline in WASM; CLI; B-LT default option; public anchoring | — |
| 8 | **API and webhooks** | OAuth 2.1, JWT grant, API keys, webhooks with delivery log, sandbox accounts, TypeScript and Python SDKs, API reference site | OpenCalc's SDK packaging (its docs/55) |
| 9 | **Embedding** | Signing, prepare and correct views; `<openseal-signing>` and `<openseal-prepare>` elements | OpenCalc's embed element and theme tokens |
| 10 | **Organization admin** | Users, groups, permission profiles, OIDC and SAML SSO, domain claims, SCIM, admin audit log | — |
| 11 | **Bulk send and signing links** | CSV bulk send with test row and progress; signing links with QR, limits and email verification | — |
| 12 | **Brand and language** | Multiple brands, email templates, landing pages, 20 languages, RTL | OpenCalc's i18n module |
| 13 | **Payments** | Payment fields bound to formulas through Stripe; receipts in the certificate | — |
| 14 | **In person and kiosk** | Hosted in-person signing; kiosk mode with inactivity reset | — |
| 15 | **Enterprise data controls** | Retention policies, legal hold, WORM storage, per-tenant data keys (BYOK), data-region tags | — |
| 16 | **Per-signer seals and witnesses** | Seal per signer, certification signature with DocMDP, witness recipients | — |
| 17 | **Archive** | PDF/A-3b output; B-LTA renewal job | — |
| 18 | **Advanced and qualified signatures** | CSC API remote signing (AES/QES), IDV and KBA plugins, seal recipient | — |
| 19 | **Part 11 mode** | Account users only, re-authentication at signing, signing reasons, validation pack | — |
| 20 | **Operations** | Helm chart, HA reference, backup and restore drill, OpenTelemetry, control mapping for SOC 2 and ISO 27001 | OpenCalc's cluster deployment (its docs/65) |
| 21 | **Desktop** | Tauri app for senders and offline verification | OpenCalc's desktop shell (its docs/44, docs/81) |
| 22 | **Agent access** | MCP server: create from template, send, status, download, verify | OpenCalc's `casual-calc-mcp` (its docs/97) |
| 23 | **Responsive signing** | Reflowed, mobile-native signing view for long documents; PWA | — |
| 24 | **Integrations** | Import from cloud storage; Slack and Teams notifications; "Send for signature" from OpenDoc, OpenCalc and OpenPresent | Sister apps' host seams |
| 25 | **Compatibility API** | DocuSign-shaped endpoint, if `DEC-10` says yes | — |
| 26 | **Comments and co-editing** | Envelope comments; real-time template co-editing | OpenCalc's collaboration server |
| 27 | **Forms and clickwrap** | Web forms that create envelopes; clickwrap consent API | — |
| 28 | **Document generation** | Merge data into DOCX templates, then send | OpenDoc engine |
| 30 | **Mobile apps** | iOS and Android apps for senders and signers, with offline signing that syncs | Sister desktop shell patterns |
| 31 | **Remote online notarization** | A notary recipient runs an audio-video session, keeps a journal and applies a notarial certificate and seal; commissioned notaries through licensed providers | — |
| 32 | **Contract lifecycle module** | Clause library, drafting and redlining (with OpenDoc), approvals, repository and obligation dates, built on the public API | OpenDoc engine |
| 33 | **Rooms module** | Shared transaction workspaces with participants, tasks, documents and envelopes | — |
| 34 | **Workflow builder module** | No-code agreement workflows: forms, approvals, conditional steps, envelope sends and integrations, driven by the event stream | — |
| 35 | **Agreement intelligence module** | Extraction of parties, dates and amounts, search across agreements, renewal alerts; models behind a host seam, off by default | OpenCalc's MCP agent access |
| 29 | **Advanced routing** | Conditional routing, signing groups, scheduled sending, delayed routing, delegation and auto-delegate | — |

**Slice 1 end point (`VS-01`)**, ticked from evidence only:

- [x] Outcome through the API: a sender sends one signer a signature, date and text field; the signer signs; the worker
  seals; the sender and the signer (through the completion email's link, in a new browser) each get the sealed PDF and
  the certificate, the same bytes, accepted by our verifier and pyHanko. Evidence: worker `tests/end_to_end.rs`
  `one_signer_gets_the_sealed_pdf_and_the_certificate_from_the_completion_email`, red with `GET /s/{token}/certificate`
  removed (404 for 409), green with it (2026-11-13).
- [x] Outcome in a browser on the Compose stack, CI green: `real-stack.spec.mjs` "send and sign … (VS-01)" (document-first
  editor, signer on an iPhone 13 context, four downloads to pyHanko) runs in `compose-e2e`; green on chromium and webkit
  on GitHub runs 43481106364, 43482114678, 43492019831, 43499151699 and 43503843137, with `tools/verify-sealed.py` after it
  (2026-11-14).
  In mock mode the signer's certificate button is covered by `ceremony.spec.mjs` on the phone project, seen red without it.
- [x] [96](96-FEATURE-FIT-GAP.md) rows updated (`FG-006`, `FG-055`, `FG-057`, `FG-072`, `FG-150`); `FG-006`, `FG-055`,
  `FG-057` and `FG-072` now `Works` (`S1-05`, `S1-03`, `S1-01`, `S1-04`, `field-kinds.spec.mjs` seen red, 2026-11-13);
  the slice-1 row still short of `Works` is `FG-124` (`A11Y-01`).
- [x] Demo recorded (`S1-02`): `compose-e2e` records the VS-01 run (sender and phone) and uploads it as artefact
  `slice-1-demo`; ticked when a green run's recording is linked from [65](65-RUNNING-IT.md). Evidence: `slice-1-demo`
  of green run 44023485128, watched and linked from docs/65 §Demos (2026-11-18).
- [x] Accessibility (WCAG 2.2 AA) and i18n extraction: axe scans the editor (`a11y.spec.mjs`), every ceremony step
  (`a11y-sign.spec.mjs`) and the done screen with the certificate (`ceremony.spec.mjs`, seen red with an unnamed
  button), and every string is in `webapp/strings/`; ticked when `e2e` is green on GitHub with them. Axe green in
  `e2e` of run 44023485128; the strings check is `I18N-01` (`webapp/tests/i18n-slices.test.mjs`, [73](73-M3-SLICE-EVIDENCE.md)). The WCAG audit
  `A11Y-01` is a release gate, below. Evidence: `e2e` green with `I18N-01` on `main` run 44419251440 (2026-11-19).

**Slice 1 closed by the owner, 2026-11-19** (instruction 59), with slices 2, 5 and 7 ([73](73-M3-SLICE-EVIDENCE.md)).

**Release gates** (before any version is called 1.0): `PV-01` Acrobat verification; `SEC-REV-01` external security
review of the ceremony, sealing and keyd; `SEC-ASVS-01` ASVS self-assessment; `A11Y-01` accessibility audit;
`UXR-01` usability tests; `LEG-01` licence and notices review; `LEG-02` counsel review of legal claims and the default
ERSD; slices 1–12 closed.
