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

Docs are true as of `1163eca` (2026-11-10). The engine's first half is built; no server or UI.

| Phase | State | Note |
| --- | --- | --- |
| D Design | **Open** 2026-11-10 | This document set. Owner decisions in [14](14-EXECUTION-TRACKER.md) §Owner decisions |
| 0 Foundation | **Open** 2026-11-10 | 3 of the 4 non-sign-off exit items met (corpus and fixtures; validators on GitHub CI; spikes and ADRs). Left: seeded violations seen failing on GitHub's runners, owner sign-off |
| 1 PDF and evidence core | **Open** 2026-11-10 under `W-2` | Built and merged: 1A reader, 1B writer and normalizer, 1C geometry, text, anchors and tags, 1D field rules, 1E flattening and fill-in-place, 1F crypto structures, 1G sealing, 1H verifier, 1I audit and certificate (each with leftovers in its row); reader completion (417 of 422 corpus PDFs open). In progress, for the exit gate: 1J SDK and CLI with the corpus pipeline (`P1-GATE-01`), `WASM-01`, `VER-03`, `FUZZ-01`. Corpus run: 422 real PDFs, no panic, 387 admitted with correct page counts, 31 encrypted refused, 4 wrongly refused (`PDF-REAL-*`) |
| 2 Envelope engine and server | Not opened | May open once stages 1A and 1B close (`W-1` proposed, `DEC-13`) |
| Slices 1–35 | Not opened | Slice 1 needs Phases 1 and 2 |

### Waivers

| ID | Criterion not met | Risk | Accepted | If it fails |
| --- | --- | --- | --- | --- |
| W-2 | Phase 1 opens before Phase 0 closes: CI cannot run on GitHub while the repository is private (instruction 7), so "CI green on three platforms" is unmet | Platform-specific failures (Linux, Windows) found late; the local run is macOS only, with Linux only for the validators in Docker | Owner's "proceed", 2026-11-10, with instruction 7 | Phase 0 still closes only on a green GitHub run, at the latest when the repository goes public for the pre-release alpha (M3); failures found then are fixed first |
| W-1 (proposed) | Phase 2 opens before Phase 1 closes, once stages 1A and 1B are closed | The model or API may need a change when sealing lands | Awaiting owner | Phase 2 work adapts; Phase 2 cannot close before Phase 1 |

## Phase D — Design

- **Gives:** an agreed design, so later phases need no do-over.
- **Opens:** project start (2026-11-10).
- **In:** PRD, HLD, research studies, data model, lifecycle, PDF pipeline, sealing, audit, API, threat model, ADRs,
  enterprise requirements, process documents, tracker, fit-gap.
- **Out:** product code.
- **Closes when:**
  - [x] PRD, HLD and pillar documents drafted ([00](00-README.md)).
  - [x] DocuSign, SignNow and open-source studies recorded ([48](48-DOCUSIGN-STUDY.md), [49](49-SIGNNOW-STUDY.md), [52](52-COMPETITOR-STUDY.md)).
  - [ ] Every ADR needed by Phases 0–2 is Accepted or has a named spike deciding it ([08](08-ADR-REGISTER.md)).
  - [ ] `DEC-01` to `DEC-07` answered, or marked not blocking with the phase that needs them.
  - [ ] An independent doc audit's P0 and P1 findings are fixed (`DOC-002`).
  - [ ] Owner sign-off.

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
  - [ ] CI green on three platforms; a seeded violation seen failing each job on GitHub's runners. *(Green on all 8 jobs, Linux, macOS, Windows, at `fd5e8f3`, run 42825291522; seeded violations on GitHub not yet run, `F-003`.)*
  - [x] Fixture corpus: ≥ 200 PDFs from ≥ 10 producers (Word, LibreOffice, Acrobat, Chrome print, macOS Quartz, Ghostscript output used only as a file, scanners, InDesign, LaTeX, Google Docs), each with provenance and licence; ≥ 50 hostile fixtures, one per limit in [21](21-PARSER-LIMITS.md). Evidence: `F-004` (422 PDFs, 40 producer families, licences recorded), `F-005` (50 hostile fixtures, manifest-checked).
  - [x] pyHanko and EU DSS run in CI over a known-good signed PDF and a known-tampered one, and disagree correctly. Evidence: GitHub run 42825291522, job `validators`, at `fd5e8f3` (2026-11-10); `F-006`.
  - [x] `SPK-01` (PDF reader: own versus `lopdf`) and `SPK-02` (crypto stack in WASM) reported; ADR-005 and ADR-006 settled. Evidence: [64](64-SPK-01-PDF-READER.md), [66](66-SPK-02-CRYPTO-STACK.md).
  - [ ] Owner sign-off.

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
  - [ ] Every corpus PDF is admitted or refused with a coded reason; no panic, hang or unbounded allocation under fuzzing (24 h cumulative per target).
  - [x] For every admitted corpus PDF, fill + flatten + seal (B-T) + verify passes rungs 1–3 of the verification ladder; `sealed.starts_with(delivered)` holds. Evidence: `fixtures/corpus/pipeline/` (2026-11-10, main session): 385 pass, 32 excluded by the ruling below, 0 fail (`P1-GATE-01`).
    Owner ruling (2026-11-10, [03](03-OWNER-INSTRUCTIONS.md) instruction 11): a file certified DocMDP P1 (no changes
    permitted) is out of this item by rule. It must be refused for filling with a stable code, since any fill would break
    its certification; making such files fillable as a new document is `NORM-02`.
  - [x] B-LT and B-LTA outputs are detected at their level by EU DSS. Evidence: `fixtures/sealed`, `tools/verify-sealed.py fixtures/sealed --dss`, EU DSS 6.5.1 reports PAdES-BASELINE-LT and -LTA (stage 1G, re-run by the main session).
  - [ ] Tampering fixtures (byte flip in each revision, appended unsigned revision, shadow attacks: hide, replace, hide-and-replace; incremental saving attack; signature wrapping) are all detected by our verifier and agree with pyHanko and EU DSS.
  - [x] The audit chain verifier detects deletion, insertion, reordering and edit of any event in generated chains. Evidence: `casual-sign-audit` tamper tests and the every-mutation property (1,024 cases); the prev-link check seen red by the main session (stage 1I).
  - [ ] The WASM build of `-fields` and `-verify` gives byte-identical verdicts to native over the corpus.
  - [ ] Owner sign-off.

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
  - [ ] An API-driven end-to-end test sends a two-signer sequential envelope, signs through the ceremony endpoints, and downloads a sealed PDF that passes rungs 1–3, on the Compose deployment in CI.
  - [ ] Crash tests: killing the server or worker at every effect boundary loses no audit event and never yields `completed` without a verified seal.
  - [ ] Tenant isolation tests: every endpoint refuses cross-tenant ids (generated from the OpenAPI document), with RLS disabled and enabled.
  - [ ] Threats `SEC-A*`, `SEC-T*`, `SEC-W*` in [07](07-SECURITY-THREAT-MODEL.md) have tests seen red.
  - [ ] Owner sign-off.

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

**Release gates** (before any version is called 1.0): `PV-01` Acrobat verification; `SEC-REV-01` external security
review of the ceremony, sealing and keyd; `SEC-ASVS-01` ASVS self-assessment; `A11Y-01` accessibility audit;
`UXR-01` usability tests; `LEG-01` licence and notices review; `LEG-02` counsel review of legal claims and the default
ERSD; slices 1–12 closed.
