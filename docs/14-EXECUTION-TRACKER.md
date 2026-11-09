# 14 — Execution tracker

**The only tracker.** Ids are stable and never reused. Status: `Open`, `In progress`, `Blocked`, `Done`, as defined
with Definition of Done in [05](05-PHASES-AND-TASKS.md). Phase state and waivers are in
[06](06-ROADMAP-AND-DELIVERY.md). Severity: P0 blocks a phase gate or is a security or evidence defect; P1 blocks a
slice; P2 otherwise.

Docs are true as of the Phase 0 foundation commit (2026-11-10).

## Owner decisions

| ID | Decision | St | Recommendation | Why it matters |
| --- | --- | --- | --- | --- |
| DEC-01 | Product name | Done | Owner, 2026-11-10 (instruction 4): **OpenSeal**. Chosen because "OpenSign" is OpenSign Labs' AGPL e-signature product ([52](52-COMPETITOR-STUDY.md)). A web search found only an unrelated, old .NET library called openSEAL on SourceForge; trademark search remains `DEC-07`. Crates stay `casual-sign-*`; the local folder `opensign/` may be renamed to `openseal/` when the repo is created | Avoids confusion and a trademark dispute |
| DEC-02 | Where to build; how to share code with the sisters | Open | Separate repo in this folder; copy from OpenCalc and OpenPresent with `PROVENANCE.md` (as OpenPresent's `DEC-02`) | Sets ADR-003 |
| DEC-03 | Accent colour | Open | Indigo `#4338ca` (7.9:1 on white): distinct from OpenCalc's green, OpenPresent's cyan, and DocuSign's and SignNow's brand colours | One token; the sisters each have one |
| DEC-04 | Acrobat verification | Open | Release gate `PV-01`, run in a CI container or on a machine that is not the owner's; phases close on our verifier + pyHanko + EU DSS | So work never waits on Acrobat; "valid in Acrobat" stays unclaimable until then |
| DEC-05 | Web and desktop | Open | Web first (signers are on the web); desktop as slice 21 for senders and offline verification | The sisters support both |
| DEC-06 | Reference products | Open | DocuSign sets the feature bar, vocabulary and API concepts; SignNow's document-first editor is offered beside DocuSign's flow ([01](01-PRD.md) §3) | Decides every UX dispute |
| DEC-07 | Legal reviews | Open | Trademark search on the chosen name; counsel review of legal claims and the default ERSD (`LEG-02`) before 1.0 | E-signature products carry legal exposure |
| DEC-08 | CLM, Rooms, workflow builders, AI analysis | Open | Out of the core; API, events and MCP let them be built outside | Scope |
| DEC-09 | Remote online notarization | Open | Out; jurisdiction-specific licensing | Scope |
| DEC-10 | DocuSign-compatible API endpoint | Open | Defer to slice 25 and decide with counsel; the native API stays the primary contract | Migration value against trademark risk |
| DEC-11 | Git workflow | Done | Owner, 2026-11-10 (instruction 5), as recommended: work lands on `main`, parallel workers on worktree branches merged by the main session; GitHub org `CasualOffice`, repo `openseal` | Needed for `F-001` |
| DEC-12 | Default seal level | Open | PAdES B-T for every account; B-LT one switch away; B-LTA with renewal for archives (ADR-008) | Cost (TSA calls) against long-term verifiability |
| DEC-14 | FIPS build profile | Open | Offer FIPS as a separate build (CMake and Go in its image) and allow the OpenSSL licence for `aws-lc-fips-sys` only; default builds stay non-FIPS | Some regulated buyers need FIPS 140-3 validated crypto; the licence and toolchain cost apply only to that build |
| DEC-13 | Open Phase 2 early (waiver `W-1`) | Open | Yes, once stages 1A and 1B close | Shortens time to a usable product; model risk is small |

## Milestones

Defined in [06](06-ROADMAP-AND-DELIVERY.md) §Milestones. Only the owner declares one reached.

| ID | Milestone | St | Contains | Size |
| --- | --- | --- | --- | --- |
| MS-0 | Ready to build | In progress | Phase D, Phase 0 (open 2026-11-10) | M |
| MS-1 | Engine alpha | Open | Phase 1 | XL |
| MS-2 | Service alpha | Open | Phase 2 | L |
| MS-3 | First signature (private preview) | Open | VS-01, VS-02, VS-05, VS-07 | L |
| MS-4 | Team beta | Open | VS-03, VS-04, VS-06, VS-08, VS-09 | XL |
| MS-5 | 1.0 GA | Open | VS-10, VS-11, VS-12, VS-15, VS-20; release gates | XL |
| MS-6 | Regulated | Open | VS-16 to VS-19 | L |
| MS-7 | Ecosystem | Open | VS-13, VS-14, VS-21 to VS-29 | XL |

## Phase D

| ID | Title | St | Sev | Mechanism | Gate |
| --- | --- | --- | --- | --- | --- |
| DOC-001 | Initial document set: PRD, HLD, studies, pillars, process, tracker, fit-gap, CLAUDE.md, AGENTS.md, README, skills | Done | P0 | Written 2026-11-10 from two research passes (DocuSign; SignNow, open source, standards) and the sisters' docs at OpenPresent `8011d28` | Owner reads [00](00-README.md) |
| DOC-002 | Independent doc audit | Open | P0 | Fresh session audits every doc for contradictions, broken references and unsupported claims (`openseal-docs` skill) | Findings fixed or rows |
| RES-01 | Confirm DocuSign items marked [?] in [48](48-DOCUSIGN-STUDY.md): certificate layout, bulk-send limits, correct rules, expiry defaults, retry policy, pricing | Open | P2 | A trial account or official docs; never on the owner's desktop if it needs software installed | Each [?] resolved or kept with reason |
| RES-02 | Confirm SignNow items marked [M]/[?] in [49](49-SIGNNOW-STUDY.md): left palette, bulk invite API, token lifetime | Open | P2 | As RES-01 | As RES-01 |
| LEG-03 | Study other jurisdictions, India (IT Act, Aadhaar eSign) first | Open | P2 | [09](09-LEGAL-AND-COMPLIANCE.md) §4 | Section per jurisdiction |

## Phase 0

| ID | Title | St | Sev | Mechanism | Gate |
| --- | --- | --- | --- | --- | --- |
| F-001 | `git init`, remote, branch protection per `DEC-11` | In progress | P0 | Owner created `CasualOffice/openseal` (private); `main` pushed at `d24120e`, 2026-11-10. **Left:** branch protection, once CI can run (`F-003`) | Remote exists; first commit pushed |
| F-002 | Copy foundation from the sisters with provenance: lints, toolchain, `deny.toml`, hooks, `check-repo.py`, CI skeleton, `CONTRIBUTING`, `SECURITY`, `GOVERNANCE`, `CODE_OF_CONDUCT` | Done | P0 | Copied from OpenPresent `e61277d`, recorded in `PROVENANCE.md`. Workspace with `casual-sign-pdf` skeleton (`Limits` from docs/21; its test seen red with a changed default). `check-repo.py` seen failing on a duplicate tracker id and a broken link; `check-commits.py` on a non-conventional message; clean tree passes. fmt, clippy `-D warnings`, rustdoc, wasm32 check, MSRV 1.88 check, `cargo deny` all pass locally, 2026-11-10 | Files present with `PROVENANCE.md`; CI runs |
| F-003 | CI matrix and repo gates | Blocked | P0 | `.github/workflows/ci.yml` written. GitHub Actions cannot run while the repository is private (org billing); the owner keeps it private until the pre-release alpha (instruction 7). Meanwhile `tools/ci-local.sh` runs every job locally (macOS, validators in Docker) and passed at Phase 1 opening, 2026-11-10. **Left:** a green GitHub run once public, and seeded violations seen failing there | Green on three platforms; seeded violations seen failing on GitHub's runners |
| F-004 | PDF fixture corpus with provenance | In progress | P0 | ≥ 200 PDFs from ≥ 10 producers; licences recorded; no personal data | Manifest checked by `check-repo.py` |
| F-005 | Hostile fixtures, one per limit in [21](21-PARSER-LIMITS.md) | Done | P0 | `fixtures/tools/generate.py` writes 32 synthetic PDFs (127 MB, about 8 s, not committed): every docs/21 PDF limit with a code, plus recovery and active-content cases; `fixtures/hostile/manifest.tsv` gives each its strict code and default outcome. pyHanko opens the controls and structural cases as intended (5,001 pages; 1,002 revisions). `--check` seen failing on a dropped manifest row and on a limit left uncovered, 2026-11-10; runs in CI `checks` | Manifest names each limit and expected code |
| F-006 | Independent validators in CI (pyHanko, EU DSS container) | In progress | P0 | **pyHanko:** `tools/verify-sealed.py --self-test` seals a hand-written PDF at PAdES B-B with a throwaway CA (pyHanko 0.38.1) and checks sealed → valid, flipped byte → invalid, content changed after signing → reported. **EU DSS:** `tools/eu-dss/` builds a DSS 6.5.1 validator image; with `--dss` the same three files go to it: sealed → intact, valid, `PAdES-BASELINE-B`, 0 undefined changes; flipped → `TOTAL_FAILED`/`HASH_FAILURE`; modified → 2 undefined changes. Every check of both validators seen failing under a mutation, 2026-11-10; both in CI job `validators`. **Left:** a run on GitHub (`F-003`) | Known-good passes, known-tampered fails, in CI |
| F-007 | Fuzz workspace | Open | P1 | `cargo-fuzz`, one target per byte entry point | Targets build and run 60 s in CI |
| F-008 | Test PKI issues a CRL (and later OCSP) so EU DSS can reach `TOTAL_PASSED` offline, not only intact-and-valid | Open | P1 | Feed the CRL to DSS through an offline CRL source in `tools/eu-dss` | DSS `TOTAL_PASSED` on the self-test seal; seen failing with the CRL listing the leaf |
| SPK-01 | Own PDF reader versus `lopdf`/`pdf-rs` | Done | P0 | Spike merged, main session re-ran six fixtures (2026-11-10) and saw the same outcomes: lopdf `pages=0` with no error on a page-tree cycle and deep nesting; own sketch typed errors (`Cycle`, `Depth`); pdf-rs abort on the 1 GiB Flate bomb. ADR-005 confirmed: our own reader and writer, lopdf as test oracle ([64](64-SPK-01-PDF-READER.md)). Estimate for the real reader and writer: about 3,000 lines plus tests | Report; ADR-005 decided |
| SPK-02 | Crypto stack: `aws-lc-rs` + RustCrypto on native; RustCrypto only on WASM; CMS build and verify interop with pyHanko | In progress | P0 | **Done by the spike, verified by the main session (2026-11-10):** P-256 and RSA-3072 PAdES B-B seals from aws-lc-rs keys and RustCrypto CMS validate in pyHanko 0.38.1 as `INTACT:TRUSTED,UNTOUCHED`; flipped ByteRange byte and corrupted signature value both `INVALID` (re-run by the main session); RustCrypto-only verifier builds for wasm32 (330/424 KB). ADR-006 confirmed with amendments ([66](66-SPK-02-CRYPTO-STACK.md)). **Left:** EU DSS (rung 3, `F-006`) on these outputs; Linux build | Report; ADR-006 decided |
| DEP-02 | Record the RUSTSEC-2023-0071 ignore for `rsa` (verify-only, WASM) in `deny.toml` with its reason, when `-crypto` first depends on `rsa` | Done | P1 | Not needed: the advisory database of 2026-11-10 lists the advisory as patched in `rsa` 0.10.0; `cargo deny --all-features check advisories` and `cargo audit --deny warnings` pass with no entry (stage 1F, re-run by local CI) | `cargo deny` and `cargo audit` pass |
| DEP-03 | Move `cms`, `x509-tsp`, `x509-ocsp` from release candidates to stable releases | Open | P2 | Exact pins until then | Stable versions pinned; seals still validate |
| SEAL-13 | Decide whether the verifier accepts BER CMS from third-party signers | Open | P2 | Measure how common BER is among signed PDFs in the corpus | Decision recorded in docs/31 |
| SEAL-14 | SHA-1 for identifier matching only (ESSCertID v1 in timestamps, SHA-1 OCSP CertIDs), never for signing or digests of content | Open | P1 | Recommendation: allow SHA-1 strictly to match identifiers produced by real TSAs and OCSP responders, as an ADR-006 amendment; until then such inputs are refused with `CS-SEAL-0005` | ADR amended; tests for a v1 ESSCertID and a SHA-1 CertID |
| PDF-REN-01 | Server-side page thumbnails: pdf.js headless versus `hayro` | Open | P2 | Fidelity on the corpus, speed, safety | Report; choice recorded |

## Phase 1 stages

Split into tasks when each stage opens.

| ID | Title | St | Sev | Mechanism | Gate |
| --- | --- | --- | --- | --- | --- |
| T-1A | Bounded reader and admission report | In progress | P0 | [30](30-PDF-PIPELINE.md) §2 | Stage gate in 06 |
| T-1B | Incremental writer and normalizer | Open | P0 | [30](30-PDF-PIPELINE.md) §3, §9 | Stage gate; `PDF-INV-01` |
| PDF-INV-01 | Delivered bytes are a prefix of the sealed file | Open | P0 | Corpus test | Seen red with a writer that rewrites |
| T-1C | Geometry, text extraction, anchors, text tags, AcroForm conversion | Open | P0 | [30](30-PDF-PIPELINE.md) §4, §5 | Stage gate |
| T-1D | Field validation, conditions, groups, formulas, native = WASM | In progress | P0 | **Built and merged (2026-11-10, `ad2276b`):** field types in `-model`; validation, visibility, groups, linked fields, formulas, `evaluate_envelope`, `check_client` in `-fields`; 72 tests incl. 5 property tests; 225-case table identical natively and in wasm32 (Node); 8 bounds each seen red with the guard removed (worker), length and depth re-run by the main session; found and fixed a panic formatting 29-digit results. **Left:** a cargo-fuzz target for `parse_formula` and the regex path once `fuzz/` exists (`F-007`); a committed WASM parity runner, which belongs in `casual-sign-wasm` | Stage gate |
| T-1E | Flattening | Open | P0 | [30](30-PDF-PIPELINE.md) §7 | Stage gate |
| T-1F | Crypto structures, KeyProvider, TSP, OCSP, CRL | In progress | P0 | **Built and merged (2026-11-10, `d44734f`):** `KeyProvider` signing DER signed attributes; CMS detached builder and verifier (attributes as received, ESS v2, DER only); RFC 3161 request and response/token verification; OCSP and CRL status at a time with responder authorization; 32 tests; interop both ways with `cryptography`/pyHanko (re-run by the main session: 6 of 6 of our outputs pass); 10,000 DER mutations without panic; 12 guards seen red (worker), message digest re-run by the main session. **Left:** a test for the TSA EKU check; the cargo-fuzz target (drafted in the worker's report) once `fuzz/` exists (`F-007`); `SEAL-14` | Stage gate |
| T-1G | Sealing B-B to B-LTA | Open | P0 | [31](31-SEALING-AND-SIGNATURES.md) §4 | Stage gate; ladder rungs 1–3 |
| T-1H | Verifier | Open | P0 | [31](31-SEALING-AND-SIGNATURES.md) §7 | Stage gate; tampering fixtures |
| T-1I | Audit chain and certificate of completion | Open | P0 | [32](32-AUDIT-TRAIL-AND-EVIDENCE.md) | Stage gate |
| T-1J | SDK facade and CLI | Open | P1 | [19](19-WORKSPACE-SCAFFOLD-DESIGN.md) | Stage gate |
| SEAL-12 | Ed25519 seals once reader support exists | Open | P2 | Track Acrobat and EU DSS support | Decision recorded |

## Phase 2 stages

| ID | Title | St | Sev | Mechanism | Gate |
| --- | --- | --- | --- | --- | --- |
| T-2A | Model and workflow engine | Open | P0 | [24](24-ENVELOPE-LIFECYCLE-AND-ROUTING.md) | Property tests over random command sequences |
| T-2B | Persistence, tenancy, audit immutability, blob store | Open | P0 | [22](22-DATA-MODEL.md) §9 | Cross-tenant tests; audit trigger tests |
| T-2C | Server, auth, OpenAPI, rate limits | Open | P0 | [40](40-API-DESIGN.md) | Contract tests |
| T-2D | Worker, job queue, email, webhooks | Open | P0 | [24](24-ENVELOPE-LIFECYCLE-AND-ROUTING.md) §1 | Crash tests |
| T-2E | keyd with PKCS#11 | Open | P0 | [31](31-SEALING-AND-SIGNATURES.md) §5 | SoftHSM in CI; seal verified |
| T-2F | Single-node Compose deployment | Open | P1 | [65](65-RUNNING-IT.md) | End-to-end API test on Compose in CI |
| DEP-01 | Review SAML library choice (`samael` or alternative) | Open | P1 | Security history, maintenance, XML signature handling | Decision recorded |

## Vertical slices

Each slice's outcome is in [06](06-ROADMAP-AND-DELIVERY.md) §After Phase 2; none has opened.

| ID | Slice | St | Sev |
| --- | --- | --- | --- |
| VS-01 | Send and sign | Open | P0 |
| VS-02 | Routing and recipient types | Open | P0 |
| VS-03 | Templates | Open | P1 |
| VS-04 | Every field | Open | P1 |
| VS-05 | Recipient authentication and consent | Open | P0 |
| VS-06 | Manage and correct | Open | P1 |
| VS-07 | Verify | Open | P1 |
| VS-08 | API and webhooks | Open | P1 |
| VS-09 | Embedding | Open | P1 |
| VS-10 | Organization admin | Open | P1 |
| VS-11 | Bulk send and signing links | Open | P1 |
| VS-12 | Brand and language | Open | P1 |
| VS-13 | Payments | Open | P2 |
| VS-14 | In person and kiosk | Open | P2 |
| VS-15 | Enterprise data controls | Open | P1 |
| VS-16 | Per-signer seals and witnesses | Open | P2 |
| VS-17 | Archive | Open | P2 |
| VS-18 | Advanced and qualified signatures | Open | P2 |
| VS-19 | Part 11 mode | Open | P2 |
| VS-20 | Operations | Open | P1 |
| VS-21 | Desktop | Open | P2 |
| VS-22 | Agent access | Open | P2 |
| VS-23 | Responsive signing | Open | P2 |
| VS-24 | Integrations | Open | P2 |
| VS-25 | Compatibility API | Blocked | P2 |
| VS-26 | Comments and co-editing | Open | P2 |
| VS-27 | Forms and clickwrap | Open | P2 |
| VS-28 | Document generation | Open | P2 |
| VS-29 | Advanced routing | Open | P2 |

`VS-25` is blocked on `DEC-10`.

## Release gates

| ID | Title | St | Sev | Gate |
| --- | --- | --- | --- | --- |
| PV-01 | Sealed fixtures valid in Adobe Acrobat Reader | Open | P0 | [15](15-CI-AND-RELEASE-GATES.md) |
| SEC-REV-01 | External security and cryptographic review | Open | P0 | Report; findings closed |
| SEC-ASVS-01 | ASVS L2 (L3 for ceremony, sealing, keyd) self-assessment | Open | P0 | Checklist with evidence |
| LEG-01 | NOTICE and licence review | Open | P0 | Sign-off |
| LEG-02 | Counsel review of legal claims and default ERSD | Open | P0 | Sign-off |
| LEG-04 | SOC 2 / ISO 27001 control mapping for operators | Open | P2 | Document |
| A11Y-01 | WCAG 2.2 AA audit of signer and sender UIs | Open | P0 | Report; findings closed |
| UXR-01 | Usability tests: time to send, signer completion | Open | P1 | Report |
