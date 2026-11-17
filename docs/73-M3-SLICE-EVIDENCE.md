# 73 — M3 slice evidence

Evidence for the owner to close the slices M3 needs ([06](06-ROADMAP-AND-DELIVERY.md) §Milestones: slices 1, 2, 5
and 7; tracker rows `VS-01`, `VS-02`, `VS-05`, `VS-07`). Only the owner closes a slice, and exit criteria are never bent
([05](05-PHASES-AND-TASKS.md)). This page proposes; it closes nothing and ticks no box.

**Summary:** slice 1, 3 of 5 gate items met; slice 2, 4 of 6 (its demo recorded on `main` run 44018844840, to be watched and linked); slice 5, 5 of 6 (the browser run on the stack and the demo met on `main` run 44018844840; accessibility and i18n left); slice 7, 3 of 9 (B-LT default, the WASM specs in CI, the demo, the Verify accessibility scan and public anchoring built, waiting for a CI run to show them).

**Reference run.** `main` at `ea67292`, GitHub Actions run
[43860204277](https://github.com/CasualOffice/openseal/actions/runs/43860204277) (2026-11-16), every job green:
`checks`, `test` (ubuntu, macos, windows), `msrv`, `wasm-parity`, `dependency-policy`, `commit-messages`, `validators`,
`keyd-softhsm`, `store-db`, `server-db`, `e2e` (484 passed, 90 skipped), `compose-e2e`, `chaos-compose`, `backup-drill`.
The run after it, 44001061169 (PR #15, 2026-11-17), is also green on every job (its second attempt; the first failed only `dependency-policy`). Earlier `main` runs 43849457284,
43843940320, 43842413398 failed. Every "Met" below cites what was read in that run's log or artefacts; "passed" in a
`cargo test` job means the test file ran in a job that ended green.

Sizes: S < 2 h, M < 1 day, L > 1 day.

**Gate items.** Slice 1 has its own boxes in docs/06. Slices 2, 5 and 7 have none; their gate is the general end point
in docs/06 §After Phase 2, copied verbatim: "an **outcome** (what a user can do), an **end point** (merged, CI green
including a browser run, docs/96 rows updated, demo recorded)" and "Accessibility (WCAG 2.2 AA) and i18n string
extraction are part of every UI slice's end point". The outcome is that slice's row in the docs/06 slice table.

## Slice 1 — Send and sign (`VS-01`)

| Gate item (docs/06, verbatim) | Status | Evidence, or what is missing |
| --- | --- | --- |
| Outcome through the API: a sender sends one signer a signature, date and text field; the signer signs; the worker seals; the sender and the signer (through the completion email's link, in a new browser) each get the sealed PDF and the certificate, the same bytes, accepted by our verifier and pyHanko. | Met | `casual-sign-worker` `tests/end_to_end.rs` `one_signer_gets_the_sealed_pdf_and_the_certificate_from_the_completion_email` `... ok` in `server-db`, `test (macos-latest)` and `test (windows-latest)` of run 43860204277. Seen red with the route removed (docs/06, 2026-11-13) |
| Outcome in a browser on the Compose stack, CI green: `real-stack.spec.mjs` "send and sign … (VS-01)" … runs in `compose-e2e` | Met | `compose-e2e` of run 43860204277: `real-stack.spec.mjs:177` "slice 1 (VS-01) › send and sign: one signer on a phone; both get the sealed PDF and the certificate (VS-01)" passed (chromium, 12.5 s). Earlier green runs listed in docs/06 |
| [96] rows updated (`FG-006`, `FG-055`, `FG-057`, `FG-072`, `FG-150`) | Met | docs/96: `FG-006`, `FG-055`, `FG-057`, `FG-072`, `FG-150` `Works`. `FG-124` (accessibility audit) is `A11Y-01`, a release gate, not a slice-1 item |
| Demo recorded (`S1-02`): … ticked when a green run's recording is linked from [65] | Needs the owner | Artefact `slice-1-demo` (id 14224276580, 6.7 MB, expires 2027-02-14) exists on run 43860204277. Missing: someone watches it and links it from docs/65. S |
| Accessibility (WCAG 2.2 AA) and i18n extraction: axe scans the editor (`a11y.spec.mjs`), every ceremony step (`a11y-sign.spec.mjs`) and the done screen with the certificate (`ceremony.spec.mjs` …), and every string is in `webapp/strings/`; ticked when `e2e` is green on GitHub with them | Not met | Axe half met: `e2e` of run 43860204277 passed `a11y.spec.mjs` (light, dark, phone width) and `a11y-sign.spec.mjs` on chromium, webkit and mobile, and `ceremony.spec.mjs:9` on chromium and webkit. i18n half not evidenced: `webapp/strings/` holds six `*.en.js` files, but no test or check found that fails when a user string is outside them. Missing: a run that shows every string extracted (adding a check needs the owner's word, CLAUDE.md "no new gates"). S |

Owner decision: close / not yet, because …

## Slice 2 — Routing and recipient types (`VS-02`)

Outcome (docs/06): "Sequential, parallel, mixed; cc, viewer, approver, agent; decline; void; reminders; expiry".

| Gate item (docs/06, verbatim) | Status | Evidence, or what is missing |
| --- | --- | --- |
| outcome (what a user can do): Sequential, parallel, mixed; cc, viewer, approver, agent; decline; void; reminders; expiry | Met | In `server-db` of run 43860204277: `casual-sign-server` `tests/routing.rs` (parallel, mixed, cc, agent, approver, viewer through the ceremony); worker `tests/flow.rs` (decline), `tests/crash.rs` (reminders), `tests/expiry.rs` (expiry and warning). Sequential in a browser on the real stack: `real-stack.spec.mjs:105` "two signers in order sign through emailed links; the sealed PDF and certificate download" passed in `compose-e2e` |
| merged | Met | All on `main` at `ea67292` |
| CI green including a browser run | Met | Run 43860204277 green. `compose-e2e`: `real-stack.spec.mjs:281` "an in-person signer chosen in the editor is hosted from the envelope page and signs" passed (the `UXW-18` item the tracker named). `e2e` (mock): `recipient-types.spec.mjs` approver, viewer, agent, in-person passed. Note: approver, viewer and agent browser steps were skipped in `compose-e2e` (mock only). Since `routing.spec.mjs` (2026-11-17, on `sprint1-stabilization`): one envelope to an approver, a viewer, an agent and a signer in order, each acting through the link the worker emailed (Mailpit), the agent naming the signer, the sealed PDF and certificate downloaded and added to pyHanko's manifest; passed in mock mode on chromium and webkit (seen red when the mock invited everyone at once). Its Compose run is proven only by the first green `compose-e2e` after merge |
| docs/96 rows updated | Met | Slice-2 rows: `FG-021`..`FG-024`, `FG-031`, `FG-035`, `FG-090`, `FG-094`, `FG-115`, `FG-116`, `FG-134`, `FG-135` `Works`; `FG-095` (expiration) and `FG-092` Partial; `FG-005`, `FG-038`, `FG-041` Designed; `FG-103` not started. The rows state the truth; M4, not M3, asks for `Works` |
| demo recorded | Recorded; needs watching and linking | Artifact `slice-2-demo` (id 14300839249) on green `main` run 44018844840 (`routing.spec.mjs:92` passed in `compose-e2e` on chromium and webkit). `routing.spec.mjs` records every screen of the VS-02 run on the Compose stack (sender, approver, viewer, agent, named signer: `target/e2e-demo/vs02-*.webm`), and `compose-e2e` uploads them with the sealed PDFs as artefact `slice-2-demo` (`if-no-files-found: error`), as `S1-02`. Missing: a green `compose-e2e` run that produced it, then someone watches it and links it from docs/65. S |
| Accessibility (WCAG 2.2 AA) and i18n string extraction | Axe met locally; i18n not met | `a11y-sign.spec.mjs` "the approver's, viewer's and agent's steps are accessible" (light, dark): axe on each type's documents step, review step (Approve; the agent's form, and its refused address) and receipt; passed in mock mode on chromium, webkit and mobile (seen red with `aria-hidden` on Approve). Counts once `e2e` is green on GitHub with it. i18n as slice 1. S |

Owner decision: close / not yet, because …

## Slice 5 — Recipient authentication and consent (`VS-05`)

Outcome (docs/06): "Access code, email OTP, SMS OTP, phone call, OIDC; versioned ERSD; withdraw consent".

| Gate item (docs/06, verbatim) | Status | Evidence, or what is missing |
| --- | --- | --- |
| outcome (what a user can do): Access code, email OTP, SMS OTP, phone call, OIDC; versioned ERSD; withdraw consent | Met | In `server-db` of run 43860204277: `casual-sign-server` `tests/ceremony_auth.rs` (access code, withdraw; 5 passed), `tests/ceremony_sso.rs` (OIDC), `tests/disclosure.rs`, `tests/ersd_publish.rs` (versioned ERSD); worker `tests/email_otp.rs`, `tests/sms_otp.rs` (SMS and voice) |
| merged | Met | All on `main` at `ea67292` |
| CI green including a browser run | Met | `main` run 44018844840 (2026-11-17, every job green): `compose-e2e` passed `recipient-auth.spec.mjs:187` and `:203` on chromium and webkit against the real server. Before it: mock-mode browser passed in `e2e` of run 43860204277 (chromium, webkit, mobile). Since `RAUTH-02` (branch `sprint1-stabilization`): the CI-only overlay `tools/e2e/compose.e2e.yml` adds an SMS gateway stub and an OpenID Connect provider stub (`tools/e2e/auth_stubs.py`, 12 stdlib unit tests, run first in `compose-e2e`), and `recipient-auth.spec.mjs` no longer skips on the real stack: access code, email code read from Mailpit, SMS and voice codes read from the stub, sign-in on the stub's page, consent and withdrawal. Mock mode green locally on chromium, webkit and mobile; the Compose run itself has not run yet (no Docker here). Met when `compose-e2e` on `main` shows both tests passed on chromium and webkit |
| docs/96 rows updated | Met | `FG-111`, `FG-117`, `FG-118`, `FG-119`, `FG-217` `Works`; `FG-177` (ERSD editing) Partial, real-stack e2e left; `FG-039`, `FG-040` (SMS and WhatsApp delivery) not started (`MSG-02`) |
| demo recorded | Met (recorded); to be watched | Artifact `slice-5-demo` (id 14300784371) on green `main` run 44018844840. `recipient-auth.spec.mjs` on the Compose stack records the signer's screens (codes on a phone, iPhone 13; sign-in on a desktop) into `target/e2e-demo/vs05-*.webm`; `compose-e2e` uploads them as the `slice-5-demo` artifact (`if-no-files-found: error`). Met when that artifact exists on a green `main` run |
| Accessibility (WCAG 2.2 AA) and i18n string extraction | Needs the owner | Accessibility: `recipient-auth.spec.mjs` "the code entry, sign-in and withdraw steps are accessible" (light, dark) runs axe (`expectAccessible`, WCAG 2.2 AA tags) at phone width on the access-code step, each sent-code step (email, SMS, voice) before and after asking and with a wrong code, the identity-provider sign-in step, the withdraw dialog and the withdrawn screen; green locally in mock mode on chromium, webkit and mobile, red with the code field's label unbound (`axe on email-code entry (light)`). In CI's `e2e` job from the next run. i18n as slice 1 |
| (tracker, not a docs/06 item) ADR-033 accepted | Met | Accepted by the owner, instruction 54 (2026-11-17); docs/08 records it; `RAUTH-01` Done on `server-db` of run 44001061169 |

Owner decision: close / not yet, because …

## Slice 7 — Verify (`VS-07`)

Outcome (docs/06): "`verify.html` offline in WASM; CLI; B-LT default option; public anchoring". Split into its four
parts below.

| Gate item (docs/06, verbatim) | Status | Evidence, or what is missing |
| --- | --- | --- |
| `verify.html` offline in WASM | Built; met when CI shows it | `VS-07` (2026-11-17): `ci.yml` `e2e` now builds the verifier before Playwright (rust-toolchain.toml's toolchain, wasm-pack 0.14.0, `tools/build-webapp-wasm.sh`, cached on `rust-toolchain.toml`, `Cargo.*`, `crates/**` and the script; the job fails if the files are missing). `compose-e2e` already serves it from the image (deploy/Dockerfile `wasm` stage); it now checks the server answers it as `application/wasm`, and the specs no longer skip on a real server (`test.skip(!WASM && !REAL)`). Run locally, chromium and webkit: `web02.spec.mjs:236`, `:257`, `:266`, `:279` and `signin-dashboard.spec.mjs:171`, `:189` passed in mock mode and against a local `casual-sign-server` serving `webapp/` (16 passed with the a11y scans). Missing: a green CI run that shows them run, not skipped |
| CLI | Met | `crates/casual-sign-cli/tests/cli.rs` `seal_b_t_over_http_tsa_then_verify_and_detect_tamper`, `seal_b_b_then_verify_indeterminate_without_revocation`, `audit_verify_detects_an_edit` `... ok` in `test (windows-latest)` and `test (macos-latest)` of run 43860204277 |
| B-LT default option | Built; met when CI shows it | `VS-07`: the account setting `default_seal_profile` (`PATCH /accounts/me`, refused unless `pades-b-t`, `pades-b-lt` or `pades-b-lta`; Admin → Organization "Seal new envelopes at"); an envelope created without `seal_profile` takes it. The worker could not complete a B-LT seal: its own check required whole-file coverage, which B-LT's DSS revision never has (envelope stuck `completing`, `CS-WRK-0012` coverage); fixed to accept a DSS-only tail at B-LT. `casual-sign-worker/tests/end_to_end.rs` `an_account_defaulting_to_b_lt_gets_long_term_seals_verified_by_pyhanko`: our verifier at B-LT with no CRLs supplied, and pyHanko `ltv=0:ok` from the DSS alone with hard-fail revocation; seen red without the default and without the coverage fix. Runs in `server-db`. Not built: a per-envelope control in the editor, a Compose run at B-LT. `FG-154` `Partial` |
| public anchoring | Built; met when CI shows it | `FG-158` `Engine` (docs/32 §5 As built, migration 0041, ADR-037 accepted): the worker anchors each account's changed chain heads daily with a TSA token over the tree's root and size, stores proofs insert-only and publishes to `OPENSEAL_ANCHOR_LOG`; `openseal anchor verify` proves a head offline. Tests: `casual-sign-worker/tests/anchoring.rs` (day anchored, proofs verify, tampered head fails, crash after the token and after storing), `casual-sign-sdk/tests/anchor.rs`, `casual-sign-audit/tests/anchor.rs`, CLI `anchor_verify_proves_a_head_and_detects_a_tampered_one`. Left: proofs served by the API and shown in `verify.html` (`VS-07B`); ADR-037 accepted (owner instruction 56) |
| merged | Met | What exists is on `main` at `ea67292` |
| CI green including a browser run | Not met | Run 43860204277 is green, but the slice's browser runs are the skipped WASM specs above. Closes with the first item. (counted there) |
| docs/96 rows updated | Met | `FG-157` `Works`, `FG-154` `Engine`, `FG-158` `Designed`: each states what is built |
| demo recorded | Built; met when CI shows it | `verify-demo.spec.mjs` records the verify flow and `e2e` uploads it as `slice-7-demo` (`VS-07A`, `a1a500c`, pull request #18). Missing: the artifact on a green `main` run, watched and linked from docs/65. S |
| Accessibility (WCAG 2.2 AA) and i18n string extraction | Axe built; i18n not met | `a11y.spec.mjs` scans `verify.html` at start, valid, tampered and refused, light and dark (seen red with a low-contrast rule; `VS-07A`, pull request #18); counts once `e2e` on `main` is green with it. i18n as slice 1. S |

Owner decision: close / not yet, because …

## Not met, by size

| Slice | Item | Size |
| --- | --- | --- |
| 1 | Demo watched and linked from docs/65 (`S1-02`) | S |
| 1 | i18n extraction shown | S |
| 2 | Demo (`RTE-04`): recorded on run 44018844840; watched and linked | S |
| 2 | i18n extraction shown (as slice 1) | S |
| 5 | Accessibility of auth steps (ADR-033 accepted 2026-11-17) | S |
| 7 | WASM verifier specs run in CI (built, `VS-07`; needs the CI run) | M |
| 7 | B-LT default option with a test (built, `VS-07`; editor control and Compose run not built) | M |
| 7 | Demo and accessibility scan of `verify.html` (built, `VS-07A`; need the CI artifact and the owner's decision) | S |
| 7 | Public anchoring: proofs through the API and `verify.html` (`VS-07B`; built in the engine, CLI and worker; ADR-037 accepted) | M |

Nothing here states that any signature is legally valid or that the product is compliant or certified (docs/09).
