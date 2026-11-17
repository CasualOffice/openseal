# 73 — M3 slice evidence

Evidence for the owner to close the slices M3 needs ([06](06-ROADMAP-AND-DELIVERY.md) §Milestones: slices 1, 2, 5
and 7; tracker rows `VS-01`, `VS-02`, `VS-05`, `VS-07`). Only the owner closes a slice, and exit criteria are never bent
([05](05-PHASES-AND-TASKS.md)). This page proposes; it closes nothing and ticks no box.

**Summary:** slice 1, 3 of 5 gate items met; slice 2, 4 of 6; slice 5, 3 of 6; slice 7, 3 of 9.

**Reference run.** `main` at `ea67292`, GitHub Actions run
[43860204277](https://github.com/CasualOffice/openseal/actions/runs/43860204277) (2026-11-16), every job green:
`checks`, `test` (ubuntu, macos, windows), `msrv`, `wasm-parity`, `dependency-policy`, `commit-messages`, `validators`,
`keyd-softhsm`, `store-db`, `server-db`, `e2e` (484 passed, 90 skipped), `compose-e2e`, `chaos-compose`, `backup-drill`.
The run after it (44001061169, PR #15) was in progress when this page was written. Earlier `main` runs 43849457284,
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
| CI green including a browser run | Met | Run 43860204277 green. `compose-e2e`: `real-stack.spec.mjs:281` "an in-person signer chosen in the editor is hosted from the envelope page and signs" passed (the `UXW-18` item the tracker named). `e2e` (mock): `recipient-types.spec.mjs` approver, viewer, agent, in-person passed. Note: approver, viewer and agent browser steps are skipped in `compose-e2e` (mock only); the outcome on the real server rests on `tests/routing.rs` |
| docs/96 rows updated | Met | Slice-2 rows: `FG-021`..`FG-024`, `FG-031`, `FG-035`, `FG-090`, `FG-094`, `FG-115`, `FG-116`, `FG-134`, `FG-135` `Works`; `FG-095` (expiration) and `FG-092` Partial; `FG-005`, `FG-038`, `FG-041` Designed; `FG-103` not started. The rows state the truth; M4, not M3, asks for `Works` |
| demo recorded | Not met | `RTE-04` Open; no recording exists. Could follow `S1-02`'s pattern (record in `compose-e2e`, upload an artefact). M |
| Accessibility (WCAG 2.2 AA) and i18n string extraction | Needs the owner | `a11y-sign.spec.mjs` scans the signer's ceremony steps (passed, run 43860204277); no axe scan names the approver's Approve, the viewer's finish or the agent's form specifically. i18n as slice 1. Decide whether the ceremony scan covers them, or add scans. S |

Owner decision: close / not yet, because …

## Slice 5 — Recipient authentication and consent (`VS-05`)

Outcome (docs/06): "Access code, email OTP, SMS OTP, phone call, OIDC; versioned ERSD; withdraw consent".

| Gate item (docs/06, verbatim) | Status | Evidence, or what is missing |
| --- | --- | --- |
| outcome (what a user can do): Access code, email OTP, SMS OTP, phone call, OIDC; versioned ERSD; withdraw consent | Met | In `server-db` of run 43860204277: `casual-sign-server` `tests/ceremony_auth.rs` (access code, withdraw; 5 passed), `tests/ceremony_sso.rs` (OIDC), `tests/disclosure.rs`, `tests/ersd_publish.rs` (versioned ERSD); worker `tests/email_otp.rs`, `tests/sms_otp.rs` (SMS and voice) |
| merged | Met | All on `main` at `ea67292` |
| CI green including a browser run | Not met | Mock-mode browser passed in `e2e` of run 43860204277: `recipient-auth.spec.mjs:54` "codes by email, text message and phone call, then consent and its withdrawal" and `:64` "sign-in through an identity provider comes back to the signing page", on chromium, webkit and mobile. Both are skipped in `compose-e2e`. Missing (`RAUTH-02`): an SMS gateway stub and an OIDC provider stub in `docker-compose.yml` and the spec run against the real server. M |
| docs/96 rows updated | Met | `FG-111`, `FG-117`, `FG-118`, `FG-119`, `FG-217` `Works`; `FG-177` (ERSD editing) Partial, real-stack e2e left; `FG-039`, `FG-040` (SMS and WhatsApp delivery) not started (`MSG-02`) |
| demo recorded | Not met | Part of `RAUTH-02`; nothing recorded. S once the Compose run exists |
| Accessibility (WCAG 2.2 AA) and i18n string extraction | Needs the owner | `a11y-sign.spec.mjs` "every ceremony step is accessible" passed (run 43860204277); not shown to include the code-entry, sign-in-provider and withdraw steps. i18n as slice 1. S |
| (tracker, not a docs/06 item) ADR-033 accepted | Needs the owner | ADR-033 (OIDC sign-in bound by verified email) is Proposed in docs/08; `VS-05` names its acceptance as left |

Owner decision: close / not yet, because …

## Slice 7 — Verify (`VS-07`)

Outcome (docs/06): "`verify.html` offline in WASM; CLI; B-LT default option; public anchoring". Split into its four
parts below.

| Gate item (docs/06, verbatim) | Status | Evidence, or what is missing |
| --- | --- | --- |
| `verify.html` offline in WASM | Not met | Built (`WEB-05`; `wasm-parity` green in run 43860204277, native and WASM agree over the corpus). But the browser specs that run the WASM verifier, `web02.spec.mjs:234` "a sealed PDF verifies against its trust root…" and `signin-dashboard.spec.mjs:169`, `:187` (tampered PDF), are skipped in both `e2e` and `compose-e2e` (`test.skip(!WASM ...)`: CI does not build the WASM for the web app). `shell.spec.mjs:406` passed but does not show the WASM verdict. Missing: build the WASM in the `e2e` job so these run. M |
| CLI | Met | `crates/casual-sign-cli/tests/cli.rs` `seal_b_t_over_http_tsa_then_verify_and_detect_tamper`, `seal_b_b_then_verify_indeterminate_without_revocation`, `audit_verify_detects_an_edit` `... ok` in `test (windows-latest)` and `test (macos-latest)` of run 43860204277 |
| B-LT default option | Not met | The engine seals B-LT (`casual-sign-seal` tests; `validators` green) and an envelope takes `seal_profile` (`server/casual-sign-server/src/api/envelopes.rs`), but no server or worker test was found that sends with B-LT, or sets it as an account's default, and gets a B-LT seal checked by pyHanko. `FG-154` reads `Engine`. Missing: the account default setting if absent, a worker test, an editor control. M |
| public anchoring | Built, not yet merged | `FG-158` `Engine` (docs/32 §5 As built, migration 0041, ADR-037 Proposed): the worker anchors each account's changed chain heads daily with a TSA token over the tree's root and size, stores proofs insert-only and publishes to `OPENSEAL_ANCHOR_LOG`; `openseal anchor verify` proves a head offline. Tests: `casual-sign-worker/tests/anchoring.rs` (day anchored, proofs verify, tampered head fails, crash after the token and after storing), `casual-sign-sdk/tests/anchor.rs`, `casual-sign-audit/tests/anchor.rs`, CLI `anchor_verify_proves_a_head_and_detects_a_tampered_one`. Left: proofs served by the API and shown in `verify.html` (needs a row); ADR-037 acceptance |
| merged | Met | What exists is on `main` at `ea67292` |
| CI green including a browser run | Not met | Run 43860204277 is green, but the slice's browser runs are the skipped WASM specs above. Closes with the first item. (counted there) |
| docs/96 rows updated | Met | `FG-157` `Works`, `FG-154` `Engine`, `FG-158` `Designed`: each states what is built |
| demo recorded | Not met | Nothing recorded; no tracker row (needs one). S after the browser run |
| Accessibility (WCAG 2.2 AA) and i18n string extraction | Needs the owner | No axe scan of `verify.html` found in `a11y.spec.mjs` or `a11y-sign.spec.mjs`. S |

Owner decision: close / not yet, because …

## Not met, by size

| Slice | Item | Size |
| --- | --- | --- |
| 1 | Demo watched and linked from docs/65 (`S1-02`) | S |
| 1 | i18n extraction shown | S |
| 2 | Demo (`RTE-04`) | M |
| 2 | Accessibility of approver, viewer, agent steps decided | S |
| 5 | Compose run with SMS and OIDC stubs (`RAUTH-02`) | M |
| 5 | Demo (`RAUTH-02`) | S |
| 5 | Accessibility of auth steps; ADR-033 acceptance | S |
| 7 | WASM verifier specs run in CI | M |
| 7 | B-LT default option with a test | M |
| 7 | Public anchoring: merge; proofs through the API and `verify.html`; ADR-037 acceptance | M |
| 7 | Demo (needs a row); accessibility scan of `verify.html` | S |

Nothing here states that any signature is legally valid or that the product is compliant or certified (docs/09).
