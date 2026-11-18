# 73 — M3 slice evidence

Evidence for the owner to close the slices M3 needs ([06](06-ROADMAP-AND-DELIVERY.md) §Milestones: slices 1, 2, 5
and 7; tracker rows `VS-01`, `VS-02`, `VS-05`, `VS-07`). Only the owner closes a slice, and exit criteria are never bent
([05](05-PHASES-AND-TASKS.md)). This page proposes; it closes nothing.

**Summary (2026-11-18):** slice 1, 4 of 5 gate items met; slice 2, 5 of 6; slice 5, 5 of 6; slice 7, 7 of 9. What is
left in every slice is the i18n half of the accessibility item: the check that shows every string of the slice's
screens is in `webapp/strings/` is built (`I18N-01`, below) and counts when `e2e` on `main` is green with it. Slice 7
also waits for a green `main` run with the anchoring proofs served and shown (`VS-07B`, merged in PR #20; its run
44077906918 failed only `dependency-policy`, fixed by PR #21, whose run 44155229736 had not finished when this was
written). Slice 1 also carries `S1-10` (below), found while watching its demo.

**Reference run.** `main` at `ebac68e` (PR #19), GitHub Actions run
[44023485128](https://github.com/CasualOffice/openseal/actions/runs/44023485128) (2026-11-17), every job green
(`checks`, `test` on ubuntu, macos and windows, `msrv`, `wasm-parity`, `dependency-policy`, `commit-messages`,
`validators`, `keyd-softhsm`, `store-db`, `server-db`, `e2e` 528 passed and 76 skipped, `compose-e2e` 165 passed and 375
skipped, `chaos-compose`, `backup-drill`). It is the latest green `main` run and carries all four demo artifacts. Earlier
green runs cited below: 43860204277 (`ea67292`), 44001061169, 44018844840. Every "Met" cites what was read in that
run's job log or artifacts; "passed" means the test is listed passed in a job that ended green.

**Gate items.** Slice 1 has its own boxes in docs/06. Slices 2, 5 and 7 have none; their gate is the general end point
in docs/06 §After Phase 2, copied verbatim: "an **outcome** (what a user can do), an **end point** (merged, CI green
including a browser run, docs/96 rows updated, demo recorded)" and "Accessibility (WCAG 2.2 AA) and i18n string
extraction are part of every UI slice's end point". The outcome is that slice's row in the docs/06 slice table.

**Demos.** All four are artifacts of run 44023485128 (expire 2027-02-15), downloaded on 2026-11-18, every video
non-empty, and frames taken across each video were looked at (ffmpeg, nine per video). What each shows is in
[65](65-RUNNING-IT.md) §Demos, which links them. Videos are never committed.

**i18n extraction (`I18N-01`).** `webapp/tests/i18n-slices.test.mjs` is this end point's own check, scoped to the
modules and pages of these slices' screens (sender: prepare, envelope and their parts; signer: `sign.html`, `sign.js`
and its steps, including recipient authentication; Verify; the shared `ui/` components). It is the "every string is in
`webapp/strings/`" half of the gate item, not a new repository gate: it fails when a module writes a literal with a
letter in it to a user-visible sink (`text`, `title`, `label`, `placeholder`, `alt`, `aria-label` and the other read
attributes, `data-glyph`, `textContent`, `append`, `toast`) or a page holds text or such an attribute not filled by
`data-i18n`. It was seen red on the tree before this change with nine findings (the two pages' `<title>`, the palette's
"esc" key cap, the position unit "pt", the field-kind letter glyphs "AB", "Aa", "Fn", "Ln", "Tt", "T", "i"), all now
messages; red again with `sign.html` and `ui/palette.js` restored (`'ui/palette.js:86: "esc"'`, `'sign.html: <title>
text "Sign · OpenSeal"'`). Also moved: Verify's "Event" fallback for an event with no type (`trail.js`, now
`audit.event`). It runs in `e2e` (`npm test`) and counts from the first green `main` run with it. The existing
`pure.test.mjs` check is the other direction (every key used has an English string).

**`S1-10`, found in the demos.** In the slice-1 and slice-2 sender videos the envelope page's Evidence card says
"Audit trail links do not match" on every real envelope. The page's link check (`managemodel.js` `auditLinks`) took
only bare hex; the server writes `sha256:<hex>` (casual-sign-server `audit`, `Hash256`), and the mock wrote bare hex, so
no mock-mode test could see it. Fixed: the check reads both, the mock now writes the server's shape, and the chain
head shows without the prefix. Seen red: `manage.test.mjs` "the server's own shape" (two `hash` problems) and
`audit-shape.test.mjs` (the mock's hash not `sha256:`), and in a browser, `manage.spec.mjs:74` with the old check and
the new mock (`Received string: "Audit trail links do not match…"`). `real-stack.spec.mjs` VS-01 now asserts "Audit
trail linked" on the real stack. The evidence itself was never wrong; only its display. Done when `e2e` and
`compose-e2e` are green on `main` with it.

## Slice 1 — Send and sign (`VS-01`)

| Gate item (docs/06, verbatim) | Status | Evidence, or what is missing |
| --- | --- | --- |
| Outcome through the API: a sender sends one signer a signature, date and text field; the signer signs; the worker seals; the sender and the signer (through the completion email's link, in a new browser) each get the sealed PDF and the certificate, the same bytes, accepted by our verifier and pyHanko. | Met | `casual-sign-worker` `tests/end_to_end.rs` `one_signer_gets_the_sealed_pdf_and_the_certificate_from_the_completion_email` `... ok` in `server-db`, `test (macos-latest)` and `test (windows-latest)` of run 43860204277. Seen red with the route removed (docs/06, 2026-11-13) |
| Outcome in a browser on the Compose stack, CI green: `real-stack.spec.mjs` "send and sign … (VS-01)" … runs in `compose-e2e` | Met | `compose-e2e` of run 44023485128: `real-stack.spec.mjs:179` "slice 1 (VS-01) › send and sign: one signer on a phone; both get the sealed PDF and the certificate (VS-01)" passed on chromium (14.4 s) and webkit (18.9 s). Also run 43860204277 and those listed in docs/06 |
| [96] rows updated (`FG-006`, `FG-055`, `FG-057`, `FG-072`, `FG-150`) | Met | docs/96: `FG-006`, `FG-055`, `FG-057`, `FG-072`, `FG-150` `Works`. `FG-124` (accessibility audit) is `A11Y-01`, a release gate, not a slice-1 item |
| Demo recorded (`S1-02`): … ticked when a green run's recording is linked from [65] | Met | Artifact `slice-1-demo` (14303626789, 7.2 MB, expires 2027-02-15) of green run 44023485128, linked from docs/65 §Demos; watched 2026-11-18: the editor, Sent, the signer on a phone (consent, Sign, adopt, "Signed. Thank you, Cara."), the envelope to Completed, both parties' downloads. The video shows the `S1-10` evidence-card defect, fixed on this branch |
| Accessibility (WCAG 2.2 AA) and i18n extraction: axe scans the editor (`a11y.spec.mjs`), every ceremony step (`a11y-sign.spec.mjs`) and the done screen with the certificate (`ceremony.spec.mjs` …), and every string is in `webapp/strings/`; ticked when `e2e` is green on GitHub with them | Not met (axe met; i18n waits for CI) | Axe: `e2e` of run 44023485128 passed `a11y.spec.mjs:50` (prepare, light and dark) and `:26` (envelope detail), `a11y-sign.spec.mjs:7` (every ceremony step, light and dark) on chromium, webkit and mobile, and `ceremony.spec.mjs:9` on chromium, webkit, mobile and reduced-motion. i18n: `I18N-01` built, seen red; met when `e2e` on `main` is green with it. S |

Recommendation: ready to close once `e2e` and `compose-e2e` on `main` are green with `I18N-01` and `S1-10`.

Owner decision: close / not yet, because …

## Slice 2 — Routing and recipient types (`VS-02`)

Outcome (docs/06): "Sequential, parallel, mixed; cc, viewer, approver, agent; decline; void; reminders; expiry".

| Gate item (docs/06, verbatim) | Status | Evidence, or what is missing |
| --- | --- | --- |
| outcome (what a user can do): Sequential, parallel, mixed; cc, viewer, approver, agent; decline; void; reminders; expiry | Met | In `server-db` of run 43860204277: `casual-sign-server` `tests/routing.rs` (parallel, mixed, cc, agent, approver, viewer through the ceremony); worker `tests/flow.rs` (decline), `tests/crash.rs` (reminders), `tests/expiry.rs` (expiry and warning). Sequential in a browser on the real stack: `real-stack.spec.mjs:107` "two signers in order sign through emailed links" passed in `compose-e2e` of run 44023485128 (chromium, webkit) |
| merged | Met | All on `main` |
| CI green including a browser run | Met | Run 44023485128 green. `compose-e2e`: `routing.spec.mjs:92` "slice 2 (VS-02): an approver, a viewer and an agent act in order through their links, the named signer signs; the sealed PDF and …" passed on chromium and webkit against the real server and Mailpit; `real-stack.spec.mjs:283` in-person signer passed. `e2e` (mock): `recipient-types.spec.mjs` passed |
| docs/96 rows updated | Met | Slice-2 rows: `FG-021`..`FG-024`, `FG-031`, `FG-035`, `FG-090`, `FG-094`, `FG-115`, `FG-116`, `FG-134`, `FG-135` `Works`; `FG-095` (expiration) and `FG-092` Partial; `FG-005`, `FG-038`, `FG-041` Designed; `FG-103` not started. The rows state the truth; M4, not M3, asks for `Works` |
| demo recorded | Met | Artifact `slice-2-demo` (14303182320, 11.7 MB, expires 2027-02-15) of green run 44023485128, linked from docs/65 §Demos; watched 2026-11-18: the sender's send and envelope page through Completed and the downloads; the approver approving, the viewer viewing, the agent naming the signer, the named signer signing, each through their emailed link (`RTE-04`) |
| Accessibility (WCAG 2.2 AA) and i18n string extraction | Not met (axe met; i18n waits for CI) | Axe: `a11y-sign.spec.mjs:65` "the approver's, viewer's and agent's steps are accessible" (light, dark) passed in `e2e` of run 44023485128 on chromium, webkit and mobile. i18n: `I18N-01`, as slice 1. S |

Recommendation: ready to close once `e2e` on `main` is green with `I18N-01`. The owner may also weigh `FG-095` and
`FG-092` being Partial; the gate asks only that docs/96 is true.

Owner decision: close / not yet, because …

## Slice 5 — Recipient authentication and consent (`VS-05`)

Outcome (docs/06): "Access code, email OTP, SMS OTP, phone call, OIDC; versioned ERSD; withdraw consent".

| Gate item (docs/06, verbatim) | Status | Evidence, or what is missing |
| --- | --- | --- |
| outcome (what a user can do): Access code, email OTP, SMS OTP, phone call, OIDC; versioned ERSD; withdraw consent | Met | In `server-db` of run 43860204277: `casual-sign-server` `tests/ceremony_auth.rs` (access code, withdraw; 5 passed), `tests/ceremony_sso.rs` (OIDC), `tests/disclosure.rs`, `tests/ersd_publish.rs` (versioned ERSD); worker `tests/email_otp.rs`, `tests/sms_otp.rs` (SMS and voice) |
| merged | Met | All on `main` |
| CI green including a browser run | Met | `compose-e2e` of run 44023485128 (and 44018844840): `recipient-auth.spec.mjs:187` "an access code, codes by email, text message and phone call, then consent and its withdrawal" and `:203` "sign-in through an identity provider comes back to the signing page" passed on chromium and webkit against the real server, with the SMS and OpenID Connect stubs of `tools/e2e/compose.e2e.yml` |
| docs/96 rows updated | Met | `FG-111`, `FG-117`, `FG-118`, `FG-119`, `FG-217` `Works`; `FG-177` (ERSD editing) Partial, real-stack e2e left; `FG-039`, `FG-040` (SMS and WhatsApp delivery) not started (`MSG-02`) |
| demo recorded | Met | Artifact `slice-5-demo` (14303611682, 5.0 MB, expires 2027-02-15) of green run 44023485128, linked from docs/65 §Demos; watched 2026-11-18: the email, SMS and voice code steps on a phone; sign-in through the identity provider; the withdraw dialog and "You withdrew your consent" |
| Accessibility (WCAG 2.2 AA) and i18n string extraction | Not met (axe met; i18n waits for CI) | Axe: `recipient-auth.spec.mjs:228` "the code entry, sign-in and withdraw steps are accessible" (light, dark) passed in `e2e` of run 44023485128 on chromium, webkit and mobile (axe with WCAG 2.2 AA tags at phone width on the access-code step, each sent-code step before and after asking and with a wrong code, the sign-in step, the withdraw dialog and the withdrawn screen). i18n: `I18N-01`, as slice 1; the authentication steps are in `sign.js` |
| (tracker, not a docs/06 item) ADR-033 accepted | Met | Accepted by the owner, instruction 54 (2026-11-17); docs/08 records it; `RAUTH-01` Done on `server-db` of run 44001061169 |

Recommendation: ready to close once `e2e` on `main` is green with `I18N-01`.

Owner decision: close / not yet, because …

## Slice 7 — Verify (`VS-07`)

Outcome (docs/06): "`verify.html` offline in WASM; CLI; B-LT default option; public anchoring". Split into its four
parts below.

| Gate item (docs/06, verbatim) | Status | Evidence, or what is missing |
| --- | --- | --- |
| `verify.html` offline in WASM | Met | `e2e` of run 44023485128 built the verifier ("The verifier is there" step) and passed, not skipped, `web02.spec.mjs:236` (a sealed PDF verifies against its trust root), `:257` (tampered), `:266` (the attached audit trail), `:279` (not a PDF) and `signin-dashboard.spec.mjs:171`, `:189` on chromium and webkit. `compose-e2e` serves it from the image |
| CLI | Met | `crates/casual-sign-cli/tests/cli.rs` `seal_b_t_over_http_tsa_then_verify_and_detect_tamper`, `seal_b_b_then_verify_indeterminate_without_revocation`, `audit_verify_detects_an_edit` `... ok` in `test (windows-latest)` and `test (macos-latest)` of run 43860204277 |
| B-LT default option | Met as an account default; owner to confirm the reading | `casual-sign-worker/tests/end_to_end.rs` `an_account_defaulting_to_b_lt_gets_long_term_seals_verified_by_pyhanko ... ok` in `server-db` of run 44023485128: an account's `default_seal_profile` (Admin → Organization, `PATCH /accounts/me`) makes new envelopes seal at B-LT, our verifier and pyHanko (`ltv=0:ok`, hard-fail revocation) accept them. Not built: a per-envelope seal-level control in the editor (the API takes `seal_profile`), a Compose run at B-LT. `FG-154` Partial |
| public anchoring | Not met (waits for a green run) | Worker, store and CLI met on run 44023485128: `server-db` passed `a_day_is_anchored_once_and_its_leaves_are_append_only`, `a_closed_day_is_anchored_and_each_envelope_proves_its_head`, the two crash-restart tests; CLI `anchor verify`. Served and shown (`VS-07B`, PR #20, `main` at `f794c21`): run 44077906918 passed `verify-anchor.spec.mjs:50`, `:63`, `:75`, `:87`, `:97`, `:105` on chromium and webkit and the server's `tests/anchor_proof.rs` in `server-db`, but the run failed on `dependency-policy` (four zip advisories, fixed by PR #21). Met when a `main` run with PR #20 is green on every job (44155229736 or later). Not built: the proof in the signer's downloads (`VS-07D`) |
| merged | Met | All of the above is on `main` |
| CI green including a browser run | Met | Run 44023485128 green, with the WASM verifier specs run, not skipped, in `e2e` (first item) |
| docs/96 rows updated | Met | `FG-157` `Works`, `FG-154` Partial, `FG-158` `Works`: each states what is built |
| demo recorded | Met | Artifact `slice-7-demo` (14304121907, 2.0 MB, expires 2027-02-15) of green run 44023485128 (`verify-demo.spec.mjs:24` passed on chromium and webkit), linked from docs/65 §Demos; watched 2026-11-18: a trusted certificate added, a sealed PDF "Signed and unchanged", a tampered one "Changed or broken" with the failed check marked (`VS-07A`) |
| Accessibility (WCAG 2.2 AA) and i18n string extraction | Not met (axe met; i18n waits for CI) | Axe: `a11y.spec.mjs:83` "verify: start, valid, tampered and refused" (light, dark) passed in `e2e` of run 44023485128 on chromium and webkit; `verify-anchor.spec.mjs` scans each anchor state (run 44077906918). i18n: `I18N-01`, as slice 1 (`verify.html`'s title and the trail's "Event" fallback moved). S |

Recommendation: ready to close once a `main` run is green on every job with PR #20 and `I18N-01`, if the owner reads
"B-LT default option" as the account default that is built.

Owner decision: close / not yet, because …

**Decisions only the owner can make** (each is a reading of the gate, so this page cannot make it):

1. Slice 7, "B-LT default option": does an account-level default (built, tested to pyHanko) meet it, or must the send
   editor also offer B-LT per envelope (and a Compose run at B-LT) before the slice closes?
2. Slice 7, "public anchoring": does it close with the anchor served by the API and shown on the Verify page, leaving
   the proof in the signer's own downloads (`VS-07D`) to a later slice, or is `VS-07D` part of this one?
3. Every slice, "i18n string extraction": does the focused check `I18N-01` (above) count as the evidence that every
   string of the slice's screens is in `webapp/strings/`?
4. Each slice: close, having watched its demo (docs/65 §Demos).

## Not met, by size

| Slice | Item | Size |
| --- | --- | --- |
| 1, 2, 5, 7 | i18n extraction shown: `I18N-01` on a green `main` `e2e` | S |
| 1 | `S1-10` on a green `main` (`e2e`, `compose-e2e`) | S |
| 7 | Public anchoring: a green `main` run with PR #20 (`VS-07B`) | S |
| 7 | B-LT per-envelope editor control and a Compose run at B-LT, if the owner reads the gate so | M |
| 7 | The anchor proof in the signer's downloads (`VS-07D`), if the owner reads the gate so | L |

Nothing here states that any signature is legally valid or that the product is compliant or certified (docs/09).
