# 75 — Slice 4 evidence (every field)

Evidence for the owner to close slice 4, **Every field** ([06](06-ROADMAP-AND-DELIVERY.md) §After Phase 2; tracker row
`VS-04`), in the format of [74](74-SLICE-3-EVIDENCE.md). Only the owner closes a slice, and exit criteria are never
bent ([05](05-PHASES-AND-TASKS.md)). This page proposes; it closes nothing.

**Summary (2026-11-19):** the slice is **not ready to close**. Of its nine outcome elements, six are built end to end
on a worktree branch in docs/06 order (full field set, validation, conditional fields, groups, formulas, linked
fields), with server tests on PostgreSQL seen red, web unit tests seen red, and a browser spec (`fields.spec.mjs`) in
mock mode; none is yet in a green `main` run. Three are missing as product features although their engine is built
and tested: **shared fields** (`VS-04D`, no engine either), **anchors and text tags** through the API and editor
(`VS-04E`), and **AcroForm conversion** through the API and editor (`VS-04F`). The end point waits on those and on CI.

**Reference run.** No `main` run carries this work yet. The latest `main` run read, 44432837346 (`af038fd`, slice 3),
finished red in `e2e (3)` (two webkit tests in `prepare-layout.spec.mjs`, outside this slice). Items marked
**branch** were run locally on the worktree branch (PostgreSQL 55432, Playwright headless) and are not in any CI run.

**Gate items.** Slice 4 has no boxes in docs/06; its gate is the general end point of docs/06 §After Phase 2: an
outcome, then "merged, CI green including a browser run, docs/96 rows updated, demo recorded", with accessibility
(WCAG 2.2 AA) and i18n string extraction. The outcome is the slice-4 row: "Full field set, validation, conditional
fields, groups, formulas, linked and shared fields, anchors, text tags, AcroForm conversion".

**Readings chosen** (the outcome does not say; the closest DocuSign and SignNow behaviour, docs/48–49):

- *Full field set*: every kind of the engine's `FieldType` but `payment`, which is slice 13 (`FG-070`). Stamp and
  drawing are adopted as DocuSign adopts a stamp, through the same adopt step as a signature, recorded with their own
  `mark` (`stamp`, `drawing`; the audit enum is `#[non_exhaustive]` and the change is additive); each fills only a
  field of its own kind, and the certificate's signature art is never one of them. Approve and Decline are DocuSign's
  tabs: buttons that finish and decline. A hyperlink opens only `http:` and `https:` addresses.
- *Rules on the signing page*: the server, not a second implementation, says what is hidden, computed and mirrored.
  The signing view carries `rules` from `casual_sign_fields::evaluate_envelope`, the code that runs at finish and at
  sealing (ADR-022: the server believes only its own answer). WebAssembly was not added to the signing page, whose
  CSP forbids it (`web.rs` tests); a value shows its effect when it is saved (on leaving the field), as DocuSign's do.
- *Linked fields*: DocuSign's rule, as the engine has it: one recipient, one data label, one value.
- *Conditions and formulas across recipients*: the engine evaluates over every field; the view names only this
  recipient's fields, and no other recipient's value is shown except as one of theirs mirrors or computes from it,
  as the sealed document will show it anyway.

## Outcome

| Element (docs/06) | Status | Evidence, or what is missing |
| --- | --- | --- |
| Full field set | Built (branch) | `VS-04A`. Server `tests/every_field.rs` `every_field_kind_is_filled_checked_adopted_and_drawn` (row-level security on): date in its format, email address, phone, SSN, ZIP, multi-select, a regex rule, stamp, drawing, envelope id, formula, hyperlink, approve and decline; each kind's bad value refused; server-filled, display and button kinds take no value; a stamp's capture refused in a signature field; the chain's `mark` for each adoption; every value found in the drawn preview. Seen red: the stamp guard widened to accept a stamp in a signature field (`assertion left == right failed: a stamp signed`, `200` for `422`). Earlier kinds: `tests/field_types.rs` (`WEB-06`). Signing page: `sign.js` fills each kind; web `tests/slice4.test.mjs` (seen red against the old `signfields.js`: 7 of 8 failing). Editor: every kind but payment in the palette (`geometry.js` `FIELD_TYPES`, `editor.test.mjs`). Browser: `fields.spec.mjs` fills every kind and completes (mock, chromium). Missing: a green `main` run; the Compose run |
| Validation | Built (branch) | `VS-04A`. The page checks each rule as the engine (`signfields.js` `ruleFor`, `isSsn`, `isDate`, regex compiled as a whole-value match, the sender's message); the engine refuses on every fill and at finish. `tests/every_field.rs` (each refusal), `slice4.test.mjs` (the same examples), `fields.spec.mjs` (an invalid SSN and date said beside the field). Missing: a green `main` run |
| Conditional fields | Built (branch) | `VS-04C`. Editor: Logic panel (parent label; checked, not checked, filled in, a value). Server: the view's `rules.hidden`; a hidden field is never required and its value dropped. `tests/every_field.rs` `the_signing_view_carries_the_servers_rules_as_the_signer_fills`, seen red with `rules` removed (the test panicked at `every_field.rs:358`, reading `rules.hidden`). Browser: the detail field appears when "agree" is ticked (`fields.spec.mjs`); the editor's Logic test checks the stored member. Missing: a green `main` run |
| Groups (checkbox group rules) | Built (branch) | `VS-04C`. Editor: group name and rule (at least, at most, exactly). Finish refused naming each box until the rule holds (`422`, `errors[].pointer` `/fields/{id}`, new in this slice), `tests/every_field.rs`. Browser: a box ticked to satisfy the group before finishing. Radio groups were slice 1–2 (`FG-062`). Missing: a green `main` run |
| Formulas | Built (branch) | `VS-04C`. Editor: expression and decimal places. The view's `rules.computed` is the server's result after each fill, sealed with it (`9.00` drawn). `tests/every_field.rs`; browser: the total shows `9.00` after quantity and price. The mock answers with `fieldrules.js`, a stand-in for mock mode only (`slice4.test.mjs`, `slice4-mock.test.mjs`). Missing: a green `main` run |
| Linked fields | Built (branch) | `VS-04C`. Same recipient and label: the view's `rules.values` mirror the value, both sealed with it (`R-77` drawn twice). Browser: the second "ref" shows the first's value. Missing: a green `main` run |
| Shared fields | Missing | `VS-04D` (`FG-074`): one field several recipients may fill. Needs a model member, the engine's editable rule, the API and the editor |
| Anchors | Missing (engine built) | `VS-04E` (`FG-077` Engine): `place_anchor` is built and tested, and in the WASM verifier build; the API refuses `anchor` on a field (`deny_unknown_fields`), docs/40 §3 shows it as designed |
| Text tags | Missing (engine built) | `VS-04E` (`FG-078` Engine): `scan_tags` is built and tested; no `"text_tags": true` on create or send |
| AcroForm conversion | Missing (engine built) | `VS-04F` (`FG-008`, `FG-015` Engine): `convert_acroform` is built, and `detect-fields` already offers converted fields as suggestions (`source: acroform`) that the editor can place; there is no conversion on upload with each field assigned, and no fill-in-place send option |

## End point

| Gate item (docs/06, verbatim) | Status | Evidence, or what is missing |
| --- | --- | --- |
| merged | Not met | The branch carries `VS-04A`, `VS-04B`, `VS-04C`; merged by the main session after it verifies them |
| CI green including a browser run | Not met (waits for CI and `VS-04D`–`F`) | Run locally on the branch: `cargo test -p casual-sign-server --test every_field` (2 passed); clippy `-D warnings` on audit, workflow, server, worker; `cargo check --target wasm32-unknown-unknown` on audit and workflow; `npm test` in `webapp/` (293 passed); `fields.spec.mjs` in mock mode. Met when `server-db`, `e2e` and `compose-e2e` are green on `main` with `fields.spec.mjs` passed on the Compose stack, and the missing elements are built |
| docs/96 rows updated | Met (for what is built) | `FG-053`, `FG-056`, `FG-058`, `FG-059`, `FG-060`, `FG-061`, `FG-064`, `FG-067`, `FG-068`, `FG-069`, `FG-073`, `FG-075` now Partial, each naming its test and "`Works` once `fields.spec.mjs` is green on `main`"; `FG-074`, `FG-077`, `FG-078`, `FG-008`, `FG-015` unchanged. Not in this pass: `FG-052` optional signature, `FG-037` free-form signer, `FG-079` field presets, `FG-082` 3,000 fields, colour in `FG-076`, `FG-014` dynamic XFA (rows below) |
| demo recorded | Not met (waits for CI) | `compose-e2e` uploads `target/e2e-demo/vs04-*` as `slice-4-demo` (`.github/workflows/ci.yml`, the slice-3 pattern): the signer filling every kind, a condition showing a field, a formula computing, linked fields mirroring. Met when a green `main` run carries it and it is watched and linked from [65](65-RUNNING-IT.md) §Demos |
| Accessibility (WCAG 2.2 AA) and i18n string extraction | Not met (waits for CI) | Axe: `fields.spec.mjs` scans every field kind on the signing page, the multi-select panel, the drawing pad, and the editor's Logic panel with and without a formula, light and dark (mock, chromium). The dark scan found an optional field's blue at 2.03:1 on the page (a defect before this slice, unseen because no scanned envelope had an optional field); fixed with `--os-sign-optional`. i18n: `i18n-slices.test.mjs` now covers `fieldlogic.js`, `geometry.js`, `fieldrules.js` (sign.js, signfields.js, signature.js and prepare.js were covered); seen red with a literal "Give this field a data label" in `prepare.js` (`'prepare.js:1691: "Give this field a data label"'`); every new string in `webapp/strings/`. Met when `e2e` is green on `main` with them |

Recommendation: not ready. Build `VS-04D`, `VS-04E`, `VS-04F` (in that order, the docs/06 order), then propose closure
on the first green `main` run carrying all of them.

**Decisions only the owner can make:**

1. "Full field set": does it include optional signature (`FG-052`), the free-form signer (`FG-037`), saved field
   presets (`FG-079`), 3,000 fields per envelope (`FG-082`), colour (`FG-076`) and dynamic XFA (`FG-014`), all marked
   slice 4 in docs/96 but not named in the docs/06 outcome?

## Found and not fixed

| Row | What | Size |
| --- | --- | --- |
| `VS-04D` | Shared fields (`FG-074`) | M |
| `VS-04E` | Anchors and text tags through the API and editor | M |
| `VS-04F` | AcroForm conversion through the API and editor; fill in place | M |
| `VS-04G` | The rest of docs/96's slice-4 rows outside the outcome's words (`FG-052`, `FG-037`, `FG-079`, `FG-082`, colour of `FG-076`) | M |
| `VS-04H` | A capture is named by its image: one image adopted as a signature and as a stamp is one capture, so the stamp guard cannot tell them apart (found by `tests/every_field.rs`); the capture document should carry its mark | S |

Nothing here states that any signature is legally valid or that the product is compliant or certified (docs/09).
