# 75 — Slice 4 evidence (every field)

Evidence for the owner to close slice 4, **Every field** ([06](06-ROADMAP-AND-DELIVERY.md) §After Phase 2; tracker row
`VS-04`), in the format of [74](74-SLICE-3-EVIDENCE.md). Only the owner closes a slice, and exit criteria are never
bent ([05](05-PHASES-AND-TASKS.md)). This page proposes; it closes nothing.

**Summary (2026-11-19, second pass):** every one of the nine outcome elements is now built end to end on the worktree branch, in docs/06 order, with server tests on PostgreSQL seen red, web unit tests seen red and a browser spec (`fields.spec.mjs`) in mock mode on chromium. None is in a green `main` run yet, so none is Met. Shared fields (`VS-04D`), anchors and text tags (`VS-04E`) and AcroForm conversion in the editor (`VS-04F`) were added in this pass, with the capture fix `VS-04H`. What is left is what only CI proves (`server-db`, `e2e` on webkit, `compose-e2e` with the demo), and the readings the owner may want changed (below).

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
| Shared fields | Built (branch) | `VS-04D`. DocuSign's shared tabs: `shared_with` on a field (model, engine, API by id or `ref`, editor "Also filled by", ceremony, mock). Refused at send when shared with its own recipient, a recipient twice, one who does not sign or cannot see the document (`CS-WF-0004`). Server `tests/every_field.rs` `a_shared_field_is_filled_by_each_recipient_it_is_shared_with_the_last_value_kept`: three refusals; the first signer fills, the second sees the value and changes it, each change its own `recipient.field_completed`, the last value sealed. Seen red with the engine's editable rule unchanged (the second signer's change `409`, the test panicking in `ok` at `flow.rs:17`). Web: `slice4-mock.test.mjs`, seen red against the old mock (1 passed, 2 failed). Not on template fields (a role has no recipient id yet). Missing: a green `main` run |
| Anchors | Built (branch) | `VS-04E` (`FG-077`). `anchor` on a field in create and `POST /fields`, resolved at once against the delivered document by the engine's `place_anchor` (now `casual_sign_sdk::Engine::place_anchors`): one field per match, or the first; offsets in points, inches, millimetres, centimetres or pixels; the field's own size or its kind's default. An absent anchor is `422 CS-FLD-0010` at `/fields/{i}/anchor` unless `ignore_if_absent`. Server `tests/anchors_tags.rs`; seen red with anchors not placed (`CS-FLD-0002` at `/fields/0`). Reading: anchors are an API feature, as in DocuSign; the editor places by hand or by Detect fields and has no "place at text" control. Missing: a green `main` run |
| Text tags | Built (branch) | `VS-04E` (`FG-078`). `"text_tags": true` on create places a field at each tag, its recipient the request's `ref`; a malformed tag is `422 CS-FLD-0011`. Detect fields also suggests each tag (`source: tag`), so the editor places them. `tests/anchors_tags.rs`, seen red without the suggestions (`anchors_tags.rs:119`); browser: the tag's date field suggested and placed (`fields.spec.mjs`). The tag text stays in the document as the signer sees it (`VS-04I`). Missing: a green `main` run |
| AcroForm conversion | Built (branch) | `VS-04F` (`FG-008`). Detect fields suggests a PDF's own form fields (`source: acroform`, named after the form field), and the editor places them for the chosen signer: every kind is now placeable, so a form's text boxes, check boxes, choices and signature fields all land. Browser: `fields.spec.mjs` "a PDF's own form fields and its text tags are suggested in the editor and placed" (the text box keeps the name `policy_number` as its data label); mock `slice4-mock.test.mjs`, seen red against the old mock. Only `compose-e2e` shows the real server converting the test's form. Filling the form in place (`FG-015`) as a send option is not offered (`VS-04J`). Missing: a green `main` run |

## End point

| Gate item (docs/06, verbatim) | Status | Evidence, or what is missing |
| --- | --- | --- |
| merged | Not met | The branch carries `VS-04A`, `VS-04B`, `VS-04C`; merged by the main session after it verifies them |
| CI green including a browser run | Not met (waits for CI and `VS-04D`–`F`) | Run locally on the branch: `cargo test -p casual-sign-server --test every_field` (2 passed); clippy `-D warnings` on audit, workflow, server, worker; `cargo check --target wasm32-unknown-unknown` on audit and workflow; `npm test` in `webapp/` (293 passed); `fields.spec.mjs` in mock mode on chromium (the slice test and the axe tests passed; webkit and the neighbouring specs could not be judged locally: a run of five specs on both browsers timed out across old and new tests alike at a load average over 200, so only CI shows webkit). Met when `server-db`, `e2e` and `compose-e2e` are green on `main` with `fields.spec.mjs` passed on the Compose stack, and the missing elements are built |
| docs/96 rows updated | Met (for what is built) | `FG-053`, `FG-056`, `FG-058`, `FG-059`, `FG-060`, `FG-061`, `FG-064`, `FG-067`, `FG-068`, `FG-069`, `FG-073`, `FG-075`, `FG-074`, `FG-077`, `FG-078`, `FG-008` now Partial, each naming its test and "`Works` once `fields.spec.mjs` is green on `main`"; `FG-015` unchanged (`VS-04J`). Not in this pass: `FG-052` optional signature, `FG-037` free-form signer, `FG-079` field presets, `FG-082` 3,000 fields, colour in `FG-076`, `FG-014` dynamic XFA (rows below) |
| demo recorded | Not met (waits for CI) | `compose-e2e` uploads `target/e2e-demo/vs04-*` as `slice-4-demo` (`.github/workflows/ci.yml`, the slice-3 pattern): the signer filling every kind, a condition showing a field, a formula computing, linked fields mirroring. Met when a green `main` run carries it and it is watched and linked from [65](65-RUNNING-IT.md) §Demos |
| Accessibility (WCAG 2.2 AA) and i18n string extraction | Not met (waits for CI) | Axe: `fields.spec.mjs` scans every field kind on the signing page, the multi-select panel, the drawing pad, and the editor's Logic panel with and without a formula, light and dark (mock, chromium). The dark scan found an optional field's blue at 2.03:1 on the page (a defect before this slice, unseen because no scanned envelope had an optional field); fixed with `--os-sign-optional`. i18n: `i18n-slices.test.mjs` now covers `fieldlogic.js`, `geometry.js`, `fieldrules.js` (sign.js, signfields.js, signature.js and prepare.js were covered); seen red with a literal "Give this field a data label" in `prepare.js` (`'prepare.js:1691: "Give this field a data label"'`); every new string in `webapp/strings/`. Met when `e2e` is green on `main` with them |

Owner decision (2026-11-20, instruction 68): close once `main`'s CI run on `6bd9646` is green. 2026-11-20: `main` run 44605190804 on `6bd9646` finished red in `e2e (2)` and `e2e (6)`, the same stale test (`prepare-layout.spec.mjs:185`, the palette's field-kind count 16 → 29, chromium and webkit), fixed in PR #36; every other job green. Not closed on it: the main session closes it on the first green `main` run after #36 merges.

Recommendation: ready to propose for closure once a `main` run with this branch is green on every job and `slice-4-demo` has been watched.

**Decisions only the owner can make:**

0. "Anchors": is the API (DocuSign's anchor tabs) enough, or must the editor also place a field at typed text?
1. "Full field set": does it include optional signature (`FG-052`), the free-form signer (`FG-037`), saved field presets (`FG-079`), 3,000 fields per envelope (`FG-082`) and colour (`FG-076`)? **Decided 2026-11-20 (owner instruction 67): not part of slice 4;** each stays its own row (`FLD-OPT-01`, `FLD-FREE-01`, `FLD-PRESET-01`, `FLD-3K-01`, `FLD-COLOUR-01`), picked up in plan order. Dynamic XFA (`FG-014`) stays with `XFA-02`..`XFA-05`.

## Found and not fixed

| Row | What | Size |
| --- | --- | --- |
| `FLD-OPT-01`, `FLD-FREE-01`, `FLD-PRESET-01`, `FLD-3K-01`, `FLD-COLOUR-01` | Outside slice 4 by owner instruction 67 (`VS-04G`) | M |
| `VS-04I` | Text tags stay visible in the delivered and sealed document (DocuSign and SignNow advise white tag text; hiding it would change the document the signer reviews) | S |
| `VS-04J` | Fill a PDF's own form in place and keep it fillable (`FG-015`) as a send option, beside flattening | M |

Nothing here states that any signature is legally valid or that the product is compliant or certified (docs/09).
