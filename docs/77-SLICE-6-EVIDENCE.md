# 77 — Slice 6 evidence (Manage and correct)

Evidence for the owner to close slice 6, **Manage and correct** ([06](06-ROADMAP-AND-DELIVERY.md) §After Phase 2;
tracker row `VS-06`), in the format of [76](76-SLICE-8-EVIDENCE.md). Only the owner closes a slice, and exit criteria
are never bent ([05](05-PHASES-AND-TASKS.md)). This page proposes; it closes nothing.

**Summary (2026-11-20, first pass):** of the nine outcome elements, seven are built end to end on the worktree branch
with tests seen red (folders and quick views except restoring a deleted envelope, search, correct, resend, copy,
transfer, editor and intermediary types, reports and CSV); none is yet in a green `main` run. Two are short: Word,
Excel and PowerPoint conversion waits for the owner (ADR-042 Proposed, question 1), and restoring a deleted envelope
waits for ADR-031 (Proposed since 2026-11-13, question 2). The plan's rows for this slice: `UXW-02` (restore left),
`UXW-20` (one evidence-package download left), `UXW-42` (seen red against a server without the endpoints left),
`WEB-07` (its Compose test is written here, in `manage-correct.spec.mjs`).

**Reference run.** The last `main` run green on every job before this branch is 44610734814 (`f667422`). Slice 8
(PR #37) merged into `main` at `7763dd1` and this branch is merged with it at `abfaf78`. Items marked **branch** ran
locally (PostgreSQL 55432; Playwright headless, mock mode, one worker) and are in no CI run.

**Gate items.** Slice 6 has no boxes in docs/06; its gate is the general end point of docs/06 §After Phase 2: the
outcome, then "merged, CI green including a browser run, docs/96 rows updated, demo recorded", with accessibility
(WCAG 2.2 AA) and i18n string extraction. The outcome is the slice-6 row: "Folders and quick views, search, correct,
resend, copy, transfer; editor and intermediary types; Word, Excel, PowerPoint uploads converted; reports and CSV".

**Readings chosen** (the outcome does not say; DocuSign's behaviour, docs/48):

- *Quick views*: DocuSign's five (Action Required, Waiting for Others, Expiring Soon, Completed, Authentication
  Failed). "Authentication failed" is an envelope in progress with a recipient locked out, or failed and not passed
  since; a resend clears it (the engine already resets failures on resend).
- *Search*: text, recipient, sender, status, date ranges (built before) and envelope custom fields (FG-132, FG-139),
  which needed custom fields themselves: sender metadata, never part of the agreement or its evidence.
- *Correct*: recipients, expiry and reminders (the Correct panel, built before) and documents and fields, through
  the editor opened on the sent envelope (DocuSign opens its editor to correct).
- *Copy*: a new draft with the same documents, recipients and fields (client-side through the API, built before).
- *Editor and intermediary*: offered in the editor; the editor names later recipients and then signs; the
  intermediary updates later recipients (name and email) and finishes. An editor changing fields at the ceremony and
  an intermediary changing authentication are `VS-06A`.
- *Reports and CSV*: DocuSign's envelope, recipient and usage reports, computed on the server for the whole
  workspace, as CSV.

## Outcome

| Element (docs/06) | Status | Evidence, or what is missing |
| --- | --- | --- |
| Folders and quick views | Built (branch), restore missing | Folders, Move and the Deleted view are on `main` (`UXW-02`; `inbox-folders.spec.mjs` green on chromium and webkit in `compose-e2e`, runs 43481106364 and later). New: `GET /envelopes?auth_failed=true` and `?expires_before=` (`-server` `tests/manage_views.rs`, seen red with the filter disabled in the handler: `left: ["Later", "Never", "Soon"] right: ["Soon"]`; and the auth-failed test failed with it); the Authentication failed view in Agreements (`managemodel.js`, `agreementparts.js`), web `tests/slice6.test.mjs` seen red with the mock's filter and the view's check removed (3 failed); `manage-correct.spec.mjs` (a wrong access code puts the envelope in the view, a resend takes it out). **Missing:** restoring a deleted envelope (`UXW-43`), blocked on ADR-031 Proposed (question 2) |
| Search | Built (branch) | Text, recipient, sender, status and date search on `main` (`WEB-04`, `WEB-08`, `UXW-03`). New: envelope custom fields `GET`/`PUT /envelopes/{id}/custom-fields` and `?custom_field=&custom_value=` (`tests/manage_views.rs`, seen red with the search dropped in the handler: `left: ["Later", "Never", "Soon"] right: ["Soon"]` at line 177); the envelope page's Custom fields card and panel, the Agreements filter (`manage-correct.spec.mjs` step 4); mock and unit tests (`slice6.test.mjs`) |
| Correct | Built (branch) | Recipients, expiry and reminders on `main` (`UX-07`, server `tests/correct.rs`). New: documents and fields in the editor's Correct mode (`#/prepare/{id}?correct=1`, "Correct documents and fields" on the envelope page, no autosave, "Save correction"); a saved document can be removed (`api.js` `deleteDocument`). Server `tests/correct_documents.rs`: a document added while sent, a field on it, the document a signer finished on removed sends them back to sign; seen red with the engine's touched-document redo disabled (`left: "completed" right: "completed"`, "signer 1 acts again"). Browser: `manage-correct.spec.mjs` step 5 adds an annex in Correct mode; it was red before the route took a query (`#/prepare/{id}?correct=1` matched no route: "Correcting:" not found) |
| Resend | Built (branch, real stack) | Server and web on `main` (`WF-04`, FG-135 `Works`); new on the real stack: `manage-correct.spec.mjs` step 3 resends from the envelope page and the Authentication failed view lets it go (the resend clears the lock). Mock mode passed on chromium and webkit; `compose-e2e` only on CI |
| Copy | Built (branch, real stack) | `copyEnvelope` on `main` (FG-136 `Works`, mock e2e `manage.spec.mjs`); new on the real stack: `manage-correct.spec.mjs` step 6 (More → Copy opens the "(copy)" draft) |
| Transfer | Built (branch) | `POST /envelopes/{id}/transfer` on `main` (`ORG-09`). New: the envelope page's Transfer panel (`transferPanel`, a member of the workspace; `ORG-41`), `api.js` `transferEnvelope`, the mock's transfer (`slice6.test.mjs`), `manage-correct.spec.mjs` step 8 ("Ownership transferred" in the trail) |
| Editor and intermediary types | Built (branch), ceremony field editing missing | Engine, server and signing page handled both before; new: offered in the editor (`RECIPIENT_TYPES_READY`), an editor takes fields, the send summary names both. Server `tests/editor_intermediary.rs`: an editor names the signer and signs, an intermediary updates the signer and finishes, the signer signs, the envelope goes to its seal; seen red with Editor taken out of `edits_recipients` ("an editor's view lists later recipients"). Web `slice6.test.mjs` seen red with `people.js` as before. **Missing (`VS-06A`):** an editor changing fields at the ceremony (the engine allows it; no endpoint or screen) and an intermediary changing authentication |
| Word, Excel, PowerPoint uploads converted | **Missing** (owner question 1) | ADR-021 (Accepted) chose the seam and the order; the concrete build adds dependencies (OpenCalc's and OpenPresent's import and PDF renderers, a LibreOffice image for `.docx`) and a new Compose service, so it is written as ADR-042 **Proposed** and not built (`VS-06C`). docs/30 §3 says so; docs/07 `SEC-P13` stays Planned |
| Reports and CSV | Built (branch) | The page's own envelope report and CSV on `main` (`UX-08`). New: `GET /reports/{envelopes,recipients,usage}` as JSON or formula-safe CSV (`reports.read`; `UXW-25`); "Full reports" on the Reports page. Server `tests/reports.rs` seen red with the formula guard removed (`=HYPERLINK` unquoted); unit test `a_cell_a_spreadsheet_would_run_is_written_as_text`; web `slice6.test.mjs` seen red with the mock's route removed; `manage-correct.spec.mjs` step 7 downloads the recipient report |

## End point

| Gate item (docs/06, verbatim) | Status | Evidence, or what is missing |
| --- | --- | --- |
| merged | Not met | The worktree branch carries the slice; merged by the main session after it verifies it |
| CI green including a browser run | Not met (waits for CI) | Branch: `cargo test -p casual-sign-server` for `manage_views`, `correct_documents`, `editor_intermediary`, `reports`, `contract`, `isolation` on PostgreSQL; clippy `-D warnings` on server and store; the sqlx offline cache regenerated; `npm test` in `webapp/` (311 passed); `manage-correct.spec.mjs` mock mode on chromium and webkit (3 passed each); the specs that count views and menus re-run on chromium (below). Only CI shows `compose-e2e` (the real-stack steps, Mailpit links, `WEB-07`) and `server-db` on Linux |
| docs/96 rows updated | Met (for what is built) | `FG-130`, `FG-131`, `FG-132`, `FG-133`, `FG-137`, `FG-139`, `FG-140`, `FG-025`, `FG-026` Partial naming their tests and what makes them `Works` (a green `main` run); `FG-002` waits for question 1 |
| demo recorded | Not met (waits for CI) | `compose-e2e` uploads `target/e2e-demo/vs06-*` as `slice-6-demo-${{ matrix.shard }}` (`.github/workflows/ci.yml`, the slice-8 pattern). Met when a green `main` run carries it and it is watched and linked from [65](65-RUNNING-IT.md) §Demos |
| Accessibility (WCAG 2.2 AA) and i18n string extraction | Not met (waits for CI) | Axe in `manage-correct.spec.mjs`, light and dark, chromium and webkit (mock): the Authentication failed view, the envelope page with custom fields, the custom fields and transfer panels, the editor in Correct mode, Reports with Full reports. i18n: `i18n-slices.test.mjs` now covers `dashboard.js`, `managemodel.js`, `inspector.js`, `home.js`, `reports.js`, `reportmodel.js`; it went red on the New button's shortcut key ("N"), now marked as not language; every new string is in `webapp/strings/` |

Recommendation: not ready to propose for closure: conversion (question 1) and envelope restore (question 2) are
outcome elements; the editor's field editing at the ceremony (`VS-06A`) and the evidence-package download
(`UXW-20`) are short as well. Everything else waits for a green `main` run with this branch and the demo watched.

**Owner questions:**

1. **Office conversion (ADR-042, Proposed):** accept the design: a `casual-sign-convertd` sidecar per job; `.xlsx`
   and `.pptx` through OpenCalc's and OpenPresent's renderers (ours, Apache-2.0, pinned by commit); `.docx` and the
   legacy formats through LibreOffice in a fresh, network-less, read-only, time- and memory-bounded container pinned
   by digest; the PDF then admitted as any upload, the original kept as evidence. Recommendation: accept; it is
   ADR-021 made concrete.
2. **Envelope restore (ADR-031, Proposed since 2026-11-13):** accept `RestoreDeleted` with the audit type
   `envelope.restored`, so the Deleted view's Restore works for envelopes as it does for templates.
   Recommendation: accept.
3. **Slice-6 rows in docs/96 outside the outcome's words** (`FG-009` envelope id stamping, `FG-013` sign on paper,
   `FG-080` strike-through by an editor, `FG-141` insights dashboard): kept as `VS-06E`, outside this slice's
   closure, unless the owner wants them in it.

## Found and not fixed

| Row | What | Size |
| --- | --- | --- |
| `VS-06A` | An editor changes fields at the ceremony; an intermediary changes authentication | M |
| `VS-06B` | Slice 6 on CI: `manage-correct.spec.mjs` in `compose-e2e`, `slice-6-demo` watched and linked | S |
| `VS-06C` | Office conversion per ADR-042, once accepted | L |
| `VS-06D` | One evidence-package download (sealed PDFs, certificate, audit trail) for an envelope (`UXW-20`'s remainder) | M |
| `VS-06E` | docs/96 slice-6 rows outside the outcome's words: `FG-009`, `FG-013`, `FG-080`, `FG-141` | L |

Nothing here states that any signature is legally valid or that the product is compliant or certified (docs/09).
