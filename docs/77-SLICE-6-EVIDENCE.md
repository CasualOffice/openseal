# 77 — Slice 6 evidence (Manage and correct)

Evidence for the owner to close slice 6, **Manage and correct** ([06](06-ROADMAP-AND-DELIVERY.md) §After Phase 2;
tracker row `VS-06`), in the format of [76](76-SLICE-8-EVIDENCE.md). Only the owner closes a slice, and exit criteria
are never bent ([05](05-PHASES-AND-TASKS.md)). This page proposes; it closes nothing.

**Summary (2026-11-21, second pass):** every outcome element, and the four docs/96 rows owner instruction 78 added
(`FG-009`, `FG-013`, `FG-080`, `FG-141`), is built end to end on the worktree branch with tests seen red; none is
yet in a green `main` run, so none is Met. Owner instructions 76 (Word conversion with an Apache-2.0 library), 77
(ADR-031 restore accepted) and 78 answered the first pass's three questions. Excel and PowerPoint conversion is its
own row (`VS-06F`), outside this slice by instruction 76.

**Update 2026-11-21:** merged into `main` by PR #39 (`87854fe`, 2026-11-20). `main` run 44809730807 on it went red in
`compose-e2e (2)` only, on slice 8's `api-webhooks.spec.mjs` reading the webhook receiver before the delivery showed;
`9c20a0e` made that spec poll, and `main` run 44813535957 on `9c20a0e` is green on every job. In it `compose-e2e` ran
`manage-correct.spec.mjs`, `docx-send.spec.mjs` and `vs06e-screens.spec.mjs` on the Compose stack on chromium and
webkit, every test passing, and uploaded `slice-6-demo-2` (artifact 14669791318) and `slice-6-demo-4` (14669427856).
The "Built (branch)" statuses below are now on `main` and green. Closed by the owner on that run (instruction 83).

**Reference run.** `main` green on every job at `a4da083` (run 44653889545); this branch is merged with it at
`1a03047`. Items marked **branch** ran locally (PostgreSQL 55432; Playwright headless, mock mode, one worker) and are
in no CI run.

**Gate items.** Slice 6 has no boxes in docs/06; its gate is the general end point of docs/06 §After Phase 2: the
outcome, then "merged, CI green including a browser run, docs/96 rows updated, demo recorded", with accessibility
(WCAG 2.2 AA) and i18n string extraction. The outcome: "Folders and quick views, search, correct, resend, copy,
transfer; editor and intermediary types; Word, Excel, PowerPoint uploads converted; reports and CSV", with
`FG-009`, `FG-013`, `FG-080`, `FG-141` (instruction 78).

## Outcome

| Element | Status | Evidence (red → green), or what is missing |
| --- | --- | --- |
| Folders and quick views | Built (branch) | Folders and Move on `main` (`UXW-02`). Authentication failed and Expiring soon on the server: `tests/manage_views.rs`, red with the filter disabled (`left: ["Later", "Never", "Soon"] right: ["Soon"]`). **Deleted folder and restore** (ADR-031 Accepted, instruction 77): engine `RestoreDeleted`, audit type `envelope.restored`, `POST /envelopes/{id}/restore`, the sidebar's Deleted view with Restore; a purged envelope is refused. Red: workflow transition test with the guard removed; audit `delete_and_restore_events_verify_and_are_recognised` (`left: [3] right: []`); server `tests/lists.rs` with the route removed (`not deleted: … 404`); browser step without the inspector's Restore |
| Search | Built (branch) | Custom fields `GET`/`PUT /envelopes/{id}/custom-fields` and `?custom_field=&custom_value=` (`tests/manage_views.rs` line 177 red with the search dropped); the Agreements filter |
| Correct | Built (branch) | Recipients on `main`; documents and fields in the editor's Correct mode (`#/prepare/{id}?correct=1`): `tests/correct_documents.rs` red with the engine's touched-document redo off (`left: "completed" right: "completed"`); `manage-correct.spec.mjs` red before the route took a query |
| Resend, copy | Built (branch, real stack) | On `main`; real-stack steps in `manage-correct.spec.mjs` |
| Transfer | Built (branch) | The envelope page's Transfer panel (`ORG-41`), `slice6.test.mjs`, browser step |
| Editor and intermediary types | Built (branch) | Offered in the editor; `tests/editor_intermediary.rs` (Editor removed from `edits_recipients`: "an editor's view lists later recipients"). **An editor changes fields during signing** (`VS-06A`): `POST`/`PATCH`/`DELETE /s/{token}/editor/fields…`, the signing page's Edit fields mode; red with the reached-recipient check removed (`left: 403 right: 409`) and in the browser (`Expected: "Field moved." Received: "Field added."`). **An intermediary sets authentication**: access code (Argon2id, never returned), email or SMS code; red with the code not stored (`left: 403 right: 200`) |
| Word uploads converted | Built (branch) | ADR-042 Accepted (instruction 76): `docxide-pdf` 0.21.4 (Apache-2.0, pure Rust; every crate in its tree passes `deny.toml`) in `casual-sign-convertd`, a container with no network, a read-only root, and a fresh child per job (memory, CPU, time, page caps); the `.docx` kept as the `original` version. convertd `tests/convert.rs` over 14 hostile fixtures: red with the VBA check removed (`docx_vba_part.docx left: None right: Some(Macros)`), the ratio cap removed (zip bomb), the time kill removed; `tests/feature_gate.rs` (the API server links no converter); server `tests/convert.rs` (`left: 422 right: 201` with admission skipped); `docx_screen` fuzz target (124,384 runs, no finding); `docx-send.spec.mjs` (mock; Compose on CI). Excel and PowerPoint: `VS-06F` (instruction 76) |
| Reports and CSV | Built (branch) | `GET /reports/{envelopes,recipients,usage}` (formula-safe CSV; `tests/reports.rs` red with the guard removed); **Insights dashboard** (`FG-141`): `GET /insights`, `#/insights` with charts and table alternatives; red with the scope guard removed (`left: String("workspace")`), the 90th percentile as the median (`left: 10800.0 right: 33840.0`) |
| `FG-009` envelope id stamping | Built (branch) | ADR-045 Accepted (written under instruction 78, confirmed by instruction 79): drawn by the flattener in every page's top margin, shown during signing; `signing_options.stamp_envelope_id` with an account default. Red: flatten with stamping off; server `tests/envelope_id_stamp.rs` with the account default ignored (`assertion failed: stamped(&draft(…))`, seen again after the merges); worker seal; the sealed stamped PDF accepted by pyHanko 0.38.1 (Docker) |
| `FG-013` sign on paper | Built (branch) | ADR-043 Accepted (written under instruction 78, confirmed by instruction 79): `allow_sign_on_paper`, `SignOnPaper`, audit type `recipient.signed_on_paper`, `POST /s/{token}/paper` (PDF only, admitted, malware-screened), the certificate says "Signed on paper". Red: workflow option check removed; server `tests/sign_on_paper.rs` with the route removed (`left: 404`); browser step |
| `FG-080` strike-through by an editor | Built (branch) | ADR-044 Accepted (written under instruction 78, confirmed by instruction 79): field kind `strikethrough`, placed by an editor, drawn into the sealed PDF. Red: flatten (`ValueMismatch`), fields (`left: None right: Some(Checked(true))`), worker end to end (sealed, pyHanko intact and valid), browser (`Expected: 1 Received: 0`) |
| `VS-06D` one evidence package | Built (branch) | `GET /envelopes/{id}/evidence-package`: one ZIP (store-only writer on `crc32fast`) with a SHA-256 manifest, the documents, the certificate and the audit trail, recording `envelope.exported`. Red: manifest hashing the path (`documents/01-w.pdf`), export not recorded (`left: 500 right: 409`), and after the merges with the route renamed (`left: 404 right: 409`) |

## End point

| Gate item (docs/06, verbatim) | Status | Evidence, or what is missing |
| --- | --- | --- |
| merged | Met | PR #39, merge commit `87854fe` (2026-11-20) |
| CI green including a browser run | Met 2026-11-21 | `main` run 44813535957 (`9c20a0e`) green on every job, the slice's specs on the Compose stack on chromium and webkit (the update above). Before the merge: | Branch, on the combined tree: the server's slice tests on PostgreSQL; `npm test` 334 passed; the final local list (fmt, engine, store, convertd, server, worker, clippy, wasm32, `cargo deny`, `cargo audit`, sqlx, SDK and repository checks) and the chromium browser suite are reported with the branch. Only CI shows `compose-e2e` (Compose steps of `manage-correct.spec.mjs`, `docx-send.spec.mjs`, `vs06e-screens.spec.mjs`; convertd's image; the memory cap on Linux) and `server-db` on Linux |
| docs/96 rows updated | Met | After run 44813535957: `FG-009`, `FG-013`, `FG-025`, `FG-026`, `FG-080`, `FG-131`–`FG-133`, `FG-139`–`FG-141` `Works`; `FG-002` Partial (Excel and PowerPoint, `VS-06F`), `FG-130` Partial (the Inbox and folders on the Compose stack), `FG-137` Partial (slice 10's Users screen) |
| demo recorded | Recorded, not yet watched | `slice-6-demo-2` and `slice-6-demo-4` from run 44813535957; `compose-e2e` uploads `target/e2e-demo/vs06-*` as `slice-6-demo-${{ matrix.shard }}`; met when a green `main` run carries it and it is linked from [65](65-RUNNING-IT.md) §Demos |
| Accessibility (WCAG 2.2 AA) and i18n string extraction | Met 2026-11-21 (`e2e` and `npm test` green in run 44813535957) | Axe light and dark on every new screen (mock, chromium and webkit); `i18n-slices.test.mjs` covers the new modules |

**Closed 2026-11-21** under owner instruction 83, on `main` run 44813535957 (commit `9c20a0e`), green on every job.
The open follow-ups stay Open: `VS-06F` (Excel and PowerPoint), `VS-06G` (Carlito and Caladea), `ORG-18` (import);
watching and linking `slice-6-demo` is `DOC-016`.

**Owner review, answered 2026-11-21 by instruction 79 (all three accepted as built):** ADR-043 (sign on
paper: the scan joins the envelope as a fixed document), ADR-044 (one strike field draws one line; recorded as
`envelope.corrected`), ADR-045 (the stamp drawn at flattening, not in the delivered bytes).

**Owner question, answered 2026-11-21 by instruction 80:** convertd's image may ship Carlito and Caladea (OFL-1.1,
metric-compatible with Calibri and Cambria) so converted Word documents break lines as Word does. Not yet built
(`VS-06G`).

## Found and not fixed

| Row | What | Size |
| --- | --- | --- |
| `VS-06F` | Excel and PowerPoint uploads converted (instruction 76) | L |
| `VS-06G` | Word's own fonts in conversion (Carlito and Caladea, allowed by instruction 80) | S |
| `DEP-09` | Remove the `ttf-parser` audit ignore (RUSTSEC-2026-0192, unmaintained, informational) | S |
| `ORG-18` | Import of an exported package as a read-only archived agreement (the export is built) | M |

Nothing here states that any signature is legally valid or that the product is compliant or certified (docs/09).
