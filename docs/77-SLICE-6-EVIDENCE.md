# 77 — Slice 6 evidence (Manage and correct)

Evidence for the owner to close slice 6, **Manage and correct** ([06](06-ROADMAP-AND-DELIVERY.md) §After Phase 2;
tracker row `VS-06`), in the format of [76](76-SLICE-8-EVIDENCE.md). Only the owner closes a slice, and exit criteria
are never bent ([05](05-PHASES-AND-TASKS.md)). This page proposes; it closes nothing.

**Summary (2026-11-21, second pass):** every outcome element, and the four docs/96 rows owner instruction 78 added
(`FG-009`, `FG-013`, `FG-080`, `FG-141`), is built end to end on the worktree branch with tests seen red; none is
yet in a green `main` run, so none is Met. Owner instructions 76 (Word conversion with an Apache-2.0 library), 77
(ADR-031 restore accepted) and 78 answered the first pass's three questions. Excel and PowerPoint conversion is its
own row (`VS-06F`), outside this slice by instruction 76.

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
| `FG-009` envelope id stamping | Built (branch) | ADR-045 Accepted (instruction 78), for owner review: drawn by the flattener in every page's top margin, shown during signing; `signing_options.stamp_envelope_id` with an account default. Red: flatten with stamping off; server `tests/envelope_id_stamp.rs` with the account default ignored (`assertion failed: stamped(&draft(…))`, seen again after the merges); worker seal; the sealed stamped PDF accepted by pyHanko 0.38.1 (Docker) |
| `FG-013` sign on paper | Built (branch) | ADR-043 Accepted (instruction 78), for owner review: `allow_sign_on_paper`, `SignOnPaper`, audit type `recipient.signed_on_paper`, `POST /s/{token}/paper` (PDF only, admitted, malware-screened), the certificate says "Signed on paper". Red: workflow option check removed; server `tests/sign_on_paper.rs` with the route removed (`left: 404`); browser step |
| `FG-080` strike-through by an editor | Built (branch) | ADR-044 Accepted (instruction 78), for owner review: field kind `strikethrough`, placed by an editor, drawn into the sealed PDF. Red: flatten (`ValueMismatch`), fields (`left: None right: Some(Checked(true))`), worker end to end (sealed, pyHanko intact and valid), browser (`Expected: 1 Received: 0`) |
| `VS-06D` one evidence package | Built (branch) | `GET /envelopes/{id}/evidence-package`: one ZIP (store-only writer on `crc32fast`) with a SHA-256 manifest, the documents, the certificate and the audit trail, recording `envelope.exported`. Red: manifest hashing the path (`documents/01-w.pdf`), export not recorded (`left: 500 right: 409`), and after the merges with the route renamed (`left: 404 right: 409`) |

## End point

| Gate item (docs/06, verbatim) | Status | Evidence, or what is missing |
| --- | --- | --- |
| merged | Not met | On the worktree branch `worktree-agent-a3d5bfa804adb0cc3`, merged with `main` at `a4da083`; the main session merges it |
| CI green including a browser run | Not met (waits for CI) | Branch, on the combined tree: the server's slice tests on PostgreSQL; `npm test` 334 passed; the final local list (fmt, engine, store, convertd, server, worker, clippy, wasm32, `cargo deny`, `cargo audit`, sqlx, SDK and repository checks) and the chromium browser suite are reported with the branch. Only CI shows `compose-e2e` (Compose steps of `manage-correct.spec.mjs`, `docx-send.spec.mjs`, `vs06e-screens.spec.mjs`; convertd's image; the memory cap on Linux) and `server-db` on Linux |
| docs/96 rows updated | Met (for what is built) | `FG-002`, `FG-009`, `FG-013`, `FG-025`, `FG-026`, `FG-080`, `FG-130`–`FG-133`, `FG-137`, `FG-139`–`FG-141` Partial, each naming its tests and the green `main` run that makes it `Works` |
| demo recorded | Not met (waits for CI) | `compose-e2e` uploads `target/e2e-demo/vs06-*` as `slice-6-demo-${{ matrix.shard }}`; met when a green `main` run carries it and it is linked from [65](65-RUNNING-IT.md) §Demos |
| Accessibility (WCAG 2.2 AA) and i18n string extraction | Not met (waits for CI) | Axe light and dark on every new screen (mock, chromium and webkit); `i18n-slices.test.mjs` covers the new modules |

Recommendation: propose for closure once a `main` run with this branch is green on every job and `slice-6-demo` has
been watched.

**Owner review (designs marked Accepted under instruction 78, which ordered the features built):** ADR-043 (sign on
paper: the scan joins the envelope as a fixed document), ADR-044 (one strike field draws one line; recorded as
`envelope.corrected`), ADR-045 (the stamp drawn at flattening, not in the delivered bytes).

**Owner question:** may convertd's image ship Carlito and Caladea (OFL-1.1, metric-compatible with Calibri and
Cambria) so converted Word documents break lines as Word does (`VS-06G`)? Not done: OFL-1.1 is not Apache-2.0.

## Found and not fixed

| Row | What | Size |
| --- | --- | --- |
| `VS-06F` | Excel and PowerPoint uploads converted (instruction 76) | L |
| `VS-06G` | Word's own fonts in conversion (question above) | S |
| `DEP-09` | Remove the `ttf-parser` audit ignore (RUSTSEC-2026-0192, unmaintained, informational) | S |
| `ORG-18` | Import of an exported package as a read-only archived agreement (the export is built) | M |

Nothing here states that any signature is legally valid or that the product is compliant or certified (docs/09).
