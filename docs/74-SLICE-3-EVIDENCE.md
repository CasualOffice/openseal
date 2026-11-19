# 74 — Slice 3 evidence (templates)

Evidence for the owner to close slice 3, **Templates** ([06](06-ROADMAP-AND-DELIVERY.md) §After Phase 2; tracker row
`VS-03`), in the format of [73](73-M3-SLICE-EVIDENCE.md). Only the owner closes a slice, and exit criteria are never
bent ([05](05-PHASES-AND-TASKS.md)). This page proposes; it closes nothing.

**Summary (2026-11-19):** every outcome element is built and tested. Roles, save as template, use template and
sharing were already on `main` and passed in green run 44419251440. Composite templates (`VS-03A`) and template
folders (`TSH-03`) were missing and are built on a worktree branch, with server tests seen red on PostgreSQL, web unit
tests, a real-stack and mock-mode browser spec (`templates.spec.mjs`), axe scans light and dark, the i18n check
extended to the template screens, and a `slice-3-demo` upload in `compose-e2e` (`VS-03B`). What is left is what only
CI proves: a green `main` run with the branch merged (`server-db`, `e2e`, `compose-e2e`), then watching the demo.

**Reference run.** `main` at `584634d` (PR #30), GitHub Actions run
[44419251440](https://github.com/CasualOffice/openseal/actions/runs/44419251440) (2026-11-18), every job green. "Passed"
below means listed passed in that job's log, read 2026-11-19. Items marked **branch** were run locally on the branch
(PostgreSQL 55432, Playwright headless) and are not yet in any CI run.

**Gate items.** Slice 3 has no boxes in docs/06; its gate is the general end point in docs/06 §After Phase 2: "an
**outcome** (what a user can do), an **end point** (merged, CI green including a browser run, docs/96 rows updated,
demo recorded)" and "Accessibility (WCAG 2.2 AA) and i18n string extraction are part of every UI slice's end point".
The outcome is the slice-3 row: "Roles, save as template, use template, composite templates, sharing, folders".

**Readings chosen** (the outcome does not say; the closest DocuSign and SignNow behaviour, docs/48–49):

- *Composite templates*: DocuSign's: one envelope from several server templates, their documents in order, roles
  matched by role name (here ignoring case) so a person named in two templates is one recipient with both templates'
  fields. Made on the server (`POST /envelopes/from-templates`), not by the browser re-uploading documents.
- *Folders*: each member's own template folders (DocuSign's personal template folders; SignNow's template folders),
  the same model as envelope folders (`UXW-02`): filing is the member's view, never a change of the template.
  Template *locking* (also in `FG-098`) is not in the docs/06 outcome; it is `TSH-04`.

## Outcome

| Element (docs/06) | Status | Evidence, or what is missing |
| --- | --- | --- |
| Roles | Met | A template's roles (name, type, routing order) made, changed and removed, fields bound to them: `casual-sign-server` `tests/templates.rs` (2 passed in `server-db` of 44419251440). In a browser: `editor.spec.mjs:19` "Edit reopens a template's document, roles and fields…" passed in `e2e` (chromium, webkit); on the Compose stack `real-api.spec.mjs:174` "the editor on the server: a template saved, reopened and saved back; a parallel step…" passed in `compose-e2e` (chromium, webkit). `FG-096` `Works` |
| Save as template | Met | `manage.spec.mjs:240` "the inspector's More menu: copy, save as template, history, delete" passed in `e2e` (chromium). **Branch:** `templates.spec.mjs` saves the completed composite envelope as a template and opens it with roles Role 1 and Role 2, in mock mode (chromium, webkit) and, once merged, on the Compose stack. `FG-136` `Works` |
| Use template | Met | `manage.spec.mjs:351` "use a template: the document beside a panel holding the roles and Send" passed in `e2e`; `bulk-send.spec.mjs:34` (a template sent to a list) passed in `compose-e2e`. **Branch:** Use now calls `POST /envelopes/from-templates` (made on the server from the stored documents); `tests/use_templates.rs` "draft from one template" |
| Composite templates | Built (branch) | `VS-03A`. `POST /envelopes/from-templates` and the Use page's "Add a template". `tests/use_templates.rs` `an_envelope_is_made_from_several_templates_with_roles_matched_by_name_with_rls` / `_without_rls` (documents in order; Buyer named "Buyer" and "buyer" is one recipient with both documents' fields; refusals at `/recipients`, `/recipients/{i}/role`, `/template_ids/{i}`, `/status`; nothing made on a refusal) and `a_member_uses_only_the_templates_they_may` (not shared: `422`; shared: `201`); unit tests in `api/usetemplates.rs`. Seen red: route renamed, `left: 405 right: 201`; role names matched by case, `left: ["Buyer", "Agent", "buyer", "Seller"]`. Browser: `templates.spec.mjs` adds the order template to the NDA, sends, both signers sign in turn (mock, chromium and webkit). Missing: a green `main` run with it |
| Sharing (users and groups) | Met | `UXW-06`. `tests/template_sharing.rs` `templates_are_shared_with_members_groups_and_the_account_and_starred_with_rls` / `_without_rls` passed in `server-db`; `template-sharing.spec.mjs:25` passed in `compose-e2e` on chromium and webkit (shared by email with Can edit; the member finds it under Shared with me with edit access; another member gets `404`). Groups as share targets are in the server test; the browser spec shares with a member |
| Folders | Built (branch) | `TSH-03`. Migration 0047; `tests/use_templates.rs` `template_folders_are_each_members_own_with_rls` / `_without_rls` (kind kept apart from envelope folders, filter `?folder=` and `none`, another member's or account's folder `404`, a template the member may not use `404`, an envelope folder takes no template, rename and delete); store `tests/isolation.rs` (another account's folder and template; the database refuses a template in an envelope folder). Seen red: route renamed, `left: 404 right: 200`. Browser: `templates.spec.mjs` New folder, Move to folder, the filter. Missing: a green `main` run with it |

## End point

| Gate item (docs/06, verbatim) | Status | Evidence, or what is missing |
| --- | --- | --- |
| merged | Not met | The branch carries `VS-03A`, `TSH-03`, `VS-03B`; merged by the main session after it verifies them |
| CI green including a browser run | Not met (waits for CI) | Run locally on the branch: `cargo test -p casual-sign-server` `use_templates`, `contract` (every operation, the two new ones included), `isolation`, `inbox_folders`, `templates`, `template_sharing`, `bulk_send`, lib; `cargo test -p casual-sign-store` `isolation`, `migrations`; `npm test` in `webapp/` (272 passed); `templates.spec.mjs` in mock mode on chromium and webkit; the full chromium mock suite. Met when `server-db`, `e2e` and `compose-e2e` are green on `main` with `templates.spec.mjs` passed on the Compose stack |
| docs/96 rows updated | Met | Slice-3 rows: `FG-096` `Works`; `FG-097` Partial (built, `Works` from the green `main` run); `FG-098` Partial (sharing works; folders built; locking `TSH-04`); `FG-099` Designed (`VS-03C`); `FG-012` Partial (unchanged, `WEB-19`). `FG-136` (slice 6) `Works`. M4, not this gate, asks for `Works` |
| demo recorded | Not met (waits for CI) | `compose-e2e` uploads `target/e2e-demo/vs03-*` as `slice-3-demo` (`.github/workflows/ci.yml`): the sender's folder, the two templates used together and Save as template; the Buyer signing both documents; the Seller signing. Met when a green `main` run carries it and it is watched and linked from [65](65-RUNNING-IT.md) §Demos |
| Accessibility (WCAG 2.2 AA) and i18n string extraction | Not met (waits for CI) | Axe: `templates.spec.mjs` "templates: the list with folders, the folder and move panels, and using two templates are accessible", light and dark, passed locally (mock); `manage.spec.mjs:319` already scans the templates list and edit panel in `e2e`. i18n: `webapp/tests/i18n-slices.test.mjs` now covers `templates.js`, `templatemodel.js`, `templatesync.js` (the template editor is `prepare.js`, already covered); seen red with a literal "Folder" (`'templates.js:73: "Folder"'`), green with every new string in `webapp/strings/admin.en.js`. Met when `e2e` is green on `main` with them |

Recommendation: ready to close once a `main` run with this branch is green on every job and `slice-3-demo` has been
watched.

Owner decision (2026-11-19, instruction 66): **close on green `main`**: slice 3 closes once `main`'s CI run on `af038fd` (run 44432837346) is green. Decisions 1 and 3 below are answered: template folders are each member's own; template locking (`TSH-04`) is outside slice 3. Status: run 44432837346 finished **red**: job `e2e (3)`, two webkit tests in `prepare-layout.spec.mjs` (`:127` "a clicked field type places its field where the page is clicked…", `:386` "review: a signer without fields is a warning…"); every other job green. The slice-3 rows stay In progress until a `main` run is green.

**Decisions only the owner can make:**

1. "Folders": do personal template folders (each member's own, as envelope folders are) meet it, or must folders also
   be shared across members (DocuSign's shared template folders)?
2. "Composite templates": does matching roles by name across templates (DocuSign's rule) meet it, or must the sender
   also map roles by hand when names differ?
3. Template locking (`TSH-04`) and document group templates (`VS-03C`, `FG-099`): outside this slice's outcome, or
   part of it?

## Found and not fixed

| Row | What | Size |
| --- | --- | --- |
| `TSH-04` | Template locking | M |
| `TSH-05` | "Last used" never set on the real server | S |
| `TSH-06` | An envelope from templates does not record `template_ids` | S |
| `VS-03C` | Document group templates (`FG-099`) | L |

Nothing here states that any signature is legally valid or that the product is compliant or certified (docs/09).
