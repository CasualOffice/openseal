# 04 — Mistakes made, and the rule that stops each

Read this before starting work. Add a row whenever a mistake costs the owner time, in the same turn. **The rule column binds every session.**

This page starts with the rules the sister repos paid for (OpenPresent's docs/04 at `8011d28`, OpenCalc's history), because the same people and agents work here. Rows 1 to 24 are inherited; rows from 25 are this repository's own.

## Inherited from the sisters

| # | Rule | Paid for in |
|---|---|---|
| 1 | **Until Phase 1 closes, work only on the PDF and evidence core.** If it does not move Phase 1, do not start it | OpenPresent started rendering before the model was done |
| 2 | **Biggest remaining work starts first.** Independent stages all start at once | OpenPresent held its largest tiers back |
| 3 | **Ask of every design: does this help the user get an agreement signed and proven?** Neutralize attacks; refuse only what cannot be handled safely | OpenPresent built refusal where recovery was wanted |
| 4 | **Design only what the next merge needs. A document is not progress** | OpenPresent spent long on documents before code |
| 5 | **Every status update states the percentage of the current phase, merged only** | The owner had to ask |
| 6 | **Say "stopped" only after checking the processes, twice** | A tool kept crashing after "stopped" |
| 7 | **Run it before stating it** | A wrong fact in the docs |
| 8 | **Tested means that exact guard was removed and a test failed** | False "Tested" security rows |
| 9 | **Short updates. Say what changed, what is left, what I need. One question, with a recommendation** | Long reports the owner could not act on |
| 10 | **Say something brief before long work, and every time something finishes** | Silence |
| 11 | **Decide, record it, carry on.** Ask only when blocked: a permission denial, a legal question, or something only the owner can do | Interrupting the owner |
| 12 | **Read the whole gate output, then commit, then push** | Red `main` |
| 13 | **The local gates list is exactly what CI runs** | Red `main` repeatedly |
| 14 | **Never skip a hook or route around a gate** | — |
| 15 | **Name files in a merge; no wildcards** | Lost conflict resolutions |
| 16 | **Tests compare normalized text; fixtures are marked in `.gitattributes`** | Red Windows CI |
| 17 | **Nothing that can pop up or crash on the owner's desktop.** Desktop tools (LibreOffice, Acrobat) run only in a container or on CI | Crash dialogs while the owner worked |
| 18 | **Commit each increment. Merge each session as soon as its gates pass** | Large conflicting merges |
| 19 | **Each session uses its own scratch subfolder** | Overwritten scripts |
| 20 | **Check disk at every merge; remove finished worktrees at once** | Full disk |
| 21 | **Verify by running: gates, then break something real.** A report is not evidence | Weak claims nearly merged |
| 22 | **Check machine load before adding sessions. Above twice the core count, start nothing new.** Cargo runs with `CARGO_BUILD_JOBS=2 RUST_TEST_THREADS=2`; fuzz one at a time | Load average 134 |
| 23 | **Say nothing when nothing changed** | Wasted time and tokens |
| 24 | **Fix what was complained about; don't remove the thing itself** | A validation was dropped by over-reading an instruction |

## This repository

| # | Mistake | What it cost | Rule |
|---|---|---|---|
| 25 | — | — | **Never state that a signature or a deployment is legally valid, compliant or certified.** Say what the design supports and what an operator must still do (docs/09). Pre-empted, not yet paid for: an e-signature product that overclaims is a liability for its users |
| 26 | — | — | **Never verify a seal only with our own verifier.** An independent validator must agree (docs/31). Pre-empted: a signer and verifier written by the same hand share the same misreading of the standard |
| 27 | Committed `admit_dir.rs` without running `tools/ci-local.sh`, then committed again while its output showed a failure (unformatted code), because the commit was chained after the CI with `;` instead of `&&` | Two commits on `main` that fail the CI list | **While the repository is private, commit to `main` only as `tools/ci-local.sh && git commit`.** Read its last line before reporting anything as done |
| 28 | Treated an offered option as declined on an ambiguous "ok" (fill-in-place forms), called dynamic XFA "not supported" because competitors do the same, and parked real-file gaps as low priority and features as `Later` | The owner had to say it is not an MVP | **Enterprise means complete. Never drop, defer indefinitely or refuse-for-good on MVP reasoning, and never cite a competitor's gap as a reason for ours.** Every capability gets a slice and a row; priority only orders work. An ambiguous reply to an offer is a yes to tracking it, never a no |
