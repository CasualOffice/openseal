---
name: openseal-task
description: Run one tracked OpenSeal task from row to commit. Use when starting any implementation, fix or doc task in this repository.
---
Adapted from OpenPresent's `openslide-task` skill.

1. Find the row in `docs/14-EXECUTION-TRACKER.md`, or add one after reading the id space. Set it `In progress`. State the acceptance test before writing code. Work with no row is not allowed.
2. Check the phase or slice is open in `docs/06-ROADMAP-AND-DELIVERY.md`. If not, it needs a recorded waiver from the owner.
3. Read the design note that owns the area. If an ADR trigger in `docs/08` fires, stop for an Accepted ADR.
4. Look for the sister repos' solution first (`../opencalc`, `../openslide`): copy with provenance, change only what e-signature needs.
5. Write the failing test. Run it and keep the failure output.
6. Implement to `CLAUDE.md`'s engineering standards. Anything that touches a PDF also follows `openseal-pdf`.
7. Check by running, then ask what would have to be true for this to be wrong, and go and look. Revert the fix to confirm the test goes red, then restore.
8. Run `cargo test -p <crate>` for what you changed, with `CARGO_BUILD_JOBS=2 RUST_TEST_THREADS=2`. Full gates run on CI.
9. Use `openseal-docs` to update every affected document, in the same commit.
10. Mark `Done` only per Definition of Done in `docs/05`, with evidence in the row. If partial, stay `In progress` and say what remains. New findings become rows.
11. Commit with Conventional Commits, citing the row.
