---
name: openseal-merge
description: Verify and merge a parallel worker's branch into OpenSeal. Use when a worktree session reports completion.
---
Adapted from OpenPresent's `openslide-merge` skill. A worker's report is not evidence.

1. `git diff --stat base..branch`: confirm it stayed in its owned files. Strays are rejected or examined.
2. Check out the branch. Run the tests of the crates it changed.
3. Pick the most important tests. Revert the fix, watch them go red, restore.
4. For anything that seals: run the independent validators in `docs/31` §Verification over its outputs yourself.
5. Merge into `main`, then push, per the branching rule in `CLAUDE.md`.
6. Update `docs/14`, `docs/96` and anything else via `openseal-docs`. Findings not fixed become rows.
7. Commit, then remove the worktree once merged.
