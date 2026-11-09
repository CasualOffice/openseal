---
name: openseal-worker
description: Brief a parallel OpenSeal session. Use when splitting independent work across worktree-isolated agents.
---
Adapted from OpenPresent's `openslide-worker` skill.

Parallelism is decided by invariants: two workers may run together only if they cannot touch the same invariant or file. Two tasks in one file are one worker, in sequence. Read-only audits can run freely.

**A worktree may start from the last pushed commit, not local `main`:** every brief tells the worker to run `git merge --ff-only main` (or `git rebase main`) in its worktree before starting. Commit a shared base first, with skeleton files for each worker, so they do not collide on `Cargo.toml`, `lib.rs` or a migration number.

Every brief says: read `docs/04-MISTAKES-AND-RULES.md`; use your own scratch subfolder; nothing that can pop up on the owner's desktop; no real personal data or real signed agreements in fixtures; commit each increment; keep the disk small; prefix cargo with `CARGO_BUILD_JOBS=2 RUST_TEST_THREADS=2`, use only `cargo test -p` on what you changed, never full gates or fuzz. Check `uptime` before spawning: above twice the core count, do not spawn.

Each brief has: the job and its tracker row; documents to read; **the files it owns, and that everything else is off limits**, including `docs/14`, which the main session updates (a worker that writes a new numbered document also adds its own row to `docs/00`, or the pre-commit gate refuses the commit); design decisions already fixed; the acceptance test, which for phase work is the phase's exit gate item in docs/06, not just the code; that it commits on its worktree branch with the attribution line and does not push; what to report: branch, a test seen red then green with verbatim output, what is truly covered and not, defects found. Tell it not to stop for questions: make the sensible call and note it. **A failing gate is reported, never routed around.**
