# Provenance

What was copied from the sister repositories, from where, and what changed (docs/19 §Provenance). OpenPresent lives
in the folder `openslide/`; its commit at the time of copying was `e61277d`.

| Here | From | Changed |
| --- | --- | --- |
| `LICENSE` | OpenPresent `LICENSE` | Nothing |
| `rust-toolchain.toml` | OpenPresent | Provenance comment |
| `deny.toml` | OpenPresent | Advisory ignore comments removed; list empty |
| `Cargo.toml` `[workspace.lints]`, `[profile.release]` | OpenPresent `Cargo.toml` | Added `missing_docs` and clippy lints for panics on untrusted input (`unwrap_used`, `expect_used`, `indexing_slicing`, `arithmetic_side_effects`, `panic`) |
| `.githooks/commit-msg`, `.githooks/pre-commit` | OpenPresent | Nothing |
| `tools/tracker_rows.py`, `tools/check-tracker-shape.py` | OpenPresent (from OpenCalc) | Nothing |
| `tools/check-commits.py` | OpenPresent | Example message |
| `tools/check-crate-deps.py` | OpenPresent | Reserved server crate names |
| `tools/check-repo.py` | OpenPresent | Gate list; XML-walker check replaced by unsafe and `#[allow]` checks; skills' links checked |
| `.github/workflows/ci.yml` | OpenPresent | OOXML jobs and fuzz build removed; `validators` job added |
| `CODE_OF_CONDUCT.md` | OpenPresent | Reporting link |
| `GOVERNANCE.md` | OpenPresent | Roles and protected areas for e-signature |
| `.claude/skills/*` | OpenPresent `openslide-*` skills | Rewritten for OpenSeal |
| `crates/casual-sign-flatten/src/subset.rs` | OpenPresent `crates/casual-slide-render/src/subset.rs` at `e61277d` | Every read and sum checked (no panics on untrusted fonts) |
| `crates/casual-sign-flatten/fonts/` (Liberation Sans, Serif, Mono Regular) | OpenPresent `crates/casual-slide-text/fonts/liberation/` at `e61277d` | Regular faces only; details in that folder's PROVENANCE.md |
| `server/casual-sign-secrets/` (`src/lib.rs`, `tests/secrets.rs`) | OpenCalc `server/casual-calc-secrets/` at `b23c67c` | `Secret` type (redacted `Debug`, zeroized on drop) returned instead of `String`; `code()` giving `CS-KEY-0005`; `OPENSEAL_` prefix; tests moved to `tests/` with a scratch dir under `target/` and a test that a secret never prints (T-2E) |
| `server/casual-sign-server/` (router setup with per-route `DefaultBodyLimit`, in-process `tower::ServiceExt::oneshot` tests) | OpenCalc `server/casual-calc-host/src/main.rs` at `e65e202` | Conventions only, no code lines: axum 0.8 router and body limits, tests through `oneshot`; everything else (auth, problems, command pipeline, ceremony) is new (T-2C) |
| `server/casual-sign-server/tests/common/mod.rs` | This repository's `server/casual-sign-store/tests/common/mod.rs` (T-2B) | Unchanged but for its module list and a note (T-2C) |
| `server/casual-sign-host/src/{apply,jobs,ids}.rs` | This repository's `server/casual-sign-worker/src/{apply,jobs}.rs` (T-2D) | Moved at the integration of 2C and 2D: errors made `HostError`; the projection merged with the server's (every envelope column, recipients upserted and pruned); `RevokeTokens` performed in the transaction instead of queued |
| `server/casual-sign-server/tests/common/mmdb.rs` | This repository's `server/casual-sign-server/src/geo.rs` unit-test database builder (T-2C) | Made a test module of its own for `tests/location.rs` |
