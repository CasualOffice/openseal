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
