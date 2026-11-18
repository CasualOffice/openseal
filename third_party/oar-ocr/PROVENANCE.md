# Provenance: `oar-ocr` 0.10.2 (vendored, patched)

Patched into the workspace by `[patch.crates-io]` in the root `Cargo.toml` (`DEP-06`, `DEP-07`; docs/19
§Vendored crates). Used only by `casual-sign-modeld`'s `server` feature (ML-02, docs/33 §5.2).

| | |
| --- | --- |
| Upstream | <https://github.com/greatv/oar-ocr>, crate `oar-ocr` 0.10.2 from crates.io (the latest release on 2026-11-18) |
| Upstream commit | `16ee0599a12a477178b8495918f99e1ed92e5e4e` (`.cargo_vcs_info.json`) |
| Licence | Apache-2.0 (`license` in `Cargo.toml`; `LICENSE` here is upstream's, unchanged). Permissive, compatible with OpenSeal's Apache-2.0 and on `deny.toml`'s allow list. Not a copyleft competitor's code (CLAUDE.md clean-room list) |
| Vendored | 2026-11-18 |

## What was changed

1. `Cargo.toml` (the registry-normalised manifest):
   - `zip` `8.6` → `9.0.5` (same features: `default-features = false`, `deflate-flate2`). `zip` below 9.0.0 has
     RUSTSEC-2026-0367, -0368, -0369, -0429, -0545, -0546, -0547, and below 9.0.5 RUSTSEC-2026-0548. The lockfile
     pins 9.3.0, the newest 9.x at least two weeks old on 2026-11-18 (docs/33 §5). No source change was needed:
     `src/indra/lm.rs` uses only `ZipArchive::new`, `by_name` and `ZipError::FileNotFound`, which 9.x keeps.
   - `image` and `imageproc` with `default-features = false`. Upstream takes both with their defaults, which turn
     on every `image` codec (avif with the `rav1e` encoder, which brings `paste`, RUSTSEC-2024-0436; exr, tiff,
     gif, webp and the rest), `imageproc`'s `text` (`ab_glyph`, `ttf-parser`, RUSTSEC-2026-0192), `fft` and
     `rayon`. This crate calls only `imageproc::geometric_transformations::rotate_about_center` and works on raw
     pixel buffers; `rayon` there only splits the per-pixel loop across threads (same output), and this crate
     already runs its crops in parallel with its own `rayon`.
   - The `[[example]]` targets and `[dev-dependencies]` (`ab_glyph`, `clap`, `fontdb`, `hayro`, `tempfile`,
     `tracing-subscriber`) removed: the examples are not vendored, and no test in `src/` uses those crates.
     Without dev-dependencies, Cargo can run this crate's unit tests from the workspace
     (`cargo test -p oar-ocr --lib`), which it refuses for a non-member that has them.
2. `src/indra/lm.rs`: a `#[cfg(test)] mod tests` appended (marked as ours) that writes a deflated `.npz` with
   `zip::ZipWriter` and loads it with `NgramLm::load`: the table is read and sorted, a missing member is reported
   by name (the `ZipError::FileNotFound` arm), and a file that is not an archive is refused. Upstream has no test
   of the loader. No other source line differs.
3. Not vendored: `.github/`, `.gitignore`, `CODE_OF_CONDUCT.md`, `docs/`, `examples/`, `Cargo.lock`,
   `Cargo.toml.orig`, `.cargo-ok`.

`diff -r` against `~/.cargo/registry/src/*/oar-ocr-0.10.2` shows exactly the above.

## When to drop the patch

When an `oar-ocr` release (and its `oar-ocr-core`) requires `zip` ≥ 9.0.5 and takes `image` and `imageproc` without
default features: delete `third_party/oar-ocr/` and `third_party/oar-ocr-core/`, remove both entries from
`[patch.crates-io]`, move modeld's `oar-ocr` pin to that release, and check that `cargo audit --deny warnings`
still passes and `tests/ocr.rs` keeps its recall. Proposed upstream: the `zip` bump and `default-features = false`
on `image` and `imageproc`, with `imageproc`'s `rayon` left to callers.
