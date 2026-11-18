# Provenance: `oar-ocr-core` 0.10.2 (vendored, patched)

Patched into the workspace by `[patch.crates-io]` in the root `Cargo.toml` (`DEP-07`; docs/19 §Vendored crates).
Reached only through `oar-ocr`, in `casual-sign-modeld`'s `server` feature (ML-02, docs/33 §5.2). Its
`clipper2-rust` dependency stays replaced by our own `server/clipper2-rust` (ML-02C).

| | |
| --- | --- |
| Upstream | <https://github.com/greatv/oar-ocr> (folder `oar-ocr-core`), crate `oar-ocr-core` 0.10.2 from crates.io (the latest release on 2026-11-18) |
| Upstream commit | `16ee0599a12a477178b8495918f99e1ed92e5e4e` (`.cargo_vcs_info.json`) |
| Licence | Apache-2.0 (`license` in `Cargo.toml`). The published crate carries no licence file, so `LICENSE` here is the repository's root `LICENSE` from the same commit (as shipped in `oar-ocr` 0.10.2), added unchanged to meet Apache-2.0 §4(a). Permissive, compatible with OpenSeal's Apache-2.0 and on `deny.toml`'s allow list. Not a copyleft competitor's code |
| Vendored | 2026-11-18 |

## What was changed

1. `Cargo.toml`: `image` and `imageproc` with `default-features = false`. Upstream takes both with their
   defaults, which compile every `image` codec (avif with the `rav1e` encoder, which brings `paste`,
   RUSTSEC-2024-0436; exr, tiff, gif, webp and the rest) and `imageproc`'s `text` (`ab_glyph`, `ttf-parser`,
   RUSTSEC-2026-0192), `fft` and `rayon`. This crate calls only `imageproc::{contours, distance_transform,
   morphology, point}` on raw buffers. Its `ImageReader` and `load_image` helpers (`image::open`) still compile;
   with no codec enabled they return an unsupported-format error, and modeld never calls them (it hands
   `RgbImage` pixels to `OAROCR` directly).
2. `LICENSE` added (see above).
3. Not vendored: `Cargo.lock`, `Cargo.toml.orig`, `.cargo-ok`.

No source file differs (`diff -r` against `~/.cargo/registry/src/*/oar-ocr-core-0.10.2`). Upstream `unsafe` remains,
as it was when this crate came from crates.io: in `src/core/download/mod.rs` (tests of a module behind feature
`auto-download`, off, so not compiled) and in `src/core/inference/ort_infer_builders.rs`
(`ensure_cuda_launch_blocking`, a `set_var` reached only for a FormulaNet model on the CUDA or TensorRT execution
provider; modeld loads neither). The workspace's `unsafe_code = "forbid"` applies to our crates only.

## When to drop the patch

With `oar-ocr`'s (see `third_party/oar-ocr/PROVENANCE.md`): when a release takes `image` and `imageproc` without
default features. Proposed upstream: `default-features = false` on both, and a `LICENSE` file in the published
`oar-ocr-core` package.
