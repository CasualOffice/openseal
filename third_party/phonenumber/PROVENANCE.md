# Provenance: `phonenumber` 0.3.10+9.0.33 (vendored, patched)

Patched into the workspace by `[patch.crates-io]` in the root `Cargo.toml` (`DEP-08`; docs/19 §Vendored crates).
Reached through `casual-sign-pii` (phone-number recogniser, ADR-029, docs/33 §5.4).

| | |
| --- | --- |
| Upstream | <https://github.com/whisperfish/rust-phonenumber>, crate `phonenumber` 0.3.10+9.0.33 from crates.io (the latest release on 2026-11-20) |
| Upstream commit | `0a1516ee708d751aee80ee0e258f4bfad3ff6c65` (`.cargo_vcs_info.json`) |
| Licence | Apache-2.0 (`LICENSE` shipped with the crate, unchanged). Permissive, on `deny.toml`'s allow list. Not a copyleft competitor's code |
| Vendored | 2026-11-20 |

## What was changed

Only `Cargo.toml`: `postcard` (a dependency and a build dependency) is taken with `default-features = false`
(`alloc` for the library, `use-std` for the build script). postcard's default `heapless-cas` feature brought
`heapless` 0.7 (RUSTSEC-2026-0578, -0580, -0582, published 2026-11-20) and `atomic-polyfill` (RUSTSEC-2023-0089).
phonenumber serializes its metadata with postcard at build time and reads it from a byte slice at run time, which
needs neither. `.cargo_vcs_info.json` and `Cargo.toml.orig` were removed.

## When to drop it

When a phonenumber release takes postcard without its default features, or postcard's defaults stop pulling
heapless 0.7.
