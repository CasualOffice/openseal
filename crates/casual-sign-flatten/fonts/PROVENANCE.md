# Bundled faces and copied code (`T-1E`)

Every face here is SIL Open Font License 1.1 font data, embedded by `FontSet::bundled()`
and subset into flattened documents. The OFL permits embedding a subset in a document; a
subset embedded in a document is not a Modified Version under the licence (OFL FAQ 1.10,
2.12), so the Reserved Font Names below do not apply to it. The files are unmodified.

## Liberation (copied from OpenPresent)

Source: the sister repository OpenPresent, `../openslide/crates/casual-slide-text/fonts/`
at commit `e61277d` (read-only; itself copied from OpenCalc's
`crates/casual-calc-text/fonts/` at `b23c67c`). Upstream:
https://github.com/liberationfonts/liberation-fonts, `liberation-fonts-ttf-2.1.5`.
Licence: [`LICENSES/OFL-1.1-Liberation.txt`](LICENSES/OFL-1.1-Liberation.txt)
(Reserved Font Name "Liberation"; Arimo, Tinos and Cousine digitized data © Google).

| File | Role | SHA-256 |
| --- | --- | --- |
| `liberation/LiberationSans-Regular.ttf` | Sans (Helvetica metrics) | `76d04c18ea243f426b7de1f3ad208e927008f961dc5945e5aad352d0dfde8ee8` |
| `liberation/LiberationSerif-Regular.ttf` | Serif (Times metrics) | `058ea80864aef09a23f45cbec2bb5400bc3dfbdea01c3f10538a21fcb497fb74` |
| `liberation/LiberationMono-Regular.ttf` | Mono (Courier metrics) | `f2b83c763e8afd21709333370bed4774337fae82267937e2b5aea7e2fbd922c1` |

Only the regular weights are copied: a field's format has a family, size, colour and
alignment but no weight or style (docs/22 §6). The bold and italic faces are at the same
sister path when the format gains them.

## Script faces for typed signatures (downloaded 2026-11-10)

From Google Fonts' repository of OFL families, branch `main`. Chosen because neither
declares a Reserved Font Name. Sacramento was considered and left out: it reserves its
name.

| File | URL | SHA-256 | Licence |
| --- | --- | --- | --- |
| `script/GreatVibes-Regular.ttf` | https://raw.githubusercontent.com/google/fonts/main/ofl/greatvibes/GreatVibes-Regular.ttf | `8d509802186f1b51572531ecf313e8098f9a5bfdfaca93f0c9b34467f9982d15` | [`LICENSES/OFL-1.1-GreatVibes.txt`](LICENSES/OFL-1.1-GreatVibes.txt), © 2015 The Great Vibes Pro Project Authors, from `ofl/greatvibes/OFL.txt` (SHA-256 `61093a21f5e63dedf54222b3c09997e54c0fe43e3851d21386e02ddcbc246d49`) |
| `script/Allura-Regular.ttf` | https://raw.githubusercontent.com/google/fonts/main/ofl/allura/Allura-Regular.ttf | `9c142b2e515832c0dfc4ff8b8ea18f40314943bf937b72e2b23c4661bac14cc6` | [`LICENSES/OFL-1.1-Allura.txt`](LICENSES/OFL-1.1-Allura.txt), © 2010 The Allura Project Authors, from `ofl/allura/OFL.txt` (SHA-256 `c8cb4c94a558b6cb82ac5dc981a73a0b8aee35a5c52c8a7832fc0280c289ad49`) |

## Not bundled yet

Noto Sans for scripts beyond Latin, Greek and Cyrillic (CJK, Arabic, Hebrew, Devanagari,
Thai). The sister repositories hold Noto Sans Arabic and Noto Naskh Arabic
(`../openslide/crates/casual-slide-text/fonts/noto/`, OFL), but Arabic drawn without
shaping would be wrong (unjoined, left to right), and this crate's layout does not shape.
Until a shaper and the Noto faces land, such text is refused with `CS-FLT-0001`, never
drawn wrongly or dropped.

## Code

`src/subset.rs` is copied from OpenPresent's `crates/casual-slide-render/src/subset.rs`
at `e61277d` (itself OpenCalc's `casual-calc-render/src/subset.rs` at `b23c67c`),
Apache-2.0, same owner. Changed: every read, offset and sum is checked. The `ToUnicode`
CMap writer and the number formatting in `src/write.rs` and `src/canvas.rs` follow
OpenPresent's `crates/casual-slide-render/src/pdf.rs` at the same commit.
