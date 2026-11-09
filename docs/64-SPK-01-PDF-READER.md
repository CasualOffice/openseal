# 64 — SPK-01: our own PDF reader versus `lopdf` or `pdf-rs`

**Status: spike report, 2026-11-10.** Decides [ADR-005](08-ADR-REGISTER.md). Tracker row `SPK-01`
([14](14-EXECUTION-TRACKER.md)). Code, fixtures generator and raw results: `spikes/spk-01-pdf-reader/` (a standalone
Cargo project with its own `[workspace]`, outside the product workspace, `publish = false`).

## 1. Answer

**(a) Our own bounded reader and incremental writer, as ADR-005 already says. `lopdf` stays as a test oracle only.**

- `lopdf` 0.47 is far better than its reputation: no panic, crash or hang on any hostile file, good recovery, and an
  incremental writer that matches the original's xref form and chains `/Prev` on sound files (over a repaired file it
  silently writes an update with no `/Prev`, §4). The writer is not the main problem.
- The reader's limits are. Four controls in [07](07-SECURITY-THREAT-MODEL.md) cannot be met by a caller wrapping it:
  no cancellation hook (SEC-P10), no per-document decode budget (SEC-P01: 2 GiB inflated in one `load` call, every
  stream under the per-stream cap), no object cap with an 8.4× memory amplification (SEC-P02), and **silent wrong
  answers** (a page-tree cycle or over-deep catalog yields 0 pages and no error: SEC-P03, SEC-P05, SEC-P11). Its
  other limits are fixed constants, not the host-overridable values [21](21-PARSER-LIMITS.md) requires, and it pulls in
  an RNG that forces `wasm-bindgen` on `wasm32-unknown-unknown` (ADR-004).
- `pdf` (pdf-rs) is rejected outright: unbounded Flate, no recovery, a writer that drops `/Prev`.
- The risky core of our own reader (lexer, iterative parser, xref, `/Prev`, recovery, page walk) took ~300 lines in
  the sketch and handled every hostile file in its scope with a typed error and no recursion. Estimated full effort:
  about 3,000 lines of product code plus tests, 4–6 engineer-weeks (§7).

## 2. What was measured, and how

| | |
| --- | --- |
| Machine | Apple M4, 10 cores, 16 GiB, macOS 26.3; load average ≈ 2 during runs |
| Toolchain | rustc 1.96.0, release profile; `CARGO_BUILD_JOBS=2` |
| Candidates | `lopdf` 0.47.0 (`default-features = false`, lenient and `strict: true`), `pdf` 0.10.0 (`default-features = false, features = ["sync"]`), `own` (the sketch in `own/src/lib.rs`) |
| Operation | Load from memory, count pages, then decode and tokenize every page's content stream (what flattening and anchor search do). `lopdf` gets `get_page_content_with_limit(256 MiB)`, docs/21's per-stream cap |
| Time cap | 10 s per run, killed by the harness (`run_probes.py`) |
| Memory | Peak RSS from `wait4(2)` rusage, the source `/usr/bin/time -l` prints (cross-checked: `lopdf` on `many_objects` reads 485 MiB both ways). A capped global allocator (3 GiB) in the probe stops any run before it can push the machine into swap; hitting it shows as `CRASH SIGABRT alloc cap` |
| Fixtures | 18 files from `gen_fixtures.py` (standard library only, nothing downloaded) |

### Robustness (item 1)

Outcome per run. "ok" means the library returned a result; whether that result is right is in the note.

| Fixture | lopdf (lenient) | lopdf strict | pdf-rs | own sketch |
| --- | --- | --- | --- | --- |
| `valid` (3 pages, classic xref) | ok, 3 | ok, 3 | ok, 3 | ok, 3 |
| `valid_xrefstream` | ok, 3 | ok, 3 | ok, 3 | ok, 3 (rebuilt by scan: no xref-stream support) |
| `deep_nesting` (10⁵ `[` in catalog) | **ok, 0 pages, no error** | error | error | error `Depth` |
| `deep_nesting_dict` (10⁵ `<<`) | **ok, 0 pages, no error** | error | error | error `Depth` |
| `deep_nesting_content` (10⁵ `[` in content) | error | error | ok, 1 op | n/a (no content parser) |
| `prev_loop` (A→B→A) | ok, 1 | ok, 1 | error | ok, 1 (loop detected, rebuilt) |
| `prev_self_loop` | ok, 1 | ok, 1 | error | ok, 1 (loop detected, rebuilt) |
| `xref_size_2g_table` (`/Size 2³¹`) | ok, 3 | ok, 3 | error (refuses `/Size` > 10⁶) | ok, 3 |
| `xref_size_2g_stream` (`/Size`, `/Index` 2³¹) | ok, 1 (rebuilt) | error | error | ok, 1 (rebuilt) |
| `flate_bomb_content` (1 GiB zeros, 1.04 MB) | error at cap; 325 MiB RSS | same | **CRASH: tried to allocate 1 GiB+, aborted at the 3 GiB cap; 1,032 MiB RSS** | n/a (no filters) |
| `flate_bomb_objstm` (same, in an object stream) | error at cap; 325 MiB | same | **CRASH, as above** | error (no object streams) |
| `flate_bomb_many` (8 object streams × 250 MiB, 2 MB file) | **ok: 2 GiB inflated, 1.0 s, 2,521 MiB RSS** | same, 2,173 MiB | ok (lazy: never touches them) | n/a |
| `objstm_self` (ObjStm inside itself) | ok, 1 (rebuilt) | **ok, 0 pages, no error** | error | error |
| `page_tree_cycle` (2→3→2, page 4 under 3) | **ok, 0 pages, no error** | **same** | error ("page tree depth") | error `Cycle(2)` |
| `truncated` (60 %) | ok, 3 (rebuilt) | error | error | error `Syntax` |
| `broken_xref_offsets` (+5 each) | ok, 3 (rebuilt) | error | error | ok, 3 (rebuilt) |
| `broken_startxref` | ok, 3 (offset corrected) | error | error | ok, 3 (rebuilt) |
| `many_objects` (10⁶ + 4 objects, 57.7 MB) | ok, 0.27 s, **485 MiB RSS** | same | error (hard 10⁶ cap); 136 MiB | error at our 10⁶ cap; 85 MiB. With the cap raised: ok, 0.16 s, 85 MiB |

No candidate panicked, overflowed its stack or hung on any file; every run finished in under 1.1 s. Full rows with
error text: `spikes/spk-01-pdf-reader/results.md`.

### Can the caller bound it? (item 1, last question)

| docs/21 limit | lopdf 0.47 | pdf-rs 0.10 | own |
| --- | --- | --- | --- |
| Single stream decoded (256 MiB) | **Yes**, `LoadOptions::max_decompressed_size`, `get_page_content_with_limit`; peak heap ≈ 2× the cap (Vec doubling) | **No**: no cap anywhere | Yes (design) |
| Total decoded per document (1 GiB) | **No**: object streams are inflated inside `load`; `flate_bomb_many` inflated 2 GiB. A 50 MiB file could hold ~200 such streams (extrapolated, not run) | No | Yes (design) |
| Decode ratio | No | No | Yes (design) |
| Filter chain length (8) | Fixed 16 | No | Yes |
| Indirect objects (10⁶) | **No**; memory ≈ 8.4× file size on tiny objects | Fixed 10⁶ from `/Size`, which it also pre-allocates (`Vec::with_capacity(/Size)`) | Yes, `Limits::max_objects` |
| `/Size` never sizes an allocation | Holds on these files | **Violated** up to 10⁶ entries | Holds (count checked against bytes present) |
| Revisions (1,000) | Loop-safe; count exposed as `xref_section_count`, so checkable afterwards | Loop-safe, no cap (`Vec::contains` per step) | Yes |
| Nesting depth (256) | Fixed 100; lenient mode then **drops the object silently** | Fixed 20 | Yes, iterative parser |
| Reference depth (64) | Fixed 128 | — | Yes |
| Pages (5,000) | No; page-tree cycles end iteration **silently** | Trusts `/Count` for the page count | Yes, visited set |
| Time budget / cancellation (SEC-P10) | **No hook** | **No hook** | Yes (design: predicate in every file-driven loop) |
| Errors map to `CS-PDF-*` | Typed enum: mappable | Strings with the build machine's source paths in them | Typed by construction |

## 3. Recovery (item 2)

`lopdf` lenient mode rebuilt `broken_xref_offsets`, `truncated` and the xref-stream `/Size 2³¹` file by scanning, and
corrected a wrong `startxref`, reporting which in `Document::xref_recovery` (`Reconstructed`, `OffsetCorrected`): the
`CS-PDF-0101` report is available. `pdf` 0.10 has no recovery; its `repair.rs` is not compiled. The sketch rebuilds by
scanning line starts for `n g obj` and finding the catalog; it recovered the broken offsets, bad `startxref` and both
`/Prev` loops, but not `truncated` (a cut object fails the page walk; `lopdf` drops it and carries on).

## 4. Incremental update (item 3)

`src/bin/append.rs` adds one new object (and, for `lopdf`, a changed catalog) to `valid.pdf` (classic xref) and
`valid_xrefstream.pdf`, saves twice, and re-opens the result with all three readers.

| Case | Prefix bytes equal | xref form (orig → new) | `/Prev` = original `startxref` | Deterministic | Re-opened by lopdf strict / pdf-rs / own |
| --- | --- | --- | --- | --- | --- |
| lopdf, classic | yes | table → table | yes (693) | yes | 3 pages, change visible / 3 / 3 |
| lopdf, stream | yes | stream → stream | yes (693) | yes | 3, change visible / 3 / 3 |
| pdf-rs, classic | yes | **table → stream** | **no `/Prev`** | yes | 3 / 3 / 3 |
| pdf-rs, stream | yes | stream → stream | **no `/Prev`** | yes | 3 / 3 / 3 |
| lopdf, over `broken_xref_offsets` (recovered on load) | yes | table → table | **no `/Prev`** | yes | **0 pages, no error** / error / error |
| pdf-rs, over `broken_xref_offsets` | refused (cannot read it) | | | | |

`lopdf::IncrementalDocument` meets docs/30 §9 on sound files: no second header, only changed objects, xref in the
original's form, `/Prev` chained. Two cautions. `IncrementalDocument::load*` reads without `LoadOptions` (so without
the caller's limits); build it with `create_from(bytes, doc)` instead. And over a document it had to repair, it writes
an update **without `/Prev`** and without error: the result has an xref listing only the three new entries, which
lopdf itself then reads as 0 pages. An incremental update over a repaired file must be refused, never written.
`pdf` writes an xref stream covering every object, always, and its `Trailer::prev_trailer_pos` is an `i32`.

## 5. WASM (item 4)

`cargo build --profile wasm --target wasm32-unknown-unknown -p wasm-<x>`, each package built alone; profile:
`opt-level = "z"`, `lto = true`, `codegen-units = 1`, `panic = "abort"`, `strip = true`. Program: parse bytes handed in
from JS and count pages.

| Candidate | Builds as-is? | `.wasm` | gzip -9 |
| --- | --- | ---: | ---: |
| lopdf 0.47 | **No.** `getrandom` 0.4 (through lopdf's unconditional `rand`, used for encryption) fails with a `compile_error!`. Builds with lopdf's `wasm_js` feature, which adds `wasm-bindgen` imports, including `crypto.getRandomValues`; the module then needs `wasm-bindgen` glue to load | 670,568 B | 295,965 B |
| pdf-rs 0.10 | Yes | 653,494 B | 260,879 B |
| own sketch | Yes | 59,117 B | 32,402 B |

The sketch has no filters, xref streams or decryption, so its size is a floor, not a comparison; with `miniz_oxide`
and the RustCrypto ciphers it would still be expected well under the others (estimate, not measured).

## 6. Licence and maintenance (item 5)

From crates.io and the GitHub API on 2026-11-10. Both pass this repository's `deny.toml` (`cargo deny check licenses
bans` on each probe crate: ok).

| | lopdf | pdf (pdf-rs) |
| --- | --- | --- |
| Licence | MIT | MIT |
| Latest release | 0.47.0, 2026-11-04 | 0.10.0, 2026-03-02 (0.9.0 2023-11 → 0.9.1 2025-12) |
| Cadence | 0.42 → 0.47 between June and November 2026: six breaking minor releases in five months | Slow |
| MSRV | 1.88, the same as ours: any bump breaks our `cargo +1.88.0 check` gate | Not declared |
| Repository | 2,292 stars, 87 open issues and PRs, pushed 2026-11-04 | 1,719 stars, 38 open, pushed 2026-11-07 |
| Open issues mentioning "panic" | 8 (27 closed), including #615 "Fuzzing: issues found when testing public functions with random inputs" (2026-10-18), #440 an `unwrap` panic in the parser, #441 an assertion in `weezl` | 4 (36 closed), including #131 "Panics when trying to parse a PDF with Forms & Digital Signatures" and #101 "Parse PDFs with broken xref section" |
| Transitive crates, approximate (`cargo tree`, normal deps) | ≈ 66 | ≈ 65 |

## 7. The sketch, and the effort of the real thing (item 6)

`own/src/lib.rs`, 300 lines, dense formatting (about 500 after `rustfmt`). It has a lexer for all token types, string
escapes and name `#xx` escapes with length caps; an **iterative** object parser (an explicit stack, so 10⁵ levels is a
counted error, never a stack overflow); classic xref sections whose counts are believed only as far as the bytes
present; a `/Prev` chain with a visited set and revision cap; header checks on every xref entry, falling back to a
scan; reference resolution with a depth cap; and a page walk with a visited set and page cap that never trusts
`/Count`. Errors are a typed enum carrying offsets and object numbers only.

What a product reader and writer still needs, with estimates:

| Part | Product lines (estimate) |
| --- | ---: |
| Lexer, parser, classic xref, recovery, page tree (the sketch, hardened) | 900 |
| Xref streams, object streams, hybrid files, indirect `/Length` | 400 |
| Filters with per-stream, per-document and ratio budgets: Flate (`miniz_oxide`, streaming), LZW (`weezl`), ASCIIHex, ASCII85, RunLength, PNG/TIFF predictors; image codecs passed through undecoded | 500 |
| Standard security handler, RC4 / AES-128 / AES-256, through library primitives | 400 |
| Incremental writer, table and stream forms, deterministic serializer | 400 |
| Fresh-file writer for normalization | 300 |
| Limits, cancellation predicate, `CS-PDF-*` errors, admission report plumbing | 150 |
| **Total** | **≈ 3,050**, plus 1,000–1,500 lines of tests, hostile fixtures and fuzz targets |

That is roughly 4–6 engineer-weeks. `lopdf::IncrementalDocument` and lopdf's recovery heuristics are good MIT-licensed
references for behaviour, and `lopdf` (no default features) is the differential oracle in tests: every corpus file
must give the same page count and object set from both readers, or the difference is explained.

## 8. Recommendation against the threats

| Threat ([07](07-SECURITY-THREAT-MODEL.md)) | With lopdf + wrapper (option b) | With our own reader (option a) |
| --- | --- | --- |
| SEC-P01 decompression bomb | Per-stream cap only; per-document total and ratio unenforceable during `load` (measured: 2 GiB, 2.5 GiB RSS) | All three caps in the inflate loop |
| SEC-P02 object count | No cap; ~8× memory amplification; a file-size cap is the only lever | Counted cap; 85 MiB for 10⁶ objects |
| SEC-P03 nesting, reference cycles | Safe (fixed 100), but over-deep objects vanish silently in lenient mode | Counted, typed `CS-PDF-0004` |
| SEC-P04 `/Prev` loops | Handled | Handled |
| SEC-P05 page-tree cycles | **0 pages, no error.** The wrapper would have to re-walk the tree itself | Typed `CS-PDF-0007` |
| SEC-P10 slow parse | **Cannot be bounded in-process**; only by a killed worker or process | Host predicate in every loop |
| SEC-P11 parser differential | Silent drops and lenient repairs we did not choose; partly visible through `xref_recovery` | Every repair is ours and reported (`CS-PDF-0101`, `-0102`) |
| ADR-004 engine purity, WASM | An RNG and `wasm-bindgen` imports in the engine | None |

Option (b) would be "wrap lopdf, re-implement the page walk, add a file-size cap, run it in a killable worker, and
accept the rest", which keeps most of the work and leaves SEC-P01 and SEC-P10 open. So: **(a)**, with ADR-005
unchanged, and lopdf as the test oracle it already names.

## 9. Not measured

- **Real-world files.** No corpus was used; how many ordinary PDFs each reader opens is unknown. `lopdf` is certainly
  ahead of the sketch here; the product reader must be measured against a corpus before Phase 1A closes.
- Encrypted files, LZW bombs, chained filters, broken predictors, linearized and hybrid-reference files.
- Fuzzing of any candidate.
- Linux and Windows; threads with small stacks (all runs on the 8 MiB main thread; `lopdf` and `pdf` limit recursion
  depth, the sketch does not recurse).
- `flate_bomb_many` at larger N: the 50 MiB-file figure (~200 streams) is extrapolated, not run.
- pdf-rs without our 3 GiB allocator cap (a host would have allocated until the OS stopped it).
- The heap counter and RSS disagree on `flate_bomb_many` (501 MiB live heap, 2.5 GiB RSS); the gap is presumably
  allocator-retained pages and was not investigated. RSS is the figure quoted.
- The WASM modules were sized, not run.
- GitHub issue counts beyond the queries listed (the unauthenticated API rate limit was reached).

## 10. Defects found in other documents

For the main session to turn into rows; this spike edits none of them.

1. **[30](30-PDF-PIPELINE.md) §9, "Object numbers come from `/Size`".** `/Size` is a number from the file and may be
   2³¹ (`xref_size_2g_table`) or smaller than the highest object present. New numbers should be
   `max(/Size, highest object number read + 1)`, refused above the 8,388,607 architectural limit of ISO 32000-1 Annex C, and never an allocation
   size ([21](21-PARSER-LIMITS.md) already says the last).
2. **[30](30-PDF-PIPELINE.md) §2, "structurally sound" for appending to signed input** is undefined. §4 shows why it
   matters: an update over a file that needed repair loses its `/Prev`. Suggest "read without any `CS-PDF-0101`
   recovery".
3. **ADR-006 does not name the primitives decryption needs.** [30](30-PDF-PIPELINE.md) §2 promises RC4, AES-128 and
   AES-256 standard-handler decryption (MD5, RC4, AES-CBC, SHA-256/384/512), while CLAUDE.md says primitives come only
   from the libraries ADR-006 names (`aws-lc-rs`, RustCrypto structure crates). `aws-lc-rs` has no RC4; RustCrypto
   `rc4`, `md-5`, `aes`, `cbc`, `sha2` would need adding to ADR-006.
4. **[21](21-PARSER-LIMITS.md), decode ratio 1:1000.** A single Flate stream cannot exceed about 1,032:1; the 1 GiB
   zero bomb here is 1,028:1. The ratio cap therefore only bites on chained filters; the absolute caps do the work for
   plain Flate. Not wrong, but the table reads as if the ratio were the main defence.
5. **[21](21-PARSER-LIMITS.md), the `/Size` row has no error code**, unlike every other PDF limit.
6. **Process:** `tools/check-repo.py` (the pre-commit hook) fails any commit that adds a `docs/*.md` not linked from
   [00](00-README.md), while workers are told not to edit docs/00. A worker cannot commit a new document without
   either breaking the brief or the hook.

## 11. Reproduce

```sh
cd spikes/spk-01-pdf-reader
python3 -I gen_fixtures.py                     # 18 files, ~63 MB; large ones are .gitignored
CARGO_BUILD_JOBS=2 cargo build --release
python3 -I run_probes.py target/release/probe fixtures > results.md
./target/release/append fixtures out-append > results-append.md
CARGO_BUILD_JOBS=2 cargo build --profile wasm --target wasm32-unknown-unknown -p wasm-own   # and -p wasm-pdf, -p wasm-lopdf
cargo clean
```
