# 33 — ML models (pretrained, no training)

Status: **Accepted** (ADR-029; owner, 2026-11-12, instruction 30). **Partly built:** the modeld skeleton (`ML-09`),
and pieces C and D (2026-11-12): the rasteriser in a killable child, the rule and box finder, OCR with PP-OCRv6
measured on the synthetic scans (§5.1), DOC_OPEN and OCR on the wire, the fixed log filter. The server side (`WEB-19`, 2026-11-13): settings, entitlements, runs, suggestions and their routes, and the worker's two jobs (§7 As built). Owner instructions
27, 28 and 30: ML before LLM, PaddleOCR for OCR, and for now only pretrained models that need no training, built now
in parallel with the UI and workspace work. Rows: `ML-01` (seam), `ML-09` (the model process), `ML-02` (OCR),
`ML-02B` (rules and boxes on scans), `ML-05` (template matching), `ML-07` (pretrained extraction and search;
CUAD fine-tuning deferred), `ML-07A` (the pretrained half's exit), `ML-08` (personal data and console alerts),
`FLD-L10N` (localized detector labels). `ML-03`, `ML-04` and every `LLM-*` row are out of scope: they need training
or an LLM. `ML-06` is an open owner question (§5.8).

The design was revised for an adversarial review before acceptance; §16 lists each defect and where it is fixed.
Figures marked *est.* are research estimates, not measured on our hardware; §15 lists what must be measured before
an exit is claimed.

**Invariants**
1. No model, weight, tokenizer or runtime enters `crates/`. Engine crates stay pure, deterministic and wasm32. The
   only engine crate this note adds, `casual-sign-pii`, holds deterministic recognisers and no model.
2. Every output is a **suggestion**. A person accepts, edits or dismisses it. Suggestions are never written into a
   sealed document, an audit event's hash chain, the certificate of completion or the evidence package. A suggestion
   a person accepts becomes an ordinary edit (a field posted, a template applied), recorded as that edit always is.
3. With every ML feature off, every flow behaves byte for byte as it does today and no ML job is enqueued (`ML-01`
   acceptance).
4. No network egress from the model process, at build or at run time, except the one hash-checked fetch in the image
   build (§8). Weights and the ONNX Runtime library are pinned by SHA-256.
5. Document text, OCR text, entities, personal-data spans, embeddings, page hashes and rasters are **document
   content** (`SEC-D*`). They never appear in logs, metrics, errors or the op log, including logs written by
   third-party crates (§3.4).
6. No training on customer documents. Nothing here learns from them; thresholds are tuned on synthetic fixtures.
7. The secret-holding worker never links the inference stack (§1, `SEC-I14`).

## 1. Where it runs

    server ──(upload admitted, entitlement on)──► jobs: analyze_document / fingerprint_template
                                                     │
    worker (claims job; holds DB/SMTP/keyd secrets)  │  reads stored normalized PDF + engine text layer
         │  links casual-sign-modeld with default-features = false: wire + client only
         │  mTLS frames (§3)                         ▼
         └──────────────────────────────► casual-sign-modeld (no secrets, no egress, read-only weights)
                                             ├─ raster child process per document (hayro; killable alone)
                                             ├─ PP-OCR · rule/box finder · dHash/pHash
                                             └─ e5-small embeddings · GLiNER NER · GLiNER-PII
         ◄─ words+boxes, rules, hashes, vectors, spans (byte offsets) ─┘
    worker → casual-sign-pii (deterministic recognisers) and normalisation rules
    worker → casual_sign_fields::detect_fields(PageText from OCR) → suggestions table (outside the chain)
    web app / API → GET suggestions → person accepts → normal field/template/metadata endpoints

- **`casual-sign-modeld`** (new, `server/`, native only, excluded from the wasm32 check like keyd). It copies keyd's
  `wire.rs`, `server.rs`, `client.rs` and `oplog.rs` with provenance (PROVENANCE.md). **Every inference dependency
  (`ort`, `oar-ocr`, `hayro`, `tokenizers`, `image_hasher`) is optional, behind the crate's `server` feature**, which
  is in its default features and is a `required-features` of the `casual-sign-modeld` binary. The worker depends on
  it with `default-features = false` and so gets the wire format and client only. Cargo unifies features across the
  packages selected in one build, so images build the worker with `cargo build -p casual-sign-worker`, and a test runs
  `cargo tree -p casual-sign-worker -e normal` and fails if `ort`, `oar-ocr`, `hayro`, `tokenizers` or `onig_sys`
  appears (`SEC-I14`).
- **Deterministic personal-data recognisers** (§5.4 layer 1) are not models. They live in a new pure engine crate,
  **`casual-sign-pii`** (owner decision D7(a)). `phonenumber` builds for wasm32-unknown-unknown with no I/O (checked
  in piece J, 2026-11-12), so the crate exists and no worker module is needed. The browser
  can then preview redactions with the same code.
- **Date, money and duration normalisation** is rules in Rust, in the worker. A relative date resolves against a
  supplied base (the envelope's recorded time), never the clock.
- The **Compose** service `modeld` sits under an optional profile `ml`, on a new network with `internal: true` (Compose
  defines no networks today), with a read-only root filesystem and weights mount, running as non-root with a memory
  limit, a `pids` limit, the default seccomp profile, no core dumps (`ulimit -c 0`) and tmpfs for scratch. Without the
  profile the worker's ML client is unset and no ML job is enqueued.

## 2. Jobs

| Kind | Enqueued by | Payload | Idempotency key |
| --- | --- | --- | --- |
| `analyze_document` | server, in the transaction that admits an upload to a draft envelope, when the workspace has any ML feature on; or `POST …/analysis` (as built, template uploads get `fingerprint_template` only; entities on templates wait, §7 as built) | `{account_id, document_id, envelope_id?, template_id?, uses: [ocr, template, entities, personal_data], document_sha256}` | `analyze:{account_id}:{document_id}:{document_sha256}:{uses}:{bundle_id}` |
| `fingerprint_template` | server, on template document add or change, when `template` is on | `{account_id, template_id, document_id, document_sha256}` | `fingerprint:{account_id}:{template_id}:{document_id}:{document_sha256}:{bundle_id}` |

**Both keys carry the account and the document id.** Two accounts that upload the same bytes get two runs, and so
does one account that uses the same bytes in two envelopes; no run is ever shared across accounts or documents
(`SEC-I06`, tested with two accounts uploading identical bytes). `uses` is written in a fixed order.

These are advisory jobs in the `jobs` table (ADR-012) beside the effect jobs (ADR-011). They are added to
`casual-sign-host::jobs` as non-effect kinds and touch no envelope state. `max_attempts` is 3. A dead job means only
"no suggestions"; it never blocks sending or sealing. Steps:

1. Load the stored normalized PDF and the engine's `PageText` per page (existing code).
2. **OCR pages** = pages with no text runs, or whose only text is invisible (render mode 3: a scanner's OCR layer)
   when the workspace chose "re-read scanner text". Up to the page cap.
3. `DOC_OPEN` once per job (the PDF crosses the wire once), then one `OCR` request per page → words, boxes,
   confidences, rules, boxes drawn. Convert pixel space to displayed page space (ADR-019: points, top-left;
   `x_pt = x_px × 72 / dpi`, the raster already includes `/Rotate` and the crop box) and build `PageText` runs marked
   OCR-sourced. Call `detect_fields` on the merged pages.
4. `HASH` per page and `EMBED` (template) → compare with the account's fingerprints (§5.2).
5. `casual-sign-pii` over the text; `ENTITIES` and `PERSONAL_DATA` frames over text chunks → spans as byte offsets
   into text the worker already holds (§3.2).
6. Write one `analysis_runs` row and its `suggestions` rows in one transaction.

## 3. modeld protocol

Mutual TLS 1.3 as keyd (worker identity on modeld's allow list). Frames as keyd's `wire.rs`:

    frame    = len:u32be body        (len <= 64 MiB for DOC_OPEN and, while it carries its PDF, HASH; 4 MiB otherwise)
    request  = 0x01 op deadline_ms:u32be account:str8 job:str8 body
      op 0x01 INFO        → bundle_id:str8, n:(model_id:str8 sha256:32B)*, ort_version:str8
      op 0x07 DOC_OPEN    pdf:bytes32 → doc:u32 pages:u32   (valid on this connection only; one per connection)
      op 0x08 DOC_CLOSE   doc:u32 → (empty)
      op 0x02 OCR         doc:u32 page:u16 dpi:u16 scripts:(str8)*
                          → page:u16 status:u16 code, width:u16, height:u16, dpi:u16 (as rendered),
                            rotate:u16, crop:(x0,y0,x1,y1:f32 user space),
                            words:(text:str16 quad:4×(f32,f32) conf:u16)*, lines:(quad)*,
                            rules:(x0,y0,x1,y1:f32)*, boxes:(x0,y0,x1,y1:f32)*
      op 0x03 HASH        doc:u32 page:u16 → dhash:u64 phash:u64
                          (built today as pdf:bytes32 pages:(u16)*; moves to a handle with piece I)
      op 0x04 EMBED       kind:u8 (query|passage) texts:(str32)*  → vectors (f32 × 384, L2-normalized)*
      op 0x05 ENTITIES    text:str32 labels:(str8)* threshold:u16 → spans (start:u32 end:u32 label:u8 score:u16)*
      op 0x06 PERSONAL    text:str32 labels:(str8)* threshold:u16 → spans as ENTITIES
    response = 0x01 0x00 ok-body | 0x01 0x01 code:u16be
    str8 ids = [A-Za-z0-9._-]{1,64}; text fields are UTF-8 and NFC, checked, never logged

### 3.1 Document handles

A handle names a PDF this connection opened. It is never shared across connections, accounts or jobs, and nothing
survives a connection: modeld keeps no cache keyed across requests (`SEC-I06`). An unknown handle is `CS-ML-0004`, as
is a second DOC_OPEN while one is open. Built (`src/server.rs` `ConnectionState`): the daemon holds the PDF in memory
for its connection and hands it to the raster child over a pipe (no file is written, so no tmpfs is needed); DOC_CLOSE
or the end of the connection drops it and ends the child. The handle is checked before the model, so a wrong handle
is `CS-ML-0004` even where OCR is not installed (`tests/mtls.rs`).

Every OCR page carries the geometry the rasteriser used: the resolution it rendered at (lower than asked when the
page exceeds the raster cap), `/Rotate`, and the crop box (intersected with the media box) in user space. The worker
maps a pixel to displayed page space with `OcrPage::to_displayed` (`x_pt = x_px × 72 / dpi`) or to user space with
`OcrPage::to_user`, without parsing the PDF itself (`src/wire.rs`; tested against real rasters within 1 pt for every
`/Rotate` with a crop box offset).

### 3.2 Span offsets

Spans return **offsets, not text**, so a response carries no extracted personal data. `start` and `end` are **UTF-8
byte offsets into the exact text the worker sent**, which the worker has already put into NFC and, for right-to-left
OCR output, into logical order. modeld maps token and word positions back to these byte offsets and never returns an
offset inside a UTF-8 sequence (`CS-ML-0013` if it would). Tested with Arabic, Devanagari and Latin text with
combining marks.

### 3.3 Deadlines, rasterising and concurrency

- **Rasterising runs in a child process**, one per `DOC_OPEN`, started from the modeld binary with a fixed
  subcommand, an address-space limit (`RLIMIT_AS`, provisional 1 GiB, set from measurement), a CPU-time limit and no
  inherited descriptors besides its pipes. `hayro` cannot cancel a render, so the per-page time cap is enforced by
  killing that child alone; other slots and other jobs are untouched. The page reports `CS-ML-0006`; the child is
  restarted for the next page, and after three kills in one document the remaining pages are reported `truncated`. A
  child that dies otherwise (signal, memory limit) reports `CS-ML-0014` and is counted in the op log, since it can
  mark an exploit attempt.
  **Built** (`src/raster.rs`): the child is the modeld binary run as `raster-child <address-space> <cpu-seconds>`,
  with an empty environment and stderr discarded; it sets `RLIMIT_AS` (1 GiB), `RLIMIT_CPU` (30 min, a backstop),
  `RLIMIT_CORE` 0 and `RLIMIT_NOFILE` 16 before reading the PDF. Writes to and reads from the child run on a helper
  thread so a child that stops reading cannot block the daemon; the page time also bounds opening the PDF. Deaths
  count toward the three kills. A page after the third is answered `CS-ML-0006` without starting a child (the
  worker counts it as `truncated`). The child also renders no annotations: OCR reads what the scanner produced.
  **Platforms (`CI-NEW`, 2026-11-13): Linux only.** The child's limits are the containment, and only Linux enforces
  `RLIMIT_AS` (macOS accepts it and ignores it; Windows has no `setrlimit`). modeld ships in a Linux container, so on
  any other platform `Document::open` starts no child and answers `CS-ML-0014`, a typed refusal, and a child started
  there by hand exits before reading the PDF. `rustix` is a Linux-only dependency; the tests that need a child run on
  Linux, and `off_linux_opening_a_document_is_refused_with_raster_child` runs on the macOS and Windows CI jobs.
- **Inference deadline:** the client sets a deadline per op (§4). modeld cancels at the deadline with ONNX Runtime's
  run terminate flag (`RunOptions::terminate()` in `ort` 2.0.0-rc.13). A watchdog ends the process at 2× deadline,
  and Compose restarts it. The worker's socket timeout is the deadline plus 5 s. **Not built yet:** `oar-ocr` 0.10.2
  does not expose its sessions' run options, so today an op that overruns is answered `CS-ML-0007` only after it
  ends, and no watchdog runs (a finding row; the fallback is D3(b), our own pre- and post-processing).
- **Concurrency:** a semaphore of `OPENSEAL_MODELD_SLOTS`. Its default is derived from memory, not only cores:
  `min(max(1, cores ÷ 2), floor((memory_limit − model_rss) ÷ per_slot_peak))`, where `model_rss` is measured at start
  after every session loads and `per_slot_peak` is provisional 512 MiB (a raster child's cap plus ORT working memory;
  measured in `ML-09`). `memory_limit` is `OPENSEAL_MODELD_MEMORY_LIMIT` (bytes, or `KiB`/`MiB`/`GiB`), else the
  cgroup v2 `memory.max`, else 4 GiB; `model_rss` is `VmRSS` from `/proc/self/status` (built in the skeleton, with no
  inference session loaded yet). If that is below 1, modeld refuses to start (`CS-ML-0001`). A value set by the operator above
  the derived one is refused the same way. When full, modeld answers busy (`CS-ML-0009`) and the worker retries with
  back-off.

### 3.4 Logging

- **Op log:** op, account id, job id, page count, word, span or vector counts, milliseconds, code, bundle id. Never
  text, labels' matches, boxes, hashes or vectors.
- **Third-party logs are filtered.** `oar-ocr` 0.10.2 writes recognised text and boxes to `tracing` at debug level
  (`stitching.rs`, `structure.rs`, and `oar-ocr-core`'s formula adapter). modeld installs one fixed subscriber that
  drops every event below WARN from `oar_ocr*`, `ort`, `hayro*` and `tokenizers`, and **ignores `RUST_LOG` for those
  targets**. ONNX Runtime's own logger is set to `error`. The log-scrubber test (`SEC-I05`) runs every op at trace
  level with a marker string in the input and fails if the marker appears in any output stream; it is seen red with
  the filter removed.
- **Built** (`src/logging.rs`): a `tracing_subscriber::filter::Targets` with every target at WARN by default and
  `ort` (ONNX Runtime's log, routed through `ort`'s `tracing` feature) at ERROR; `RUST_LOG` is read once and may only
  raise `casual_sign_modeld*` (a bare level is read as modeld's), so no directive reaches a third-party target. The
  scrubber (`tests/log_scrub.rs`) runs with the real OCR weights, checks that OCR read the marker, and fails on the
  marker or on any third-party event below its cap; with the filter opened the marker reached the log.

## 4. Bounds and limits (docs/21 §ML)

| Limit | Default | Code |
| --- | ---: | --- |
| modeld frame: `DOC_OPEN`; every other frame | 64 MiB (a 50 MiB upload plus headers); 4 MiB | CS-ML-0004 |
| Open documents per connection | 1 | CS-ML-0004 |
| Pages OCR'd per document | 200; later pages are not read (`truncated`) | — (report) |
| Render resolution | 150 DPI (host may set 100–200) | CS-ML-0001 |
| Raster size per page | 4,096 px on the long side, 16.8 MP; checked from the page box **before** allocation; larger pages render at a lower DPI | CS-ML-0005 |
| Decoded image data per page during rasterising | 256 MiB (as `SEC-P01`) | CS-ML-0005 |
| Rasterise time per page | 10 s, enforced by killing the raster child | CS-ML-0006 |
| Raster child kills per document | 3; remaining pages `truncated` | — (report) |
| OCR deadline per page / per job | 20 s / 15 min | CS-ML-0007 |
| Words per OCR page | 20,000 (= `MAX_DETECT_WORDS`) | — (truncated) |
| Text per ENTITIES/PERSONAL call; per document | 64 KiB; 4 MiB | CS-ML-0005 |
| Window | e5: 512 tokens; GLiNER (built, piece K): at most the config's `max_len` words (multi and small 384, PII 2,048) and 2,048 tokens per window, prompt and special tokens included; each next window starts 64 words (at most half a window) before the last ended; a word whose tokens alone overflow a window is skipped; candidates of all windows pooled and decoded once; 2,000 windows per call | — (truncated, deterministic) |
| Labels per call; label length | 32; 64 bytes | CS-ML-0004 |
| GLiNER label prompt | 1,024 tokens (half a window; `ML-17`) | CS-ML-0005 |
| Texts per EMBED call | 64, each ≤ 8 KiB | CS-ML-0004 |
| Suggestions per document | fields 500 (existing); entities 2,000; personal-data spans 5,000 | — (truncated) |
| Fingerprints searched per account | 50,000 page vectors in process (more need pgvector) | — |
| Concurrent slots | derived from memory (§3.3) | CS-ML-0001, CS-ML-0009 |
| modeld memory | 4 GiB container limit (provisional; set from the measured RSS of the chosen profiles) | (process restarts) |
| Model bundle | 2 GiB total; each file ≤ 1 GiB (provisional; re-set from the measured fp16 exports, §5.3) | CS-ML-0002 |

## 5. Models chosen (pretrained, no training)

Versions are those at least two weeks old on 2026-11-12. "Est." means estimated, not measured. The licence column is
the weight licence; code licences are in §5.5; training-data notes are in the weights register (docs/09 §8).

### 5.1 ML-02 OCR for scanned and image-only pages

| Part | Choice | Weights licence (source) | ONNX | Size | CPU (est.) | Languages |
| --- | --- | --- | --- | --- | --- | --- |
| Rasteriser | `hayro` 0.8.0 (0.9.0 of 2026-11-02 too new), with `hayro-jbig2`, `hayro-jpeg2000` and `hayro-ccitt` for scanned images; PDFium via `pdfium-render` 0.9.4 as a sandboxed fallback, settled by `PDF-REN-01` | Apache-2.0 OR MIT (https://crates.io/api/v1/crates/hayro); pdfium-render MIT OR Apache-2.0, PDFium BSD-3 (https://pdfium.googlesource.com/pdfium/+/refs/heads/main/LICENSE) | n/a | crate | unverified, measure in PDF-REN-01 | n/a |
| Pipeline | `oar-ocr` 0.10.2 (2026-10-26), **`default-features = false, features = ["simd"]`** (its defaults `download-binaries` would fetch ONNX Runtime at build), `auto-download` off, `return_word_box` on | Apache-2.0 (https://crates.io/api/v1/crates/oar-ocr) | ort =2.0.0-rc.13 | crate | — | — |
| Detection | PP-OCRv6_small_det | Apache-2.0 (https://huggingface.co/PaddlePaddle/PP-OCRv6_small_det_onnx) | official | 9.6 MB | v5 mobile_det 58 ms/image on Paddle's machine; v6 unpublished | script-independent |
| Recognition | PP-OCRv6_small_rec (5.2M parameters) | Apache-2.0 (https://huggingface.co/PaddlePaddle/PP-OCRv6_small_rec_onnx) | official | 20.4 MB | est. 0.5–1.5 s per page with detection | 50 languages per the card (list unverified) |
| Script packs (operator-chosen, D10(a)) | PP-OCRv5 mobile rec: arabic, devanagari, and others as needed | Apache-2.0 (https://huggingface.co/PaddlePaddle/arabic_PP-OCRv5_mobile_rec, https://huggingface.co/PaddlePaddle/devanagari_PP-OCRv5_mobile_rec; other packs checked per card when added) | **Paddle format only: exported by us** with PaddlePaddle and `paddle2onnx`, offline, hash-pinned (piece X); third-party re-hosts are not a source | 7.5–14 MB each (est.) | 21 ms per line (docs table) | per pack |
| Line orientation | PP-LCNet_x1_0_textline_ori | Apache-2.0 (https://huggingface.co/PaddlePaddle/PP-LCNet_x1_0_textline_ori) | Paddle format only: exported by us as above | 0.96 MB | ms per line (est.) | — |
| Rules and boxes on scans (`ML-02B`) | Our code in modeld: binarise, morphological horizontal and vertical runs ≥ 36 pt, rectangles 2.5–100 pt tall (the `Shape` definition in `-fields`) | n/a | n/a | — | < 50 ms per page (est.) | — |

**Built and measured (2026-11-12, pieces C and D).** `src/raster.rs` renders with `hayro` 0.8.0 in the raster child
(§3.3); `src/rules.rs` finds rules and boxes (Otsu threshold; rules from ink runs of at least 8 pt joined across
neighbouring rows, so a rule skewed by 2° or touched by typed text stays one; boxes as two horizontal and two vertical
lines closing a rectangle 2.5–100 pt tall, whose edges are not also rules); `src/ocr.rs` runs `oar-ocr` with ONNX
Runtime loaded from the bundle, the recogniser's dictionary read from its pinned `inference.yml`, CPU only and one
thread per session, `return_word_box` on, lines split into words whose quads follow the line. A page whose median
line confidence is below 0.75 is read again turned half round and the more confident reading kept (an upside-down
scan; no model needed). Measured on the 15 scans of `fixtures/ml` rendered at 200 DPI through DOC_OPEN and OCR:

| Measure | Result |
| --- | --- |
| Latin word recall (11 scans, 1,476 words; script-font signatures not counted) | **99.25%** (1,465); per file 96.7% (the upside-down page) to 100% |
| Arabic word recall (2 scans, 38 words) | 0%: PP-OCRv6 small has no Arabic characters; the `arabic` pack awaits its export (piece X) |
| Devanagari word recall (2 scans, 38 words) | 0%: as Arabic, the `devanagari` pack awaits its export |
| Drawn field evidence found (rules, underscore runs, boxes; 126 fields on all 15 scans, at each scan's resolution) | **99.2%** (125); the miss is one entry box on a filled 150 DPI scan |
| A rule mapped back to PDF user space, every `/Rotate`, crop box offset, 100–200 DPI | within 1 pt |
| OCR time per page, debug build, this development machine | 4–12 s (not the reference machine, not a release build; §15 stays open) |

Text-line orientation (PP-LCNet) and the script packs are loaded when the bundle holds them; neither is exported yet,
so neither is measured.

OCR words become `TextRun`s (characters spaced across the word box when per-character positions are missing) with
`size` set to the box height. Arabic output gets bidi reordering to logical order, and all text gets NFC, before
labels are matched and before any span offset is taken (§3.2). **Gap:** `detect.rs` matches English labels only
("signature", "date", "name"…), so non-Latin OCR gives no field suggestions until the labels are localized
(`FLD-L10N`); the ML-02 exit measures Latin-script scans first. OCR text never leaves the analysis tables; the
sealed PDF gets no text layer from it.

### 5.2 ML-05 Template matching

Stage 1 is layout: render each page at 72 DPI greyscale, then compute dHash and pHash (64-bit) with `image_hasher`
3.1.1 (MIT OR Apache-2.0, https://crates.io/api/v1/crates/image_hasher; `image` without decoders, fed raw pixels).
They are stored as `BIGINT` and compared by Hamming distance. No model is needed.

**Built (piece I, `ML-05`), `server/casual-sign-modeld/src/hash.rs`:** dHash is `image_hasher`'s `Gradient` over a 9×8
resize, pHash its `Median` over the 8×8 low frequencies of a 16×16 DCT; pages are rendered on white and converted to
grey by Rec. 601 luma. A page over 4,096 px a side renders at a lower resolution (docs/21). Because piece C's raster
child is not built yet, HASH renders with `hayro` **in process**: a panic is caught and answered `CS-ML-0006`, but there
is no per-page time cap, decoded-image budget or `RLIMIT_AS` until `render_each` is replaced by piece C's raster call
(`SEC-I01`, a recorded gap). Pages are rendered one at a time, each hashed and its raster dropped before the next, so
a request holds one page raster, not all of its up to 200; the request deadline is checked before every page. Measured on fixtures/ml (scan against its vector original, dHash / pHash Hamming
distance): blank-form scans at 150–300 DPI with JPEG q60–q75 or fax and skew up to ±2° are 1–9 / 0–6, and the one
turned 90° is 5 / 2; filled scans are 3–15 / 2–8 (dHash over 10 on `latin-acroform` filled at 150 DPI, 15, and
`latin-consent` filled, 11); a scan turned 180° is 26 / 34, so an upside-down scan does not match until orientation is corrected first. The acceptance pair
(`latin-consent` at 200 DPI, q75, +0.6°) is 4 / 2, and another form is over 10.

Stage 2 is text: one passage embedding per page from text-layer or OCR text.

**Built (piece I), `src/embed.rs`:** e5's `query: ` or `passage: ` prefix is added by modeld from the request's kind;
each text is tokenized and run alone (512 tokens with `<s>` and `</s>`, cut at the end, no padding, so a vector never
depends on the other texts of a call); the last hidden state is mean-pooled and L2-normalised, as the checkpoint's
sentence-transformers pipeline declares. ONNX Runtime runs CPU only, one intra- and one inter-op thread, sequential,
full graph optimisation (`src/runtime.rs`, loading the bundle's `runtime/libonnxruntime.so`). **fp16 (owner
instruction 34):** `tools/ml/export-e5.py` converts the pinned fp32 ONNX to fp16 (fp32 inputs and outputs) and writes
golden vectors from the fp32 PyTorch reference over 24 synthetic texts in 15 languages (`fixtures/ml/e5-golden`). In
modeld the token ids equal the reference's exactly, the fp32 file's lowest cosine is 1.0000000 and the fp16 file's
0.9999999, so the fp16 file passes the 1e-3 bound and modeld prefers it (`e5-small-fp16`) when a bundle holds it; until
it is hosted (`ML-15`) bundles carry fp32.

| Model | Weights licence (source) | ONNX file | Size | CPU (est.) | Languages | Verdict |
| --- | --- | --- | --- | --- | --- | --- |
| intfloat/multilingual-e5-small (`passage: ` prefix) | MIT (https://huggingface.co/intfloat/multilingual-e5-small) | **fp32 `onnx/model.onnx`** (CPU-portable); our fp16 conversion of it passes the 1e-3 cosine bound and replaces it once hosted (above). The repository's only int8 file, `model_qint8_avx512_vnni.onnx` (118,346,824 B), is quantized for AVX-512 VNNI, slow and numerically different on AVX2; `model_O4.onnx` is a GPU fp16 optimisation. Neither is used. A portable int8 export of our own (piece X) replaces fp32 only once its match results equal fp32's on the fixtures | 470 MB fp32 | 10–40 ms per 512-token page (est.) | about 100 | default (D4) |
| sentence-transformers/all-MiniLM-L6-v2 | Apache-2.0 (https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2) | official fp32; any int8 file is checked for CPU-specific quantization first | about 90 MB fp32 (unverified) | a few ms (est.) | English | "small" profile |

The tokenizer is `tokenizers` 0.23.2 (Apache-2.0, https://crates.io/api/v1/crates/tokenizers) with
**`default-features = false`** (no `http`, no `esaxx_fast` C++). `oar-ocr-core` turns on its `onig` and
`progressbar` features and Cargo merges features, so **Oniguruma (C, BSD-2-Clause, through `onig_sys`) and
`indicatif` are always compiled into modeld**. That is accepted and recorded in `SEC-I01`: tokenizer input is fuzzed
(`modeld_tokenize`). There is no pure-Rust tokenizer path.

Search is an exact cosine search in the worker over vectors read through the tenancy-scoped repository
(deterministic, no extension). pgvector 0.8.7 (PostgreSQL Licence,
https://github.com/pgvector/pgvector/blob/master/LICENSE) is an optional later path for large accounts.

A match is suggested only when **both** hold: at least 80% of pages within Hamming distance ≤ 10 of the
template's pages, and mean cosine ≥ 0.90. Both thresholds are tuned on fixtures, **with the file the bundle ships**,
to meet ML-05's false-match bound.

### 5.3 ML-07 Agreement extraction (pretrained part)

| Model | Weights licence (source) | ONNX | Size | CPU (est.) | Languages |
| --- | --- | --- | --- | --- | --- |
| urchade/gliner_multi-v2.1 (default, D5(a)) | Apache-2.0 (https://huggingface.co/urchade/gliner_multi-v2.1) | exported by us from `model.safetensors` with the `gliner` library's export, fp16 (onnx-community copies carry no licence; the int8 export loses every span, `ML-14`) | **about 289M parameters** (encoder microsoft/mdeberta-v3-base, MIT); fp32 1,155,830,112 B, over the 1 GiB file cap; fp16 579,687,008 B (measured, piece X) | est. 0.2–0.5 s per 384-word window per core | multilingual (list unverified) |
| urchade/gliner_small-v2.1 (English profile) | Apache-2.0 (https://huggingface.co/urchade/gliner_small-v2.1) | exported by us; ships only `pytorch_model.bin` (pickle), so the export follows §8's pickle rule | 166M; fp16 306,237,114 B (measured) | faster than multi | English |

Labels are passed at inference: `party organization`, `person`, `effective date`, `date`, `monetary amount`,
`duration`, `address`. **Only v2 and v2.1 checkpoints are allowed:** v0 and v1 (`gliner_base`, `gliner_multi`) are
CC-BY-NC-4.0, and the fetch script refuses them by repository id. Decoding is our own on the shared `ort`; `gline-rs`
1.1.0 (Apache-2.0, https://crates.io/api/v1/crates/gline-rs) is the reference for the span logic, not a dependency
(it requires `ort =2.0.0-rc.9`).

**Built (piece K, `server/casual-sign-modeld/src/gliner.rs`):** our own decoder on `ort =2.0.0-rc.13`
(`load-dynamic`), reproducing `gliner` 0.2.29: its whitespace word splitter (`\w+(?:[-_]\w+)*|\S` with Python's
`\w` and `\s`), the `<<ENT>>`/`<<SEP>>` prompt encoded as pre-split words by the model's `tokenizer.json`
(`tokenizers =0.23.2`), the first-sub-token word mask, every span up to `max_width`, sigmoid over the threshold, and
stable greedy flat decoding. Spans are UTF-8 byte offsets into the NFC text sent (a text not in NFC is refused
`CS-ML-0004`); scores are ten-thousandths. Windows are as §4. The run is cancelled at the deadline through ONNX
Runtime's terminate flag (`CS-ML-0007`); ONNX Runtime's logger is replaced by one that writes only the level and
category of an error, never its message. modeld loads `gliner-multi` (else `gliner-small`) for ENTITIES and
`gliner-pii-base` for PERSONAL at start; an op whose model is absent answers `CS-ML-0010`. **Files: the fp16 exports**
(owner instruction 34): the quint8 exports lose spans (`ML-14`) and are not used until `ML-14` passes. Measured
parity (`tests/gliner_golden.rs`, run with `OPENSEAL_MODELD_TEST_BUNDLE`): spans equal the golden fp16 spans of
`fixtures/ml/gliner-golden/` on all 50 texts for `gliner_multi-v2.1` (185 spans), `gliner_small-v2.1` (159) and
`gliner-pii-base-v1.0` (57), and the feeds equal the reference's `input_ids`, `words_mask` and `text_lengths`.
fp16 sizes: multi 579,687,008 B, small 306,237,114 B, PII 332,987,248 B. `tools/ml/models.toml` pins these fp16
files and their `tokenizer.json` by the golden files' SHA-256 (`ML-21`; `fetch-models.py --self-test` refuses a
GLiNER entry that is not the file the parity ran on). They are "pinned but not hosted": no URL serves our exports
until OpenSeal's mirror holds them (`ML-15`), so the three GLiNER profiles are refused at fetch and `personal_data`
left the image's default profiles; the tokenizer sizes were not recorded by the export and are filled at upload.

**Parity is checked in two separate steps** (`tools/ml/`, offline): our Rust decoder's spans equal those of Python
`onnxruntime` running **the same quantized file** through `gliner` 0.2.29's decoding (exact, after threshold); and
the accuracy lost to quantization is measured separately against the PyTorch reference and reported, never hidden
inside a parity tolerance.

Normalisation (ISO 8601 dates and durations, amount plus ISO 4217 currency) is Rust rules in the worker, with
`dateparser` 1.4.3 (BSD-3-Clause, https://pypi.org/project/dateparser/) used only offline as the cross-check.
Pretrained NER cannot tell a party from any organization named, or the effective date from any date, so every value
is a suggestion. The ML-07 exit ("F1 per field on a held-out CUAD split") belongs to the fine-tuned half; the
pretrained half closes on **`ML-07A`: F1 per label on the synthetic agreement set (§11), reported per language**.

**Agreement search (ML-07, pretrained, no training):** the same e5-small passage embeddings already loaded for §5.2
index each completed agreement's text per page in the account's own table; a search query uses the `query: ` prefix
and the same exact cosine search through the tenancy-scoped repository. No new model. Tracked as `ML-07B`.

### 5.4 ML-08 Personal-data detection

**Layer 1: deterministic, needs no model, ships first** (`casual-sign-pii`, §1). This rebuilds Presidio's pattern,
checksum and context approach (MIT; https://github.com/data-privacy-stack/presidio, formerly microsoft/presidio).
Ported logic cites the commit in PROVENANCE.md: tag 2.2.364, commit `779dbd286d5ef4d1fbe2514275fb1bce358f2417`.

**Built (piece J):** email, phone, IBAN, card, US SSN, UK NINO, IN PAN and Aadhaar, IP address, and a date of birth
(a date only after a birth context word, which Presidio lacks). Departures from Presidio, each tested: its IBAN table is
wrong for PT, MU, PS and QA and is corrected to the SWIFT registry; Mastercard's 2-series is added; look-arounds became
checks in code; a match that is the tail of a longer grouped number (a preceding digit group as wide as its own first
group, or a chain back to an IBAN's country and check digits) is not reported, so an IBAN whose check fails does not
yield a card or an Aadhaar number, while a row number or quantity before a value ("Row 1 4111 …") does not hide it.
Scores are integers in thousandths.

**Built (`ML-08C`, owner instruction 33: validation before models):** each kept only when its check or structural
rule holds, written from the identifier's published specification (not ported): US ITIN (IRS middle groups) and EIN
(IRS-assigned prefixes); ABA routing numbers (Federal Reserve prefix, 3-7-1); Canadian SIN (Luhn); UK NHS number
(mod 11); Australian TFN (weighted mod 11, nine and legacy eight digits) and Medicare (ten digits, check ninth);
German Steuer-ID (one digit twice or three times, never three in a row, ISO 7064 MOD 11,10); French NIR (mod-97 key,
Corsica 2A/2B); Spanish DNI and NIE (mod-23 letter); Italian codice fiscale (check letter, day 1–31 or 41–71,
omocodia); Dutch BSN (11-test); EU VAT for AT, BE, DE, DK, ES (NIF, NIE, CIF), FI, FR (numeric key), IT (Luhn and
office code), NL (11-test or the 2020 mod-97), PL, PT and SE; passport MRZ, TD3 second line (all five 7-3-1 check
digits); SWIFT/BIC (ISO 3166 country, location and branch rules); IMEI (Luhn); MAC-48 (one separator throughout, or
Cisco's dotted form; all-zero and broadcast refused); Bitcoin addresses, Base58Check (double SHA-256, version 0x00 or
0x05) and Bech32/Bech32m (BIP 173, 350). Labels follow Presidio's where it has the entity (`US_ITIN`,
`ABA_ROUTING_NUMBER`, `UK_NHS`, `AU_TFN`, `AU_MEDICARE`, `ES_NIF`, `ES_NIE`, `IT_FISCAL_CODE`, `CRYPTO`,
`MAC_ADDRESS`) and are ours otherwise (`US_EIN`, `CA_SIN`, `DE_TAX_ID`, `FR_NIR`, `NL_BSN`, `EU_VAT`, `PASSPORT_MRZ`,
`SWIFT_BIC`, `IMEI`).

Scoring rule: a check that random strings of the same shape pass less than about one time in a hundred (two check
digits, a check letter, a check plus a structural rule, a cryptographic checksum, a country prefix plus a check)
scores 1.0. A single check digit over a bare string of nine to fifteen digits (ABA, SIN, NHS, TFN, Medicare, BSN,
IMEI) scores 0.4, below the 0.5 callers display, and 0.75 after a context word, because about one random number in
ten passes it. No check at all keeps a pattern score as Presidio's do: ITIN 0.5 separated and 0.3 bare, EIN 0.3, MAC
0.6, SWIFT/BIC 0.1 all letters (it reads like an upper-case word) and 0.3 with a digit. A digit identifier is not
reported after "+<country code> " (a phone number), after a group of two or more digits (the tail of a longer
number), before a separator and a digit (the head of one), or touching the `<` filler of an MRZ line; a card number
touching that filler is not a card either. Our departure from Presidio's SSN rules: area 900–999 is refused (never
issued as an SSN; it is the ITIN's space).

Measured (`tests/validated.rs`, `--nocapture`), on a held-out synthetic set from its own seed, 300 values per kind,
half with a context word: every kind detected 300/300 (100%), and 0 false positives on the same values with their
check broken (for ITIN, EIN, BIC and MAC, a broken structural rule). On 2,000 random tokens holding no personal data
(1,500 bare numbers of 8 to 16 digits, 500 upper-case 8- and 11-letter words), the weak kinds find what their check
allows, all below 0.5: TFN 1.6%, IMEI 1.0%, SIN 0.8%, BSN 0.7%, NHS 0.6%, Medicare 0.6%, ABA 0.45%, ITIN 0.45% of the
tokens; SWIFT/BIC 177 of the 500 letter tokens at 0.1; no `ML-08C` kind at 0.5 or more. The synthetic set is ours, so
these rates say the checks behave as specified, not how real documents score (§15).

Not yet built: URLs; PL PESEL, AU ABN, SE personnummer and SG NRIC (below); US driver's licence formats with context
(named in `ML-08C`); the other fifteen EU VAT schemes and XI, France's alphanumeric VAT keys; MRZ TD1 and TD2
(identity cards, visas) and Medicare's eleventh digit; Ethereum addresses, whose EIP-55 checksum needs Keccak-256, a
hash not in the workspace (skipped rather than matched unchecked).

**Engine dependency (ADR-029 names it; recorded here as the repository records engine dependencies):** `phonenumber`
=0.3.10+9.0.33 (Apache-2.0) is the crate's only new dependency beyond `regex` (`sha2`, below, was already in the
engine). Reason: libphonenumber's per-region metadata
is the only sound way to tell a phone number from an order number, and no Rust alternative carries it. It is pure (its
metadata is compiled in by its build script; nothing is read at run time), builds for wasm32-unknown-unknown, and is
handed only short ASCII candidates, never document text. Its tree adds `postcard`, `heapless` 0.7, `quick-xml`,
`strum`, `regex-cache`, `nom` and smaller crates, all MIT or Apache-2.0; `heapless` 0.7 depends on `atomic-polyfill`
(RUSTSEC-2023-0089, unmaintained) for targets we do not build, ignored in `.cargo/audit.toml` under owner
instruction 32 and removed under `DEP-05`. `email_address` and `iban_validate` are not used: the email domain check
and the IBAN table and mod-97 are our own, short and tested. `sha2` =0.11.1 (RustCrypto, MIT OR Apache-2.0, ADR-006)
computes Base58Check's double SHA-256 for Bitcoin addresses (`ML-08C`); it was already in the engine through
`casual-sign-pdf` and `casual-sign-crypto`, same version, no default features, so it adds nothing to the tree.

- Email: pattern plus our own domain check (stands in for Presidio's `tldextract`, which needs the Public Suffix List).
- Phone: `phonenumber` 0.3.10 (Apache-2.0, https://crates.io/api/v1/crates/phonenumber).
- IBAN: mod-97 and the registry's per-country format, our own.
- Card: Luhn, written inline (ten lines; the `luhn` crate 1.0.2 of 2026-10-04 is old enough but not needed).
- IP address and URL.
- Dates, shared with the field detector.
- National ids with checksums for launch markets: US SSN, UK NINO and NHS, ES NIF and NIE, IT codice fiscale,
  PL PESEL, DE Steuer-ID, IN Aadhaar (Verhoeff) and PAN, AU TFN and ABN, CA SIN, SE personnummer, SG NRIC. Built:
  all but PL PESEL, AU ABN, SE personnummer and SG NRIC.
- Low-specificity types need a checksum or a context word.

**Layer 2: optional, off by default.** Names, addresses and organizations come from a pretrained GLiNER-PII model
in modeld.

| Model | Weights licence (source) | ONNX | Size | CPU (est.) | Languages | Verdict |
| --- | --- | --- | --- | --- | --- | --- |
| knowledgator/gliner-pii-base-v1.0 | Apache-2.0 (https://huggingface.co/knowledgator/gliner-pii-base-v1.0) | our fp16 export of `pytorch_model.bin` (the official `model_quint8.onnx`, used before `ML-21`, was never measured against the golden spans; our quint8 export keeps 47 of 57) | 332,987,248 B | unverified | **English only**: encoder microsoft/deberta-v3-small (MIT), English vocabulary, despite the card's "multilingual" tag. Training data **undisclosed** (the card names only an evaluation set). Window from its config, `max_len` 2,048 | default (D6(a)); F1 81.0% on synthetic-multi-pii-ner-v1 per card |
| urchade/gliner_multi_pii-v1 | Apache-2.0 (https://huggingface.co/urchade/gliner_multi_pii-v1) | ships only `pytorch_model.bin` (1,155,900,362 B, pickle), over the file cap: usable **only as our own int8 export under the cap** (piece X, §8 pickle rule) | int8 unmeasured | unverified | 6 (unnamed) | fallback for non-Latin names, once the export fits the caps |
| openai/privacy-filter | Apache-2.0 (https://huggingface.co/openai/privacy-filter) | — | about 1.5B parameters, about 6 GB fp32, over the 4 GiB container limit | — | English-primary | **not usable within the caps; not evaluated** (D6(d) not chosen) |

Rejected:
- `iiiorg/piiranha-v1` (CC-BY-NC-ND-4.0).
- `nvidia/gliner-PII` (NVIDIA Open Model License, not on the allow list).
- spaCy and Presidio as runtime (Python, no ONNX path). They are used offline only. This changes `ML-08`'s wording
  ("Presidio, with spaCy"): Presidio's approach is ported, not run (§16, defect 14).
- spaCy fr and es pipelines (LGPL-LR and GPL-3.0).
- `Davlan/xlm-roberta-base-ner-hrl` (AFL-3.0).
- `Babelscape/wikineural` (CC BY-NC-SA).
- Flair classic models (non-commercial).

No model detects everything. Spans feed the redaction and retention proposals of slice 15, which a person accepts.
Never claim GDPR or other compliance (docs/09).

### 5.5 Runtime and code

| Component | Version | Licence (source) |
| --- | --- | --- |
| ONNX Runtime | **1.28.x**, the release `ort` rc.13 targets (its README badge reads `onnxruntime-v1.28.0`), pinned by SHA-256 in the manifest; a later 1.x only when a test shows it works with rc.13 | MIT (https://github.com/microsoft/onnxruntime/blob/main/LICENSE) |
| `ort` | =2.0.0-rc.13 (2026-07-28), `default-features = false`, features `load-dynamic` (and what rc.13 needs for `ndarray`), never `download-binaries` or `tls-native` | MIT OR Apache-2.0 (https://crates.io/api/v1/crates/ort) |
| `oar-ocr` | =0.10.2, `default-features = false, features = ["simd"]` | Apache-2.0 |
| `tokenizers` | =0.23.2, `default-features = false` (Oniguruma comes in through `oar-ocr-core`, §5.2) | Apache-2.0 |
| `image_hasher` | 3.1.1 | MIT OR Apache-2.0 |
| `hayro` | 0.8.0 | Apache-2.0 OR MIT |
| `phonenumber` (in `casual-sign-pii`; `email_address` and `iban_validate` not used, §5.4) | =0.3.10 | Apache-2.0 |
| `sha2` (in `casual-sign-pii` for Base58Check, `ML-08C`; already in the engine, ADR-006) | =0.11.1 | MIT OR Apache-2.0 |

**`unsafe`:** the `hayro` crate itself forbids `unsafe`; its dependencies do not (`zune-jpeg`, `fearless_simd`,
`pic-scale`, `bytemuck`, `vello_cpu`). Its JBIG2, JPX and CCITT decoders are fuzzed specifically (`SEC-I01`).

**Upstream lag (recorded risk):** `ort` rc.14 and rc.15 have shipped, and `oar-ocr` pins `=rc.13`, so a fix in `ort`
cannot be taken until `oar-ocr` moves. Tracked as a finding row (`ML-10`); the fallback is D3(b), vendoring the OCR
pre- and post-processing onto a newer `ort`.

Every crate passes `deny.toml` as it stands (licences from crates.io); confirming the transitive tree, Oniguruma
included, with `cargo deny` is part of `ML-09`.
**Found 2026-11-12 (piece D):** it does not. `cargo deny check licenses` rejects `clipper2-rust` 1.2.0 (BSL-1.0),
a required dependency of `oar-ocr-core` 0.10.2 (polygon offsetting in its DB post-processing). Owner instruction 32
admits BSL-1.0 for the ONNX Runtime binary only, so the licence gate fails on any tree with the `server` feature
until the owner decides (allow BSL-1.0 for this crate in `deny.toml` with an ADR, or replace the unclip step under
D3(b)); a row is proposed.
**Resolved 2026-11-13 (`ML-02`), under D3(b):** the unclip step is replaced, not the licence admitted. The workspace
`[patch.crates-io]` puts our own Apache-2.0 crate `server/clipper2-rust` in place of the BSL-1.0 one; it provides
only the five items `oar-ocr-core` calls (round-joined outward offset of a closed polygon, taken over its convex
hull, and the shoelace area), written from that call, not from Clipper2's source. For the quad boxes modeld's
detector produces the hull is the box itself. `cargo deny check bans licenses sources` passes; the real-weight
recall test (`tests/ocr.rs`, Latin word recall at least 95%) passes with it and reads nothing when the offset is
disabled. `deny.toml` is unchanged.
**Also found:** `oar-ocr` 0.10.2 and its `-core` and `-derive` crates declare `rust-version = 1.95`, above the
workspace's pinned 1.94.0, so the CI list's `cargo +1.94.0 check --workspace` fails with the `server` feature until
the MSRV moves to 1.95 (the toolchain in use is 1.96) or an older `oar-ocr` is pinned; a row is proposed. No
older `oar-ocr` avoids either: 0.7.0 onward all declare 1.95 and use `clipper2-rust` (BSL-1.0 in every version),
and 0.6.x uses `clipper2`, a binding to the same BSL-1.0 C++ library.
**Still open (2026-11-13, `ML-02`):** the 1.95 declaration is metadata only: `cargo +1.94.0 check -p
casual-sign-modeld --all-features --all-targets --ignore-rust-version` compiles, but the CI list's `cargo +1.94.0
check --workspace --locked` refuses on the declaration. Clearing it needs the owner: move the MSRV to 1.95
(instruction 14 sets 1.94), or patch the three `oar-ocr` crates in as vendored copies declaring 1.94 (D3(b)).
**Lockfile ages (2026-11-13, review of piece D):** four crates the tree locked were under the two-week rule of §5;
they are pinned back to `bit_field` 0.10.3, `exr` 1.74.0 (1.74.1 and 1.74.2 bring `pulp` and the unmaintained
`paste`), `hayro-cmap` 0.1.0 and `hayro-postscript` 0.1.0 (the fuzz lockfile too). `rustix` moves to 1.1.6
(2026-10-27) for RUSTSEC-2026-0486. `cargo audit` ignores, each with its reason in `.cargo/audit.toml` and pending
the owner's confirmation: the four `zip` 8.6 `extract` advisories (`oar-ocr` requires `^8.6`, reads one archive
with `by_name` only and never extracts; `DEP-06`) and the unmaintained `paste` and `ttf-parser`, which arrive only
through `imageproc`'s default features turning on every `image` codec and `ab_glyph` (`DEP-07`).

Determinism: CPU execution only, one intra-op thread per session, a fixed graph optimisation level, and fixed
truncation. Output is expected to be bit-identical on the same build and CPU instruction set; across AVX2 and
AVX-512 it is expected to be equal after thresholding (unverified; tested on the shipped files). Every suggestion
stores `model_id`, `weights_sha256`, `ort_version` and `bundle_id`.

### 5.6 ML-08 Console anomaly alerts (no model)

`ML-08`'s second half needs no model and no training: the platform console (`CON-01`) flags queue depth, error
rates and usage that leave a robust band (median ± k × MAD over a trailing window, k fixed and tuned on seeded
synthetic series). It reads counts only, never content or per-person data. Tracked as `ML-08B`, after `CON-01`'s
health page.

### 5.7 What else counts as "no training"

Checked against the ML rows: `ML-02`, `ML-05`, `ML-07` (pretrained extraction and search) and `ML-08` (both halves)
are covered here. `ML-03` and `ML-04` need fine-tuning or training and stay out. `LLM-*` are not ML rows.

### 5.8 ML-06 (open owner question)

`ML-06` (advisory ceremony risk score) uses no pretrained model, but an isolation forest or robust statistics is
**fitted per deployment on that deployment's own signing events**. Whether that counts as "training" under
instruction 30, and whether fitting on customer signing events is acceptable at all, is for the owner. It is raised
as a decision row (`DEC-15`) and not designed here.

## 6. How suggestions reach people (docs/40 style; for `ML-01` and piece G)

| Endpoint | Behaviour |
| --- | --- |
| `POST /envelopes/{id}/documents/{doc}/analysis` | Requests analysis (idempotent on the job key); `202 {status: queued\|running\|done\|failed\|unavailable, uses}`. `403 CS-ML-0011` when the workspace has no ML feature on or the plan lacks it. A draft envelope only. Scope `envelopes:write` |
| `GET /envelopes/{id}/documents/{doc}/analysis` | Status, `ocr_pages`, `truncated`, `bundle_id`. Scope `envelopes:read` |
| `POST /envelopes/{id}/documents/{doc}/detect-fields` (existing) | When analysis is done, OCR-sourced suggestions are merged into the same response. Additive members `text_source: "layer"\|"ocr"`, `source` gains `ocr_rule` and `ocr_box`, and `confidence` becomes min(cue, OCR word confidence). Unchanged when ML is off (the test asserts identical bytes) |
| `GET /envelopes/{id}/suggestions?kind=template\|entity\|personal_data&state=open` | Cursor-paginated `{id, kind, document_id, page?, rect?, label, value?, normalized?, score, model:{id, sha256}, state}`. `value` is the span text, read from the stored text at request time and shown only to users who may read the document. A `template` suggestion is listed only to a member who may use the matched template (UXW-06, TSH-01) |
| `POST /envelopes/{id}/suggestions/{s}/accept` / `…/dismiss` | Accept performs the ordinary action: a `template` suggestion applies the template's roles and fields (as `POST /envelopes` from a template does, `If-Match` on the envelope); an `entity` suggestion sets an envelope custom field or agreement metadata; a `personal_data` suggestion is added to the document's redaction or retention proposal (slice 15). It records `decided_by` and `decided_at` on the suggestion row. `409 CS-ML-0012` when the document changed since the analysis |
| `POST /templates/{id}/documents/{doc}/analysis` and `GET` | Same, for templates (`fingerprint_template`, entities) |
| `GET`/`PATCH /account/settings/ml` | `{ocr, template_matching, extraction, personal_data, personal_data_model, ocr_scripts: [...], reread_scanner_text}`. Workspace admin only; a feature the plan lacks is refused with `403 CS-ML-0011` |
| `GET /search?q=…&mode=meaning` (planned, `WEB-19`) | Search agreements by meaning (`ML-07B`, `agreement_vectors`): `{items: [{envelope_id, document_id, subject, page, snippet: [{text, mark?}], score}]}`, only envelopes the caller may read, cursor-paginated. The web app's ⌘K "Matches by meaning" section calls it (`api.searchByMeaning`) and hides on 404 or `CS-ML-0011`. Scope `envelopes:read` |
| `GET`/`PATCH /account/settings/ml` | `{ocr, template_matching, extraction, personal_data, personal_data_model, ocr_scripts: [...], reread_scanner_text}`. Workspace admin only; a feature the plan lacks is refused with `403 CS-ML-0011`. The answer also carries, read-only, `not_in_plan: [feature]`, `installed` (false when modeld is absent), `models: [{id, name, profile, status: ready|installing|failed, licence, bytes, sha256}]` and `ocr_packs: [{script, state: installed|installing|missing}]` for the admin page (WEB-18; the web app reads them when present, the server does not send them yet) |
| Console (`CON-01`) `GET /console/ml` | modeld health, bundle id, model ids, hashes and licences, queue depth, error rates. Never content or per-workspace data beyond counts |

Another account's envelope is `404` before any body is read. Every query goes through the tenancy-scoped
repository.

**Screens** (each verb a registered command; `textContent` for every string):
- **Editor, prepare.** On upload of a scanned document a quiet status reads "Reading scanned pages… n of N". "Detect
  fields" shows OCR suggestions with a "from scanned text" badge and their confidence.
- **Upload banner.** "This looks like your *Mutual NDA* template (3 of 3 pages match). Use it? / Not now". Never
  applied automatically.
- **Details panel.** "Suggested details: parties, dates, amounts", each with accept, edit or dismiss, showing the
  page and a highlight.
- **Retention and redaction (slice 15).** Personal-data highlights by type with accept or dismiss.
- **Workspace admin.** "Assistive features", one toggle per feature, greyed with "not in your plan" when not
  entitled, and an OCR script picker limited to the installed packs.
- **Console.** A "Models" page.

## 7. Enablement and plan entitlement

Four entitlements in `PLAN-01` (D9(a)): `ml.ocr`, `ml.template_matching`, `ml.extraction`, `ml.personal_data`. The
effective switch is (operator deployed modeld) ∧ (plan entitles) ∧ (workspace admin turned it on). The default is
off at every level. A quota of OCR pages per period is metered (`PLAN-01` usage). When modeld is absent, the
settings show "not installed on this server".

### As built (`WEB-19`, 2026-11-13: the server side of §2, §6, §7, §13)

- **Migration `0021_ml_analysis.sql`** (forward-only): `ml_settings`, `ml_entitlements`, `analysis_runs`,
  `suggestions`, `ocr_pages`, `template_fingerprints` (docs/22 §9). Every table carries `account_id`, has RLS keyed on
  the current account, and is reached only through `casual_sign_store::repo::ml` (`tx.ml()`). `ml_entitlements` is
  read-only to the application role: the operator sets it (as the migrator role, until `PLAN-02` moves entitlements
  into the platform's plans). `agreement_vectors` (`ML-07B`) is not created yet.
- **Enablement (§7).** `casual_sign_host::ml::effective`: a feature is in effect only when the server was started with
  `OPENSEAL_ML_BUNDLE_ID` (the operator deployed modeld), `ml_entitlements` lists it, and `ml_settings` has it on. No
  row means off; the default is off at every level. With none in effect an upload writes no run and no job, and
  detect-fields answers the same bytes (`ML-01` exit: `server/tests/ml.rs`
  `with_every_feature_off_nothing_is_enqueued_and_detect_fields_is_unchanged`, seen red with an enqueue forced while
  every feature is off). The OCR-page quota (`PLAN-01` usage) is not metered yet.
- **Jobs (§2).** `analyze_document` is enqueued in the transaction that admits an upload to a draft envelope (create
  or add-document), or by `POST …/analysis`; `fingerprint_template` in the transaction that adds a template document,
  when template matching is in effect, or by `POST /templates/{id}/documents/{doc}/analysis`. Keys exactly as §2,
  built in `casual_sign_host::ml::{analyze_key, fingerprint_key}`; `max_attempts` 3. A template upload is not also
  run through `analyze_document` (entities on templates wait). The worker (`casual-sign-worker::ml`) calls modeld
  through the `Inference` seam (`casual-sign-modeld`'s client, `default-features = false`: `SEC-I14`, re-seen red
  2026-11-13 with the default features on); without `OPENSEAL_MODELD_ADDR` a run ends `unavailable`, a final model
  error ends it `failed` with its code, and a transient one is retried. OCR reads pages with no text layer;
  "re-read scanner text" is stored but not yet honoured (invisible-text pages are not re-read). Entities and personal
  data (`casual-sign-pii` first, then the model's non-overlapping spans) are stored as page and UTF-8 byte offsets
  into the analysed text (`casual_sign_host::ml::page_text`: the text layer, or the OCR words). Nothing touches an
  envelope's state, audit chain or documents (`tests/ml.rs` in the worker compares state and events before and
  after).
- **Routes (§6)**, as `webapp/api.js` calls them: `GET`/`PATCH /account/settings/ml` (scope `admin:account`; answers
  also `not_in_plan` and `installed`; `models` and `ocr_packs` are not sent yet; a change appends
  `workspace.ml_settings_changed` to the workspace's admin log, ORG-05), `POST`/`GET
  /envelopes/{id}/documents/{doc}/analysis` (a run: `{id, document_id, status, uses, ocr_pages, truncated,
  bundle_id}`; `POST` is `202`, a draft only, else `409 CS-WF-0001`), `GET /envelopes/{id}/suggestions` (`kind`,
  `state`, `cursor`, `limit` 1 to 200; only the kinds whose feature is in effect; `value` read from the stored text at
  request time; a `template` suggestion carries `template_id`, `pages_matched`, `pages_total` and no `value`),
  `POST …/suggestions/{s}/accept` and `…/dismiss`, and `POST`/`GET /templates/{id}/documents/{doc}/analysis`. With no
  feature in effect every route but the settings answers `403 CS-ML-0011`. Another account's envelope, template,
  document or suggestion is `404`; asking for an analysis and deciding a suggestion are the sender's or an
  administrator's.
- **Accept differs from the §6 table (finding row, for the owner).** `accept` records `decided_by` and `decided_at`
  only; it does not itself apply a template, set a custom field or add to a redaction proposal. The web app applies a
  matched template as an ordinary, undoable edit of the draft and then records the acceptance (`prepare.js`
  `applyMatchedTemplate`), so a server that also applied it would apply it twice; the redaction proposal (slice 15) and
  envelope custom fields from entities do not exist yet. `409 CS-ML-0012` is answered when the suggestion is already
  decided or its document has left the envelope (a stored document's bytes never change, so "changed since the
  analysis" is a document removed or replaced). §6 is unchanged pending that decision.
- **Not built:** OCR-sourced suggestions merged into `detect-fields` (`text_source`, `ocr_rule`, `ocr_box`), search by
  meaning (`ML-07B`), the console's `/console/ml`.
- **Purge and evidence (`ML-31`, `ML-32`).** The purge job deletes an envelope's analysis runs, and their suggestions
  and OCR pages with them; a deleted template takes its run, page prints and the suggestions naming it (`SEC-I07`); a purged
  envelope's analysis routes answer `404`, and an analysis job that finds its envelope purged deletes its run. An
  envelope analysed with every feature on seals to the same signed bytes and audit chain as with ML off (`SEC-I13`).

## 8. Weights: pinning and delivery

- `tools/ml/models.toml` (committed) lists, per file: `id, profile (ocr|templates|extraction|personal_data),
  source_url pinned to a revision commit (https://huggingface.co/<repo>/resolve/<commit>/<file>), sha256, bytes,
  licence (SPDX), licence_url, card_url, provenance_note`. The ONNX Runtime archive is listed the same way.
- `tools/ml/fetch-models.py` (standard library, `-I`) downloads only the profiles asked for into an empty directory,
  checks size and SHA-256, writes `bundle.json` (the bundle id is the hash of the manifest entries), and **exits
  non-zero naming the file** on any mismatch or on a licence not in the allowed set. That set is exactly `deny.toml`'s
  allow list (Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC, MIT, NCSA, Unicode-3.0, Unlicense, Zlib); anything else
  needs an ADR. The one scoped exception is owner instruction 32: the ONNX Runtime library entries carry
  `licence_exception = "owner-instruction-32"`, which admits MPL-2.0 (Eigen) and BSL-1.0 (Boost) for those entry
  ids alone and only in a bundle that holds the archive's `ThirdPartyNotices.txt` (docs/09 §8). It also refuses GLiNER v0 and v1 repository ids (D12(a): the licence check lives in this script, no
  new CI gate).
- The Dockerfile gets a `models` stage that runs the fetch (the only network use, at build) and a `modeld` target
  that copies the bundle to `/opt/openseal/models`, read-only. Air-gapped operators run the same script elsewhere
  and mount the directory (D8(a)).
- modeld embeds the manifest at compile time (`include_str!`). At start it re-hashes every file, refuses anything
  not listed or mismatched (`CS-ML-0002`), refuses ONNX files with external-data references or custom-op domains
  (`CS-ML-0003`), and never loads pickle (`.bin`, `.pt`).
- **Exports we make** (GLiNER multi int8, GLiNER small, GLiNER multi-PII int8, the PP-OCRv5 script packs and the
  orientation classifier) come from `tools/ml/export-*.py`, run offline with hash-pinned requirements
  (`pip install --require-hashes`; PaddlePaddle and `paddle2onnx` for the Paddle-format packs), in a sandbox with the
  network off. **Pickle rule:** safetensors is used where the repository has it (`gliner_multi-v2.1` does). Where only
  `pytorch_model.bin` exists, the `.bin` is itself pinned by SHA-256 in the manifest and loaded only with
  `torch.load(weights_only=True)`. Each output's hash is recorded with its source revision.

## 9. Licence auditing

- **Rust code:** cargo-deny as today.
- **ONNX Runtime binary and weights:** the manifest licence field, checked by `fetch-models.py`, plus the weights
  register in docs/09 §8, which records each entry's licence and training-data note (MS MARCO, non-commercial
  research, in the e5 and MiniLM training sets; Pile-derived `urchade/pile-mistral-v0.1` for GLiNER v2.1;
  undisclosed for knowledgator GLiNER-PII). We rely on the weight licence and do **not** claim a clean data lineage.
  Whether that reliance is acceptable is an open owner decision (D13, `DEC-16`, docs/09 §8).
- **Python:** in `tools/ml/` only, never at run time. Hash-pinned requirements; `pip-licenses` run when they change,
  recorded in docs/19. No repository check is added (D12(a)).

## 10. Threats (docs/07 §Inference and models, `SEC-I*`)

The rows, controls and tests are in [07](07-SECURITY-THREAT-MODEL.md) §Inference and models (`SEC-I01` to
`SEC-I15`), each **Designed** until its test is seen red.

## 11. Evaluation fixtures (no real personal data)

- **Scanned forms.** `tools/ml/make-scans.py` takes corpus PDFs that have a text layer and AcroForm or labelled
  lines. It rasterises them at 150, 200 and 300 DPI and applies deterministic, seeded degradations: skew ±2°, noise,
  JPEG quality 60, a 180° page, and a binarised fax look. Each result is wrapped as an image-only PDF. Ground truth
  is `detect_fields` on the original text layer. Hashes go in `fixtures/ml/manifest.tsv`, checked like
  `generate.py --check`.
- **Scripts.** Generated forms with Arabic and Devanagari labels set in OFL Noto fonts. They measure OCR word
  accuracy now, and field detection once `FLD-L10N` lands.
- **Templates.** Positives are each corpus template re-filled with synthetic values and scanned; negatives are every
  other corpus document. The false-match rate is reported against ML-05's bound.
- **Agreements (NER).** Synthetic agreements from public-domain clause templates with known parties, dates, amounts,
  durations and addresses, in English and at least two other languages (`ML-07A`). CUAD (CC BY 4.0) is reserved for
  the fine-tuned half.
- **Personal data.** Synthetic: names from US Census surname and first-name frequency tables (public domain);
  addresses with fictional streets; phone numbers in reserved fictional ranges (US 555-01xx, UK Ofcom drama ranges);
  card numbers from issuers' published test numbers; IBANs from the registry's examples; national ids generated to
  pass checksums. The manifest states that no entry belongs to a real person.

## 12. Codes (docs/20 §ML)

Reserved in [20](20-ERROR-CODE-REGISTRY.md) §ML: `CS-ML-0001` to `CS-ML-0015` (`CS-ML-0015`: a caller not on the allow list, final, kept apart from the transport code `CS-ML-0008`, which is retried).

## 13. Data model (docs/22; migration number reserved in docs/14, forward-only)

- `analysis_runs(id, account_id, document_id, envelope_id?, template_id?, uses, status, bundle_id, ort_version,
  pages_ocr, truncated, code?, created_at, finished_at)`
- `suggestions(id, account_id, run_id, document_id, kind, page?, rect?, label, span_start?, span_end?,
  normalized?, score, model_id, weights_sha256, state, decided_by?, decided_at?)`. No span text column: the text is
  read from the stored document when shown. `span_start` and `span_end` are UTF-8 byte offsets (§3.2).
- `ocr_pages(account_id, run_id, page, words jsonb)` holds OCR words, needed to show spans. It is document content
  and purged with the document.
- `template_fingerprints(account_id, template_id, document_id, page, dhash bigint, phash bigint, embedding bytea,
  model_id, weights_sha256)`
- `agreement_vectors(account_id, envelope_id, document_id, page, embedding bytea, model_id, weights_sha256)` for
  `ML-07B` search.

Every table carries `account_id`, is reached through the scoped repository, and has RLS. Built as migration
`0021_ml_analysis.sql` (`WEB-19`), with `ml_settings` and `ml_entitlements` beside these, `analysis_runs` also
carrying `kind`, `document_sha256` and `job_key` (unique per account), and `pages_ocr` named `ocr_pages`; see §7 As
built. `agreement_vectors` waits for `ML-07B`.

## 14. Companion edits

Done with this note: docs/00, docs/07 (`SEC-I*`), docs/08 (ADR-029), docs/09 (§8 weights register), docs/19
(`casual-sign-modeld`, `casual-sign-pii`), docs/20 (§ML), docs/21 (§ML). Done with `WEB-19`: docs/22, docs/40 and `api/openapi.yaml`. Owed by the pieces that build them:
docs/14 rows (main session), docs/47 (piece H), docs/96,
the wasm exclude list in `tools/ci-local.sh`, `.github/workflows/ci.yml` and CLAUDE.md (piece A).

## 15. Measured later (must be true before the exits)

- Per-page OCR time on the reference machine.
- modeld resident memory with each profile; `per_slot_peak`; the raster child's `RLIMIT_AS`.
- The int8 GLiNER exports' sizes and accuracy loss; the bundle and per-file caps set from them.
- hayro fidelity on JBIG2, JPX and CCITT scans (`PDF-REN-01`).
- PP-OCRv6 script list. (Its small recogniser's 18,708-entry dictionary holds no Arabic or Devanagari character, checked 2026-11-12: those scripts need their packs.)
- Latin word recall on the synthetic scans at 200 DPI: 99.25% (§5.1, 2026-11-12). Still to measure: the same on the reference machine's release build, and with the textline orientation model.
- ~~Whether `phonenumber` builds for wasm32 (decides `casual-sign-pii`).~~ It does (piece J, 2026-11-12).
- Cross-ISA equality after thresholding, on the shipped files.

## 16. Review defects and where each is fixed

The adversarial review of 2026-11-12 found twenty defects; the owner accepted the design on condition they are
fixed before acceptance (instruction 30).

| # | Defect | Fixed in |
| --- | --- | --- |
| 1 | Job key shared across tenants and documents | §2 keys; `SEC-I06` test with identical bytes in two accounts |
| 2 | `oar-ocr` default features download ONNX Runtime at build | §5.1, §5.5 `default-features = false`; `SEC-I09` asserts `download-binaries`, `tls-native`, `auto-download` absent |
| 3 | `oar-ocr` logs OCR text at debug | §3.4 fixed subscriber ignoring `RUST_LOG`; `SEC-I05` at trace level |
| 4 | Worker would link the inference stack | §1 optional `server` feature; `SEC-I14` `cargo tree -p casual-sign-worker` |
| 5 | Pure-Rust tokenizer impossible | §5.2: Oniguruma accepted, recorded in `SEC-I01`, fuzzed |
| 6 | GLiNER multi size understated | §5.3 sizes; caps set from measurement; two-step parity |
| 7 | PII default effectively English-only | §5.4: English only, training data undisclosed, window from its config, non-Latin fallback named |
| 8 | Fallback and "evaluate" models break caps | §5.4: int8 export required; privacy-filter not usable |
| 9 | Exports from pickle run code | §8 pickle rule; `SEC-I15` |
| 10 | e5 int8 file tied to AVX-512 VNNI | §5.2: fp32 default, own portable int8 later |
| 11 | Rasteriser time and memory unenforceable | §3.3 raster child; slots from memory; PDF sent once (`DOC_OPEN`) |
| 12 | Scope gaps | §5.3 search (`ML-07B`), §5.6 alerts (`ML-08B`), §5.8 `ML-06` to the owner |
| 13 | Training-data risk undecided | §9; docs/09 §8; D13 raised as `DEC-16` |
| 14 | Contradicts `ML-01` and `ML-08` rows | Amended row text returned to the main session for docs/14, and raised with the owner |
| 15 | Paddle-format packs need Paddle to export | §5.1, §8: exported by us; re-hosts dropped |
| 16 | "No `unsafe`" in hayro overstated | §5.5 reworded; JBIG2, JPX, CCITT fuzzed |
| 17 | `ort` pairing answerable; pin ages | §5.5 ONNX Runtime 1.28.x; `ML-10` finding row |
| 18 | `luhn` age; NCSA missing from allow list | §5.4, §8 |
| 19 | Span offset units undefined | §3.2 UTF-8 byte offsets into the sent NFC text |
| 20 | Migration and ADR ids can collide | §13; ids reserved in docs/14 by the main session |

## 17. Owner decisions referred to above

Chosen 2026-11-12 (instruction 30) from the options put with this design; the numbering is used throughout.

| # | Question | Choice |
| --- | --- | --- |
| D1 | Where models run | A separate Rust process, `casual-sign-modeld`, no secrets, no egress |
| D2 | Rasteriser for scans | `hayro` 0.8.0 by default; PDFium measured as a sandboxed fallback (`PDF-REN-01`) |
| D3 | The `ort` version conflict | One exact `ort` (rc.13, `oar-ocr`'s), with our own GLiNER decoding |
| D4 | Embedding model | multilingual-e5-small, all-MiniLM-L6-v2 as a small English profile, plus page hashes |
| D5 | Extraction model | GLiNER `gliner_multi-v2.1`, `gliner_small-v2.1` as an English profile |
| D6 | Personal-data depth | Deterministic recognisers first; GLiNER-PII optional |
| D7 | Where the recognisers live | A pure engine crate `casual-sign-pii` if it builds for wasm32, else the worker |
| D8 | How weights ship | Fetched and hash-checked at image build; operator-chosen profiles |
| D9 | Enablement | Four per-workspace switches, off by default, plan-gated, with an OCR-page quota |
| D10 | OCR languages | PP-OCRv6 small always; PP-OCRv5 script packs by operator choice |
| D11 | Scope and order | Build the four pretrained models now, in parallel with the UI and workspace work; `ML-07A` is the pretrained extraction exit |
| D12 | Weight licence check | Inside `fetch-models.py` only; no new CI gate |
| D13 | Reliance on weight licences where training data is non-commercial or undisclosed | **Open** (`DEC-16`; docs/09 §8) |
