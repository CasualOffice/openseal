# 30 — PDF pipeline

**Status: Draft for owner.** How a file goes from upload to a sealed agreement: admission, normalization, field
geometry, anchors and tags, flattening, and the incremental writer. Crates: `casual-sign-pdf`, `-fields`, `-flatten`,
`-certificate`. Sealing is [31](31-SEALING-AND-SIGNATURES.md); limits are [21](21-PARSER-LIMITS.md); threats are
[07](07-SECURITY-THREAT-MODEL.md) §PDF.

## 1. Stages

```
bytes ─▶ admit ─▶ normalize ─▶ [deliver: hash fixed] ─▶ fill (values) ─▶ flatten ─▶ certificate + attachments ─▶ seal
          │          │                                                      │
          │          └─ convert non-PDF (Converter seam); optionally flatten an existing AcroForm; strip actives
          └─ bounded parse; classify; report                                └─ incremental update over the delivered bytes
```

**Invariant:** the bytes delivered to signers are a prefix of the sealed file. Every later stage appends. A test asserts
`sealed.starts_with(delivered)` for every corpus document (`PDF-INV-01`).

## 2. Admission (`casual-sign-pdf`)

Our own bounded reader (ADR-005), in the sisters' style: no allocation sized by a number from the file, every limit
named in docs/21, every failure a `CS-PDF-*` code.

- **Lexer and parser** for the object syntax (ISO 32000-2 §7.2–7.3); strings, names, numbers, arrays, dictionaries,
  streams, indirect references.
- **Cross-reference**: classic tables and xref streams, hybrid files, object streams, `/Prev` chains with cycle
  detection, incremental revisions counted.
- **Recovery** for unsigned files: if the xref is broken, rebuild it by scanning for `n g obj` (as every reader does),
  record `CS-PDF-0101` in the report, and **normalize** into a clean file before delivery so signers and verifiers see
  one unambiguous structure.
- **Signed input** (has `/Sig` fields with values, or `/Perms`): never repaired or rewritten. Options shown to the
  sender: keep the existing signatures and append (only if the file is **structurally sound**, meaning it was read without any `CS-PDF-0101` repair, and DocMDP permits; `SPK-01` saw a library write an update with no `/Prev` over a repaired file), or
  "print to new PDF" (flatten to a fresh file, existing signatures become pictures, recorded in the report).
- **Encryption** (built): standard security handler revisions 2–6 (RC4 40–128, AES-128, AES-256 with Algorithm 2.B),
  V4/V5 crypt filters including `/Identity`, per-stream `/Crypt`, `EncryptMetadata false`. Passwords come from the host
  through `Credentials` (`admit_with`); the empty user password is tried first, then each supplied one as user and owner;
  passwords are wiped on drop and never logged; no guessing. Decryption is lazy and charged to the document budget.
  Normalization writes the document decrypted and unencrypted (`CS-PDF-0109`); appending to an encrypted file is
  refused (`CS-WRT-0006`). Public-key security handler: refused (`CS-PDF-0010`; `PDF-ENC-02` plans it).
- **Signed** means a certification signature (`/Perms /DocMDP`) or any signature other than a usage-rights one. A
  document whose only signatures are usage rights (`/Perms /UR3` or `/UR`, Reader extensions) is unsigned for the
  repair rule: it may be repaired and normalized, because Reader extensions attest no content; normalization removes
  `/Perms` and reports it (`CS-PDF-0107`).
- **Classification**: page count and per-page geometry (`MediaBox`, `CropBox`, `Rotate`, `UserUnit`); existing
  AcroForm fields; signatures; JavaScript; actions (`/OpenAction`, `/AA`, `/Launch`, `/GoToR`, `/GoToE`, `/URI`,
  `/SubmitForm`, `/ImportData`); embedded files; XFA; RichMedia, 3D; external streams (`/F` on a stream); optional
  content; PDF version and conformance claims (PDF/A, PDF/UA).
- **Admission report**: everything found and what was done, shown to the sender before sending and stored with the
  version ([22](22-DATA-MODEL.md) §4).

### As built (stage 1A)

`admit(bytes, &Limits, cancel)` recovers and `admit_strict` refuses; both return an `AdmissionReport` (version, pages
with resolved geometry, revisions with their end offsets, fields, signatures, `/Perms`, actions and whether they run
without a click, embedded files, RichMedia, external streams, XFA, optional content, findings with codes and object
numbers). Every in-use object is parsed once, reachable or not, so hidden actions and bombs are seen; content streams
are decoded once at admission. **Both modes refuse:** size, object count, revisions, nesting, page count and cycles, the
document decode budget, an undecodable object stream, cancellation, encryption (decryption is a later row) and
dynamic XFA. **Default mode reports instead:** reference depth, long strings and names (value dropped), a single
content stream over its caps, ratio, unsupported filters (LZW among them for now), long filter chains and content
operators. **Strict still corrects** xref offsets within ±1 KiB and a wrong `startxref` (`CS-PDF-0101`), and such a
file is not structurally sound for appending. Signed or `/Perms` input that needed any repair is refused
(`CS-PDF-0014`). If the catalog or page tree cannot be read, the default reader rebuilds the xref; if the tree's root
is still unreadable, pages are recovered from the `/Type /Page` objects in file order (`CS-PDF-0101`, page tree
rebuilt); unreadable `/Metadata` is a finding, never a refusal. Xref entries with a generation above 65,535 or an offset
of 0 are read as free (iText and LiveCycle write them). LZW is decoded (EarlyChange, predictors), bounded like Flate.
**Corpus:** 417 of 422 real PDFs open with page counts equal to the manifest; the 5 refused are 3 public-key handlers
and 2 dynamic-only XFA forms (`XFA-01`). All 28 standard-handler files decrypt to the same page-1 content as pyHanko.

## 3. Normalization

| Found | Done |
| --- | --- |
| JavaScript, actions that run or fetch, `/Launch`, `/SubmitForm`, `/ImportData` | Removed. Reported |
| `/URI` link annotations | Kept, never followed automatically; the signer UI shows the target before opening it in a new tab |
| Embedded files, RichMedia, 3D | Removed by default (account setting may keep embedded files as attachments, admitted separately). Reported |
| XFA (dynamic forms) | Today: static rendering kept if present and XFA removed; dynamic-only XFA refused (`CS-PDF-0012`). **Planned (`XFA-01`):** lay out dynamic XFA into static pages (template, data and layout per the XFA 3.3 specification), so the form renders, fills and signs; refusal is temporary, not a policy |
| Existing AcroForm fields | Offered to the sender to **convert to OpenSeal fields** (name, type, rect, options mapped) or flatten as they are |
| External streams, remote fonts | Removed. Reported |
| Broken xref, damaged objects | Rebuilt; unreadable objects dropped and reported |
| Non-PDF upload | `Converter` seam: `.docx`, `.xlsx`, `.pptx` through the sister engines' PDF export when deployed, otherwise LibreOffice in a sandboxed container with no network; images (PNG, JPEG) wrapped as one page each |

The normalized file is written fresh (not incrementally), linearization dropped, objects repacked into object streams,
deterministic object order. Its SHA-256 is the document hash every later event cites.

### As built (stage 1B)

`normalize` writes a fresh file: reachable objects renumbered densely breadth-first from the trailer; by default an
xref stream with every non-stream object repacked into object streams of 100 (a classic table on request); stream
data copied as stored, with its filters, so a stream that crossed a content limit keeps its code on re-admission;
the page tree always kept, `/Kids` rebuilt from dictionaries and `/Count` recomputed; bare reference chains collapsed;
`/ID` carried when it is two strings. Removed, each listed with its code and input object number: `/OpenAction` and
`/AA` whole, JavaScript actions and the JavaScript name tree, Launch, SubmitForm, ImportData, GoToR, GoToE, URI actions
that run without a click (link URIs are kept), embedded files and FileAttachment annotations, RichMedia and 3D, XFA;
external stream data emptied; optional content reported and kept. Signed input is refused (`CS-PDF-0014`); print to new
and keeping embedded files as attachments are not built yet (`NORM-02`). `IncrementalUpdate` appends objects with an
xref in the file's own form, checks DocMDP (`CS-WRT-0004`) and refuses repaired files (`CS-WRT-0003`). `PDF-INV-01`
holds over the hostile set and the corpus: 315 corpus files normalized and appended; of 72 signed files, 42 appended
with every signature, page and MediaBox kept and 30 refused for DocMDP P=1, as they must be. pyHanko reads every output
strictly. A `normalize` fuzz target ran 1.4 million inputs without a crash after four fixed findings.

## 4. Geometry (`casual-sign-fields`)

Fields are stored in **displayed page space** ([22](22-DATA-MODEL.md) §6): points, origin top-left, after the page's
crop box and rotation. The engine converts to PDF user space for flattening:

```
displayed (x, y, w, h) ─▶ undo /Rotate (0, 90, 180, 270) ─▶ offset by CropBox origin ─▶ flip y ─▶ scale by UserUnit
```

The same function, compiled to WASM, positions the overlays in the browser, so the editor and the flattener cannot
disagree. Tests cover all four rotations, non-zero crop origins and UserUnit ≠ 1 with fixtures in each combination.

## 5. Anchors and text tags

- **Anchor text** (DocuSign's auto-place): at send, find each occurrence of a string in a document and place a field
  relative to it. Needs **text extraction with positions**: a content-stream interpreter for text operators only
  (`BT/ET`, `Tf`, `Tm`, `Td`, `TJ`, …), font metrics from the embedded font's widths, ToUnicode maps. Bounded; no
  rendering. Matching is on normalized text (NFKC, whitespace collapsed).
- **Text tags** (SignNow-style): tags such as `{{signature:client}}` in the document text become fields at their
  position (only the `{{…}}` form is built; grammar below); the tag text is covered by a white box in the normalized document, or left if the tag is in white
  text. Grammar in `-fields`, documented with the API ([40](40-API-DESIGN.md) §Text tags).

### As built (stage 1C)

**Geometry:** `PageGeometry` converts between displayed page space and PDF user space (divide by UserUnit, undo the
clockwise `/Rotate`, flip y inside the crop box, add the crop origin); tested for every rotation × crop origin ×
UserUnit and round-trip within 1e-6 pt; placements round to 4 decimals. **Text:** a bounded text-only interpreter
(text state and positioning operators, `q/Q/cm`, Form XObjects to depth 8, inline images skipped) with widths from
`/Widths`, `/W` or the standard-14 AFM tables, and Unicode from ToUnicode, base encodings and `/Differences`;
whitespace inferred from glyph geometry; positions asserted within 0.5 pt. Over the corpus: 422 files, no panic, 371
with text, 15 ms mean; strings agree with pypdf on 296 of 387 admitted files and at 0.977 mean similarity on the rest,
where LZW-encoded content was the main gap until LZW decoding landed (12 of 14 LZW files now identical to pypdf, 2 at 0.999). **Anchors:** normalized (NFKC, whitespace collapsed)
matching across runs, case and whole-word options, units points, inches, mm, cm and 96-dpi pixels; the field's
top-left is the match's top-left plus the offsets.

**Text-tag grammar:**

```
tag       = "{{" type ":" recipient [ ":" required ] [ ":" label ] [ ":" size ] "}}"
type      = signature|s|initials|i|stamp|date_signed|name|first_name|last_name|email|company|
            title|envelope_id|text|t|number|date|d|email_address|phone|ssn|zip|checkbox|c|
            attachment|a|approve|decline        (ASCII case-insensitive)
recipient = 1*64( ALPHA / DIGIT / "_" / "-" )
required  = "req" / "required"
label     = a data label (1–255 bytes), no ":" "{" "}"
size      = number "x" number   (points, 0 < n <= 14,400)
```

Whitespace inside a tag is ignored; full-width braces count after NFKC. The field takes the tag's glyph box, or its
top-left with the given size. Types that need options, a formula or a URL cannot be tagged.

**AcroForm conversion:** one OpenSeal field per widget (text with `MaxLen` and required, checkbox, radio group as one
field over its buttons, combo with custom entry, signature); push buttons, multi-page radio groups and off-page widgets
are reported as skipped; multi-select is reported as lossy. A radio group's choices come from each widget's on-state
(the first non-`/Off` key of `/AP /N`, else of `/D`, else `/AS`), with text from `/Opt`, else the state name as UTF-8 or,
failing that, PDFDocEncoding; widgets sharing a state are one choice. A widget with no on-state anywhere gets one named
after its position (`"0"`, `"1"`, as `/Opt` groups name theirs, ISO 32000-2 §12.7.5.2.4) and, filled in place, a dot
appearance under it. Filling and flattening map a choice back to the document's own name bytes, never to decoded text
(`FLD-RADIO-NAME`, `FLD-RADIO-NOOPT`).

## 6. Field values and formulas

Validation, conditional visibility, group rules and formulas run in `casual-sign-fields` on both the browser (WASM) and
the server ([24](24-ENVELOPE-LIFECYCLE-AND-ROUTING.md) §5).

### Formulas

A small, total expression language: numbers (decimal, not float, with explicit precision 0–15), field labels as
variables, `+ - * /`, parentheses, comparisons, `IF`, `SUM`, `MIN`, `MAX`, `ROUND`, `ABS`, and date difference in days.
No loops, no user functions, no string building. Evaluation is bounded (expression length, depth, references) and the
dependency graph is checked for cycles at send time (`CS-FLD-0020`). Division by zero is an error value shown to the
signer, not a crash.

As built in stage 1D (`casual-sign-fields`): precedence from loosest to tightest is comparison, `+ -`, `* /`,
unary signs, and chained comparisons (`a<b<c`) are refused rather than guessed. Functions: `IF(cond, then, else)`
evaluates only the branch taken; `SUM`, `MIN`, `MAX` take one or more arguments; `ROUND(x[, places])`; `ABS(x)`;
`DAYS(end, start)` takes date-field labels only. Labels are bare identifiers or `[any label]`, compared after NFC
normalization. Results round half away from zero at the formula's precision. An empty or hidden referenced field
counts as 0. A runtime error (division by zero, overflow, not a number, not a date) is a value shown to the signer.
A table of 225 cases gives byte-identical output natively and in `wasm32-unknown-unknown` (run under Node).

## 7. Flattening (`casual-sign-flatten`)

For each document at completion, one incremental update that:

- Draws every visible field's value into a **Form XObject** per field and invokes it from a new content stream
  appended to the page's `/Contents` array, wrapped in `q … Q` and positioned with a `cm` derived from §4.
- Text: shaped with the font the field specifies, from the bundled set (Liberation Sans/Serif/Mono, Noto for other
  scripts, OFL), **embedded and subset**; auto-shrink to fit when the field allows; multi-line wrap by the engine.
- Signatures and initials: drawn signatures stored as vector paths (from the pad's strokes) and written as PDF paths;
  uploaded images as image XObjects (PNG and JPEG only, re-encoded after decoding with bounded dimensions); typed
  signatures in a bundled script font (OFL).
- Radio buttons and checkboxes from their own on-state appearance (a dot or a vector checkmark when they have none, `FLT-04`); dropdowns as text.
- Optional content flattened to its default visibility and non-widget annotations drawn or removed as the signer saw
  them on screen (`FLT-03`, SEC-S03), so the sealed page renders the same in every viewer.
- A small "signed by" line under each signature when the account enables it (DocuSign's "DocuSigned by" with an
  envelope id) and the Part 11 meaning when required.
- The original AcroForm, if converted, is removed in the same update so no live field remains.

What the signer reviewed is this output: the ceremony's review step renders the flattened bytes produced by the WASM
build of this crate, through pdf.js (WYSIWYS, [02](02-HLD.md) §6).

### As built (stage 1E)

`flatten(&mut Admitted, &FlattenInput, &FontSet, &FlattenOptions, cancel)` appends one incremental update: each field
with a value becomes a Form XObject invoked from a new content stream, positioned through the stage 1C geometry for any
rotation, crop and UserUnit; existing content is wrapped in one `q … Q` (more than one unbalanced `q` in the original is
a known gap, `FLT-02`). Text uses the bundled Liberation Sans, Serif and Mono or host-supplied faces, **subset and
embedded with ToUnicode** (subsetter copied from OpenPresent), with engine wrapping and auto-shrink to 4 pt; drawn
signatures become smoothed paths; PNG and JPEG uploads are decoded within bounds and re-encoded (JPEG metadata
stripped, EXIF orientation applied); typed signatures use the OFL script faces Great Vibes or Allura; a "Signed by" line
with the envelope id and a signing-reason line are optional. Converted AcroForms are removed with every widget.
**Fill in place (`FILL-01`):** values written to `/V`, appearances regenerated with the subset font (`/MK /R`
honoured), `NeedAppearances false`, the form kept fillable. Checked independently: PDFium renders ink inside every
field's rectangle and none outside across every geometry and field type (32 documents; a shifted rectangle fails the
check), pypdf extracts every value and reads back `/V`; 20 real corpus forms (up to 6,197 fields) flatten and fill with
no failure. Not yet: text shaping and CJK or RTL faces (`FLT-01`).

**Checkboxes (`FLT-04`):** a converted checkbox, checked, draws its widget's own on-state appearance (a cross, a filled
square) in the field's box, the widget nearest the box when the sender moved it; our checkmark only when it has none.

**Optional content (`FLT-03`, SEC-S03):** visibility comes from `/OCProperties /D`: `/BaseState` (`/Unchanged` counts as
on), then `/OFF` or `/ON`; a group whose `/Intent` the configuration does not consider has no effect (on). A membership
dictionary uses its `/VE` when it is readable (`/And`, `/Or`, `/Not` over groups and nested expressions), else `/P`
(`AnyOn` by default, `AllOn`, `AnyOff`, `AllOff`) over its `/OCGs`; one with no group has no effect. A `/VE` deeper
than 32 or over 4,096 terms is refused (`CS-FLT-0006`, docs/21); a malformed one falls back to `/P`. Every page's
content (its streams read as one), every form and tiling pattern it reaches and every appearance that stays is
rewritten: inside a hidden `/OC … BDC` sequence the painting operators go (a path is ended with `n`, so a pending clip
still applies; `'` and `"` keep their line move and spacing) and the graphics state stays, as a viewer processes it
(ISO 32000-2 §8.11.3.2); `Do` of an XObject whose `/OC` is hidden goes anywhere. Then nothing optional is left for a
viewer to decide on: `/OCProperties` is removed, visible `/OC … BDC` markers become plain `/OC BMC`, `/OC` is removed
from visible XObjects and from annotations that stay (a widget of a kept form that it hid is marked Hidden), and an
appearance hidden by its own `/OC` is emptied. PDFium showed why: without a configuration it still evaluates `/OC`,
taking every group as on, so a visible `AnyOff` membership disappeared. Not applied: the configuration's `/AS`
automatic states (usage-driven, viewer-dependent); and a hidden string's text advance is not kept, so a visible
string in the same text object placed only by that advance moves (`FLT-06`, proposed).

**Annotations (`FLT-03`):** what the signer saw on screen decides, not print: an annotation with Hidden or NoView in
`/F`, or in hidden optional content, is removed; Print and its absence change nothing. Every other non-widget annotation
with a normal appearance (its `/AS` state when `/N` holds states) is drawn into the page through the appearance
algorithm (§12.5.5), upright at its upper-left corner when NoRotate is set on a rotated page (NoZoom needs nothing at
100 %), and removed with its pop-up. Links stay (navigation, no appearance in practice), as do annotations without an
appearance, which viewers draw in their own way (`FLT-07`, proposed). A certified document filled in place keeps its
optional content and annotations as certified (its DocMDP permits no new page content; reported as
`layers_kept_as_certified`); flattening it is refused by the writer. Checked independently
(`tools/check_layers.py`): PDFium renders every synthetic input and its output alike, and PDFium and pypdf find every
visible word and no hidden one; PDFium does not honour `/OC` on annotations, so it draws one the standard hides. The
corpus sweep (`tests/corpus_layers.rs`, `OPENSEAL_CORPUS_SWEEP=1`): of 371 files that admit, 16 have optional content
and 164 non-widget annotations (150 drawn, 4 removed, 27,620 kept, nearly all links); all flatten and fill in place
with no failure, and PDFium draws the 24 changed files' first three pages as it drew the inputs (within two
anti-aliased pixels per annotation drawn).

## 8. Certificate of completion (`casual-sign-certificate`)

A PDF (appended to the sealed document or delivered separately, per account setting) generated by our own small
layout writer: envelope id, subject, document names and SHA-256 hashes (delivered and sealed), sender, each recipient
(name, email, routing order, authentication used, IP, user agent, signature image, timestamps of sent, viewed,
signed), consent records, the seal certificate, and the audit chain head. Layout in [32](32-AUDIT-TRAIL-AND-EVIDENCE.md).

The full audit trail is also embedded as an **associated file** (`/AF`, `AFRelationship /Supplement`) named
`audit-trail.json`, in canonical JSON, so the evidence travels with the document. With `pdfa` output enabled (slice 17),
the sealed file conforms to PDF/A-3b; conversion to PDF/A happens before sealing.

## 9. The writer

`casual-sign-pdf` writes incremental updates: new and changed objects, a new xref section in the same form as the
file's last one (table or stream), and a trailer with `/Prev`. It never rewrites earlier bytes. New object numbers start at max(`/Size`, highest object number read + 1), a value from the file that is never used to allocate; above 8,388,607 the update is refused (`CS-WRT-0002`) (`SPK-01`); generation numbers are respected. Output is deterministic.

## 10. Rendering

The engine does not rasterize PDFs. Browsers render through vendored **pdf.js** (Apache-2.0, ADR-007) in a worker with
scripting and XFA disabled and `isEvalSupported: false`. Server-side thumbnails and previews use pdf.js under a
headless runtime or `hayro` (pure Rust, Apache/MIT) once it is mature enough (`PDF-REN-01`, a spike).
