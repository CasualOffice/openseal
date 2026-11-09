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
- **Encryption**: standard security handler RC4/AES-128/AES-256 with a host-supplied password; removed on
  normalization (the sealed output is not encrypted; confidentiality comes from access control and storage
  encryption). Public-key security handler: refused (`CS-PDF-0010`).
- **Classification**: page count and per-page geometry (`MediaBox`, `CropBox`, `Rotate`, `UserUnit`); existing
  AcroForm fields; signatures; JavaScript; actions (`/OpenAction`, `/AA`, `/Launch`, `/GoToR`, `/GoToE`, `/URI`,
  `/SubmitForm`, `/ImportData`); embedded files; XFA; RichMedia, 3D; external streams (`/F` on a stream); optional
  content; PDF version and conformance claims (PDF/A, PDF/UA).
- **Admission report**: everything found and what was done, shown to the sender before sending and stored with the
  version ([22](22-DATA-MODEL.md) §4).

## 3. Normalization

| Found | Done |
| --- | --- |
| JavaScript, actions that run or fetch, `/Launch`, `/SubmitForm`, `/ImportData` | Removed. Reported |
| `/URI` link annotations | Kept, never followed automatically; the signer UI shows the target before opening it in a new tab |
| Embedded files, RichMedia, 3D | Removed by default (account setting may keep embedded files as attachments, admitted separately). Reported |
| XFA (dynamic forms) | Static rendering kept if present; XFA removed. Dynamic-only XFA refused (`CS-PDF-0012`) |
| Existing AcroForm fields | Offered to the sender to **convert to OpenSeal fields** (name, type, rect, options mapped) or flatten as they are |
| External streams, remote fonts | Removed. Reported |
| Broken xref, damaged objects | Rebuilt; unreadable objects dropped and reported |
| Non-PDF upload | `Converter` seam: `.docx`, `.xlsx`, `.pptx` through the sister engines' PDF export when deployed, otherwise LibreOffice in a sandboxed container with no network; images (PNG, JPEG) wrapped as one page each |

The normalized file is written fresh (not incrementally), linearization dropped, object streams kept, deterministic
object order. Its SHA-256 is the document hash every later event cites.

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
- **Text tags** (SignNow-style): tags such as `{{s:signer1}}` or `[[t|1|req|name]]` in the document text become fields
  at their position; the tag text is covered by a white box in the normalized document, or left if the tag is in white
  text. Grammar in `-fields`, documented with the API ([40](40-API-DESIGN.md) §Text tags).

## 6. Field values and formulas

Validation, conditional visibility, group rules and formulas run in `casual-sign-fields` on both the browser (WASM) and
the server ([24](24-ENVELOPE-LIFECYCLE-AND-ROUTING.md) §5).

### Formulas

A small, total expression language: numbers (decimal, not float, with explicit precision 0–15), field labels as
variables, `+ - * /`, parentheses, comparisons, `IF`, `SUM`, `MIN`, `MAX`, `ROUND`, `ABS`, and date difference in days.
No loops, no user functions, no string building. Evaluation is bounded (expression length, depth, references) and the
dependency graph is checked for cycles at send time (`CS-FLD-0020`). Division by zero is an error value shown to the
signer, not a crash.

## 7. Flattening (`casual-sign-flatten`)

For each document at completion, one incremental update that:

- Draws every visible field's value into a **Form XObject** per field and invokes it from a new content stream
  appended to the page's `/Contents` array, wrapped in `q … Q` and positioned with a `cm` derived from §4.
- Text: shaped with the font the field specifies, from the bundled set (Liberation Sans/Serif/Mono, Noto for other
  scripts, OFL), **embedded and subset**; auto-shrink to fit when the field allows; multi-line wrap by the engine.
- Signatures and initials: drawn signatures stored as vector paths (from the pad's strokes) and written as PDF paths;
  uploaded images as image XObjects (PNG and JPEG only, re-encoded after decoding with bounded dimensions); typed
  signatures in a bundled script font (OFL).
- Checkboxes and radio buttons as vector marks; dropdowns as text.
- A small "signed by" line under each signature when the account enables it (DocuSign's "DocuSigned by" with an
  envelope id) and the Part 11 meaning when required.
- The original AcroForm, if converted, is removed in the same update so no live field remains.

What the signer reviewed is this output: the ceremony's review step renders the flattened bytes produced by the WASM
build of this crate, through pdf.js (WYSIWYS, [02](02-HLD.md) §6).

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
