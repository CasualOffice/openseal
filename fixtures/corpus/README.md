# Real-world PDF corpus

PDFs written by the software people actually use (Word, LibreOffice, Acrobat and Distiller, InDesign, LiveCycle,
LaTeX, Chrome and Google Docs, macOS Quartz, Ghostscript, iText, Apache FOP, scanners and others), for `F-004` and the
Phase 0 criterion in [docs/06](../../docs/06-ROADMAP-AND-DELIVERY.md): at least 200 PDFs from at least 10 producers,
each with provenance and licence, and no personal data. Stage 1A admits or refuses every one with a coded reason, and
the Phase 1 gate fills, flattens, seals and verifies every admitted one.

The PDFs are **not committed**. [manifest.tsv](manifest.tsv) is: one row per file with its source URL, SHA-256, size,
licence, what that licence asks of anyone who copies the file, producer family, PDF version, page count and
features. The hostile, synthetic files live in [../hostile](../hostile/README.md).

```sh
python3 -I fixtures/corpus/fetch.py            # download into fixtures/corpus/files/ (git-ignored), checking size and SHA-256
python3 -I fixtures/corpus/fetch.py NAME ...   # only these rows
python3 -I fixtures/corpus/fetch.py --verify   # hash and re-scan what is downloaded; no network
python3 -I fixtures/corpus/fetch.py --check    # manifest shape, licence policy, producers, this README's counts; no network
python3 -I fixtures/corpus/fetch.py --stats    # print the counts block below
python3 -I fixtures/corpus/pdfscan.py FILE...  # describe a PDF: producer family, version, pages, features
```

Standard library only. Downloaded files are untrusted data: the scripts hash them and scan their bytes, nothing more.

## Sources and licence policy

Only works whose licence lets anyone copy them are listed, and the licence is the one the source states for that
file, recorded in the `licence` column. We store only a URL and a hash, but the `attribution` column records what a
copy would have to carry; [NOTICE](../../NOTICE) lists the attribution-required sources.

| Source | Licence | What was taken |
| --- | --- | --- |
| IRS prior-year forms (`irs.gov/pub/irs-prior/`) | public domain (US government work) | Blank forms 1993–2024: AcroForms, XFA, Reader usage rights, JavaScript |
| govinfo.gov (GPO) | public domain | Bills, public laws, statutes, CFR and US Code extracts, each certified with GPO's signature |
| NIST (`nvlpubs.nist.gov`, `csrc.nist.gov`) | public domain | FIPS and SP publications, including scanned NBS legacy reports |
| NASA NTRS | public domain (NTRS "public use permitted", no third-party material) | Technical reports across the decades, many scanned |
| Other US federal agencies, via the Internet Archive | public domain | Blank forms and leaflets (SSA, OPM, DoD, USCIS, State, VA, CMS, CDC and others) |
| arXiv | CC BY 3.0 / 4.0, CC BY-SA 4.0 or CC0, as stated on each abstract page | Papers from 2008 to 2025; the licence was read from the paper's arXiv page, not assumed |
| Wikimedia Commons | the file's stated free licence (CC0, CC BY, CC BY-SA, public domain) | Slides, leaflets, manuals, reports and scans |
| pyHanko test data | MIT | Signed, certified, encrypted and form test files |
| qpdf test suite | Apache-2.0 | Encrypted (RC4, AES-128, AES-256), linearized, rotated and attachment test files |
| Apache PDFBox and Apache FOP | Apache-2.0 | Signing samples, form, encryption and PDF/A test files; FOP output |
| py-pdf/sample-files | CC BY-SA 4.0 | Small files from many producers (ReportLab, WeasyPrint, ImageMagick, FPDF, Qt) |
| PDF Association pdf20examples | CC BY-SA 4.0 | PDF 2.0 examples |

Rules this corpus keeps:

- **No personal data.** Forms are blank, as published. Nothing is a filled-in form, a court filing or a record about a
  private person. Names that appear are authors of published works and officials named in public law.
- **Stable URLs.** Government pages that change in place (agency forms) are referenced through an Internet Archive
  snapshot (`web.archive.org/web/<time>id_/<url>`), which never changes; IRS forms through the prior-year archive;
  GitHub files through a pinned commit; arXiv through a versioned `v1` URL.
- **No redirects to another host.** `fetch.py` refuses them, so the `url` column always names where the bytes come from.
- **Nothing over 50 MiB**; the whole corpus stays under 1.5 GiB.
- No files from the test suites of AGPL PDF tools (iText, MuPDF, Ghostscript). A file made *with* such a tool (one
  pyHanko test file was written by iText) is used under its own source's licence.
- Left out on review: files whose public-domain claim had no stated basis, a patent naming private individuals,
  Wayback captures truncated at 1 MiB, near-duplicate slide decks, and two files whose `/Producer` names nothing
  identifiable.
- **Hashes can drift at the source.** arXiv occasionally regenerates a paper's PDF; Commons files can be re-uploaded
  (the URL then changes). `fetch.py` reports the row; refetch, re-describe with `pdfscan.py`, and update the row.

## Columns

`file` (our stable name), `url`, `sha256`, `bytes`, `licence`, `attribution` (`-` when none is needed), `producer` (a
family from `pdfscan.FAMILY_RULES`, matched against `/Producer` and `/Creator`), `pdf_version` (the header, or the
catalog's `/Version` when higher), `pages`, `features` (comma list from `pdfscan.FEATURES`, or `-`), `fetched` (date).

How the descriptive columns were made, and their limits:

- `producer`, `pdf_version`, `pages` and `features` come from `pdfscan.py`, a byte scanner, not a PDF reader. Page
  counts were cross-checked with pyHanko's reader; where they differ, pyHanko's count is used. For encrypted files,
  pdfscan cannot read the encrypted `/Info` strings or object streams, so producer and pages come from pyHanko after
  opening the file with its empty or published test password; a public-key-encrypted file that cannot be opened is
  named `No /Producer recorded` and its page count is taken from its unencrypted page tree.
- `--verify` therefore prints notes for those encrypted rows, where the manifest holds pyHanko's reading and the
  byte scan sees less; every other row scans exactly as recorded.
- `signed` means a signer's signature dictionary; `usage-rights` marks Adobe Reader-extension signatures (IRS forms),
  which are not signatures by a person; `certified` marks a DocMDP certification signature (all govinfo files).
- `scanned` is a heuristic: an image per page and no fonts (or only an OCR font), or a scanner or OCR producer.
- `acroform` is set whenever the catalog has an `/AcroForm` with fields, including a lone signature field.

## Counts

Computed from the manifest by `fetch.py --stats`; `--check` fails when this block is out of date.

<!-- corpus-stats:begin -->
422 files, 40 producer families (not counting files with no /Producer), 686,468,720 bytes (655 MiB), 13,926 pages.

| Producer family | Files |
| --- | ---: |
| Adobe LiveCycle Designer | 45 |
| No /Producer recorded | 42 |
| Adobe InDesign | 38 |
| Adobe Acrobat Distiller | 36 |
| pdfTeX | 31 |
| Microsoft Office via Acrobat PDFMaker | 28 |
| Ghostscript | 23 |
| LibreOffice / OpenOffice | 18 |
| Microsoft Word | 17 |
| iText | 17 |
| Scanner or OCR software | 16 |
| Adobe Acrobat / PDF Library | 15 |
| Amgraf OneForm Designer | 12 |
| Quartz PDFContext (macOS) | 8 |
| Google Slides | 7 |
| Adobe Acrobat PDFWriter | 6 |
| Adobe Illustrator | 6 |
| Datalogics APDFL | 6 |
| Apache FOP | 5 |
| pypdf | 5 |
| ImageMagick | 4 |
| Microsoft PowerPoint | 4 |
| Skia/PDF (Chrome, Google Docs) | 4 |
| pikepdf | 4 |
| pyHanko | 4 |
| Adobe PageMaker | 3 |
| PDF Tools 3-Heights | 2 |
| Qt (wkhtmltopdf) | 2 |
| WeasyPrint | 2 |
| Adlib PDF | 1 |
| Apex PDFWriter | 1 |
| Esri ArcGIS | 1 |
| FPDF | 1 |
| Foxit | 1 |
| Hand-written | 1 |
| Ipe | 1 |
| IrfanView | 1 |
| LuaTeX | 1 |
| PDF Annotator | 1 |
| ReportLab | 1 |
| cairo | 1 |

| Feature | Files |
| --- | ---: |
| xref-stream | 201 |
| objstm | 195 |
| linearized | 178 |
| tagged | 139 |
| acroform | 127 |
| incremental | 106 |
| embedded-files | 60 |
| javascript | 58 |
| usage-rights | 50 |
| signed | 39 |
| certified | 32 |
| encrypted | 31 |
| scanned | 27 |
| xfa | 26 |
| cropbox | 13 |
| rotated-pages | 8 |
| pdfa | 7 |

| PDF version | Files |
| --- | ---: |
| 1.7 | 112 |
| 1.5 | 90 |
| 1.4 | 86 |
| 1.6 | 86 |
| 1.3 | 35 |
| 2.0 | 11 |
| 1.2 | 2 |

| Licence | Files |
| --- | ---: |
| public-domain-us-gov | 210 |
| CC-BY-SA-4.0 | 71 |
| Apache-2.0 | 36 |
| CC-BY-4.0 | 31 |
| CC-BY-3.0 | 24 |
| CC-BY-SA-3.0 | 23 |
| MIT | 18 |
| CC0-1.0 | 6 |
| public-domain | 3 |
<!-- corpus-stats:end -->
