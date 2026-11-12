# Synthetic scanned forms (ML evaluation)

Fixtures for OCR on scanned pages (`ML-02`) and template matching (`ML-05`), as planned in ADR-029 (piece E). Every
PDF and JSON file here is **synthetic**: [`tools/ml/make-scans.py`](../../tools/ml/make-scans.py) lays out each form
and writes it. No real document, scan or person is in it. Names, e-mail addresses and phone numbers in the filled
variants are invented. The e-mail addresses use `example.com` (RFC 2606) and the phone number is in the fictional
+1 555-01xx range.

```sh
python3 -I tools/ml/make-scans.py            # regenerate vector/, scans/, truth/ and manifest.tsv (about 20 s)
python3 -I tools/ml/make-scans.py --check    # regenerate in memory; fail unless every file is byte-identical
```

The script uses the standard library only and downloads nothing. Output is the same bytes on every machine:

- It writes its own JPEG and RunLength encoders and uses no zlib, whose output differs between zlib and zlib-ng.
- Pixel arithmetic is integer, and the skew uses a Taylor series, not libm.
- Random choices come from a seeded SplitMix64 generator.
- JSON keys are sorted.

`--check` also keeps `fixtures/ml` under 15 MB. It is about 2.7 MB today.

## What is here

| Path | What |
| --- | --- |
| `vector/<form>.pdf` | The clean form as a vector PDF with a text layer, for `detect_fields` on the text layer (the "before" measurement). Latin forms use Helvetica. The Arabic and Devanagari forms embed their Noto font (Identity-H, ToUnicode, ActualText per word). `latin-acroform` also has AcroForm fields (text, signature and check box) |
| `scans/<form>--<variant>.pdf` | The same layout rasterised by the script and degraded, as an image-only PDF (one greyscale image per page, no text) |
| `truth/<name>.json` | Ground truth for each page. `fields` gives each field's `kind` (the `FieldType` wire name), `name`, `label`, how it is `drawn` (underscores, rule or box) and `rect`. `words` gives each word's `text`, `script` (Latn, Arab or Deva), `role` and `rect`. Rectangles are `[x, y, w, h]` in displayed page space (ADR-019: points, origin top left) after degradation. `form_rect` is the field on the clean form. `template` names the form a scan should match |
| `manifest.tsv` | Generated. Every file with its SHA-256, size, origin (`synthetic` or `third-party`), licence and provenance |
| `fonts/` | Noto Sans Arabic v2.013 and Noto Sans Devanagari v2.007 (unhinted TTF, OFL-1.1, with their licence texts), from the notofonts GitHub releases named in the manifest |

Liberation Sans (labels) and Great Vibes (signatures in the filled variants) are read from
`crates/casual-sign-flatten/fonts/`. Every font is pinned by SHA-256 in the script. The Arabic and Devanagari words
were shaped once with HarfBuzz (uharfbuzz 0.51.1) against the pinned fonts and are stored in the script as glyph ids
and positions, so no shaper runs at generation time.

## Forms and degradations

| Form | Fields drawn as | Pages |
| --- | --- | --- |
| `latin-consent` | Underscore runs with the label beside them, check boxes, initials | 1 |
| `latin-services` | Painted rules with the label under them, in a two-party signature block | 2 |
| `latin-acroform` | Labelled boxes, which are also AcroForm fields in the vector PDF | 1 |
| `arabic-application` | Right-to-left labels with a rule to their left | 1 |
| `devanagari-application` | Hindi labels with a rule to their right | 1 |

Variant names spell out what each scan went through:

- **Resolution:** 150, 200 or 300 DPI.
- **Skew:** up to ±2°, made of three integer shears, so the truth moves exactly with the pixels.
- **Encoding:** baseline JPEG at quality 60–75 (`DCTDecode`), or a binarised fax look at 300 DPI (1 bit, `RunLengthDecode`).
- **Orientation:** a page scanned upside down (`rot180`), or a page stored sideways and shown upright by `/Rotate 90` (`rot90`, where the truth stays upright).
- **Filled:** the variant carries typed values, ticked boxes and a script-font signature (`filled-`).

Every variant also has paper and ink tone, a [1 2 1] blur and specks. Each variant's seed and parameters are in its
truth file.

Field rectangles on lines stand on the line: 24 pt tall for a signature or initials and 16 pt otherwise. A word's
rectangle spans its advance width from the font's ascender to its descender. Underscore runs are drawn but are not
counted as words.
