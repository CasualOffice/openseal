# 21 — Parser and input limits

Every limit the code will hold, its default, its code, and whether a hostile fixture proves it. **Proposed defaults;
nothing is built.** Each default becomes a host-overridable value in `casual-sign-pdf::Limits` or the server's
configuration; the defaults are chosen to admit every corpus document with headroom, and are re-measured at the
Phase 1 gate.

## PDF

| Limit | Default | Code | Fixture |
| --- | ---: | --- | --- |
| File size (UI upload) | 50 MiB | CS-PDF-0001 | — |
| File size (API upload) | 50 MiB | CS-PDF-0001 | — |
| Envelope total | 200 MiB | CS-API-0001 | — |
| Indirect objects | 1,000,000 | CS-PDF-0002 | — |
| Xref entries declared (`/Size`) honoured for allocation | 0 (never); a `/Size` above 8,388,607 is treated as damage and the xref rebuilt by scanning | CS-PDF-0002 | — |
| Revisions (`/Prev` chain) | 1,000 | CS-PDF-0006 | — |
| Nesting depth (arrays and dictionaries) | 256 | CS-PDF-0004 | — |
| Reference resolution depth | 64 | CS-PDF-0004 | — |
| Single stream decoded | 256 MiB | CS-PDF-0003 | — |
| Total decoded per document | 1 GiB | CS-PDF-0003 | — |
| Decode ratio per stream | 1:1000 after the first 1 MiB (plain Flate tops out near 1:1032, so this catches chained filters; the size caps above stop Flate bombs, `SPK-01`) | CS-PDF-0003 | — |
| Filter chain length | 8 | CS-PDF-0011 | — |
| Pages | 5,000 | CS-PDF-0007 | — |
| String length | 16 MiB | CS-PDF-0008 | — |
| Name length | 127 bytes (PDF 2.0 recommendation) | CS-PDF-0008 | — |
| Content-stream operators interpreted for text extraction, per page | 2,000,000 | CS-PDF-0013 | — |
| Time budget | Host-supplied predicate | CS-PDF-0013 | — |

## Images (signatures, stamps, attachments shown inline)

| Limit | Default | Code |
| --- | ---: | --- |
| Upload size | 5 MiB | CS-FLT-0002 |
| Width × height | 4,096 × 4,096 | CS-FLT-0002 |
| Formats | PNG, JPEG | CS-FLT-0003 |
| Drawn signature points | 20,000 | CS-FLD-0002 |

## Fields and envelopes

| Limit | Default | Code |
| --- | ---: | --- |
| Recipients per envelope | 100 | CS-WF-0004 |
| Fields per envelope | 3,000 | CS-WF-0004 |
| Text field value | 4,000 bytes | CS-FLD-0002 |
| Dropdown options | 500 | CS-FLD-0002 |
| Formula length / depth / references | 1,024 chars / 32 / 100 | CS-FLD-0021 |
| Anchor matches per string | 500 | CS-FLD-0010 |
| Subject / message | 255 / 10,000 characters | CS-API-0001 |
| Custom fields per envelope | 100 | CS-API-0001 |
| Signer attachment size | 25 MiB | CS-FLD-0002 |

## Bulk and links

| Limit | Default | Code |
| --- | ---: | --- |
| Bulk send rows per batch | 1,000 | CS-API-0001 |
| Bulk CSV size | 10 MiB | CS-API-0001 |
| Signing link uses | Owner-set; default unlimited with per-IP rate limit | CS-API-0003 |
