# 20 — Error code registry

Stable, never reused. **The contract:** messages carry object numbers, ids, names from the PDF specification and
counts, never document text, field values or personal data (`SEC-D01`). Codes are reserved here before use; **none is
issued yet.** Ranges: `CS-PDF` reading, `CS-WRT` writing, `CS-FLD` fields, `CS-FLT` flattening, `CS-SEAL` sealing,
`CS-VER` verification, `CS-AUD` audit, `CS-WF` workflow, `CS-API` API, `CS-AUTH` authentication, `CS-KEY` keyd,
`CS-CNV` conversion.

## Reading (`casual-sign-pdf`)

| Code | Meaning |
| --- | --- |
| CS-PDF-0001 | Input too large |
| CS-PDF-0002 | Too many objects or xref entries |
| CS-PDF-0003 | Stream expansion over cap or ratio |
| CS-PDF-0004 | Nesting too deep, or reference cycle |
| CS-PDF-0005 | Not a PDF: no header and nothing recoverable |
| CS-PDF-0006 | Too many revisions, or a `/Prev` loop |
| CS-PDF-0007 | Too many pages, or a page tree cycle |
| CS-PDF-0008 | String or name over length cap |
| CS-PDF-0009 | Encrypted, and no password or the wrong one supplied |
| CS-PDF-0010 | Public-key security handler: not supported |
| CS-PDF-0011 | Unsupported filter |
| CS-PDF-0012 | Dynamic-only XFA form: no static content to sign |
| CS-PDF-0013 | Read stopped by the host's time budget |
| CS-PDF-0014 | Signed document is damaged and cannot be kept without breaking its signatures |
| CS-PDF-0101 | (report) Cross-reference rebuilt by scanning |
| CS-PDF-0102 | (report) Object unreadable; dropped |
| CS-PDF-0103 | (report) Active content removed: JavaScript or action |
| CS-PDF-0104 | (report) Embedded file removed |
| CS-PDF-0105 | (report) External reference removed |
| CS-PDF-0106 | (report) Existing form fields found |
| CS-PDF-0107 | (report) Existing signatures found |
| CS-PDF-0108 | (report) Optional content flattened to default visibility |

## Writing, fields, flattening

| Code | Meaning |
| --- | --- |
| CS-WRT-0001 | Incremental update would modify earlier bytes (invariant) |
| CS-WRT-0002 | Object number space exhausted |
| CS-FLD-0001 | Required field empty |
| CS-FLD-0002 | Value fails validation |
| CS-FLD-0003 | Group rule not satisfied |
| CS-FLD-0004 | Field outside its page |
| CS-FLD-0005 | Field references an unknown recipient or document |
| CS-FLD-0006 | Signer has no signature field (and free-form is off) |
| CS-FLD-0010 | Anchor text not found (and not ignorable) |
| CS-FLD-0011 | Text tag malformed |
| CS-FLD-0020 | Formula or condition cycle |
| CS-FLD-0021 | Formula invalid or over its bounds |
| CS-FLD-0022 | Client-computed value differs from the server's |
| CS-FLT-0001 | Glyph missing from every bundled font |
| CS-FLT-0002 | Signature image over dimension or pixel cap |
| CS-FLT-0003 | Image undecodable |

## Sealing and verification

| Code | Meaning |
| --- | --- |
| CS-SEAL-0001 | Key provider failed or refused |
| CS-SEAL-0002 | Timestamp authority failed or answered invalidly |
| CS-SEAL-0003 | Signature larger than its placeholder |
| CS-SEAL-0004 | Revocation data unavailable for the requested level |
| CS-SEAL-0005 | Algorithm or key not allowed by policy |
| CS-SEAL-0010 | Our own output failed verification (P0) |
| CS-VER-0001 | ByteRange malformed or not covering the revision |
| CS-VER-0002 | Digest mismatch |
| CS-VER-0003 | CMS signature invalid |
| CS-VER-0004 | Chain does not build to a trusted anchor (indeterminate) |
| CS-VER-0005 | Certificate revoked or expired at signing time |
| CS-VER-0006 | Timestamp invalid |
| CS-VER-0007 | Disallowed modification after signing |
| CS-VER-0008 | Audit chain broken (sequence, link or hash) |
| CS-VER-0009 | Audit chain head differs from the certificate's |

## Workflow, API, authentication, keys, conversion

| Code | Meaning |
| --- | --- |
| CS-WF-0001 | Command not allowed in the current state |
| CS-WF-0002 | Stale version (optimistic concurrency) |
| CS-WF-0003 | Actor not permitted to perform the command |
| CS-WF-0004 | Envelope invalid for sending (with the list of violations) |
| CS-WF-0005 | Routing would leave a required recipient unreachable |
| CS-API-0001 | Malformed request |
| CS-API-0002 | Not found (also returned for objects of another tenant) |
| CS-API-0003 | Rate limited |
| CS-API-0004 | Idempotency key reused with a different body |
| CS-API-0005 | Precondition failed (`If-Match`) |
| CS-AUTH-0001 | Not authenticated |
| CS-AUTH-0002 | Token expired or revoked |
| CS-AUTH-0003 | Recipient authentication failed |
| CS-AUTH-0004 | Recipient locked after too many attempts |
| CS-AUTH-0005 | Consent required |
| CS-KEY-0001 | Caller not authorized by keyd |
| CS-KEY-0002 | Unknown key alias |
| CS-KEY-0003 | HSM or KMS unavailable |
| CS-KEY-0004 | Insecure development key refused |
| CS-CNV-0001 | Conversion failed or timed out |
| CS-CNV-0002 | Format not supported |
