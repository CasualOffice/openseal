# 20 — Error code registry

Stable, never reused. **The contract:** messages carry object numbers, ids, names from the PDF specification and
counts, never document text, field values or personal data (`SEC-D01`). Codes are reserved here before use. **Issued so far:** `CS-FLD-0001` to `0005`, `0010`, `0011` and `0020` to `0022` (stages 1C, 1D); `CS-WRT-0001` to `0006` (stages 1B, reader completion), `0007` (stage 1J); `CS-FLT-0001` to `0005` (stage 1E), `0006` (`FLT-03`); `CS-SEAL-0001` to `0006`, `0010` (stage 1G); `CS-AUD-0001` to `0010`, `0020` to `0024` (stage 1I); `CS-SEAL-0001`, `0002`, `0004`, `0005`, `0010` and `CS-VER-0001` to `0003`, `0005`, `0006` (`casual-sign-crypto`, stage 1F); `CS-VER-0001` to `0007` (`casual-sign-verify`, stage 1H, which also uses `CS-SEAL-0004` for missing revocation data and `CS-SEAL-0005` for refused algorithms); `CS-KEY-0001` to `0012` (`casual-sign-keyd` and `casual-sign-secrets`, stage 2E); `CS-WF-0001` to `0018`, and `CS-AUTH-0003` to `0005` for a recipient's authentication and consent (`casual-sign-workflow`, stage 2A; `casual-sign-model` issues `CS-WF-0004` for a routing order or reminder step out of range). Ranges: `CS-PDF` reading, `CS-WRT` writing, `CS-FLD` fields, `CS-FLT` flattening, `CS-SEAL` sealing,
`CS-VER` verification, `CS-AUD` audit, `CS-WF` workflow, `CS-API` API, `CS-AUTH` authentication, `CS-KEY` keyd,
`CS-CNV` conversion.

## Reading (`casual-sign-pdf`)

| Code | Meaning |
| --- | --- |
| CS-PDF-0001 | Input too large |
| CS-PDF-0002 | Too many objects or xref entries |
| CS-PDF-0003 | Stream expansion over cap or ratio |
| CS-PDF-0004 | Nesting too deep, or reference cycle |
| CS-PDF-0005 | Not a PDF: no header and nothing recoverable; under `strict`, also a malformed object |
| CS-PDF-0006 | Too many revisions, or a `/Prev` loop |
| CS-PDF-0007 | Too many pages, or a page tree cycle |
| CS-PDF-0008 | String or name over length cap |
| CS-PDF-0009 | Encrypted, and no password or the wrong one supplied |
| CS-PDF-0010 | Security handler not supported: public-key (`PDF-ENC-02`), or a handler, revision or crypt filter method other than the standard one's |
| CS-PDF-0011 | Unsupported filter, or a filter chain over its limit |
| CS-PDF-0012 | Dynamic-only XFA form: no static content to sign |
| CS-PDF-0013 | Read stopped by the host's time budget, or a page's content-operator budget for text extraction |
| CS-PDF-0014 | Signed document cannot be repaired or rewritten (normalized) without breaking its signatures |
| CS-PDF-0101 | (report) Cross-reference rebuilt by scanning, offsets corrected, or the page tree rebuilt from the page objects |
| CS-PDF-0102 | (report) Object unreadable; dropped (also issued by normalization for page content it drops) |
| CS-PDF-0103 | (report) Active content removed: JavaScript or action |
| CS-PDF-0104 | (report) Embedded file removed |
| CS-PDF-0105 | (report) External reference removed |
| CS-PDF-0106 | (report) Existing form fields found |
| CS-PDF-0107 | (report) Existing signatures found, including usage-rights (Reader extensions) signatures, which normalization removes |
| CS-PDF-0109 | (report) Encrypted document decrypted with a supplied or empty password; normalized output is unencrypted |
| CS-PDF-0108 | (report) Optional content present, kept as it is at admission; flattening takes it to its default visibility (`FLT-03`, SEC-S03, docs/30 §7) |

The recovering reader's findings also carry limit codes (`0002`, `0003`, `0004`, `0006`, `0008`, `0011`, `0013`) where a
limit was crossed and the rest of the document still opened; `fixtures/hostile/manifest.tsv` lists which. **Issued by stage
1A:** every `CS-PDF` code above.

## Writing, fields, flattening

| Code | Meaning |
| --- | --- |
| CS-WRT-0001 | Incremental update would modify earlier bytes (invariant) |
| CS-WRT-0002 | Object number space exhausted (above 8,388,607) |
| CS-WRT-0003 | File not structurally sound for appending: its cross-reference was repaired or rebuilt |
| CS-WRT-0004 | DocMDP of a certification signature forbids the change |
| CS-WRT-0005 | Replacing an object the file does not have, or a stream whose data is not in the file |
| CS-WRT-0006 | Appending to an encrypted file is refused (an update would have to be encrypted); normalize first |
| CS-WRT-0007 | Keeping a document as signed when it carries no signature; normalize it instead |
| CS-FLD-0001 | Required field empty |
| CS-FLD-0002 | Value fails validation; also a sender rule that cannot be used (a regex that does not compile or is over its limits, inverted min and max) |
| CS-FLD-0003 | Group rule not satisfied |
| CS-FLD-0004 | Field outside its page |
| CS-FLD-0005 | Field references an unknown recipient, document, field id or data label, or two fields share an id |
| CS-FLD-0006 | Signer has no signature field (and free-form is off) |
| CS-FLD-0010 | Anchor text not found (and not ignorable), or more than 500 matches |
| CS-FLD-0011 | Text tag malformed |
| CS-FLD-0020 | Formula or condition cycle |
| CS-FLD-0021 | Formula invalid or over its bounds |
| CS-FLD-0022 | Client-computed value differs from the server's |
| CS-FLT-0001 | Glyph missing from every bundled font |
| CS-FLT-0002 | Signature image over dimension or pixel cap |
| CS-FLT-0003 | Image undecodable |
| CS-FLT-0004 | More fields on one page than the flattening limit |
| CS-FLT-0005 | A font face supplied by the host cannot be read |
| CS-FLT-0006 | An optional content visibility expression (`/VE`) nested deeper than 32 or over 4,096 terms |

## Sealing and verification

| Code | Meaning |
| --- | --- |
| CS-SEAL-0001 | Key provider failed or refused |
| CS-SEAL-0002 | Timestamp authority failed or answered invalidly |
| CS-SEAL-0003 | Signature larger than its placeholder after one retry with the measured size |
| CS-SEAL-0004 | Revocation data unavailable for the requested level, or OCSP/CRL data unusable |
| CS-SEAL-0005 | Algorithm, curve or key not allowed by policy or not supported (build and verify), including SHA-1 identifiers |
| CS-SEAL-0006 | Seal request does not fit the document: certification after an existing signature, a field that is not a signature field or is already signed, a bad field name, a page out of range |
| CS-SEAL-0010 | Our own output failed verification, or our own DER could not be encoded (P0) |
| CS-VER-0001 | ByteRange malformed or not covering the revision |
| CS-VER-0002 | Digest mismatch |
| CS-VER-0003 | CMS malformed or its signature invalid |
| CS-VER-0004 | Chain does not build to a trusted anchor (indeterminate) |
| CS-VER-0005 | Certificate revoked or expired at signing time |
| CS-VER-0006 | Timestamp invalid |
| CS-VER-0007 | Disallowed modification after signing |
| CS-VER-0008 | Audit chain broken (sequence, link or hash) |
| CS-VER-0009 | Audit chain head differs from the certificate's |

## Workflow, API, authentication, keys, conversion

| Code | Meaning |
| --- | --- |
| CS-AUD-0001 | Malformed JSON: syntax, duplicate key, lone surrogate, number out of range, non-finite, trailing data |
| CS-AUD-0002 | Audit limit crossed |
| CS-AUD-0003 | Event or trail has the wrong shape |
| CS-AUD-0004 | Append refused: another envelope |
| CS-AUD-0005 | Append refused: sequence is not the next |
| CS-AUD-0006 | Append refused: previous hash is not the head |
| CS-AUD-0007 | Append refused: time goes backwards beyond the tolerance |
| CS-AUD-0008 | Chain failed verification |
| CS-AUD-0009 | Merkle inclusion proof invalid |
| CS-AUD-0010 | Tombstone does not match its chain |
| CS-AUD-0020 | Certificate input invalid or over its bounds |
| CS-AUD-0021 | Certificate over 500 pages |
| CS-AUD-0022 | Document already has `/AF` or embedded files |
| CS-AUD-0023 | Catalog or page tree unusable for appending a certificate |
| CS-AUD-0024 | Certificate text did not fit (refused rather than clipped) |
| CS-WF-0001 | Command not allowed in the current state |
| CS-WF-0002 | Stale version (optimistic concurrency) |
| CS-WF-0003 | Actor not permitted to perform the command |
| CS-WF-0004 | Envelope invalid for sending (with the list of violations) |
| CS-WF-0005 | Routing would leave a required recipient unreachable: no address and nobody earlier to supply one |
| CS-WF-0006 | Command id already applied with a different command (re-applying the same command is a replay, not an error) |
| CS-WF-0007 | Routing has not reached the recipient yet |
| CS-WF-0008 | Unknown envelope, recipient, document or field id |
| CS-WF-0009 | Seal result does not prove an independently verified seal of every document as delivered (or names a job not pending) |
| CS-WF-0010 | Id already used in the envelope |
| CS-WF-0011 | Envelope has applied its most commands (100,000; the idempotency record is bounded) |
| CS-WF-0012 | Envelope's signing options do not allow decline, reassign or finish later |
| CS-WF-0013 | Signature or initials not adopted before use |
| CS-WF-0014 | Viewer has not viewed every document to the end |
| CS-WF-0015 | Viewed document does not match the document as fixed (hash or pages) |
| CS-WF-0016 | Field not editable by this recipient: another's, read-only, locked, or takes no input |
| CS-WF-0017 | A computed time (timer, date stamp) falls outside years 0000 to 9999 |
| CS-WF-0018 | A value could not be put in canonical form for hashing |
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
| CS-KEY-0001 | Caller not authorized by keyd: no client certificate, an untrusted one, or one not on the allow-list |
| CS-KEY-0002 | Unknown key alias |
| CS-KEY-0003 | HSM or KMS unavailable, PIN refused, or a backend operation failed |
| CS-KEY-0004 | Insecure development key refused (`OPENSEAL_DEV_INSECURE_KEY` is not `1`) |
| CS-KEY-0005 | Secret unreadable: `NAME` and `NAME_FILE` both set, or the file unreadable or empty (`casual-sign-secrets`) |
| CS-KEY-0006 | Key configuration: no or unparsable certificate, key not found or ambiguous in the token, key not the certificate's, unsupported key type, size or scheme |
| CS-KEY-0007 | keyd request or response malformed: frame, identifier, digest length, or algorithm not the key's |
| CS-KEY-0008 | keyd rate limit exceeded for this caller |
| CS-KEY-0009 | keyd operation log cannot be opened, written or synced, or its hash chain does not verify; no signature is released |
| CS-KEY-0010 | keyd TLS certificates, keys or allow-list do not load |
| CS-KEY-0011 | keyd unreachable, or the TLS connection failed (a refused handshake included) |
| CS-KEY-0012 | keyd setting missing or invalid |
| CS-CNV-0001 | Conversion failed or timed out |
| CS-CNV-0002 | Format not supported |
