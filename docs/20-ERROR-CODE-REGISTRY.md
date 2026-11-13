# 20 — Error code registry

Stable, never reused. **The contract:** messages carry object numbers, ids, names from the PDF specification and
counts, never document text, field values or personal data (`SEC-D01`). Codes are reserved here before use. **Issued so far:** `CS-FLD-0001` to `0005`, `0010`, `0011` and `0020` to `0022` (stages 1C, 1D); `CS-WRT-0001` to `0006` (stages 1B, reader completion), `0007` (stage 1J); `CS-PDF-0110` (`NORM-03`) and `0111` (`NORM-02`); `CS-FLT-0001` to `0005` (stage 1E), `0006` (`FLT-03`); `CS-SEAL-0001` to `0006`, `0010` (stage 1G); `CS-AUD-0001` to `0010`, `0020` to `0024` (stage 1I), `0011` (`GEO-01`); `CS-SEAL-0001`, `0002`, `0004`, `0005`, `0010` and `CS-VER-0001` to `0003`, `0005`, `0006` (`casual-sign-crypto`, stage 1F); `CS-VER-0001` to `0007` (`casual-sign-verify`, stage 1H, which also uses `CS-SEAL-0004` for missing revocation data and `CS-SEAL-0005` for refused algorithms); `CS-KEY-0001` to `0012` (`casual-sign-keyd` and `casual-sign-secrets`, stage 2E), `0013` (keyd TLS refusal, `HRD-01`) and `0014` (`casual-sign-secrets`, keyd and the worker, `HRD-06`); `CS-DB-0001` to `0012` and `CS-BLOB-0001` to `0005` (`casual-sign-store`, stage 2B), `CS-DB-0015` (`ASVS-14`); `CS-WF-0001` to `0018` (stage 2A) and `0019`, `0020` (`GEO-01`), and `CS-AUTH-0003` to `0005` for a recipient's authentication and consent (`casual-sign-workflow`, stage 2A); `CS-WRK-0001` to `0016` (`casual-sign-worker`, stage 2D; `0001` to `0004` also from `casual-sign-host`, the decide-and-record path the server shares); `CS-API-0001` to `0014`, `0015` (`SEC-ID-01`), `0016` (`RAUTH-01`) and `CS-AUTH-0001`, `0002`, `0006` to `0010`, and `0011`, `0012` (`ASVS-01`) (`casual-sign-server`, stage 2C, which also answers the engine's, store's and PDF codes as problem details; `casual-sign-model` issues `CS-WF-0004` for a routing order or reminder step out of range). `CS-PII-0001` (`casual-sign-pii`, `ML-08`). `CS-ML-0011` and `0012` (`casual-sign-server`, `WEB-19`). `CS-BLK-0001` to `0007` (`casual-sign-server`, bulk send, `UXW-04`). `CS-WRK-0018` (`casual-sign-worker`, `ASVS-08`). `CS-LOG-0001` (`casual-sign-seclog`, `ASVS-08`). `CS-SCAN-0001` and `0002` (`casual-sign-server`, malware scanning of uploads, `ASVS-11`). `CS-NET-0001` and `0002` (the web app's API client, `webapp/api.js`; client-side only). Ranges: `CS-PDF` reading, `CS-WRT` writing, `CS-FLD` fields, `CS-FLT` flattening, `CS-SEAL` sealing,
`CS-VER` verification, `CS-AUD` audit, `CS-WF` workflow, `CS-DB` persistence, `CS-BLOB` blob storage, `CS-API` API, `CS-AUTH` authentication, `CS-KEY` keyd,
`CS-CNV` conversion, `CS-ML` model process and ML jobs (reserved, ADR-029), `CS-PII` personal-data recognisers, `CS-NET` the web app's API client, `CS-BLK` bulk send, `CS-SCAN` malware scanning of uploads, `CS-LOG` the log and security events; proposed (ADR-028, not issued): `CS-ORG` organizations, `CS-PLAN` plans, `CS-CON` console.

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
| CS-PDF-0014 | Signed document cannot be repaired or rewritten (normalized) without breaking its signatures; print to new (`NORM-02`) makes a new, unsigned document of it instead |
| CS-PDF-0101 | (report) Cross-reference rebuilt by scanning, offsets corrected, or the page tree rebuilt from the page objects |
| CS-PDF-0102 | (report) Object unreadable; dropped (also issued by normalization for page content it drops) |
| CS-PDF-0103 | (report) Active content removed: JavaScript or action |
| CS-PDF-0104 | (report) Embedded file removed |
| CS-PDF-0105 | (report) External reference removed |
| CS-PDF-0106 | (report) Existing form fields found |
| CS-PDF-0107 | (report) Existing signatures found, including usage-rights (Reader extensions) signatures, which normalization removes |
| CS-PDF-0109 | (report) Encrypted document decrypted with a supplied or empty password; normalized output is unencrypted |
| CS-PDF-0108 | (report) Optional content present, kept as it is at admission; flattening takes it to its default visibility (`FLT-03`, SEC-S03, docs/30 §7) |
| CS-PDF-0110 | (report) The catalog's `/Metadata` is not an XMP packet: not a stream, unreadable, over 4 MiB, not well-formed XML, a DOCTYPE, or another root element; normalization dropped it (an `rdf:RDF` root is wrapped in `x:xmpmeta` instead and reported as repaired) (`NORM-03`) |
| CS-PDF-0111 | (report) Print to new: a signature value, `/Perms` or the DSS removed; the signature's field appearance is drawn into the page as static content (`NORM-02`) |

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

## XFA layout (`casual-sign-xfa`, `XFA-01`)

A dynamic-only XFA form is refused by admission (`CS-PDF-0012`); the SDK then lays it out into static pages, and these
are the codes of that step (docs/30 §3 XFA, limits in docs/21 §XFA).

| Code | Meaning |
| --- | --- |
| CS-XFA-0001 | XFA packets (the XDP) larger than the limit |
| CS-XFA-0002 | XML elements nested deeper than the limit, or containers (subforms, areas, groups) nested deeper than the layout limit |
| CS-XFA-0003 | Too many XML nodes, or too many attributes on one element |
| CS-XFA-0004 | XML not well formed: syntax, crossed or unbalanced tags, a duplicate attribute, an undefined entity, an invalid character reference |
| CS-XFA-0005 | A document type or entity declaration: refused, so no entity is expanded or resolved |
| CS-XFA-0006 | No template packet with a root subform |
| CS-XFA-0007 | Merging or layout made more form nodes or layout items than the limit (instance explosion) |
| CS-XFA-0008 | Layout made more pages than the limit |
| CS-XFA-0009 | Cancelled by the host |
| CS-XFA-0010 | No usable face supplied to draw text with |

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
| CS-AUD-0011 | Signer location invalid or over its bounds (coordinate out of range or too precise, accuracy, country, region, city or database name; names the member, never the value) |
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
| CS-WF-0007 | Routing has not reached the recipient yet (for the Inbox's `POST …/sign-link`, also: has passed them, `UXW-01`) |
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
| CS-WF-0019 | The envelope captures location and a recipient action (delivered, viewed, signed, approved, declined) came without one; the server always supplies at least the IP approximation |
| CS-WF-0020 | The request's location contradicts the envelope's `capture_location`: a device location or a `declined`/`unavailable` reason when off, `not_requested` when on |
| CS-API-0001 | Malformed request |
| CS-API-0002 | Not found (also returned for objects of another tenant) |
| CS-API-0003 | Rate limited |
| CS-API-0004 | Idempotency key reused with a different body |
| CS-API-0005 | Precondition failed (`If-Match` unreadable); a stale version is `CS-WF-0002` |
| CS-API-0006 | Request body too large (413) |
| CS-API-0007 | Unsupported media type (415); ceremony calls that change state, and every `/api/v1` body, must be `application/json` (`ASVS-09`; the token endpoint also takes its RFC 6749 form, a document upload a raw PDF) |
| CS-API-0008 | Precondition required: `If-Match` absent where it is required (428) |
| CS-API-0009 | Not available in the object's state (409): a sealed document, certificate or PDF audit report before the seal job made it |
| CS-API-0010 | Internal error (500); the detail names the failing step, never data (`panic` for a handler that panicked, `ASVS-26`) |
| CS-API-0011 | A request with this idempotency key is still in progress (409) |
| CS-API-0012 | Method not allowed (405) |
| CS-API-0013 | Webhook URL refused: not HTTPS to a public address (SEC-W01) |
| CS-API-0014 | Recipient authentication method not available: not required of this recipient, not a sent code (`email_otp`, `sms_otp`, `voice_otp`), or nowhere to send it (no address or phone number) |
| CS-API-0015 | The user is also a member of another account: only they may change their password or name (403, `SEC-ID-01`); from the store's `CS-DB-0009` with SQLSTATE `OS003` |
| CS-API-0016 | The recipient's identity provider (`sso`, RAUTH-01) could not be reached, or answered neither a token nor a refusal (502); not counted as a failed sign-in |
| CS-AUTH-0001 | Not authenticated |
| CS-AUTH-0002 | Token expired or revoked |
| CS-AUTH-0003 | Recipient authentication failed |
| CS-AUTH-0004 | Recipient locked after too many attempts |
| CS-AUTH-0005 | Consent required |
| CS-AUTH-0006 | Credential lacks the scope or permission (403) |
| CS-AUTH-0007 | Invalid credentials: login or OAuth client (401) |
| CS-AUTH-0008 | CSRF token missing or wrong on a session request that changes something (403) |
| CS-AUTH-0009 | Ceremony link bound to another browser, or not yet opened in this one (403) |
| CS-AUTH-0010 | The API client does not own the embedding it acts for (row WF-05) (403) |
| CS-AUTH-0011 | The staff session owes a second factor: it has not passed it (`detail` `verify`), or the account's `mfa_policy` asks for one the user has not enrolled (`detail` `enrol`; administrators by default, `ASVS-31`); only the sign-in steps, `GET /auth/session` and `POST /auth/logout` serve it (403, `ASVS-01`) |
| CS-AUTH-0012 | Second factor refused: a wrong TOTP code, one for a step already used, or a recovery code not among the user's unspent ones (401, `ASVS-01`) |
| CS-KEY-0001 | Caller not authorized by keyd: no client certificate, an untrusted one, or one not on the allow-list |
| CS-KEY-0002 | Unknown key alias |
| CS-KEY-0003 | HSM or KMS unavailable, PIN refused, or a backend operation failed |
| CS-KEY-0004 | Insecure development key refused (`OPENSEAL_DEV_INSECURE_KEY` is not `1`) |
| CS-KEY-0005 | Secret unreadable: `NAME` and `NAME_FILE` both set, or the file unreadable or empty (`casual-sign-secrets`) |
| CS-KEY-0006 | Key configuration: no or unparsable certificate, key not found or ambiguous in the token, key not the certificate's, unsupported key type, size or scheme |
| CS-KEY-0007 | keyd request or response malformed: frame, identifier, digest length, or algorithm not the key's |
| CS-KEY-0008 | keyd rate limit exceeded for this caller |
| CS-KEY-0009 | keyd operation log cannot be opened, written or synced, or its hash chain does not verify; no signature is released (also `casual-sign-keyd verify-oplog`, `ASVS-14`, naming the first line that fails) |
| CS-KEY-0010 | keyd TLS certificates, keys or allow-list do not load |
| CS-KEY-0011 | keyd unreachable, or the connection failed before TLS answered (refused, reset, timed out, closed, the name does not resolve): an outage |
| CS-KEY-0012 | keyd setting missing or invalid |
| CS-KEY-0013 | TLS handshake with keyd refused: keyd's certificate does not chain to the configured CA or does not carry the configured name, or keyd refused the client certificate (none, untrusted, expired, revoked); a configuration error, fatal at worker start (`HRD-01`) |
| CS-KEY-0014 | Security configuration does not match `OPENSEAL_CONFIG_MANIFEST`: a setting changed, set but not listed, or listed but not set, a malformed manifest line, or an unreadable manifest or setting file; names the setting or line, never a value or digest. keyd and the worker refuse to start (`casual-sign-secrets::integrity`, ASVS-24, `HRD-06`) |
| CS-CNV-0001 | Conversion failed or timed out |
| CS-CNV-0002 | Format not supported |

## Persistence and blobs (`casual-sign-store`, stage 2B)

Messages carry the code, a SQLSTATE, a constraint name, an entity name or a count, never a database error's text,
which can quote the offending value (an email in a unique violation). Cross-tenant calls answer `CS-DB-0003`,
`CS-DB-0008` or `CS-DB-0009`, never `CS-DB-0006`: keys lead with `account_id`, so no answer reveals that another
account's row exists. The server maps `CS-DB-0003` to `CS-API-0002`, `CS-DB-0007` to `CS-WF-0002`, and `CS-DB-0009` with `OS003` to `CS-API-0015`.

| Code | Meaning |
| --- | --- |
| CS-DB-0001 | Database unreachable, connection failed, or pool exhausted |
| CS-DB-0002 | A migration failed, or an applied migration's text changed (migrations are forward-only) |
| CS-DB-0003 | Not found in this account (another account's object answers the same) |
| CS-DB-0004 | Update, delete or truncate of the audit chain, a tombstone, an admin log (`admin_events`, `org_admin_events`; `ORG-05`, migration 0020), the operator log (`CON-03`), or the usage ledger (`usage_ledger`; `PLAN-03`, migration 0025) refused (SQLSTATE `OS001`) |
| CS-DB-0005 | Audit event does not extend its envelope's chain: hash, `seq` or `prev` (SQLSTATE `OS002`); from `verify-evidence` (`ASVS-14`), also a stored event that does not rebuild into the chain or an envelope whose stored chain head is not its last event's hash, naming the envelope |
| CS-DB-0006 | Already exists (a unique constraint, named) |
| CS-DB-0007 | Stale version: the object changed since it was read |
| CS-DB-0008 | Check, reference or not-null constraint violated, including a reference to another account's object; with constraint `organization_keeps_an_owner` (SQLSTATE `23514`, `ORG-02`), a commit that would leave an active organization with no enabled owner (`StoreError::is_last_owner`, served as `CS-ORG-0008` by ORG-03's routes); with constraint `organization_admin_is_a_member` (SQLSTATE `23503`, `ORG-02`), an organization administrator who is not an enabled member of one of that organization's workspaces (ORG-03's routes check first and answer `CS-ORG-0018`); with constraint `admin_change_has_event` (SQLSTATE `23514`, `ORG-05`), a commit by the application role that changed settings, a member, a profile, a workspace or the organization without appending that change's admin event, or by the console role (`CON-16`) that changed an organization or workspace without its `operator.*` copy in that organization's log; from `TenantTx::record_usage` (SQLSTATE `23514`, `PLAN-03`), a gauge meter (`seats`, `storage_bytes`, `workspaces`, `templates`) or a quantity below 1 offered for counting |
| CS-DB-0009 | Refused by the database: missing privilege, or a row row-level security does not admit; SQLSTATE `OS003` (the store's own) when the user to change is also a member of another account (`SEC-ID-01`, served as `CS-API-0015`) |
| CS-DB-0010 | A stored value could not be read back as its type |
| CS-DB-0011 | The database has a migration this build does not know |
| CS-DB-0012 | Any other database error, by SQLSTATE |
| CS-DB-0013 | Change to an immutable column refused: a workspace's organization, outside ORG-20's operator link (SQLSTATE `OS004`; `ORG-02`, migration 0014) |
| CS-DB-0014 | Admin or operator log event does not extend its chain: hash, `seq`, `prev`, or columns that differ from its canonical bytes (SQLSTATE `OS005`; `ORG-05`, migration 0020, for `admin_events` and `org_admin_events`; `CON-03`, migration 0017, for `platform.operator_events`) |
| CS-DB-0015 | A check that must read every account's rows (`casual-sign-server verify-evidence`, `ASVS-14`) was run as a role that row-level security filters: run it as the schema owner |
| CS-BLOB-0001 | Blob store failed (I/O, network, unexpected status) |
| CS-BLOB-0002 | No blob under that key |
| CS-BLOB-0003 | Bytes stored under a key do not hash to it |
| CS-BLOB-0004 | Blob over the store's size cap (256 MiB by default) |
| CS-BLOB-0005 | Key is not 64 lower-case hexadecimal digits |

## Worker (`casual-sign-worker`, stage 2D)

Messages carry codes, ids, counts and HTTP statuses, never an address, a name, a subject, a URL, a token or document
content. The store's, the engine's, the SDK's and keyd's codes pass through unchanged. A job failing with a code
marked *final* is dead-lettered at once with an operator alert; the others are retried with back-off.

| Code | Meaning |
| --- | --- |
| CS-WRK-0001 | A worker setting is missing or invalid (named, never its value). *Final* |
| CS-WRK-0002 | A stored engine state does not read back as an `EnvelopeState`. *Final* |
| CS-WRK-0003 | An engine id the database keys by UUID is not a canonical UUID. *Final* |
| CS-WRK-0004 | A job's payload is malformed or its kind unknown. *Final* |
| CS-WRK-0005 | An email address or header value refused (`SEC-M02`): not an address, CR/LF, quotes, over its length. *Final* |
| CS-WRK-0006 | The SMTP server unreachable or refusing for now (4xx) |
| CS-WRK-0007 | The SMTP server refused the recipient permanently (5xx): reported to the engine as a bounce |
| CS-WRK-0008 | A webhook URL refused (`SEC-W01`): not `https://`, user information, or a host resolving to a private, loopback, link-local, metadata, CGNAT, documentation, multicast or reserved address not allow-listed. *Final* |
| CS-WRK-0009 | A webhook delivery failed: timeout, connection or TLS failure, or a status other than 2xx |
| CS-WRK-0010 | A webhook secret reference does not resolve, or is not `whsec_` and base64 of 16 bytes or more |
| CS-WRK-0011 | A seal input missing or unusable: a delivered document's blob, a capture, the sender's row |
| CS-WRK-0012 | A sealed document failed the worker's independent verification of the stored bytes (the envelope stays `completing`) |
| CS-WRK-0013 | No provider for the channel (SMS, WhatsApp; slice 12). *Final* |
| CS-WRK-0014 | No payment gateway configured (slice 13). *Final* |
| CS-WRK-0015 | The job's lease was lost: it lapsed and another worker took the job; also the code of an analysis run whose last attempt's lease lapsed with its worker gone (`ML-25`) |
| CS-WRK-0016 | A capture (signature art) malformed or over its limits. *Final* |
| CS-WRK-0017 | The SMS or voice provider did not accept a one-time code message (its HTTP status, when it answered); retried within the code's attempts (VS-05) |
| CS-WRK-0018 | A time-stamping authority not reached, refused by the address policy, or answering no time-stamp (connection, TLS, timeout, HTTP status, an answer over its limit); logged as `transport.backend_failed` with the TSA's index in the list, never its URL, and the next TSA is tried (`ASVS-08`, ASVS 9.2.5). A log code, not a job's |

## Log and security events (`casual-sign-seclog`, `ASVS-08`)

| Code | Meaning |
| --- | --- |
| CS-LOG-0001 | `OPENSEAL_LOG_PSEUDONYM_KEY` (or its `_FILE`) is not 32 bytes as base64, or both forms are set: the server, the console, the worker, keyd and modeld refuse to start, with a `start_failed` line (docs/65 §Logs) |

## Platform console (`casual-sign-console`, `casual-sign-platform-store`; `CON-02`, `CON-03`, `CON-04`, `CON-06`, `CON-07`)

Issued by the console's first rows (migrations 0016 to 0018). Every console answer is an RFC 9457 problem with one of
these codes; messages carry codes, ids and sequence numbers only. The platform store maps SQLSTATEs raised by the
`platform` definer functions: `OS006` → `CS-CON-0001`, `OS007` → `CS-CON-0002`, `OS008` → `CS-CON-0003`, `OS009` →
`CS-CON-0004`, `OS010` → `CS-PLAN-0006` (plans, `PLAN-02`, migration 0024), `OS012` → `CS-CON-0006` (TSA changes, `CON-07`, migration 0034), `OS005` → `CS-DB-0014`, `OS001` → `CS-DB-0004` (widened to `platform.operator_events` and
`platform.alerts`, which use the same refusal).

| Code | Meaning |
| --- | --- |
| CS-CON-0001 | Operator not authenticated: no session cookie, or the session expired (8 hours), idled (30 minutes), was revoked, or its operator is disabled; also a wrong password, an unknown e-mail (the same answer) and an unknown or spent enrolment token (401) |
| CS-CON-0002 | Second factor required, stale or wrong: a session that has passed only the password, a wrong code, a code for a time step already used, or a two-person step whose second factor is older than 5 minutes (401) |
| CS-CON-0003 | Operator role lacks the action, checked by the route and again by the database (403) |
| CS-CON-0004 | Action needs a second operator's approval; missing, expired, used, by the requester, or for another payload (409). Issued for suspending and resuming an organization (`CON-04`, migration 0019) and for adding a `platform_owner` (refused until that action has its approval function) |
| CS-CON-0005 | Console listener refused: a non-loopback bind without `OPENSEAL_CONSOLE_PUBLIC=1`, or without `OPENSEAL_TRUSTED_PROXIES` (TLS terminates at the proxy), or the console's origin equal to the public application's (start-up) |
| CS-CON-0008 | keyd admin call refused: a caller on keyd's signing allow-list calling an admin operation (`list-keys`, `oplog-head`, `oplog-range`, `health`), or a caller on the admin allow-list asking for a chain or a signature. Issued by keyd (`CON-06`; wire number 1008, recorded in keyd's log) and answered by the console as 502 when its keyd identity is on the wrong list. The console answers other keyd failures with keyd's own `CS-KEY-*` code (502) |
| CS-CON-0006 | Seal alias, TSA or trust anchor refused: unknown to keyd, expired, unapproved, or fails its check (422; names the field). Issued for TSA changes (`CON-07`, migration 0034): a proposed URL that is not `http`/`https` or whose host resolves to an address outside the `SEC-W01` policy (`url`), a policy OID, certificate hash or priority out of shape, and from the database a payload that fails its checks (SQLSTATE `OS012`, `payload`). Issued for seal alias changes (`CON-10`, migration 0035): an alias keyd does not serve with a certificate valid at `active_from`, or no keyd to ask (`alias`), a start already past (`active_from`, at proposal and, from the database's `OS012`, at apply; a change proposed without a start begins when applied and is never refused for it); and by the worker when the alias in force is not fully approved or the worker has no keyd (the seal fails, `SealFailed`) |
| CS-CON-0007 | Operator log does not verify (names the first bad `seq`): the console refuses to start; the API and health page report it (503) |
| CS-CON-0010 | Request invalid: malformed JSON or a value out of range; names the field (422) |
| CS-CON-0011 | No such object (404); also a key change granted or applied through the routes of another kind (a seal alias change through `/console/v1/tsa/changes/…`, or a TSA change through `/console/v1/seal/changes/…`; `HRD-06`) |
| CS-CON-0012 | Rate limit: sign-in per address and per e-mail, TOTP per operator, requests per session; `retry_after` seconds (429) |
| CS-CON-0013 | A changing request without its session's CSRF token, with a wrong one, or not `application/json` (403) |
| CS-CON-0014 | Internal failure; names the step, never a value (500; `panic` for a handler that panicked, `ASVS-26`) |
| CS-CON-0015 | The database is unavailable (503) |
| CS-CON-0016 | Already exists: an operator with that e-mail (409) |
| CS-CON-0017 | Console configuration invalid or a secret missing; names the variable (start-up) |

## Organizations, plans and console (proposed, ADR-028)

**Proposed, not issued.** Reserved by ADR-028 (Accepted 2026-11-12) and [23](23-ORGANIZATIONS-WORKSPACES-AND-CONSOLE.md)
§8; nothing issues them yet. Each moves to the issued list above when the row that builds it merges. New ranges:
`CS-ORG` (organizations, workspaces, delegated administration, identity), `CS-PLAN` (plans and quotas), `CS-CON`
(platform console). `CS-ORG-0012` is withdrawn before issue: `SEC-ID-01`'s fix issues `CS-API-0015` (store `CS-DB-0009`,
SQLSTATE `OS003`) for the identity-attribute refusal, so this design's SQLSTATEs are `OS004` and `OS005`.
`CS-PLAN-0002` to `CS-PLAN-0005` are issued (`PLAN-04`, migration 0028; SQLSTATE `OS011` is raised and caught
inside `openseal_consume_quota` only, to roll back a refused count, and never reaches a client); `CS-PLAN-0001` and
`CS-PLAN-0007` are not. `CS-DB-0004`'s widening to the admin logs and `CS-DB-0014` are issued (`ORG-05`, migration 0020); the operator log
(`platform.operator_events`) uses both (`CON-03`, migration 0017). `CS-DB-0013` is issued (`ORG-02`). All are listed with
the store codes above; `CS-CON-0001` to `-0005` and `-0007` are issued (`CON-02`, `CON-03`), `-0008` (`CON-06`) and `-0006` (`CON-07`), and listed in the section above.

| Code | Meaning |
| --- | --- |
| CS-ORG-0001 | Not a member of that workspace, or the membership is disabled (switch, 403). Issued (`ORG-04`): `POST /auth/switch`, the same for an id that does not exist |
| CS-ORG-0002 | Setting locked or tightened by the organization's policy (422; names the key) |
| CS-ORG-0003 | Domain not verified (TXT record absent or wrong) (422) |
| CS-ORG-0004 | Domain cannot be claimed (already claimed, or a public e-mail domain); never says by whom (409) |
| CS-ORG-0005 | Grant refused: exceeds the granting admin's own rights or scope, or grants to itself (403) |
| CS-ORG-0006 | Sign-in method not allowed for this identity by its governing organization's policy (401) |
| CS-ORG-0007 | Switching needs a fresh sign-in satisfying the target organization's policy (401; names the method) |
| CS-ORG-0008 | The organization must keep at least one enabled owner (409) |
| CS-ORG-0009 | Envelopes do not move between workspaces; transfer within one, or export the evidence package (422) |
| CS-ORG-0010 | Workspace archived: no new envelopes, members or settings (409) |
| CS-ORG-0011 | Identity-provider assertion for an identity outside the provider organization's verified domains, or with no binding (401) |
| CS-ORG-0012 | *Withdrawn before issue:* the identity-attribute refusal is `CS-API-0015` (`SEC-ID-01`). Never reused |
| CS-ORG-0013 | Action reserved to an organization owner, or awaiting an owner's approval (403) |
| CS-ORG-0014 | Sensitive action needs a fresh sign-in (401) |
| CS-ORG-0015 | Organization closed: read-only (409) |
| CS-ORG-0016 | Cross-workspace template copy not allowed by the organization's policy (403) |
| CS-ORG-0017 | Imported evidence package does not verify (422; names the failing check) |
| CS-ORG-0018 | An organization administrator must be an enabled member of one of that organization's workspaces (422, `POST /organizations/me/admins`, ORG-03) |
| CS-PLAN-0001 | Feature not in the plan (403; names the feature) |
| CS-PLAN-0002 | Quota for the period reached (403; meter, limit, used, period end). Issued (`PLAN-04`, migration 0028): `envelopes_sent` at every send, by `TenantTx::consume_quota` (store `StoreError::Plan`); the problem carries `meter`, `limit`, `used`, `period_end` |
| CS-PLAN-0003 | Seat limit reached (403). Issued (`PLAN-04`): `POST /users`, `PATCH /users/{id}` (profile, enable), by `TenantTx::gauge_check`; `meter`, `limit`, `used` |
| CS-PLAN-0004 | Storage limit reached (403). Issued (`PLAN-04`): envelope and template document uploads; `meter`, `limit`, `used` |
| CS-PLAN-0005 | Organization suspended by the platform: new work refused, sent envelopes continue (403). Issued (`PLAN-04`) at sends, member additions and uploads; the other creation points are `PLAN-17` |
| CS-PLAN-0006 | Plan, quota or override invalid, including `hard` on an approximate meter (console, 422; names the field). Issued (`PLAN-02`): by `casual-sign-policy` validation and by the migration 0024 definer functions (`OS010`) |
| CS-PLAN-0007 | Workspace allocations exceed the organization's quota (422) |
| CS-CON-0009 | Reconciliation found a keyd signature with no seal record, or a seal record with no signature (alert) |

## Personal data (`casual-sign-pii`, `ML-08`)

The deterministic recognisers refuse only text over their size bound; every other bound truncates and is reported in
the result, never as an error ([21](21-PARSER-LIMITS.md) §ML). The message carries the byte count and the limit, never
any of the text (`SEC-D01`), and a test checks that with a marker string. The validated identifiers of `ML-08C` add
no code: a candidate whose check fails is simply not a finding.

| Code | Meaning |
| --- | --- |
| CS-PII-0001 | Text over the bound for one detection call (`Options::max_text_bytes`, default 4 MiB). *Final* for that text |

## Bulk send (`casual-sign-server`, `UXW-04`)

A list's problems. `0004`, `0005` and `0007` refuse the whole request as `422` problem details (`errors[].pointer`
names `/columns`, `/columns/{i}`, `/csv` or `/rows`); `0001` to `0003` and `0006` are a row's problems, answered in the
row with the column they are in and stored as the row's `error_code`; such a row is never sent. Never carries a value
from the list.

| Code | Meaning |
| --- | --- |
| CS-BLK-0001 | A row's name or email for a role is empty |
| CS-BLK-0002 | A row's email cannot be an address (not one `@` with text on both sides, spaces or control characters, over 320 bytes) |
| CS-BLK-0003 | A row's name is over 255 characters or has control characters |
| CS-BLK-0004 | A column the template needs (`<role>::name`, `<role>::email`) is not in the list |
| CS-BLK-0005 | A column the template does not have, or one given twice |
| CS-BLK-0006 | A CSV row has more values than the header has columns |
| CS-BLK-0007 | No row, more than 1,000, or CSV that cannot be read (a quote never closed) |

## Malware scanning of uploads (`casual-sign-server`, `ASVS-11`)

Answered when a malware scanner is configured (`OPENSEAL_CLAMD_ADDR`, docs/65 §Malware scanning) and an upload (an
envelope's or a template's document, a signer's attachment, an adopted signature image, a saved profile mark) is
refused before anything of it is read or stored. Each refusal also appends an event to the workspace's admin log
(`upload.malware_refused`, `upload.unscanned_refused`). Neither carries the file's name or content; `0001` does not
carry the signature name either (it is in the admin log).

| Code | Meaning |
| --- | --- |
| CS-SCAN-0001 | The scanner found malware in the upload (`422`); nothing of it is stored |
| CS-SCAN-0002 | The scanner could not judge the upload and the server fails closed (`503`, `Retry-After: 30`); `detail` is the reason: `connect` (clamd not reached, or the connection broke), `timeout`, `too_large` (over `OPENSEAL_CLAMD_MAX_BYTES` or clamd's `StreamMaxLength`), `error` (clamd answered an error) or `protocol` (an answer that is none of clamd's). With `OPENSEAL_CLAMD_FAIL_OPEN=1` the upload is admitted instead and `upload.unscanned_admitted` recorded |

## Web app API client (`webapp/api.js`, `UX-03`)

Raised by the browser's API client, never sent by the server, so no problem-details response carries them. The
`detail` holds at most the client call's name, never request or document content. Each has an English string in
`webapp/strings.en.js` (`error.CS-NET-…`).

| Code | Meaning |
| --- | --- |
| CS-NET-0001 | The request did not reach the server or no answer came back (network failure); status 0 |
| CS-NET-0002 | The call is not served by this server yet (listed in `NOT_ON_SERVER`); refused at once with status 501 and no request sent; `detail` is the call's name |

## ML (`casual-sign-modeld`, the worker's ML jobs; reserved, ADR-029)

Reserved by [33](33-ML-MODELS.md); none issued yet. Messages carry codes, ids, page numbers and counts, never document
text, OCR text, entity or personal-data values, labels' matches, boxes, hashes or vectors (`SEC-I05`). A runtime's or
third-party crate's own error text is never passed on. An ML job failing with a code marked *final* is dead-lettered;
a dead ML job means only "no suggestions" and never blocks sending or sealing.

| Code | Meaning |
| --- | --- |
| CS-ML-0001 | A modeld or ML setting missing or invalid (named, never its value), including a slot count of zero once derived from memory or one set above it. *Final* |
| CS-ML-0002 | Model bundle: a file missing, unlisted, over its size or not matching its SHA-256; modeld does not start. *Final* |
| CS-ML-0003 | A model file refused: external data, custom op domain, pickle format, or licence not allowed. *Final* |
| CS-ML-0004 | A frame malformed or over a bound (length, count, id alphabet, UTF-8 or NFC), or a document handle unknown on this connection |
| CS-ML-0005 | Input over its bound: page pixels, decoded image data, text bytes, GLiNER label-prompt tokens. *Final* for that page or call |
| CS-ML-0006 | A page could not be rasterised: encrypted, unsupported, damaged, or over its time (the raster child was killed). Reported per page |
| CS-ML-0007 | Inference deadline passed |
| CS-ML-0008 | modeld unreachable, TLS refused, or the connection closed |
| CS-ML-0009 | modeld busy; retry |
| CS-ML-0010 | The model for this op is not installed in the bundle. *Final* |
| CS-ML-0011 | The feature is off for the workspace or not in its plan (API `403`); also every analysis route while no feature is in effect, and turning a feature on while the model service is not installed (`WEB-19`) |
| CS-ML-0012 | Suggestion stale or already decided (API `409`); as built (`WEB-19`), stale means its document has left the envelope |
| CS-ML-0013 | Inference failed inside the runtime, or a span would not fall on a UTF-8 boundary of the text sent |
| CS-ML-0014 | The raster child exited abnormally (signal, memory limit) other than by the time cap; counted in the op log. Reported per page. Also the refusal to open a document on any platform but Linux, where the child's limits cannot be enforced (docs/33 §3.3) |
| CS-ML-0015 | The caller's client certificate chains to the client CA but its SHA-256 fingerprint is not on modeld's allow list; recorded in the op log as a `connect` refusal; its first frame is never held (docs/21 §ML). *Final* (an operator must add the fingerprint) |
