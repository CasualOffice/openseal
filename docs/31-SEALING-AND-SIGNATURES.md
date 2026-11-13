# 31 — Sealing and digital signatures

**Status: Draft for owner.** How `casual-sign-seal`, `-crypto`, `-verify` and `server/casual-sign-keyd` make a completed
agreement tamper-evident and verifiable for decades. Legal context is [09](09-LEGAL-AND-COMPLIANCE.md); the PDF writer is
[30](30-PDF-PIPELINE.md); evidence content is [32](32-AUDIT-TRAIL-AND-EVIDENCE.md).

## 1. Two kinds of signature

| | Electronic signature (the person's) | Digital signature (the seal) |
| --- | --- | --- |
| What | A drawn, typed or uploaded mark adopted with intent, plus the evidence of who adopted it | A cryptographic signature over the document bytes |
| Legal role | SES under ESIGN, UETA, eIDAS | Integrity: "the record has not changed since" (eIDAS Art. 26(d)); with a per-signer key, AES or QES |
| Made by | The recipient, in the ceremony | The platform's key in `keyd`; or, for AES/QES, the signer's key via a QTSP |
| In the PDF | Flattened image and text on the page | A `/Sig` field with CMS SignedData |

DocuSign and SignNow work the same way by default: people adopt marks, and the platform seals.

## 2. Profiles

The account chooses; the default is **PAdES B-T**, so every sealed document carries trusted time.

| Profile | Adds | When |
| --- | --- | --- |
| PAdES **B-B** | CMS SignedData, `SubFilter /ETSI.CAdES.detached`; signed attributes `content-type`, `message-digest`, `signing-certificate-v2`; signing time in the PDF `/M`, not CMS `signingTime` | Never alone in production; tests |
| PAdES **B-T** | RFC 3161 `signature-time-stamp` unsigned attribute on the SignerInfo | **Default** |
| PAdES **B-LT** | A later incremental update with the **DSS** dictionary: `/Certs`, `/OCSPs`, `/CRLs`, `/VRI` per signature | Regulated accounts; validation years later without network |
| PAdES **B-LTA** | A **document timestamp** (`/Type /DocTimeStamp`, `SubFilter /ETSI.RFC3161`) over everything including the DSS; renewed before the TSA certificate or algorithm weakens | Archives; renewal job (slice 17) |

`adbe.pkcs7.sha1` and `adbe.x509.rsa_sha1` are never written. `adbe.pkcs7.detached` is read and verified, not written.

## 3. When the seal is applied

**Default: once, at completion**, after every value has been flattened and the certificate of completion and audit
JSON have been added ([02](02-HLD.md) §5.3). This is the pattern DocuSign follows and the one that keeps the file simple
for readers: one platform signature over the final document.

**Option: seal per signer** (slice 16). After each recipient finishes, an incremental revision with a platform
signature naming that recipient in `/Name` and `/Reason`. Each signer's contribution is then protected individually
and visible in Acrobat's signature panel. The first seal may be a **certification signature** with `/DocMDP P=2`
(form filling and signing allowed), so later approval signatures do not invalidate it.

**Option: per-signer keys** (slice 18, AES/QES). The signer's signature is made by their own key at a QTSP through the
CSC API. Then the document is locked once sent, signing is sequential, and the certificate of completion and audit
trail are **separate PDFs** so the signed PDF stays untouched by our additions (the same choice Documenso made [V]).

## 4. The sealing algorithm

All in `casual-sign-seal`, pure, given the document bytes, supplied time, a `KeyProvider`, a `TimestampSource` answer
and revocation answers.

1. Append an incremental update: the signature field (`/FT /Sig`) with a widget (invisible by default, or a visible
   seal stamp on the certificate page), and the signature dictionary with `/Filter /Adobe.PPKLite`,
   `/SubFilter /ETSI.CAdES.detached`, `/M`, `/Name`, `/Reason`, `/Location`, a `/ByteRange` placeholder of fixed width,
   and a `/Contents` placeholder.
2. **Size the placeholder by computation, not guess**: certificate chain length + signature size for the key type + a
   timestamp token upper bound (from a probe of the TSA, cached) + margin. If the final CMS is larger, sealing fails
   with `CS-SEAL-0003`; it never truncates.
3. Fill the ByteRange `[0, a, b, c]` covering every byte except the `/Contents` hex string, in place, keeping widths.
4. Digest the covered bytes with SHA-256 (SHA-384 and SHA-512 supported).
5. Build signed attributes; DER-encode them in DER order (`SET OF` sorted); hand **the encoded attributes** to `KeyProvider::sign`, which hashes and signs them in one FIPS-approved call (`SPK-02`: `sign_digest` is not FIPS-approved in `aws-lc-rs`). The provider returns
   the signature value and the certificate chain; it never sees the document.
6. Send the signature value's digest to the TSA; embed the token as an unsigned attribute (B-T).
7. Assemble CMS SignedData (detached), hex-encode, write into `/Contents`, zero-padded.
8. **Verify the result** with `casual-sign-verify` before returning. A seal that does not verify is an error.
9. For B-LT: collect OCSP responses (or CRLs) for every certificate in the signer and TSA chains; append a second
   incremental update with `/DSS` and `/VRI`. For B-LTA: append a document timestamp over the whole.

Supported keys: RSA 3072+ (PKCS#1 v1.5 and PSS), ECDSA P-256 and P-384. Ed25519 is not used for PDF seals until reader
support exists (`SEAL-12`).

## 5. Key custody: `keyd`

`server/casual-sign-keyd` is a small, separate process whose only job is to sign digests.

- It holds no documents, no database credentials and no network access except to its HSM or KMS.
- Callers authenticate with mTLS (or a Unix socket with peer credentials on a single node); each request names the key
  alias, the digest algorithm and the digest, and an envelope id for its own log.
- It rate-limits, logs every signature (digest, alias, caller, time) to its own append-only log, and refuses digests of
  the wrong length.
- Backends: PKCS#11 (HSMs, SoftHSM in development), AWS KMS, GCP KMS/Cloud HSM, Azure Key Vault, HashiCorp Vault
  Transit, and a **file key in development only**: `keyd` refuses to start with a file key unless
  `OPENSEAL_DEV_INSECURE_KEY=1`, and every seal made with one carries `/Reason (Development key — not for production)`.

Why separate: a compromise of the web tier must not yield the signing key, and the audit of what was signed must not
depend on the web tier's logs.

### As built (stage 2E)

`server/casual-sign-keyd`, with `server/casual-sign-secrets` (copied from OpenCalc). Every key implements the engine's
`KeyProvider` and keyd's `DigestSigner` (sign a digest the caller computed over the CMS signed attributes, so no
document byte or signed attribute reaches keyd).

- **PKCS#11** through `cryptoki`'s safe API: the private key is found by `CKA_LABEL` and/or `CKA_ID` and must be unique;
  the chain is configured, or the signer certificate is read from the token (the `CKO_CERTIFICATE` with the key's
  `CKA_ID`). ECDSA P-256/P-384 with `CKM_ECDSA` (raw `r || s` re-encoded as DER), RSA 3072 to 8192 bits with
  `CKM_RSA_PKCS` over a `DigestInfo` or `CKM_RSA_PKCS_PSS` (hash, MGF1 with the same hash, salt of the digest length).
  The PIN comes from `OPENSEAL_KEYD_PKCS11_PIN` or `_PIN_FILE` (never both) as a `Secret` whose `Debug` is redacted. One
  session per key; a failed operation reopens it and logs in once.
- **Before any key is served, a probe signature is verified** against the certificate's public key with aws-lc-rs, so a
  key that is not its certificate's is refused at start (`CS-KEY-0006`), not per seal.
- **File key, development only**: refused unless `OPENSEAL_DEV_INSECURE_KEY=1` exactly (`CS-KEY-0004`). keyd reports
  it as a development key on get-certificate-chain, so the caller writes `/Reason (Development key — not for
  production)`.
- **The daemon**: rustls, TLS 1.3 only, a client certificate is mandatory and must chain to the configured client CA;
  the caller is then identified by the SHA-256 fingerprint of its certificate, which must be on the allow-list
  (`CS-KEY-0001`, recorded). Operations: get-certificate-chain and sign-digest, in length-prefixed binary frames
  with every field bounded (frame 1 MiB, identifiers `[A-Za-z0-9._-]{1,64}`, digest 64 bytes); a digest of the wrong
  length or for another algorithm is refused (`CS-KEY-0007`). Per-caller rate limit (default 600 signatures a
  minute, `CS-KEY-0008`), at most 64 connections, 30 s timeouts. Configured by `OPENSEAL_KEYD_*` variables (the
  binary's documentation lists them).
- **Operation log**: one tab-separated line per request (sequence, time, caller fingerprint, operation, alias,
  algorithm, digest, envelope id, outcome), hash-chained with SHA-256, opened for append only and synced before a
  signature is released; a write failure releases nothing (`CS-KEY-0009`); keyd refuses to start on a log whose chain
  does not verify.
- **`RemoteKey`**: the caller's `KeyProvider` over keyd (one mTLS connection per signature, envelope id attached).
- **Admin interface** (`CON-06`, [23](23-ORGANIZATIONS-WORKSPACES-AND-CONSOLE.md) §5.4): a second allow-list
  (`OPENSEAL_KEYD_ADMIN_ALLOW_LIST`, disjoint from the signing one) is answered only `list-keys` (alias, backend,
  algorithm, chain, the signer certificate's validity, subject and issuer), `oplog-head`, `oplog-range` (at most 256
  records) and `health` (each key's backend state; for PKCS#11 an open session), never a chain to sign with or a
  signature; a signing caller is refused them. Both refusals are `CS-CON-0008` and recorded. The wire format and
  client live in `casual-sign-keyd-client`, without `cryptoki`.

Checked: keys generated in SoftHSM 2.7 (P-256 with its certificate in the token, P-384, RSA-3072 PKCS#1 v1.5 and PSS)
seal a PDF at B-B in process and through keyd; all eight pass our verifier (integrity, signature and chain;
`TRY_LATER` for revocation at B-B) and pyHanko (`intact, valid, trusted`, whole file). A file key sealed through
keyd passes both too. A client without a certificate, with a certificate from another CA, and with one not on the
allow-list are refused. Not yet built: cloud KMS backends (AWS KMS, GCP KMS, Azure Key Vault, Vault Transit), a Unix
socket transport with peer credentials, several keys per daemon from a configuration file, and the reconciliation of
keyd's log with `document.sealed` (`SEC-S05`).

## 6. Timestamps

`TimestampSource` is a list of TSAs with failover. Requests carry a nonce and `certReq=true`; the response is checked
(status, nonce, message imprint, TSA certificate chain against the trust store, ESSCertIDv2 per RFC 5816) before
embedding. Free public TSAs are allowed for evaluation and flagged in the admin console as not production-grade.
The worker's list is the enabled rows of `platform.tsa_endpoints`, changed in the console by two key custodians
and read at most once a minute (`CON-07`, [23](23-ORGANIZATIONS-WORKSPACES-AND-CONSOLE.md) §5.6), else
`OPENSEAL_TSA_URLS`; each database URL's addresses pass the `SEC-W01` policy before every request.

## 7. Verification

`casual-sign-verify` verifies **any** signed PDF, ours or not, and is the same code in the server, the WASM verify page
and the CLI.

For each signature: the ByteRange covers the whole file except `/Contents`, with no gaps or overlaps; the digest
matches; the CMS signature verifies against the signer certificate; the signed attributes are present and consistent;
the certificate chain builds to a supplied trust anchor at the signing time (timestamp time when present) with key
usage and policy checks; revocation from the DSS or from supplied answers; the timestamp token verifies; and **every
later revision is classified** (DSS addition, document timestamp, form fill permitted by DocMDP, annotation, or
disallowed change). The verdict is structured: per signature `valid`, `invalid` (why), or `indeterminate` (why: no
trust anchor, no revocation data, unsupported algorithm), in the vocabulary of ETSI EN 319 102-1.

### As built (stage 1G)

`seal(input, &SealRequest, &dyn KeyProvider, &dyn TimestampSource, &dyn RevocationSource)`, `augment` (B-T to B-LT or
B-LTA later) and `renew_lta`. The placeholder is `max_der_len` plus 64 bytes, retried once with the measured size;
ByteRange is a fixed-width placeholder filled in place. Certification adds `/Reference` with a DocMDP transform and
`/Perms /DocMDP`. Invisible widgets carry no appearance stream (a zero-size Rect needs none), which keeps P=1 documents
able to take B-LTA. `/VRI` keys are the upper-case hex SHA-1 of the whole decoded `/Contents`, as PAdES defines (an
identifier only). Revocation: OCSP first (RFC 6960 request with a SHA-256 CertID), then CRL; responder certificates and
missing issuers go into `/Certs`. Every output is verified by `casual-sign-verify` before it is returned. Checked: ours,
pyHanko (LTV from the DSS alone, hard-fail) and EU DSS agree on 19 fixtures and on 30 corpus PDFs sealed at B-LT.

### As built (stage 1H)

Verdicts follow ETSI EN 319 102-1: `TOTAL_PASSED`; `TOTAL_FAILED` with `HASH_FAILURE`, `FORMAT_FAILURE` (a malformed
ByteRange, or an unreadable CMS under `ETSI.CAdES.detached`) or OpenSeal's `DISALLOWED_MODIFICATION` (`CS-VER-0007`, a
revision after the signature that the whitelist refuses); `INDETERMINATE` with `NO_CERTIFICATE_CHAIN_FOUND`,
`REVOKED_NO_POE` (revoked before the best signature time), `OUT_OF_BOUNDS_NO_POE` (expired), `TRY_LATER` (no
revocation data), `SIG_CONSTRAINTS_FAILURE` (invalid signature timestamp), `CRYPTO_CONSTRAINTS_FAILURE` (SHA-1) or
`FORMAT_FAILURE` (legacy or BER CMS under `adbe.pkcs7.detached`, `SEAL-13`). A document timestamp is proof of existence
once its cryptography and chain pass. No DocMDP behaves as P=3; `/Info` and XMP changes are always allowed.

**EU DSS's default policy does not fail modifications.** On the shadow and incremental-saving fixtures it says
`TOTAL_PASSED` while counting the changes as "undefined changes", and it does not flag DocMDP violations. Rung 3 is
therefore read with that column: `tools/verify-sealed.py` already requires 0 undefined changes for a pass.

### Verification ladder

A seal is "verified" only when every rung below passes. **Our verifier alone is never enough** (rule 26 in
[04](04-MISTAKES-AND-RULES.md)).

| Rung | Validator | Where it runs |
| --- | --- | --- |
| 1 | `casual-sign-verify` | Every test, every seal in production |
| 2 | pyHanko (MIT) `validate` with the test trust root | CI, over `fixtures/sealed` |
| 3 | EU DSS 6.5.1 (LGPL, our own small validator in a container built from `tools/eu-dss/`, run with no network): signature intact and valid, PAdES baseline level detected, no undefined changes after signing; `TOTAL_PASSED` once the test PKI supplies revocation data (`F-008`); until then a seal is `INDETERMINATE` (`CERTIFICATE_CHAIN_GENERAL_FAILURE`) offline | CI, over `fixtures/sealed` |
| 4 | Adobe Acrobat Reader shows the signature valid with the test root trusted | Release gate `PV-01`, by hand or in a Windows CI container, never on the owner's desktop |
| 5 | ETSI TS 119 144-4 conformance checks for the claimed baseline level | Release gate |

## 8. Algorithms and crate choices

ADR-006 settles this, confirmed by `SPK-02` ([66](66-SPK-02-CRYPTO-STACK.md)): **`aws-lc-rs`** (ISC, Apache-2.0, MIT,
BSD-3-Clause, all allowed) for private-key operations, hashing and RSA verification in hosts; non-FIPS it builds with
only a C compiler (about 13 s on an M4). **RustCrypto**, the `der` 0.8 generation (`der`, `spki`, `x509-cert`,
`cms =0.3.0-rc.2`, `x509-tsp =0.2.0-rc.0`, `x509-ocsp =0.3.0-rc.1`, `sha2`, `p256`, `p384`), for structures and for
the WASM verifier, which builds at 330 KB (ECDSA) or 424 KB (with RSA) and has no imports; `aws-lc-rs` cannot compile
for `wasm32` and is never in that build. The release candidates are pinned exactly until stable (`DEP-03`). `rsa` is
used **only for verification in WASM**. RUSTSEC-2023-0071 (Marvin) is a timing attack on private-key operations we never
perform; the advisory database of 2026-11-10 lists it as patched in `rsa` 0.10.0, so no ignore entry is needed (`DEP-02`). `cryptographic-message-syntax` (MPL-2.0) is not used.

Rules the spike found:

- **Hash signed attributes exactly as received.** `der` re-sorts `SET OF` on decoding; a verifier that re-encodes would
  reject a signer who wrote them out of order, where pyHanko accepts.
- **ESS `signing-certificate-v2`** is our own type (RustCrypto has none); `hashAlgorithm` is omitted for SHA-256, as DER
  requires for a DEFAULT.
- `/Contents` is zero-padded after the CMS: decode exactly one TLV.
- The verifier reads DER; BER from other signers needs a decision before stage 1H (`SEAL-13`).
- Stage 1F (as built): every signed structure (signed attributes, OCSP `tbsResponseData`, CRL `tbsCertList`, a
  delegated responder's certificate, the certificates ESS hashes) is verified over its bytes **as received**; CMS,
  timestamp and OCSP inputs are capped at 1 MiB and CRLs at 32 MiB (docs/21); RSA keys of 2,048 to 8,192 bits are
  accepted for verification. **SHA-1 is never used**, which refuses ESSCertID v1 timestamps and SHA-1 OCSP CertIDs that
  many real TSAs and responders still produce: `SEAL-14` decides.
- **FIPS** (`aws-lc-fips-sys`) needs CMake and Go to build and carries the OpenSSL licence, which `deny.toml` does not
  allow: a separate build profile, decided by `DEC-14`.

## 9. Failure modes

| Failure | Behaviour |
| --- | --- |
| TSA down | Next TSA; if all fail, the job retries with backoff; the envelope stays `completing`; an alert fires after a threshold. Never seal without the account's profile |
| OCSP unavailable for B-LT | Fall back to CRL; if neither, seal at B-T and schedule the LT augmentation; the envelope completes with `seal.level = B-T` recorded and the augmentation recorded later |
| HSM unavailable | Retry; alert; no fallback to a different key |
| Placeholder overflow | `CS-SEAL-0003`; resize from the measured size and retry once |
| Verification of our own output fails | `CS-SEAL-0010`; P0 incident; the envelope stays `completing` |
