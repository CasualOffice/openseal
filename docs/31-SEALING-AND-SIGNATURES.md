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
5. Build signed attributes; DER-encode; hand the digest of the attributes to `KeyProvider::sign`. The provider returns
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

## 6. Timestamps

`TimestampSource` is a list of TSAs with failover. Requests carry a nonce and `certReq=true`; the response is checked
(status, nonce, message imprint, TSA certificate chain against the trust store, ESSCertIDv2 per RFC 5816) before
embedding. Free public TSAs are allowed for evaluation and flagged in the admin console as not production-grade.

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

### Verification ladder

A seal is "verified" only when every rung below passes. **Our verifier alone is never enough** (rule 26 in
[04](04-MISTAKES-AND-RULES.md)).

| Rung | Validator | Where it runs |
| --- | --- | --- |
| 1 | `casual-sign-verify` | Every test, every seal in production |
| 2 | pyHanko (MIT) `validate` with the test trust root | CI, over `fixtures/sealed` |
| 3 | EU DSS (LGPL, separate container) validation report: PAdES baseline level detected and `TOTAL_PASSED` | CI, over `fixtures/sealed` |
| 4 | Adobe Acrobat Reader shows the signature valid with the test root trusted | Release gate `PV-01`, by hand or in a Windows CI container, never on the owner's desktop |
| 5 | ETSI TS 119 144-4 conformance checks for the claimed baseline level | Release gate |

## 8. Algorithms and crate choices

ADR-006 settles this: **`aws-lc-rs`** (ISC/Apache-2.0; FIPS 140-3 validated module available) for private-key
operations and hashing in hosts, and **RustCrypto** (`der`, `spki`, `x509-cert`, `cms`, `x509-tsp`, `x509-ocsp`,
`sha2`, `p256`, `p384`, `rsa` for verification only) for structures and for the WASM build, where `aws-lc-rs` does not
compile. Engine crates depend on traits; the WASM verifier uses the pure-Rust verifiers. `cryptographic-message-syntax`
(MPL-2.0) is not used. `rsa` private-key operations are never used (RUSTSEC-2023-0071, Marvin).

## 9. Failure modes

| Failure | Behaviour |
| --- | --- |
| TSA down | Next TSA; if all fail, the job retries with backoff; the envelope stays `completing`; an alert fires after a threshold. Never seal without the account's profile |
| OCSP unavailable for B-LT | Fall back to CRL; if neither, seal at B-T and schedule the LT augmentation; the envelope completes with `seal.level = B-T` recorded and the augmentation recorded later |
| HSM unavailable | Retry; alert; no fallback to a different key |
| Placeholder overflow | `CS-SEAL-0003`; resize from the measured size and retry once |
| Verification of our own output fails | `CS-SEAL-0010`; P0 incident; the envelope stays `completing` |
