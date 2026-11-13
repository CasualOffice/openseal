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
   incremental update with `/DSS` and `/VRI`. For B-LTA: append a document timestamp over the whole. Issuers come
   from the CMS, the revocation source and the request's trust store (anchors and intermediates): a real CA's chain
   stops below its offline root, and so does a TSA's token. A chain ends at a trust anchor or at a
   cross-certificate with an anchor's subject and key, which needs no revocation data. CRLs scoped by a critical
   Issuing Distribution Point are used for the certificates their scope covers (HRD-02).

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
| 3 | EU DSS 6.5.1 (LGPL, our own small validator in a container built from `tools/eu-dss/`, run with no network over `fixtures/sealed`; the `HRD-02` interop steps run it `--online` on the host's network, against the PKI served on 127.0.0.1): signature intact and valid, PAdES baseline level detected, no undefined changes after signing; `TOTAL_PASSED` once the test PKI supplies revocation data (`F-008`); until then a seal is `INDETERMINATE` (`CERTIFICATE_CHAIN_GENERAL_FAILURE`) offline | CI, over `fixtures/sealed` |
| 2–3, real-style PKI | `tools/interop/interop.py` (HRD-02): ours, pyHanko (fetching, `hard-fail`) and EU DSS (`--online`) over seals the CLI makes at B-T and B-LTA under an offline root, an issuing CA, a delegated OCSP responder, CRLs and an RFC 3161 TSA served on 127.0.0.1; revoked and tampered seals must fail | CI job `validators`, fresh each run, and over the committed packet `fixtures/interop` |
| 4 | Adobe Acrobat Reader shows the signature valid with the test root trusted, following `fixtures/interop/ACROBAT-CHECKLIST.md` | `HRD-03` and release gate `PV-01`, by hand or in a Windows CI container, never on the owner's desktop |
| 5 | ETSI TS 119 144-4 conformance checks for the claimed baseline level | Release gate |

### As built (HRD-02): real-style PKI and production TSA

`tools/interop/interop.py check` builds a PKI as a CA would run one: `OpenSeal Interop Root CA` (RSA-4096, offline:
it signs only the issuing CA and its own CRL), `OpenSeal Interop Issuing CA` (RSA-3072; AIA caIssuers and a CRL
distribution point pointing at the root's), and under it a delegated OCSP responder (P-256, `id-kp-OCSPSigning`,
`id-pkix-ocsp-nocheck`), a TSA (RSA-3072, critical `id-kp-timeStamping`, ESS signing-certificate-v2) and seal
certificates (P-256, RSA-3072, and one revoked for keyCompromise), each naming its OCSP responder, issuer and CRL. A
threaded HTTP server on 127.0.0.1 answers OCSP (POST and RFC 6960 GET, nonce echoed, SHA-1 to SHA-512 CertIDs),
CRLs, AIA and RFC 3161 while the run lasts. The `openseal` CLI normalizes two sample agreements and seals them at B-T
and B-LTA (approval P-256 and RSA-3072, certification P=2), fetching everything from the URLs in the certificates.
Each output must be `TOTAL_PASSED` by ours (B-LTA; B-T is `TRY_LATER` offline, as it carries no revocation data),
valid and trusted with its timestamp by pyHanko with fetching on and `revocation_mode="hard-fail"` (and B-LTA from
its DSS alone), and `TOTAL_PASSED` at the right PAdES level with every timestamp `PASSED` and revocation data found by
EU DSS fetching online. Negative controls: a B-T seal by the revoked certificate is not trusted by pyHanko and is
`INDETERMINATE/REVOKED_NO_POE` in EU DSS; the engine refuses a B-LT seal with it (`CS-SEAL-0004`, certificate
revoked); a flipped byte fails all three. Served with no revocation data, the committed packet fails every check
(seen 2026-11-14), so revocation is really checked. In CI's `validators` job and `tools/ci-local.sh`.

`interop.py packet fixtures/interop` writes the packet: six PDFs (`manifest.tsv`, `SHA256SUMS`), the root
(`trust/`, with its fingerprint), and the public PKI material (`pki/`: CA certificates, CRLs and OCSP answers
pre-signed per CertID hash, valid until 2036; no private key is kept). `interop.py verify fixtures/interop` serves
that material on 127.0.0.1:47380 and validates the packet again; `serve` does the same for Acrobat
(`ACROBAT-CHECKLIST.md`, `HRD-03`).

The run found three engine defects, each fixed with a test seen red first: B-LT failed with `CS-SEAL-0004` "issuer
not found" whenever the chain stopped below the root, as every real CA's chain and TSA token does (issuers are now
also taken from the trust store); CRLs with a critical Issuing Distribution Point, which production CAs issue, were
refused, so a chain whose OCSP fails had no revocation data (`crl_status_for` reads the scope against the
certificate, RFC 5280 §5.2.5 and §6.3.3; a CRL scoped elsewhere is `NotCovered`, never good); and a cross-certificate
of a trust anchor in a TSA token sent the walk after an issuer no one holds (the walk now ends at an anchor's subject
and key).

**Production TSA (opt-in).** `OPENSEAL_INTEROP_NETWORK=1 interop.py check --tsa-url URL --tsa-root ROOT.pem` takes
every timestamp from a public TSA, its root supplied by the operator, never taken from the token. Results on
2026-11-14: **DigiCert** (`http://timestamp.digicert.com`, root DigiCert Trusted Root G4) passes every check at B-T
and B-LTA. Its OCSP responder answers `unauthorized` to SHA-256 CertIDs, so the engine uses its CRLs (with a critical
Issuing Distribution Point), and EU DSS 6.5.1 refuses its OCSP answer for the timestamping CA ("The ResponderId
does not match the OCSP issuer certificate!") without falling back, so the run gives EU DSS `--crl-first` for a
public TSA. **FreeTSA** (`https://freetsa.org/tsr`) is refused by the engine with `CS-SEAL-0005`: its tokens name
their signer by ESSCertID v1 (SHA-1), which `SEAL-14` decides. CI uses the local TSA only.

### Rung 4 on a Windows runner (HRD-03): Adobe Acrobat Reader

The owner has no Acrobat (owner instruction 49), and Reader never runs on a desktop (rule 17 in
[04](04-MISTAKES-AND-RULES.md)), so the checklist runs on a disposable GitHub `windows-latest` runner in its own
workflow, `.github/workflows/acrobat.yml`. It is not part of `ci.yml` and never blocks `main`: it runs by hand
(Actions > acrobat > Run workflow, or `gh workflow run acrobat.yml`), every Monday, and on any push or pull request
that changes `fixtures/interop/`, `tools/interop/acrobat*` or the workflow.

What the job does, in order:

1. checks the packet against `SHA256SUMS` (checked out with `core.autocrlf false`), and runs the judge's own tests;
2. installs Adobe Acrobat Reader from Chocolatey at a pinned package version (`READER_PACKAGE_VERSION`), and
   Tesseract OCR (`TESSERACT_PACKAGE_VERSION`);
3. `tools/interop/acrobat-setup.ps1` **trusts the test root without a dialog**: it checks the root's SHA-256 against
   `trust/FINGERPRINT.txt`, imports it into the runner's `LocalMachine\Root` store, and sets Reader's documented
   preference `Security\cASPKI\cMSCAPI_DirectoryProvider\iMSStoreTrusted = 0x62` (trust the Windows store for
   signatures and certified documents; Adobe's Preference Reference, Windows Integration). Reader's own trusted-identity
   list (`addressbook.acrodata`) has no documented non-interactive import, so the root is not in that list: Reader
   trusts it through the Windows store instead, which is what an enterprise deploying a private CA does. It also sets
   the checklist's step 3 (verify on open, revocation must succeed when possible, embedded long-term data always
   used) and turns off what blocks an unattended run (first-run screens, sign-in, upsell, updater, Protected Mode,
   JavaScript);
4. `tools/interop/acrobat_driver.py` opens each packet PDF in Reader, waits for validation to finish, screenshots the
   whole screen with the banner, clicks **Signature Panel**, chooses **Expand All** from the panel's context menu,
   screenshots again, and opens **Show Signature Properties** for each signature, screenshotting each. Reader draws
   its message bar and panel without UI Automation text, so the driver reads them with Tesseract from the
   screenshots (and adds what UI Automation does expose: menus, dialogs). The B-LTA and tampered files are opened
   with nothing served, the B-T files with `interop.py serve` answering the packet's OCSP, CRL and AIA URLs on
   127.0.0.1:47380;
5. uploads the artifact **`acrobat-reader-<run id>`** (kept 90 days): every screenshot (`<file>-1-opened.png`,
   `-2-panel.png`, `-3-expanded.png`, `-4-properties-N.png`), what OCR read from each (`*.ocr.txt`), the UI
   Automation trees (`uia-*.txt`) and `acrobat-report.json`;
6. `tools/interop/acrobat_report.py` (standard library, any OS; tests in `tools/interop/test_acrobat_report.py`,
   `python3 -I -m unittest discover -s tools/interop -p 'test_*.py'`) judges the report against the checklist and
   fails the job naming each file and missing phrase: a valid file needs the banner "Signed and all signatures are
   valid" (or "Certified by" for the certification seal), "Signature is valid", "Document has not been modified
   since this signature was applied", "Signer's identity is valid" and an embedded timestamp, plus "Signature is
   LTV enabled" at B-LTA, and none of Reader's words for an invalid, unknown or altered signature; the tampered file
   needs "At least one signature is invalid" or "altered or corrupted". The verdict is also on the run's summary page.

To read a run: `gh run download <run id> -n acrobat-reader-<run id>` and open the PNGs, or
`python3 -I tools/interop/acrobat_report.py acrobat-report.json`.

**Not automated:** the checklist's last half of step 5 (stop `serve` and reopen a B-T file: "revocation could not be
checked", never "invalid"), and step 7 (clean-up: the runner is discarded). The Help > About version is taken from
the executable's file version instead.

**Result so far (run `43527032537`, 2026-11-13, Reader 26.2.22031.0 64-bit, Windows Server 2025 build 26100,
1920×1080; artifact `acrobat-reader-43527032537`): not green, so rung 4 is not yet met.** The automation works end to
end (trust import, banner, panel, expansion and Signature Properties for every file), and Reader says:

| File | Reader shows | As expected? |
| --- | --- | --- |
| `agreement-p256-bt.pdf` | "Signed and all signatures are valid."; signature valid, document not modified, signer's identity valid, embedded timestamp, not LTV enabled; trust from the Windows store | Yes |
| `agreement-rsa3072-bt.pdf` | the same | Yes |
| `agreement-p256-blta.pdf` | "At least one signature has problems."; seal and document timestamp: "Signature validity is UNKNOWN", document not modified, "valid, but revocation checks could not be made" ("Revocation checks could not be done, possibly because you are not currently connected to a network"); validated as of the secure timestamp time | **No**: Reader does not use the packet's embedded long-term material offline |
| `agreement-rsa3072-blta.pdf` | the same as `agreement-p256-blta.pdf` | **No** |
| `agreement-p256-certified-p2-blta.pdf` | "The validity of the document certification is UNKNOWN. The author could not be verified."; the same revocation finding | **No** |
| `tampered-p256-blta.pdf` | "At least one signature is invalid." | Yes |

So Reader accepts the signatures, the timestamps and the trust path, and detects tampering; it does not accept the
B-LTA files' embedded revocation data as sufficient offline, where pyHanko and EU DSS do. That is a finding against
the B-LTA output (or Reader's expectations of the DSS), to be tracked as its own row; the ladder row 4 says what it
proves only after a green run.


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
