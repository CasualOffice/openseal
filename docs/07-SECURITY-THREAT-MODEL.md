# 07 — Security threat model

**Every upload is hostile, every party is a potential adversary of the record, and the operator is trusted only as far
as the evidence can be checked without them.** Every threat has a control and a named test. A limit without a test seen
to fail is not a control. Status: **Planned** (where it lands), **Partial**, **Tested** (test seen red without the fix).
Nothing is built; every row is Planned.

## Adversaries

| Who | Wants |
| --- | --- |
| Outside attacker | Data, account takeover, phishing using our emails, SSRF into the operator's network, resource exhaustion |
| Malicious sender | Make a signer agree to something other than what they saw; harvest data; spam through the platform |
| Malicious signer | Repudiate ("I never signed"), alter a document after signing, sign as someone else, exhaust resources with uploads |
| Malicious counterparty holding the PDF | Alter the completed PDF and keep a "valid" appearance (shadow attacks, incremental saving attacks) |
| Another tenant | Read or change another tenant's envelopes |
| Malicious integrator | Abuse webhooks or embedded views to impersonate signers |
| Insider / compromised operator | Rewrite evidence, backdate, sign with the platform key |

## PDF input (`SEC-P*`)

| ID | Threat | Control | Status |
| --- | --- | --- | --- |
| SEC-P01 | Decompression bomb in a stream (Flate, LZW, chained filters) | Per-stream and per-document inflate caps and ratio caps; inflate is streamed and stops at the cap (`CS-PDF-0003`) | Planned 1A |
| SEC-P02 | Object count, xref size or `/Size` sized allocation | No allocation from a file number; caps on objects and xref entries (`CS-PDF-0002`) | Planned 1A |
| SEC-P03 | Deep nesting of arrays and dictionaries; reference cycles | Depth cap; cycle detection on resolution (`CS-PDF-0004`) | Planned 1A |
| SEC-P04 | `/Prev` loops and thousands of revisions | Visited set; revision cap | Planned 1A |
| SEC-P05 | Page tree cycles, huge page count | Visited set; page cap | Planned 1A |
| SEC-P06 | JavaScript, `/OpenAction`, `/AA`, `/Launch`, `/SubmitForm`, `/ImportData`, `/GoToR`, `/GoToE` | Never executed; removed on normalization; pdf.js with scripting disabled; reported | Planned 1B |
| SEC-P07 | External references: remote fonts, external streams, URI on open | Never fetched; removed; reported | Planned 1B |
| SEC-P08 | Embedded files and RichMedia (malware carriers) | Removed by default; if kept, admitted as attachments and never opened | Planned 1B |
| SEC-P09 | Images used for signatures or stamps: decompression bombs, malformed PNG/JPEG | Dimension and pixel caps before decode; decode in a bounded decoder; re-encode | Planned 1E |
| SEC-P10 | Slow parse within size budget | Host-supplied cancellation predicate checked in loops (sisters' `SEC-P10` pattern) | Planned 1A |
| SEC-P11 | Parser differential: what we parse differs from what readers render, so a sender shows one thing and the PDF says another | Normalization rewrites a fresh, unambiguous file before delivery; signers see pdf.js rendering of exactly the delivered bytes; fixtures of known differentials (duplicate object numbers, xref vs scanned objects) | Planned 1B |
| SEC-P12 | Polyglot files (PDF + ZIP/HTML/JS) | Normalized output is a fresh file; served with `Content-Type: application/pdf`, `Content-Disposition: attachment` unless viewed inline in pdf.js, and `X-Content-Type-Options: nosniff` | Planned 1B |
| SEC-P13 | Malicious Office upload exploiting the converter | Converter runs in a separate container: no network, read-only root, seccomp, CPU and memory limits, time limit, a fresh instance per job | Planned slice 6 |
| SEC-P14 | Fonts embedded in the PDF exploiting the viewer | pdf.js in a worker on our origin; we do not parse embedded fonts beyond widths and ToUnicode | Planned 1C |

## Signatures and evidence (`SEC-S*`)

| ID | Threat | Control | Status |
| --- | --- | --- | --- |
| SEC-S01 | Shadow attacks (hide, replace, hide-and-replace) after sealing | Verifier classifies every revision after a signature; any content change other than DSS or document timestamp is reported as a modification; fixtures from the published attack classes | Planned 1H |
| SEC-S02 | Incremental saving attack; signature wrapping; universal signature forgery (empty or malformed ByteRange, `/Contents` tricks) | ByteRange must start at 0, cover to EOF of its revision, exclude only `/Contents`; strict CMS parsing; fixtures | Planned 1H |
| SEC-S03 | Signer sees content different from what is sealed (overlay tricks, optional content, annotations hidden at render) | WYSIWYS: signers review the engine's flattened output; optional content groups flattened to their default state and reported; annotations flattened or removed | Planned 1E |
| SEC-S04 | Platform key theft from the web tier | Key only in `keyd` and its HSM/KMS; the web tier has no key material; file keys refused outside development | Planned 2E |
| SEC-S05 | Misuse of the platform key (signing arbitrary digests) | `keyd` authenticates callers, logs every digest with envelope id, rate-limits; worker requests are tied to `completing` envelopes; reconciliation job compares `keyd`'s log with `document.sealed` events | Planned 2E |
| SEC-S06 | Backdating | Trusted time from RFC 3161 TSA on every seal; server time only as a claim; anchoring of chain heads | Planned 1G |
| SEC-S07 | Evidence rewrite by an insider | Hash chain; chain head inside the sealed PDF every party received; append-only DB grants and trigger; optional public anchoring | Planned 1I, slice 7 |
| SEC-S08 | Weak algorithms | SHA-256+ only, SHA-1 never (identifiers included, pending `SEAL-14`); RSA ≥ 3072 or ECDSA P-256/P-384 for new seals; RSA 2,048–8,192 bits accepted for verification | Partial: verification side built in stage 1F; sealing side in 1G |
| SEC-S09 | Timestamp response forgery or replay | Nonce, imprint, TSA signature, ESSCertIDv2 and critical timeStamping EKU checked before embedding (`casual-sign-crypto`); nonce and imprint checks seen red when removed (stage 1F). **Left:** a guard test for the EKU check; chain to the TSA's trust anchor in stage 1H | Partial |

## Accounts, ceremony and API (`SEC-A*`)

| ID | Threat | Control | Status |
| --- | --- | --- | --- |
| SEC-A01 | Invitation link forwarded, leaked or guessed | 256-bit random tokens stored hashed; one recipient; expiring; revocable; optional extra authentication; first use binds a browser session; links in reminders are new tokens | Planned 2C |
| SEC-A02 | OTP brute force | 6+ digits, 5 attempts, lockout with sender notification, per-token and per-IP rate limits, OTP valid 10 minutes | Planned slice 5 |
| SEC-A03 | Access code brute force | Same as A02; codes stored with Argon2id | Planned slice 5 |
| SEC-A04 | Cross-tenant access (IDOR) | Tenancy-scoped repository; RLS; generated cross-tenant tests for every endpoint | Planned 2B |
| SEC-A05 | Privilege escalation in an account | Permission checks per endpoint from the OpenAPI document's `x-permission`; deny-by-default; tests per profile | Planned 2C |
| SEC-A06 | Session theft; CSRF; clickjacking | Secure cookies; CSRF tokens; `frame-ancestors` per account; CSP strict with nonces | Planned 2C |
| SEC-A07 | XSS through names, messages, field values, filenames | `textContent` only; no HTML from users anywhere, including emails (plain text plus a fixed template with escaped values) | Planned slice 1 |
| SEC-A08 | Embedded view token misuse | Single-use, 5-minute URLs bound to recipient and host client; `auth.asserted_by_host` recorded as such | Planned slice 9 |
| SEC-A09 | Credential stuffing on staff login | SSO preferred; WebAuthn and TOTP; rate limits; breached-password check (k-anonymity, optional) | Planned 2C |
| SEC-A10 | API key leakage | Prefixed keys for secret scanning, hashed at rest, scoped, expiring, last-used shown | Planned 2C |

| SEC-S10 | Malformed DER in CMS, timestamps, OCSP or CRLs crashes or fools the verifier | Bounded DER parsing; signed bytes verified as received, never re-encoded; 10,000 deterministic mutations over every fixture with no panic (stage 1F); digest, signature, ESS, nonce, imprint, OCSP and CRL status and validity checks each seen red when removed (worker; digest re-run by the main session) | Tested |
| SEC-S11 | Revocation answered by an unauthorized responder | OCSP accepted only from the issuer or a delegate with the OCSPSigning EKU signed by the issuer and valid at producedAt; CRL issuer, cRLSign, signature and period checked; unauthorized responder test seen red when removed (stage 1F) | Tested |

## Field input (`SEC-F*`)

| ID | Threat | Control | Status |
| --- | --- | --- | --- |
| SEC-F01 | A sender's validation regex causes catastrophic backtracking (ReDoS) when a signer types, on the server or in the browser | `regex` crate (finite automata, linear time); pattern length, nesting, compiled size and DFA cache bounded (docs/21); `(a+)+$` over 4,000 characters completes within the test bound; size and length guards seen red when removed | Tested |
| SEC-F02 | Formula bombs: huge, deep or self-referencing formulas | Length refused before lexing, depth, reference count, cycle detection without recursion (3,000-field chain tested); property tests of random formulas never panic; length and depth guards seen red when removed (stage 1D, re-run by the main session) | Tested |
| SEC-F03 | A client submits values or formula results different from the server's | `evaluate_envelope` re-runs every rule on the server; `check_client` reports `CS-FLD-0022`; locked and read-only fields keep the sender's value | Tested |

## Abuse and outbound (`SEC-W*`, `SEC-L*`, `SEC-M*`)

| ID | Threat | Control | Status |
| --- | --- | --- | --- |
| SEC-W01 | SSRF through webhook URLs, URL import, IdP metadata URLs | Public HTTPS only; refuse private, loopback, link-local, metadata ranges at registration and after DNS resolution at connect; no redirects to such ranges; egress proxy option | Planned 2D |
| SEC-W02 | Webhook spoofing to integrators | Standard Webhooks HMAC with timestamps; secret rotation | Planned slice 8 |
| SEC-L01 | Signing links used for spam or resource exhaustion | Email verification by default; per-link and per-IP limits; usage caps; CAPTCHA option | Planned slice 11 |
| SEC-M01 | Platform used for phishing (our domain sending lures) | Sender verification for new accounts; outbound rate limits; content of emails fixed by template; abuse reporting link in every email; DKIM/SPF/DMARC | Planned 2D |
| SEC-M02 | Email header injection | Names and subjects validated; no CR/LF; library-built messages | Planned 2D |

## Data classification (`SEC-D*`)

| Class | Examples | Rules |
| --- | --- | --- |
| **Evidence** | Sealed PDFs, audit events, certificates | Immutable; retained per policy; never in logs |
| **Personal** | Names, emails, phones, IPs, user agents, signature images, ID evidence | Encrypted at rest; minimized; masked in admin views where possible; never in logs (ids only); export and purge supported |
| **Secret** | Keys, OTPs, access codes, tokens, webhook secrets | Hashed or in KMS; never logged; never returned after creation |
| **Document content** | Uploaded documents, field values | Never in logs, errors or metrics; field values hashed in audit events |

| ID | Threat | Control | Status |
| --- | --- | --- | --- |
| SEC-D01 | PII or content in logs, traces, error messages | Typed errors with ids and counts only (docs/20); log scrubber tests over every error code | Planned Phase 0 |
| SEC-D02 | Backups leak data | Backups encrypted with separate keys; restore drill | Planned slice 20 |
| SEC-D03 | Purge leaves copies (thumbnails, caches, search index) | Every derived artefact keyed by envelope and deleted by the purge job; purge test enumerates stores | Planned slice 15 |

## Supply chain (`SEC-C*`)

| ID | Threat | Control | Status |
| --- | --- | --- | --- |
| SEC-C01 | Malicious or vulnerable dependency | `cargo deny` (advisories, licences, sources), lockfiles, vendored pdf.js with a recorded hash, Dependabot | Planned Phase 0 |
| SEC-C02 | Tampered release artefacts | Signed container images (cosign), SBOM (CycloneDX), SLSA provenance | Planned slice 20 |
| SEC-C03 | AGPL code contamination | Clean-room rule; DCO and attestation; review | Planned Phase 0 |
