# 07 — Security threat model

**Every upload is hostile, every party is a potential adversary of the record, and the operator is trusted only as far
as the evidence can be checked without them.** Every threat has a control and a named test. A limit without a test seen
to fail is not a control. Status: **Planned** (where it lands), **Designed** (control specified in a design note, nothing built), **Partial**, **Tested** (test seen red without the fix).
The PDF, field and cryptographic rows built in Phase 1 are Tested or Partial; the account, ceremony and webhook rows
built in Phase 2 are tested with each control seen red (§Phase 2 threat tests); abuse rows are Planned.

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
| SEC-P01 | Decompression bomb in a stream (Flate, LZW, chained filters) | Per-stream and per-document inflate caps and ratio caps; inflate is streamed and stops at the cap (`CS-PDF-0003`) ; **Built (stage 1A; LZW added with the same sink): per-stream 256 MiB, per-document 1 GiB, ratio 1 MiB + 1000× encoded, streamed `miniz_oxide`; `lzw_bomb` fixture; peak 384 MiB on every bomb fixture; budget and ratio guards seen red when removed** | Tested |
| SEC-P02 | Object count, xref size or `/Size` sized allocation | No allocation from a file number; caps on objects and xref entries (`CS-PDF-0002`) ; **Built (stage 1A): nothing allocated from `/Size`; object and xref-entry caps; `many_objects` peaks at 46 MB (lopdf: 485 MiB); guard seen red** | Tested |
| SEC-P03 | Deep nesting of arrays and dictionaries; reference cycles | Depth cap; cycle detection on resolution (`CS-PDF-0004`) ; **Built (stage 1A): depth 256 (ceiling 4,096), reference depth 64, cycle detection; guard seen red** | Tested |
| SEC-P04 | `/Prev` loops and thousands of revisions | Visited set; revision cap ; **Built (stage 1A): visited set and revision cap; guard seen red** | Tested |
| SEC-P05 | Page tree cycles, huge page count | Visited set; page cap ; **Built (stage 1A): iterative walk, visited set, page cap; guard seen red by the worker and again by the main session** | Tested |
| SEC-P06 | JavaScript, `/OpenAction`, `/AA`, `/Launch`, `/SubmitForm`, `/ImportData`, `/GoToR`, `/GoToE` | Never executed; removed on normalization; pdf.js with scripting disabled; reported ; **normalizer removes every kind, each tested from a fixture and a hand-built file and seen red with its guard off (stage 1B)** | Tested |
| SEC-P07 | External references: remote fonts, external streams, URI on open | Never fetched; removed; reported ; **external references and external stream data removed or emptied, tested from fixtures (stage 1B)** | Tested |
| SEC-P08 | Embedded files and RichMedia (malware carriers) | Removed by default; if kept, admitted as attachments and never opened ; **embedded files, FileAttachment, RichMedia and 3D removed, tested from fixtures (stage 1B)**; **kept as attachments when asked (`NORM-02`): at most 64 extracted within the decode budget, each admitted and normalized on its own (a non-PDF one refused), never recursively, written under names of our own** | Tested |
| SEC-P09 | Images used for signatures or stamps: decompression bombs, malformed PNG/JPEG | Dimension and pixel caps before decode; decode in a bounded decoder; re-encode ; **built (stage 1E): size, side and point limits, decode then re-encode, metadata stripped; each bound seen red when removed** | Tested |
| SEC-P16 | Encrypted input: password guessing, passwords leaking into logs or reports, decryption used to amplify work, encrypted output | Passwords only from the host, at most 16, wiped on drop, `Debug` shows only a count; no guessing; decryption charged to the document budget; normalized output never encrypted; wrong password, encrypted bomb, malformed `/Encrypt` and unknown handler fixtures; password check and decryption budget seen red when removed (reader completion, re-run by the main session) | Tested |
| SEC-P10 | Slow parse within size budget | Host-supplied cancellation predicate checked in loops (sisters' `SEC-P10` pattern) ; **Built (stage 1A): host predicate checked in loops; guard seen red** | Tested |
| SEC-P15 | Pathological files (thousands of headers or `trailer` keywords each followed by an unterminated string) make parsing quadratic in time | Memory stays bounded; the cancellation predicate is checked between objects and trailers; the host time budget is the control; 10-minute fuzz runs at `-timeout=10` found no slow unit (stage 1A). `PDF-PERF-01` measures the worst case | Partial |
| SEC-P11 | Parser differential: what we parse differs from what readers render, so a sender shows one thing and the PDF says another | Normalization rewrites a fresh, unambiguous file before delivery; signers see pdf.js rendering of exactly the delivered bytes; fixtures of known differentials (duplicate object numbers, xref vs scanned objects) ; **normalization rewrites a fresh file and recomputes the page tree; pyHanko strict agrees on every output; a /Count mismatch was found and fixed this way (stage 1B)** | Tested |
| SEC-P12 | Polyglot files (PDF + ZIP/HTML/JS) | Normalized output is a fresh file (built, stage 1B); served with `Content-Type: application/pdf`, `Content-Disposition: attachment` unless viewed inline in pdf.js, and `X-Content-Type-Options: nosniff` (server, Phase 2) | Partial |
| SEC-P13 | Malicious Office upload exploiting the converter | Converter runs in a separate container: no network, read-only root, seccomp, CPU and memory limits, time limit, a fresh instance per job | Planned slice 6 |
| SEC-P14 | Fonts embedded in the PDF exploiting the viewer | pdf.js in a worker on our origin; we do not parse embedded fonts beyond widths and ToUnicode ; text extraction parses only widths, `/W` and ToUnicode CMaps, bounded (stage 1C) | Partial |

## Signatures and evidence (`SEC-S*`)

| ID | Threat | Control | Status |
| --- | --- | --- | --- |
| SEC-S01 | Shadow attacks (hide, replace, hide-and-replace) after sealing | Verifier classifies every revision against a whitelist of allowed changes (DSS, document timestamp, form fill and annotations as DocMDP permits); five shadow fixtures and an incremental-saving fixture all fail with `DISALLOWED_MODIFICATION`; pyHanko agrees; EU DSS's default policy passes them with "undefined changes" counted; default deny seen red when removed (stage 1H, re-run by the main session) | Tested |
| SEC-S02 | Incremental saving attack; signature wrapping; universal signature forgery (empty or malformed ByteRange, `/Contents` tricks) | ByteRange must start at 0, cover to its revision's end and exclude exactly `/Contents`; strict CMS parsing; fixtures for a non-zero start, a gap and a flipped byte in each range; each check seen red when removed (stage 1H) | Tested |
| SEC-S03 | Signer sees content different from what is sealed (overlay tricks, optional content, annotations hidden at render) | WYSIWYS: signers review the engine's flattened output; optional content groups flattened to their default state and reported; annotations flattened or removed ; field values are flattened from the engine and checked by PDFium (stage 1E); optional content and non-widget annotations are not flattened yet (`FLT-03`) | Partial: the flattening half is built (2026-11-11, `FLT-03`: optional content to its default state, annotations drawn or removed as seen on screen, tests seen red; gaps `FLT-06`, `FLT-07`, `FLT-09`); signers reviewing the flattened output (ADR-020) comes with the signing UI, slice 1 |
| SEC-S04 | Platform key theft from the web tier | Key only in `keyd` and its HSM/KMS; the web tier has no key material; file keys refused outside development | Built 2E (2026-11-11): keys only in keyd behind PKCS#11; file keys need `OPENSEAL_DEV_INSECURE_KEY=1` (`CS-KEY-0004`, test seen red); SoftHSM gate |
| SEC-S05 | Misuse of the platform key (signing arbitrary digests) | `keyd` authenticates callers, logs every digest with envelope id, rate-limits; worker requests are tied to `completing` envelopes; reconciliation job compares `keyd`'s log with `document.sealed` events | Partly built 2E: mTLS with client allow-list (test seen red), per-caller rate limit, hash-chained operation log synced before release. Not yet: refusing envelopes not `completing` (`KEYD-02`), reconciliation (`KEYD-03`) |
| SEC-S06 | Backdating | Trusted time from RFC 3161 TSA on every seal; server time only as a claim; anchoring of chain heads ; RFC 3161 time on every B-T and later seal (stage 1G) | Partial (anchoring is slice 7) |
| SEC-S07 | Evidence rewrite by an insider | Hash chain; chain head inside the sealed PDF every party received; append-only DB grants and trigger; optional public anchoring ; **chain, verifier, Merkle proofs and the certificate printing the head built (stage 1I); every random single tampering detected** | Partial (database grants and public anchoring wait for Phase 2 and slice 7); **append-only grants and trigger built (stage 2B)**: UPDATE, DELETE and TRUNCATE refused for owner and app role, chain links checked in the database; seen red |
| SEC-S08 | Weak algorithms | SHA-256+ only, SHA-1 never (identifiers included, pending `SEAL-14`); RSA ≥ 3072 or ECDSA P-256/P-384 for new seals; RSA 2,048–8,192 bits accepted for verification | Partial: verification side built in stage 1F; sealing side in 1G |
| SEC-S09 | Timestamp response forgery or replay | Nonce, imprint, TSA signature, ESSCertIDv2 and critical timeStamping EKU checked before embedding (`casual-sign-crypto`); nonce and imprint checks seen red when removed (stage 1F). **Left:** a guard test for the EKU check; chain to the TSA's trust anchor in stage 1H | Partial |
| SEC-S10 | Malformed DER in CMS, timestamps, OCSP or CRLs crashes or fools the verifier | Bounded DER parsing; signed bytes verified as received, never re-encoded; 10,000 deterministic mutations over every fixture with no panic (stage 1F); digest, signature, ESS, nonce, imprint, OCSP and CRL status and validity checks each seen red when removed (worker; digest re-run by the main session) | Tested |
| SEC-S11 | Revocation answered by an unauthorized responder | OCSP accepted only from the issuer or a delegate with the OCSPSigning EKU signed by the issuer and valid at producedAt; CRL issuer, cRLSign, signature and period checked; unauthorized responder test seen red when removed (stage 1F) | Tested |

## Accounts, ceremony and API (`SEC-A*`)

| ID | Threat | Control | Status |
| --- | --- | --- | --- |
| SEC-A01 | Invitation link forwarded, leaked or guessed | 256-bit random tokens stored hashed; one recipient; expiring; revocable; optional extra authentication; first use binds a browser session; links in reminders are new tokens | Partial, tested and seen red 2026-11-12 (`P2-THREATS`, §Phase 2 threat tests): hashed at rest, one recipient, expiring, revoked on void, correction, reassignment and lock, bound to the first browser, limited per link and per address. Not checked: reminder links being new tokens; optional extra authentication beyond the access code (slice 5) |
| SEC-A02 | OTP brute force | 6+ digits, 5 attempts, lockout with sender notification, per-token and per-IP rate limits, OTP valid 10 minutes | Partial, tested and seen red 2026-11-12 (`P2-THREATS`): **email one-time code built** (`email_otp`, `POST /s/{token}/otp` and `/otp/verify`): 6 digits drawn uniformly by the worker, only the Argon2id hash stored (`recipient_otp_codes`, migration 0012), at most one open code, 10 minutes, spent on a pass; 3 requests a minute per link and per address, 30 s between codes and 5 an hour per recipient; failures counted by the engine to the account's lockout (as A03), which locks and revokes the link, and 5 wrong tries spend a code; challenged, failed and passed in the chain. `casual-sign-worker` `tests/email_otp.rs` on PostgreSQL 17 shows expiry, supersession, replay of a used code refused, five wrong codes then the link revoked, and the code absent from the chain, jobs, job steps and every TRACE log line; with the spend-on-pass removed it failed `left: 200 right: 403` at the replay. Not built: SMS and voice codes (slice 5); sender notification on lock untested (as A03) |
| SEC-A03 | Access code brute force | Same as A02; codes stored with Argon2id | Partial, tested and seen red 2026-11-12: Argon2id at rest; the account's attempts (default 3) lock the recipient and revoke the link, so the right code then fails; each failure is an audit event. Not tested: the sender notification effect |
| SEC-A04 | Cross-tenant access (IDOR) | Tenancy-scoped repository; RLS; generated cross-tenant tests for every endpoint | Built and tested, seen red 2026-11-12: repository scoping and RLS (stage 2B); every id-bearing operation of `api/openapi.yaml` (53 of 89; the 17 ceremony operations are reached by token, A01) refused across accounts, generated, with RLS on and off; one repository query unscoped turned the RLS-off run red (200 with the other account's webhook) while RLS alone held |
| SEC-A05 | Privilege escalation in an account | Permission checks per endpoint from the OpenAPI document's `x-permission`; deny-by-default; tests per profile | Built and tested, seen red 2026-11-12: one guard per route from the table the OpenAPI document is checked against; a generated test calls every scoped route with a key holding every scope but its own (`403 CS-AUTH-0006`); profile tests (a sender cannot administer or mint wider keys) |
| SEC-A06 | Session theft; CSRF; clickjacking | Secure cookies; CSRF tokens; `frame-ancestors` per account; CSP strict with nonces | Partial, tested and seen red 2026-11-12: `HttpOnly`, `Secure`, `SameSite=Lax` staff cookie and `SameSite=Strict` ceremony cookie; CSRF token on every changing session request; CSP `default-src 'none'; frame-ancestors 'none'`, `X-Frame-Options: DENY`, `nosniff`, `no-referrer`, HSTS, `no-store` on every kind of response; JSON bodies over 1 MiB refused. Not built: per-account `frame-ancestors` for embedding (slice 9) |
| SEC-A07 | XSS through names, messages, field values, filenames | `textContent` only; no HTML from users anywhere, including emails (plain text plus a fixed template with escaped values) | Built and tested, seen red 2026-11-12 (`P2-THREATS`): `webapp/e2e/xss.spec.mjs` (chromium and mobile; mock mode, and real-stack mode with `OPENSEAL_E2E_BASE_URL`) puts `<img src=x onerror=…>`, `"><svg/onload=…>` and `javascript:` URLs in envelope subjects, messages and document names, recipient names and an email, field labels, template names, subjects and roles, a member, an API client and account settings, then visits home, agreements, envelope detail, all four prepare steps, templates (list, detail, editor), admin (users, API, account), the signer page and its review, and verify, asserting `window.__xss` unset, no dialog, no `on*` attribute or `javascript:` URL, and the payload shown as text. With `home.js`'s recent-list subject set by `innerHTML` it failed `home: a payload became markup`. Emails are plain text from a fixed template with B-encoded headers (SEC-M02). Not run here: real-stack mode (no local stack), and verify's file-name assertion until the browser verifier is built |
| SEC-A08 | Embedded view token misuse | Single-use, 5-minute URLs bound to recipient and host client; `auth.asserted_by_host` recorded as such | Partial, tested and seen red 2026-11-12: the view URL lives 5 minutes, only the creating API client may ask (`CS-AUTH-0010`), it binds to the first browser that opens it (A01); `auth.asserted_by_host` recorded. Not built: `prepare` and `correct` views (slice 9) |
| SEC-A09 | Credential stuffing on staff login | SSO preferred; WebAuthn and TOTP; rate limits; breached-password check (k-anonymity, optional) | Partial, tested and seen red 2026-11-12: sign-in limited per login name and per client address, API calls per principal; an unknown email costs a wrong password's time (not tested). Not built: SSO, WebAuthn, TOTP, breached-password check |
| SEC-A10 | API key leakage | Prefixed keys for secret scanning, hashed at rest, scoped, expiring, last-used shown | Built and tested, seen red 2026-11-12: `osk_` prefix, stored only as SHA-256 (a search of every table for the clear key, client secret, link and ceremony cookie), scoped (A05), expiring, revocable; access tokens expire and die with their client. Not checked: last-used shown |
## Field input (`SEC-F*`)

| ID | Threat | Control | Status |
| --- | --- | --- | --- |
| SEC-F01 | A sender's validation regex causes catastrophic backtracking (ReDoS) when a signer types, on the server or in the browser | `regex` crate (finite automata, linear time); pattern length, nesting, compiled size and DFA cache bounded (docs/21); `(a+)+$` over 4,000 characters completes within the test bound; size and length guards seen red when removed | Tested |
| SEC-F02 | Formula bombs: huge, deep or self-referencing formulas | Length refused before lexing, depth, reference count, cycle detection without recursion (3,000-field chain tested); property tests of random formulas never panic; length and depth guards seen red when removed (stage 1D, re-run by the main session) | Tested |
| SEC-F03 | A client submits values or formula results different from the server's | `evaluate_envelope` re-runs every rule on the server; `check_client` reports `CS-FLD-0022`; locked and read-only fields keep the sender's value | Tested |

## Abuse and outbound (`SEC-W*`, `SEC-L*`, `SEC-M*`)

| ID | Threat | Control | Status |
| --- | --- | --- | --- |
| SEC-W01 | SSRF through webhook URLs, URL import, IdP metadata URLs | Public HTTPS only; refuse private, loopback, link-local, metadata ranges at registration and after DNS resolution at connect; no redirects to such ranges; egress proxy option | Partial, tested and seen red 2026-11-12: webhook URLs checked at registration and every address checked again at connect (worker integration test red with the policy removed). Not built: URL import, IdP metadata URLs, egress proxy option |
| SEC-W02 | Webhook spoofing to integrators | Standard Webhooks HMAC with timestamps; secret rotation | Partial, tested and seen red 2026-11-12: Standard Webhooks HMAC over `id.timestamp.body`, checked against the specification's example; the header on every delivery. Not tested: several secrets during rotation |
| SEC-L01 | Signing links used for spam or resource exhaustion | Email verification by default; per-link and per-IP limits; usage caps; CAPTCHA option | Planned slice 11 |
| SEC-M01 | Platform used for phishing (our domain sending lures) | Sender verification for new accounts; outbound rate limits; content of emails fixed by template; abuse reporting link in every email; DKIM/SPF/DMARC | Planned 2D |
| SEC-M02 | Email header injection | Names and subjects validated; no CR/LF; library-built messages | Planned 2D |

## Phase 2 threat tests (`SEC-A*`, `SEC-W*`; `P2-THREATS`)

docs/06 Phase 2 exit item 4 names `SEC-A*`, `SEC-T*` and `SEC-W*`; this document has no `SEC-T*` rows. Each control
below was removed or weakened once on 2026-11-12, its test run against PostgreSQL 17 and seen to fail with the message
shown, then restored. Server tests are in `server/casual-sign-server/tests/`, worker tests in
`server/casual-sign-worker/`.

| Threat | Control removed | Test | Seen red |
| --- | --- | --- | --- |
| A01 | Per-link ceremony limit raised 1000× | `threats.rs::ceremony_calls_are_limited_per_link_and_per_client_address` | `left: (401, "CS-AUTH-0002")` `right: (429, "CS-API-0003")` |
| A01 | Per-address ceremony limit raised 1000× | same | `an address guessing links is limited (0)` |
| A01 | Browser binding (`CS-AUTH-0009`) skipped | `contract.rs::every_operation_and_a_two_signer_envelope_to_its_seal_job` | `left: (200, "")` `right: (403, "CS-AUTH-0009")` |
| A01 | `revoked_at IS NULL` dropped from the token resolver | `threats.rs::a_voided_envelopes_link_opens_nothing`; `correct.rs::a_sent_envelope_is_corrected_and_changed_links_are_reissued` | `left: (200, "")` `right: (401, "CS-AUTH-0002")`; `the old link is revoked` |
| A01, A08 | `expires_at > now` dropped from the token resolver | `auth.rs::only_the_creating_client_opens_an_embedded_signing_view` | `left: (200, "")` `right: (401, "CS-AUTH-0002")` |
| A01, A10 | An API key written in clear (as the client's name) | `threats.rs::keys_secrets_and_signing_links_are_stored_only_as_hashes` | `API key in clear in api_clients` `left: 1` `right: 0` |
| A03 | Engine lock threshold made unreachable | `threats.rs::an_access_code_locks_after_the_accounts_attempts_even_for_the_right_code` | `left: (200, "")` `right: (401, "CS-AUTH-0002")` |
| A04 | `account_id = $1` dropped from the webhook `get` query | `isolation.rs::another_accounts_ids_are_not_found_without_rls` (the RLS-on run stayed green) | `GET /api/v1/webhooks/{id} as another account (Off)` `left: (200, "")` |
| A05 | Route guard checks no scope | `threats.rs::every_scoped_route_refuses_a_credential_lacking_exactly_its_scope`; `auth.rs::wrong_accounts_revoked_keys_expired_tokens_and_missing_csrf_are_refused` | `PATCH /api/v1/accounts/me needs admin:account` `left: (422, …)`; `left: (200, "")` `right: (403, "CS-AUTH-0006")` |
| A06 | CSRF check skipped | `auth.rs::wrong_accounts_…`; `threats.rs::every_kind_of_response_carries_the_security_headers_and_bodies_are_bounded` | `left: (201, "")` `right: (403, "CS-AUTH-0008")` |
| A06 | `X-Frame-Options` not set | `threats.rs::every_kind_of_response_…`; `auth.rs::every_guarded_route_refuses_a_request_without_credentials` | `no x-frame-options` |
| A06 | `Cache-Control: no-store` not set | `threats.rs::every_kind_of_response_…` | `200 JSON: no cache-control` |
| A06 | `Secure`, then `HttpOnly`, dropped from the session cookie | `auth.rs::wrong_accounts_…` | the cookie printed without the flag |
| A06 | JSON body limit raised to 4 MiB | `threats.rs::every_kind_of_response_…` | `left: (400, "CS-API-0001")` `right: (413, "CS-API-0006")` |
| A08 | Embedding owner check skipped | `auth.rs::only_the_creating_client_opens_an_embedded_signing_view` | `left: (201, "")` `right: (403, "CS-AUTH-0010")` |
| A08 | View lifetime 300 s → 3,600 s | same | `left: (200, "")` `right: (401, "CS-AUTH-0002")` |
| A09 | Per-name sign-in limit raised 1000× | `auth.rs::rate_limits_answer_429_with_retry_after` | `left: (200, "")` `right: (429, "CS-API-0003")` |
| A09 | Per-address sign-in limit raised 1000× | `threats.rs::sign_in_attempts_are_limited_per_client_address_across_names` | `left: (401, "CS-AUTH-0007")` `right: (429, "CS-API-0003")` |
| A09 | Per-principal API limit raised 1000× | `auth.rs::rate_limits_answer_429_with_retry_after` | `left: (200, "")` `right: (429, "CS-API-0003")` |
| A10 | `revoked_at IS NULL` dropped from the key resolver | `auth.rs::wrong_accounts_…` | `left: (200, "")` `right: (401, "CS-AUTH-0001")` |
| A10 | Expiry dropped from the key resolver | same | `expired key` `left: (200, "")` |
| A10 | Access-token `exp` not checked | same | `left: (200, "")` `right: (401, "CS-AUTH-0002")` |
| A10 | Revoked OAuth client's tokens accepted | same | `revoked client's token` `left: (200, "")` |
| W01 | Literal forbidden address accepted at registration | `casual-sign-server` lib `api::webhooks::tests::only_public_https_urls_register` | `called Result::unwrap_err() on an Ok value` |
| W01 | Worker address policy allows everything (both the pre-request and the connect-time check) | `flow.rs::a_webhook_to_a_private_address_is_refused` | `[("deliver_webhook", Done), …]` |
| W02 | Timestamp left out of the HMAC input | worker lib `webhook::tests::signature_matches_the_standard_webhooks_example` | `left: "v1,qpNd…"` `right: "v1,g0hM…"` |
| W02 | Signature header renamed | `flow.rs::two_signers_reach_completed_with_a_verified_seal` | `no entry found for key` |

**Timing-safe comparisons.** Session CSRF tokens, ceremony cookies and idempotency bodies are compared as SHA-256
digests with `crypto::same`, which folds over all 32 bytes; API keys, client secrets and links are found by the
digest's index lookup, never compared in clear. `same_compares_every_byte` checks the result, not the timing: no test
measures time.

**Still without a seen-red test**, so exit item 4 is not met: A02 (one-time codes, slice 5), A07 (a browser test of
hostile names, subjects and filenames), and the unbuilt or untested parts named in the rows above (per-account
`frame-ancestors`, WebAuthn and TOTP, breached-password check, reminder links as new tokens, the lock's sender
notice, several webhook secrets, URL import and IdP metadata).

## Inference and models (`SEC-I*`; ADR-029, [33](33-ML-MODELS.md))

**Designed** means the control is specified in docs/33 and nothing is built; each row moves to Tested only when its
test is seen red with the control off (`ML-01`, `ML-09`, piece M).

| ID | Threat | Control | Test | Status |
| --- | --- | --- | --- | --- |
| SEC-I01 | Hostile PDF or image exploits the rasteriser, image decoders or tokenizer (memory bug, code execution) | Rasterising only in a per-document child process of `casual-sign-modeld`, which holds no secrets (in Compose it mounts only its own `modeld-secrets` volume: its TLS chain and key, the root certificate and its allow list, never the shared `secrets` volume); the `hayro` crate forbids `unsafe` but its dependencies (`zune-jpeg`, `fearless_simd`, `pic-scale`, `bytemuck`, `vello_cpu`) use it, and its JBIG2, JPX and CCITT decoders are separate crates (`hayro-jbig2`, `hayro-jpeg2000`, `hayro-ccitt`) fuzzed on their own; Oniguruma (C, through `oar-ocr-core`'s `tokenizers` features) is always compiled in; PDFium only in the same sandbox; seccomp default profile, non-root, read-only root, `pids` and memory limits, `RLIMIT_AS` on the child | Fuzz targets `rasterise` (with JBIG2, JPX and CCITT seeds), `modeld_wire`, `modeld_tokenize`; hostile fixtures; a test that modeld's environment and filesystem hold no credentials; `tools/ml/check-modeld-isolation.py` (Compose mounts and dev-pki output) | Designed |
| SEC-I02 | Pixel or decompression bomb: huge MediaBox, 100k×100k image, JBIG2, CCITT or Flate bombs, deep Form XObject nesting | Pixel cap checked from the page box before allocation; decoded-image budget per page; per-page time enforced by killing the raster child alone; container memory cap | Fixtures `ml_mediabox_huge`, `ml_image_100k`, `ml_jbig2_bomb`, `ml_flate_image_bomb`, `ml_xobject_deep`, each refused with its code under the cap; seen red with the cap removed | Designed |
| SEC-I03 | Weights or runtime tampered with or swapped (supply chain, operator volume) | SHA-256 manifest checked at build and at start; read-only mount; signed images (`SEC-C02`); revisions pinned by commit; ONNX Runtime 1.28.x pinned by SHA-256 | modeld refuses to start with one byte flipped (seen red with the check off) | Designed |
| SEC-I04 | Malicious ONNX graph (custom ops, external-data path traversal, huge initialisers) | Only manifest files load; custom-op libraries never registered; external data refused; file size cap | A graph with an external-data reference and one with a custom domain are refused (`CS-ML-0003`) | Designed |
| SEC-I05 | Document content leaks through logs (ours or third-party: `oar-ocr` logs recognised text at debug), ONNX Runtime logs, the op log, metrics, panics or core dumps | Typed codes only; one fixed `tracing` subscriber that drops events below WARN from `oar_ocr*`, `ort`, `hayro*`, `tokenizers` and ignores `RUST_LOG` for them; ORT log level `error`; op log counts only; `ulimit -c 0`; tmpfs scratch wiped per connection | Log scrubber test runs every op **at trace level** on a fixture whose text is a marker string and asserts the marker never appears in any output stream; seen red with the filter removed | Designed |
| SEC-I06 | Cross-tenant leak through job deduplication, fingerprints, vectors or caches | Job keys carry `account_id` and `document_id`; modeld keeps nothing across connections (document handles are per connection); fingerprints and vectors read only through the account-scoped repository; RLS second line | Two accounts upload **identical bytes**: each gets its own run and suggestions; B's upload of A's template never matches | Designed |
| SEC-I07 | Derived data outlives a purge; embedding inversion | Vectors, page hashes, OCR text and spans classified as document content; deleted by the purge job (`SEC-D03`) with the document | The purge test enumerates `analysis_runs`, `suggestions`, `ocr_pages`, `template_fingerprints` and `agreement_vectors` | Designed |
| SEC-I08 | Resource exhaustion: CPU or memory starvation, upload floods, a hung render or inference | Separate process; slot count derived from memory; raster child killed alone at the per-page time; ORT run terminate at the deadline, watchdog at 2×; per-workspace OCR-page quota; page and text caps; a caller off modeld's allow list is refused before its frame is held (its length read, at most 64 KiB discarded through a 1 KiB buffer) | Watchdog test with a deliberately slow model; a page that never finishes rendering is killed without failing a concurrent job; quota test seen red; `a_refused_caller_cannot_make_modeld_allocate_a_large_buffer` (modeld unit test, seen red) | Designed (pre-admission bound built) |
| SEC-I09 | Exfiltration or download from the model process, at run time or build time | `internal: true` network, no DNS resolver; `ort` with `default-features = false` and `load-dynamic`; `oar-ocr` with `default-features = false` (no `download-binaries`, no `tls-native`) and no `auto-download`; `tokenizers` with `default-features = false` (no `http`) | modeld starts and serves with networking disabled; `cargo tree -p casual-sign-modeld -e features` asserts `download-binaries`, `tls-native`, `auto-download` and `http` are absent | Designed |
| SEC-I10 | Steered suggestions: invisible text, adversarial images or a look-alike template push a sender toward a wrong field or template | Suggestions are never applied without a person; source, badge and confidence shown; template match needs both stages; text-layer/visual mismatch (invisible text over an image) is flagged in the suggestion | Fixture with invisible "Signature ____" over a blank image yields a suggestion marked `text_source: layer, invisible` | Designed |
| SEC-I11 | Copyleft or non-commercial weights enter the bundle | Manifest licence allow list equal to `deny.toml`'s; GLiNER v0 and v1 refused by repository id; weights register (docs/09 §8) | `fetch-models.py --self-test` refuses a CC-BY-NC entry and a wrong hash | Designed |
| SEC-I12 | modeld impersonated, or traffic read | mTLS both ways with allow lists, as keyd | Wrong-client and wrong-server certificate tests (copied from keyd) | Designed |
| SEC-I13 | Suggestions mistaken for evidence | Separate tables outside the chain; the seal job never reads them | Seal and verify tests unchanged with ML on | Designed |
| SEC-I14 | The secret-holding worker links the inference stack (C++ runtime, C tokenizer, rasteriser) | Inference dependencies optional behind modeld's `server` feature; the worker depends with `default-features = false`; images build the worker with `-p` | `cargo tree -p casual-sign-worker -e normal` fails if `ort`, `oar-ocr`, `hayro`, `tokenizers` or `onig_sys` appears; seen red with the default feature on | Designed |
| SEC-I15 | An offline export runs code hidden in a pickled checkpoint | Safetensors where available; otherwise the `.bin` pinned by SHA-256 and loaded only with `torch.load(weights_only=True)`, in a sandbox with the network off | The export script refuses a `.bin` whose hash is not in the manifest | Designed |

## Data classification (`SEC-D*`)

| Class | Examples | Rules |
| --- | --- | --- |
| **Evidence** | Sealed PDFs, audit events, certificates | Immutable; retained per policy; never in logs |
| **Personal** | Names, emails, phones, IPs, user agents, signer locations (device coordinates and IP approximations, GEO-01), signature images, ID evidence | Encrypted at rest; minimized; masked in admin views where possible; never in logs (ids only); export and purge supported. A location is retained and purged exactly as the IP address it sits beside (`context.location` in the audit crate's personal members); device coordinates are rounded to about 11 m before recording, and are collected only when the envelope's `capture_location` is on and the signer agrees |
| **Secret** | Keys, OTPs, access codes, tokens, webhook secrets | Hashed or in KMS; never logged; never returned after creation |
| **Document content** | Uploaded documents, field values | Never in logs, errors or metrics; field values hashed in audit events |

| ID | Threat | Control | Status |
| --- | --- | --- | --- |
| SEC-D01 | PII or content in logs, traces, error messages | Typed errors with ids and counts only (docs/20): built in every engine crate, with tests that no message carries document text or anchor strings (stages 1C, 1F); log scrubber tests over every error code wait for the server | Partial |
| SEC-D02 | Backups leak data | Backups encrypted with separate keys; restore drill | Planned slice 20 |
| SEC-D03 | Purge leaves copies (thumbnails, caches, search index) | Every derived artefact keyed by envelope and deleted by the purge job; purge test enumerates stores | Planned slice 15 |
| SEC-D04 | A recipient learns another recipient's personal data from the signing page (history), or staff read a signer's attachment they may not see | The signer's history answers only `{seq, type, at, by}` for their own events and the envelope's milestones, never another person's name, address, IP, user agent, location or values, and only in the bound browser after authentication and consent; a staff attachment download is per object (`404` for an envelope the caller may not see or another account's), checked against the hash, and recorded as `attachment.downloaded` (`WEB-07`, `WEB-08`) | Tested (`server/casual-sign-server/tests/signer_history.rs`, `tests/lists.rs`; the history filter seen red) |

## Supply chain (`SEC-C*`)

| ID | Threat | Control | Status |
| --- | --- | --- | --- |
| SEC-C01 | Malicious or vulnerable dependency | `cargo deny` (advisories, licences, sources), lockfiles, vendored pdf.js with a recorded hash, Dependabot ; `cargo deny` and `cargo audit` run in CI and `tools/ci-local.sh` | Partial |
| SEC-C02 | Tampered release artefacts | Signed container images (cosign), SBOM (CycloneDX), SLSA provenance | Planned slice 20 |
| SEC-C03 | AGPL code contamination | Clean-room rule; DCO and attestation; review | Planned Phase 0 |
