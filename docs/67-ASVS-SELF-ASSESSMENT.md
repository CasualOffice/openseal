# 67 — OWASP ASVS 4.0.3 self-assessment

**A self-assessment, not a certification or an audit.** It states what was checked in the code at the commit that
added it, and the evidence for each requirement. It makes no claim of compliance with ASVS or anything else (docs/09,
docs/04 rule 25). The external review is `SEC-REV-01`. Tracker row: `SEC-ASVS-01` ([14](14-EXECUTION-TRACKER.md)).

## Scope and method

- **Standard.** OWASP Application Security Verification Standard 4.0.3 (October 2021), every requirement by its id.
  The requirement text is the standard's, at owasp.org/ASVS; the third column here is a short paraphrase.
- **Level.** Level 2 for the whole product (server, worker, store, web app, platform console). **Level 3** in
  addition for three high-value parts: the **ceremony** (`/s/{token}` routes, `server/casual-sign-server/src/ceremony.rs`,
  `idp.rs`, `webapp/sign.js`), **sealing** (`server/casual-sign-worker/src/seal.rs`, `tsa.rs`, `crates/casual-sign-seal`,
  `-crypto`, `-verify`) and **keyd** (`server/casual-sign-keyd`). Level-3-only requirements are assessed for those
  three parts only; their scope column says so.
- **Method.** Each requirement was checked against the code, tests and documents on `main` at 2026-11-13 by reading
  the named file or test. A test is cited only where it exists; where the threat model records a control seen red, its
  `SEC-*` id is cited. Nothing was penetration-tested and no scanner was run for this document.
- **Paths.** `-server/src/x.rs` means `server/casual-sign-server/src/x.rs`; likewise `-worker`, `-store`, `-keyd`,
  `-console`, `-modeld`, `-secrets`, `-host` under `server/`. Engine crates are under `crates/`.
- **Status.** **Met**: the control exists and the evidence was found. **Partly**: some of it exists. **Not met**:
  absent. **N/A**: the feature the requirement governs does not exist in OpenSeal (the reason is given). **Deleted**:
  withdrawn in 4.0.3 itself. Every Partly and Not met has a docs/14 row (`ASVS-*`, or an existing row).

## Summary

| Status | All | L1 | L2 only | L3 only |
| --- | --- | --- | --- | --- |
| Met | 187 | 105 | 76 | 6 |
| Partly | 50 | 12 | 30 | 8 |
| Not met | 17 | 4 | 10 | 3 |
| N/A | 24 | 7 | 15 | 2 |
| Deleted | 8 | 0 | 0 | 8 |
| Total | 286 | 128 | 131 | 27 |

The largest gaps: a second factor for tenant staff that accounts must opt into (`ASVS-01` built TOTP; `ASVS-31` makes it the default for administrators), no security event log for staff authentication and
access refusals (`ASVS-08`), production deployment hardening left to the operator (`ASVS-19`), a backup and restore drill built but not yet run (`ASVS-14`), and no anomaly alerting (`ASVS-13`). The evidence core is
strong: access control, injection, file handling, the ceremony's link binding and one-time codes, keyd's mTLS and
operation log, and the append-only hash-chained logs are met, with tests that docs/07 records as seen red.

## Findings

Each is a docs/14 row in §ASVS findings. `SEC-ASVS-01` closes when these are closed; `ASVS-02`, `ASVS-04`, `ASVS-05`, `ASVS-09`, `ASVS-11`, `ASVS-12`, `ASVS-26`, `ASVS-30` and `ASVS-34` are closed.

| Row | Sev | Requirements | What is missing |
| --- | --- | --- | --- |
| ASVS-01 | P0 | ASVS 2.2.1, 2.3.2, 2.5.6, 2.5.7, 2.6.x, 4.3.1, 1.2.4; `SEC-A09` | Staff multi-factor authentication in the tenant server: TOTP (reuse `-console/src/totp.rs` and its sealed seeds) and WebAuthn (`CON-13`), mandatory for administrators and enforceable by organization policy; one-time recovery codes (112 bits, single use, hashed); the factor is required in password reset; identity proofing before a lost factor is replaced |
| ASVS-02 (Done) | P1 | ASVS 2.1.7; `SEC-A09` | Closed 2026-11-13: every path that sets a password refuses one on a bundled list of breached passwords, offline; the optional operator lookup is `ASVS-36`. Was: Refuse breached and common passwords at set, change and reset |
| ASVS-03 | P2 | ASVS 2.1.8 | Password strength indication on the set-password screens; needs the owner's design approval before any UI change |
| ASVS-04 (Done) | P1 | ASVS 2.2.3, 2.5.5 | Closed 2026-11-13: a password set, changed or reset and a factor added each email the user one notice with no secret; `ASVS-32` notifies a factor's removal when it adds one. Was: Email the user when their password is changed, reset or set from an invitation, and when a factor is added or removed |
| ASVS-05 (Done) | P1 | ASVS 3.2.3, 3.4.4 | Closed 2026-11-13: the staff cookie is `__Host-os_session` whenever `Secure`; the ceremony cookie keeps `Path=/s/`. Was: Name the staff session cookie `__Host-os_session` whenever cookies are `Secure` (and the ceremony cookie with a `__Host-` or narrowest-path equivalent) |
| ASVS-06 | P1 | ASVS 3.3.2, 3.3.4; relates to `UXW-13` | Staff session idle timeout (account setting, default 30 minutes), a list of the user's own sessions, and ending any or all after re-entering the password |
| ASVS-07 | P1 | ASVS 3.7.1, 4.3.3 | Step-up re-authentication (password or second factor within the last 5 minutes) before creating API clients or keys, granting administrator profiles, changing webhook URLs and changing the user's email |
| ASVS-08 | P1 | ASVS 1.7.1, 1.7.2, 2.8.5, 7.1.3, 7.1.4, 7.2.1, 7.2.2, 8.3.5, 9.2.5; `SEC-D01` stays (no personal data) | Security event log: staff sign-in success and failure, logout, reset, lockout, operator TOTP rejection, rate-limit hits and every 401/403 with request id and a hashed principal; one JSON log format across server, worker, keyd and modeld; staff document downloads recorded; worker logs keyd and TSA connection failures with their code; docs/65 explains shipping logs to a remote collector |
| ASVS-09 (Done) | P1 | ASVS 4.2.2, 13.1.5, 13.2.5 | Closed 2026-11-13: `/api/v1` answers `415 CS-API-0007` to a body that is not JSON. Was: `/api/v1` refuses a request body that is not `Content-Type: application/json` (`415`), including `POST /auth/login`, closing login CSRF by a cross-site form |
| ASVS-10 | P2 | ASVS 12.3.4, 14.4.2 | `Content-Disposition` on API responses (`attachment` for JSON; `attachment` or `inline` with a server-made filename for documents and certificates) |
| ASVS-11 (Done) | P1 | ASVS 12.4.2 | Closed 2026-11-14: every upload is scanned by ClamAV's clamd in its own container before it is read or stored; malware is refused and recorded in the admin log; fail closed with an operator switch; a clean document's admission report, bound by the chain, says so. Was: Malware scanning seam for uploads: an optional scanner (ICAP or ClamAV in its own container) called before admission, its verdict recorded in the audit chain |
| ASVS-12 (Done) | P2 | ASVS 6.2.8 | Closed 2026-11-13: comparisons call `aws_lc_rs::constant_time`. Was: Replace the hand-rolled hash comparison `same` in `-server/src/crypto.rs` (and any copy in the console) with a vetted constant-time primitive (`subtle` or `aws-lc-rs`), per CLAUDE.md: cryptography is never hand-rolled |
| ASVS-13 | P1 | ASVS 8.1.4, 11.1.7, 11.1.8; `VS-20` | Detect and alert on abnormal activity: request and 429 rates per principal and address, authentication failure bursts, mass downloads, bulk voids; thresholds configurable; alerts to the operator's channel |
| ASVS-14 | P1 | ASVS 8.1.5, 8.1.6; `SEC-D02` | Backups encrypted with separate keys, with a documented and tested restore drill that verifies the audit chain, admin logs and keyd's operation log after restore |
| ASVS-15 | P1 | ASVS 1.14.2, 10.3.2, 14.1.1, 14.2.5; `SEC-C02` | Sign release images with cosign and document verification at deploy; an SBOM for the source tree and vendored web files beside the image SBOMs |
| ASVS-16 | P1 | ASVS 8.3.2, 8.3.3; `VS-15` | Self-service export and erasure requests for staff users and signers (evidence kept as retention requires, personal data otherwise removed), and an operator privacy-notice template |
| ASVS-17 | P2 | ASVS 1.8.2, 6.1.1, 6.1.2, 8.3.7 | Decide by ADR between application-level encryption of personal data at rest and operator storage encryption, and record what the operator must enable |
| ASVS-18 | P1 | ASVS 8.3.8; `SEC-D03`, `VS-15` | Retention classification and purge of personal data per account policy, derived data included |
| ASVS-19 | P1 | ASVS 1.2.2, 1.6.2, 1.9.1, 1.9.2, 1.14.1, 1.14.4, 1.14.5, 2.10.1, 9.1.1, 9.1.3, 9.2.2, 14.1.3 | Production deployment template: per-service secrets (seal key and PIN only in keyd), TLS to PostgreSQL (`sslmode=verify-full`) and the object store, the same container hardening as modeld for every service, a documented TLS edge, and a start-up refusal of an `http` public URL outside development |
| ASVS-20 | P2 | ASVS 3.1.1, 8.3.1, 13.1.3 | Record the accepted risk of the bearer token in the signing link path (`/s/{token}`, bound to the first browser, no-referrer, route template in logs) in docs/07 `SEC-A01` and an ADR |
| ASVS-21 | P2 | ASVS 2.2.4, 2.7.1 (L3 ceremony) | Phishing-resistant signer authentication option (a passkey for returning signers) as an alternative to SMS codes |
| ASVS-22 | P2 | ASVS 3.6.1 (L3 ceremony) | Recipient sign-in: send `max_age` in the OIDC request and refuse an ID token whose `auth_time` is older |
| ASVS-23 | P2 | ASVS 10.1.1, 10.2.3 to 10.2.6 (L3) | Malicious-code review for ceremony, sealing and keyd: a static scan for hard-coded credentials, time comparisons and hidden routes in CI, and a recorded manual review (feeds `SEC-REV-01`) |
| ASVS-24 | P2 | ASVS 14.1.5 (L3 sealing, keyd) | keyd and the worker log the SHA-256 of their security configuration (allow list, client CA, trust anchors, TSA list) at start and refuse a change without a restart; the operator can compare it |
| ASVS-25 | P2 | ASVS 8.3.6 | Hold passwords, one-time codes and link tokens from requests in zeroizing buffers and drop them after use |
| ASVS-26 (Done) | P1 | ASVS 7.4.3 | Closed 2026-11-13, server and console (`ASVS-34` with it). Was: A last-resort panic layer on the server answering `500` problem details with the request id (and the same in the console) |
| ASVS-27 | P2 | ASVS 1.1.3 | A security-constraint line in docs/14 rows that add a user-facing feature (who may do it, what is refused), checked when the row is written |
| ASVS-28 | P2 | ASVS 1.6.1, 1.6.3; `CON-10` covers the seal key | Key and secret rotation runbook: API token signing key (`kid` overlap via JWKS), keyd and modeld TLS identities, database and object-store credentials |
| ASVS-29 | P2 | ASVS 2.4.5 | Optional password pepper held outside the database (a secret file through `casual-sign-secrets`), with rehash on login |
| ASVS-30 (Done) | P2 | ASVS 5.2.3 | Closed 2026-11-13: the test went red without the guard and docs/07 `SEC-M02` was updated. Was: docs/07 `SEC-M02` still read Planned although `-worker/src/email.rs` refuses CR/LF and encodes headers: confirm its test goes red without the guard and update the row |
| ASVS-34 (Done) | P2 | ASVS 7.4.3 | Closed 2026-11-13 with `ASVS-26`. Was: The console's last-resort panic layer answering a `500` problem, as the server's since `ASVS-26` |
| ASVS-35 | P2 | ASVS 7.1.2, 7.4.3 | The worker's and keyd's binaries replace the default panic hook (it prints the message) with one logging the place only, as the server and console since `ASVS-26` |

Existing rows also cited: `CON-10` (seal key rotation), `CON-13` (WebAuthn), `KEYD-01` (cloud KMS), `SEAL-14`
(SHA-1 only for identifiers).

## Requirements

### V1 Architecture, Design and Threat Modeling

**V1.1 Secure Software Development Lifecycle**

| Req | L | Scope | Requirement (paraphrase) | Status | Evidence checked | Row |
| --- | --- | --- | --- | --- | --- | --- |
| 1.1.1 | 2 | All | Secure development lifecycle across all stages | Met | CLAUDE.md §The cycle (design, execute, check, fix, commit with tests); docs/05 Definition of Done; docs/15 CI gates | — |
| 1.1.2 | 2 | All | Threat modelling for every design change | Met | docs/07 (every threat has a control and a named test); CLAUDE.md "Update every document": a threat's control goes to docs/07 in the same commit | — |
| 1.1.3 | 2 | All | Security constraints in user stories | Partly | docs/01 non-functional requirements and docs/07 controls; docs/14 rows name a gate per feature, but not every feature row states a security constraint | ASVS-27 |
| 1.1.4 | 2 | All | Trust boundaries, components and data flows documented | Met | docs/02 HLD (engine, hosts, seams); docs/07 §Adversaries; docs/23 §5 (console boundary); docs/33 §1 (modeld boundary) | — |
| 1.1.5 | 2 | All | High-level architecture and remote services analysed | Met | docs/02; docs/07 threat rows per service (keyd `SEC-S04`, modeld `SEC-I*`, console `SEC-X*`, webhooks `SEC-W*`) | — |
| 1.1.6 | 2 | All | Centralised, reusable security controls | Met | One auth guard per route (`-server/src/auth.rs`, `routes.rs` access table); one tenancy-scoped repository (`-store/src/repo/mod.rs`); one error type (`-server/src/error.rs`); one secret reader (`casual-sign-secrets`) | — |
| 1.1.7 | 2 | All | Secure coding checklist available to developers | Met | CLAUDE.md §Engineering standards; docs/04 rules; `.claude/skills/openseal-pdf` | — |

**V1.2 Authentication Architecture**

| Req | L | Scope | Requirement (paraphrase) | Status | Evidence checked | Row |
| --- | --- | --- | --- | --- | --- | --- |
| 1.2.1 | 2 | All | Low-privilege OS accounts per component | Met | `deploy/Dockerfile`: `USER nonroot` (server, worker, modeld), `USER keyd`; modeld `cap_drop: [ALL]`, `no-new-privileges`, read-only root (`docker-compose.yml`) | — |
| 1.2.2 | 2 | All | Component-to-component communication authenticated | Partly | keyd and modeld: mTLS with client allow-list (`-keyd/tests/mtls.rs`); PostgreSQL and S3 by password from secret files, no TLS in the compose file | ASVS-19 |
| 1.2.3 | 2 | All | One vetted authentication mechanism | Met | Staff: Argon2id password, session cookie plus CSRF token, API keys and OAuth client credentials, all resolved in `-server/src/auth.rs`; signers: link token bound to a browser cookie (`-server/src/ceremony.rs`) | — |
| 1.2.4 | 2 | All | All authentication pathways equally strong | Partly | Login, password reset and invite acceptance share rate limits and Argon2id (`-server/src/api/admin.rs` `login_limit`); staff TOTP is required only where an account's `mfa_policy` asks for it or the user enrolled (`ASVS-01`, `-server/tests/mfa.rs`), while operators must always use TOTP (`-console/src/totp.rs`) | ASVS-01, ASVS-31 |

**V1.4 Access Control Architecture**

| Req | L | Scope | Requirement (paraphrase) | Status | Evidence checked | Row |
| --- | --- | --- | --- | --- | --- | --- |
| 1.4.1 | 2 | All | Access control enforced at trusted enforcement points | Met | Server-side guard per route (`routes.rs`), PostgreSQL RLS (`migrations/0001_roles_and_tenancy.sql`); `-server/tests/threats.rs` `every_scoped_route_refuses_a_credential_lacking_exactly_its_scope`; `SEC-A05` | — |
| 1.4.2 | 3 | — | Deleted in 4.0.3 | Deleted | — | — |
| 1.4.3 | 3 | — | Deleted in 4.0.3 (duplicate of 4.1.3) | Deleted | — | — |
| 1.4.4 | 2 | All | Single, well-vetted access control mechanism | Met | `Principal::require` (`-server/src/auth.rs`) plus the tenancy-scoped transaction (`TenantTx`) for every object; ADR-028 for organizations | — |
| 1.4.5 | 2 | All | Feature/attribute-based access control | Met | Scopes per permission profile (`profile_scopes`, docs/22 §8); envelope-level `view_all`/owner checks; `SEC-A05` | — |

**V1.5 Input and Output Architecture**

| Req | L | Scope | Requirement (paraphrase) | Status | Evidence checked | Row |
| --- | --- | --- | --- | --- | --- | --- |
| 1.5.1 | 2 | All | Input and output handling defined per type | Met | docs/21 parser limits; docs/40 request schemas; `api/openapi.yaml` kept equal to the routes by a test (`-server/tests/contract.rs`) | — |
| 1.5.2 | 2 | All | No unsafe serialization with untrusted clients | Met | JSON only, typed `serde` structs with `deny_unknown_fields` (`-server/src/dto.rs`); no native object serialization | — |
| 1.5.3 | 2 | All | Input validation on a trusted service layer | Met | Server re-validates everything (`dto.rs`; `evaluate_envelope` re-runs field rules, `SEC-F03`) | — |
| 1.5.4 | 2 | All | Output encoding close to the interpreter | Met | Web app writes user strings with `textContent` only (CLAUDE.md, `SEC-A07`, `webapp/e2e` XSS spec); emails encoded per header (`-worker/src/email.rs`) | — |

**V1.6 Cryptographic Architecture**

| Req | L | Scope | Requirement (paraphrase) | Status | Evidence checked | Row |
| --- | --- | --- | --- | --- | --- | --- |
| 1.6.1 | 2 | All | Key management policy and lifecycle | Partly | docs/31 §5 (keyd), docs/65 production checklist; seal key rotation designed, not built (`CON-10`); API token key rotation not documented | CON-10, ASVS-28 |
| 1.6.2 | 2 | All | Key material protected in vaults; secrets out of code | Partly | Seal key only in keyd behind PKCS#11 (`SEC-S04`); secrets from files (`casual-sign-secrets`); the development compose file mounts one shared secrets volume, seal key included, into every service | ASVS-19 |
| 1.6.3 | 2 | All | Keys and passwords replaceable with a re-encryption process | Partly | Passwords and API clients replaceable through the API; database and S3 credentials replaceable by redeploying secret files; no documented rotation runbook for the JWT signing key and keyd TLS identities | ASVS-28 |
| 1.6.4 | 2 | All | Client-side secrets treated as insecure | Met | No secret in the web app; the CSRF token is per session, the session cookie is `HttpOnly`; WASM verifier holds no key | — |

**V1.7 Errors, Logging and Auditing Architecture**

| Req | L | Scope | Requirement (paraphrase) | Status | Evidence checked | Row |
| --- | --- | --- | --- | --- | --- | --- |
| 1.7.1 | 2 | All | Common logging format | Partly | `tracing` in every binary (`-server/src/main.rs`); plain text, not one structured (JSON) format across server, worker, keyd and modeld | ASVS-08 |
| 1.7.2 | 2 | All | Logs shipped securely to a remote system | Not met | No log forwarding configured or documented beyond "OTLP endpoint" in docs/65 checklist; not built | ASVS-08 |

**V1.8 Data Protection and Privacy Architecture**

| Req | L | Scope | Requirement (paraphrase) | Status | Evidence checked | Row |
| --- | --- | --- | --- | --- | --- | --- |
| 1.8.1 | 2 | All | Sensitive data identified and classified | Met | docs/07 data classification (personal data list, `SEC-D01`) | — |
| 1.8.2 | 2 | All | Protection requirements per protection level | Partly | docs/07 controls per class; encryption at rest delegated to the operator (docs/65 checklist) | ASVS-17 |

**V1.9 Communications Architecture**

| Req | L | Scope | Requirement (paraphrase) | Status | Evidence checked | Row |
| --- | --- | --- | --- | --- | --- | --- |
| 1.9.1 | 2 | All | Components encrypt communication | Partly | keyd and modeld mTLS (rustls, TLS 1.3); server to PostgreSQL and S3 unencrypted in the compose file | ASVS-19 |
| 1.9.2 | 2 | All | Components verify each other's authenticity | Partly | keyd/modeld verify client certificates against a CA and an allow-list (`-keyd/tests/mtls.rs` `a_client_not_on_the_allow_list_is_refused_and_logged`); database and object store not authenticated by certificate | ASVS-19 |

**V1.10 Malicious Software Architecture**

| Req | L | Scope | Requirement (paraphrase) | Status | Evidence checked | Row |
| --- | --- | --- | --- | --- | --- | --- |
| 1.10.1 | 2 | All | Source control with traceable check-ins | Met | Git; Conventional Commits citing tracker rows, checked by the commit-msg hook and CI job `commit-messages` (`.github/workflows/ci.yml`) | — |

**V1.11 Business Logic Architecture**

| Req | L | Scope | Requirement (paraphrase) | Status | Evidence checked | Row |
| --- | --- | --- | --- | --- | --- | --- |
| 1.11.1 | 2 | All | Components documented by function and security role | Met | docs/19 crate table and dependency DAG; docs/02 | — |
| 1.11.2 | 2 | All | High-value flows not shared unsynchronized state | Met | Workflow commands run in one database transaction per command; audit chain head locked (`-store/src/repo/audit.rs`); rate limiter behind a mutex that fails closed (`-server/src/state.rs`) | — |
| 1.11.3 | 3 | Ceremony, sealing, keyd | L3 (ceremony, sealing, keyd): high-value flows thread-safe against TOCTOU | Met | Ceremony: each call one transaction with the recipient row; sealing: job claimed once (`-worker/src/jobs.rs`), crash points tested (`-worker/tests/process_crash.rs`); keyd: op-log line synced before a signature is released (`-keyd/src/oplog.rs`) | — |

**V1.12 Secure File Upload Architecture**

| Req | L | Scope | Requirement (paraphrase) | Status | Evidence checked | Row |
| --- | --- | --- | --- | --- | --- | --- |
| 1.12.1 | 3 | — | Deleted in 4.0.3 (duplicate of 12.4.1) | Deleted | — | — |
| 1.12.2 | 2 | All | Uploaded files served safely | Met | Documents served as `application/pdf` with `nosniff` and the API CSP `default-src 'none'` (`-server/src/http.rs`); rendered by pdf.js in a worker with eval disabled (`webapp/pdfview.js`) | — |

**V1.14 Configuration Architecture**

| Req | L | Scope | Requirement (paraphrase) | Status | Evidence checked | Row |
| --- | --- | --- | --- | --- | --- | --- |
| 1.14.1 | 2 | All | Segregation of components by trust level | Partly | keyd and modeld separate processes; modeld on an `internal: true` network; console on a private listener (docs/23 §5); compose file does not segregate server from keyd's secrets volume | ASVS-19 |
| 1.14.2 | 2 | All | Signed binaries, trusted deployment connections | Partly | Release images pushed with SBOM and provenance attestation (`.github/workflows/release.yml`); images not signed with cosign (`SEC-C02` Planned) | ASVS-15 |
| 1.14.3 | 2 | All | Build warns of out-of-date or insecure components | Met | `cargo deny check` and `cargo audit --deny warnings` in CI job `dependency-policy`; `SEC-C01` | — |
| 1.14.4 | 2 | All | Build verifies secure deployment | Partly | CI builds and tests; `tools/ci-local.sh`; no automated check of a production deployment's configuration | ASVS-19 |
| 1.14.5 | 2 | All | Deployments sandboxed/network isolated | Partly | modeld sandboxed (`internal: true`, `cap_drop: [ALL]`, read-only); other services not given the same hardening in compose | ASVS-19 |
| 1.14.6 | 2 | All | No deprecated client technologies | Met | Plain ES modules, no plugins, no Flash/ActiveX/Java; CSP `object-src 'none'` (`-server/src/web.rs` `PAGE_CSP`) | — |

### V2 Authentication

**V2.1 Password Security**

| Req | L | Scope | Requirement (paraphrase) | Status | Evidence checked | Row |
| --- | --- | --- | --- | --- | --- | --- |
| 2.1.1 | 1 | All | Passwords at least 12 characters | Met | `check_password` 12..=256 characters (`-server/src/api/admin.rs`) | — |
| 2.1.2 | 1 | All | Passwords of 64+ allowed, 128+ allowed or denied | Met | Up to 256 characters accepted | — |
| 2.1.3 | 1 | All | No truncation | Met | Whole string hashed by Argon2id (`-server/src/crypto.rs` `hash_password`) | — |
| 2.1.4 | 1 | All | Any printable Unicode allowed | Met | Length counted in characters, no character class rule (`check_password`) | — |
| 2.1.5 | 1 | All | Users can change their password | Met | `PATCH /users/me {password, current_password}` (`admin.rs`, UXW-37) | — |
| 2.1.6 | 1 | All | Change requires current and new password | Met | `PATCH /users/me` verifies `current_password` before setting the new one (`admin.rs` around `current_password`) | — |
| 2.1.7 | 1 | All | Passwords checked against breached/common lists | Met | Every path that sets a password refuses one of the 46,146 breached passwords of 12 to 256 characters bundled in `-server/data/common-passwords.txt` (`-server/src/passwords.rs`; `422` `common_password`); `-server/tests/self_service.rs` `a_breached_password_is_refused_wherever_a_password_is_set`, seen red (`ASVS-02`). An operator lookup is optional (`ASVS-36`); the console's operators are `ASVS-37` | ASVS-02 |
| 2.1.8 | 1 | All | Password strength meter | Not met | None on the set-password screens (`webapp/acceptinvite.js`, `webapp/profile.js`) | ASVS-03 |
| 2.1.9 | 1 | All | No composition rules | Met | `check_password` checks length only | — |
| 2.1.10 | 1 | All | No periodic rotation or history rules | Met | None in code or settings | — |
| 2.1.11 | 1 | All | Paste and password managers allowed | Met | Password fields carry `autocomplete` `current-password`/`new-password`; no paste blocking (`webapp/authview.js`, `signin.js`) | — |
| 2.1.12 | 1 | All | User can temporarily view the password | Met | `passwordField` reveal toggle (`webapp/authview.js`) | — |

**V2.2 General Authenticator Security**

| Req | L | Scope | Requirement (paraphrase) | Status | Evidence checked | Row |
| --- | --- | --- | --- | --- | --- | --- |
| 2.2.1 | 1 | All | Anti-automation against credential stuffing and brute force | Partly | Login limited per login name and per client address (`login_limit`; `-server/tests/threats.rs` `sign_in_attempts_are_limited_per_client_address_across_names`); unknown emails cost a wrong password's time (`dummy_phc`); staff TOTP attempts limited per user as logins (`-server/src/api/mfa.rs`), the factor opt-in per account until `ASVS-31`; no breached-password check | ASVS-31, ASVS-02 |
| 2.2.2 | 1 | All | Weak authenticators (SMS, email) only secondary | Met | Staff have no SMS/email login factor; signers' email/SMS codes are an extra factor on top of the link (`-server/src/ceremony.rs` `otp_send`) | — |
| 2.2.3 | 1 | All | Notifications after authentication detail changes | Met | A password set from an invitation, changed by the user or an administrator, or reset, and a factor added, each queue one `send_security_notice` email in the same transaction, with no secret (`-worker/tests/security_notice.rs`, seen red; `ASVS-04`) | ASVS-04 |
| 2.2.4 | 3 | Ceremony, sealing, keyd | L3 (ceremony): phishing-resistant authentication | Not met | Signer methods: link, access code, email/SMS/voice code, OIDC sign-in (`idp.rs`); none is phishing-resistant (no WebAuthn) | ASVS-21 |
| 2.2.5 | 3 | Ceremony, sealing, keyd | L3: mutual TLS between separate CSP and verifier | N/A | The ceremony's OIDC provider is reached over HTTPS with server certificate checks; no separate credential service with mTLS exists in the ceremony, sealing or keyd. keyd's own callers do use mTLS | — |
| 2.2.6 | 3 | Ceremony, sealing, keyd | L3 (ceremony): replay resistance | Met | One-time codes spent on first pass (`otp/verify`), OIDC `nonce` and `state` checked (`idp.rs`); link bound to the first browser by cookie (`CS-AUTH-0009`) | — |
| 2.2.7 | 3 | Ceremony, sealing, keyd | L3 (ceremony): intent to authenticate | Met | Codes are typed in and SSO is started by the signer's own action (`webapp/sign.js`) | — |

**V2.3 Authenticator Lifecycle**

| Req | L | Scope | Requirement (paraphrase) | Status | Evidence checked | Row |
| --- | --- | --- | --- | --- | --- | --- |
| 2.3.1 | 1 | All | System-generated initial secrets random and short-lived | Met | Invitation and reset links: 256 random bits, SHA-256 stored, 7 days, single use (docs/40 §2 table, `-worker/tests/user_invite.rs`) | — |
| 2.3.2 | 2 | All | Enrolment of user-provided authenticators (FIDO/U2F) | Not met | No WebAuthn for staff (`CON-13`) | CON-13, ASVS-01 |
| 2.3.3 | 2 | All | Renewal instructions for time-bound authenticators | N/A | No time-bound authenticators issued to users (API keys expire but are replaced by an administrator) | — |

**V2.4 Credential Storage**

| Req | L | Scope | Requirement (paraphrase) | Status | Evidence checked | Row |
| --- | --- | --- | --- | --- | --- | --- |
| 2.4.1 | 2 | All | Passwords stored resistant to offline attack | Met | Argon2id (`-server/src/crypto.rs`) | — |
| 2.4.2 | 2 | All | Salt at least 32 bits | Met | 16-byte random salt per hash (`hash_password`) | — |
| 2.4.3 | 2 | All | PBKDF2 iterations | N/A | PBKDF2 not used | — |
| 2.4.4 | 2 | All | bcrypt work factor | N/A | bcrypt not used | — |
| 2.4.5 | 2 | All | Additional secret-salt (pepper) KDF iteration | Not met | No pepper held outside the database | ASVS-29 |

**V2.5 Credential Recovery**

| Req | L | Scope | Requirement (paraphrase) | Status | Evidence checked | Row |
| --- | --- | --- | --- | --- | --- | --- |
| 2.5.1 | 1 | All | Activation/recovery secret not sent in clear text | Met | Links carry a random one-time token in the URL fragment, not a password (docs/40 §2) | — |
| 2.5.2 | 1 | All | No password hints or secret questions | Met | None exist | — |
| 2.5.3 | 1 | All | Recovery never reveals the current password | Met | Reset sets a new Argon2id hash (`password_reset_confirm`); old password never stored in clear | — |
| 2.5.4 | 1 | All | No shared or default accounts | Met | `bootstrap` names the first administrator and requires `OPENSEAL_ADMIN_PASSWORD` (`docker-compose.yml` header, `-server/tests/bootstrap.rs`) | — |
| 2.5.5 | 1 | All | User notified when an authentication factor changes | Met | Password changes and a TOTP factor added email the user (`-worker/tests/security_notice.rs`, `ASVS-04`); no route removes a factor yet, and `ASVS-32` sends `factor_removed` when one does | ASVS-04 |
| 2.5.6 | 1 | All | Secure recovery mechanism | Partly | Emailed one-time reset link, 202 for any address, rate-limited (`reset_inner`); a reset does not bypass a staff user's TOTP (every session of an enrolled user owes it, `SecondFactor::of` in `-server/src/auth.rs`), but a lost factor has no recovery path but the recovery codes | ASVS-32 |
| 2.5.7 | 2 | All | Identity proofing when MFA factors are lost | Not met | Staff TOTP exists (`ASVS-01`); nothing yet resets or replaces a lost factor, so there is no proofing step either | ASVS-32 |

**V2.6 Look-up Secret Verifier**

| Req | L | Scope | Requirement (paraphrase) | Status | Evidence checked | Row |
| --- | --- | --- | --- | --- | --- | --- |
| 2.6.1 | 2 | All | Lookup secrets used once | Met | Staff recovery codes are removed from `users.recovery_code_sha256` as they are used (`openseal_use_own_recovery_code`, `migrations/0032_staff_mfa.sql`); `-server/tests/mfa.rs` refuses a spent code, seen red | — |
| 2.6.2 | 2 | All | Lookup secrets 112 bits | Met | 14 bytes from `aws_lc_rs::rand` per code (`-server/src/mfa.rs` `recovery_code`) | — |
| 2.6.3 | 2 | All | Lookup secrets resist offline attack | Met | Random (not user-chosen) 112-bit codes, stored only as SHA-256 (`-server/src/mfa.rs` `recovery_hash`) | — |

**V2.7 Out of Band Verifier**

| Req | L | Scope | Requirement (paraphrase) | Status | Evidence checked | Row |
| --- | --- | --- | --- | --- | --- | --- |
| 2.7.1 | 1 | All | Clear-text out-of-band (SMS/PSTN) not offered by default | Partly | Default signer code is email (`OtpSendIn` default `email_otp`); SMS and voice only when the sender requires them and the operator configures a gateway (docs/65); no alternative strong method offered beside SMS | ASVS-21 |
| 2.7.2 | 1 | All | Out-of-band codes expire after 10 minutes | Met | `OTP_TTL` 10 minutes (`ceremony.rs`) | — |
| 2.7.3 | 1 | All | Codes usable once, for the original request | Met | A pass spends the code; code bound to the recipient and channel (`ceremony.rs` `otp_verify`, `-server/tests/ceremony_auth.rs` `the_document_is_refused_until_the_emailed_code_is_passed`) | — |
| 2.7.4 | 1 | All | Out-of-band channel secure and independent | Met | Email or SMS gateway over HTTPS from the worker, separate from the browser session (`-worker/src/messenger.rs`) | — |
| 2.7.5 | 2 | All | Only a hash of the code retained | Met | Argon2id of the code (`-worker/src/worker.rs` `hash_code`; docs/07 `SEC-A02`) | — |
| 2.7.6 | 2 | All | Initial code from a CSPRNG with 20+ bits | Met | 6 digits drawn uniformly from `aws_lc_rs::rand` (`one_time_code`), about 19.9 bits as ASVS allows for six digits; 5 tries then lockout (`OTP_TRIES`) | — |

**V2.8 One Time Verifier**

| Req | L | Scope | Requirement (paraphrase) | Status | Evidence checked | Row |
| --- | --- | --- | --- | --- | --- | --- |
| 2.8.1 | 1 | All | TOTP lifetime defined | Met | Operators' and staff TOTP (RFC 6238, 30 s step, `-console/src/totp.rs`, `-server/src/totp.rs`) | — |
| 2.8.2 | 2 | All | TOTP seeds highly protected | Met | Operators' seeds sealed with AES-256-GCM under `OPENSEAL_CONSOLE_MFA_KEY`, operator id as associated data; the database holds only the sealed seed (`-console/src/crypto.rs`); staff seeds likewise under `OPENSEAL_MFA_KEY` with the user id (`-server/src/mfa.rs`) | — |
| 2.8.3 | 2 | All | Approved algorithms for OTP | Met | HMAC-SHA1 TOTP per RFC 6238 vectors (`-console/src/totp.rs` tests); signer codes from `aws_lc_rs::rand` | — |
| 2.8.4 | 2 | All | TOTP used once within its validity | Met | `platform.operator_mfa.last_step`: a code is accepted only for a step later than the last (`migrations/0017_operators.sql`); `-console/tests/api.rs` `operators_enrol_and_sign_in_with_a_single_use_second_factor` replays the same code on a new session and is refused; staff: `users.totp_last_step` (`migrations/0032_staff_mfa.sql`), `-server/tests/mfa.rs` refuses a replayed code, seen red | — |
| 2.8.5 | 2 | All | Reused TOTP logged and rejected | Partly | Rejected by `last_step`; the rejection is not written to a security log | ASVS-08 |
| 2.8.6 | 2 | All | Physical OTP generators revocable | N/A | No physical generators issued | — |
| 2.8.7 | 2 | All | Biometrics only as secondary factor | N/A | No biometric authenticators | — |

**V2.9 Cryptographic Verifier**

| Req | L | Scope | Requirement (paraphrase) | Status | Evidence checked | Row |
| --- | --- | --- | --- | --- | --- | --- |
| 2.9.1 | 2 | All | Cryptographic authenticator keys stored securely | N/A | No cryptographic authenticators for users yet (`CON-13`) | CON-13 |
| 2.9.2 | 2 | All | Challenge nonce 64+ bits | N/A | As 2.9.1; OIDC `nonce` is 256 random bits (`idp.rs`) | — |
| 2.9.3 | 2 | All | Approved algorithms for cryptographic authenticators | N/A | As 2.9.1 | — |

**V2.10 Service Authentication**

| Req | L | Scope | Requirement (paraphrase) | Status | Evidence checked | Row |
| --- | --- | --- | --- | --- | --- | --- |
| 2.10.1 | 2 | All | Intra-service secrets not static credentials | Partly | keyd and modeld use client certificates; PostgreSQL and S3 use static passwords from secret files | ASVS-19 |
| 2.10.2 | 2 | All | No default service credentials | Met | `pki` generates random database, S3 and SoftHSM passwords on first start (docs/65 §services) | — |
| 2.10.3 | 2 | All | Service passwords protected against offline recovery | Met | Held only in secret files mounted read-only, wiped on drop (`casual-sign-secrets` `Zeroizing`) | — |
| 2.10.4 | 2 | All | Secrets not in source code or images | Met | `casual-sign-secrets` (`_FILE` convention; both set is an error, `-secrets/tests/secrets.rs`); docs/65 "Nothing is baked into an image" | — |

### V3 Session Management

**V3.1 Fundamental Session Management Security**

| Req | L | Scope | Requirement (paraphrase) | Status | Evidence checked | Row |
| --- | --- | --- | --- | --- | --- | --- |
| 3.1.1 | 1 | All | Session tokens never in URLs | Partly | Staff session only in a cookie; the signing link carries its 256-bit token in the path `/s/{token}` by design (an emailed link), bound to the first browser by an `HttpOnly` cookie, `Referrer-Policy: no-referrer`; the access log records the route template, not the token | ASVS-20 |

**V3.2 Session Binding**

| Req | L | Scope | Requirement (paraphrase) | Status | Evidence checked | Row |
| --- | --- | --- | --- | --- | --- | --- |
| 3.2.1 | 1 | All | New session token on authentication | Met | `login_inner` mints a new random secret and session row per login (`admin.rs`) | — |
| 3.2.2 | 1 | All | Session tokens 64+ bits | Met | 256 bits (`random_secret`, `-server/src/crypto.rs`) | — |
| 3.2.3 | 1 | All | Tokens stored in browser securely | Met | Cookies `HttpOnly`, `Secure`, `SameSite`; the staff cookie is `__Host-os_session` whenever `Secure` (`-server/src/auth.rs` `session_cookie`; `-server/tests/web.rs` `the_staff_session_cookie_is_host_prefixed_whenever_it_is_secure`) | ASVS-05 |
| 3.2.4 | 2 | All | Tokens from approved algorithms | Met | `aws_lc_rs::rand::SystemRandom` | — |

**V3.3 Session Termination**

| Req | L | Scope | Requirement (paraphrase) | Status | Evidence checked | Row |
| --- | --- | --- | --- | --- | --- | --- |
| 3.3.1 | 1 | All | Logout and expiry invalidate the token server-side | Met | `POST /auth/logout` revokes the session row and clears the cookie (`admin.rs` `logout`); resolver refuses revoked or expired rows (`-store/src/repo/sessions.rs`) | — |
| 3.3.2 | 1 | All | Periodic re-authentication (absolute and idle) | Partly | Absolute 8 h staff session (`Config::session_ttl`); no idle timeout for staff (operators have 30 min idle, `-console/src/lib.rs`) | ASVS-06 |
| 3.3.3 | 2 | All | Option to end other sessions after password change | Met | A new password ends the user's sessions in every account (`patch_user`, `SEC-ID-01`; `revoke_all`) | — |
| 3.3.4 | 2 | All | Users view and log out of active sessions | Not met | No session list or per-session logout | ASVS-06 |

**V3.4 Cookie-based Session Management**

| Req | L | Scope | Requirement (paraphrase) | Status | Evidence checked | Row |
| --- | --- | --- | --- | --- | --- | --- |
| 3.4.1 | 1 | All | Cookies `Secure` | Met | `Secure` unless plain-HTTP development (`Config::secure_cookies`; `-server/tests/web.rs` `the_ceremony_cookie_is_secure_unless_the_server_is_plain_http_development`) | — |
| 3.4.2 | 1 | All | Cookies `HttpOnly` | Met | `cookie()` in `admin.rs`; ceremony cookie `ceremony.rs` | — |
| 3.4.3 | 1 | All | Cookies `SameSite` | Met | Staff `SameSite=Lax`, ceremony `SameSite=Strict` | — |
| 3.4.4 | 1 | All | `__Host-` prefix | Met | Operator cookie `__Host-os_op`; staff cookie `__Host-os_session` whenever `Secure` (plain `os_session` only for plain-HTTP development); the ceremony cookie keeps the narrowest path instead (`Path=/s/`, `SameSite=Strict`, `Secure`), which `__Host-` would forbid | ASVS-05 |
| 3.4.5 | 1 | All | Path attribute narrowest practical | Met | Ceremony cookie `Path=/s/`; staff cookie `Path=/` (the app and API share one origin) | — |

**V3.5 Token-based Session Management**

| Req | L | Scope | Requirement (paraphrase) | Status | Evidence checked | Row |
| --- | --- | --- | --- | --- | --- | --- |
| 3.5.1 | 2 | All | Users can revoke OAuth grants | Met | API clients and keys revocable (`DELETE /api-clients/{id}`); tokens die with their client (`SEC-A10`) | — |
| 3.5.2 | 2 | All | Session tokens rather than static API secrets for users | Met | Browser uses session cookies; API keys are for integrations, scoped, expiring, hashed (`SEC-A10`) | — |
| 3.5.3 | 2 | All | Stateless tokens signed and checked | Met | ES256 access tokens with issuer, audience and expiry checked (`-server/src/crypto.rs` `Claims`, `jsonwebtoken` `Validation`); `/.well-known/jwks.json` | — |

**V3.6 Federated Re-authentication**

| Req | L | Scope | Requirement (paraphrase) | Status | Evidence checked | Row |
| --- | --- | --- | --- | --- | --- | --- |
| 3.6.1 | 3 | Ceremony, sealing, keyd | L3 (ceremony): RP specifies maximum authentication time to the IdP | Not met | Recipient OIDC request sends no `max_age` and does not check `auth_time` (`idp.rs`) | ASVS-22 |
| 3.6.2 | 3 | Ceremony, sealing, keyd | L3: CSP informs RP of last authentication | N/A | OpenSeal is not a credential service provider | — |

**V3.7 Defenses Against Session Management Exploits**

| Req | L | Scope | Requirement (paraphrase) | Status | Evidence checked | Row |
| --- | --- | --- | --- | --- | --- | --- |
| 3.7.1 | 1 | All | Re-authentication before sensitive actions | Not met | No step-up before creating API clients, granting administrators or changing webhook URLs | ASVS-07 |

### V4 Access Control

**V4.1 General Access Control Design**

| Req | L | Scope | Requirement (paraphrase) | Status | Evidence checked | Row |
| --- | --- | --- | --- | --- | --- | --- |
| 4.1.1 | 1 | All | Access control on a trusted service layer | Met | Server guard per route; hiding a button is never a control (CLAUDE.md); `-server/tests/auth.rs` `every_guarded_route_refuses_a_request_without_credentials` | — |
| 4.1.2 | 1 | All | Access-control attributes not user-manipulable | Met | Account from the credential only (`SEC-O05`); scopes from the stored profile (`profile_scopes`) | — |
| 4.1.3 | 1 | All | Least privilege | Met | Profiles Admin/Sender/Viewer; API keys narrow, never widen (`auth.rs`); console role has no grant on `public` (`SEC-X01`) | — |
| 4.1.4 | 3 | — | Deleted in 4.0.3 (duplicate of 4.1.3) | Deleted | — | — |
| 4.1.5 | 1 | All | Access control fails securely | Met | Deny by default; a poisoned rate-limit lock fails closed (`state.rs`); store errors map to refusals (`error.rs`) | — |

**V4.2 Operation Level Access Control**

| Req | L | Scope | Requirement (paraphrase) | Status | Evidence checked | Row |
| --- | --- | --- | --- | --- | --- | --- |
| 4.2.1 | 1 | All | IDOR protection | Met | Tenancy-scoped repository plus RLS; `-server/tests/isolation.rs` `another_accounts_ids_are_not_found_with_rls`/`_without_rls`; `-store/tests/isolation.rs`; `SEC-A04` | — |
| 4.2.2 | 1 | All | Strong anti-CSRF | Met | CSRF token on every changing session request (`auth.rs` `CSRF_HEADER`; `-server/tests/auth.rs` `..._missing_csrf_are_refused`); ceremony requires `application/json`; every `/api/v1` body, `POST /auth/login` included, must be `application/json` (`-server/src/http.rs` `json_only`, `415 CS-API-0007`), so a cross-site form cannot log in | ASVS-09 |

**V4.3 Other Access Control Considerations**

| Req | L | Scope | Requirement (paraphrase) | Status | Evidence checked | Row |
| --- | --- | --- | --- | --- | --- | --- |
| 4.3.1 | 1 | All | Administrative interfaces use MFA | Partly | Platform console: password plus mandatory TOTP (`-console/src/lib.rs`); tenant administrators: TOTP when the account's `mfa_policy` is `administrators` or `everyone` (`-server/tests/mfa.rs`), not yet by default | ASVS-31 |
| 4.3.2 | 1 | All | No directory browsing or metadata exposure | Met | Web app read into memory at start, only the web app's kinds of file served (`-server/src/web.rs`, test `only_the_web_apps_kinds_of_file_are_served`); test folders and Node manifests skipped | — |
| 4.3.3 | 2 | All | Step-up or adaptive authorization for high-value actions | Not met | None | ASVS-07 |

### V5 Validation, Sanitization and Encoding

**V5.1 Input Validation**

| Req | L | Scope | Requirement (paraphrase) | Status | Evidence checked | Row |
| --- | --- | --- | --- | --- | --- | --- |
| 5.1.1 | 1 | All | HTTP parameter pollution | Met | Typed `serde` query and body structs; unknown fields refused (`deny_unknown_fields`, `dto.rs`) | — |
| 5.1.2 | 1 | All | Mass assignment protection | Met | Explicit DTOs with `deny_unknown_fields`; profile and disabled refused on oneself (`patch_user`) | — |
| 5.1.3 | 1 | All | All input validated (allow lists) | Met | `dto.rs` validators (email, E.164 phone, lengths); docs/21 limits; JSON body cap 1 MiB (`routes.rs` `JSON`) | — |
| 5.1.4 | 1 | All | Structured data strongly typed and schema-validated | Met | `serde` types match `api/openapi.yaml` (`-server/tests/contract.rs`) | — |
| 5.1.5 | 1 | All | Redirects only to allow-listed destinations | Met | OIDC endpoints and redirect URI from the operator's file only (`idp.rs`); the web app navigates to same-origin paths or server-issued sign links (`webapp/app.js`) | — |

**V5.2 Sanitization and Sandboxing**

| Req | L | Scope | Requirement (paraphrase) | Status | Evidence checked | Row |
| --- | --- | --- | --- | --- | --- | --- |
| 5.2.1 | 1 | All | HTML sanitizer for WYSIWYG input | N/A | No HTML input is accepted anywhere (`SEC-A07`) | — |
| 5.2.2 | 1 | All | Unstructured data sanitized (characters, length) | Met | Length caps on names, subjects and messages (`dto.rs`, docs/21) | — |
| 5.2.3 | 1 | All | Mail input sanitized against SMTP injection | Met | `-worker/src/email.rs` `supplied_text_cannot_inject_headers` (seen red 2026-11-13 with names written unencoded), `bad_addresses_are_refused`, `encoded_words`; docs/07 `SEC-M02` | — |
| 5.2.4 | 1 | All | No eval or dynamic code execution | Met | No `eval`/`new Function` in `webapp/`; pdf.js `isEvalSupported: false`; CSP `script-src 'self'` (only the Verify page adds `'wasm-unsafe-eval'`, `web.rs`) | — |
| 5.2.5 | 1 | All | Template injection | Met | Email bodies are fixed templates with escaped values (`SEC-A07`); no server-side template engine over user input | — |
| 5.2.6 | 1 | All | SSRF protection | Met | Webhook URLs `https` only, every resolved address checked at registration and at connect, no redirects (`-worker/src/webhook.rs`, `SEC-W01`); OIDC endpoints from operator config only | — |
| 5.2.7 | 1 | All | SVG scriptable content sandboxed | Met | Uploads are PDF (Office via converter, `SEC-P13`); signature images PNG/JPEG only; the web app never renders user SVG | — |
| 5.2.8 | 1 | All | Scriptable/expression templates sandboxed | Met | PDF JavaScript never executed (`SEC-P*`, docs/30); field formulas evaluated by a bounded interpreter (`SEC-F02`) | — |

**V5.3 Output Encoding and Injection Prevention**

| Req | L | Scope | Requirement (paraphrase) | Status | Evidence checked | Row |
| --- | --- | --- | --- | --- | --- | --- |
| 5.3.1 | 1 | All | Context-appropriate output encoding | Met | `textContent` in the web app; JSON responses via `serde_json`; RFC 2047 in mail headers | — |
| 5.3.2 | 1 | All | Encoding preserves character set | Met | UTF-8 throughout; `Content-Type` with charset on pages (`web.rs` `content_type`) | — |
| 5.3.3 | 1 | All | Context-aware escaping against XSS | Met | `webapp/e2e/xss.spec.mjs` (`SEC-A07`, seen red) | — |
| 5.3.4 | 1 | All | Parameterized queries | Met | `sqlx` bound parameters in every repository (`-store/src/repo/*.rs`); no `format!` building SQL found | — |
| 5.3.5 | 1 | All | Encoding where parameterization is unavailable | N/A | Not needed: all queries parameterized | — |
| 5.3.6 | 1 | All | JSON injection | Met | Responses serialized with `serde_json`; web app uses `JSON.parse` | — |
| 5.3.7 | 1 | All | LDAP injection | N/A | No LDAP | — |
| 5.3.8 | 1 | All | OS command injection | Met | No shell; the only child processes take fixed arguments (`-modeld/src/raster.rs`, `-host/src/crash.rs`) | — |
| 5.3.9 | 1 | All | LFI/RFI | Met | Web files served from an in-memory map by exact name (`web.rs`); blob paths from content hashes (`-store/src/blob/fs.rs`) | — |
| 5.3.10 | 1 | All | XPath/XML injection | Met | XFA XML parsed by a bounded reader, never queried with XPath (`casual-sign-xfa`) | — |

**V5.4 Memory, String, and Unmanaged Code**

| Req | L | Scope | Requirement (paraphrase) | Status | Evidence checked | Row |
| --- | --- | --- | --- | --- | --- | --- |
| 5.4.1 | 2 | All | Memory-safe code | Met | Rust; `unsafe` forbidden in `crates/` (`tools/check-repo.py`) | — |
| 5.4.2 | 2 | All | Format strings constant | Met | Rust format strings are compile-time literals | — |
| 5.4.3 | 2 | All | Integer overflow prevention | Met | Checked/saturating arithmetic on untrusted values (CLAUDE.md); `overflow-checks = true` in release (`Cargo.toml`) | — |

**V5.5 Deserialization Prevention**

| Req | L | Scope | Requirement (paraphrase) | Status | Evidence checked | Row |
| --- | --- | --- | --- | --- | --- | --- |
| 5.5.1 | 1 | All | Serialized objects integrity-checked | Met | Audit events as RFC 8785 canonical bytes, hash-chained (`-store/src/repo/audit.rs`); access tokens signed | — |
| 5.5.2 | 1 | All | XML parsers restrictive (no XXE) | Met | XFA reader expands no external entities (`casual-sign-xfa`, `SEC-P07`) | — |
| 5.5.3 | 1 | All | Untrusted data deserialization safe | Met | `serde` into typed structs; no polymorphic deserialization | — |
| 5.5.4 | 1 | All | `JSON.parse` in the browser | Met | `webapp/api.js` uses `fetch().json()`/`JSON.parse` | — |

### V6 Stored Cryptography

**V6.1 Data Classification**

| Req | L | Scope | Requirement (paraphrase) | Status | Evidence checked | Row |
| --- | --- | --- | --- | --- | --- | --- |
| 6.1.1 | 2 | All | Regulated personal data encrypted at rest | Partly | Delegated to the operator: "PostgreSQL encrypted", "S3 encryption on" (docs/65 checklist); no application-level encryption | ASVS-17 |
| 6.1.2 | 2 | All | Regulated health data encrypted at rest | N/A | OpenSeal does not classify document content as health data; covered by 6.1.1 for operators who process it | ASVS-17 |
| 6.1.3 | 2 | All | Regulated financial data encrypted at rest | N/A | No payment data held (payments are slice 13) | — |

**V6.2 Algorithms**

| Req | L | Scope | Requirement (paraphrase) | Status | Evidence checked | Row |
| --- | --- | --- | --- | --- | --- | --- |
| 6.2.1 | 1 | All | Cryptographic modules fail securely | Met | `aws-lc-rs` and RustCrypto return errors mapped to typed codes (`CS-KEY-*`, `CS-SEAL-*`); no padding-oracle surface (no decryption service) | — |
| 6.2.2 | 2 | All | Proven algorithms and libraries | Met | ADR-006: `aws-lc-rs`, RustCrypto `argon2`, `cms`; `SEC-S08` SHA-256+ | — |
| 6.2.3 | 2 | All | IV, cipher and mode configuration | N/A | No symmetric encryption of data in the application | — |
| 6.2.4 | 2 | All | Algorithms replaceable | Met | Seal algorithms selectable (ECDSA P-256/P-384, RSA PSS; docs/31); Argon2 parameters in one function | — |
| 6.2.5 | 2 | All | No insecure modes (ECB, PKCS#1 v1.5) | Partly | keyd supports RSA PKCS#1 v1.5 signatures for compatibility with readers (docs/31); SHA-1 only for identifiers (`SEAL-14`) | SEAL-14 |
| 6.2.6 | 2 | All | Nonces/IVs not reused | Met | RFC 3161 nonces random per request (`SEC-S09`); no IV-based encryption | — |
| 6.2.7 | 3 | Ceremony, sealing, keyd | L3 (sealing, keyd): encrypted data authenticated | Met | No data encrypted; every sealed document and timestamp is signed and verified independently (`-worker/src/seal.rs`) | — |
| 6.2.8 | 3 | Ceremony, sealing, keyd | L3 (ceremony, sealing, keyd): constant-time operations | Met | Argon2 verify is constant-time; token-hash and TOTP code comparisons call `aws_lc_rs::constant_time::verify_slices_are_equal` (`-server/src/crypto.rs` `same`, `-server/src/totp.rs`, and the console's copies) | ASVS-12 |

**V6.3 Random Values**

| Req | L | Scope | Requirement (paraphrase) | Status | Evidence checked | Row |
| --- | --- | --- | --- | --- | --- | --- |
| 6.3.1 | 2 | All | Random values from a CSPRNG | Met | `aws_lc_rs::rand` for tokens, codes, salts (`crypto.rs`, `worker.rs`) | — |
| 6.3.2 | 2 | All | GUIDs from v4 with CSPRNG | Met | Ids are UUIDv7 (time-ordered, `uuid` crate) and are never secrets: access to any id is checked per object (4.2.1); every secret is a separate 256-bit value | — |
| 6.3.3 | 3 | Ceremony, sealing, keyd | L3: entropy under heavy load | Met | `aws-lc-rs` reads the OS CSPRNG (`getrandom`), which does not block or degrade after seeding | — |

**V6.4 Secret Management**

| Req | L | Scope | Requirement (paraphrase) | Status | Evidence checked | Row |
| --- | --- | --- | --- | --- | --- | --- |
| 6.4.1 | 2 | All | Secrets management solution | Partly | File-mounted secrets (Docker/Kubernetes/systemd convention, `casual-sign-secrets`); no vault integration other than PKCS#11 for the seal key | KEYD-01 |
| 6.4.2 | 2 | All | Key material isolated in a security module | Met | Seal key in an HSM via PKCS#11 in keyd only; file keys refused without `OPENSEAL_DEV_INSECURE_KEY=1` (`-keyd/tests/mtls.rs` `a_file_key_is_refused_without_explicit_consent`, `SEC-S04`) | — |

### V7 Error Handling and Logging

**V7.1 Log Content**

| Req | L | Scope | Requirement (paraphrase) | Status | Evidence checked | Row |
| --- | --- | --- | --- | --- | --- | --- |
| 7.1.1 | 1 | All | No credentials or payment details logged | Met | Request log fields: id, method, route template, status, time (`-server/src/http.rs`); secrets `Debug` redacted (`casual-sign-secrets`) | — |
| 7.1.2 | 1 | All | No other sensitive data logged | Met | Typed errors with ids and counts only (`error.rs`, `SEC-D01`); client IP never logged (`net.rs`); modeld log scrub test (`-modeld/tests/log_scrub.rs`) | — |
| 7.1.3 | 2 | All | Security-relevant events logged | Partly | Admin changes in the hash-chained admin log (`-store/src/admin_log.rs`); envelope events in the audit chain; staff login success and failure only as an HTTP status in the request log | ASVS-08 |
| 7.1.4 | 2 | All | Log events carry investigation detail | Partly | Request id, route, status, duration; no principal identifier on staff authentication outcomes | ASVS-08 |

**V7.2 Log Processing**

| Req | L | Scope | Requirement (paraphrase) | Status | Evidence checked | Row |
| --- | --- | --- | --- | --- | --- | --- |
| 7.2.1 | 2 | All | Authentication decisions logged | Partly | Ceremony authentication decisions recorded in the audit chain (`recipient.auth_passed`/`auth_challenged`); staff login decisions only as status codes | ASVS-08 |
| 7.2.2 | 2 | All | Access control decisions logged, failures always | Partly | Refusals answer RFC 9457 errors and appear as 401/403/404 in the request log without the principal | ASVS-08 |

**V7.3 Log Protection**

| Req | L | Scope | Requirement (paraphrase) | Status | Evidence checked | Row |
| --- | --- | --- | --- | --- | --- | --- |
| 7.3.1 | 2 | All | Log injection prevented | Met | `tracing` structured fields; values are server-made (request id is a server UUID, route is a template) | — |
| 7.3.2 | 3 | — | Deleted in 4.0.3 (duplicate of 7.3.1) | Deleted | — | — |
| 7.3.3 | 2 | All | Security logs protected from modification | Met | Audit, admin and operator logs append-only with triggers and grants, hash-chained (`-store/tests/admin_events.rs`, `SEC-O13`, `SEC-X04`); keyd op log refuses an edited file (`-keyd/tests/mtls.rs` `an_edited_operation_log_is_refused`) | — |
| 7.3.4 | 2 | All | Time sources synchronized; UTC | Met | Timestamps in UTC (`time::OffsetDateTime`, `tracing` default); trusted time for evidence from RFC 3161 TSAs (`SEC-S06`); host NTP is the operator's | — |

**V7.4 Error Handling**

| Req | L | Scope | Requirement (paraphrase) | Status | Evidence checked | Row |
| --- | --- | --- | --- | --- | --- | --- |
| 7.4.1 | 1 | All | Generic error messages with an id | Met | RFC 9457 problem details: fixed title per code plus request id (`-server/src/error.rs`) | — |
| 7.4.2 | 2 | All | Exception handling across the codebase | Met | Typed `Result` errors; untrusted input never panics (CLAUDE.md; fuzz targets in `fuzz/`) | — |
| 7.4.3 | 2 | All | Last-resort error handler | Met | The server and the console catch a handler panic: the server answers `500 CS-API-0010` with the request id (`-server/src/routes.rs` `finish`, `http.rs` `panicked`; `routes::tests::a_handler_that_panics_answers_a_problem_with_the_request_id_only`), the console `500 CS-CON-0014` with `x-request-id` (`-console/src/lib.rs` `finish`; its `tests::a_handler_that_panics_answers_a_problem_with_the_request_id_only`); both binaries' panic hooks log the place and never the message (`quiet_panics`; `tests/panic_hook.rs` in each) | ASVS-26 |

### V8 Data Protection

**V8.1 General Data Protection**

| Req | L | Scope | Requirement (paraphrase) | Status | Evidence checked | Row |
| --- | --- | --- | --- | --- | --- | --- |
| 8.1.1 | 2 | All | Sensitive data not cached in intermediaries | Met | `Cache-Control: no-store` on every API response (`http.rs`; `-server/tests/threats.rs` `every_kind_of_response_carries_the_security_headers...`) | — |
| 8.1.2 | 2 | All | Server-side cached/temporary copies protected | Met | No disk caches of documents; blobs in the store under the tenancy model; modeld derived data keyed by account (`SEC-I06`) | — |
| 8.1.3 | 2 | All | Minimal request parameters | Met | Ids in paths, typed bodies; no hidden fields carrying authorization | — |
| 8.1.4 | 2 | All | Detect and alert on abnormal request numbers | Not met | Rate limits answer 429 (`-server/tests/auth.rs` `rate_limits_answer_429_with_retry_after`), but nothing detects or alerts | ASVS-13 |
| 8.1.5 | 3 | Ceremony, sealing, keyd | L3 (sealing, keyd): regular backups and test restores | Partly | Built (`ASVS-14`): `tools/backup/openseal_backup.py` takes scheduled backups (database snapshot, blobs, keyd's log) and restores only into a fresh install, then `casual-sign-server verify-evidence` rebuilds every chain (the operator log too) and reads back every blob the evidence names: documents, certificates of completion, signature captures and their images, logos and attachments; the backup itself refuses an export lacking any of them (`-store/tests/evidence.rs`, `-server/tests/backup_commands.rs`, `tools/backup/test_openseal_backup.py`; docs/65 §Backups and restore). The restore drill (`tools/backup/drill.sh`, CI job `backup-drill`) is written but has not yet been run to completion, so the test restore is not yet evidenced | ASVS-14 |
| 8.1.6 | 3 | Ceremony, sealing, keyd | L3 (sealing, keyd): backups stored securely | Partly | Built (`ASVS-14`): CMS AuthEnvelopedData (AES-256-GCM, RSA-OAEP-SHA-256) for an offline recipient key, manifest signed with Ed25519 by a key only the backup host holds (verifiers hold its public half, so they cannot forge a backup a restore would run), roles script limited to role statements with no psql meta-command, no private key or secret in a backup; every check runs on the bytes then used (manifest, signature and payload read from the store once, into a private directory; only that copy decrypted); a flipped payload byte, an edited or re-signed manifest, a payload or manifest swapped in the store between check and use, another key, a roles script with `\!` or a `$` in a role name, and a hostile tar entry are refused (`tools/backup/test_openseal_backup.py`). Partly until the drill has run | ASVS-14 |

**V8.2 Client-side Data Protection**

| Req | L | Scope | Requirement (paraphrase) | Status | Evidence checked | Row |
| --- | --- | --- | --- | --- | --- | --- |
| 8.2.1 | 1 | All | Anti-caching headers | Met | `no-store` on API responses; web app files revalidated (`web.rs`) | — |
| 8.2.2 | 1 | All | No sensitive data in browser storage | Met | `localStorage`: theme, panel state, last-seen notice only; `sessionStorage`: CSRF token and the SSO return state (`webapp/api.js`, `sign.js`) | — |
| 8.2.3 | 1 | All | Client storage cleared after session end | Met | Logout revokes the session and clears the cookie (`admin.rs` `logout`); the web app's `logout` removes the CSRF token from `sessionStorage` whether or not the call succeeds (`webapp/api.js` `setCsrf(null)`); nothing else of the session is stored in the browser (8.2.2) | — |

**V8.3 Sensitive Private Data**

| Req | L | Scope | Requirement (paraphrase) | Status | Evidence checked | Row |
| --- | --- | --- | --- | --- | --- | --- |
| 8.3.1 | 1 | All | Sensitive data in body or headers, not query string | Met | Passwords, codes and tokens in JSON bodies or headers; the signing link token is in the path by design (3.1.1) | ASVS-20 |
| 8.3.2 | 1 | All | Users can export or remove their data | Not met | No self-service export or erasure (VS-15 enterprise data controls) | ASVS-16 |
| 8.3.3 | 1 | All | Clear language about personal data use | Partly | ERSD disclosure and consent for signers (`/s/{token}/disclosure`, docs/09); no privacy notice template for operators | ASVS-16 |
| 8.3.4 | 1 | All | Sensitive data identified with a handling policy | Met | docs/07 data classification; docs/22 marks personal fields (`Personal<T>` wrapper in the store) | — |
| 8.3.5 | 2 | All | Access to sensitive data audited | Partly | Signer document views recorded (`/s/{token}/documents/{doc}/viewed`); staff downloads of documents not recorded | ASVS-08 |
| 8.3.6 | 2 | All | Sensitive data in memory overwritten | Partly | Secrets read through `Secret` wiped on drop (`casual-sign-secrets`); request passwords and codes are plain `String`s | ASVS-25 |
| 8.3.7 | 2 | All | Encryption of required data with approved algorithms | Partly | As 6.1.1 | ASVS-17 |
| 8.3.8 | 2 | All | Retention classification and deletion | Not met | Retention policies not built (`SEC-D03`, VS-15) | ASVS-18 |

### V9 Communication

**V9.1 Client Communication Security**

| Req | L | Scope | Requirement (paraphrase) | Status | Evidence checked | Row |
| --- | --- | --- | --- | --- | --- | --- |
| 9.1.1 | 1 | All | TLS for all client connectivity | Partly | The server listens on plain HTTP; TLS is the edge's (docs/65 "Edge"); HSTS sent on every response (`http.rs`) | ASVS-19 |
| 9.1.2 | 1 | All | Strong cipher suites | N/A | Configured at the operator's edge, not in OpenSeal; keyd/modeld use rustls defaults (TLS 1.3 suites only) | — |
| 9.1.3 | 1 | All | Only TLS 1.2/1.3 | Partly | keyd and modeld TLS 1.3 only (`-keyd/src/server.rs`); edge is the operator's | ASVS-19 |

**V9.2 Server Communication Security**

| Req | L | Scope | Requirement (paraphrase) | Status | Evidence checked | Row |
| --- | --- | --- | --- | --- | --- | --- |
| 9.2.1 | 2 | All | Trusted certificates on connections | Met | Outbound HTTPS (webhooks, OIDC, SMS gateway, TSA) verified against system roots; keyd/modeld against the configured CA | — |
| 9.2.2 | 2 | All | TLS for all inbound and outbound connections | Partly | Webhooks and OIDC `https` only (HTTP to loopback for a same-host IdP); PostgreSQL and S3 not over TLS in compose; TSA URLs may be HTTP (RFC 3161 responses are signed) | ASVS-19 |
| 9.2.3 | 2 | All | Encrypted, authenticated connections to external systems | Met | As 9.2.1; keyd mutual TLS | — |
| 9.2.4 | 2 | All | OCSP stapling | N/A | At the operator's edge; seal-time revocation checks are separate (`SEC-S11`) | — |
| 9.2.5 | 3 | Ceremony, sealing, keyd | L3 (sealing, keyd): backend TLS failures logged | Partly | keyd refuses a bad client at the handshake and records allow-list refusals in its op log; the worker's keyd and TSA connection failures surface as job errors without a dedicated log line | ASVS-08 |

### V10 Malicious Code

**V10.1 Code Integrity**

| Req | L | Scope | Requirement (paraphrase) | Status | Evidence checked | Row |
| --- | --- | --- | --- | --- | --- | --- |
| 10.1.1 | 3 | Ceremony, sealing, keyd | L3 (ceremony, sealing, keyd): code analysis for malicious code | Partly | clippy with `-D warnings`, `cargo deny`, `cargo audit`, no `unsafe`; no tool searching for time bombs, back doors or hard-coded credentials | ASVS-23 |

**V10.2 Malicious Code Search**

| Req | L | Scope | Requirement (paraphrase) | Status | Evidence checked | Row |
| --- | --- | --- | --- | --- | --- | --- |
| 10.2.1 | 2 | All | No unauthorized phone home | Met | Outbound calls only to operator-configured endpoints (TSA, webhooks, OIDC, SMS gateway, keyd, modeld); modeld on an internal network (`SEC-I09`) | — |
| 10.2.2 | 2 | All | No excessive permissions | Met | Permissions-Policy: `camera=()`, `microphone=()`, `geolocation=(self)` only on pages, for the optional signing location (`web.rs`, GEO-01) | — |
| 10.2.3 | 3 | Ceremony, sealing, keyd | L3: no back doors | Partly | Reviewed for this assessment: no hard-coded credentials or hidden routes found in `routes.rs` (route table equals `api/openapi.yaml` by test); no systematic review recorded | ASVS-23 |
| 10.2.4 | 3 | Ceremony, sealing, keyd | L3: no time bombs | Partly | Engine crates take time as input, never sample it (CLAUDE.md); no systematic scan | ASVS-23 |
| 10.2.5 | 3 | Ceremony, sealing, keyd | L3: no malicious code (salami, logic bypass) | Partly | As 10.2.3 | ASVS-23 |
| 10.2.6 | 3 | Ceremony, sealing, keyd | L3: no Easter eggs | Partly | As 10.2.3 | ASVS-23 |

**V10.3 Application Integrity**

| Req | L | Scope | Requirement (paraphrase) | Status | Evidence checked | Row |
| --- | --- | --- | --- | --- | --- | --- |
| 10.3.1 | 1 | All | Auto-update over secure channels | N/A | No auto-update; operators pull images by digest | — |
| 10.3.2 | 1 | All | Integrity protections (code signing, SRI) | Partly | All web assets self-hosted, vendored pdf.js with a recorded hash (`SEC-C01`); images not signed | ASVS-15 |
| 10.3.3 | 1 | All | Subdomain takeover protection | N/A | DNS is the operator's; the project site is GitHub Pages (`site/`) | — |

### V11 Business Logic

**V11.1 Business Logic Security**

| Req | L | Scope | Requirement (paraphrase) | Status | Evidence checked | Row |
| --- | --- | --- | --- | --- | --- | --- |
| 11.1.1 | 1 | All | Business flows in sequential order | Met | Envelope and recipient state machines (docs/24, `casual-sign-workflow`); `-store/tests/workflow_states.rs` | — |
| 11.1.2 | 1 | All | Realistic timing | Met | Signing order and authentication gates enforced per step (`-server/tests/ceremony_auth.rs` `every_ceremony_endpoint_refuses_before_the_access_code`); OTP resend minimum 30 s | — |
| 11.1.3 | 1 | All | Limits on business actions | Met | Plan quotas (`-store/src/quota.rs`), OTP 5 per hour, envelope size caps (docs/21) | — |
| 11.1.4 | 1 | All | Anti-automation for excessive calls | Met | Per-principal API, per-link and per-address ceremony limits (`-server/tests/threats.rs` `ceremony_calls_are_limited_per_link_and_per_client_address`) | — |
| 11.1.5 | 1 | All | Limits against business risks | Met | Access-code lockout (`-server/tests/threats.rs` `an_access_code_locks_after_the_accounts_attempts...`); voided envelopes open nothing | — |
| 11.1.6 | 2 | All | No TOCTOU or race conditions | Met | Quotas by conditional update (`SEC-U01`); chain head locked; workflow commands transactional | — |
| 11.1.7 | 2 | All | Monitor unusual business events | Not met | Not built (VS-20 operations) | ASVS-13 |
| 11.1.8 | 2 | All | Configurable alerting on automated attacks | Not met | Not built | ASVS-13 |

### V12 Files and Resources

**V12.1 File Upload**

| Req | L | Scope | Requirement (paraphrase) | Status | Evidence checked | Row |
| --- | --- | --- | --- | --- | --- | --- |
| 12.1.1 | 1 | All | Large files refused | Met | 50 MiB per document, 200 MiB per envelope (`Config`, `-server/tests/threats.rs` `an_envelopes_documents_stay_within_the_total...`) | — |
| 12.1.2 | 2 | All | Compressed content checked against uncompressed size | Met | Per-stream and per-document inflate caps (`SEC-P01`, docs/21) | — |
| 12.1.3 | 2 | All | Per-user file quota | Met | Storage gauge per workspace and organization (`-store/src/quota.rs`, `PLAN-04`) | — |

**V12.2 File Integrity**

| Req | L | Scope | Requirement (paraphrase) | Status | Evidence checked | Row |
| --- | --- | --- | --- | --- | --- | --- |
| 12.2.1 | 2 | All | Content validated as the expected type | Met | PDF admission parses and normalizes every upload (docs/30, `SEC-P12` polyglots) | — |

**V12.3 File Execution**

| Req | L | Scope | Requirement (paraphrase) | Status | Evidence checked | Row |
| --- | --- | --- | --- | --- | --- | --- |
| 12.3.1 | 1 | All | Filenames not used by the file system | Met | Blobs stored by content hash (`-store/src/blob/fs.rs`) | — |
| 12.3.2 | 1 | All | Filename metadata validated against traversal | Met | As 12.3.1; names are display metadata only | — |
| 12.3.3 | 1 | All | Filename metadata not executed | Met | As 12.3.1 | — |
| 12.3.4 | 1 | All | Reflective file download | Partly | No `Content-Disposition` on downloads or JSON responses | ASVS-10 |
| 12.3.5 | 1 | All | File metadata not passed to OS commands | Met | No shell or system call takes a filename | — |
| 12.3.6 | 2 | All | No functionality from untrusted sources | Met | No remote includes; modeld loads only manifest-listed files (`SEC-I04`) | — |

**V12.4 File Storage**

| Req | L | Scope | Requirement (paraphrase) | Status | Evidence checked | Row |
| --- | --- | --- | --- | --- | --- | --- |
| 12.4.1 | 1 | All | Uploads stored outside the web root | Met | Blob store separate from `webapp/`, which is read into memory at start (`web.rs`) | — |
| 12.4.2 | 1 | All | Uploads scanned for malware | Met | Every upload (documents, template documents, signer attachments, adopted signature images, saved profile marks) is streamed to ClamAV's clamd (`INSTREAM`, its own container, Compose profile `production`) before it is read or stored, outside any database transaction; a bulk send scans its template's documents again; malware refused `422 CS-SCAN-0001` and recorded in the admin log, fail closed (`503 CS-SCAN-0002`) with an operator switch (`-server/src/scan.rs`, `tests/malware.rs` with EICAR against a fake clamd, and a real one where `OPENSEAL_TEST_CLAMD_ADDR` is set (not yet in CI, `SCAN-04`), seen red 2026-11-14; docs/07 `SEC-P17`). Scanning is on when the operator sets `OPENSEAL_CLAMD_ADDR` (docs/65 §Malware scanning); PDFs are still normalized (`SEC-P08`, `SEC-P12`) | ASVS-11 (Done) |

**V12.5 File Download**

| Req | L | Scope | Requirement (paraphrase) | Status | Evidence checked | Row |
| --- | --- | --- | --- | --- | --- | --- |
| 12.5.1 | 1 | All | Only known file extensions served | Met | `content_type` allow list in `web.rs` (`only_the_web_apps_kinds_of_file_are_served`) | — |
| 12.5.2 | 1 | All | Uploaded files never executed as HTML/JS | Met | Served as `application/pdf` with `nosniff` and `default-src 'none'` | — |

**V12.6 SSRF Protection**

| Req | L | Scope | Requirement (paraphrase) | Status | Evidence checked | Row |
| --- | --- | --- | --- | --- | --- | --- |
| 12.6.1 | 1 | All | Outbound allow list (SSRF) | Met | Webhook address policy with operator allow-list ranges (`-worker/src/webhook.rs`); other endpoints from configuration only | — |

### V13 API and Web Service

**V13.1 Generic Web Service Security**

| Req | L | Scope | Requirement (paraphrase) | Status | Evidence checked | Row |
| --- | --- | --- | --- | --- | --- | --- |
| 13.1.1 | 1 | All | Same parsers across components | Met | One JSON library (`serde_json`), one PDF reader shared by server, worker and WASM verifier (`tools/wasm-parity.sh`) | — |
| 13.1.2 | 3 | — | Deleted in 4.0.3 (duplicate of 4.3.1) | Deleted | — | — |
| 13.1.3 | 1 | All | API URLs expose no secrets | Partly | `/api/v1` takes credentials in headers or cookies only; the ceremony path carries the link token (3.1.1) | ASVS-20 |
| 13.1.4 | 2 | All | Authorization at URI and resource level | Met | Route guard plus per-object tenancy check | — |
| 13.1.5 | 2 | All | Unexpected content types rejected | Met | Ceremony: state-changing calls must be `application/json` (`ceremony.rs`); `/api/v1` refuses any other media type, or a body without one, with `415 CS-API-0007` (`http.rs` `json_only`; the token endpoint's RFC 6749 form and a raw PDF upload named per route; `routes::tests::api_v1_refuses_a_body_that_is_not_json`) | ASVS-09 |

**V13.2 RESTful Web Service**

| Req | L | Scope | Requirement (paraphrase) | Status | Evidence checked | Row |
| --- | --- | --- | --- | --- | --- | --- |
| 13.2.1 | 1 | All | Only valid HTTP methods enabled | Met | Each route registered with one method (`routes.rs` `r(...)`); others answer 405 | — |
| 13.2.2 | 1 | All | JSON schema validation before accepting input | Met | Typed `serde` structs with `deny_unknown_fields`; OpenAPI contract test | — |
| 13.2.3 | 1 | All | Cookie-based REST protected from CSRF | Met | CSRF token header on every changing staff request; ceremony `SameSite=Strict` and JSON-only | — |
| 13.2.4 | 3 | — | Deleted in 4.0.3 (duplicate of 11.1.4) | Deleted | — | — |
| 13.2.5 | 2 | All | REST services check the incoming Content-Type | Met | As 13.1.5 | ASVS-09 |
| 13.2.6 | 2 | All | Messages trustworthy in transit | Met | HTTPS at the edge with HSTS; webhook payloads HMAC-signed (`SEC-W02`); keyd requests over mTLS | — |

**V13.3 SOAP Web Service**

| Req | L | Scope | Requirement (paraphrase) | Status | Evidence checked | Row |
| --- | --- | --- | --- | --- | --- | --- |
| 13.3.1 | 1 | All | XSD validation of SOAP/XML services | N/A | No XML web services | — |
| 13.3.2 | 2 | All | WS-Security signed payloads | N/A | No SOAP | — |

**V13.4 GraphQL**

| Req | L | Scope | Requirement (paraphrase) | Status | Evidence checked | Row |
| --- | --- | --- | --- | --- | --- | --- |
| 13.4.1 | 2 | All | GraphQL query limits | N/A | No GraphQL | — |
| 13.4.2 | 2 | All | GraphQL authorization at business layer | N/A | No GraphQL | — |

### V14 Configuration

**V14.1 Build and Deploy**

| Req | L | Scope | Requirement (paraphrase) | Status | Evidence checked | Row |
| --- | --- | --- | --- | --- | --- | --- |
| 14.1.1 | 2 | All | Secure, repeatable build and deploy | Partly | Pinned toolchain (`rust-toolchain.toml`), `--locked` builds, images pinned by digest; images not signed | ASVS-15 |
| 14.1.2 | 2 | All | Compiler protections and warnings | Met | Memory-safe Rust; `overflow-checks = true` in release; clippy `-D warnings` in CI | — |
| 14.1.3 | 2 | All | Server configuration hardened | Partly | Security headers on every response; production hardening left to docs/65 checklist without a hardened template | ASVS-19 |
| 14.1.4 | 2 | All | Automated redeployment and recovery | Met | `docker-compose.yml`, release workflow; `migrate` step (docs/65 §Upgrades) | — |
| 14.1.5 | 3 | Ceremony, sealing, keyd | L3 (sealing, keyd): integrity of security-relevant configuration verifiable | Not met | keyd's allow list, client CA and trust anchors are files with no recorded digest; console changes to TSA and seal profile are two-person (`SEC-X05`, designed) | ASVS-24 |

**V14.2 Dependency**

| Req | L | Scope | Requirement (paraphrase) | Status | Evidence checked | Row |
| --- | --- | --- | --- | --- | --- | --- |
| 14.2.1 | 1 | All | Components up to date | Met | `cargo audit --deny warnings`, `cargo deny` advisories; ignores recorded with reasons (`DEP-04`, `DEP-05`) | — |
| 14.2.2 | 1 | All | Unneeded features and samples removed | Met | Web app test folders and Node manifests skipped at load (`web.rs` `SKIP_DIRS`); mock mode only on a loopback host (`webapp/api.js`) | — |
| 14.2.3 | 1 | All | External assets with SRI | Met | No external assets: CSP `default-src 'self'`; fonts and pdf.js vendored | — |
| 14.2.4 | 2 | All | Components from trusted repositories | Met | `cargo deny check sources` (crates.io only, `deny.toml`) | — |
| 14.2.5 | 2 | All | SBOM maintained | Partly | SBOM attached to release images (`release.yml` `--sbom=true`); none for the source tree or the web app's vendored files | ASVS-15 |
| 14.2.6 | 2 | All | Third-party libraries sandboxed | Met | ONNX Runtime and OCR inside modeld only; Office conversion in a separate container (`SEC-P13`); pdf.js in a worker | — |

**V14.3 Unintended Security Disclosure**

| Req | L | Scope | Requirement (paraphrase) | Status | Evidence checked | Row |
| --- | --- | --- | --- | --- | --- | --- |
| 14.3.1 | 3 | — | Deleted in 4.0.3 (duplicate of 7.4.1) | Deleted | — | — |
| 14.3.2 | 1 | All | Debug modes off in production | Met | Release builds; mock API mode refused off loopback (`webapp/api.js`); dev key needs explicit consent (`CS-KEY-0004`) | — |
| 14.3.3 | 1 | All | No version information in headers | Met | No `Server` or `X-Powered-By` header set (`http.rs`) | — |

**V14.4 HTTP Security Headers**

| Req | L | Scope | Requirement (paraphrase) | Status | Evidence checked | Row |
| --- | --- | --- | --- | --- | --- | --- |
| 14.4.1 | 1 | All | Every response has Content-Type with charset | Met | JSON `application/json`, pages `text/html; charset=utf-8` (`web.rs`), PDFs `application/pdf` | — |
| 14.4.2 | 1 | All | API responses carry `Content-Disposition` | Not met | Not set | ASVS-10 |
| 14.4.3 | 1 | All | CSP in place | Met | API `default-src 'none'; frame-ancestors 'none'`; pages `PAGE_CSP` (`web.rs`; `-server/tests/web.rs`) | — |
| 14.4.4 | 1 | All | `X-Content-Type-Options: nosniff` on all responses | Met | `http.rs`; `-server/tests/threats.rs` `assert_security_headers` | — |
| 14.4.5 | 1 | All | HSTS on all responses | Met | `max-age=63072000; includeSubDomains` (`http.rs`) | — |
| 14.4.6 | 1 | All | Referrer-Policy | Met | `no-referrer` (`http.rs`) | — |
| 14.4.7 | 1 | All | Not embeddable by third parties | Met | `frame-ancestors 'none'` and `X-Frame-Options: DENY` | — |

**V14.5 HTTP Request Header Validation**

| Req | L | Scope | Requirement (paraphrase) | Status | Evidence checked | Row |
| --- | --- | --- | --- | --- | --- | --- |
| 14.5.1 | 1 | All | Only methods in use accepted | Met | As 13.2.1 | — |
| 14.5.2 | 1 | All | Origin header not used for access control | Met | Not read by `auth.rs` or `ceremony.rs` | — |
| 14.5.3 | 1 | All | CORS strict | Met | No CORS grant anywhere: no `Access-Control-Allow-Origin` header is emitted (`ceremony.rs` relies on this) | — |
| 14.5.4 | 2 | All | Proxy-added headers authenticated | Met | `Forwarded`/`X-Forwarded-For` believed only from configured trusted proxies (`-server/src/net.rs`) | — |
