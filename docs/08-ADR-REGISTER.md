# 08 — ADR register

ADR ids here are this repository's own; the sisters' are always cited as "OpenCalc's ADR-n" or "OpenPresent's ADR-n".
ADR-001 to ADR-009 are Accepted on the owner's "proceed" of 2026-11-10 (instruction 6); ADR-005 and ADR-006 still have their spikes (`SPK-01`, `SPK-02`) confirm the library choice, and change only by a superseding ADR. **Proposed unless marked.** Status moves to Accepted when the owner agrees, or when the spike named in the row confirms
it.

**Write an ADR when a decision touches:** public API; a crate boundary or the DAG; a persisted or wire format; the
envelope state machine; the audit event schema; cryptographic algorithms, libraries or key custody; what enters the
WASM bundle; a new dependency in the engine; a legal or evidence property.

| ADR | Decision | Status | Reasoning in |
| --- | --- | --- | --- |
| ADR-001 | Crates `casual-sign-*`; product OpenSeal (`DEC-01`) | Accepted | [52](52-COMPETITOR-STUDY.md) §Name collision |
| ADR-002 | Follow the sisters' layered engine and host split; the server is a first-class host | Accepted | [02](02-HLD.md) §2 |
| ADR-003 | Separate repo; copy from OpenCalc and OpenPresent with provenance | Accepted | [19](19-WORKSPACE-SCAFFOLD-DESIGN.md) |
| ADR-004 | Engine purity: time, randomness, keys, fonts, trust lists and network answers are supplied values | Accepted | [02](02-HLD.md) §6 |
| ADR-005 | Our own bounded PDF reader and incremental writer in `casual-sign-pdf`; `lopdf` (MIT, no default features) only as a test oracle; `pdf-rs` rejected. `lopdf` cannot be bounded by a caller for four docs/07 controls (no cancellation, no per-document decode budget, no object cap, silent 0-page results on cycles and deep nesting), has fixed limits, and pulls `getrandom` into WASM; `pdf-rs` has unbounded Flate, no recovery and drops `/Prev` | Accepted; confirmed by `SPK-01` ([64](64-SPK-01-PDF-READER.md)) | [30](30-PDF-PIPELINE.md) §2 |
| ADR-006 | Crypto: `aws-lc-rs` for private-key operations and hashing in hosts; RustCrypto (`der` 0.8 generation: `spki`, `x509-cert`, `cms =0.3.0-rc.2`, `x509-tsp =0.2.0-rc.0`, `x509-ocsp =0.3.0-rc.1`, `sha2`, `p256`, `p384`) for structures and for WASM verification; `rsa` for verification in WASM only (no advisory ignore needed, `DEP-02`); `cmpv2` and `crmf` 0.3.0-rc.0 arrive through `x509-tsp`; hosts verify RSA with `aws-lc-rs`; ESS `SigningCertificateV2` is our own type in `-crypto`; the verifier hashes signed attributes exactly as received. Decrypting password-protected **input** only (never to protect anything) uses RustCrypto `aes`, `cbc`, `rc4` 0.2, `md-5`, `sha2`, with `stringprep` (SASLprep for R5/R6 passwords) and `zeroize`; Algorithm 2.B uses AES-128-CBC in the encrypt direction only as a hash step. FIPS is a separate build profile (`DEC-14`). No `rsa` private-key operations; no MPL `cryptographic-message-syntax` | Accepted; confirmed by `SPK-02` ([66](66-SPK-02-CRYPTO-STACK.md)), with these amendments | [31](31-SEALING-AND-SIGNATURES.md) §8 |
| ADR-007 | Browsers render PDFs with vendored pdf.js (Apache-2.0) in a worker, scripting off; the engine never rasterizes | Accepted | [30](30-PDF-PIPELINE.md) §10 |
| ADR-008 | Default seal: one platform PAdES B-T signature at completion over flattened documents, certificate and embedded audit JSON | Accepted | [31](31-SEALING-AND-SIGNATURES.md) §3 |
| ADR-009 | Key custody in a separate `keyd` process that signs DER signed attributes only (hashes and certificate ids, never document bytes), so FIPS-approved `sign` APIs apply (`SPK-02`) | Accepted | [31](31-SEALING-AND-SIGNATURES.md) §5 |
| ADR-010 | Audit events: JCS canonical JSON, SHA-256 hash chain per envelope, committed with the state change | Accepted (owner, 2026-11-11, instruction 12) | [32](32-AUDIT-TRAIL-AND-EVIDENCE.md) |
| ADR-011 | Workflow as a pure command function returning state, events and effects; effects run as idempotent jobs | Accepted (owner, 2026-11-11, instruction 12) | [24](24-ENVELOPE-LIFECYCLE-AND-ROUTING.md) §1 |
| ADR-012 | PostgreSQL as the only required stateful service besides the object store; job queue in Postgres; Redis optional | Accepted (owner, 2026-11-11, instruction 12) | [02](02-HLD.md) §9 |
| ADR-013 | Tenancy: `account_id` on every row, scoped repository, RLS as second line | Accepted (owner, 2026-11-11, instruction 12) | [22](22-DATA-MODEL.md) §9 |
| ADR-014 | Server stack: `axum`, `tokio`, `sqlx` 0.9 (compile-time checked queries with a committed offline cache, `SQLX_OFFLINE`; instruction 14), `tower`; copied conventions from OpenCalc's servers | Accepted (owner, 2026-11-11, instruction 12) | [19](19-WORKSPACE-SCAFFOLD-DESIGN.md) |
| ADR-015 | Public API: envelope-centric REST `/api/v1`, OpenAPI 3.1, RFC 9457 errors, idempotency keys, cursor pagination | Accepted (owner, 2026-11-11, instruction 12) | [40](40-API-DESIGN.md) |
| ADR-016 | Webhooks signed per Standard Webhooks; at-least-once; no documents in payloads | Accepted (owner, 2026-11-11, instruction 12) | [40](40-API-DESIGN.md) §4 |
| ADR-017 | Embedding through iframe views and custom elements wrapping them, not shadow-root mounting | Accepted (owner, 2026-11-11, instruction 12) | [40](40-API-DESIGN.md) §5 |
| ADR-018 | Web app: vanilla ES modules, no framework or bundler, command registry, copied from the sisters | Accepted (owner, 2026-11-11, instruction 12) | [47](47-UX-AND-FEATURE-MAP.md) |
| ADR-019 | Field geometry stored in displayed page space (points, top-left); one conversion function shared by WASM and native | Accepted (owner, 2026-11-11, instruction 12) | [30](30-PDF-PIPELINE.md) §4 |
| ADR-020 | WYSIWYS: signers review engine-flattened output before finishing | Accepted (owner, 2026-11-11, instruction 12) | [02](02-HLD.md) §6 |
| ADR-021 | Document conversion through a sandboxed `Converter` sidecar; sister engines first, LibreOffice container fallback | Accepted (owner, 2026-11-11, instruction 12) | [30](30-PDF-PIPELINE.md) §3 |
| ADR-022 | Formulas: a small total expression language with decimal arithmetic, evaluated identically in browser and server | Accepted (owner, 2026-11-11, instruction 12) | [30](30-PDF-PIPELINE.md) §6 |
| ADR-023 | Engine dependencies outside crypto: `miniz_oxide` (Flate inflate and deflate, streaming, MIT/Apache/Zlib) in `-pdf`; `regex` (finite automata, linear time, MIT/Apache), `unicode-normalization` and `rust_decimal` (MIT/Apache) in `-fields` and `-model`; `serde` (MIT/Apache) for the model's wire form. Each compiles to wasm32 and passes `deny.toml` | Accepted (owner, 2026-11-11, instruction 12) | [19](19-WORKSPACE-SCAFFOLD-DESIGN.md) |
| ADR-024 | Flattening dependencies: `skrifa` (font metrics), `png`, `zune-jpeg` (MIT/Apache/Zlib), and a TrueType subsetter copied from OpenPresent rather than the `subsetter` crate; fonts are host-supplied bytes, never OS lookups, so the crate builds for wasm32 | Accepted (owner, 2026-11-11, instruction 12) | [30](30-PDF-PIPELINE.md) §7 |
| ADR-025 | Multi-select list fields: `FieldType::MultiSelect` (`multi_select`) with `FieldValue::Choices` (at most 500 distinct options, each one of the field's); additive to the persisted field format; converted from AcroForm list boxes with the multi-select flag | Accepted (owner, 2026-11-11, instruction 16) | [22](22-DATA-MODEL.md) §6, [30](30-PDF-PIPELINE.md) §5 |
| ADR-026 | XFA layout (`XFA-01`): dynamic-only XFA forms are laid out by our own engine crate `casual-sign-xfa` into static pages before normalization, with **our own bounded XML reader** rather than `quick-xml`: XFA needs elements, attributes, text, CDATA and the five predefined entities, and must refuse DTDs and entities outright and bound depth, nodes and attributes itself; a small iterative reader (about 400 lines, unit and hostile tests) is easier to prove bounded than a general crate configured to refuse. No new dependency: `skrifa` and `miniz_oxide` are already in the tree (ADR-023/024); the subsetter is copied from `-flatten`. No XFA script (FormCalc, JavaScript) is ever run | Accepted (owner, 2026-11-12, instruction 23) | [30](30-PDF-PIPELINE.md) §3 |
| ADR-027 | Envelope lists (`WEB-08`): removing an envelope that ended without completing is a workflow command (`DeleteEnded`) recording a new audit type `envelope.deleted` and the state's `deleted_at` (additive, absent when unset), never a purge; a staff attachment download records a new access type `attachment.downloaded` `{field_id, hash}`. Both additive to the event schema of ADR-010 (earlier chains hash unchanged; earlier verifiers list the types as unrecognised, not failed) | Accepted (owner, 2026-11-12, instruction 23) | [24](24-ENVELOPE-LIFECYCLE-AND-ROUTING.md) As built, [32](32-AUDIT-TRAIL-AND-EVIDENCE.md) §3, [40](40-API-DESIGN.md) As built `WEB-07`, `WEB-08` |
| ADR-028 | Organizations, workspaces, delegated administration, platform console and plans (`ORG-01`, `CON-01`, `PLAN-01`; owner instructions 24, 25, 29; the adversarial review's findings folded in, docs/23 §13). **(a) Tenancy:** a new `organizations` table sits above `accounts`; every account (a **workspace** on screen; `account` stays in the database and API v1) belongs to one organization through `accounts.organization_id NOT NULL`, which a trigger keeps unchanged except through one operator two-person function owned by a role nothing else can assume (`ORG-20`); the application role loses INSERT on `accounts` (workspaces are created by definer functions) and may UPDATE only `name`, `settings`, `data_region`. Every content table keeps its single-account RLS policy. A second setting, `openseal.organization_id`, is read by `openseal_current_org()`, which is NULL whenever an account is set. Organization reach is `FOR SELECT` policies on `accounts`, `account_memberships` and `users` (never `password_hash`), plus definer functions; organization writes into a workspace go through a `WorkspaceOf` proof and an ordinary single-account transaction. **(b) Identity:** the shared `users` row changes only by the person, by an organization whose verified domain covers the email, or by a workspace admin while that workspace is the person's only membership; a password or MFA change revokes sessions in every workspace (`SEC-ID-01`'s fix, in progress, implements the person and sole-membership rules; the domain and platform rules arrive with `ORG-11` and `CON-04`). IdP bindings move to `user_identities`; an IdP signs in only identities of its organization's verified domains. **(c) Policy:** each organization key has a value and a `locked` flag; security keys only tighten in a workspace; the effective policy is a pure function in a new Host crate `casual-sign-policy`. **(d) Roles:** organization owner, admin and delegated admin; workspace permission profiles split into named actions, delegated admins optionally limited to groups; one `grantable()` (granted ⊆ held, no self-grants) on every grant path; IdPs, SSO enforcement and loosening security are owner-only; sensitive workspace actions need a fresh sign-in, are bounded by organization floors and never group-scoped. Organization admins read agreements only by joining a workspace, recorded and notified (delegated admins cannot). **(e) Moves:** envelopes never change workspace; ownership transfers within one; a completed agreement's evidence package can be exported and imported read-only as an archived agreement (not an envelope); templates are copied by an organization-scope operation. **(f) Console:** a separate binary `casual-sign-console` on its own private listener, origin and cookie, with `operators` in a `platform` schema, mandatory TOTP, a hash-chained operator log copied into organization logs, and a two-person rule enforced by definer functions over insert-only approvals. It connects as `openseal_console`, with no grant on any `public` table, and depends on `casual-sign-platform-store`, `casual-sign-policy`, `casual-sign-audit`, `casual-sign-secrets` and a split `casual-sign-keyd-client`, never on `-store`, `-host` or `-server`. No impersonation; the console never holds a private key; keyd gains read-only admin operations behind a second allow-list. **(g) Plans:** versioned entitlements and quotas per organization with overrides; an append-only ledger and counters per workspace and per organization, consumed atomically by one definer function; enforcement only on actions that create something (`CS-PLAN-*`); **a sent envelope always completes and seals** whatever the quota, suspension or archive; usage export CSV or JSON; billing later as a plugin. **(h) Engine:** one workflow command (`Transfer`) and two audit types (`envelope.transferred`, access `envelope.exported`), additive to ADR-010 as ADR-027 was; nothing else enters an engine crate or WASM. **(i) Operations:** ops listeners (`/livez`, `/readyz`, `/metrics`) on server, worker and console, keyd health over its own protocol, OpenTelemetry behind a feature | Accepted (owner, 2026-11-12, instruction 29) | [23](23-ORGANIZATIONS-WORKSPACES-AND-CONSOLE.md) |
| ADR-029 | **The ML model seam (`ML-01`) and how models are hosted.** Pretrained models only, no training (owner instructions 27, 28, 30). They run in a new server-layer process, `casual-sign-modeld` (`ML-09`), never in `crates/`; the engine stays pure and wasm32. modeld is built like keyd: TLS 1.3 mutual TLS on `rustls` with `aws-lc-rs`, length-prefixed bounded binary frames, and an op log of counts and ids only. **Every inference dependency is optional behind modeld's `server` feature**, which only its binary requires; the worker links modeld with `default-features = false` and gets the wire format and client only, so the secret-holding worker never links the inference stack (`SEC-I14`). modeld holds no database, SMTP, webhook or keyd credentials and runs on an internal network with no egress. The worker calls it from new advisory job kinds, `analyze_document` and `fingerprint_template`, whose idempotency keys carry the account and document id (`SEC-I06`). Those jobs are not workflow effects and touch no envelope state, so turning the features off enqueues nothing. Inference uses ONNX Runtime 1.28.x (MIT, bundling Eigen MPL-2.0 and Boost BSL-1.0, which owner instruction 32 allows inside that unmodified binary in the modeld image only, shipped with its ThirdPartyNotices), pinned by SHA-256, through `ort =2.0.0-rc.13` (MIT OR Apache-2.0) with `default-features = false` and `load-dynamic`, CPU only, fixed thread count. That rc is the exact version required by `oar-ocr =0.10.2` (Apache-2.0), which supplies the PaddleOCR pipeline with `default-features = false` (its defaults download ONNX Runtime at build) and `auto-download` off. GLiNER span decoding (extraction and personal data) is our own code on the same `ort`, not `gline-rs`, which requires `=rc.9`. `tokenizers =0.23.2` runs with `default-features = false`; Oniguruma (C) still comes in through `oar-ocr-core` and is fuzzed. Third-party `tracing` events below WARN from `oar_ocr*`, `ort`, `hayro*` and `tokenizers` are dropped whatever `RUST_LOG` says, because `oar-ocr` logs recognised text at debug (`SEC-I05`). Pages are rasterised by `hayro` 0.8.0 (Apache-2.0 OR MIT; the crate forbids `unsafe`, its dependencies do not) in a per-document child process of modeld that can be killed alone, with pixel, decoded-data, address-space and time caps; the slot count is derived from memory. ADR-007 is unchanged: the engine still never rasterises. Personal data is found first by deterministic recognisers in a new pure engine crate `casual-sign-pii` (engine dependency `phonenumber` =0.3.10, Apache-2.0; it builds for wasm32, so the crate exists (`ML-08`, 2026-11-12); `email_address` and `iban_validate` proved unneeded, docs/33 §5.4), then optionally by GLiNER-PII in modeld. Models: PP-OCRv6 small (det, rec) with operator-chosen PP-OCRv5 script packs; multilingual-e5-small (fp32, CPU-portable) plus dHash/pHash for template matching; GLiNER `gliner_multi-v2.1` (int8 export of our own) for extraction; knowledgator `gliner-pii-base-v1.0` (English only) as the optional personal-data layer. Weights are pinned by SHA-256 and revision in a committed manifest, each with a licence on `deny.toml`'s allow list, checked by the fetch script only (no new CI gate). They are fetched at image build, never at run time; exports from pickle load only with `weights_only=True` from a hash-pinned file; modeld refuses to start on a mismatch and never loads pickle. Each feature is off by default and enabled per workspace when the plan entitles it (`PLAN-01`). Outputs are suggestions a person accepts. They never enter the sealed document, the audit chain or the evidence, and each records model id, weight hash and runtime version. **Rejected:** `ort` inside the worker (a C++ runtime and hostile rasters next to every secret, OCR starving sealing and email jobs, no way to stop a hung run without killing the worker); a Python model service with Presidio, spaCy and onnxruntime (outside cargo-deny, a second toolchain, a large image; tldextract fetches the Public Suffix List over the network by default); PaddlePaddle at run time (heavy framework, downloads from model hubs; used offline only to export script packs); `tract-onnx` as the main runtime (slower, patchy int8; kept as a fallback); `fastembed` (downloads from the HF hub at run time); PDFium as the default rasteriser (C++ with a CVE history; kept as a sandboxed fallback under `PDF-REN-01`); the AVX-512-only int8 e5 file; openai/privacy-filter (over the memory cap). **Recorded fallback:** a Python Presidio sidecar under the same mTLS and no-egress rules, only if the Rust personal-data recognisers miss ML-08's detection-rate gate. **Open:** reliance on weight licences where training data is non-commercial or undisclosed (D13, docs/09 §8), and `ML-06` (docs/33 §5.8) | Accepted (owner, 2026-11-12, instruction 30), with the adversarial review's defects fixed (docs/33 §16) | [33](33-ML-MODELS.md) |
| ADR-030 | **A draft's edits get their own audit type** (`WEB-14`). The engine's `Edit` (a draft's edits, including the one the server issues inside create) records a new type `envelope.edited` `{changed}` (the same paths `envelope.corrected` carries) instead of `envelope.corrected`, which then means only a change after `envelope.sent`, as docs/24 §2 and docs/32 §3 state. Every observable change still emits an event (the engine's property tests). `envelope.edited` is not a milestone, a webhook topic or a notice; the sender's audit list shows it, a signer's history does not. Additive to the event schema of ADR-010, as ADR-027 was: earlier chains hash unchanged, an earlier verifier lists the type as unrecognised, not failed, and a reader of an earlier chain treats an `envelope.corrected` before the first `envelope.sent` as a draft edit. The mock records the same. Until Accepted, the server shows a signer milestones only from the first `envelope.sent` | Proposed | [24](24-ENVELOPE-LIFECYCLE-AND-ROUTING.md) As built, [32](32-AUDIT-TRAIL-AND-EVIDENCE.md) §3 |
| ADR-031 | **Restoring a deleted envelope is a workflow command with its own audit type** (`UXW-02`). An envelope that ended without completing and was removed from the lists (`DeleteEnded`, `envelope.deleted`, `WEB-08`) is brought back by a new engine command `RestoreDeleted`, allowed only while it is deleted and only to a member who may see it with `envelopes:write`, recording a new type `envelope.restored` `{}` (actor the member) and clearing `deleted_at`. Nothing in the agreement changes: documents, chain, certificate and evidence are as they were; the event only records that it is listed again, so the trail shows both removals and returns. Not a milestone, a webhook topic or a notice; the sender's audit list shows it, a signer's history does not. Additive to the event schema of ADR-010, as ADR-027 and ADR-030 were: earlier chains hash unchanged, an earlier verifier lists the type as unrecognised, not failed. "Within retention": a purged envelope cannot be restored (`409 CS-WF-0001`). *Built* (`UXW-43`, slice 6): the engine command, `POST /envelopes/{id}/restore` (`envelopes.write`, `If-Match` optional), `deleted_at` on the envelope and the Deleted view's items, the web app's Deleted view with Restore (`list.restore`) and Restore on a deleted envelope's page; `NOT_ON_SERVER.restoreEnvelope` removed | Accepted (owner instruction 77, 2026-11-20) | [24](24-ENVELOPE-LIFECYCLE-AND-ROUTING.md) As built, [32](32-AUDIT-TRAIL-AND-EVIDENCE.md) §3, [40](40-API-DESIGN.md) |
| ADR-032 | **A signer clearing a value before finishing is a workflow command with its own audit type** (`UXW-35`). While a recipient's required action is open, the recipient removes the value they set on a field assigned to them (a signature, initials, text, a check, an attachment) through `DELETE /s/{token}/fields/{field}`, only after every required authentication and, where the account requires it, consent (as every ceremony write, `SEC-CER-01`). A new engine command `ClearFieldValue` records a new type `recipient.field_cleared` `{field_id}` (actor the recipient; never the value, which the earlier field event's hash already binds) and leaves the field empty, so a required field must be filled again before finishing. A finished recipient, a field of another recipient, a read-only or prefilled sender value, or an envelope that is not in progress is `409 CS-WF-0001`. Not a milestone, a webhook topic or a notice; the sender's audit list and the recipient's history show it. Additive to the event schema of ADR-010, as ADR-027, ADR-030 and ADR-031 are: earlier chains hash unchanged, an earlier verifier lists the type as unrecognised, not failed. The mock already records it. Until Accepted, the server does not serve the endpoint (`NOT_ON_SERVER.clearField`) | Proposed | [24](24-ENVELOPE-LIFECYCLE-AND-ROUTING.md), [32](32-AUDIT-TRAIL-AND-EVIDENCE.md) §3, [40](40-API-DESIGN.md) |
| ADR-033 | **A signer's sign-in through an identity provider is bound by verified email and recorded as issuer plus subject hash** (`RAUTH-01`, slice 5). `sso` is met through one of the operator's OpenID Connect providers (`OPENSEAL_RECIPIENT_IDPS_FILE`, not per account until slice 10's SSO configuration): authorization code with PKCE S256, `state` (stored hashed) and `nonce`, each sign-in used once. The ID token must be signed by the provider's JWKS with an asymmetric algorithm, name its issuer and our client, be unexpired by the server's clock, carry the nonce, and assert a verified email equal to the recipient's, which is what makes any account at a trusted provider prove *this* recipient. Public API: `POST /s/{token}/sso` and `/sso/verify`, the view's `sso_providers` and `sso_authorization_url`, `CS-API-0016`. Audit schema: `recipient.auth_passed` gains an optional `identity {issuer, subject_sha256}`, present only for `sso`, absent from the wire otherwise so earlier chains hash unchanged (additive to ADR-010, as ADR-027 and ADR-030 to ADR-032); the engine's `AuthResult` carries it and refuses an `sso` pass without it. The subject is never recorded, only its hash. Built in q-VS-05 and served only where the operator configures providers; the owner's acceptance is still needed | Accepted (owner instruction 54, 2026-11-17) | [07](07-SECURITY-THREAT-MODEL.md) SEC-A14, [32](32-AUDIT-TRAIL-AND-EVIDENCE.md) §3, [40](40-API-DESIGN.md) §6, [65](65-RUNNING-IT.md) |
| ADR-034 | **One JSON log line and a typed security event log, shipped by the container runtime** (`ASVS-08`). A new host crate `casual-sign-seclog` (depends on `-secrets` only; native only) gives every host process one line format: a JSON object per line on standard error, `ts`, `level`, `service`, `event` first. Security events are `"event":"security"` with a closed `Kind` taxonomy (19 kinds, each naming the services that emit it; a 20th, `alert.abnormal_activity`, added by `ASVS-13` within this decision: the server's abnormal-activity alert, same typed fields, docs/65 §Abnormal activity; a 21st and 22nd, `auth.reauthenticate` and `auth.session_end`, by `ASVS-07` and `ASVS-06` likewise; a 23rd, `auth.mfa_remove`, by `ASVS-32` and `CON-13`), an `outcome`, and fields that are typed so no free text enters: `Uuid` ids, `&'static str` codes and words, `Label` (`[A-Za-z0-9._-]{1,64}`), and for an identifier presented before a principal is known (an e-mail, a client address, a client id) a `Pseudonym`: HMAC-SHA-256 (aws-lc-rs, ADR-006) under `OPENSEAL_LOG_PSEUDONYM_KEY`, truncated to 128 bits, `p1:` prefixed and domain-separated, so the log alone cannot be reversed with a dictionary while attempts still correlate. Security events bypass `RUST_LOG`. The processes open no log socket: forwarding is the runtime's (Docker's `syslog` driver over mutual TLS in `deploy/compose.log-forwarding.yml`; a node agent on Kubernetes), so no network client, retry queue or credential enters the binaries. keyd's `RemoteKey` gains an optional failure hook so the worker can log keyd's refusals with their code. Rejected: `tracing-subscriber`'s `json` feature (adds `tracing-serde`, and cannot type the fields), an unkeyed hash of the e-mail (reversible by dictionary), shipping from inside the processes (a second transport and its secrets in every binary) | Accepted (owner instruction 50, 2026-11-14) | [65](65-RUNNING-IT.md) §Logs, [07](07-SECURITY-THREAT-MODEL.md) SEC-D06, [19](19-WORKSPACE-SCAFFOLD-DESIGN.md) |
| ADR-035 | **Conditional routing and signing groups: a `skipped` recipient status and three audit types** (`WF-01`, slice 29). *Rules.* An envelope carries `routing_rules`, at most one per recipient: `{id, recipient_id, match: all\|any, conditions: [{label, op, value?}]}`; the recipient is included only when the conditions hold. Operators `eq`, `ne`, `gt`, `ge`, `lt`, `le` (numeric when both sides read as numbers under the `-fields` number grammar, otherwise exact text), `one_of`, `checked`, `unchecked`, `filled`, `empty`. A condition's label is a data field assigned to a recipient with a lower routing order, so its value is final when read; at least one signer or approver has no rule; otherwise the send is refused (`422 CS-WF-0024`). *Evaluation.* In the decision where routing reaches the recipient's order, from completed values only, the engine records `routing.evaluated` `{rule_id, recipient_id, inputs: [{label, value_hash}], result: include\|skip}` (value hashes as `recipient.signed` binds them, `null` for an empty value; never the value), and on `skip` `recipient.skipped` `{recipient_id, rule_id}` and the new terminal status `skipped`: not active, never invited, not required for completion; their fields are filled by no one and dropped at completion as hidden fields are (docs/24 §5). An order whose recipients are all skipped is passed in the same decision. A correction may change the rule of a recipient routing has not reached; a skipped recipient stays skipped (the sender adds a new recipient instead). *Signing groups.* A `signer`, `approver` or `viewer` may carry `signing_group`: 2 to 20 members `{member_id, name, email, phone?, delivery}` frozen at send, taken by the server from an account group (`groups`, `group_members`, `UXW-07`) or listed in the request; any other type is `422 CS-WF-0004`. The recipient keeps one status, one set of fields and one set of authentication requirements. Every member is invited with a link of their own (`invitation.sent` gains an optional `member_id`, absent otherwise, so earlier chains hash unchanged). The first member to open their link claims the recipient: `recipient.group_member_acted` `{recipient_id, member_id}` is recorded before `recipient.delivered`, and every later act of the recipient has that member as its actor. Other members' links answer `409 CS-WF-0025` until the claimant chooses finish later (`recipient.finish_later` releases the claim and clears authentication passed) or the sender corrects the recipient. Members' names, emails and phones are personal data classified as a recipient's (docs/07). *Schema.* Additive to the event schema of ADR-010, as ADR-027 and ADR-030 to ADR-032 are: earlier chains hash unchanged, an earlier verifier lists the new types as unrecognised, not failed. None is a milestone, webhook topic or notice; the sender's audit list shows all three, a signer's history none. The certificate lists a skipped recipient as skipped by a routing rule and a group recipient with the member who acted. Limits (docs/21): 50 rules per envelope, 10 conditions per rule, a condition value of 1,024 bytes, 20 values in `one_of`. Until Accepted nothing is recorded or served: the API does not accept `routing_rules` or `signing_group`, and `CS-WF-0024` and `CS-WF-0025` are reserved | Proposed | [24](24-ENVELOPE-LIFECYCLE-AND-ROUTING.md) §4, [22](22-DATA-MODEL.md) §5, [32](32-AUDIT-TRAIL-AND-EVIDENCE.md) §3 |
| ADR-036 | **keyd signs only for envelopes that owe a seal: a database-minted seal token** (`KEYD-02`, `SEC-S05`; touches a wire format and key custody). *Proof.* The database vouches, the worker carries, keyd verifies: `openseal_keyd_seal_token(envelope)` (migration 0040, `SECURITY DEFINER`, granted to `openseal_app`) returns, for an envelope of the transaction's account that is `completing` or declined, voided or expired without its envelope certificate (UXW-30), an expiry ten minutes ahead and an HMAC-SHA-256 over `openseal-keyd-seal-token-v1` LF envelope id LF expiry under a 32-byte key in `openseal_keyd.seal_token_key`, which no application role can read or write (installed by `casual-sign-server migrate` from `OPENSEAL_KEYD_SEAL_TOKEN_KEY`); keyd holds the same key and refuses (`CS-KEY-0015`, recorded, `key.use` refused) a signature without a token valid for the request's envelope id, expired, or expiring more than 15 minutes ahead. HMAC comes from `pgcrypto` in the database and aws-lc-rs in keyd (ADR-006; nothing hand-rolled); no new Rust dependency. *Wire.* Protocol version 1 gains op 7 `sign-digest-sealing` (op 2's fields, then `expires:u64be mac:bytes8`); op 2 stays for a keyd without the key, which warns `seal_token_not_enforced` at start; an older keyd answers op 7 `CS-KEY-0007`, so a new worker fails closed. *Rejected:* keyd reading envelope state from PostgreSQL with its own role (puts keyd on the data network with a database credential and a SQL client, against ADR-009's isolation; keyd sits on the `signing` network only); a token signed by the server when the envelope enters `completing` (the worker also schedules seal jobs after `SealFailed` and seals ended certificates, so it would need the key itself; a long-lived token to survive retries); binding the digest (the worker computes the signed attributes at seal time, so no other party can know it beforehand). *Residual:* a caller with the worker's identity can still have arbitrary digests signed under an envelope that owes a seal while it does, and the application role can move an envelope into `completing` (a trace in the database and the chain); reconciliation (`KEYD-03`) stays the check on what was signed | Accepted (owner instruction 55, 2026-11-17) | [31](31-SEALING-AND-SIGNATURES.md) §5, [07](07-SECURITY-THREAT-MODEL.md) SEC-S05 |
| ADR-037 | **Public anchoring of audit chain heads: a daily per-account RFC 6962 tree, an RFC 3161 token over a statement of its root and size, and two new file formats** (`FG-158`, slice 7, owner instruction 54). *Tree.* Per account and UTC day, one leaf per envelope whose chain gained an event that day: its head as of the day's end, not already anchored, in envelope id order; the existing `merkle` hashing (RFC 6962 leaves and nodes). At most 1,000,000 leaves. *Statement.* The TSA signs `SHA-256("openseal.anchor.v1" ‖ 0x00 ‖ size u64 BE ‖ root)`, so the size an inclusion proof needs comes from the trusted side. The TSAs are the seal's (no new trust or setting); nonce and every token check as for a seal. *Formats (persisted and wire).* `openseal.anchor` v1, the published line (`id, period, tree_size, root, statement, tsa_time, timestamp_token` hex), naming no envelope or account; `openseal.anchor-proof` v1, an envelope's proof (`envelope_id, seq, head, leaf_index, path, anchor`); both canonical JSON (RFC 8785) read by the audit crate's strict parser, at most 256 KiB, token at most 64 KiB. *Storage.* Migration 0041: `chain_anchors` (unique per account and day) and `chain_anchor_leaves` (a head anchored once), insert-only with the audit chain's triggers; `openseal_enqueue_anchor_jobs`, a definer function returning a count. *Publication.* A host-supplied sink; as built, an append-only file (`OPENSEAL_ANCHOR_LOG`) the operator publishes, at least once. *Verification.* Offline, in engine code (`casual_sign_audit::anchor`, `casual_sign_verify::verify_timestamp`, `casual_sign_sdk::anchor`), and `openseal anchor verify`; with the trail, the head must be the trail's event at `seq` (`CS-AUD-0012`). New codes `CS-AUD-0012`, `CS-WRK-0019`. Rejected: one global tree across accounts (one token a day, but a proof would reveal other accounts' tree size and a tenant's anchor would depend on others'); time-stamping the bare root (size untrusted); publishing account ids; the root as the RFC 3161 imprint without domain separation. Claims no legal or regulatory effect for an anchor (docs/09) | Accepted (owner instruction 56, 2026-11-17) | [32](32-AUDIT-TRAIL-AND-EVIDENCE.md) §5, [22](22-DATA-MODEL.md), [07](07-SECURITY-THREAT-MODEL.md) SEC-S06, SEC-S07, [65](65-RUNNING-IT.md) |
| ADR-038 | **An in-profile load balancer, HAProxy, in front of two server replicas** (`HRD-11`). *Why.* A single server meant every restart (token key, object store credentials, upgrades) dropped signer requests; two replicas behind a proxy let one drain while the other serves. *Choice.* HAProxy 3.2, pinned by image digest like every other service (docs/04 rule 31): mature, small, a plain-text config (`deploy/production/haproxy.cfg`), health checks on each replica's ops-listener `/readyz` every second, one connection per request, a refused connection sent to the other replica, nothing that reached a replica retried (no double submit). *Privacy.* It logs no requests: signing links carry bearer tokens (`SEC-D01`). *Scope.* Production profile only; only the proxy publishes a port; `tools/check-deploy.py` enforces it; operators set `OPENSEAL_TRUSTED_PROXIES` to the edge network. *Rejected.* Nginx or Traefik (larger surface for this one job); relying on the operator's edge proxy alone (would leave the profile unable to restart without an outage). *Known gap.* Rate limits and anomaly windows are per replica (`HRD-15`). | Accepted (owner instruction 59, 2026-11-19) | docs/65 §Production deployment, §Rotation |
| ADR-039 | **Personal-data erasure and retention purge never alter evidence** (`ASVS-16`, `ASVS-18`; touches the evidence store and the data model). *Erasure of a member* (`DELETE /users/me`, `POST /users/{id}/erase`): the `users` row is pseudonymised in place by a definer function (`openseal_erase_user`, migration 0045: name `Erased user`, email `erased-<id>@erased.invalid`, login binding, password and second factor removed, `erased_at` set, disabled), because envelopes and the admin log name the id; the member's sessions, saved marks, notices, invitations and password resets here are deleted and their API clients revoked; one admin event `member.erased {identity: pseudonymised}`. Only for a member of this workspace alone (SEC-ID-01), never the last administrator or an organization administrator. *What stays:* audit events (the actor's name and email as they were, inside the hash chain and the sealed trail), admin-log events, tombstones and sealed bytes, unchanged. *Retention:* `retention_rules` per account and data class (`draft`, `ended`, `completed`, `sessions`), none by default; a daily job (`retention_sweep`) purges each expired envelope through the engine's `Purge` (which appends `envelope.purged` naming the rule; drafts now purgeable by the system), never one under `envelopes.legal_hold_at`; the purge job then writes the tombstone and deletes the envelope's relational records holding personal data or content (documents and versions, recipients and their tokens, codes, adoptions, fields and values, comments, the certificate key), keeping the envelope row, its scrubbed workflow state and its whole audit chain. *Blob bytes* are not deleted by the purge: a key is a content hash that a retained record may share, so reclaiming bytes belongs to the orphan sweep (`HRD-09`), which must keep any blob a retained record names. *Rejected:* redacting audit events in place (breaks the chain every party holds); deleting blobs inline at purge (a concurrent upload of the same bytes would lose its blob); erasing a user of several workspaces from one workspace's session (an attribute of a shared identity changes only by the person in each workspace, ADR-028 (b)). Claims no legal effect for an erasure or purge (docs/09) | Accepted 2026-11-19 (owner instruction 63) | [32](32-AUDIT-TRAIL-AND-EVIDENCE.md) §7, [22](22-DATA-MODEL.md), [07](07-SECURITY-THREAT-MODEL.md) §Data classification, [40](40-API-DESIGN.md) |
| ADR-040 | **Staff passkeys: a WebAuthn relying party written on aws-lc-rs, with the browser's SubjectPublicKeyInfo** (`CON-13`, ASVS 2.3.2). *Why.* Staff need a phishing-resistant second factor beside TOTP; the maintained Rust RP library, `webauthn-rs`, is MPL-2.0, which `deny.toml` does not allow, and links OpenSSL, outside ADR-006; the permissive alternatives (`webauthn_rp`, `passkey-auth`, others) are young or unmaintained and verify with RustCrypto in the host, against ADR-006's aws-lc-rs for hosts. *Choice.* The server is the relying party in `casual-sign-server/src/webauthn.rs`: it checks the protocol of WebAuthn Level 2 §7.1/§7.2 (client data type, challenge, origin, cross-origin; authenticator data RP id hash, user presence, backup flags, the attested credential id; the signature counter) and leaves every primitive to `aws-lc-rs` (SHA-256; ES256, EdDSA and RS256 verification, which parses the key). Registration takes the key from `getPublicKey()` (SubjectPublicKeyInfo DER, which Level 2 provides so an RP need not decode CBOR), so no CBOR or COSE parser and **no new dependency** enter. Attestation is `none`: the key is as good as the authenticated session that registers it, and every use is a signature over a 32-byte single-use challenge kept on the staff session. RP id from the public URL's host or `OPENSEAL_WEBAUTHN_RP_ID`; one origin. A counter that does not move is refused as a clone. A passkey is a second factor only (no passwordless sign-in yet); it is the person's in every workspace, stored in `staff_passkeys` (migration 0046) under the tenant rules and reached through definer functions. *Rejected.* `webauthn-rs` (licence, OpenSSL); the permissive RP crates (maintenance, RustCrypto in the host); decoding the attestation object with `ciborium`/`coset` (a new parser and dependency for a key the browser already gives as SPKI; it would be needed for attestation other than `none`, or for browsers without `getPublicKey()`, which all current ones have). *Tested.* A software authenticator in unit and PostgreSQL tests; Chromium's virtual authenticator against the server in `webapp/e2e/passkeys.spec.mjs` (seen red with the signed data changed) | Accepted 2026-11-19 (owner instruction 65) | [40](40-API-DESIGN.md) §As built `CON-13`, [07](07-SECURITY-THREAT-MODEL.md) SEC-A09, [22](22-DATA-MODEL.md) |
| ADR-041 | **Sandbox workspaces: a permanent mark, a separate sandbox seal key, and nothing metered** (`VS-08D`, slice 8; touches the evidence store, key custody and the data model). *Why.* Integrators need a place to send, sign and seal test envelopes through the real API (DocuSign's developer environment) without any of them passing for an agreement or counting against the plan. *Choice* (owner instruction 69, model (a)). A workspace is a sandbox from its creation and for good: `accounts.sandbox` (migration 0049), taken at insert from a transaction-local setting the organization administrator's `POST /organizations/me/workspaces {sandbox: true}` sets, and refused by a trigger on any later change; the admin event names it. Its envelopes are sealed with **a separate sandbox key** only: keyd serves it beside the platform key under its own alias (`OPENSEAL_KEYD_SANDBOX_*`), the worker uses it for every seal of a sandbox workspace (documents and the ended-envelope certificate) with the `/Reason` "Sandbox: not for agreements", and while none is configured a sandbox seal waits (`CS-WRK-0020`); it is never sealed with the platform key, and the platform key never seals with the sandbox one. The sandbox key's certificate says "not for agreements" in its subject (development: `OU=Sandbox - not for agreements`); the verifier reports each signer certificate's subject (`SignatureReport::signer`) and the Verify page marks such a seal as a sandbox test without changing its verdict. The certificate of completion is titled "Sandbox Certificate (not for agreements)" and says so first. Every page of the workspace and the signing page carry a banner; every email of it starts with "SANDBOX: NOT FOR AGREEMENTS" and its subject with "[Sandbox]". Nothing it does is metered or refused by a quota: the ledger's two writers (`openseal_meter_apply`, `openseal_consume_quota`) are wrapped to count nothing for a sandbox, though a suspended organization still stops it. Its API keys start `osk_test_`, so neither code nor a secret scanner mistakes one for a live key. *Rejected.* A separate sandbox deployment only (option (b): no in-product mark, and the same key would seal both if an operator reused it); stamping a watermark on the sealed pages (it changes the document the signer reviewed). *Tested.* Server `tests/sandbox.rs`, worker `tests/sandbox.rs`, keyd `tests/two_keys.rs`, certificate `a_sandbox_certificate_says_it_is_not_for_agreements`, verify `the_report_names_the_signer_once_the_signature_verified`, web `slice8.test.mjs`, `api-webhooks.spec.mjs` | Accepted 2026-11-20 (owner instruction 69) | [76](76-SLICE-8-EVIDENCE.md), [40](40-API-DESIGN.md), [22](22-DATA-MODEL.md), [31](31-SEALING-AND-SIGNATURES.md), [07](07-SECURITY-THREAT-MODEL.md) |
| ADR-042 | **Word uploads converted to PDF: `docxide-pdf` (Apache-2.0, pure Rust) in `casual-sign-convertd`, a container with no network and a fresh child process per job** (`VS-06C`; owner instruction 76 revised the proposal: uploads take PDF and DOCX only, the converter and everything it pulls in Apache-2.0, no LibreOffice, no copyleft; Excel and PowerPoint are `VS-06F`). *Why.* Senders start from Word (FG-002); ADR-021 accepted a sandboxed `Converter` seam but not what fills it. *Candidates, by licence first (2026-11-20).* (a) **`docxide-pdf` 0.21.4** (crates.io, Apache-2.0, pure Rust, active: 41 releases, last 2026-11-16; aims at Word's own PDF export: styles, lists, tables, sections, headers and footers, images, fields, footnotes, tracked changes in final view): 108 crates in its tree, every one MIT, Apache-2.0, BSD, Zlib or Unicode-3.0, or offering one of them (`r-efi`'s LGPL is one choice of three), so `deny.toml` passes unchanged; one unmaintained-crate notice, `ttf-parser` (RUSTSEC-2026-0192, informational, no vulnerability), ignored in `.cargo/audit.toml` with its reason (row `DEP-09`). (b) `office2pdf` 0.11.0 (Apache-2.0, on Typst): 400-odd crates including MPL-2.0 (`option-ext`) and 0BSD/CC0-only crates `deny.toml` refuses; rejected. (c) `dxpdf` (MIT, on Skia: C++ and a downloaded binary) and `zavora-docx-pdf` (MIT OR Apache-2.0, 2 releases): rejected, the owner asked for Apache-2.0 and these are not or are too young. (d) docx4j + Apache FOP on the JVM: Apache-2.0 jars, but a Java runtime (OpenJDK, GPL-2.0 with the Classpath exception) and JAXB (EDL) come with it, so not everything it pulls in is Apache-2.0; rejected. (e) LibreOffice (MPL-2.0): excluded by the owner. *Choice.* (1) A new host crate and image, `casual-sign-convertd` (server/; Compose service `convertd`, its own Dockerfile stage built apart from the server so Cargo's feature unification cannot link the converter into it). It holds no secret and has **no network at all** (`network_mode: none`), a read-only root, every capability dropped, `no-new-privileges`, 3 GiB, 2 CPUs and 64 processes. (2) **A fresh child per job**: the daemon starts its own binary with an empty environment for each conversion; the child sets `RLIMIT_AS` (2 GiB, Linux), `RLIMIT_CPU` (60 s), `RLIMIT_FSIZE` 0 (it writes no file), `RLIMIT_CORE` 0 and `RLIMIT_NOFILE` before it reads a byte, and the daemon kills it at 60 s wall clock; two jobs at once, more refused at once (`CS-CNV-0005 busy`). (3) **Screened first**, inside the child: entry count, declared and read part sizes, total expanded size, expansion ratio (zip bombs), encryption, macros (a macro-enabled content type, a VBA project or VBA data part: refused, `CS-CNV-0004`), templates, and an early page estimate (docs/21 §DOCX conversion); external references are counted, never fetched. (4) **Transport**: one request and one answer over a Unix socket on a volume shared with the API server only (no TCP, so no network for convertd); the server reads the answer as hostile (lengths bounded, a PDF must start as one). (5) **Synchronous with a deadline**, not a job: an ordinary agreement converts in well under a second, so the upload waits for its conversion (90 s at most, holding no database connection or row lock, as the malware scan does) and the API stays one call, with no "converting" state in the data model. `POST /conversions` converts and admits for the editor's preview and stores nothing; the upload converts again with the same converter and fonts, so the pages fields were placed on are the pages delivered. (6) **Evidence**: the `.docx` is the document's `original` version (its SHA-256 the `upload_hash` of `document.added`), the converted PDF goes through admission and normalization like any upload, and the normalized version's admission report (bound into the chain by its hash) says `converted: {from, converter, pdf_sha256, external_references}`. A template keeps only its PDF. (7) Fonts: Debian's `fonts-croscore` (Arimo, Tinos, Cousine; Apache-2.0) in the image. *Rejected.* Converting in the server process (a hostile archive next to the server's secrets); a conversion job with a "converting" state (more state for a sub-second step); a hosted conversion API (sends agreements to a third party); TCP to the daemon (it would need a network). *Consequences.* Word's own fonts (Calibri, Cambria, Times New Roman) are not shipped: a document set in them is drawn in the Apache-2.0 faces, with different line breaks (row `VS-06G`). The memory cap is enforced on Linux only (the shipped container); elsewhere the child runs with the other limits. *Tested.* `casual-sign-convertd` `tests/convert.rs` (every hostile fixture of `fixtures/hostile/docx/` meets its manifest code through a real child; a job over its time is killed; Linux: over its memory ends without an answer; external references never fetched; busy beyond the slots), the server's `tests/convert.rs` on PostgreSQL, the `docx_screen` fuzz target, and `webapp/e2e/docx-send.spec.mjs` on the Compose stack | Accepted (owner instruction 76, 2026-11-20) | [30](30-PDF-PIPELINE.md) §3, [07](07-SECURITY-THREAT-MODEL.md) `SEC-P13`, [21](21-PARSER-LIMITS.md) §DOCX conversion |
| ADR-043 | **Sign on paper: the scan joins the envelope as a fixed document, bound by a new audit type** (`FG-013`, slice 6, owner instruction 78; touches the audit event schema). *Why.* DocuSign lets a signer print, sign by hand and return the pages; OpenSeal must do the same without weakening evidence. *Choice.* An envelope option `signing_options.allow_sign_on_paper` (off by default, absent from the wire when off, so earlier options hash unchanged). A signer (type `signer` only) whose turn it is, authenticated and consented (as every ceremony write, `SEC-CER-01`), chooses Sign on paper on the signing page, prints the documents (the page's own print and download) and uploads the scan, a PDF only, at most the document size limit, through `POST /s/{token}/paper`: screened for malware, admitted and normalized like any upload (docs/30 §2) and stored with its original. The engine command `SignOnPaper {recipient, document}` adds it to the envelope as a fixed document named "Signed on paper.pdf" (`document.added`, `document.admitted`, `document.fixed`, as a correction adds one), then records the new type `recipient.signed_on_paper {recipient_id, documents, document_id, upload_hash}` (`documents`: the delivered hashes of what the signer printed, before the scan joined them) and `recipient.completed`; routing moves on. Because the scan is a document of the envelope, the seal job seals it with the rest and the certificate lists it; the certificate shows the signer as "Signed on paper" with the scan's document, never "Signed" alone. Fields assigned to that signer keep what they hold and need no value. Additive to the event schema of ADR-010, as ADR-027 and ADR-031 are: earlier chains hash unchanged, an earlier verifier lists the type as unrecognised, not failed. Not a milestone or a webhook topic of its own (`recipient.completed` is). *Rejected:* keeping the scan outside the sealed set (an attachment, as signer attachments are: then the seal would not cover the evidence of the signature); drawing the scan's pages into the delivered documents (changes what other parties saw); allowing other recipient types (an approver or viewer has nothing to sign by hand). *What it does not claim:* that a hand signature on a scan is verified; the evidence is that this scan, of these printed documents, was uploaded by this authenticated recipient at this time (docs/09). Written by the slice-6 worker for the owner's review | Accepted 2026-11-21 (owner instruction 79) | [24](24-ENVELOPE-LIFECYCLE-AND-ROUTING.md) As built, [32](32-AUDIT-TRAIL-AND-EVIDENCE.md) §3, [40](40-API-DESIGN.md), [96](96-FEATURE-FIT-GAP.md) FG-013 |
| ADR-044 | **A strike-through is a field kind, `strikethrough`, that an editor places at the ceremony and the seal draws as one line** (`FG-080`, slice 6, DocuSign's polyline overlay used by an editor). *What.* A new `FieldType::Strikethrough` (wire `strikethrough`): one horizontal line through the vertical middle of the field's rectangle, as wide as it, 1 point thick (half the height under 2 points), butt caps, in the field's `format.color` or black. It takes no recipient value (`takes_input` false; never required): `casual_sign_fields::evaluate_envelope` gives a visible one the implied value `{checked: true}` and a client that sends anything else gets `CS-FLD-0022`; a condition may hide it, and then it is not drawn. `casual-sign-flatten` draws it like any other field, in the same incremental update, so the delivered bytes stay a prefix (docs/30 §7). Any recipient type may hold one (a display kind, as `note`). An editor adds, moves, lengthens and removes it through `POST /s/{token}/editor/fields` and `PATCH`/`DELETE …/editor/fields/{field}` (`VS-06A`); a sender may place one through the API. *Evidence.* The chain records each change as `envelope.corrected` naming `fields.<id>` with the editor as actor (the engine's `RecipientEdit`, no new event type: the audit schema is unchanged); every later recipient's view lists every strike on a document they see (`strikes`), and the signing and review pages draw them, so they see the text struck through before acting (WYSIWYS); the sealed document draws the same line, and its hash is the chain's `document.sealed`. Bounded by the envelope's field limit (docs/21). *Alternatives.* A set of free polylines per field (DocuSign's `polyLineOverlayTabs`): needs a new value type and a parser for untrusted point lists, for no gain in the common case of striking words on a line; several strikes are several fields. A dedicated audit type carrying the geometry: deferred; the sealed PDF and the field id carry it today. *Tests.* `-fields` `tests/envelope.rs` and the parity table (227 cases, native = WASM), `-flatten` `tests/flatten.rs` (every rotation, crop and UserUnit; the line's operators), `-worker` `tests/end_to_end.rs` (sealed, verified by ours and pyHanko), `manage-correct.spec.mjs` FG-080 | Accepted 2026-11-21 (owner instruction 79) | [30](30-PDF-PIPELINE.md) §7, [24](24-ENVELOPE-LIFECYCLE-AND-ROUTING.md), [40](40-API-DESIGN.md) |
| ADR-045 | **Envelope id stamping: drawn by the flattener over every page like a field value, shown to every signer, chosen before sending and fixed after** (`FG-009`, `VS-06E1`; touches the evidence). *Why.* DocuSign stamps the envelope id in each page's top margin so a printed page leads back to its envelope; the stamp must be in what every signer saw and in the sealed bytes, and the seal must cover it. *Choice.* `signing_options.stamp_envelope_id` per envelope (off by default, absent from the JSON when off); the account setting `stamp_envelope_id` is the default for a create request that does not say, and the editor starts a new envelope from it. The delivered document (normalized at upload, its hash in `document.added` and `document.fixed`) is not changed. `casual-sign-flatten` draws the stamp (`FlattenOptions::envelope_id_stamp`) in the same incremental update as the field values: "Envelope ID: <id>" in 7 pt Liberation Sans, grey, one line in a 10 pt band 4 pt below the top edge of every page as displayed, inset 18 pt from the sides (5 % on a narrow page, shrinking to fit), placed through the page geometry for every rotation, crop box and UserUnit; an id that is not an id is refused (`CS-FLD-0005`). The signing page draws the same line in the same place over every page from the start of the ceremony and in the review, and the in-progress download (`version=current`) carries it, so what a signer sees is what is sealed, as for values (ADR-020). The choice is in the audit chain: `envelope.sent` carries `envelope_id_stamped: true` (absent when off, so earlier chains hash unchanged), and the engine refuses to turn it on or off after sending (`CS-WF-0001`), since a signer may already have seen the pages. The seal is applied over the stamped bytes. The certificate of completion is not stamped (it is generated after, and names the envelope id in its own text). *Rejected.* Stamping the delivered document at send time: a second revision of the delivered bytes after the hash the upload recorded, so `document.added` would no longer name what signers received, anchors and detected fields would be found on other bytes, and template documents reused by hash would diverge; the flatten-time stamp gives the same guarantee (shown before acting, sealed, covered) without it. Stamping only at seal time without showing it (the sealed pages would differ from what signers saw). *Tested.* flatten `tests/flatten.rs` `the_envelope_id_stamp_is_in_the_top_margin_of_every_page_in_every_rotation` and `the_envelope_id_stamp_is_on_every_page_and_needs_a_valid_id`, the corpus sweep `every_corpus_file_takes_the_envelope_id_stamp_on_every_page` (`tests/corpus_layers.rs`, `OPENSEAL_CORPUS_SWEEP=1`: 371 files, 10,692 pages, each stamp read back, no failure); workflow `the_envelope_id_stamp_is_recorded_at_send_and_fixed_after`; server `tests/envelope_id_stamp.rs`; worker `an_envelope_stamped_with_its_id_is_sealed_with_the_stamp_on_every_page` (pyHanko 0.38.1 in Docker: intact, valid, trusted, `ENTIRE_FILE`, no modification; pypdf reads the stamp on every delivered page and not on the certificate's); web `tests/stamp.test.mjs`; browser `vs06e-screens.spec.mjs` | Accepted 2026-11-21 (owner instruction 79) | [30](30-PDF-PIPELINE.md) §7, [31](31-SEALING-AND-SIGNATURES.md) §3, [32](32-AUDIT-TRAIL-AND-EVIDENCE.md) §3, [22](22-DATA-MODEL.md), [24](24-ENVELOPE-LIFECYCLE-AND-ROUTING.md), [40](40-API-DESIGN.md) |
| ADR-046 | **Remote-provider signatures per recipient, and the CSC API v2 adapter** (`RSP-01`, slice 5r, owner instruction 75; touches the public API, the PDF revisions before the seal, the audit event schema, the state machine, key custody and a legal property). *What.* A `signer` gets a signature type, `simple` (today) or `remote` with a provider the account enabled; two remote signers never share a routing order. *PDF.* Per document, the first remote signature is a **lock point**: revision R0 flattens every final value into page content and materializes the fields of recipients not yet finished as AcroForm fields; each remote signature is a revision that fills those fields in place (`FILL-01`) and adds the signer's `/Sig`; layout is frozen after it; at completion a last fill, then **the platform seal last** (keyd, ADR-036 tokens, the account's profile), DSS over every signature; the certificate of completion and audit trail become a separate sealed PDF. *Engine.* `casual-sign-seal` splits into `prepare` (placeholder, ByteRange digest, DER signed attributes) and `complete` (a provider's value or CMS, our RFC 3161 time-stamp, verify); `seal()` stays byte-identical. *CSC.* v2.0.0.2 (v2.1 to confirm): `oauth2/authorize` scope `service` with PKCE, `credentials/list` and `credentials/info` (chain, `SCAL`, `signatureQualifier`), prepare, then scope `credential` binding the signed-attribute hashes (SCAL2), `signatures/signHash`; never a PIN or OTP on our pages, never `extendTransaction`; B-T then DSS at once. keyd gains a non-interactive `csc` backend (the `KeyProvider` seam proper) through a new host crate `casual-sign-csc`. *Evidence.* Four additive audit types (`recipient.remote_signing_started`, `_prepared`, `_failed`, `recipient.remote_signed`); the certificate prints the provider certificate and what the provider states, never a legal status. *Secrets.* Operator catalogue with secret files by reference; an account's own client secret sealed AES-256-GCM under `OPENSEAL_PROVIDER_SECRETS_KEY`; keys only in keyd. Full record, protocol facts, failures, tests (a CSC stub signing with `openssl`, pyHanko and EU DSS), owner inputs and open questions below | Accepted 2026-11-21 (owner instruction 82) | This page §ADR-046 (below); [31](31-SEALING-AND-SIGNATURES.md) §3.1; [09](09-LEGAL-AND-COMPLIANCE.md) §2a |
| ADR-047 | **India eSign through a licensed ESP, OpenSeal as the ASP** (`RSP-02`, slice 5r, owner instruction 75; touches a wire format, the audit schema, key custody, a crate boundary and a legal property). Everything ADR-046 decides for remote signatures applies. *Protocol.* CCA eSign API v2.1 (Aadhaar online e-KYC; request and response through the browser; one hash per request) and v3.3 (CA e-KYC account; server-to-server request, acknowledgement, `txnref`, server-to-server answer, `EsignStatus`; up to 5 hashes). *Hash.* The SHA-256 ByteRange digest of the prepared revision as `InputHash`; `responseSigType` `PKCS7pdf` (chain, revocation and CA time-stamp captured while the one-time certificate lives); raw types refused (the certificate does not exist before signing). *Format.* `ETSI.CAdES.detached` when the ESP's CMS conforms, else `adbe.pkcs7.detached` as the one exception to docs/31 §2, only for a provider's CMS; our time-stamp if it has none; DSS at once; BER refused until `SEAL-13`. *Checks.* The ESP's XML Signature under its configured certificate, `txn` correlation and single use, `message-digest` equal to ours, chain to the CCA root. *XML.* ADR-026's bounded reader moves to a new engine crate `casual-sign-xml`; a narrow XML Signature profile and canonicalization in a new host crate `casual-sign-esign`, checked against xmlsec1 in CI only. *Keys.* The ASP's request-signing key in keyd, answered only with a database-minted ASP token for an open session. *Data.* OpenSeal never receives an Aadhaar number, VID, OTP or biometric; the certificate is personal data. Full record below | Accepted 2026-11-21 (owner instruction 82) | This page §ADR-047 (below); [31](31-SEALING-AND-SIGNATURES.md) §3.1; [09](09-LEGAL-AND-COMPLIANCE.md) §2a, §4 |

## Full records

ADRs whose reasoning is too long for a table row are written out here; the row above stays the summary.

### ADR-046 — Remote-provider signatures per recipient, and the CSC API v2 adapter (`RSP-01`)

**Status: Accepted 2026-11-21 (owner instruction 82); proposed 2026-11-21.** Owner instruction 75 brought it forward from slice 18 to right after slice 9 (M4).
It touches the public API, the persisted PDF format (new revisions before the seal), the audit event schema, the
envelope and recipient state machines, key custody and a legal property, so it needs an Accepted ADR before any code.
ADR-047 (India eSign, below) builds on the shared parts
here: §3.1 to §3.9 and §3.11 to §3.14 are written once, for every remote provider.

#### 1. Context

Today every agreement is a simple electronic signature (SES) protected by **one platform seal** at completion
([31](31-SEALING-AND-SIGNATURES.md) §3, ADR-008): the signer adopts a mark, the platform's key in `keyd` signs the
finished document. Customers in the EU who need an advanced or qualified signature, and customers whose counterparty
insists on a certificate in the signer's own name, need **the signer's own key** to sign: a key that a qualified
trust service provider (QTSP) or another remote signing service provider (RSSP) holds for the signer, reached over the
Cloud Signature Consortium (CSC) API. DigiCert Document Trust Manager and A-Trust are the two named providers;
others speak the same API.

Three facts shape the design:

1. **The signer authorizes each signature at the provider, interactively, over a hash we compute.** At SCAL2 (the
   level a qualified signature needs) the authorization is bound to the hash. So the document bytes the signature
   covers must exist, final, *at the signer's turn*, not at completion.
2. **A PDF signature covers every byte before it.** Anything written after it must be a change validators accept
   (a new signature, form filling of fields that existed, DSS data, a document timestamp). Our flattener draws values
   into page content ([30](30-PDF-PIPELINE.md) §7), which after a signature is a disallowed change for every
   validator, ours included (`casual-sign-verify` `diff.rs`, `Disallowed::PageChanged`).
3. **`KeyProvider::sign` is a synchronous call inside `seal()`** (`casual-sign-crypto` `key.rs`). It fits a key the
   platform can use without a person (an HSM, a KMS, or a CSC credential authorized by the service), not a signer
   who must log in at the provider between our hash and their signature.

#### 2. Protocol facts relied on

Source: *Architectures and protocols for remote signature applications*, Cloud Signature Consortium API
**v2.0.0.2** (the public V2 release; its revision history lists 2.0.0.0 of 25/03/2022 and 2.0.0.1 of 19/08/2022),
sections 8.4 and 11. **v2.1** is published by the Consortium with changes to `signatures/signDoc` and authorization;
what it changes for the calls below is **to confirm** before building, and against each provider's sandbox, since a
provider may implement a profile of either.

| Call | What we rely on | Confidence |
| --- | --- | --- |
| `info` (§11.1) | Base URI, the authorization types offered (`oauth2code`, `implicit`, `explicit`), the OAuth 2.0 endpoints, the methods supported | Spec |
| `oauth2/authorize` (§8.4.2) | Authorization code flow. Scope `service` for the signer to log in; scope `credential` with `credentialID`, `numSignatures`, `hashes` (base64url) and `hashAlgorithmOID` to authorize specific hashes, or `authorization_details` (RFC 9396) carrying the same | Spec; whether DigiCert DTM and A-Trust require PKCE and accept `authorization_details`: to confirm with the provider's sandbox |
| `oauth2/token` (§8.4.4) | Code for an access token; with scope `credential` the token is good as the SAD for `signHash` (§11.10) | Spec |
| `credentials/list` (§11.4) | The signer's credential ids, optionally with `credentialInfo` | Spec |
| `credentials/info` (§11.5) | `key/status`, `key/algo` (OIDs), `key/len`, `key/curve`, `cert/status`, `cert/certificates` (the chain, base64 DER), `cert/issuerDN`, `cert/serialNumber`, `cert/subjectDN`, `cert/validFrom`, `cert/validTo`, `auth/mode`, `SCAL`, `multisign`, and the optional `signatureQualifier` (for example `eu_eidas_qes`) | Spec; the qualifier values each provider returns: to confirm |
| `credentials/authorize` (§11.6) | For `explicit` mode only: `credentialID`, `numSignatures`, `hashes`, `hashAlgorithmOID`, `authData` (PIN, OTP) → `SAD`, `expiresIn` (default 3600 s); at SCAL2 the hashes are required and bind the SAD; never used with `oauth2code` | Spec |
| `credentials/extendTransaction` (§11.9) | Renews a SAD for more `signHash` calls in a multi-signature transaction; the spec warns it "may break the support of SCAL 2" | Spec; not used by this design (§3.4) |
| `signatures/signHash` (§11.10) | `credentialID`, `SAD`, `hashes` (base64 raw digests), `hashAlgorithmOID`, `signAlgo` (one of `key/algo`), `signAlgoParams` (RSASSA-PSS); synchronous by default (`operationMode` `S`); answers `signatures`, one per hash, **in input order** | Spec; whether an ECDSA value comes back DER-encoded or as raw `r‖s`: to confirm with the provider's sandbox (the adapter accepts both and re-encodes to DER) |
| `signatures/signDoc` (§11.11) | The provider builds the whole PDF signature from the document | Spec; not used (§6) |

What is **not** in the CSC API, and so is the provider's policy: how the signer is identified and enrolled, which
second factor they use, the certificate profile, the time a SAD or code lives in practice, rate limits.

#### 3. Decision

##### 3.1 A signature type per recipient

A recipient of type `signer` gets a **signature type**: `simple` (the default and today's behaviour: an adopted mark
under the platform seal) or `remote` with a **provider** the account has enabled (§3.11). On the wire it is
`signature: {type: "remote", provider_id: "…"}`, absent for `simple`, so every earlier envelope and event hashes as
before (the additive rule of ADR-027). It is chosen by the sender (or a template role) before sending and may be
corrected only while that recipient has not started signing; changing it after their turn began is
`409 CS-RSP-0007`. In-person signers, signing groups and the `seal` recipient type (slice 18) are not given a remote
type by this ADR. **Two remote signers never share a routing order**: their signatures must be made one after the
other over each other's bytes, so a send that places two at one order is refused (`422 CS-RSP-0007`, with the
violation naming both). Simple recipients may share an order with a remote one.

##### 3.2 The PDF: a lock point, signer revisions, and the platform seal last

This is the part ADR-047 and slice 16 (per-signer seals) reuse.

- **Until the first remote signature, nothing changes**: values are recorded, corrections and editors work as today.
- **The lock point**, per document, is the moment the first remote signature over that document is prepared (§3.4);
  a document no remote signer acts on (one hidden from them, WF-02) is never locked and is flattened at completion as
  today. For each locked document the worker writes revision **R0**: the delivered document with **every value already final flattened into page content**
  by the existing flattener (finished recipients, this signer's own values, the envelope id stamp of ADR-045,
  strike-throughs of ADR-044), and **every field of recipients who have not finished materialized as an AcroForm
  field** with an empty appearance, in its rectangle, read-only to viewers. Text, date, number, email, formula and
  dropdown fields become text fields; checkboxes and radio groups become button fields; a later simple signer's
  signature and initials become read-only text fields whose filled appearance draws the adopted mark (a text field
  rather than a push button because validators classify a text field's `/V` and `/AP` change as form filling; this is
  **to confirm with pyHanko and EU DSS in the first stage** before the rest is built). Each **later remote signer**
  gets an unsigned `/Sig` field at their first signature field's rectangle. R0 is ordinary page-content flattening
  for everything already known, so it adds no new rendering path for finished values.
- **Each remote signature is one revision Rk** on top of the previous bytes: a fill-in-place update (the built
  `FILL-01` code: `/V` and a regenerated appearance) for every materialized field whose recipient finished since the
  last revision, then the remote signer's `/Sig` field with its signature dictionary and a `/Contents` placeholder.
  The signer's first signature field is the visible widget: the adopted mark, the recipient's name as sent, and
  "Digitally signed, see the signature panel" (the certificate's own name is not known before signing for every
  provider, and the appearance is inside the signed bytes). Their other signature and initials fields are drawn as
  materialized fields filled in the same revision, so the signature covers them.
- **After a document's lock point, its layout is frozen.** Adding, moving or removing a field, an editor's strike-through, turning
  on the envelope id stamp, replacing a document or any correction that changes a document is refused
  (`409 CS-RSP-0007`); correcting a later recipient's name, email, phone or authentication, reminders, void and
  decline are still allowed (none of them changes a document's bytes).
- **At completion** the worker writes one last fill-in-place revision for values after the last remote signature (if
  any), then **the platform seal**, an approval signature by `keyd` exactly as today (seal token of ADR-036, the
  account's profile, B-T by default), then, at B-LT or above, the DSS for every signature in the file (the existing
  `augment` over all signatures), then the B-LTA document timestamp if the profile asks. The platform seal is the
  last signature and covers the whole file, so `seal::check_verified`'s rule (the last signature covers the whole
  file but a DSS tail) holds unchanged.
- **No DocMDP certification at the lock point** by this ADR: an approval signature without DocMDP permits form
  filling and further signatures, which is what later recipients need, and certifying at the lock point would need a
  platform key use for an envelope that is not completing (outside ADR-036's token). Slice 16 may add certification
  with `/DocMDP P=2` at the lock point; the revision model is the same.
- **The certificate of completion and the audit trail become a separate PDF** for an envelope with any remote
  signature: appending pages or an associated file to a document after signatures is a disallowed change. The
  separate certificate is rendered, sealed on its own with the platform key and verified, as the envelope certificate
  of an ended envelope already is (UXW-30, [32](32-AUDIT-TRAIL-AND-EVIDENCE.md) §6), with `audit-trail.json` embedded
  in it. It prints each document's final sealed SHA-256, so the documents are bound to it by hash and it to them by
  its own seal. The account setting that appends the certificate to the document does not apply to such envelopes;
  the evidence package (§6.1 there) already carries `certificate.pdf` as its own entry.

Validators: our verifier already classifies `FormFill`, `Signature` and `DssUpdate` as allowed after an approval
signature without DocMDP (`casual-sign-verify` `report.rs`, `ModificationClass`); pyHanko's difference analysis and
EU DSS's "undefined changes" count must agree on the stub fixtures before the design is built out (§4).

##### 3.3 The engine: sign in two phases

`casual-sign-seal` gains a split of what `seal()` does in one call (docs/31 §4 steps 1 to 7):

- `prepare(input, &SealRequest, &PlaceholderPlan) -> Prepared`: append the signature revision with a fixed-width
  `/ByteRange` and a `/Contents` placeholder of a planned size, fill the ByteRange, and return the bytes, the
  ByteRange, the **ByteRange digest** and, when the caller gives the signer's certificate chain and algorithm, the
  **DER signed attributes** (`content-type`, `message-digest`, ESS `signing-certificate-v2`; no CMS `signingTime`,
  as today) and their digest. `Prepared` is plain data the worker stores (bytes in the blob store, the rest in the
  session row) so completion may run in another process, minutes later.
- `complete(prepared, ExternalSignature, &dyn TimestampSource, &CompleteOptions) -> Sealed`, where
  `ExternalSignature` is either `Value {signature, chain, algorithm}` (CSC: we assemble the CMS around the provider's
  value over our signed attributes) or `Cms(der)` (ADR-047: the provider's own CMS, checked before use). It verifies
  the signature value against the certificate's public key and the digest, adds the RFC 3161 `signature-time-stamp`
  unsigned attribute (B-T), writes the CMS into the placeholder, and runs our verifier on the result (docs/31 §4
  step 8). It **never re-lays out**: a CMS larger than the placeholder is `CS-RSP-0005` and the session fails,
  because a new layout is a new hash the signer did not authorize.
- `seal()` becomes `prepare` then `complete` with a `KeyProvider`, and **its output must stay byte-identical** on the
  existing fixtures (a test compares the bytes before and after the refactor). Placeholder planning for a remote
  signature uses the chain from `credentials/info`, the key's maximum signature length and the TSA's token bound plus
  the usual margin, so the one-retry rule of today is never needed.

The engine stays pure: no network, the time supplied, the signature value supplied (ADR-004).

##### 3.4 The ceremony, with a CSC provider

1. The signer opens their link, passes the envelope's authentication and consent, fills their fields and adopts a
   mark for the visible widget, as today. The review step shows the engine's preview, as today (ADR-020).
2. **Sign with <provider>** replaces Finish. The engine command `BeginRemoteSigning` (their turn, every required field
   filled, no other remote session open in the envelope) freezes their values and records
   `recipient.remote_signing_started`. The browser goes, top-level (never in a frame: providers forbid framing, and an
   embedded view opens a window), to the provider's `oauth2/authorize` with scope `service`, PKCE S256 and a `state`
   bound to the session (stored hashed, as RAUTH-01 does).
3. Back at `/rsp/callback/{provider}`, the server checks `state` and hands the code to a worker job, which exchanges
   it, calls `credentials/list` and `credentials/info`, and keeps the credentials that are enabled, valid, of an
   algorithm we accept (§3.6) and of a `signatureQualifier` the account requires, if it requires one (for example
   only `eu_eidas_qes`). None: the session fails with `CS-RSP-0006`. More than one: the page asks the signer to
   choose. The worker then prepares every document the signer may see (§3.5), records
   `recipient.remote_signing_prepared`, and the page **shows the prepared documents rendered from the exact bytes
   whose hashes will be signed** (`GET /s/{token}/remote-signing/documents/{id}`), with a button to authorize.
4. The browser goes to `oauth2/authorize` with scope `credential`, the `credentialID`, `numSignatures` equal to the
   number of documents, the hashes of the signed attributes and their algorithm OID. With `multisign` below the
   number of documents, the signer authorizes in batches of `multisign`, one round trip each. We never use
   `credentials/extendTransaction` (it weakens SCAL2 binding) and **never collect a signer's PIN or OTP on our
   pages** (`explicit` mode would pass them through the platform, which undermines the sole-control argument a
   remote signature exists for); a credential whose `auth/mode` is only `explicit` is not offered (§8 question 3).
5. Back at the callback, the worker exchanges the code for the credential token, calls `signatures/signHash` once with
   all the hashes, checks that the answer has one value per hash in order, and completes each document (§3.6). In the
   same transaction as storing the revisions it records `recipient.remote_signed`, then `recipient.signed` and
   `recipient.completed` as today, and routing moves on.

Access tokens, the SAD and the credential token live only in the worker's memory for the job; the authorization code
and the PKCE verifier sit in the session row sealed under the provider secrets key (§3.11) and are deleted at first
use.

##### 3.5 The hash, from the exact bytes that will be sealed

For each document: take the stored bytes as they stand (the delivered document, or the last revision written for
this envelope); write R0 if this is the lock point, then Rk with the placeholder, through `casual-sign-pdf`'s
incremental writer (deterministic, the input a prefix of the output); fill the `/ByteRange` `[0, a, b, c]` so it
covers every byte except the `/Contents` hex string; digest the covered bytes with SHA-256 (SHA-384 or SHA-512 when
the key's algorithm calls for it). For CSC that ByteRange digest becomes the `message-digest` signed attribute and the
**hash sent to the provider is the digest of the DER signed attributes** (with the explicit `SET OF` tag, RFC 5652
§5.4), which is what the signature value is over. The prepared bytes are stored content-addressed before the signer
is sent away; completion embeds into exactly those bytes and nothing else, and a second preparation (a retry) is a new
revision from the same base with a new hash.

##### 3.6 Embedding, level, and what is accepted

- The provider's value is checked before use: it verifies under the certificate's public key over our signed
  attributes (aws-lc-rs in the worker), the certificate is the one `credentials/info` returned, and its chain builds
  to a trust anchor configured for that provider, valid at the time-stamp time and not revoked (OCSP, else CRL).
  Anything else fails the session `CS-RSP-0004` and nothing is written.
- Algorithms accepted from a provider: RSA 2,048 to 8,192 bits (PKCS#1 v1.5 or PSS) and ECDSA P-256 or P-384, with
  SHA-256 or stronger. RSA 2,048 is below what our own seals use (SEC-S08) but common at providers whose certificate
  policy governs it; it is recorded and printed (§8 question 4).
- The CMS is PAdES **B-B** (`SubFilter /ETSI.CAdES.detached`, our signed attributes), then **B-T** with our own TSA
  (`TimestampSource`, docs/31 §6). Right after it, while the signer's certificate is certainly valid, the worker
  appends a DSS revision for that signature (**B-LT** for it, the existing `dss::add_dss`), so a short-lived provider
  certificate never leaves a signature without revocation data. The account's B-LTA, if any, is applied once at
  completion over the whole file.
- `casual-sign-verify` runs on every revision written; the worker also requires that every remote signature already
  in the file still verifies and that every later revision classifies as allowed.

##### 3.7 Audit events (additive to ADR-010, as ADR-027 was)

| Type | Actor | Data |
| --- | --- | --- |
| `recipient.remote_signing_started` | recipient | `session`, `provider: {id, kind: "csc" or "in_esign", name}` |
| `recipient.remote_signing_prepared` | platform | `session`, `documents: [{document_id, base_hash, prepared_hash, byte_range, byte_range_digest, to_be_signed}]` (SHA-256 of the bytes before the revision, of the prepared bytes, and the digest the provider signs), `certificate_sha256` when known before signing (CSC), `lock_point: true` on the first |
| `recipient.remote_signed` | recipient | `session`, `provider`, `provider_reference` (the provider's transaction id where it has one, else absent), `certificate: {sha256, issuer, serial, not_before, not_after, subject_cn, key, qualifier, qc_statements}`, `name_match: exact, normalized or differs`, `documents: [{document_id, revision_hash, signature_sha256, timestamp_time}]` |
| `recipient.remote_signing_failed` | recipient or platform | `session`, `reason: cancelled, expired, provider_unavailable, provider_refused, response_invalid, no_eligible_credential, placeholder_overflow, envelope_ended`, `provider_code` (the provider's own error code, never its message) |

`subject_cn` is personal data, classified as a name (docs/07 §Data). Values the signer typed stay hashed in their
field events as today. A failed session reopens the signer's fields; a new attempt is a new session. `qualifier` is
the CSC `signatureQualifier` **as the provider stated it**; `qc_statements` lists the ETSI EN 319 412-5 statements
present in the certificate (`QcCompliance`, `QcSSCD`, `QcType`) as found, never interpreted as a legal status.
None of these types is a milestone or a notice; `recipient.remote_signing_failed` is a webhook topic (§3.14).

##### 3.8 Certificate of completion and verification

The certificate's signer section gains, per remote signer: the provider's name, the signature type ("Signature
created by <provider> with the signer's certificate"), the certificate's subject common name, issuer, serial,
validity and SHA-256 fingerprint, the qualifier and QC statements as stated by the provider and the certificate, the
name match result, the signature format and level (`PAdES B-LT`), the time-stamp time, and the provider's reference.
The wording is fixed by docs/09 §2a and reviewed by counsel; it never says "qualified", "advanced" or "legally
valid" in OpenSeal's own voice. The Verify page and CLI report each remote signature as its own signer (they already
verify any signature); a provider's roots are added to the verifier's trust store by the operator, as other roots
are.

##### 3.9 How the platform seal coexists, and slice 16

Per-signer remote signatures come first, in routing order; the platform seal is always last, over everything, at
the account's profile. A reader's signature panel shows each signer's own signature and then the platform's. Slice
16's **per-signer platform seals** are the same revision model with `keyd` instead of a provider at each signer's
Finish (and optionally a DocMDP P=2 certification at the lock point); slice 16 therefore reuses the lock point, the
materialized fields and the two-phase engine API rather than designing its own.

##### 3.10 The `KeyProvider` seam proper: a `csc` backend in keyd

Where no person authorizes each signature, a CSC credential **is** a `KeyProvider`: keyd gains a `csc` backend beside
PKCS#11, for an operator who holds the **platform seal key** (or, in slice 18, a legal entity's seal for the `seal`
recipient) at a QTSP instead of in their own HSM. It authorizes with the service's own credentials (OAuth 2.0 client
credentials or mutual TLS, as the provider offers), uses `credentials/authorize` with the hash for each signature
when the credential is SCAL2 and `implicit` otherwise, and calls `signHash` with the digest of the signed attributes
keyd is given. Everything keyd does today stays: seal tokens (ADR-036), the operation log, the probe signature at
start, the refusal of an expired signer certificate, reconciliation (CON-09). keyd's only new egress is the
configured CSC base URI. The CSC client is one small host crate, `server/casual-sign-csc` (wire types, the OAuth 2.0
exchanges, bounded JSON reading: answers over 1 MiB, more than 32 credentials or 16 certificates are refused), whose
first consumers are the worker (§3.4) and keyd; it compiles natively only and never enters the engine.

##### 3.11 Providers, accounts and secrets

- **The provider catalogue is the operator's**: `platform.signing_providers` (kind `csc` or `in_esign`, name, base
  URI and OAuth endpoints, the trust anchors for its signers' certificates, the OAuth `client_id`, the names of the
  secrets it needs, the accounts it is offered to, enabled), changed in the console by two key custodians and read by
  the worker at most once a minute, exactly as TSA endpoints are (CON-07). Every URL passes the `SEC-W01` address
  policy before each request.
- **An account enables a provider** in a tenant table, `account_signing_providers` (`account_id`, provider, options:
  the qualifiers it requires, whether a differing name refuses or is recorded, its own credentials if it brought its
  own contract), under RLS and the scoped repository (ADR-013); `account:admin` changes it, and each change is an
  admin audit event.
- **Secrets are never in the database in clear.** By default they are files the operator mounts for the worker (and
  keyd) and the catalogue names them (`secret_refs`, as webhooks do, read through `casual-sign-secrets`). An account
  that brings its own provider contract writes its client secret through the API once; it is stored **sealed with
  AES-256-GCM under `OPENSEAL_PROVIDER_SECRETS_KEY`** (an operator file, rotated with a previous key as
  `OPENSEAL_MFA_KEY` is, docs/65), with `openseal-provider-secret-v1 ‖ account id ‖ provider id ‖ name` as associated
  data so a sealed value cannot be moved to another row; it is never returned, only replaced, and only the worker
  opens it. Slice 15's per-tenant keys (BYOK) re-wrap these values. **A private key is never a secret of this kind**:
  any key a provider integration signs with lives in keyd (ADR-047's ASP key).

##### 3.12 Failure and timeouts

| Case | Behaviour |
| --- | --- |
| Provider unreachable or 5xx before the signer leaves | No session opens; the page says the provider is unavailable and the signer may try later. `provider_unavailable` if a session was open |
| Signer abandons at the provider (closes the tab, denies consent, wrong second factor) | The session expires after **15 minutes** without a callback (account setting, 5 to 60), `recipient.remote_signing_failed {expired}` or `{cancelled}` when the provider says so (OAuth `access_denied`); fields reopen; the signer can start again from their link |
| SAD or credential token expired before `signHash` | The job never waits: it signs within the callback's job. An expiry answer (`invalid_request` on the SAD) fails the session `expired`; the signer authorizes again, over a new preparation |
| A callback or answer after the session closed | Refused (`CS-RSP-0003`), logged as a security event; the prepared bytes are never embedded; nothing enters the chain |
| `signHash` answers the wrong number of values, or a value that does not verify | `response_invalid` (`CS-RSP-0004`); nothing is written |
| Our TSA or OCSP down at completion of the signature | The provider's value is kept in the session; `complete` retries with backoff (the signer sees "finishing your signature"); after 15 minutes the session fails `provider_unavailable` and the value is discarded (a signature made but never embedded binds nothing) |
| Envelope voided, declined or expired while a session is open | The session closes `envelope_ended`; a late answer is refused as above |
| Repeated failures | After 3 failed sessions for one recipient the sender is notified; there is **no automatic fallback** to a simple signature, which would silently lower the assurance the sender asked for; the sender may correct the recipient's signature type before they start again |

##### 3.13 Threats (new rows in docs/07, `SEC-S13` to `SEC-S16`)

A provider signature over bytes other than those shown (the prepared bytes are stored first and are the only bytes
completed; the hash is computed by the worker, never the browser); a forged or replayed callback (state hashed and
single-use, session-bound, PKCE, code exchanged only by the worker with the client secret); substitution of another
person's credential (the certificate is the one `credentials/info` returned for that session; name match recorded);
theft of provider credentials (files or AES-GCM sealed values, worker-only; keyd for keys); a hostile provider answer
(bounded JSON, every value verified before use); a provider page framing or phishing (top-level navigation only to
the configured authorization endpoint).

##### 3.14 API and webhooks

`POST /envelopes` and templates accept `signature` on a recipient; `GET /signing-providers` lists what the account
may use (`envelopes:write`); `GET`/`PUT /signing-providers/{id}` (account options and its own credentials, write-only,
`account:admin`). Ceremony (not public API): `POST /s/{token}/remote-signing` (start), `GET …/remote-signing`
(state, polled), `GET …/remote-signing/documents/{id}` (the exact prepared bytes), `POST …/remote-signing/cancel`,
and `GET /rsp/callback/{provider}` (the OAuth redirect URI). Webhook topic `recipient.remote_signing_failed`;
success is the existing `recipient.completed`. OpenAPI and the SDKs gain these when built (docs/40).

#### 4. Test strategy, without real providers

- **A CSC stub** in `tools/e2e/auth_stubs.py` (`csc`; standard library and the `openssl` command, as the OIDC stub):
  `info`, `oauth2/authorize` (a consent page, PKCE S256 checked), `oauth2/token`, `credentials/list`,
  `credentials/info`, `signatures/signHash`, with credentials at SCAL1 and SCAL2 under the test PKI
  (`tools/interop`), RSA-3072, RSA-2048, P-256; switches for each failure in §3.12 (deny, expire, wrong count,
  wrong value, another credential's certificate, raw `r‖s` ECDSA, slow answer). It signs hashes with
  `openssl pkeyutl`, never with our code.
- **Engine tests**: `seal()` byte-identical before and after the split; `prepare`/`complete` with a supplied value;
  overflow refused; a value over other bytes refused; R0 and fill revisions classify as `FormFill` and `Signature`
  in our verifier; a page-content change after a remote signature is `Disallowed` (each seen red with its check
  removed).
- **Fixtures**: `fixtures/sealed/remote-csc-*.pdf` (simple, remote, simple; two remote signers; three documents with
  `multisign` 2), generated by `fixtures/tools/generate.py` against the stub, and checked by `tools/verify-sealed.py`
  with **pyHanko** (whole file, hard-fail revocation, its difference analysis at form filling) and **EU DSS** (each
  signature `TOTAL_PASSED` with the test root, PAdES level detected, **0 undefined changes**). A tampered copy of
  each must fail all three (rule 26).
- **End to end**: the worker's `tests/end_to_end.rs` and a Playwright spec on the Compose stack with the stub, through
  both redirects, including abandon, expiry and retry.
- **keyd `csc` backend**: keyd seals through the stub at SCAL1 and SCAL2; refused without a seal token, as today.
- **Real sandboxes, opt-in** (`OPENSEAL_INTEROP_NETWORK=1`, as the production TSA check): `tools/interop/rsp.py`
  runs one envelope through a provider's sandbox with the owner's credentials and validates the output with pyHanko
  and EU DSS; the result and date are recorded in docs/31. CI never needs network or provider credentials.

#### 5. What the owner must supply

- A commercial agreement and **sandbox access** with DigiCert (Document Trust Manager) and with A-Trust: client ids
  and secrets, test signer identities and credentials (SCAL1 and SCAL2), the roots and intermediates of their test
  and production signer certificates, the redirect URIs to register, and each provider's terms for a third-party
  signing application (some QTSPs require the application to meet their integration conditions or to be named in
  their service; to confirm per provider).
- Which `signatureQualifier` values each provider returns, and whether each requires PKCE or `authorization_details`.
- Counsel review (`LEG-02`, docs/69 question 9) of the docs/09 §2a wording and the certificate's text before the
  first real provider is enabled.

#### 6. Alternatives considered

- **`signatures/signDoc`** (the provider builds the PDF signature): sends the whole document to the provider, gives
  up control of the bytes and of the revision model, and differs between providers. Rejected; it may serve a provider
  that offers nothing else, as its own decision.
- **Sign at completion, over the final document**: every remote signer would have to return after everyone finished,
  and a SAD cannot wait days. Rejected.
- **Flatten each signer's values into page content as today and accept the "modified" verdict**: every validator
  would report earlier signatures as covering a changed document. Rejected: evidence integrity first.
- **`explicit` mode with PIN or OTP typed on our page**: simpler (one redirect fewer), but the signer's credential
  secrets would pass through the platform. Rejected (open question 3 for credentials that offer nothing else).
- **Only the `KeyProvider` seam, calling the provider inside `seal()`**: blocks a worker thread on a person for
  minutes and cannot carry the signer's authorization; kept only for the non-interactive keyd backend (§3.10).
- **A remote signature without the platform seal**: possible, but the platform seal is what binds the later simple
  signers and the final state, and keeps one rule for every completed envelope. Rejected.
- **Certificate pages before the first remote signature**: the certificate must record the remote signatures and
  the completion, which come later. Rejected; the separate sealed certificate is what docs/31 §3 already chose.

#### 7. What changes where, when built

Engine: `casual-sign-seal` (`prepare`, `complete`), `casual-sign-crypto` (CMS around an external value; foreign CMS
for ADR-047), `casual-sign-flatten` (materialize fields; `FILL-01` reused), `casual-sign-workflow` (the commands, the
recipient's `signing_remotely` sub-state, the lock rules), `casual-sign-audit` (the four types),
`casual-sign-certificate` (the remote signer section). Hosts: `casual-sign-csc` (new), the worker (jobs), the server
(ceremony, callback, API), keyd (`csc` backend), the console (catalogue), migrations for the session table, the
catalogue and account enablement. Documents: docs/19, 20, 21, 22, 24, 30, 31, 32, 40, 07, 09, 65, 96.

#### 8. Open questions for the owner

1. **Who contracts with the QTSP?** The operator, for all accounts (simplest; the catalogue holds one set of
   credentials per provider), or each customer with their own contract (the design supports both). Recommendation:
   operator-wide first, per-account credentials as built here for enterprise customers.
2. **Required qualifier per account**: should an account be able to require `eu_eidas_qes` only, so a signer with a
   non-qualified credential cannot sign? Recommendation: yes, as designed (an account option, off by default).
3. **Credentials that offer only `explicit` PIN or OTP entry**: offer them (our page would carry the PIN to the
   provider) or not? Recommendation: not, until a provider we need offers nothing else.
4. **RSA 2,048-bit provider keys**: accept (as designed) or require 3,072+? Recommendation: accept and record; the
   provider's certificate policy governs its keys.
5. **Name mismatch**: when the certificate's name differs from the recipient's name, record it (default) or refuse
   the signature? Recommendation: record by default, refusal as an account option.
6. **Remote signers in parallel**: this design refuses two remote signers at one routing order. Acceptable, or should
   the second wait while the first finishes? Recommendation: refuse at send; it keeps every signature over a known base.

#### 9. As built (`RSP-01`, recorded as each part lands)

- **Status.** Accepted 2026-11-21 (owner instruction 82, with the recommended answers to §8).
- **Engine (§3.3).** `prepare` and `complete` as designed; `seal()` shares their revision writer and its bytes are
  unchanged (a test against a frozen copy of the pre-split code). docs/31 §3.1 As built.
- **Catalogue (§3.11), a decision.** The console is paused (owner instruction 51), so the catalogue is the operator's
  JSON file `OPENSEAL_SIGNING_PROVIDERS_FILE`, read by the server and the worker at start, as RAUTH-01's identity
  providers are; client secrets by reference (`client_secret_ref`), trust anchors as a PEM file. The table
  `platform.signing_providers` with two-custodian changes is `RSP-01A`, the file staying the fallback.
- **Accounts (§3.11).** `account_signing_providers` and `GET`/`PUT /signing-providers` as designed; an account's own
  client secret sealed AES-256-GCM (`casual-sign-csc` `sealing`), each change a
  `workspace.signing_provider_changed` admin event.
- **The return from the provider (§3.4), a decision.** The redirect URI is the signing page's
  `{OPENSEAL_PUBLIC_URL}/s/rsp`, not `GET /rsp/callback/{provider}`: as RAUTH-01's `/s/oidc`, the page keeps the
  signing link in the tab's session storage and posts `state` and `code` (or `error`) to
  `POST /s/{token}/remote-signing/callback`, so the link's cookie binding and rate limits cover the answer and no
  unauthenticated endpoint takes provider answers. The state is checked against the open session's SHA-256 for its
  step and spent in one statement; the code (at most 900 bytes) is sealed with the PKCE verifier for the worker's
  `remote_signing` job (`prepare` after scope `service`, `sign` after scope `credential`; three attempts, idempotent
  per session and phase). docs/40 §6.
- **The worker (§3.4 to §3.6).** `remote_signing` jobs exchange the code (the account's own client secret, else the
  operator's), list and read credentials, keep the eligible ones, and prepare every document the signer sees from
  its current revision: the lock point's R0 when the document has none yet (final values flattened by the
  engine, unfinished fields materialized, one unsigned slot per remote signer, `Remote_<recipient id>`), then the
  signer's fill in place with the slot's appearance, then `prepare` at B-LT. After the second redirect: `signHash`
  with the authorized hashes, one value per hash in order, `complete` (our B-T and the DSS at once) against the
  operator's anchors plus the provider's and the chain's intermediates; the revisions are stored and
  `CompleteRemoteSigning` records `recipient.remote_signed` with the certificate facts and the name match.
  Failures close the session with their reason (`recipient.remote_signing_failed`); nothing falls back to a simple
  signature. At completion the seal job seals each locked document over its latest revision (remaining materialized
  fields filled in place) and the certificate of completion stays a separate sealed PDF, its remote signer block in
  docs/09 §2a's words. HTTP to providers goes through `ureq` with the worker's address policy (no redirects, 30 s,
  plain HTTP only to loopback). docs/31 §3.1 As built.
- **Still to build, each its own row.** keyd's `csc` backend (§3.10, `RSP-01B`: it serves a platform seal key held
  at a QTSP and has no consumer in the per-recipient flow); the signer's choice among several eligible credentials
  (`RSP-01C`; the first eligible one is used, the session's `choosing` step exists unused); `multisign` batches
  (`RSP-01D`; one `signHash` today); P-384 and RSA-PSS credentials (`RSP-01E`; P-256 and RSA PKCS#1 v1.5 with SHA-256
  are eligible); the webhook topic `recipient.remote_signing_failed` (`RSP-01F`); template roles' signature type
  (`RSP-01G`); a real sandbox run and counsel's review (`RSP-01H`).

### ADR-047 — India eSign through a licensed ESP, as an ASP (`RSP-02`)

**Status: Proposed, 2026-11-21.** Owner instruction 75. It touches a wire format (signed XML to and from an ESP), the
audit event schema, key custody (an ASP request-signing key), a new engine crate boundary and a legal property.
**Everything ADR-046 decides for remote-provider signatures applies unchanged**: the per-recipient signature type
(§3.1), the lock point and signer revisions with the platform seal last (§3.2), the two-phase engine API (§3.3), the
hash from the exact prepared bytes (§3.5), the four audit types (§3.7), the separate certificate of completion
(§3.2, §3.8), providers, accounts and secrets (§3.11), the failure model (§3.12) and the API shape (§3.14). This
record decides only what India eSign changes.

#### 1. Context

eSign is India's online electronic signature service: an **eSign Service Provider (ESP)**, a Certifying Authority
licensed by the Controller of Certifying Authorities (CCA), authenticates the signer through an e-KYC provider,
generates a key pair for them, has its CA issue a short-lived certificate, signs the hash an **Application Service
Provider (ASP)** sent, and deletes the key. eMudhra and CDSL Ventures (CVL) are the two ESPs the owner named. OpenSeal
(or its operator) is the ASP: it never sees the signer's Aadhaar number, OTP or biometrics, and it never holds the
signer's key. The owner's operator is in India and India is in the legal scope beside the US and the EU (instruction
52), so this matters early.

#### 2. Protocol facts relied on

Sources, read 2026-11-21 from cca.gov.in: **eSign API Specifications v2.1** ("Online Aadhaar & Others"; version 2.1
of May 2018, changed 10.08.2020 to add `PKCS7pdf` and `PKCS7complete`, and 07.02.2023 to add face authentication; ESP
readiness 07.04.2023) and **eSign API Specifications v3.3** ("CA eKYC Account based", 09 Dec 2020). The CCA lists
v2.0 and earlier as withdrawn. Section numbers below are the specifications'.

| Fact | v2.1 | v3.3 |
| --- | --- | --- |
| Flow | §3.1.1: the ASP sends the request XML through the browser to the ESP's URL (or the ESP's SDK); the ESP authenticates the signer by e-KYC (Aadhaar), shows the hash with `docInfo`, creates a key pair and gets a certificate, signs, and **redirects the browser to the ASP's `responseUrl`** with the response XML | §3.1: the ASP **posts the request server to server** and gets an acknowledgement (`status="2"`, pending, with `resCode`); the browser is then sent to the ESP's authentication page by an `application/x-www-form-urlencoded` POST of `txnref = Base64(txn + "\|" + resCode)` (§3.4); the signer authenticates against their e-KYC account at the CA (PIN and SMS OTP or TOTP, or the ESP's app); the ESP **POSTs the final response to `responseUrl` from its server** and optionally redirects the browser to `redirectUrl` |
| Request | §3.3.1: `<Esign ver sc ts txn ekycId ekycIdType aspId AuthMode responseSigType responseUrl>` with `<Docs><InputHash id hashAlgorithm docInfo>hex</InputHash></Docs>` and an enveloped W3C XML Signature by the ASP | §3.3.1: `<Esign ver signerid ts txn maxWaitPeriod aspId responseUrl redirectUrl signingAlgorithm>`, `InputHash` gains `docUrl` (mandatory) and carries `responseSigType` per document |
| Consent | `sc="Y"` is mandatory and means the ASP took the signer's explicit, informed consent (identity and address data from e-KYC, the certificate application, key generation, one-time signature, key deletion); "Check box [Y/N], No by default" | Consent taken at the ESP's account |
| Clock | `ts` in Indian Standard Time, ISO format, within 30 minutes of the ESP's clock | Same; `txn` unique per ASP and ESP per calendar day; `maxWaitPeriod` in minutes (default 1440) |
| Authentication | `AuthMode`: 1 OTP or TOTP, 2 fingerprint, 3 iris, 4 face; OTP gives a "Single Factor" class certificate, biometrics "Multi Factor" (India PKI CP) | ESP account's PIN and second factor; `signerid` (`id@id-type.esp-id`, id types username, mobile, PAN) optional |
| Documents per request | `id` "should be 1. Only single document hash is allowed" | 1 to 5, sequential; the signer may untick one, which returns that `DocSignature` with error "User Rejected" |
| Hash | `hashAlgorithm` fixed to `SHA256`, the value in hex | Same |
| Response signature types | `rawrsa`, `rawecdsa`, `PKCS7` (signer certificate only, no revocation), `PKCS7pdf` (all issuer certificates to the root, CRLs or OCSP for each issuer as the signed attribute `pdfRevocationInfoArchival` 1.2.840.113583.1.1.8, and "should also be time stamped" by the CA's TSA), `PKCS7complete` (issuer certificates and revocation as unsigned information) | `raw`, `PKCS7`, `PKCS7pdf` (time-stamp optional), `PKCS7complete`; `signingAlgorithm` `RSA` or `ECDSA` |
| Response | §3.4: `<EsignResp status ts txn resCode errCode errMsg>` with `<UserX509Certificate>` (base64 DER), `<Signatures><DocSignature id sigHashAlgorithm error>` and the ESP's enveloped XML Signature; `resCode` is the ESP's transaction id, which "ASP is expected to store in their audit log"; "the API does not give any identity related data of the eSign user" | §3.5: as v2.1 with `ver`, `status` 1, 0 or **2 (pending)**, `error`; the same `resCode` across the acknowledgement and the final answer |
| Status check | — | §3.6: `<EsignStatus ver ts txn aspId>` signed by the ASP returns the response again; the ESP keeps it at least 30 days |
| Errors | Annexure 1: `ESP-901` to `ESP-999` (for example `ESP-911` input signature verification failed, `ESP-944` and `ESP-945` user terminated, `ESP-946` page expired, `ESP-991` database error, `ESP-999` unknown), and UIDAI authentication errors passed through | As v2.1, plus "User Rejected" per document |
| Certificate | §3.1.1(h): an e-KYC class certificate "which has e-KYC number, Name of the eSign user, e-KYC response code, Authentication Type, and Time Stamp embedded"; v3.3 §1: "limited validity period and is only for one-time signing" | Same |

**To confirm with each ESP's sandbox (UAT)**: how a browser carries the request and the response in v2.1 (the
specification says POST `application/xml`, which a browser form cannot send; ESPs take it in a named form field);
which XML canonicalization and signature algorithm their XML Signatures use; the exact signed attributes of their
`PKCS7pdf` CMS (ESS `signing-certificate-v2` present or not, CMS `signingTime` present or not, DER or BER, a
time-stamp or not); what the certificate's "e-KYC number" holds (a token, a hash, masked digits); the certificate
policy OIDs of each class; which versions each ESP runs; the maximum size of a response; whether an API key is
required beside the XML Signature.

#### 3. Decision

##### 3.1 Versions and flows

The adapter speaks **v2.1** (Aadhaar online e-KYC, the common case for individual signers) and **v3.3** (an e-KYC
account at the CA), chosen per catalogue row; one ESP may appear twice. The ceremony of ADR-046 §3.4 becomes:

1. Review as today. Then the **eSign consent** (v2.1): a versioned text (the points §3.3.1.1 lists, in the signer's
   language, reviewed by counsel), a checkbox unticked by default, and **Sign with eSign (<ESP>)**. The text's
   SHA-256 goes into `recipient.remote_signing_started`; without the tick no request is made (`sc="Y"` is never sent
   on the platform's word alone).
2. `BeginRemoteSigning` as in ADR-046. No certificate is needed before signing (the ESP issues it), so the worker
   prepares the documents at once (lock point, revisions, ByteRange digests) and records
   `recipient.remote_signing_prepared`; the page shows the exact prepared bytes.
3. **v2.1:** the worker builds and signs the request; the page posts it to the ESP's URL in a top-level navigation;
   the signer enters their Aadhaar number or VID and authenticates **at the ESP**; the ESP sends the browser back to
   `POST /rsp/esign/{provider}/response` with the response; the server stores it (bounded, §3.5) and queues the
   worker. One request per document (v2.1 allows one hash), in order, the page saying "document 2 of 3".
   **v3.3:** the worker posts the request server to server (up to 5 hashes, so 5 documents per round trip), keeps the
   acknowledgement's `resCode`, and the page posts `txnref` to the ESP's authentication page; the ESP's final answer
   arrives server to server at the same `responseUrl` (and the browser returns through `redirectUrl` to a page that
   polls). With no answer when the session's time ends, the worker asks `EsignStatus` once before closing it
   `expired`.
4. The worker checks the response and the CMS (§3.4, §3.5), completes each document (ADR-046 §3.3 `complete` with
   `ExternalSignature::Cms`) and records `recipient.remote_signed`, `recipient.signed`, `recipient.completed`.

Request values: `ver` from the catalogue; `txn` the session id (a UUIDv7, unique per day by construction);
`ts` from the worker's clock in IST; `aspId` from the catalogue; `AuthMode` from the account's allowed list (OTP and
face by default; fingerprint and iris need a registered capture device at the signer's side, so only for an account
that runs assisted signing); `responseSigType` `PKCS7pdf`; `ekycId` and `ekycIdType` per the specification with **no
UID token**, so the request carries no Aadhaar data; `maxWaitPeriod` the session's limit in minutes; `signerid` not
sent unless the account opts in and the sender gave one; `signingAlgorithm` `RSA` unless the catalogue row says the ESP
offers ECDSA. `docInfo` is the document's name cut to 50 characters with control characters removed, or the account's
generic label ("Agreement <envelope short id>") if the account chooses not to send names. **v3.3 `docUrl`** is a
capability URL to the exact prepared bytes: 256 random bits, one document, valid only while the session is open,
read-only, each fetch recorded as `document.downloaded` by the ESP's viewer.

##### 3.2 The hash and the response type

`InputHash` is the hex SHA-256 **ByteRange digest** of the prepared revision (ADR-046 §3.5); with `PKCS7pdf` the ESP
writes it as the CMS `message-digest` signed attribute and signs its own signed attributes. We ask for `PKCS7pdf`
because the certificate lives minutes: the issuer chain and the revocation data the ESP gathers at signing time are
what a validator needs years later, and the CA's time-stamp fixes the time inside the certificate's validity.
`PKCS7complete` and `PKCS7` are accepted per catalogue row (we then gather revocation ourselves at once). **`rawrsa`,
`rawecdsa` and `raw` are not used**: we would have to build the signed attributes, whose ESS `signing-certificate-v2`
names a certificate that does not exist until the ESP signs; the only CMS possible without them is a legacy one with
no signed attributes.

##### 3.3 Which PDF signature format we write

The ESP's CMS is theirs; we never re-sign or re-encode its signed attributes (they are verified as received, docs/31
§8). The `SubFilter` follows what the CMS is: **`ETSI.CAdES.detached`** when its signed attributes are
`content-type`, `message-digest` and ESS `signing-certificate` or `signing-certificate-v2`, without CMS
`signingTime`; otherwise **`adbe.pkcs7.detached`**. docs/31 §2 says we never write `adbe.pkcs7.detached`; this ADR
makes one exception: it is written **only to carry a provider's CMS that is not CAdES-conformant**, never for a
signature we make. Its time-stamp: an existing `signature-time-stamp` unsigned attribute is kept if it verifies to an
anchor configured for that ESP (the CA's TSA under the CCA root); otherwise we add ours (B-T), re-encoding only the
outer SignedData in DER with the signed attributes' bytes untouched. Then, as for every remote signature, a DSS
revision at once (B-LT for it) from the CMS's archival revocation data and fresh OCSP or CRL answers for the signer
certificate. A **BER** CMS is refused (`CS-RSP-0004`) until `SEAL-13` decides whether BER from third-party signers is
accepted; the certificate of completion states the format and level honestly ("CMS signature, adbe.pkcs7.detached,
with time-stamp and validation data", never "PAdES" when it is not).

##### 3.4 What is checked before anything is embedded

The response: its XML Signature verifies (§3.5) under **the ESP's response-signing certificate configured in the
catalogue** (never a certificate from the message); `txn` names an open session of this provider and this is the
first valid answer for it (a second, from the browser and the server both, is ignored once one is accepted; a
replay after close is refused `CS-RSP-0003`); `status="1"`; one `DocSignature` per `InputHash` sent, by id. The CMS:
exactly one SignerInfo; `message-digest` equals our ByteRange digest for that document; the signature verifies over
the signed attributes as received; the signer certificate is the `UserX509Certificate`; its chain builds to the
configured anchors (the CCA root for the environment, through the ESP's CA), with digital-signature or
non-repudiation key usage, valid at the time-stamp time, not revoked; SHA-256 or stronger; RSA 2,048 bits or more or
ECDSA P-256 or P-384 (ADR-046 §3.6). Any failure fails the session `response_invalid` and nothing is written.

##### 3.5 XML: a bounded reader and a narrow XML Signature profile

- **No general XML library in the product.** The bounded XML reader of ADR-026 (refuses DTDs and entities, bounds
  depth, nodes and attributes) moves from `casual-sign-xfa` into an engine crate of its own, **`casual-sign-xml`**,
  whose consumers are `-xfa` and the new host crate below (a crate boundary change, which this ADR records; docs/19
  when built). Limits for eSign answers: 512 KiB per response, depth 16, 256 elements, 5 `DocSignature`, 16 KiB of
  base64 certificate, 512 KiB of base64 per signature; the reader's own limits otherwise (docs/21).
- **XML Signature, one profile**: an enveloped `Signature` as the last child of the root; one `Reference` with
  `URI=""`; transforms enveloped-signature then canonical XML 1.0 or exclusive canonical XML (whichever the ESP uses,
  to confirm); digest SHA-256; signature RSA-SHA256 (or ECDSA-SHA256 if an ESP uses it). Anything else (other
  references, `XPath` transforms, comments, more than one `Signature`, a `Signature` elsewhere) is refused. The values
  the worker reads come from **the same parsed tree** whose canonical form was verified, so signature wrapping finds
  nothing to wrap. Canonicalization of that subset (namespaces in scope, attribute order, character escaping) is
  written in the host crate **`server/casual-sign-esign`** (request writer, canonicalization, signature verification
  with aws-lc-rs, response reader, error mapping; consumers the worker and the server); it is not cryptography of
  our own, and interoperability is checked in CI against **xmlsec1**, an independent implementation (§4).
- **Requests are signed by the ASP's key in keyd**, never a key on disk in the worker: a new alias class for ASP
  keys, which keyd answers only with an **ASP token** the database mints for an open eSign session
  (`openseal-keyd-asp-token-v1`, HMAC over the session id and expiry, the seal-token mechanism of ADR-036 with its own
  label and key), so a caller with the worker's identity can sign ASP requests only for sessions the database says
  are open. The ASP's certificate (public) is in the catalogue and in the signature's `KeyInfo` if the ESP wants it.

##### 3.6 The ESP's endpoints on our side

`POST /rsp/esign/{provider}/response` is public: in v2.1 the browser brings the answer, in v3.3 the ESP's server
does. It is authenticated only by what §3.4 checks, so it is rate-limited per provider and IP, refuses bodies over the
limit before reading them, and answers the same way for a known and an unknown `txn`. A catalogue row may add an IP
allow-list for v3.3 server calls. The raw request and response XML of each session are kept with the envelope's
evidence (blob store, hashes in the chain, §3.8), as the ASP's record of the transaction.

##### 3.7 Aadhaar and personal data

OpenSeal **never asks for, receives or stores** an Aadhaar number, VID, UID token, OTP, biometric or e-KYC record:
the signer gives them to the ESP on the ESP's page, and the request carries none. What we receive is the signer's
certificate, which the specification says embeds an "e-KYC number", the name, the e-KYC response code, the
authentication type and a time; it is necessarily inside the signed PDF, since a validator needs it. The whole
certificate is classified as personal data (docs/07 §Data): logs carry only its fingerprint; the chain records its
fingerprint, issuer, serial, validity, subject common name and policy OIDs, never its other attributes. Whether the
"e-KYC number" in issued certificates is Aadhaar-derived, and what that means for showing it in the certificate of
completion, is to confirm on a sandbox certificate and for counsel (§8 question 6); until then the certificate of
completion prints only the fields above.

##### 3.8 Audit trail and certificate of completion

ADR-046's four types, with `provider.kind = "in_esign"` and these members: `remote_signing_started` adds
`consent_sha256` (the eSign consent text) and `api_version`; `remote_signing_prepared` adds per document the
`txn`; `remote_signed` adds `provider_reference` = the ESP's `resCode`, `auth_mode` (what the request allowed, and
the authentication type the certificate states), `request_sha256` and `response_sha256` (the stored XML),
`signature_format` (`ETSI.CAdES.detached` or `adbe.pkcs7.detached`) and the certificate's policy OIDs;
`remote_signing_failed` adds the ESP's error code (`ESP-944`, a UIDAI code, "User Rejected"), never its message. The
certificate of completion says, per signer: "Signed with eSign through <ESP>; the signer authenticated at the ESP by
<Aadhaar OTP, face, …>; certificate issued by <CA>", the `resCode`, the certificate's details and the format. Nothing
says the signature is valid under the IT Act; docs/09 §2a and §4 hold the wording.

##### 3.9 Failures (in addition to ADR-046 §3.12)

| ESP answer | Session result |
| --- | --- |
| `ESP-944`, `ESP-945` (user terminated), UIDAI authentication failures, "User Rejected" on a document | `cancelled`; fields reopen |
| `ESP-946` (page expired), no answer by the session's end (after `EsignStatus` in v3.3) | `expired` |
| `ESP-901` to `ESP-911`, `ESP-922`, `ESP-992` (the request or the ASP was refused) | `provider_refused`; an operator alert, since these mean a configuration or ASP registration problem, not the signer's |
| `ESP-991`, `ESP-993`, `ESP-999`, HTTP failure | `provider_unavailable` |
| `status="2"` from a status check | Still pending; the session stays open until its end |

#### 4. Test strategy, without a real ESP

- **A stub ESP** in `tools/e2e/auth_stubs.py` (`esign`; standard library, the `openssl` command and **xmlsec1**, a
  CI tool only): both flows (v2.1 through the browser, v3.3 server to server with acknowledgement, `txnref`,
  background answer, `EsignStatus`), a page asking for a made-up 12-digit number and a code, a per-transaction
  certificate issued by a test "ESP CA" under a test "CCA root" (`tools/interop`), CMS built from the given hash by
  writing the signed attributes in DER by hand and signing them with `openssl pkeyutl` (never with our crypto
  code), and its responses signed with `xmlsec1 --sign`; our requests are checked with `xmlsec1 --verify` against the
  test ASP certificate. Variants: CAdES-like; Adobe-like `PKCS7pdf` (`signingTime`, `pdfRevocationInfoArchival`, a
  CA time-stamp); `PKCS7`; `PKCS7complete`; BER-encoded; a digest of other bytes; another certificate than
  `UserX509Certificate`; an expired certificate; an unsigned, wrongly signed or wrapped XML; a DTD or entity payload;
  an oversize body; a late, replayed or duplicate answer; each Annexure error code.
- **Fixtures**: `fixtures/sealed/remote-esign-*.pdf` (one per CMS variant that is accepted), checked by our verifier,
  **pyHanko** and **EU DSS** with the test CCA root, each with a tampered copy that fails all three.
- **Unit and hostile tests** for `casual-sign-xml` (moved, behaviour unchanged, the XFA corpus still passing) and
  `casual-sign-esign` (canonicalization against xmlsec1 outputs committed as fixtures; every refusal of §3.5 seen
  red), and a fuzz target for the response reader.
- **End to end**: worker tests and a Playwright spec on the Compose stack through the stub, for both versions,
  including cancel, expiry, a status-check recovery and a multi-document envelope.
- **Real UAT, opt-in** (`OPENSEAL_INTEROP_NETWORK=1`): `tools/interop/rsp.py --esign` through eMudhra's or CVL's UAT
  with the owner's ASP credentials and the test identities the ESP provides; validated by pyHanko and EU DSS; the run
  and date recorded in docs/31.

#### 5. What the owner must supply

- **ASP onboarding with each ESP** (eMudhra, CVL): the agreement and commercial terms, the **ASP ID**, the ASP's
  request-signing certificate registered with the ESP (which certificate class and issuer each ESP accepts: to
  confirm) with its key provisioned in keyd's HSM, UAT and production URLs per API version, the ESP's
  response-signing certificate, the CCA root and ESP CA chains for UAT and production, the test identities UAT
  accepts, and the ASP obligations each ESP sets (consent wording, how long the ASP keeps transaction logs, any
  security audit or undertaking: to confirm).
- Whether **the operator is the ASP** for every account, or some customers register as ASPs themselves.
- **Counsel review** (`LEG-02`, `LEG-03`) of the docs/09 §2a and §4 wording, the eSign consent text, and the handling
  of the certificate's e-KYC attributes under the IT Act 2000 (section 3A and the Second Schedule), the CCA's
  e-authentication guidelines, the Aadhaar Act 2016 and the DPDP Act 2023.

#### 6. Alternatives considered

- **`rawrsa` or `raw` responses** with our own CMS: impossible to make CAdES-conformant (the certificate is unknown
  until the ESP signs). Rejected.
- **The ESP's JavaScript SDK or widget inside our signing page**: a third party's script in the page that holds the
  agreement, against the strict CSP (docs/07). Rejected; top-level navigation to the ESP instead.
- **xmlsec1 or libxml2 in the product** for XML Signature: a C parser outside ADR-006 with a history of entity and
  memory defects. Rejected for the product; used in CI only, as the independent check.
- **An eSign aggregator** instead of direct ESP onboarding: if it speaks the CCA API it is just another catalogue row;
  a proprietary API would be its own adapter and ADR.
- **eSign Remote API** (the CCA's remote key storage specification) and USB-token DSCs through a browser bridge:
  other products, other decisions (the bridge is slice 18).

#### 7. What changes where, when built

Engine: `casual-sign-xml` (new, moved from `-xfa`), `-seal` and `-crypto` (`ExternalSignature::Cms`, keeping a
foreign CMS's signed attributes and adding an unsigned time-stamp), `-workflow`, `-audit`, `-certificate`. Hosts:
`casual-sign-esign` (new), the worker, the server (consent, response endpoint, `docUrl`), keyd (ASP alias class and
ASP tokens), migrations (sessions' eSign members, the token function). Documents: docs/19, 20, 21, 22, 24, 31, 32, 40,
07, 09, 65, 96.

#### 8. Open questions for the owner

1. **Which version first**: v2.1 (Aadhaar online e-KYC, individuals; recommended first) and v3.3 in the same row if the
   ESP offers it, or v2.1 only?
2. **Operator as the ASP** for every account (recommended first), or per-customer ASPs too?
3. **Authentication modes allowed by default**: OTP and face (recommended), or OTP only? Fingerprint and iris only for
   accounts that run assisted signing?
4. **`docInfo`**: send the document's name (recommended, cut to 50 characters) or always a generic label?
5. **Keeping the raw request and response XML** with the envelope's evidence for as long as the envelope (recommended),
   or only for the ESP's required log period?
6. **The certificate's e-KYC attributes**: if a sandbox certificate shows Aadhaar-derived data, may the signed PDF
   carry it (it must, to be verifiable) and may the certificate of completion show any of it? Counsel to answer.
7. **Name mismatch** between the e-KYC name and the recipient's name as sent: record (recommended) or refuse?
8. **Non-CAdES CMS** (`adbe.pkcs7.detached`, if an ESP's `PKCS7pdf` carries `signingTime`): accept as designed, or
   offer only ESPs whose CMS is CAdES-conformant?
