# 02 — High-level design

**Status: Draft for owner.** The shape of the system, what is inherited from OpenCalc and OpenPresent, and what must
differ. Detailed designs live in the pillar documents this page links to. Nothing here is built yet.

## 1. The one-paragraph version

OpenSeal is **a deterministic, headless agreement engine in Rust, hosted by a server of record.** The engine owns the
PDF, the fields, the routing rules, the seal and the evidence; it does no I/O, reads no clock and holds no key, so the
same code runs in the server, in the browser through WebAssembly, and in a verifier anyone can run offline. The server
owns identity, persistence, delivery (email, SMS, webhooks), key custody and policy. The web app is a vanilla-JS client
of the public API, built the way the sisters' editors are built, and is itself replaceable: everything it does, an
integrator can do through the API or the embeddable elements.

## 2. Why this shape, and why it differs from the sisters

OpenCalc and OpenPresent are **client-heavy document editors**: the file is the product, the engine runs in the
browser, and a server exists only to order collaborative edits. An e-signature product is the opposite in one respect
and identical in another.

| | Sisters (OpenCalc, OpenPresent) | OpenSeal |
| --- | --- | --- |
| The product is | The file | **The evidence that the file was agreed to** |
| System of record | The user's file | **The server**: no party may hold the only copy of the evidence |
| Trust | The editor trusts its user | **No party trusts another**: sender, signer and operator are each potential adversaries of the record |
| Engine role | Model, layout, render, export | Admit, place, fill, flatten, seal, verify, chain events |
| Engine runs in | Browser (WASM) and native | Server, browser (WASM: preview, validation, offline verify) and CLI |
| Hard problems | Fidelity of a format, text layout, OT | **Cryptographic correctness, tamper evidence, multi-party workflow, delivery, tenancy** |
| Collaboration | Real-time OT | Asynchronous routing; real-time only for template co-editing (slice 26) |

So the **engine-and-host split is inherited unchanged** (sisters' ADR-002), and the **server becomes first-class**,
not an optional adjunct.

## 3. Context

```
                    ┌───────────────────────── Operator's deployment ─────────────────────────┐
  Sender (browser) ─┤                                                                          │
  Signer (browser) ─┤  edge (TLS, WAF) ─▶ casual-sign-server ──▶ PostgreSQL (record, audit)    │
  Integrator (API) ─┤                       │      ▲            ──▶ Object store (documents,   │
  AI agent (MCP)  ──┤                       │      │                 immutable versions)      │
                    │                       ▼      │                                           │
                    │                 casual-sign-worker ──▶ casual-sign-keyd ──▶ HSM / KMS   │
                    │                       │                 (holds no data, only signs     │
                    │                       │                  digests)                        │
                    └───────────────────────┼───────────────────────────────────────────────────┘
                                            ├──▶ SMTP / email API      (notifications)
                                            ├──▶ SMS / voice provider  (OTP, phone auth)
                                            ├──▶ RFC 3161 TSA          (timestamps)
                                            ├──▶ OCSP / CRL            (revocation for LTV)
                                            ├──▶ IdP (OIDC / SAML)     (staff SSO)
                                            ├──▶ IDV provider          (ID verification, plugin)
                                            ├──▶ Payment provider      (collect payment, plugin)
                                            └──▶ Integrator endpoints  (webhooks)
  Anyone, offline ─▶ verify.html (WASM) or `openseal verify` CLI — needs no server
```

Every arrow leaving the deployment goes through a **host seam** (§8): an interface with a default implementation and a
test double. Nothing in `crates/` knows any of them exist.

## 4. The layers

```
 Clients      webapp/ (app, prepare, sign, verify)   sdk/ (JS elements, typed API client)   desktop/   MCP
                              │ HTTPS: REST /api/v1, signer ceremony, webhooks out
 Hosts        server/casual-sign-server (axum)   server/casual-sign-worker (jobs)   server/casual-sign-keyd
              server/casual-sign-convert (sidecar)   server/casual-sign-mcp   server/casual-sign-secrets
                              │ Rust calls, values in and out, no I/O
 Engine SDK   crates/casual-sign-sdk  ·  crates/casual-sign-wasm
 Engine       workflow ── model                    (envelopes, routing, state machine, policies)
              fields ──── model, pdf               (geometry, validation, formulas, conditions, anchors)
              flatten ─── pdf, fields, fonts       (values → page content, signature images)
              certificate ─ audit, flatten         (certificate of completion PDF)
              seal ────── pdf, crypto              (PAdES B-B/B-T/B-LT/B-LTA, DSS, doc timestamps)
              verify ──── pdf, crypto              (any signed PDF; revisions; trust; LTV)
              audit ───── model, crypto            (events, canonical form, hash chain, anchors)
              crypto                                (CMS, X.509, TSP, OCSP/CRL structures; KeyProvider trait)
              pdf                                   (bounded reader, object model, incremental writer)
              model                                 (types, ids, invariants; no dependencies)
```

The dependency DAG, crate by crate, is [19](19-WORKSPACE-SCAFFOLD-DESIGN.md).

## 5. Core flows

### 5.1 Send

```
upload ─▶ admit (bounded parse, neutralize actives, report) ─▶ normalize (convert non-PDF; optional flatten of
existing AcroForm) ─▶ store immutable original + hash ─▶ prepare (recipients, routing, fields placed by hand, by
anchor text, or from a template) ─▶ validate (engine: every signer has a signature field, geometry within page,
conditions acyclic) ─▶ send: envelope sealed for editing; document hash fixed; audit `envelope.sent`
─▶ workflow computes the first routing step ─▶ worker delivers invitations
```

### 5.2 Sign (the ceremony)

```
invitation link (opaque token, single envelope, single recipient) ─▶ recipient authentication (access code, email
OTP, SMS OTP, IdP, IDV plugin) ─▶ ERSD consent (records the disclosure version) ─▶ document delivered: the exact
bytes whose hash is in the chain ─▶ fill fields (engine-side validation in WASM, re-run on the server) ─▶ adopt
signature (draw, type, upload) ─▶ review: the engine's flattened preview of what will be sealed (WYSIWYS, §6.4) ─▶
finish: server re-validates, records values, audit `recipient.signed` with value hashes ─▶ workflow advances
```

Decline, reassign (if allowed), finish later, and in-person hosting are branches of the same machine
([24](24-ENVELOPE-LIFECYCLE-AND-ROUTING.md)).

### 5.3 Complete and seal

```
last required action ─▶ envelope `completing` ─▶ worker: flatten all values into the documents (incremental update)
─▶ generate certificate of completion ─▶ attach audit trail as an associated file (PDF/A-3 style) ─▶ compute ByteRange
digest ─▶ keyd signs digest (HSM) ─▶ TSA timestamp (B-T) ─▶ fetch OCSP/CRL, add DSS (B-LT) ─▶ optional document
timestamp (B-LTA) ─▶ verify the output with casual-sign-verify before release ─▶ store immutable ─▶ audit
`envelope.completed` with the sealed hash ─▶ deliver copies and webhooks
```

A failure anywhere leaves the envelope in `completing` with a retryable job; it never reaches `completed` with an
unsealed or unverified document.

### 5.4 Verify

Anyone holding a completed PDF verifies it **without our server**: the WASM verifier in `verify.html` or the CLI checks
every signature, every revision, the timestamp, the certificate chain against a supplied trust list, and the embedded
audit chain against the hash in the certificate of completion. The server's verification endpoint is a convenience
that runs the same code.

## 6. Design rules

1. **The engine is pure.** Time, randomness, keys, fonts, trust lists and network answers (TSA, OCSP) are supplied as
   values. This is what makes every seal reproducible in a test and every verdict the same on every host.
2. **Mutation only through commands.** Every change to an envelope is a typed command applied by `-workflow`, which
   returns the new state, the audit events and the effects to perform (send this email, schedule this reminder). The
   server performs effects; it never mutates state outside a command. This is the sisters' "mutation only through
   operations" in a form that fits a workflow.
3. **Evidence before acknowledgement.** An audit event is durable (committed in the same database transaction as the
   state change) before the client hears success.
4. **Append-only evidence.** Audit events are never updated or deleted; documents are never overwritten; a sealed PDF
   is never modified except by appending a signed revision.
5. **What you see is what you sign (WYSIWYS).** The signer reviews pages rendered from the engine's flattened output,
   not from DOM overlays, before finishing. The document hash recorded at delivery is the hash of the bytes rendered.
6. **Deny by default, per object.** Every request is authorized against the object it touches and the tenant it
   belongs to; Postgres row-level security is a second line, never the first.
7. **The host owns policy.** Retention, branding, which authentication methods are allowed, which TSA, which trust
   list, which email provider: configuration, not code.
8. **No silent loss.** A PDF feature we neutralize (JavaScript, embedded files, existing form fields, existing
   signatures) is named in the admission report shown to the sender.
9. **One verifier.** Our own seals and third-party signatures go through the same `-verify` crate, and every seal is
   checked by it and by an independent validator before release ([31](31-SEALING-AND-SIGNATURES.md)).

## 7. Inherited from the sisters, unchanged

Each has already been paid for there.

- Rust core compiling unchanged to native and `wasm32-unknown-unknown`; no `#[cfg]` forks; platform needs arrive as
  host-supplied values (OpenCalc's ADR-019).
- Bounded admission of untrusted input: every limit named, coded, fixtured and fuzzed (OpenCalc's docs/21, OpenPresent's
  docs/07 and docs/21).
- Recovery before refusal for unsigned input; typed error codes that carry no document content (OpenPresent's ADR-015,
  docs/20).
- `casual-calc-secrets`: secrets from `NAME_FILE`, both set is an error. Copied with provenance.
- Host-signed JWT identity verified against JWKS, deny-by-default access checks on every operation (OpenCalc's docs/59,
  docs/72), applied here to API calls instead of OT operations.
- A vanilla-JS web app with no framework or bundler: data-driven toolbar, command registry, Fluent icons (MIT),
  `--oc-*`-style tokens, shadow-root custom elements for embedding (OpenCalc's docs/55).
- Tauri desktop shell (OpenCalc's docs/44, docs/81), MCP agent access (OpenCalc's docs/97), Docker Compose and cluster
  deployment (OpenCalc's docs/65).
- One roadmap, one tracker, docs true as of a commit, CI as the gate, the same skills.

## 8. Host seams

| Seam | Trait (engine or server) | Default | Plugins planned |
| --- | --- | --- | --- |
| Key custody | `KeyProvider` (engine) | `keyd` with PKCS#11; file key in dev only | AWS KMS, GCP KMS, Azure Key Vault, HashiCorp Vault Transit |
| Timestamps | `TimestampSource` (engine trait, server impl does HTTP) | Configured RFC 3161 TSA list with failover | Qualified TSAs for eIDAS |
| Revocation | `RevocationSource` | OCSP then CRL over HTTP, cached | — |
| Trust | `TrustStore` (value) | Bundled Mozilla roots plus operator roots; EU LOTL for verification | AATL list (operator-supplied) |
| Object storage | `BlobStore` (server) | Local filesystem; S3-compatible | Azure Blob, GCS |
| Email | `Mailer` | SMTP | SES, SendGrid, Postmark |
| SMS / voice | `Messenger` | Disabled | Twilio, Vonage, MessageBird |
| Identity verification | `IdentityVerifier` | Disabled | Onfido, Veriff, Persona, eID schemes, BankID |
| Payments | `PaymentGateway` | Disabled | Stripe |
| Document conversion | `Converter` | Sister engines (OpenDoc, OpenCalc, OpenPresent PDF export) where present; LibreOffice in a sandboxed container | — |
| Remote qualified signing | `RemoteSigner` | Disabled | Cloud Signature Consortium (CSC) API v2 providers |
| Fonts | value | Bundled Liberation, Noto, and signature script fonts (OFL) | Operator fonts |

## 9. Data and storage

- **PostgreSQL** is the system of record: tenants, users, envelopes, recipients, fields, templates, audit events, jobs,
  webhooks. One database, row-level security on every tenant table, forward-only migrations. Model in
  [22](22-DATA-MODEL.md).
- **Object store** holds document bytes, content-addressed by SHA-256, write-once. Optional S3 Object Lock (WORM) for
  regulated tenants.
- **Job queue** is Postgres (`FOR UPDATE SKIP LOCKED`), so a deployment needs two stateful services, not three. Redis is
  optional, for rate limiting and caching in a cluster (OpenCalc's docs/59 pattern).
- **Encryption at rest:** database and object store encrypted by the platform; documents additionally envelope-encrypted
  per tenant with a data key wrapped by the KMS (BYOK, slice 15).

## 10. Deployment shapes

| Shape | What runs | For |
| --- | --- | --- |
| Single node | `docker compose up`: server, worker, keyd (file key), Postgres, MinIO, Mailpit | Evaluation, small teams |
| Cluster | N servers behind a load balancer, M workers, keyd pair with HSM, managed Postgres, S3 | Production |
| Embedded | A host app uses `casual-sign-sdk` directly (no server) to fill, seal and verify | Products that bring their own workflow |
| Offline verify | `verify.html` or the CLI | Anyone |

Statelessness: servers and workers hold no state beyond caches; any node serves any request. Jobs are idempotent and
keyed, so a crashed worker's job is retried safely ([24](24-ENVELOPE-LIFECYCLE-AND-ROUTING.md) §Effects).

## 11. Quality attributes

Targets are in [10](10-ENTERPRISE-REQUIREMENTS.md); the threat model is [07](07-SECURITY-THREAT-MODEL.md); legal
underpinning is [09](09-LEGAL-AND-COMPLIANCE.md). The ones that shape the architecture:

- **Integrity** — hash chain per envelope; seals verified before release; WORM option; key isolation in `keyd`.
- **Confidentiality** — tenant isolation (RLS + scoped repository); per-tenant data keys; no PII in logs.
- **Availability** — stateless nodes; idempotent jobs; TSA and email failover; a signer can finish even if email is down.
- **Long-term verifiability** — PAdES B-LT/B-LTA, PDF/A-3 output, audit trail embedded in the file, published
  verification algorithm.
- **Determinism** — same inputs, same bytes; reproducible builds of the verifier.

## 12. What is out of the core

Contract lifecycle management, transaction rooms, a workflow builder and AI agreement analysis are **add-on modules**
(slices 32–35) built on the public API and event stream, not code inside the signing core; remote online notarization
is a slice (31) with licensed provider integrations ([01](01-PRD.md) §5).
