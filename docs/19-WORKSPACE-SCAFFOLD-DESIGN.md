# 19 — Workspace and layer division

**Status: Draft for owner. As built (2026-11-10):** eleven members: `-model`, `-fields`, `-pdf`, `-crypto`, `-verify`, `-flatten`, `-seal`, `-audit`, `-certificate` (built), `-sdk` and `-wasm` (skeletons, in progress). `fuzz/` targets: `admit`, `normalize`, `content`, `verify`, `verify_chain`, `seal`. The **Key external dependencies** column is the target; a crate not yet built does not have them.

## Layout

```
openseal/
  Cargo.toml                 workspace; edition 2024; Apache-2.0; lints copied from the sisters
  rust-toolchain.toml        pinned, with wasm32-unknown-unknown
  deny.toml                  copied from OpenPresent; licence allow-list unchanged
  crates/                    the engine: pure, no I/O, wasm-compatible (except where marked)
  server/                    hosts: may depend on crates/, never the reverse
  webapp/                    vanilla-JS clients: app, prepare, sign, verify, site
  sdk/                       JS custom elements and generated API clients
  desktop/                   Tauri shell (slice 21), its own workspace
  api/openapi.yaml           the API contract
  migrations/                numbered, forward-only SQL
  fixtures/                  PDFs with provenance: generated, producers, hostile, sealed, tampered
  fuzz/                      cargo-fuzz targets, separate workspace
  tools/                     check-repo.py, verify-sealed.py, fixture generators
  deploy/                    Dockerfiles, compose files, Helm chart (slice 20)
  docs/                      this documentation
```

## Crates

| Crate | Layer | Depends on (internal) | Key external dependencies | First consumer |
| --- | --- | --- | --- | --- |
| `casual-sign-model` | Engine | — | `serde`, `rust_decimal` | `-workflow`, `-fields` |
| `casual-sign-pdf` | Engine | — | `miniz_oxide` (streaming Flate, inflate and deflate); `aes`, `cbc`, `rc4`, `md-5`, `sha2`, `stringprep`, `zeroize` (decrypting input); dev: `lopdf =0.47.0` (oracle, no default features), `peak_alloc` | `-fields`, `-flatten`, `-seal`, `-verify` |
| `casual-sign-fields` | Engine | model, pdf | `rust_decimal`, `regex` (linear-time matching), `unicode-normalization` | `-flatten`, `-wasm` |
| `casual-sign-flatten` | Engine | pdf, fields, model | `skrifa` (font metrics), `png`, `zune-jpeg`, `miniz_oxide`, `unicode-normalization`; TrueType subsetter copied from OpenPresent | `-certificate`, `-sdk` |
| `casual-sign-crypto` | Engine | — | `der`, `spki`, `x509-cert`, `cms =0.3.0-rc.2`, `x509-tsp =0.2.0-rc.0`, `x509-ocsp =0.3.0-rc.1`, `sha2`, `p256`, `p384`, `rsa` (verify only, feature `rsa`); dev: `aws-lc-rs` (test `KeyProvider`), `rcgen` | `-seal`, `-verify`, `-audit` |
| `casual-sign-seal` | Engine | pdf, crypto, verify (self-check, docs/31 §4 step 8) | `sha1` (PAdES `/VRI` identifiers only) | `-sdk` |
| `casual-sign-verify` | Engine | pdf, crypto (audit joins with stage 1I) | `der`, `spki`, `x509-cert`, `x509-ocsp`, `sha2`, `p256`, `p384`, `rsa` (verify only, default feature) | `-sdk`, `-wasm` |
| `casual-sign-audit` | Engine | model, crypto | `serde`, `serde_json`; RFC 8785 and a bounded JSON parser are our own | `-workflow`, `-certificate` |
| `casual-sign-certificate` | Engine | audit, flatten, pdf, model, crypto | `rust_decimal`, `md-5` (the `/CheckSum` ISO 32000-2 defines) | `-sdk` |
| `casual-sign-workflow` | Engine | model, audit, fields | `serde`, `serde_json` (both already in the tree); dev: `proptest`, `rust_decimal` | server |
| `casual-sign-sdk` | Engine facade | model, pdf, fields, flatten, crypto, seal, verify, audit, certificate | —; dev: `aws-lc-rs`, `rcgen` and the RustCrypto PKI crates (test TSA and OCSP, as `-seal`) | server, `-cli`, desktop |
| `casual-sign-cli` | Host | sdk | `serde_json`; native only: `aws-lc-rs` (file keys, TSA nonce), `der`, `x509-cert`, `pem-rfc7468`, `ureq` with `rustls` on aws-lc-rs and `rustls-native-certs` (TSA, OCSP, CRL over HTTP) | developers, `tools/pipeline-corpus.py` |
| `casual-sign-wasm` | Binding | fields, verify, model, pdf (flatten and audit join with the signing UI) | `wasm-bindgen`, `serde_json`, `rust_decimal`; dev: `sha2` (parity harness) | `webapp/`, `tools/wasm-parity.sh` |
| `casual-sign-secrets` | Host | — | `zeroize` (a `Secret` is wiped on drop; its `Debug` is redacted) | server, worker, keyd (copied from OpenCalc's `casual-calc-secrets` at `b23c67c`, PROVENANCE.md; built in stage 2E) |
| `casual-sign-store` | Host | model, audit | **Built (stage 2B):** `sqlx` 0.9 (Postgres, compile-time checked `query!` with the committed offline cache `.sqlx/`, `SQLX_OFFLINE=true`; `sqlx-prepare.sh --check` proves it current; rustls on ring with platform roots), `tokio`, `uuid`, `time`, `rust_decimal`, `serde_json`; S3: `rusty-s3` 0.11 (SigV4 presigning on aws-lc-rs, BSD-2-Clause), `ureq` over `rustls` (aws-lc-rs) and `rustls-native-certs`, `url`. Native only (excluded from the wasm32 check) | server, worker |
| `casual-sign-server` | Host | sdk, workflow, model, audit, store, secrets | **Built (stage 2C):** `axum` 0.8, `tokio`, `tower`, `tower-http` (body limits), `serde`, `serde_json`, `uuid`, `time`, `base64`, `argon2` (Argon2id, RustCrypto), `aws-lc-rs` (randomness, ES256 keys), `jsonwebtoken` 10 (ES256 only, on aws-lc-rs), `tracing`, `tracing-subscriber`, `maxminddb` (ISC; GeoIP, GEO-01), `rust_decimal`; dev: `tower`, `http-body-util`, `sqlx`, `serde_norway` (reads `api/openapi.yaml`). **Not yet:** `openidconnect` (OIDC login), `samael` (SAML); WebAuthn's `webauthn-rs` is MPL-2.0, which `deny.toml` does not allow (report of T-2C) | — |
| `casual-sign-worker` | Host | sdk, workflow, audit, model, store, keyd, secrets | **Built (stage 2D):** `tokio`; `lettre` 0.11 (SMTP only, rustls on aws-lc-rs with platform roots; without its `builder` feature, whose `quoted_printable` is 0BSD and not in `deny.toml`: messages are written by the worker with every header checked or RFC 2047-encoded); `ureq` 3 over `rustls` (aws-lc-rs) and `rustls-native-certs` for webhooks and RFC 3161/OCSP/CRL, with an SSRF-checking resolver (in place of `reqwest`, not in the tree); `aws-lc-rs` (HMAC-SHA256, randomness); `base64`, `der`, `x509-cert`, `uuid`, `time`, `serde`, `serde_json`; dev: `sqlx`, `rcgen`, the RustCrypto PKI crates, `-seal`, `-verify`, `-crypto` (the seal and keyd test harnesses, included by path). Binary `casual-sign-worker`. Native only (excluded from the wasm32 check) | Compose (`T-2F`) |
| `casual-sign-keyd` | Host | crypto, secrets | `cryptoki` 0.12 (PKCS#11; Apache-2.0, brings `cryptoki-sys`, `libloading` (ISC), `secrecy`), `aws-lc-rs` (hashing, development file key, TLS provider), `rustls` 0.23 (TLS 1.3 mTLS, aws-lc-rs provider) and `rustls-pki-types` (PEM), `der`, `spki`, `x509-cert`; dev: `rcgen`, `-seal`, `-verify`. Cloud KMS SDKs behind features, not yet built (stage 2E as built: docs/31 §5) | worker |
| `casual-sign-convert` | Host (sidecar) | — | — | worker |
| `casual-sign-mcp` | Host | sdk | (as OpenCalc's `casual-calc-mcp`) | slice 22 |

## Dependency DAG (target)

```
 wasm ─▶ fields, verify, flatten, audit
 sdk ──▶ workflow, certificate, seal, verify, flatten, fields, audit, crypto, pdf, model
 workflow ─▶ model, audit, fields
 certificate ─▶ audit, flatten, pdf
 verify ─▶ pdf, crypto, audit
 seal ───▶ pdf, crypto
 flatten ─▶ pdf, fields, model
 fields ──▶ model, pdf
 audit ───▶ model, crypto
 model, pdf, crypto: no internal dependencies
 server/* ─▶ crates/*        crates/* never ─▶ server/*
```

`tools/check-crate-deps.py` (copied from OpenPresent) fails any edge from `crates/` to `server/` or outside `crates/`.

## Provenance

Anything copied from a sister repo records, in a `PROVENANCE.md` beside it: source repository, path, commit, date, and
what was changed. Candidates, in order of need:

| From | What | When |
| --- | --- | --- |
| OpenPresent | `Cargo.toml` lints, `rust-toolchain.toml`, `deny.toml`, `.githooks`, `tools/check-repo.py` and its checkers, CI workflow skeleton, skills | Phase 0 |
| OpenCalc | `server/casual-calc-secrets` | Phase 2 |
| OpenCalc | Server conventions: JWT/JWKS identity, access checks, Dockerfiles, compose and nginx config | Phase 2 |
| OpenCalc / OpenPresent | `webapp/` skeleton: `commands.js`, `ribbon.js`, tokens, `icons.fluent.svg`, `site.js`, deploy and download pages | Slice 1 |
| OpenCalc | `sdk/` packaging and embed element | Slices 8, 9 |
| OpenCalc | `desktop/` Tauri shell | Slice 21 |
| OpenCalc | `server/casual-calc-mcp` | Slice 22 |
| OpenPresent | Fonts (Liberation, Noto) with their OFL licences | Stage 1E |

## Licence policy

`deny.toml` allows Apache-2.0, BSD-2/3-Clause, ISC, MIT, Unicode-3.0, Zlib, Unlicense, NCSA, and OFL-1.1 for font
data only. MPL, LGPL, GPL and AGPL are refused in the product graph. Tools that run as separate processes in CI only
(EU DSS, LibreOffice in the converter container, pyHanko) are not linked and are recorded in `NOTICE` where shipped.
