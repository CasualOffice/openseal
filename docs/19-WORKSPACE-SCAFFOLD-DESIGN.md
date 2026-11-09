# 19 — Workspace and layer division

**Status: Draft for owner. As built (2026-11-10):** members `casual-sign-model` and `casual-sign-fields` (stage 1D, merged), `casual-sign-crypto` (stage 1F, merged), `casual-sign-pdf` (skeleton; stage 1A in progress). Edges: `-fields` → `-model`. `fuzz/` arrives with stage 1A.

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
| `casual-sign-pdf` | Engine | — | `zlib-rs` or `miniz_oxide` (decided with ADR-005) | `-fields`, `-flatten`, `-seal`, `-verify` |
| `casual-sign-fields` | Engine | model (pdf joins with stage 1C) | `rust_decimal`, `regex` (linear-time matching), `unicode-normalization` | `-flatten`, `-wasm` |
| `casual-sign-flatten` | Engine | pdf, fields, model | `subsetter`, `skrifa` (font subset and metrics), `png`, `zune-jpeg` | `-certificate`, `-sdk` |
| `casual-sign-crypto` | Engine | — | `der`, `spki`, `x509-cert`, `cms =0.3.0-rc.2`, `x509-tsp =0.2.0-rc.0`, `x509-ocsp =0.3.0-rc.1`, `sha2`, `p256`, `p384`, `rsa` (verify only, feature `rsa`); dev: `aws-lc-rs` (test `KeyProvider`), `rcgen` | `-seal`, `-verify`, `-audit` |
| `casual-sign-seal` | Engine | pdf, crypto | — | `-sdk` |
| `casual-sign-verify` | Engine | pdf, crypto, audit | — | `-sdk`, `-wasm` |
| `casual-sign-audit` | Engine | model, crypto | `serde_json`, `serde_json_canonicalizer` (JCS) | `-workflow`, `-certificate` |
| `casual-sign-certificate` | Engine | audit, flatten, pdf | — | `-sdk` |
| `casual-sign-workflow` | Engine | model, audit, fields | — | server |
| `casual-sign-sdk` | Engine facade | all of the above | — | server, CLI, desktop |
| `casual-sign-wasm` | Binding | fields, verify, flatten, audit | `wasm-bindgen` | `webapp/` |
| `casual-sign-secrets` | Host | — | — | server, worker, keyd (copied from OpenCalc's `casual-calc-secrets`) |
| `casual-sign-server` | Host | sdk, workflow, secrets | `axum`, `tokio`, `sqlx`, `tower-http`, `jsonwebtoken`, `openidconnect`, `samael` (SAML, reviewed in `DEP-01`), `aws-lc-rs` | — |
| `casual-sign-worker` | Host | sdk, workflow, secrets | `tokio`, `sqlx`, `lettre`, `reqwest` (rustls) | — |
| `casual-sign-keyd` | Host | crypto, secrets | `cryptoki` (PKCS#11), `aws-lc-rs`, cloud KMS SDKs behind features | worker |
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
