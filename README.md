<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/logo-dark.svg">
    <img src="docs/assets/logo.svg" alt="OpenSeal" width="420">
  </picture>
</p>

# OpenSeal

[![CI](https://github.com/CasualOffice/openseal/actions/workflows/ci.yml/badge.svg)](https://github.com/CasualOffice/openseal/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Status: pre-alpha](https://img.shields.io/badge/status-pre--alpha-orange.svg)](#status)

**Electronic signatures you can run anywhere, embed in anything, and verify without us.**
An Apache-2.0 agreement platform with DocuSign's workflow and SignNow's speed: send documents for signature, route them
through signers in order, collect every kind of field, and get back a sealed PDF whose evidence anyone can check
offline. A deterministic Rust engine does the PDF work, the sealing and the evidence; a server of record runs the
workflow; a plain web app and an API sit on top.

Part of [CasualOffice](https://github.com/CasualOffice), with
[OpenCalc](https://github.com/CasualOffice/opencalc) (spreadsheets),
[OpenPresent](https://github.com/CasualOffice/openpresent) (presentations) and OpenDoc (documents), whose architecture
it shares.

---

## Why another e-signature product?

- **Apache-2.0, not AGPL.** Every serious open-source e-signature project is AGPL, which most companies cannot embed in
  their products. This one can be embedded anywhere.
- **Nothing behind a paywall.** Bulk send, signing links, conditional fields, formulas, payments, SSO, retention,
  embedding and webhooks are all in the open core.
- **Evidence first.** Every completed agreement will carry a PAdES seal with trusted time (long-term validation
  optional), a certificate of completion, and a hash-chained audit trail embedded in the PDF. Every seal will be
  checked by our verifier and by independent validators before release (sealing, the verifier and both validators
  exist today).
- **Verify without us.** A completed PDF will be verifiable in the browser, offline, or from the command line, with no
  account and no server.
- **Keys where you want them.** Signing keys will live in your HSM or cloud KMS, behind a separate signing service that
  never sees documents.
- **An API you already know.** Envelopes, recipients, routing orders, fields, templates, embedded views and signed
  webhooks, in the shapes DocuSign and SignNow integrators expect.

## Run it

You need Docker with Compose. One command builds and starts the whole stack (server and web app, job worker, signing
key service, Postgres, object storage, a mail catcher and a development timestamp authority):

```sh
git clone https://github.com/CasualOffice/openseal && cd openseal
docker compose up -d --build --wait
docker compose exec -e OPENSEAL_ADMIN_PASSWORD='a long passphrase' server \
    casual-sign-server bootstrap "Acme" admin@acme.example "Ada Admin"
```

- Web app: <http://localhost:8080>. Sign in as `admin@acme.example`, then send a PDF for signature.
- Every email the stack sends (signing links, completions) appears in Mailpit: <http://localhost:8025>.
- Stop and discard everything: `docker compose down -v`.

This is a **development** deployment: a generated certificate authority, a software HSM for the sealing key and a
local timestamp authority, so seals validate only against that CA. Configuration, services and production notes are
in [docs/65](docs/65-RUNNING-IT.md). To look at the web app without any server, run `python3 -I tools/serve-webapp.py`
and open <http://127.0.0.1:8130/app.html?mock=1> (demo mode; sign in as `demo@openseal.test` / `openseal-demo-1`).

## Status

Docs are true as of 2026-11-11. **Pre-alpha.** The headless engine is complete and tested against 422 real-world PDFs.
The workflow engine, persistence, key service, API server and job worker are built and merged; the web app is being
built. **Phases D, 0 and 1 are closed** (owner, 2026-11-11; Phase 1 after a clean 24 h
fuzz run). **Phase 2** is open early under waiver `W-1`.
**Release 1** (the common send-and-sign case, [docs/06](docs/06-ROADMAP-AND-DELIVERY.md)) comes next.

| Phase | Exit gate | State |
| --- | --- | --- |
| D — Design | **Closed** (6 of 6) | All design docs and research; doc audit fixed; ADR-001 to 024 Accepted; owner decisions `DEC-01` to `14` answered. Signed off 2026-11-11 |
| 0 — Foundation | **Closed** (4 of 4) | CI green on GitHub (Linux, macOS, Windows), every CI job seen failing on a seeded violation (PR #1), 422-PDF corpus, 50 hostile fixtures, pyHanko and EU DSS validators, spikes. Signed off 2026-11-11 |
| 1 — PDF and evidence core | **Closed** (7 of 7) | Every admitted corpus PDF (417 of 417) filled, flattened, sealed and verified by ours, pyHanko and EU DSS; tamper and signature-wrapping fixtures detected by all three; WASM byte-identical to native; 24 h of fuzzing per target with no finding. Signed off 2026-11-11 |
| 2 — Envelope engine and server | 6 of 6 stages built; exit item 1 met locally | Workflow engine, persistence, API server, job worker, keyd, and the Docker Compose deployment. A browser test sends a two-signer envelope on the stack, both sign through emailed links, and the sealed PDF passes pyHanko. Left: the same green on GitHub (`compose-e2e`), crash tests on the stack, threat tests, sign-off |
| Release 1 and slices 1–35 | — | Release 1 scope set (owner, 2026-11-11): slice 1 send and sign with routing, templates, API and webhooks; the rest follows slice by slice |

**What the engine does today** (Rust, `crates/`, each part tested against hostile files and real documents):

| Part | Crate | What it does | Evidence |
| --- | --- | --- | --- |
| Reader | `casual-sign-pdf` | Opens any PDF within strict limits, repairs damage, decrypts password-protected files, reports active content | 417 of 422 real PDFs open, every page count right; 50 hostile files each behave as their manifest says; fuzzed |
| Writer and cleaner | `casual-sign-pdf` | Appends without touching earlier bytes; rewrites uploads clean of JavaScript, actions, embedded files, XFA | The original is a prefix of every output across the corpus; pyHanko reads every output |
| Fields | `casual-sign-model`, `casual-sign-fields` | Every DocuSign/SignNow field type, validation, conditions, groups, formulas; geometry, text extraction, anchors, `{{…}}` text tags, PDF form conversion | Identical results natively and in WebAssembly over 225 cases; text agrees with pypdf |
| Flattening | `casual-sign-flatten` | Draws values, drawn/uploaded/typed signatures, stamps and checkmarks with embedded subset fonts; or fills the PDF's own form and keeps it fillable | PDFium renders ink only inside each field on every page geometry; 20 real government forms |
| Crypto | `casual-sign-crypto` | CMS signatures, RFC 3161 timestamps, OCSP, CRL, the key-provider seam | Cross-verified both ways with `cryptography` and pyHanko |
| Sealing | `casual-sign-seal` | PAdES B-B, B-T, B-LT, B-LTA as incremental updates, upgrade and archive renewal; every seal self-verified | Ours, pyHanko and EU DSS agree on 19 fixtures and 30 real PDFs sealed at B-LT |
| Verifier | `casual-sign-verify` | Verifies any signed PDF; a whitelist of allowed later changes catches shadow and incremental-saving attacks | 29 signed and tampered fixtures; pyHanko agrees on every one |
| Audit and certificate | `casual-sign-audit`, `casual-sign-certificate` | Hash-chained audit events (RFC 8785 canonical JSON), Merkle anchoring, certificate of completion with the audit trail embedded | Every one of 1,024 random tamperings detected; JSON byte-identical to Node; certificates checked with pypdf and PDFium |

**Try it** (Rust 1.96, Python 3.12 with `uv`, Docker for EU DSS):

```sh
git config core.hooksPath .githooks          # once per clone
cargo test --workspace                       # every crate's tests
python3 -I fixtures/tools/generate.py        # the hostile PDF set
python3 -I fixtures/corpus/fetch.py          # the 422-file real-world corpus (~700 MB)
cargo run --release -p casual-sign-pdf --example admit_dir -- fixtures/corpus/files
tools/ci-local.sh                            # everything CI runs, locally
```

A command-line tool (`openseal admit | fill | seal | verify`) arrives with `T-1J`. Exact state per item:
[docs/14](docs/14-EXECUTION-TRACKER.md); phases and milestones: [docs/06](docs/06-ROADMAP-AND-DELIVERY.md).

The design, research and plan:

| | Where |
| --- | --- |
| Product requirements | [docs/01-PRD.md](docs/01-PRD.md) |
| High-level design | [docs/02-HLD.md](docs/02-HLD.md) |
| Technical design: data model, lifecycle, PDF pipeline, sealing, audit, API | [docs/22](docs/22-DATA-MODEL.md), [24](docs/24-ENVELOPE-LIFECYCLE-AND-ROUTING.md), [30](docs/30-PDF-PIPELINE.md), [31](docs/31-SEALING-AND-SIGNATURES.md), [32](docs/32-AUDIT-TRAIL-AND-EVIDENCE.md), [40](docs/40-API-DESIGN.md) |
| Research: DocuSign, SignNow, open-source competitors, law and standards | [docs/48](docs/48-DOCUSIGN-STUDY.md), [49](docs/49-SIGNNOW-STUDY.md), [52](docs/52-COMPETITOR-STUDY.md), [09](docs/09-LEGAL-AND-COMPLIANCE.md) |
| Security | [docs/07](docs/07-SECURITY-THREAT-MODEL.md) |
| Roadmap and tracker | [docs/06](docs/06-ROADMAP-AND-DELIVERY.md), [docs/14](docs/14-EXECUTION-TRACKER.md) |
| Feature parity with DocuSign and SignNow | [docs/96](docs/96-FEATURE-FIT-GAP.md): 167 features tracked; none works end to end yet (no server or UI), 32 have their engine built |

The plan: **Phase 1** finishes the headless engine; **Phase 2** builds the envelope engine, server and API; then
**35 vertical slices** deliver user-visible features, starting with send-and-sign. Milestones: M0 ready to build, M1
engine alpha, M2 service alpha, M3 first signature (private preview), M4 team beta, **M5 1.0 GA**, M6 regulated
industries, M7 ecosystem, M8 agreement platform ([roadmap](docs/06-ROADMAP-AND-DELIVERY.md#milestones)).

## How it will fit together

```
 web app · SDKs · embedded views · desktop · MCP
              │  REST /api/v1 · webhooks
 casual-sign-server ── casual-sign-worker ── casual-sign-keyd ── HSM / KMS
              │                 │
        PostgreSQL        object store             (email, SMS, TSA, IdP, IDV, payments: pluggable)
              │
 engine (Rust, also WebAssembly): pdf · fields · flatten · crypto · seal · verify · audit · workflow
```

Details: [docs/02-HLD.md](docs/02-HLD.md).

## Legal note

OpenSeal is software designed to support electronic-signature laws such as ESIGN, UETA and eIDAS. Whether a given
signature is valid depends on the deployment, its configuration, the jurisdiction and the transaction; nothing in this
repository is legal advice ([docs/09](docs/09-LEGAL-AND-COMPLIANCE.md)).

## Contributing

Read [AGENTS.md](AGENTS.md) and [CLAUDE.md](CLAUDE.md), then [CONTRIBUTING.md](CONTRIBUTING.md). Enable the hooks once per clone: `git config core.hooksPath .githooks`. Code from AGPL
projects (Documenso, DocuSeal, OpenSign Labs, LibreSign) must never be copied or adapted here.

## Licensing, Commercial Use & Attribution

OpenSeal is [Apache-2.0](LICENSE). You may use it in commercial and proprietary products, embed and integrate it,
self-host it, fork it and sell what you build, with no royalties and no separate commercial license. The Apache 2.0
conditions still apply when you redistribute it: keep the [LICENSE](LICENSE) and the notices in [NOTICE](NOTICE).

"Powered by OpenSeal" is appreciated but never required. See [ATTRIBUTION.md](ATTRIBUTION.md) for what the license
requires versus what we ask, and [BRANDING.md](BRANDING.md) for wording, logos and snippets. What was copied from the
sister repositories is in [PROVENANCE.md](PROVENANCE.md).
