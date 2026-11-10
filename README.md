# OpenSeal

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
  checked by our verifier and by independent validators before release (the verifier and validators exist today).
- **Verify without us.** A completed PDF will be verifiable in the browser, offline, or from the command line, with no
  account and no server.
- **Keys where you want them.** Signing keys will live in your HSM or cloud KMS, behind a separate signing service that
  never sees documents.
- **An API you already know.** Envelopes, recipients, routing orders, fields, templates, embedded views and signed
  webhooks, in the shapes DocuSign and SignNow integrators expect.

## Status

Docs are true as of `b7dce7b` (2026-11-10).

**Pre-alpha, engine under construction; the repository is private until the pre-release alpha.** No server or user
interface exists yet. What is built is the headless engine's first half, in Rust, tested against 422 real-world PDFs:

| Built and merged | What it does |
| --- | --- |
| PDF reader (`casual-sign-pdf`) | Opens any PDF within strict limits, repairs damaged files, reports active content; 387 of 422 real PDFs open with correct page counts, 31 encrypted ones wait on decryption, 4 wrong refusals are being fixed |
| Writer and normalizer | Appends signed revisions without touching earlier bytes; rewrites uploads clean of JavaScript, actions, embedded files, XFA |
| Fields (`casual-sign-model`, `casual-sign-fields`) | Every DocuSign/SignNow field type, validation, conditions, groups, formulas; page geometry, text extraction, anchors, `{{…}}` text tags, conversion of existing PDF forms |
| Crypto (`casual-sign-crypto`) | CMS signatures, RFC 3161 timestamps, OCSP and CRL, the key-provider seam; cross-checked with independent libraries |
| Test assets | 40 hostile PDFs, a 422-file real-world corpus, pyHanko and EU DSS validators |

In progress: the verifier, flattening and fill-in-place, decryption and the remaining reader gaps. Then sealing, the
audit chain, the server and the web app. Exact state: [docs/14](docs/14-EXECUTION-TRACKER.md); phases and milestones:
[docs/06](docs/06-ROADMAP-AND-DELIVERY.md).

The design, research and plan:

| | Where |
| --- | --- |
| Product requirements | [docs/01-PRD.md](docs/01-PRD.md) |
| High-level design | [docs/02-HLD.md](docs/02-HLD.md) |
| Technical design: data model, lifecycle, PDF pipeline, sealing, audit, API | [docs/22](docs/22-DATA-MODEL.md), [24](docs/24-ENVELOPE-LIFECYCLE-AND-ROUTING.md), [30](docs/30-PDF-PIPELINE.md), [31](docs/31-SEALING-AND-SIGNATURES.md), [32](docs/32-AUDIT-TRAIL-AND-EVIDENCE.md), [40](docs/40-API-DESIGN.md) |
| Research: DocuSign, SignNow, open-source competitors, law and standards | [docs/48](docs/48-DOCUSIGN-STUDY.md), [49](docs/49-SIGNNOW-STUDY.md), [52](docs/52-COMPETITOR-STUDY.md), [09](docs/09-LEGAL-AND-COMPLIANCE.md) |
| Security | [docs/07](docs/07-SECURITY-THREAT-MODEL.md) |
| Roadmap and tracker | [docs/06](docs/06-ROADMAP-AND-DELIVERY.md), [docs/14](docs/14-EXECUTION-TRACKER.md) |
| Feature parity with DocuSign and SignNow | [docs/96](docs/96-FEATURE-FIT-GAP.md): 167 features tracked; none works end to end yet, 17 have their engine built |

The plan: **Phase 0** sets up the repository, CI, a PDF corpus and independent validators; **Phase 1** builds the
headless PDF and evidence engine (admit, fill, flatten, seal, verify, audit); **Phase 2** builds the envelope engine,
server and API; then **35 vertical slices** deliver user-visible features, starting with send-and-sign. Slices are
grouped into milestones: M0 ready to build, M1 engine alpha, M2 service alpha, M3 first signature, M4 team beta,
**M5 1.0 GA**, then M6 regulated industries, M7 ecosystem and M8 agreement platform ([roadmap](docs/06-ROADMAP-AND-DELIVERY.md#milestones)).

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

## Licence

[Apache-2.0](LICENSE). See [NOTICE](NOTICE). What was copied from the sister repositories is in [PROVENANCE.md](PROVENANCE.md).
