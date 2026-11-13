# 09 — Legal and compliance underpinning

**Status: Draft for owner. Not legal advice.** What the law and the standards ask of e-signature software, which
product mechanism answers each requirement, and what an operator must still do. `LEG-02` in
[14](14-EXECUTION-TRACKER.md) asks for review by counsel before the first release.

**The rule for every document and the product's own copy:** OpenSeal is *designed to support* these frameworks. It is
never described as "legally binding", "compliant" or "certified" by itself. Compliance belongs to a deployment: its
operator, its configuration, its certificates, its procedures and, for Part 11, the customer's validation.

## 1. United States: ESIGN Act and UETA

ESIGN, 15 U.S.C. §7001 et seq. (https://www.law.cornell.edu/uscode/text/15/7001); UETA, adopted by 49 states and DC
(New York has ESRA).

| Requirement | Source | Mechanism | Where |
| --- | --- | --- | --- |
| An electronic signature is a sound, symbol or process attached to or logically associated with a record, **executed or adopted with intent to sign** | ESIGN §7006(5) | Explicit adopt-signature step and explicit Finish; the button wording and the adoption are events | [24](24-ENVELOPE-LIFECYCLE-AND-ROUTING.md), [32](32-AUDIT-TRAIL-AND-EVIDENCE.md) `recipient.signature_adopted` |
| Consumer consent to electronic records, after disclosure of: paper copies, right to withdraw and its consequences, scope, how to update contact details, hardware and software needs; consent that *reasonably demonstrates* access | ESIGN §7001(c) | Versioned **ERSD** (electronic record and signature disclosure) per account; consent screen before the documents; consent event records the version hash; withdraw-consent action | [22](22-DATA-MODEL.md) §8, `recipient.consented`, `recipient.consent_withdrawn` |
| Re-consent when requirements change materially | ESIGN §7001(c)(1)(D) | A new ERSD version requires fresh consent | — |
| Records accurately reflect the information and remain accessible and reproducible for the required period | ESIGN §7001(d), (e); UETA §12 | Sealed PDF, immutable storage, retention policies, export; copies sent to every party | [31](31-SEALING-AND-SIGNATURES.md), [02](02-HLD.md) §9 |
| Attribution to a person, shown by any means including the **efficacy of a security procedure** | UETA §9 | Recipient authentication methods, IP and user agent, email or SMS possession, hash chain | [32](32-AUDIT-TRAIL-AND-EVIDENCE.md) |
| Effect of error: a consumer may avoid an error made with no opportunity to correct it | UETA §10 | A review step before Finish shows every value; Finish is a separate action | [47](47-UX-AND-FEATURE-MAP.md) §Sign |
| Time and place of sending and receipt | UETA §15 | Server timestamps on `invitation.sent`, `recipient.delivered`; RFC 3161 time on the seal | [32](32-AUDIT-TRAIL-AND-EVIDENCE.md) |
| Exclusions: wills, family law, most UCC, court documents, utility cut-off, foreclosure and eviction, health and life insurance cancellation, recalls, hazardous materials | ESIGN §7003 | Not enforceable by software; the operator's terms and sender guidance say so | Operator guide, [65](65-RUNNING-IT.md) |

## 2. European Union: eIDAS and eIDAS 2

Regulation (EU) 910/2014 as amended by (EU) 2024/1183.

| Level | Requirement | OpenSeal | Status |
| --- | --- | --- | --- |
| **SES** — simple electronic signature | Data attached to or associated with other data, used to sign. Admissible; cannot be denied effect solely for being electronic (Art. 25(1)) | The default ceremony | Designed in from slice 1 |
| **AES** — advanced (Art. 26) | (a) uniquely linked to the signatory; (b) capable of identifying them; (c) created with signature-creation data under their **sole control**; (d) linked so any change is detectable | (d) by the seal. (a)–(c) need a per-signer key: **remote signing through a QTSP over the CSC API**, or a signer's own certificate (smart card, eID) through a browser bridge | Slice 18 |
| **QES** — qualified | AES by a **QSCD**, on a **qualified certificate**; equivalent to handwritten (Art. 25(2)); recognized across member states | Only through a QTSP (CSC API v2 or ETSI TS 119 432). Software alone can never produce a QES | Slice 18 |
| Qualified electronic **seal** (legal person) | As QES, for organisations | The platform seal can be a qualified seal if the operator's seal certificate is qualified and held in a QSCD | Operator choice |
| Qualified **timestamp** (Art. 41–42) | From a qualified TSA | The `TimestampSource` accepts a qualified TSA | Operator choice |

Standards: ETSI EN 319 142-1 (PAdES baseline), EN 319 142-2, EN 319 102-1 (creation and validation), EN 319 122
(CAdES), TS 119 312 (cryptographic suites), TS 119 144-4 (PAdES conformance testing). Trusted Lists: the EU LOTL.

## 3. Life sciences: FDA 21 CFR Part 11

(https://www.ecfr.gov/current/title-21/chapter-I/subchapter-A/part-11)

| Section | Requirement | Mechanism |
| --- | --- | --- |
| §11.10(a) | Validation | The customer validates their deployment; we publish an IQ/OQ test pack from CI evidence (slice 19) |
| §11.10(b) | Accurate and complete copies, human-readable and electronic | Sealed PDF and audit JSON |
| §11.10(c), (d) | Protection of records; limited access | Retention, WORM option, RBAC |
| §11.10(e) | **Secure, computer-generated, time-stamped audit trails** that do not obscure prior values | Append-only hash-chained events; corrections are new events |
| §11.10(f)–(k) | Operational, authority and device checks; training; documentation controls | Workflow enforcement; permission profiles; operator procedures |
| §11.50 | Signature manifestation: printed name, date and time, and **meaning** (review, approval, responsibility, authorship) | A `signing_reason` per signature field, required in Part 11 mode, flattened next to the signature and recorded |
| §11.70 | Signature linked to its record so it cannot be excised, copied or transferred | Seal over the document including signature appearances |
| §11.100 | Unique signatures; identity verified | Account users only (no anonymous recipients) in Part 11 mode |
| §11.200 | Non-biometric signatures need two components; **re-authentication at each signing** outside a continuous session | Part 11 mode requires staff login plus password or WebAuthn re-entry at Finish |
| §11.300 | Password controls | Delegated to the IdP or local password policy |

A product cannot be "Part 11 certified". OpenSeal provides a **Part 11 mode** (slice 19) and the documentation a
customer needs for their own validation.

## 4. Other jurisdictions

Recorded for the fit-gap, not yet studied in depth (`LEG-03`): UK (Electronic Communications Act 2000, eIDAS as
retained), Switzerland (ZertES), India (IT Act 2000: Aadhaar eSign and DSC; OpenSeal's operator is in India, so this
is likely to matter early), Canada (PIPEDA Part 2), Australia (ETA 1999), Brazil (MP 2.200-2, ICP-Brasil), Singapore
(ETA 2010). Each mostly accepts SES with exceptions and has a qualified or certificate-based tier reachable through the
`RemoteSigner` seam.

## 5. Privacy and data protection

GDPR, UK GDPR, CCPA/CPRA, India's DPDP Act 2023. Signers are data subjects; the sender's account is the controller and
the operator a processor. Mechanisms: data classification and minimization ([07](07-SECURITY-THREAT-MODEL.md) §Data),
retention and purge with an audit event, export of a subject's data, data region tagging, a sub-processor list for the
hosted service, and a DPA template (operator).

**Signer location (GEO-01), as a fact of the design, not a legal claim.** A location is recorded only when the
account turns on `capture_location` for the envelope. The signer's device location is taken only after the signer is
asked and agrees (the browser's own permission prompt); a refusal does not stop signing, and the event records the
refusal. Otherwise the location is an approximation from the IP address, by a GeoIP database named with its build
date: it is approximate, can be wrong by a city or a country (VPNs, mobile carriers, proxies), and the certificate
says "approximate from IP". Whether recording location is appropriate, and what notice the signer needs, is for the
controller to decide under the law that applies to them; the product records only what the account's setting asks.

Note the tension: **evidence must persist, and data subjects may ask for erasure.** Signed agreements are generally
retained under a legal obligation or legitimate interest; the product lets the controller decide per account, and
never deletes evidence silently.

One record is kept by design and cannot be erased: the **admin audit logs** (`ORG-05`, docs/23 §2.5) hold the acting
administrator's user or API client id and IP address inside each event's hash-chained bytes, in an append-only log, so
that who changed a workspace's settings, members or permissions stays provable. That IP address is personal data
(docs/07 §Data classification); erasing it would break the chain, so it is retained for the life of the log, and an
operator's privacy notice should say so. Whether this meets a given law is the controller's assessment; the product
claims no compliance for it.

## 6. Security attestations

SOC 2 Type II, ISO/IEC 27001, ISO/IEC 27017/27018, HIPAA, FedRAMP and PCI DSS (for payments) attach to an operator,
not to source code. The project helps operators by mapping controls to mechanisms (`LEG-04`, slice 20) and by never
storing card data (payments go through the gateway's hosted fields).

## 7. Trust in PDF readers

A seal shows "valid" in Adobe Acrobat only if its certificate chains to the **Adobe Approved Trust List (AATL)** or the
**EU Trusted List**. AATL certificates require keys in hardware (FIPS 140-2 Level 2 or higher, a QSCD, or Common
Criteria), audited CAs (WebTrust or ETSI EN 319 411), and a CP/CPS (https://support.globalsign.com/aatl-document/aatl-document-signing-faqs) [V].
A self-hosted deployment with a self-signed key will show "validity unknown". [65](65-RUNNING-IT.md) documents how an
operator obtains an AATL document-signing certificate and holds it in an HSM or cloud KMS through `keyd`.

## 8. Model weights register (ADR-029)

Pretrained model weights shipped or exported for the assistive features of [33](33-ML-MODELS.md) (OCR, template
matching, extraction, personal-data detection). Each is checked at image build against the licence in
`tools/ml/models.toml`, which must be on `deny.toml`'s allow list; GLiNER v0 and v1 checkpoints (CC-BY-NC-4.0) are
refused by repository id. **Version** is the checkpoint; the exact revision commit and SHA-256 are recorded in the
manifest when it is written (`ML-09`, piece B). Licences were read from each model card on 2026-11-12 and re-checked
by the adversarial review; nothing here is legal advice, and `LEG-02`'s counsel review covers this table.

| Model | Version | Use | Weight licence | Source | Training data (as stated by its publisher) | Status |
| --- | --- | --- | --- | --- | --- | --- |
| PaddlePaddle PP-OCRv6_small_det | PP-OCRv6 (PaddleOCR 3.7.0, 2026-06-11), official ONNX | OCR text detection | Apache-2.0 | https://huggingface.co/PaddlePaddle/PP-OCRv6_small_det_onnx | PaddleOCR's own datasets; not itemised | Default |
| PaddlePaddle PP-OCRv6_small_rec | PP-OCRv6, official ONNX | OCR recognition, 50 languages per the card | Apache-2.0 | https://huggingface.co/PaddlePaddle/PP-OCRv6_small_rec_onnx | As above | Default |
| PaddlePaddle arabic_PP-OCRv5_mobile_rec | PP-OCRv5; Paddle format, exported to ONNX by us | OCR, Arabic script pack | Apache-2.0 | https://huggingface.co/PaddlePaddle/arabic_PP-OCRv5_mobile_rec | As above | Operator-chosen pack |
| PaddlePaddle devanagari_PP-OCRv5_mobile_rec | PP-OCRv5; exported by us | OCR, Devanagari script pack | Apache-2.0 | https://huggingface.co/PaddlePaddle/devanagari_PP-OCRv5_mobile_rec | As above | Operator-chosen pack |
| PaddlePaddle PP-LCNet_x1_0_textline_ori | PaddleOCR 3.x; exported by us | Text-line orientation | Apache-2.0 | https://huggingface.co/PaddlePaddle/PP-LCNet_x1_0_textline_ori | As above | Default |
| intfloat/multilingual-e5-small | repository of 2026-04-02 (revision `614241f6`), fp32 `onnx/model.onnx`; an fp16 copy converted by us (`tools/ml/export-e5.py`) equals the fp32 PyTorch reference within 1e-3 cosine and is preferred once hosted (`ML-15`) | Template matching and agreement search embeddings | MIT | https://huggingface.co/intfloat/multilingual-e5-small | Includes MS MARCO (licensed for non-commercial research) among its fine-tuning sets | Default |
| sentence-transformers/all-MiniLM-L6-v2 | repository of 2026-06-01 | Template matching, English "small" profile | Apache-2.0 | https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2 | Includes MS MARCO among its training sets | Optional profile |
| urchade/gliner_multi-v2.1 | v2.1, `model.safetensors`, fp16 exported by us | Agreement extraction (parties, dates, amounts, durations, addresses) | Apache-2.0 | https://huggingface.co/urchade/gliner_multi-v2.1 | LLM-annotated Pile-derived data (`urchade/pile-mistral-v0.1`, card Apache-2.0); encoder microsoft/mdeberta-v3-base (MIT) | Default |
| urchade/gliner_small-v2.1 | v2.1, `pytorch_model.bin` (hash-pinned, loaded with `weights_only=True`), exported by us | Agreement extraction, English profile | Apache-2.0 | https://huggingface.co/urchade/gliner_small-v2.1 | As gliner_multi-v2.1 | Optional profile |
| knowledgator/gliner-pii-base-v1.0 | v1.0, `pytorch_model.bin` (hash-pinned, loaded with `weights_only=True`), fp16 exported by us (332,987,248 B) | Personal-data layer 2 (names, addresses, organizations), English only | Apache-2.0 | https://huggingface.co/knowledgator/gliner-pii-base-v1.0 | **Undisclosed** (the card names only an evaluation set); encoder microsoft/deberta-v3-small (MIT) | Optional, off by default |
| urchade/gliner_multi_pii-v1 | v1, `pytorch_model.bin` only; usable only as our int8 export under the file cap | Personal-data layer 2, non-Latin names | Apache-2.0 | https://huggingface.co/urchade/gliner_multi_pii-v1 | Fine-tune of gliner_multi-v2.1; data not itemised | Fallback, not yet exported |

Runtime binary in the same manifest: **ONNX Runtime 1.28.3**, MIT, https://github.com/microsoft/onnxruntime/blob/v1.28.3/LICENSE,
bundling Eigen (MPL-2.0) and Boost (BSL-1.0) among the third-party code its `ThirdPartyNotices.txt` lists. **Scoped
exception (owner instruction 32):** MPL-2.0 and BSL-1.0 are allowed for that unmodified binary in the modeld image
only, nowhere else. The manifest records it per entry (`licence_exception = "owner-instruction-32"` on the two library
entries), and `tools/ml/fetch-models.py` honours it for those entry ids alone, refusing it on any other entry and
refusing a bundle that lacks the `ThirdPartyNotices.txt` from the same archive (both cases in its `--self-test`). The
image ships `ThirdPartyNotices.txt`, the ONNX Runtime licence and `deploy/modeld/NOTICE.txt` in
`/usr/share/doc/openseal-modeld/`; the notice points to the source of the Eigen revision ONNX Runtime 1.28.3 builds
(commit `1d8b82b0740839c0de7f1242a3585e3390ff5f33`, per its `cmake/deps.txt`).

Refused (licence not on the allow list): GLiNER v0 and v1 (`gliner_base`, `gliner_multi`; CC-BY-NC-4.0),
`iiiorg/piiranha-v1` (CC-BY-NC-ND-4.0), `nvidia/gliner-PII` (NVIDIA Open Model License), spaCy fr and es pipelines
(LGPL-LR, GPL-3.0), `Davlan/xlm-roberta-base-ner-hrl` (AFL-3.0), `Babelscape/wikineural` (CC BY-NC-SA), Flair classic
models (non-commercial).

**Training-data lineage is not claimed.** The project relies on each weight licence as published. A permissive weight
licence does not establish that every dataset used to train the weights permitted commercial use: MS MARCO is
licensed for non-commercial research, and the GLiNER-PII model's training data is undisclosed. **Owner decision D13 is
open** (proposed `DEC-16`): accept reliance on the weight licence for these models, or exclude them (template
matching would then use page hashes only, and personal data the deterministic recognisers only). Until the owner
decides, the models stay off by default and no product text says they are cleared for commercial use.

**Personal-data detection is assistive.** It proposes spans for redaction and retention that a person accepts; it
does not find every item of personal data, and it is *designed to support* a controller's data-minimization work,
never described as making a deployment compliant with GDPR or any other law.

## 9. Third-party licence review packet (`LEG-01`)

For counsel. This section states what was checked, how, and what is open; it is a self-assessment prepared for review,
**not legal advice and not a clearance**. `LEG-01` stays In progress until counsel signs it off.

**What OpenSeal distributes.** Apache-2.0 source (LICENSE, NOTICE). Container images: server (with the web app and the
WebAssembly engine it serves to browsers), worker, keyd, console (with the embedded console UI) and modeld (with ONNX
Runtime and model weights). The website. Running OpenSeal as a hosted service is not distribution under Apache-2.0
(ATTRIBUTION.md), but the browser code (web app, console UI, WASM engine, fonts, pdf.js) is delivered to users' browsers
and is treated here as distributed.

**Inventory.** `python3 tools/licence-inventory.py` writes [THIRD-PARTY.md](../THIRD-PARTY.md) from the tree:

- **Rust crates** from Cargo.lock through `cargo metadata --locked`: 549 third-party crates on 2026-11-13, of which
  506 are reached through normal dependencies (`shipped`), 15 only through build-dependencies and 27 only through
  dev-dependencies. Cargo.lock covers every target platform, so `shipped` over-counts for any single binary. For each
  crate it records the declared SPDX expression and the copyright lines found in its licence files.
  [THIRD-PARTY-LICENSES.txt](../THIRD-PARTY-LICENSES.txt) reproduces every licence, notice and patent-licence file
  those crates ship, verbatim, one copy per distinct text (348 texts), including those in subfolders for bundled C
  libraries and data (Oniguruma in `onig_sys`, AWS-LC and fiat-crypto, Adobe CMaps and Foxit fonts in `hayro`, the
  Unicode tables in `regex-syntax`); the standard Apache-2.0 text is LICENSE.
- **Vendored and embedded files** (15 components): pdf.js 4.10.38 with its CMaps (Adobe, BSD-3-Clause) and standard
  fonts (Foxit, Liberation Sans), Lucide icons, Geist and Geist Mono (web app, console UI, website), Liberation, Great
  Vibes and Allura fonts embedded in flattened PDFs, the Adobe AFM and Glyph List data tables, the Presidio-derived
  recogniser patterns, the Lexend outlines in the logo, and the ONNX Runtime binary in the modeld image.
- **Model weights and tokenizers** in bundled profiles of `tools/ml/models.toml` (10 repositories; Apache-2.0 or MIT;
  §8 holds the training-data notes). Export-only inputs are not bundled and not listed.

**Licence policy applied.** `deny.toml` allows Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC, MIT, NCSA, Unicode-3.0,
Unlicense and Zlib for crates; every expression in the inventory resolves to these (where a crate offers a choice,
OpenSeal relies on an allowed option: `ryu` and `whoami` offer BSL-1.0 beside Apache-2.0, `r-efi` offers
LGPL-2.1-or-later beside MIT and Apache-2.0, `imgref` CC0-1.0 beside Apache-2.0). Expressions joined by AND require
every listed licence and are reproduced in full: `ring` (Apache-2.0 AND ISC), `aws-lc-sys` and `aws-lc-rs` (ISC,
Apache-2.0, MIT, BSD-3-Clause, with code derived from OpenSSL and BoringSSL), `brotli` and `matchit` (MIT AND
BSD-3-Clause), the Unicode crates (Unicode-3.0). ONNX Runtime's bundled Eigen (MPL-2.0) and Boost (BSL-1.0) are the
one scoped exception, owner instruction 32 (§8).

**NOTICE check.** `python3 tools/licence-inventory.py --check` fails unless NOTICE points to the inventory and the
licence texts, names every vendored component and every bundled model repository, reproduces the NOTICE of any
shipped crate that has one (Apache-2.0 §4(d); on 2026-11-13 none does: the only crate with a notices file,
`cfg_aliases`, is build-only), names every shipped crate with a PATENTS file (`rav1e`, whose Alliance for Open Media
Patent License 1.0 must be reproduced with binaries), and no licence or font file sits in a shipped folder without a component that accounts
for it. Before `LEG-01` NOTICE omitted the Geist fonts (three copies), the pdf.js CMaps (Adobe BSD-3-Clause), ONNX
Runtime and all model weights, and said nothing of the Rust crates; it now covers them. The check is a tool for this
review, not a CI gate (no new gates without the owner).

**Questions for counsel.**

1. Is NOTICE plus THIRD-PARTY.md and THIRD-PARTY-LICENSES.txt a sufficient attribution for the MIT, BSD, ISC, Zlib and
   Unicode-3.0 crates compiled into binaries and into the WebAssembly the browser loads, given that the texts are
   reproduced per crate rather than in each binary?
2. The images do not yet ship LICENSE, NOTICE or the inventory files (`LEG-05`), and the web app and console offer no
   third-party notices page; what placement satisfies Apache-2.0 §4 and the MIT and BSD notice conditions for the
   images and for code delivered to browsers?
3. Thirteen crates publish no licence file in their package (`LEG-07`); is the declared SPDX identifier with the
   upstream repository's licence file an acceptable source of the notice?
4. Model weights: the image ships each weight's licence identifier in `bundle.json` but not the licence texts or
   copyright holders (`LEG-06`). What must accompany Apache-2.0 and MIT weights, including the ones OpenSeal converts
   (ONNX export, fp16)? Does a converted weight file count as a modified work needing a change notice?
5. The scoped MPL-2.0 (Eigen) and BSL-1.0 (Boost) exception for the unmodified ONNX Runtime binary (§8,
   `deploy/modeld/NOTICE.txt`): is the source pointer adequate for MPL-2.0 §3.2?
6. Data and fonts: the Adobe AFM notice ("retain all copyright notices") as met by NOTICE; the OFL-1.1 fonts, embedded
   as subsets in signed PDFs that users distribute; the Presidio patterns ported without code, with the MIT text
   included.
7. `rav1e` 0.8.1 (an AV1 encoder that `image`'s default features compile into casual-sign-modeld, though modeld
   encodes no image) is BSD-2-Clause and also under the Alliance for Open Media Patent License 1.0, which requires
   the licence to accompany binaries and ends the patent grant for a licensee that brings a patent claim over an
   AV1 implementation. NOTICE names it and THIRD-PARTY-LICENSES.txt holds the text; is that adequate, and should
   the encoder be dropped from the build instead (`LEG-08`)?
8. Training-data lineage stays an owner and counsel question under `LEG-02` and §8; this packet covers licences only.

**Not covered here:** trademark (DEC-07), legal claims and the default ERSD (`LEG-02`), the corpus fixtures, which are
fetched by URL and never distributed (NOTICE lists their attribution), and CI-only tools (EU DSS, pyHanko, Playwright,
axe-core), which are never shipped.
