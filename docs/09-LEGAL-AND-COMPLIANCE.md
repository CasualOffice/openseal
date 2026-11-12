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
| intfloat/multilingual-e5-small | repository of 2026-04-02, fp32 `onnx/model.onnx` | Template matching and agreement search embeddings | MIT | https://huggingface.co/intfloat/multilingual-e5-small | Includes MS MARCO (licensed for non-commercial research) among its fine-tuning sets | Default |
| sentence-transformers/all-MiniLM-L6-v2 | repository of 2026-06-01 | Template matching, English "small" profile | Apache-2.0 | https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2 | Includes MS MARCO among its training sets | Optional profile |
| urchade/gliner_multi-v2.1 | v2.1, `model.safetensors`, int8 exported by us | Agreement extraction (parties, dates, amounts, durations, addresses) | Apache-2.0 | https://huggingface.co/urchade/gliner_multi-v2.1 | LLM-annotated Pile-derived data (`urchade/pile-mistral-v0.1`, card Apache-2.0); encoder microsoft/mdeberta-v3-base (MIT) | Default |
| urchade/gliner_small-v2.1 | v2.1, `pytorch_model.bin` (hash-pinned, loaded with `weights_only=True`), exported by us | Agreement extraction, English profile | Apache-2.0 | https://huggingface.co/urchade/gliner_small-v2.1 | As gliner_multi-v2.1 | Optional profile |
| knowledgator/gliner-pii-base-v1.0 | v1.0, official `model_quint8.onnx` (196,757,174 B) | Personal-data layer 2 (names, addresses, organizations), English only | Apache-2.0 | https://huggingface.co/knowledgator/gliner-pii-base-v1.0 | **Undisclosed** (the card names only an evaluation set); encoder microsoft/deberta-v3-small (MIT) | Optional, off by default |
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
