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
