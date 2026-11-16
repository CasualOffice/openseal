# 69 — Legal review brief for counsel

Status: **Ready to send to counsel** (`DOC-011`, owner instruction 51). Choosing counsel and agreeing the fee are the
owner's. This brief is what counsel reads first. It is written by the project, is not legal advice, and makes no claim
that OpenSeal or any signature made with it is valid, compliant or certified. Counsel's answers close `LEG-02` (claims
and the default disclosure) and sign off `LEG-01` (licences) in [14](14-EXECUTION-TRACKER.md).

## What OpenSeal is

- **An Apache-2.0 electronic-signature engine you embed, with a reference app on top.** The engine is Rust and also
  runs in the browser as WebAssembly. It reads, fills, flattens, seals and verifies PDFs and keeps a hash-chained audit
  trail. The server, job worker, key service and web app run the agreement workflow: send, route, sign, seal, verify
  ([README](../README.md), positioning `POS-01`, [06](06-ROADMAP-AND-DELIVERY.md) §Freeze).
- **Self-hosted first.** Operators run it on their own machines with Docker Compose ([65](65-RUNNING-IT.md)). The
  project runs no hosted service today.
- **Pre-release.** v0.0.1 was published on 2026-11-12 as a pre-release, "not yet for production agreements"
  ([README](../README.md) §Status). Milestone M3 (first signature, private preview) is not closed.
- **Operator and maintainer** are in India ([09](09-LEGAL-AND-COMPLIANCE.md) §4).

## What the project claims and does not claim

The project's rule ([09](09-LEGAL-AND-COMPLIANCE.md), opening): OpenSeal is *designed to support* ESIGN, UETA, eIDAS
and Part 11. Compliance belongs to a deployment: its operator, configuration, certificates and procedures.

| We say | We never say |
| --- | --- |
| "Designed to support" ESIGN, UETA, eIDAS simple and advanced signatures, Part 11 | "Legally binding", "compliant", "certified", "court-admissible" |
| The sealed PDF shows whether its bytes changed since sealing, checked by our verifier and two independent validators in CI ([31](31-SEALING-AND-SIGNATURES.md) §Verification ladder) | That a seal proves who a signer was |
| The audit trail detects removed, inserted or reordered events ([32](32-AUDIT-TRAIL-AND-EVIDENCE.md) §4) | That a self-hosted deployment's evidence is trustworthy without the operator's controls |
| An OWASP ASVS self-assessment exists ([67](67-ASVS-SELF-ASSESSMENT.md)) | SOC 2, ISO 27001 or any attestation ([09](09-LEGAL-AND-COMPLIANCE.md) §6) |
| Software alone cannot make a qualified electronic signature (QES) ([09](09-LEGAL-AND-COMPLIANCE.md) §2) | That OpenSeal makes an AES or QES today |

Not yet established, and stated as such wherever a claim is made: counsel review of claims and the disclosure
(`LEG-02`); external security and cryptographic review (`SEC-REV-01`); external penetration test (`HRD-05`,
[68](68-PEN-TEST-SCOPE.md)); validation of sealed files in Adobe Acrobat (`HRD-03`, `PV-01`); trademark search on the
name (`DEC-07`).

## The evidence model

What a completed agreement carries, and where each piece is specified.

| Piece | What it is | What it shows | What it does not show | Where |
| --- | --- | --- | --- | --- |
| Person's signature | A drawn, typed or uploaded mark the recipient adopts, then an explicit Finish | An act of adoption, recorded as an event | Identity beyond the authentication used | [31](31-SEALING-AND-SIGNATURES.md) §1, [09](09-LEGAL-AND-COMPLIANCE.md) §1 |
| Platform seal | A PAdES digital signature by the operator's key over the final PDF, made once at completion by default | The file has not changed since sealing, and which key sealed it | Which person signed; the seal is the operator's, not the signer's | [31](31-SEALING-AND-SIGNATURES.md) §1–3 |
| Trusted time | An RFC 3161 timestamp from a timestamp authority in every seal (default profile PAdES B-T) | The seal existed at that time, per the authority | Server times inside the audit events are the server's own clock | [31](31-SEALING-AND-SIGNATURES.md) §2, §6; [32](32-AUDIT-TRAIL-AND-EVIDENCE.md) §2 |
| Long-term validation | Optional B-LT and B-LTA profiles add revocation data and archive timestamps | The seal can be checked years later without the network | Renewal of archive timestamps is slice 17, not built | [31](31-SEALING-AND-SIGNATURES.md) §2 |
| Audit trail | One event per legally relevant fact, append-only, SHA-256 hash chain per envelope (RFC 8785 canonical JSON) | Any change, removal or reordering of events is detectable | Facts the server never saw; the truth of what a signer typed into an IP or browser field | [32](32-AUDIT-TRAIL-AND-EVIDENCE.md) §1–4 |
| Chain head in the PDF | The audit trail is embedded in the sealed PDF and its last hash printed on the certificate | Altering the embedded trail breaks the seal | — | [32](32-AUDIT-TRAIL-AND-EVIDENCE.md) §4 |
| Certificate of completion | A page set listing documents and hashes, each recipient's authentication, IP, user agent, optional location, consent and times | A human-readable summary of the chain | — | [32](32-AUDIT-TRAIL-AND-EVIDENCE.md) §6 |
| Offline verification | Browser (WebAssembly), command line, no account and no server | Anyone can check the seal and chain | Trust in the operator's certificate; that depends on the CA chain the reader trusts ([09](09-LEGAL-AND-COMPLIANCE.md) §7) | [96](96-FEATURE-FIT-GAP.md) `FG-157` |

**Signer authentication options that work today** ([96](96-FEATURE-FIT-GAP.md)): the emailed signing link; access
code (`FG-117`); email one-time code; SMS and voice one-time codes through an operator's gateway (`FG-119`); sign-in
through an OpenID Connect identity provider (`FG-217`). **Not built:** knowledge-based authentication and ID
verification (`FG-120`, `FG-121`), per-signer keys for AES or QES through a qualified trust service provider
(`FG-161`, slice 18), Part 11 mode (`FG-162`, slice 19).

**Consent.** A versioned electronic records and signature disclosure (ERSD) per account, accepted before the
documents are shown; the consent event records the version's hash; consent can be withdrawn (`FG-111`;
[09](09-LEGAL-AND-COMPLIANCE.md) §1; [07](07-SECURITY-THREAT-MODEL.md) `SEC-D05`). Each account publishes its own text (`ERSD-01`,
[22](22-DATA-MODEL.md)); the operator guide tells operators to have counsel review it ([65](65-RUNNING-IT.md)
§Production checklist). A default text for the project to offer is part of `LEG-02` (`DEC-07`); none has been
reviewed.

## Questions for counsel

### United States: ESIGN and UETA

1. Does the ceremony as specified (explicit adoption, explicit Finish, review before Finish, versioned ERSD with
   consent and withdrawal) meet ESIGN §7001(c) and UETA §§9, 10 for consumer transactions? What is missing?
2. What must a default ERSD template say, and which parts must each operator change?
3. Is "designed to support ESIGN and UETA" acceptable wording for the README, site and product? Is there wording we
   should avoid beyond the list above?
4. The certificate of completion records IP, user agent, authentication method and optional location. Is that the
   right attribution evidence under UETA §9? Is anything recorded that we should not record?
5. ESIGN §7003 exclusions are enforced only by the operator's terms ([09](09-LEGAL-AND-COMPLIANCE.md) §1). What must
   the operator guide say?

### European Union: eIDAS

6. We describe the default ceremony as a simple electronic signature (SES) and the platform seal as protecting
   integrity (Art. 26(d)). Is that accurate? Does anything we say imply an advanced signature (AES)?
7. With an access code, a one-time code or identity-provider sign-in, can any OpenSeal signature meet Art. 26(a)–(c)
   (uniquely linked, identifying, sole control) without a per-signer key? Our design says no
   ([09](09-LEGAL-AND-COMPLIANCE.md) §2). Please confirm or correct.
8. If an operator uses a qualified seal certificate and a qualified timestamp authority, what may that operator say
   about the platform seal? What may the project say?
9. For slice 18 (remote signing through a QTSP over the CSC API), what contractual and technical points should the
   design settle before we build it?

### What the evidence establishes

10. In a dispute, what does a sealed PDF with an embedded hash chain prove, and what does it leave open? Specifically:
    the operator holds the seal key and runs the server clock. What would a court or opposing expert expect beyond
    this (for example the key service's operation log, [31](31-SEALING-AND-SIGNATURES.md) §5, or public anchoring of
    chain heads, [32](32-AUDIT-TRAIL-AND-EVIDENCE.md) §5)?
11. A self-hosted seal key without a publicly trusted certificate shows "validity unknown" in Acrobat
    ([09](09-LEGAL-AND-COMPLIANCE.md) §7). Does that affect evidential weight, or only presentation?

### Records retention

12. Purging an envelope keeps a tombstone (envelope id, chain head, sealed hash, purge time and policy;
    [32](32-AUDIT-TRAIL-AND-EVIDENCE.md) §7). Is that tombstone personal data? Is keeping it defensible?
13. What default retention should the product suggest, if any? We leave it to each account today.

### Data protection

14. Roles, self-hosted: our design treats the sender's account as controller and the operator as processor
    ([09](09-LEGAL-AND-COMPLIANCE.md) §5). Is that right when the operator and sender are the same company? Who is
    controller for signers who are not the sender's customers?
15. Roles, if the project ever hosts a service (see [72](72-SUSTAINABILITY-OPTIONS.md)): what must a DPA template and
    sub-processor list contain?
16. Evidence versus erasure: signed agreements are kept, and the admin audit log keeps an administrator's IP address
    inside its hash chain for the life of the log ([09](09-LEGAL-AND-COMPLIANCE.md) §5). What lawful basis and notice
    wording would you advise operators to use?
17. Signer location is recorded only when the account turns it on, from the device with the signer's permission or
    approximated from IP ([09](09-LEGAL-AND-COMPLIANCE.md) §5). What notice is needed?
18. India's DPDP Act 2023: since the maintainer is in India, does anything change for the project itself (not for
    operators)?

### Licence and clean room

19. OpenSeal is Apache-2.0. Every major open-source competitor (Documenso, DocuSeal, OpenSign Labs, LibreSign) is
    AGPL-3.0 ([52](52-COMPETITOR-STUDY.md) §Clean-room rule). We never read their source to implement ours, use only
    their public documentation and behaviour, and contributors attest to this in CONTRIBUTING. Is that process
    sufficient? What records should we keep?
20. We match the API shapes integrators know from DocuSign and SignNow without using their names or copying their
    prose ([52](52-COMPETITOR-STUDY.md)). Is that defensible?
21. The eight open licence questions in [09](09-LEGAL-AND-COMPLIANCE.md) §9 (attribution placement, images, model
    weights, ONNX Runtime's bundled MPL-2.0 code, fonts, the `rav1e` patent licence).
22. Trademark: is "OpenSeal" clear to use for software in our classes (`DEC-07`)?

## Deliverables expected from counsel

| Deliverable | Closes |
| --- | --- |
| A short memo answering questions 1–13, with permitted and forbidden wording for the README, site and product | `LEG-02` (claims) |
| A default ERSD template (or a mark-up of our draft), with notes on what each operator must adapt | `LEG-02` (disclosure) |
| A note on controller and processor roles, a DPA outline and privacy-notice points for operators (questions 14–18) | Input to [09](09-LEGAL-AND-COMPLIANCE.md) §5 |
| Answers to the licence packet and the clean-room process (questions 19–21) | `LEG-01` sign-off; `LEG-05` to `LEG-08` |
| A trademark search result (question 22) | `DEC-07` |
| A list of anything in the repository counsel would change, each turned into a [14](14-EXECUTION-TRACKER.md) row | — |

## What we provide

The repository (public, Apache-2.0); this brief; [09](09-LEGAL-AND-COMPLIANCE.md), [31](31-SEALING-AND-SIGNATURES.md),
[32](32-AUDIT-TRAIL-AND-EVIDENCE.md), [52](52-COMPETITOR-STUDY.md); a sample sealed PDF with its certificate of
completion from the development stack; a draft ERSD text if counsel wants one to mark up; a named contact.

## Decisions for the owner

1. Which counsel, and which jurisdictions first: US and EU only, or India as well (`LEG-03`).
2. Scope: the full list above, or claims and ERSD first (questions 1–13) with data protection and licence later.
3. Whether README and site wording is held at today's text until counsel answers, or reviewed now against this brief.
