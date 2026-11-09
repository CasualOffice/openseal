# 52 — Open-source competitor study

**Status: Live; from public sources, 2026-11-10.** What the open-source e-signature projects do, how they seal, and
what OpenSeal does differently. Legend as in [49](49-SIGNNOW-STUDY.md): **[V]** checked, **[M]** general knowledge,
**[?]** uncertain.

## Clean-room rule

**Every major open-source competitor is AGPL-3.0.** None of their code, schema, CSS, UI copy or tests may enter this
Apache-2.0 repository, and translating their TypeScript or Ruby to Rust is still a derivative work. We read their
public documentation and observe their running behaviour; we never read their source to implement ours.

- Contributors attest that they have not copied AGPL code (DCO sign-off plus the attestation in CONTRIBUTING).
- AGPL or copyleft PDF stacks are never dependencies, even transitively: iText, HexaPDF, MuPDF, cpdf/coherentpdf,
  Ghostscript, Poppler. `deny.toml` holds the licence allow-list ([19](19-WORKSPACE-SCAFFOLD-DESIGN.md)).
- Permissive references may be read and, where copied, attributed in `NOTICE`: pyHanko (MIT), Apache PDFBox
  (Apache-2.0), qpdf (Apache-2.0), `@libpdf/core` (MIT), pdf.js (Apache-2.0).
- EU DSS (LGPL-2.1) is used only as a **separate process** in CI for validation, never linked.
- No use of "DocuSign" or "SignNow" in names or branding. Matching an API shape for interoperability is generally
  defensible (*Google v. Oracle*, 2021), but documentation prose is never copied. This is not legal advice; `LEG-01`
  asks for a review before release.

## The field

| Project | Licence | Stars (≈, Nov 2026) | Stack | Sealing |
| --- | --- | ---: | --- | --- |
| **DocuSeal** (github.com/docusealco/docuseal) | AGPL-3.0 + §7(b) attribution terms [V] | 19.0k [V] | Rails, Hotwire/Turbo, Vue builder; SQLite/Postgres/MySQL; S3/GCS/Azure | HexaPDF (AGPL/commercial) [V]; RSA only; PAdES via its handler; timestamps possible; self-signed certificate on-prem by default, `.p12` upload (https://www.docuseal.com/resources/add-own-signing-certificate) [V]; TSA/LTV configuration [?] |
| **Documenso** (github.com/documenso/documenso) | AGPL-3.0; Enterprise Edition commercial [V] | 15.7k [V] | TypeScript, React Router 7, Hono, tRPC, Prisma/Postgres, Tailwind | `@libpdf/core` (their own, **MIT**) (https://github.com/libpdf-js/core) [V]: incremental updates, PAdES B-B to B-LTA, DSS, DocTimeStamp; **no verification** [V]. Signers: local `.p12`, Google Cloud HSM, **CSC API** for eIDAS AES/QES (Enterprise only; forces sequential signing; audit log and certificate become separate PDFs so the signed PDF stays untouched) (https://docs.documenso.com/docs/self-hosting/configuration/signing-certificate/csc-qes) [V]. Whether B-LT ships is inconsistent in their docs [?] |
| **OpenSign** by OpenSign Labs (github.com/OpenSignLabs/OpenSign) | AGPL-3.0 with an exception for `cloud/customRoute` [V] | 7.2k [V] | React (Vite, Tailwind/DaisyUI), Parse Server on Express, MongoDB, S3 | `pdf-lib`, `@signpdf/*`, `node-forge`, `coherentpdf`, `libreoffice-convert` [V]; certificate from `PFX_BASE64`, self-signed by default [V]; basic PKCS#7 detached, no LTV [M] |
| **LibreSign** (github.com/LibreSign/libresign) | AGPL-3.0 [V] | 0.84k [V] | PHP Nextcloud app, Vue | JSignPdf (Java) and CFSSL; runs its own CA [V topics] |
| SignRequest | Proprietary; bought by Box (2021), now Box Sign [V] | — | — | — |
| EU DSS | LGPL-2.1 [M] | — | Java | Reference PAdES/CAdES/XAdES creation and **validation** |
| pyHanko | MIT [M] | — | Python | PAdES B-LTA, DSS and validation; our CI's second validator |

> **Name collision, resolved.** "OpenSign" is the name of OpenSign Labs' AGPL product in exactly this category, with
> about 7k stars, so this project is named **OpenSeal** (`DEC-01`, owner instruction 4, 2026-11-10). A web search on
> 2026-11-10 found only an old, unrelated .NET library on SourceForge called openSEAL (EPL) and no e-signature product;
> that is not trademark clearance (`DEC-07`). Crates keep the prefix `casual-sign-`.

## Feature notes

- **DocuSeal** [V]: WYSIWYG PDF form builder, about a dozen field types, multiple submitters, API, webhooks,
  signature verification, mobile apps. **Paid (Pro) only**: white-label, user roles, reminders, SMS and ID
  verification, conditional fields and formulas, bulk CSV send, SSO/SAML, HTML/DOCX template APIs, embedded components.
  Strengths: builder UX, easy deployment. Weaknesses: the paywall, and AGPL plus HexaPDF lock-in.
- **Documenso**: templates, direct links, teams and organisations, webhooks, embedding (authoring is paid), REST API
  v1/v2, signing order, roles (signer, approver, viewer, CC, assistant), access and action auth (account, 2FA, passkey)
  [M]. External pull requests paused [V]. Strengths: modern stack, a strong MIT signing library, a QES path.
  Weakness: AGPL; no verifier.
- **OpenSign Labs**: templates, signing order, guest email OTP, expiry, reject with reason, bulk send, webhooks, Zapier,
  audit trail and completion certificate, organisations [V]. Weaknesses: Parse/Mongo stack, non-persistent Mongo in the
  default compose, can start without a working certificate.
- **LibreSign**: lives inside Nextcloud; good for that audience, not a standalone product.

## Where OpenSeal differs

| | Competitors | OpenSeal |
| --- | --- | --- |
| Licence | AGPL everywhere | **Apache-2.0**: embeddable in proprietary products, the reason integrators will choose it |
| Paywalled features | Conditional fields, bulk send, SSO, embedding, reminders, QES | Everything in the open core |
| Verification | Documenso none; DocuSeal basic | A full verifier (ours) plus independent validators in CI; offline verify page in WASM |
| Evidence | Audit pages | Hash-chained events, certificate of completion, audit JSON embedded in the PDF, optional public anchoring |
| Engine | Coupled to the web app | A headless engine usable without our server (`casual-sign-sdk`) and in the browser (WASM) |
| Key custody | `.p12` in an environment variable | `keyd` isolation; PKCS#11, cloud KMS; file keys refused outside development |
| Sister ecosystem | — | Converts and previews `.docx`, `.xlsx`, `.pptx` through OpenDoc, OpenCalc and OpenPresent |

## What to measure against them

Each becomes a row in [96](96-FEATURE-FIT-GAP.md) or a benchmark in [10](10-ENTERPRISE-REQUIREMENTS.md): time from upload
to send for a three-signer document; signer ceremony steps and time on mobile; validators passed by the sealed output
(Adobe Reader, EU DSS, pyHanko); feature rows available without payment.
