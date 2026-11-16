# 71 — Design-partner pitch

Status: **Ready to send** (`DOC-013`, owner instruction 51). One page for about five companies that would embed
electronic signatures in their own product. The owner chooses whom to send it to. Every statement below is checked
against the repository; nothing here is a legal or compliance claim ([09](09-LEGAL-AND-COMPLIANCE.md)).

---

## OpenSeal: e-signature you can embed, under Apache-2.0

**The problem.** If your product needs signatures, you rent them from a vendor per envelope, or you embed an
open-source project. Every serious open-source e-signature project (Documenso, DocuSeal, OpenSign Labs, LibreSign) is
AGPL-3.0 ([52](52-COMPETITOR-STUDY.md)). Many companies cannot ship AGPL code inside a proprietary product. DocuSeal keeps bulk send, SSO and
embedded components in its paid edition, and Documenso its embedded authoring; Documenso ships no verifier and
DocuSeal a basic one.

**What OpenSeal is.** An Apache-2.0 signing and verification engine you embed, with a reference web app built on it
([README](../README.md); `POS-01`). You may use it in proprietary and commercial products with no royalty and no
separate licence; keep the LICENSE and NOTICE when you redistribute ([ATTRIBUTION.md](../ATTRIBUTION.md)).

## What you get

| | What | State today |
| --- | --- | --- |
| Engine | Rust crates that read, fill, flatten, seal (PAdES B-B to B-LTA) and verify PDFs, with a hash-chained audit trail embedded in the sealed file; the `openseal` CLI and the `casual-sign-sdk` crate | Built and tested on 417 real PDFs and 50 hostile ones; seals accepted by pyHanko and EU DSS in CI ([README](../README.md) §Status) |
| Offline verifier | The same verifier in the browser (WebAssembly) and on the command line; no account, no server | Works ([96](96-FEATURE-FIT-GAP.md) `FG-157`); a standalone npm/WASM package follows M3 (`VER-01`) |
| API | REST with an OpenAPI document (`api/openapi.yaml`); envelopes, recipients, routing, fields, templates; signed webhooks | Works (`FG-190`, `FG-194`) |
| Signer authentication | Access code, email, SMS and voice one-time codes, sign-in through your OpenID Connect provider; versioned consent disclosure | Works (`FG-111`, `FG-117`, `FG-119`, `FG-217`) |
| Self-hosting | One `docker compose up` for the whole stack; your keys in your HSM through a separate key service that never sees documents | Compose works (`FG-210`); PKCS#11 built, cloud KMS backends open (`KEYD-01`) ([31](31-SEALING-AND-SIGNATURES.md) §5) |
| No paywall | Bulk send, templates, conditional fields, SSO, embedding, webhooks are all in the open core | Policy ([README](../README.md)); several are still being built ([96](96-FEATURE-FIT-GAP.md)) |

## What is honestly not ready

- **Pre-release.** v0.0.1 (2026-11-12) runs end to end on one machine and is "not yet for production agreements".
  Milestone M3 (first signature, private preview) is not closed ([06](06-ROADMAP-AND-DELIVERY.md)).
- **No external review yet.** No penetration test (`HRD-05`, scope in [68](68-PEN-TEST-SCOPE.md)) and no external
  cryptographic review (`SEC-REV-01`). Our own ASVS self-assessment has open findings ([67](67-ASVS-SELF-ASSESSMENT.md)).
- **Not yet checked in Adobe Acrobat** (`HRD-03`, `PV-01`). A seal shows as trusted in Acrobat only with a certificate
  from a CA on Adobe's list, which each operator obtains ([09](09-LEGAL-AND-COMPLIANCE.md) §7).
- **Embedded signing and sending views and the TypeScript and Python SDKs are designed, not built** (`FG-196`,
  `FG-197`, `FG-199`). Today you integrate through the REST API and webhooks, or the Rust crates.
- **No legal review yet** (`LEG-02`). OpenSeal is designed to support ESIGN, UETA and eIDAS simple signatures; it does
  not make advanced or qualified signatures today, and holds no SOC 2 or other attestation.

## What we ask of you

1. **Integrate** OpenSeal into one real flow of your product within about three months, against the API or the engine.
2. **Report** what breaks or is missing, as GitHub issues or in a fortnightly 30-minute call. Your findings become
   tracked rows and shape the order of work.
3. **Be a reference** once it works for you: a short call with another prospective partner, or a named quote. Only
   with your written approval.

## What you get as a partner

- A direct line to the maintainers and priority on the bugs and gaps that block your integration.
- A say in the order of the work after M3 (embedding views, SDKs, key-service backends).
- Early access to the verifier package and each release before it is announced.

Nothing here is a contract, a warranty or an SLA. Partners use OpenSeal under Apache-2.0 like everyone else.

## How to start

1. Run it: `docker compose up -d --build --wait` ([65](65-RUNNING-IT.md)), or look at the web app with no server in
   demo mode ([README](../README.md) §Run it).
2. Read the API: `api/openapi.yaml` and [40](40-API-DESIGN.md).
3. Reply to this note with the flow you would integrate first; we agree a 30-minute kickoff.

---

## Decisions for the owner

1. Which companies to approach, and who sends the note (owner or maintainer).
2. What the project commits in return: the call cadence and how much priority partner bugs get against the freeze
   until M3 ([06](06-ROADMAP-AND-DELIVERY.md) §Freeze).
3. Whether to send now (pre-M3, with the limits above) or after M3 closes and the verifier package (`VER-01`) is out.
