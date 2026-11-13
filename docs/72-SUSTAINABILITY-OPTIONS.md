# 72 — Sustainability options

Status: **Ready for the owner's decision** (`DOC-014`, owner instruction 51). How the project could pay for its own
upkeep. Nothing here changes the licence: OpenSeal stays Apache-2.0, free to use, embed and commercialize, with no
CLA, no commercial licence and no trademark licence (owner instruction 20, [03](03-OWNER-INSTRUCTIONS.md);
[ATTRIBUTION.md](../ATTRIBUTION.md)). Hosting a service is the owner's business decision ([01](01-PRD.md) §5). No
prices are given; none can be checked from the repository.

## Constraints every option must respect

| Constraint | Source |
| --- | --- |
| Apache-2.0 for all code; no dual licensing, because owner instruction 20 rules out a commercial licence and a CLA | [03](03-OWNER-INSTRUCTIONS.md) instruction 20 |
| No feature behind a paywall: bulk send, signing links, conditional fields, SSO, retention, embedding and webhooks are in the open core | [README](../README.md) §Why; [52](52-COMPETITOR-STUDY.md) §Where OpenSeal differs |
| OpenSeal does not become a trust service provider; qualified signatures come through QTSPs | [01](01-PRD.md) §5 |
| No compliance or certification claimed until established by the process in [09](09-LEGAL-AND-COMPLIANCE.md) | [09](09-LEGAL-AND-COMPLIANCE.md) |
| The freeze: nothing outside the core flow, hardening, verifier and API/SDK moves until M3 closes | [06](06-ROADMAP-AND-DELIVERY.md) §Freeze |

So every option sells **operation, assurance or time**, never code.

## The options

### 1. Hosted cloud (OpenSeal run by the project)

Customers sign up and send envelopes on a service the project operates.

| | |
| --- | --- |
| What it needs: people | 24/7 on-call operations; security response; customer support; someone accountable for privacy and abuse |
| What it needs: infrastructure | Multi-node deployment with high availability (slice 20; the cluster is design only, [65](65-RUNNING-IT.md)); HSM or cloud KMS for the seal key (cloud KMS backends open, `KEYD-01`); a publicly trusted (AATL) seal certificate ([09](09-LEGAL-AND-COMPLIANCE.md) §7); email and SMS providers; backups with restore drills ([65](65-RUNNING-IT.md) §Backups) |
| What it needs: assurance (none held today) | External penetration test (`HRD-05`) and security review (`SEC-REV-01`); SOC 2 Type II and likely ISO/IEC 27001, which attach to an operator, not to code ([09](09-LEGAL-AND-COMPLIANCE.md) §6; control mapping `LEG-04` open); a DPA and sub-processor list ([09](09-LEGAL-AND-COMPLIANCE.md) §5); terms of service reviewed by counsel |
| Already built that helps | Organizations and workspaces, the platform console, plans, metering and quota enforcement (ADR-028, [23](23-ORGANIZATIONS-WORKSPACES-AND-CONSOLE.md); paused under the freeze) |
| Cost drivers | Operations staff and on-call; cloud compute, storage and HSM or KMS; per-message email and SMS fees; the CA certificate; audit fees for SOC 2 and ISO; legal |
| Risks | Highest fixed cost and longest lead time (attestations take months of evidence); the project becomes a processor of signers' personal data and a target; competes with the operators it wants to attract |
| Fit with Apache-2.0 | Good: the code stays open; customers pay for operation. Anyone else may host the same code |

### 2. Paid support and SLA for self-hosters

Companies that run OpenSeal themselves buy response times, upgrade help and deployment reviews.

| | |
| --- | --- |
| What it needs: people | Engineers who know the engine and the deployment, in a rota matching the SLA's hours |
| What it needs: infrastructure | A ticket system; a private channel for security reports beyond [SECURITY.md](../SECURITY.md) |
| What it needs: assurance | None formally; buyers will ask for the pen-test summary and the ASVS self-assessment ([67](67-ASVS-SELF-ASSESSMENT.md)); some will ask for SOC 2 of the support process |
| Already built that helps | Production checklist, hardened profile, backup and restore tooling, interop rehearsal ([65](65-RUNNING-IT.md)) |
| Cost drivers | People only; scales with customers |
| Risks | Revenue tied to headcount; pre-release status makes an SLA hard to price; support load can crowd out the roadmap |
| Fit with Apache-2.0 | Best: sells time, touches no code or licence |

### 3. Managed key service (keyd plus HSM as a service)

Self-hosted deployments keep their documents but send seal digests to a keyd the project operates, backed by an HSM,
with a publicly trusted seal certificate.

| | |
| --- | --- |
| Why it fits | keyd already signs only digests and never sees documents ([31](31-SEALING-AND-SIGNATURES.md) §5), so customers' agreements stay on their own machines. It removes the hardest step of self-hosting: getting an AATL certificate and an HSM ([09](09-LEGAL-AND-COMPLIANCE.md) §7) |
| What it needs: people | Key custodians, at least two (as for timestamp authority changes, `CON-07`); on-call for availability, since a down keyd stops every customer's sealing |
| What it needs: infrastructure | A network HSM or cloud HSM; keyd reachable over mTLS from customer sites; keyd refusing digests not tied to a completing envelope (`KEYD-02`) and reconciliation of its log (`KEYD-03`), both open; per-customer keys and certificates or a shared one (a decision) |
| What it needs: assurance | The CA's requirements for AATL keys: hardware at FIPS 140-2 Level 2 or above and audited key ceremonies ([09](09-LEGAL-AND-COMPLIANCE.md) §7); likely SOC 2 for the service. Whether running it makes the project a trust service under eIDAS, against [01](01-PRD.md) §5, is a question for counsel ([69](69-LEGAL-REVIEW-BRIEF.md)) |
| Cost drivers | HSM hardware or cloud HSM fees; certificates per customer or shared; custodians; audits |
| Risks | Concentrated key risk: one compromise affects every customer; legal status unclear; small market until self-hosting grows |
| Fit with Apache-2.0 | Good: keyd stays open; the service is operation of it |

### 4. Combined offering

Support and SLA first (Option 2), the managed key service when its open rows close (Option 3), hosted cloud only once
attestations are in reach (Option 1). The hosted service and the key service share most of their assurance work, so
doing either makes the other cheaper.

Other models considered and not recommended under the constraints: paid features (breaks the no-paywall promise),
dual licensing (ruled out by instruction 20), and paid certification of deployments (the project cannot certify
anyone, [09](09-LEGAL-AND-COMPLIANCE.md)). Sponsorship and grants need no product change and can run beside any
option.

## Comparison

| | Upfront cost | Time to first revenue | Assurance needed first | Legal exposure | Distracts from M3 |
| --- | --- | --- | --- | --- | --- |
| 1. Hosted cloud | High | Long | Pen test, review, SOC 2, DPA | Highest | Yes |
| 2. Support and SLA | Low | Short once v1 is usable | Pen-test summary | Low | Little |
| 3. Managed keys | Medium | Medium | Pen test, CA requirements, likely SOC 2 | Medium; trust-service question | Some |
| 4. Combined, staged | Grows with each stage | Short (via 2) | As each stage | Grows | Little at first |

## Recommendation

**Option 4, staged, starting with Option 2 after M3.** Support needs no new infrastructure or attestation and sells
what the project already has: deep knowledge of the engine. Design partners ([71](71-DESIGN-PARTNER-PITCH.md)) are the
first natural buyers. Prepare Option 3 by closing `KEYD-01` to `KEYD-03` and asking counsel the trust-service
question. Decide on Option 1 only after the pen test and security review (`HRD-05`, `SEC-REV-01`) and with a budget
for SOC 2.

## Decisions for the owner

1. Whether the project should earn revenue at all, and through which entity (the owner's company, a new one, or a
   foundation).
2. Approve the staged order: support first after M3, managed keys next, hosted cloud last; or pick another start.
3. Budget for the assurance work that every paid option leads to: the pen test (`HRD-05`), the external review
   (`SEC-REV-01`), and whether to begin SOC 2 readiness.
