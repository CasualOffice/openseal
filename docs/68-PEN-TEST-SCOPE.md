# 68 — External penetration test: scope

Status: **Ready to send to a vendor** (`HRD-05`, owner instruction 48). Choosing the vendor and setting the budget are
the owner's. This page is the statement of work a vendor quotes against. Our own self-assessment
([67](67-ASVS-SELF-ASSESSMENT.md)) is not a substitute for this test and is not offered as evidence of one.

## Objective

An independent, manual, adversarial test of one OpenSeal deployment built from the hardened production profile
(`deploy/compose.production.yml`, [65](65-RUNNING-IT.md) §Production deployment). It must answer three questions:

1. **Can evidence be forged or altered?** Can anyone make a sealed agreement verify when it does not show what every
   party saw, or make a genuine one fail? Can anyone rewrite, reorder or drop audit events undetected?
2. **Can anyone sign, read or act as someone else?** This covers another tenant, another recipient, a staff user
   above their role, and the platform seal key used outside the sealing path.
3. **Can the service be taken down or made to leak?** This covers hostile uploads, resource exhaustion, and personal
   data in responses, logs, errors or webhooks.

## In scope

| Area | What | Where to start |
| --- | --- | --- |
| Web app and public API | `/api/v1/*`, the sender and admin web app, sign-in, MFA, password reset, invitations, API clients (OAuth client credentials), webhooks | [40](40-API-DESIGN.md); `server/casual-sign-server` |
| Signing ceremony | Recipient links, access codes, email and SMS one-time codes, IdP sign-in, consent (ERSD), adopt-and-sign, decline, the signer view | [24](24-ENVELOPE-LIFECYCLE-AND-ROUTING.md), [07](07-SECURITY-THREAT-MODEL.md) `SEC-A*` |
| Document handling | PDF upload and normalization, Office conversion, attachments, signature images, malware scanning | [30](30-PDF-PIPELINE.md), [21](21-PARSER-LIMITS.md), `SEC-P*` |
| Sealing and evidence | PAdES seal, RFC 3161 timestamps, revocation, the audit hash chain and its head in the sealed PDF, the certificate of completion, offline verification | [31](31-SEALING-AND-SIGNATURES.md), [32](32-AUDIT-TRAIL-AND-EVIDENCE.md), `SEC-S*` |
| Key custody | `keyd` (mTLS, allow lists, operation log, rate limits, seal key rotation `CON-10`) as seen from a compromised worker or server container | `server/casual-sign-keyd`; `SEC-S04`, `SEC-S05` |
| Operator console | The platform operator's console and its TOTP | `server/casual-sign-console` |
| Tenancy | Cross-tenant access at every object-level route; row-level security | `SEC-A04`; [22](22-DATA-MODEL.md) |
| Deployment | The production Compose profile: container escape surface, network segmentation (`data`, `signing`, `edge`, `egress`), secrets handling, TLS between services, configuration integrity (`ASVS-24`) | [65](65-RUNNING-IT.md) §Production deployment |
| Model service | `modeld` (document analysis) as a target, and prompt or content injection through uploaded documents | `server/casual-sign-modeld` |

## Out of scope

- Denial of service by traffic volume (load is measured separately, `HRD-04`). Single-request resource exhaustion,
  such as decompression bombs, slow parses or unbounded allocations, **is** in scope.
- Social engineering, physical access, and the vendor's own email or SMS providers.
- Third-party services we only call: the TSA, OCSP and CRL endpoints, and the IdPs. Our handling of hostile answers
  from them **is** in scope.
- The marketing site (`site/`, static files).
- Desktop clients, until they ship.

## Test types expected

- Authenticated and unauthenticated testing of the web app and API, with accounts at every role in two tenants.
- Ceremony abuse: link forwarding and guessing, code brute force, lockout bypass, replay, routing-order skips,
  signing after void or decline.
- Evidence attacks: shadow attacks, incremental-save attacks, signature wrapping, timestamp replay, and validation
  with Adobe Acrobat Reader and an independent validator. We supply the interoperability packet in `fixtures/interop/`.
- Hostile files: a corpus of malformed and malicious PDFs, Office documents and images. Our fixtures are in
  `fixtures/`; the vendor brings its own.
- Configuration review of the production profile and a container breakout attempt from the web-facing server
  container.
- Source-assisted review (grey box): the repository is public under Apache-2.0, and we expect the vendor to read
  it.

## Environment and access we provide

- A dedicated deployment of a tagged release on the production profile, with a test HSM or SoftHSM seal key and a
  test CA chain. It holds no real customer data and no real agreements.
- Two tenants with an owner, an administrator, a sender and a viewer in each; API clients; and a console operator
  account.
- The `keyd` operation log, the security event log ([65](65-RUNNING-IT.md) §Logs) and the database, so the vendor
  can confirm what was detected.
- A named contact for the test window, and a channel to stop testing if real harm is seen.

## Rules of engagement

- Testing window, source addresses and an emergency stop are agreed in writing before the test starts.
- No testing against any deployment other than the one provided.
- Critical findings are reported within 24 hours, not held for the final report.

## Deliverables

- A report with every finding: severity (CVSS 3.1 or 4.0), affected component, reproduction steps, evidence and a
  suggested fix. Include an executive summary.
- A retest of fixed findings within an agreed period after the fixes, with a retest letter.
- The tester's methodology and tool list.

## What happens to findings

Each finding becomes a `docs/14` row on receipt (`SEC-PT-*`), with severity and owner. Critical and high findings
block the hardening exit gate (docs/06 §Hardening release) until they are fixed and retested. The report is kept
privately. After the retest we publish a summary of what was tested and found, never claiming certification
([09](09-LEGAL-AND-COMPLIANCE.md)).

## Vendor criteria

- Testers with recognised offensive-security qualifications, such as OSCP, OSWE, CREST CRT or CCT.
- Demonstrable experience with PKI, PDF or digital-signature systems. Ask for a redacted sample report.
- Willing to test a self-hosted open-source deployment and work from source (grey box).

Effort and price are the vendor's to estimate from this scope. Two reference points to ask about are web, API and
ceremony as one block, and evidence, PDF and key custody as a second.
