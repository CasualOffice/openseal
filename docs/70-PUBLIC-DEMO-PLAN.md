# 70 — Public demo deployment plan

Status: **Ready for the owner's decision** (`DOC-012`, owner instruction 51). The owner chooses the option and
provides the accounts listed at the end. This page recommends the static path first; it is the plan behind rows
`SITE-03` (public in-browser verifier) and `SITE-04` (interactive demo before Docker) in
[14](14-EXECUTION-TRACKER.md).

## Goal

A visitor tries OpenSeal in under a minute with nothing to install: sends and signs a sample agreement, then verifies
a sealed PDF. The demo must never hold a real agreement, never send mail or SMS to strangers on our behalf, and never
carry a key or certificate anyone could mistake for a real one.

## Options

| | A. Static demo on GitHub Pages | B. Hosted live stack |
| --- | --- | --- |
| What runs | The web app in mock mode (`app.html?mock=1`) and the verify page with the WebAssembly verifier, as static files | The full Compose stack ([65](65-RUNNING-IT.md)): server, worker, keyd, Postgres, object store, mail, timestamp authority |
| Backend | None. Mock mode is an in-memory fake of the API in the browser (`webapp/mock.js`, `WEB-01`) | One server we operate |
| What a visitor sees | The real UI: send editor, signing page, Agreements; a banner says it is a demo | The real product end to end, including real sealing |
| Sealing in the demo | None: mock mode's "sealed" PDF is the delivered one, and nothing is signed (`webapp/mock.js` header). The verify page verifies real sealed fixtures | Real PAdES seals from a demo key |
| Verifier | Real: the same `casual-sign-verify` code as the CLI, compiled to WebAssembly (`webapp/verify*`, `vendor/openseal-wasm`; [31](31-SEALING-AND-SIGNATURES.md) §7) | Same |
| Visitor data | Stays in the browser tab (sessionStorage); nothing is uploaded | Uploaded documents, names, emails and IPs reach our server ([07](07-SECURITY-THREAT-MODEL.md) §Data classification) |
| Outbound mail and SMS | None; the one-time code is fixed (`MOCK.emailCode`) | Needed for a real ceremony, unless kept in a mail catcher |
| Ready today | Mock mode and the verify page exist and are tested in Playwright; publishing them on the site is `SITE-03` and `SITE-04` | The stack runs on one machine; the abuse controls below are not all built |
| Operations | None beyond the site's Pages workflow (`.github/workflows/pages.yml`) | Patching, backups or resets, monitoring, abuse handling |

## Recommendation

**Option A first.** It matches `SITE-03` and `SITE-04`, needs no server, holds no visitor data, and cannot be used to
send phishing mail. Option B waits until the controls it depends on exist (§Option B prerequisites) and the owner
decides it is worth an operator's time.

Two honest limits of Option A, shown on the page:

- The demo's "sealed" PDF is not sealed. The page says so, and links to the verify page for a real seal.
- The verify page shows the sample fixtures' certificate as untrusted unless the visitor adds the demo root; that is
  correct behaviour and the page explains it ([09](09-LEGAL-AND-COMPLIANCE.md) §7).

## Option A: what to build

| Item | Row |
| --- | --- |
| Verify page on the site, linked from the top navigation; drag in a PDF; integrity, certificate trust, timestamp and revisions shown; works with the network blocked | `SITE-03` |
| Sample files beside it: one sealed fixture, one tampered fixture, and the demo root certificate, each labelled as test material | `SITE-03` |
| The web app in mock mode served from the site, as the home page's main call to action; e2e covers send and sign from the home page | `SITE-04` |
| Limitations shown on the home and demo pages: pre-release, demo seals not real, no production use | `SITE-08` |

Data handling: none leaves the browser. State lives in the tab's sessionStorage and resets when the tab closes
(`webapp/mock.js`). Nothing to reset on a schedule. No analytics unless the owner asks; if asked, a cookie-free counter
with no personal data, recorded as a decision.

Security: the page is static, served over HTTPS by GitHub Pages, under the web app's strict content security policy.
The verify page reads files locally; `SITE-03`'s acceptance test runs it with the network blocked. The sample
certificates come from the test PKI (`fixtures/interop`, [31](31-SEALING-AND-SIGNATURES.md) §As built HRD-02), whose
private keys are not kept.

Monitoring: an uptime check of the site's home and verify pages, and the Pages workflow's own link check
(`tools/check-site-links.py`).

## Option B prerequisites

A live stack open to the public is a mail-sending, file-accepting service. These must be true before it opens:

| Need | Control | State today |
| --- | --- | --- |
| No phishing through our domain | Sender verification, outbound rate limits, fixed email templates, an abuse link in every email ([07](07-SECURITY-THREAT-MODEL.md) `SEC-M01`) | Planned, not built |
| No spam or exhaustion through signing links | Per-link and per-IP limits, usage caps, CAPTCHA option (`SEC-L01`) | Planned, slice 11 |
| Upload limits | 50 MiB per file and 200 MiB per envelope today ([21](21-PARSER-LIMITS.md)); a demo wants far less | Built at those values; a lower demo cap needs configuration to be confirmed |
| Per-account quotas | Plans, metering and quota enforcement (`PLAN-02` to `PLAN-04`, [23](23-ORGANIZATIONS-WORKSPACES-AND-CONSOLE.md) §7) | Built; paused under the freeze until M3 ([06](06-ROADMAP-AND-DELIVERY.md) §Freeze) |
| Malware scanning of uploads | ClamAV, Compose profile `production` ([65](65-RUNNING-IT.md) §Malware scanning) | Built |
| Sign-in and API rate limits | Per login, per client address, per principal (`SEC-A09`) | Built in part |
| Hardened deployment | Non-root, read-only file systems, TLS, secrets from files (`HRD-06`) | In progress |

Safer variant of B: no outbound email or SMS at all. Every message lands in a mail catcher shown inside the demo, so
a visitor can play every role but cannot reach anyone else. This removes `SEC-M01` and most of `SEC-L01` from the
critical path.

**Keys and certificates for B.** A demo CA whose names say "DEMO — not for real agreements", its key in SoftHSM
through keyd (as the development stack does, [65](65-RUNNING-IT.md)); never a file key in production mode; **never a
certificate from a publicly trusted or AATL CA**, so a demo seal can never show as valid in Acrobat. A public
timestamp authority only after it passes `tools/interop/interop.py` ([31](31-SEALING-AND-SIGNATURES.md)); otherwise
the stack's local one.

**Data handling for B.** Terms on the sign-up page: test documents only, no real agreements, no personal data of
others. Every account and envelope wiped on a fixed schedule (proposal: daily), by recreating the stack's volumes
and bootstrapping again. Envelopes expire within that window. Logs carry pseudonyms only ([07](07-SECURITY-THREAT-MODEL.md)
`SEC-D06`). A privacy notice for the demo is a question for counsel ([69](69-LEGAL-REVIEW-BRIEF.md)).

**Monitoring for B.** The security events and alerts in [65](65-RUNNING-IT.md) §Logs, shipped off the box; seal
failures; job backlog; disk; a page to the owner on any malware hit or rate-limit surge.

## Cost drivers

No prices are given; none can be checked from the repository.

| | A | B |
| --- | --- | --- |
| Hosting | GitHub Pages for a public repository (no fee expected; to confirm against GitHub's current terms) | One virtual machine sized for the stack, block and object storage, backups |
| Domain and TLS | Optional custom domain | A domain; TLS certificates |
| Email and SMS | None | None in the safer variant; otherwise a sending provider and per-message fees |
| People | Build time for `SITE-03`, `SITE-04` | An operator on call for abuse, patching and resets |
| Risk cost | Low | Abuse reports, provider suspension, reputation if a demo is misused |

## What the owner must decide or provide

1. **Option:** A now and B later, A only, or both now.
2. **Enable GitHub Pages** for the repository (source: GitHub Actions); the workflow is ready (`SITE-01`).
3. **Domain:** the default Pages address, or a custom domain the owner registers.
4. For B only: a hosting account, a domain for the demo stack, and whether any real mail or SMS may be sent (the
   recommendation is none).

## Decisions for the owner

1. Approve Option A (static mock-mode demo and in-browser verifier on GitHub Pages) as the first public demo.
2. Enable GitHub Pages and choose the address (default or custom domain).
3. Whether Option B is planned at all, and if so whether it may ever send real mail or SMS.
