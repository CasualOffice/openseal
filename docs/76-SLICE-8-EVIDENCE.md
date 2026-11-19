# 76 — Slice 8 evidence (API and webhooks)

Evidence for the owner to close slice 8, **API and webhooks** ([06](06-ROADMAP-AND-DELIVERY.md) §After Phase 2;
tracker row `VS-08`), in the format of [75](75-SLICE-4-EVIDENCE.md). Only the owner closes a slice, and exit criteria
are never bent ([05](05-PHASES-AND-TASKS.md)). This page proposes; it closes nothing.

**Summary (2026-11-20, second pass):** of the seven outcome elements, API keys are met on a green `main` run; OAuth 2.1
(authorization code with PKCE), the JWT grant, webhooks with their delivery log on the real stack, sandbox accounts
(ADR-041, owner instruction 69), the TypeScript and Python SDKs (built and tested in the repository, the slice's
reading under owner instruction 70) and the API reference are built on the worktree branch with tests seen red.
Nothing built here is in a green `main` run yet; the branch is merged with `main` at `f667422` (the palette test fix).

**Reference run.** The last `main` run green on every job is 44419251440 (`584634d`, M3). The latest, 44605190804
(`6bd9646`, slices 3 and 4), finished red in `e2e (2)` and `e2e (6)` on one stale test outside this slice
(`prepare-layout.spec.mjs:185`, fixed in PR #36). Items marked **branch** ran locally on the worktree branch
(PostgreSQL 55432; Playwright headless, mock mode) and are in no CI run.

**Gate items.** Slice 8 has no boxes in docs/06; its gate is the general end point of docs/06 §After Phase 2: the
outcome, then "merged, CI green including a browser run, docs/96 rows updated, demo recorded", with accessibility
(WCAG 2.2 AA) and i18n string extraction. The outcome is the slice-8 row: "OAuth 2.1, JWT grant, API keys, webhooks
with delivery log, sandbox accounts, TypeScript and Python SDKs, API reference site". M4 adds "API reference
published; TypeScript and Python SDKs released as beta".

**Readings chosen** (the outcome does not say; DocuSign's behaviour, docs/48):

- *OAuth 2.1*: the authorization code grant with PKCE (S256 only) and rotating refresh tokens, for confidential
  clients registered in a workspace, acting for members of that workspace who consent on a consent screen. Public
  clients (no secret) are not offered. The client-credentials grant was built in Phase 2.
- *JWT grant*: DocuSign's model: an integration registers a public key; each member consents once through the
  consent screen; the integration then signs assertions acting for that member, with no refresh token.
- *Webhooks with delivery log*: what docs/40 §4 designs and Phase 2 and `UXW-31`–`UXW-33` built (account
  subscriptions, signing with rotation, retries, the log, test events, deliver again, the Admin screen), now shown on
  the real stack. Sender and template filters, disabling after five failing days and mTLS are `VS-08I`, outside the
  outcome's words.

## Outcome

| Element (docs/06) | Status | Evidence, or what is missing |
| --- | --- | --- |
| OAuth 2.1 | Built (branch) | `VS-08A`. Migration 0048, `-store` `repo/oauth.rs`, `-server` `api/oauth.rs` (authorize endpoint, checked request, consent, codes, `authorization_code` and `refresh_token` grants, consents, RFC 8414 metadata), token claims `usr`/`grt` checked on every request; web: the consent screen `authorize.js`, Admin's client form (redirect URIs), Connected apps in the profile. Server `tests/oauth.rs` `an_app_acts_for_a_member_who_consented_through_the_code_flow` (2 passed with the JWT test); seen red with consent revocation unchecked in `auth.rs` (`left: (200, "") right: (401, "CS-AUTH-0002")`) and with the PKCE comparison removed (`left: (200, "", "") right: (400, "invalid_grant", "CS-AUTH-0014")`). The contract test exercises every new operation (`tests/contract.rs`, 2 passed); the isolation test covers `/oauth/consents/{id}` across accounts (`tests/isolation.rs`, 2 passed). Web `tests/slice8.test.mjs` (4 passed), seen red without the mock's consent (`CS-API-0002: Not found`). Browser: `api-webhooks.spec.mjs` takes a member through the consent screen and (real stack) exchanges the code with PKCE and reads an envelope with the token. Missing: a green `main` run |
| JWT grant | Built (branch) | `VS-08B`. `openseal_resolve_jwt_client` (0048), `jwt_grant` (the key's SubjectPublicKeyInfo read in-tree, the signature checked by `jsonwebtoken` on aws-lc-rs, ADR-006; no new dependency), Admin takes the PEM and refuses a private key before sending. `tests/oauth.rs` `a_jwt_integration_acts_for_a_member_who_consented_once`: consent required (`CS-AUTH-0005`), another audience, expired, over an hour, another key (`CS-AUTH-0014`), a scope beyond the consent, withdrawn consent ending the token. Assertion replay within its hour is `VS-08G`. Missing: a green `main` run |
| API keys | **Met** | Phase 2 (`FG-193` `Works`): `osk_` keys, SHA-256 at rest, scoped, expiring, revocable; `tests/auth.rs` and `tests/contract.rs` in `server-db` of `main` run 44419251440, green. The Admin screen makes and revokes them (`UX-08`); `api-webhooks.spec.mjs` makes one in Admin and sends an envelope with it on the Compose stack (branch) |
| Webhooks with delivery log | Built (server Met; real stack on branch) | Server and worker on `main` since 2026-11-13: delivery, Standard Webhooks signing and rotation, retries, the log, test and deliver again (`UXW-31`–`UXW-33`; `tests/self_service.rs`, the worker's `webhook.rs` tests) in run 44419251440. Admin screen `UXW-10` (mock e2e on `main`). New: the CI receiver `tools/e2e/auth_stubs.py hooks` checks every delivery's signature (`test_auth_stubs.py`, seen red with the comparison removed), in `compose.e2e.yml` on the Compose network (`OPENSEAL_WEBHOOK_ALLOW` there only); `api-webhooks.spec.mjs`: an envelope sent through a key, the receiver told to fail, the failed `envelope.sent` in the log with 500, delivered again, the same `webhook-id` accepted and verified. Mock mode passed on chromium and webkit. Missing: `compose-e2e` green on `main` |
| Sandbox accounts | Built (branch) | `VS-08D`, ADR-041 (owner instruction 69, model (a)). Migration 0049: `accounts.sandbox`, fixed at creation (the database refuses any change), and the ledger's two writers count nothing for a sandbox; `POST /organizations/me/workspaces {sandbox}`; `sandbox` in the session, account, workspace and signing view; `osk_test_` keys; keyd's sandbox slot and the worker's sandbox key (never the platform key; `CS-WRK-0020` without one); the certificate titled "Sandbox Certificate (not for agreements)"; emails' `[Sandbox]` subject and first line; the verifier's `signer` and the Verify page's note; the web app's banner and the org screen's checkbox; the Compose stack's sandbox key. Tests seen red: worker `tests/sandbox.rs` (sandbox branch removed: sealed with the platform key, `left: Completed right: Completing`), server `tests/sandbox.rs` (quota wrapper disabled: `left: 1 right: 0`), keyd `two_keys.rs` (slot unread: `left: String("platform") right: "platform and sandbox"`), certificate and verify tests, web `slice8.test.mjs` (`isSandboxSigner` unused), `api-webhooks.spec.mjs` sandbox test (banner never shown: `toBeVisible() failed`). Real stack (CI only): a sandbox envelope sent with an `osk_test_` key, signed through its emailed link with the banner, sealed with keyd's sandbox key, the Verify page saying "not for agreements". Missing: a green `main` run |
| TypeScript and Python SDKs | Built (branch); publishing not now (owner instruction 70) | `VS-08E`. `tools/build-sdks.py` generates the operation tables of `sdk/typescript` (`@openseal/sdk` 0.1.0-beta.0) and `sdk/python` (`openseal` 0.1.0b0) from `api/openapi.yaml` (170 public operations; `--check` in CI `checks`); OAuth helpers and webhook verification in both; tests offline against `sdk/contract/recorded.json`: TypeScript 9 passed, Python 7 passed, each seen red with its signature comparison removed (`✖ webhooks: the Standard Webhooks example verifies…`; `FAIL: test_the_standard_webhooks_example_verifies_and_changes_do_not`). Owner instruction 70: the SDKs stay in the repository with no release step; the slice closes on them built and tested here; M4's "released as beta" stays open as `VS-08J`. The drift check in CI's `checks` was approved by owner instruction 71. Other languages `VS-08H` |
| API reference site | Built; published on `main` before this slice | `VS-08F`. `site/docs/api.html` generated from `api/openapi.yaml` by `tools/build-api-docs.py`, published by `pages.yml` (run 44601058854 green); regenerated on the branch with the slice's operations. Met when a green `pages` run carries them |

## End point

| Gate item (docs/06, verbatim) | Status | Evidence, or what is missing |
| --- | --- | --- |
| merged | Not met | The worktree branch carries `VS-08A`–`VS-08F`; merged by the main session after it verifies them |
| CI green including a browser run | Not met (waits for CI and sandbox) | Run locally on the branch: `cargo test --no-fail-fast -p casual-sign-store -p casual-sign-server` on PostgreSQL (every test binary passed); clippy `-D warnings` on the server; `npm test` in `webapp/` (299 passed); `api-webhooks.spec.mjs` mock mode on chromium and webkit (6 passed; the slice test seen red with the consent route removed); `python3 -I -m unittest discover -s tools/e2e` (14 passed); both SDK suites. Only CI shows `compose-e2e` (the real receiver, the code exchange) and `server-db` on Linux |
| docs/96 rows updated | Met (for what is built) | `FG-191`, `FG-192`, `FG-195`, `FG-199` Partial naming their tests and what makes them `Works`; `FG-193` `Works`; `FG-200` waits for question 1; `FG-190` `Works` |
| demo recorded | Not met (waits for CI) | `compose-e2e` uploads `target/e2e-demo/vs08-*` as `slice-8-demo` (`.github/workflows/ci.yml`, the slice-3 pattern): the key made, the envelope sent, the failed delivery delivered again, the app allowed. Met when a green `main` run carries it and it is watched and linked from [65](65-RUNNING-IT.md) §Demos |
| Accessibility (WCAG 2.2 AA) and i18n string extraction | Not met (waits for CI) | Axe in `api-webhooks.spec.mjs`, light and dark: the API client form (JWT integration with redirect URIs and key), webhooks, the consent screen, a refused request (mock, chromium and webkit). i18n: `i18n-slices.test.mjs` now covers `authorize.js`, `admin.js`, `adminmodel.js`, `profile.js`; it went red on two placeholders in `admin.js` (`"#b3141f"`, `"https://"`), now marked as not language; every new string is in `webapp/strings/admin.en.js` |

Recommendation: ready to propose for closure once a `main` run with this branch is green on every job (with
`compose-e2e` running `api-webhooks.spec.mjs` on the real stack) and `slice-8-demo` has been watched.

**Owner decisions (2026-11-20):**

1. **Sandbox accounts:** model (a), DocuSign's (instruction 69), written as ADR-041 Accepted and built (`VS-08D`).
2. **Publishing the SDKs:** "Not now" (instruction 70): no release step; the slice closes on the SDKs built and
   tested in the repository; M4's "SDKs released as beta" stays open as `VS-08J`. Publishing will need an npm scope,
   a PyPI project and their tokens as repository secrets.
3. **The SDK drift check in CI's `checks`:** approved (instruction 71).

## Found and not fixed

| Row | What | Size |
| --- | --- | --- |
| `VS-08G` | A JWT bearer assertion may be used again within its hour (`jti` not remembered) | S |
| `VS-08H` | SDKs for Java, C#, Go, PHP and Ruby | M |
| `VS-08I` | Webhook sender and template filters, disabling after five failing days, mTLS | M |
| `VS-08J` | Publish the SDKs as beta (M4), when the owner says (instruction 70) | S |
| `VS-08K` | A sandbox has no sending limit of its own beyond the rate limits | S |

Nothing here states that any signature is legally valid or that the product is compliant or certified (docs/09).
