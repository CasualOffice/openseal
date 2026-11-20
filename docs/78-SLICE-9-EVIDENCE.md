# 78 — Slice 9 evidence (embedding)

Evidence for the owner to close slice 9, **Embedding** ([06](06-ROADMAP-AND-DELIVERY.md) §After Phase 2; tracker row
`VS-09`), in the format of [76](76-SLICE-8-EVIDENCE.md). Only the owner closes a slice, and exit criteria are never
bent ([05](05-PHASES-AND-TASKS.md)). This page proposes; it closes nothing.

**Summary (2026-11-21):** before this slice only the embedded signing view's link existed (`WF-05`, Phase 2): five
minutes, the creating client only, bound to the first browser, but every page `frame-ancestors 'none'` and its
binding a `SameSite=Strict` cookie that a browser does not send to a cross-site frame, so it could not actually be
framed. Every outcome element is now built on the worktree branch with tests seen red: the signing view framed by its
host page with return URL, state and events; the prepare and correct views; the `<openseal-signing>` and
`<openseal-prepare>` elements; per-workspace `frame-ancestors`; an example host page; a browser run where a page on
another site embeds all three views and hears their events. Nothing here is in a green `main` run yet.

**Gate items.** Slice 9 has no boxes in docs/06; its gate is the general end point of §After Phase 2 ("merged, CI
green including a browser run, docs/96 rows updated, demo recorded", with WCAG 2.2 AA and i18n string extraction) over
the outcome "Signing, prepare and correct views; `<openseal-signing>` and `<openseal-prepare>` elements", copying
"OpenCalc's embed element and theme tokens". Closing it with slices 3, 4, 6 and 8 reaches **M4** (docs/06 milestones:
"Slice end points; 96 rows for those slices `Works`; API reference published; TypeScript and Python SDKs released as
beta").

**Readings chosen** (the outcome does not say; DocuSign's and SignNow's behaviour, docs/48, docs/49):

- *Audience-bound view URL*: the view request names its host page (`frame_origin`), which must be on the workspace's
  list; the page may be framed by that origin only and posts its events to it only. A view without one is framed by
  the whole list. A link opens once: the signing view binds to the first page, a prepare or correct link is spent by
  its page's first session request.
- *Cross-site binding*: inside another site's frame the browser sends no first-party cookie, so an embedded link's
  page keeps its binding in memory and sends it as `X-OpenSeal-Binding`; only an embedded link takes it.
- *Prepare and correct*: a one-hour `osv_` session acting as the API client's member through that client, on that one
  envelope, with only the operations its editor needs. Only an API client may ask for one (not a staff session).
- *Elements*: one ES module served by OpenSeal at `/openseal-elements.js` (docs/40 §5 said "from `sdk/`"; serving it
  from the server keeps the element and the pages it frames one release). An iframe, not OpenCalc's shadow root
  (ADR-017); OpenCalc's named theme tokens copied. Events map DocuSign's return events onto four DOM events
  (`complete`, `decline`, `cancel`, `error`) plus `ready`.

## Outcome

| Element (docs/06) | Status | Evidence, or what is missing |
| --- | --- | --- |
| Signing view | Built (branch) | `VS-09B`. `POST /envelopes/{id}/views/signing` takes `frame_origin`, `return_url`, `state` (`CS-EMB-0001` off the list); the page's `frame-ancestors` is the host page; the binding travels in `X-OpenSeal-Binding` for an embedded link only; the view answers `embed {frame_origin, frame_origins, return_url, state}`; sign.js posts `ready`, `completed`, `declined`, `finish_later` and returns to `return_url?event=…&state=…`. Server `tests/embedding.rs::an_embedded_signing_view_is_framed_by_its_host_only_and_binds_by_header`, seen red with the header binding removed (`left: 403 right: 200`), with the origin check removed (`left: (201, "") right: (422, "CS-EMB-0001")`); web `tests/slice9.test.mjs`. Browser: `embedding.spec.mjs` signs and declines inside a host page (mock, chromium and webkit). Missing: a green `main` run with `compose-e2e` |
| Prepare view | Built (branch) | `VS-09C`. `POST /envelopes/{id}/views/prepare` (a draft, an API client only), `GET /e/{token}` serving `embed.html`, `POST /e/{token}/session` spending the link once for an `osv_` session; the guard keeps it to its envelope and editor operations (`CS-EMB-0002`). `tests/embedding.rs::prepare_and_correct_views_are_spent_once_and_reach_their_envelope_only`, seen red with the reach check skipped (`left: (404, "CS-API-0002") right: (403, "CS-EMB-0002")`) and a revoked client allowed (`left: (200, "") right: (401, "CS-AUTH-0002")`); the contract test exercises the four new operations. Browser: the draft sent from the editor inside the host page, heard as `openseal:complete sent`; the spent link opens nothing |
| Correct view | Built (branch) | `VS-09C`. `POST /envelopes/{id}/views/correct` (sent or delivered); the page opens the app's correct panel (envactions.js, unchanged). Same server test (only its operations: `send` refused). Browser: leaving the panel heard as `openseal:cancel cancelled`. The template edit view docs/40 also lists is `VS-09F`, outside the outcome's words |
| `<openseal-signing>` and `<openseal-prepare>` | Built (branch) | `VS-09D`. `webapp/openseal-elements.js` (served with CORS; `web.rs` `ELEMENTS`), attributes `src`, `origin`, `title`, `timeout`, events `openseal:ready/complete/decline/cancel/error`, `theme()`. `slice9.test.mjs` seen red with the frame-source check removed and with the origin check removed (`✖ an element takes a message only from its own frame…`); the framed side seen red posting to `*` and taking commands from another origin. Example host page `sdk/embed/example/index.html`, the page the browser run uses |
| Per-account `frame-ancestors`, clickjacking | Built (branch) | `VS-09A`. `settings.embedding_origins` (security setting; Admin → Organization → Embedding, `embedmodel.js` checking as the server does); `X-Frame-Options: DENY` everywhere a policy names no origin. Seen red: per-account sources removed (`left: "frame-ancestors 'none'" right: "frame-ancestors https://host.example"`), DENY on every page (`left: "DENY" right: ""`), the setting unchecked (`left: (200, "") right: (422, "CS-API-0001")`). Browser: a page on an origin not allowed gets no frame (`openseal:error … timeout`), a message the host page forges is ignored |
| OpenCalc's embed element and theme tokens | Copied (branch) | Element shape (connected/attribute callbacks, `ready`, named-token `theme()` that throws on a typo) from OpenCalc `webapp/embed.js` at `b23c67c`; recorded in the files' headers |

## End point

| Gate item (docs/06, verbatim) | Status | Evidence, or what is missing |
| --- | --- | --- |
| merged | Not met | On the worktree branch; the main session merges after verifying |
| CI green including a browser run | Not met (waits for CI) | Run locally: `cargo test -p casual-sign-server` `embedding`, `contract`, `isolation`, `web`, `routing`, `auth`, `threats`, `in_person`, `sandbox`, `privacy` and the lib tests on PostgreSQL (all passed); clippy `-D warnings` on server and store; `sqlx-prepare.sh` regenerated the cache; `npm test` in `webapp/` (312 passed); `embedding.spec.mjs` mock mode on chromium and webkit (4 passed each), seen red with sign.js's completion event removed (`Expected substring: "openseal:complete completed order-7781"`); the specs that touch the same screens re-run on chromium. 2026-11-21, after merging slice 6: the Compose stack built locally exactly as `compose-e2e` (`COMPOSE_FILE=docker-compose.yml:tools/e2e/compose.e2e.yml`, admin bootstrapped), `embedding.spec.mjs`, `api-webhooks.spec.mjs` and `manage-correct.spec.mjs` on chromium against it: 16 passed, 2 skipped (manage-correct's mock-only axe), the real server framing each view for a host page on another site, the header binding and the `osv_` session in a real browser, and `vs09-*` recorded; two real-only fixes made on the way (the disclosure step is optional on a fresh account; the recording is saved after its page closes). Only CI shows: webkit against the real stack, `server-db` on Linux, the uploaded `slice-9-demo` |
| docs/96 rows updated | Met (for what is built) | `FG-196`, `FG-197`, `FG-198` Partial naming their tests; `Works` on a green `main` run with `compose-e2e` |
| demo recorded | Not met (waits for CI) | `compose-e2e` uploads `target/e2e-demo/vs09-*` as `slice-9-demo` (`.github/workflows/ci.yml`, the slice-8 pattern): the host page embedding signing, prepare and correct and listing their events. Met when a green `main` run carries it and it is watched |
| Accessibility (WCAG 2.2 AA) and i18n string extraction | Built (waits for CI) | Axe in `embedding.spec.mjs`, light and dark: Admin's Embedding card and panel, the embedded signing view, the embedded editor (mock, chromium and webkit). i18n: `i18n-slices.test.mjs` covers `embed.js`, `embedframe.js`, `embedmodel.js`, `openseal-elements.js` and `embed.html`, seen red with a literal in `embed.js`; strings in `webapp/strings/embed.en.js` |

Also updated: `api/openapi.yaml` (four operations, `EmbedSession`, `EmbedTarget`), the SDK operation tables
(`build-sdks.py`, 172 operations; `/e/` is not public API, as `/s/`), the API reference (`build-api-docs.py`), docs/07,
docs/20 (`CS-EMB-0001`, `0002`), docs/21, docs/22 (migration 0050), docs/40 §5 As built.

Recommendation: ready to propose for closure once a `main` run with this branch is green on every job (with
`compose-e2e` running `embedding.spec.mjs` on the real stack) and `slice-9-demo` has been watched; M4 then also needs
slices 6 and 8 closed and `VS-08J` (SDKs published as beta).

**Owner questions** (decided here and recorded; the owner may change them):

1. *`http://` origins on the list.* Answered (owner instruction 81): also for intranet hosts. Built: a loopback,
   RFC 1918, link-local or IPv6 unique-local address, `localhost`, a single-label name, or a name under `.local`,
   `.internal`, `.lan`, `.localhost` or `.test`; a public host still needs `https`. Tests seen red before the change:
   `embed::tests::plain_http_is_taken_for_intranet_hosts_only` (`left: None right: Some("http://10.1.2.3")`) and
   `slice9.test.mjs` "plain http is taken for intranet hosts only" (`✖`).
2. *Who may ask for a prepare or correct view.* Answered (owner instruction 81): API clients only, as built.
3. *Instruction 73* (closing slice 8 on a green `main`) is in [03](03-OWNER-INSTRUCTIONS.md) since slice 6 merged;
   nothing left to record.

## Found and not fixed

| Row | What | Size |
| --- | --- | --- |
| `VS-09F` | The embedded template edit view (`template_edit`, docs/40 §5) | M |
| `VS-09G` | The view posts its height so the element can size itself (`resize`) | S |
| `WF-06` (existing) | An embedded recipient may still be given `delivery: email` | S |

Nothing here states that any signature is legally valid or that the product is compliant or certified (docs/09).


**Owner answers (2026-11-21):** plain `http://` origins are also allowed for intranet (private-network) hosts, not only development hosts; prepare and correct views stay API-client only. To be recorded as owner instruction 81 and built before the slice 9 PR.
