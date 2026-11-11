# 47 — UX target and screen map

**Status: Draft for owner; from public sources and recall, not measured against live products.** What each screen does
and which reference it follows. Feature status is in [96](96-FEATURE-FIT-GAP.md). As in the sisters, the reference
product's flows and layout are the specification and its brand is not: our name, our accent colour (`DEC-03`), Fluent
icons (MIT), no vendor artwork or wording.

## Principles

1. **A DocuSign user needs no teaching**: the same places for the same things (Home, Agreements, Templates, Reports,
   Admin), the same words where they are generic (envelope, recipient, routing order, template, void, correct).
2. **A SignNow user gets their speed**: upload and start placing fields at once; roles assigned in the editor.
3. **Signers are untrained, often on phones, sometimes using assistive technology.** One primary action per screen;
   the next step is always visible; nothing depends on hover or drag.
4. **Every verb is a registered command** (`commands.js`, as the sisters); toolbar, context menus and shortcuts are
   views of the registry. A verb we lack is not drawn.
5. **No document or user string is ever HTML.** `textContent` everywhere.

## Screens

| Screen | File | Reference | Contents |
| --- | --- | --- | --- |
| Site | `index.html`, `docs.html`, `deploy.html`, `download.html` | Sisters' sites | What it is, live demo, self-hosting, verify link |
| Home | `app.html#/home` | DocuSign Home | Start (Send, Sign yourself, Use a template); counters (action required, waiting for others, expiring soon, completed); recent activity |
| Agreements | `app.html#/agreements` | DocuSign Agreements | Folder rail (Inbox, Sent, Drafts, Deleted, user folders, quick views, bulk sends, signing links); list with status, recipients, last change; filters and search; row actions (Correct, Void, Resend, Copy, Save as template, Move, Download, History, Certificate); detail pane with the recipient timeline |
| Prepare | `prepare.html` | DocuSign Send flow + SignNow editor | Two entry modes producing one envelope. **Recipients first**: documents → recipients (type, order, auth, message, language) → fields. **Document first**: the editor opens on upload; roles added from the field panel. Editor: page thumbnails (left), page canvas with field overlays (centre), field palette and recipient selector (left rail, colour per recipient), properties panel (right: required, label, validation, conditional, group, font, tooltip); auto-place by text; preview as recipient; send, schedule, save draft; admission report banner |
| Templates | `app.html#/templates` | DocuSign Templates | My templates, shared, favourites, deleted; folders; edit opens Prepare in template mode with roles |
| Reports | `app.html#/reports` | DocuSign Reports | Envelope and recipient reports, usage, CSV export |
| Admin | `app.html#/admin` | DocuSign eSignature Admin | Users, groups, permission profiles, SSO and domains, brands, ERSD, signing and sending settings, authentication methods, retention, webhooks, API apps and keys, seal and TSA settings, admin audit log |
| Sign | `sign.html` | DocuSign signing + SignNow | See §Signer ceremony |
| Verify | `verify.html` | — (ours) | Drop a PDF; everything runs in the browser (WASM); per-signature verdict, revision list, audit timeline, chain check, download report |

## Signer ceremony

```
 Landing ─▶ Identity (if required) ─▶ Consent (ERSD) ─▶ Documents ─▶ Review ─▶ Done
   │          access code / OTP /       "I agree to use      Start ▸ Next     flattened      download, copy
   │          IdP / IDV                  electronic records"  adopt signature  pages, values  by email; create
   │                                                          fill fields      list; Finish   account (later)
   └─ Other actions (always available): Finish later · Decline · Assign to someone else (if allowed) · View
      certificate (after completion) · Help · Session information · Language
```

- **Start / Next** flag in the margin moves to the next required field; a progress count ("3 of 7 required").
- **Required** fields have a solid outline and an accessible name ending "required"; optional fields dashed.
- **Adopt signature** dialog: name and initials prefilled and editable; tabs **Style** (typed in one of 4 bundled
  script fonts), **Draw** (pointer and touch, with clear and undo), **Upload** (PNG or JPEG, background removed
  client-side, then re-validated server-side); one "Adopt and sign" button; the adoption applies to later fields
  until changed.
- **Review** step (WYSIWYS, [02](02-HLD.md) §6): the flattened pages, with the values listed beside them; "Finish"
  is a separate, explicit action with the legal wording the account configures.
- **Mobile**: full-width pages with pinch zoom; fields enlarge when focused; the adopt dialog is full-screen; the
  Next flag becomes a bottom bar.
- **Accessibility**: every field reachable by Tab in reading order; a field list view as an alternative to the page;
  typed signature as the accessible default; live-region announcements on validation errors; contrast ≥ 4.5:1; no
  time limits except security timeouts, which warn first.

## Emails

Plain, branded, short: who sent it, what to do, one button, the sender's message, the expiry, a "report this" link,
and the security note "Do not forward this email". Fixed templates per event (invitation, reminder, completed,
declined, voided, expiring soon, OTP), with translatable strings and brand colours only; no user-supplied HTML.

## Keyboard (sender editor)

As the sisters: shortcuts are registry entries. Initial set: `Ctrl/Cmd+Z` undo, `Ctrl/Cmd+Shift+Z` redo, `Delete`
remove field, arrows nudge (Shift ×10), `Ctrl/Cmd+D` duplicate, `Ctrl/Cmd+C/V` copy and paste fields across pages,
`1`–`9` switch recipient, `?` shortcut list; since WEB-09 `Ctrl/Cmd+A` selects the page's fields and `Alt+Shift+arrows`
jump to the next snapping guide.

## What we measure

Time to send for first-time senders; signer completion time on mobile; error rate on required fields; screen-reader
completion (`UXR-01`, `A11Y-01`).

## As built (WEB-01, 2026-11-11)

Slice 1's web app, in `webapp/`: plain ES modules, no framework or bundler (ADR-018), served as static files.

| Screen | Where | Calls |
| --- | --- | --- |
| Sign-in | `app.html#/signin` (`signin.js`) | `POST /api/v1/auth/login`, `GET /api/v1/auth/session`, `POST /api/v1/auth/logout` |
| Agreements | `app.html#/agreements[?status=]` (`dashboard.js`) | `GET /api/v1/envelopes?status=&cursor=&limit=&q=`; the top bar's search sends `q` (subject, names, emails; `WEB-04`) after 250 ms |
| Envelope detail | `app.html#/envelopes/{id}` (`envelope.js`) | `GET …/{id}`, `GET …/audit`, `POST …/resend`, `POST …/void`, `GET …/documents/{doc}/content?version=sealed`, `GET …/certificate` |
| Prepare | `app.html#/prepare[/{id}]` (`prepare.js`) | `POST /api/v1/envelopes` (documents, recipients, fields in one call); for a saved draft `POST …/documents`, `POST/PATCH/DELETE …/recipients`, `POST/PATCH/DELETE …/fields` with `If-Match`, `PATCH …/{id}`; `POST …/send` |
| Signing | `/s/{token}` → `sign.html` (`sign.js`, `signature.js`) | `POST /s/{t}/session`, `/authenticate`, `/consent`, `GET /s/{t}/documents/{doc}/content`, `POST …/viewed`, `/adopt`, `PUT /fields/{f}`, `/finish`, `/decline`, `/finish-later`; `location` (GEO-01) on consent, viewed, adopt, finish and decline when the envelope sets `signing_options.capture_location` |
| Site | `index.html` | — |

- **Client** (`api.js`): CSRF header on changing staff calls, a fresh `Idempotency-Key` on every POST, `If-Match` from
  the envelope's ETag, problem details (RFC 9457) surfaced as `ApiError` with the docs/20 code and request id, and a
  sentence per code in `strings.en.js`. The API origin is `<meta name="openseal-api-base">` (empty: same origin).
- **Mock mode** (`mock.js`, `?mock=1`): an in-memory fake of exactly these endpoints, for development and the browser
  tests until the server is integrated. Honoured on a loopback host only, so a deployment cannot be made to show fake
  agreements; it shows a "Demo mode" banner and is never evidence of anything.
- **PDF pages** (`pdfview.js`): vendored pdf.js 4.10.38 in its worker, `isEvalSupported: false`, no scripting sandbox,
  no annotation or text layer (links and forms are not live), XFA off, CMaps and standard fonts from the vendored copy.
- **Geometry** (`geometry.js`): ADR-019 — points in displayed page space, top-left; screen ↔ points is one scale
  factor; coordinates go on the wire as decimal strings with at most two places.
- **Every verb is a command** (`commands.js`, copied from the sisters); keys (`keys.js`) are tables per context
  (editor, global). Editor keys as §Keyboard, plus Alt+arrows to resize, Ctrl/Cmd+S save, Ctrl/Cmd+Enter send, N new
  envelope, / search.

### Content Security Policy

Each page carries this as a meta tag; the server sends it as a header too, adding `frame-ancestors 'none'` (which a
meta tag cannot carry), `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer` and
`Permissions-Policy: geolocation=(self), camera=(), microphone=()`. `tools/serve-webapp.py` sends the same headers,
and so does `casual-sign-server`, which serves `webapp/` at `/` and `sign.html` at `/s/{token}` for a browser
(`OPENSEAL_WEBAPP_DIR`, `WEB-04`, docs/40 §As built); its other files keep the API's `default-src 'none'`.

```
default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data: blob:; font-src 'self';
connect-src 'self'; worker-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'
```

No inline script or style, no `eval` (pdf.js runs with `isEvalSupported: false`), nothing from another origin. `data:`
images are the adopted signature previews. An embedding host (`EMB-*`) relaxes `frame-ancestors` per account, and a
separate API origin is added to `connect-src` by the server that serves the page.

### Design system

One tokens file, `webapp/tokens.css`; components in `webapp/app.css`. Light and dark by `data-theme` or the OS.

| Token family | Values |
| --- | --- |
| Brand | seal red: accent text `#b3141f` (light) / `#ff8a92` (dark); fill `#b3141f` with white text; logo gradient `#c01622 → #8e0b14`. Focus ring blue, distinct from the accent and from errors |
| Type | system UI stack; 12 / 14 / 16 / 20 / 24 / 32 px; body 14 px in the app, 16 px on the signing page and below 760 px; line height 1.5 body, 1.25 headings |
| Space | 4 px grid: 4, 8, 12, 16, 24, 32, 48 |
| Radius | 6, 8, 12 |
| Icons | Lucide (ISC), inlined by `icon(name, {size, label})`: 16 dense, 20 default, 24 toolbars and empty states; stroke 2 (1.75 at 24); `aria-hidden` unless labelled |
| Controls | buttons 32 / 36 / 44 px; targets ≥ 24 px (SC 2.5.8), ≥ 44 px on the signing page and phones (SC 2.5.5); focus ring 2 px, offset 2 px |
| Motion | 150 / 200 / 250 ms, `cubic-bezier(.2,0,0,1)`; all zero under `prefers-reduced-motion: reduce` |
| Recipients | six colours, each ≥ 3:1 against the page as an outline |

Rules: status is never colour alone (badge = icon + word); every list and first-run screen has an empty state
(illustration, one-line title, one sentence, the primary action; illustrations are original line drawings in
`illustrations.js`, `aria-hidden`); lists and pages show skeletons while loading; dialogs and toasts enter and leave
in 150–200 ms; a sent envelope and a finished signing show the seal stamping in once; no looping animation except
loading shimmer and spinners. Contrast is measured, not asserted: `webapp/tests/pure.test.mjs` fails if any text
colour falls under 4.5:1 or a control edge, focus ring or recipient colour under 3:1 in either theme.

### Tests

- `cd webapp && npm test`: Node's own runner over the API client, mock server, geometry, registry, keys, i18n
  coverage and token contrast.
- `webapp/e2e/` (Playwright 1.64.1, axe-core 4.14.0, both test-only): sign-in and agreements; create and send (two
  sequential signers and a CC, fields for each, drag and keyboard placement, drafts); the ceremony at 390 px (access
  code, location, consent, guide, drawn and typed signatures, finish); decline; keyboard only; axe on every screen in
  both themes; empty states with screenshots; on Chromium, WebKit, an iPhone viewport and reduced motion. The same
  specs run against a real server with `OPENSEAL_E2E_BASE_URL` (signing tokens from `OPENSEAL_E2E_SIGN_TOKEN` and
  `OPENSEAL_E2E_DECLINE_TOKEN`, since the server emails them).
- **On the Compose deployment** (`E2E-01`, `T-2F`; CI job `compose-e2e`, docs/65): every spec in Chromium and WebKit with mock
  off. `real-stack.spec.mjs` runs only there: sign in, upload, two signers in order, send; each signer opens the link
  the worker emailed (read from Mailpit's API) and signs; the sender sees Completed and downloads the sealed PDF and
  the certificate into `target/e2e-sealed/`, which pyHanko then validates against the stack's root
  (`tools/verify-sealed.py`). Against a real server the first sign-in seeds a draft and a sent envelope through the
  API and later sign-ins reuse its session (the server allows ten sign-ins a minute); specs that need a seeded
  mock envelope or an emailed token skip, saying so. Found and fixed by this run: the signing page took
  `completing` (the server sealing) for "others still to sign", and showed an error rather than "this link does not
  work" for the server's `CS-AUTH-0002` (an unknown, expired or revoked link, answered alike); and the server's
  ceremony cookie was always `Secure`, which WebKit drops over `http://localhost` (docs/40 §As built).

### Not yet

Auto-place by text; preview as recipient; the engine-flattened review pages (`WEB-05` proposed: a server endpoint
`GET /s/{token}/preview` returning casual-sign-flatten's output; today the review draws the delivered PDF with the
values in place); palette types the model has but the ceremony cannot yet fill (company, title, radio group,
dropdown, attachment); "Sign a document myself" in the Start menu (needs an envelope where the sender signs and a
self-signing view); a Download button on the signer's completion page (no signer endpoint for the sealed PDF);
template documents and fields on the server (docs/40 slice 3; the client calls the designed endpoints and falls back
to roles only); `DELETE /templates/{id}` (not drawn); a recipient filter for "waiting for me"; the browser verifier
reporting the signer's certificate subject and recomputing the embedded audit chain's hashes; two of the four script
fonts; languages beyond English.

## As built (WEB-02 and WEB-03, 2026-11-11)

### Side by side with the reference products

Clean room: layout patterns, flows and component behaviour only, from [48](48-DOCUSIGN-STUDY.md) (DocuSign, public
sources) and SignNow's public help centre (dashboard overview, add and edit fields, send for signature, signing
process guide, templates; read 2026-11-11). DocuSign's own help pages could not be fetched in this session, so its
column rests on docs/48. No logo, name, colour, illustration or text of theirs is used.

| Screen | DocuSign | SignNow | OpenSeal |
| --- | --- | --- | --- |
| Shell | Top bar: logo, Home, Agreements, Templates, Reports, Admin; Start button; search; help; account | Left sidebar of folders; Upload or Create; search at top; notifications bell | DocuSign's top bar: logo, Home, Agreements, Templates, Reports, Admin (admins only); **Start** menu (send, use a template, verify); search; shortcuts; theme; avatar menu. Drawer below 960 px |
| Home | Start actions; counters (Action Required, Waiting for Others, Expiring Soon, Completed); recent activity | Quick access to Waiting for Me, Waiting for Others, Completed, Drafts, Expiring Soon | Greeting; four stat cards linking to their views (action required = declined or expired, waiting, expiring within 7 days, completed); drop zone that opens the editor with the PDFs; recent envelopes; start list |
| Agreements | Folders (Inbox, Sent, Drafts, Deleted) and quick views; list with status and last change; row actions (Correct, Void, Resend, Download, History…); search and filters | Folder tree, status/type/date filters, sort, bulk select (move, archive), row actions panel | Folder rail with counts (all, drafts; action required, waiting, completed; declined, voided, expired); dense table (select, subject with recipients, status pill, last change, row menu: open, edit, resend, void, download, certificate); bulk bar (resend, download, void); the top search asks the server (`q`) |
| Envelope | Detail with recipients and routing, history, documents | — | Summary tab (routing timeline in order, audit trail with chain head) and Documents tab (pdf.js preview with thumbnails and zoom; sealed PDF once completed); actions in the head |
| Send | Add documents → add recipients (action, order, authentication) → message → advanced (reminders, expiry) → tag fields (left palette, recipient dropdown, right properties) → send | Upload, then a single-screen editor: left field palette, right settings panel, roles; then Invite to Sign (recipients, order, per-recipient reminders and expiry, subject and message) | Four steps with a step bar and Back/Next footer: documents (cards with first page, reorder, remove), recipients (cards with colour, order number, type, access code; Set signing order switch), fields (SignNow's editor: palette with recipient switcher on the left, page canvas with zoom and a page strip, properties on the right; tabs in the recipient's colour with a required marker; drag, click or keyboard), review and send (subject, message, reminders, expiry, location, who signs what) |
| Templates | My templates; roles; use with people per role | Make Template from a document; Templates folder; send creates a copy | List; New template is the send flow with roles; Use: one card per role (name, email), the template's document previewed, then Send or Edit before sending; rename |
| Signer | ERSD consent; yellow Start flag becoming Next; required fields outlined; Adopt Your Signature (style, draw, upload); Finish; Other Actions (finish later, decline…) | Welcome or consent pop-up; Guide Me through required fields; Finish and Decline at top right | Access code and consent cards; a bar with the document's name, progress, zoom, a field list and Finish; a yellow Start/Next tag in the left margin beside the next required field; adopt dialog with Style, Draw, Upload; a review step showing the pages with the values before Finish (ADR-020); phones: bottom bar with progress, Next and Finish, pinch zoom, the active field enlarged |
| Verify | — (ours) | — | Drop or choose a PDF; optional trusted certificates; verdict banner; per-signature verdict, time, coverage, checks; changes after signing; the embedded audit trail as a timeline with its links checked; the document previewed |
| Reports, Admin | Envelope and usage reports; eSignature Admin | — | Reports: sent, completion rate, median time to complete, by-status bars, CSV export. Admin: users (add, rename, remove) and API clients (create, secret shown once, revoke) |

### Screens and calls added

| Screen | Where | Calls |
| --- | --- | --- |
| Home | `app.html#/home` (`home.js`) | `GET /api/v1/envelopes?status=&limit=` per counter, `GET …/{id}` for expiry |
| Agreements | `app.html#/agreements[?folder=&q=]` (`dashboard.js`) | as WEB-01, plus `GET …/{id}` per row for recipients and last change |
| Templates | `#/templates`, `#/templates/new`, `#/templates/{id}`, `#/templates/{id}/edit` (`templates.js`, `prepare.js` in template mode) | `GET/POST /api/v1/templates`, `GET/PATCH/DELETE /api/v1/templates/{id}`, the template's documents, roles and fields (`templatesync.js`, WEB-09 and WEB-10 below); using one is a single `POST /api/v1/envelopes` (`templatemodel.js`) |
| Reports | `#/reports` (`reports.js`, `reportmodel.js`) | `GET /api/v1/envelopes` (up to 1,000) and `GET …/{id}` for completed ones |
| Admin | `#/admin[?tab=api]` (`admin.js`) | `GET/POST /api/v1/users`, `PATCH/DELETE /api/v1/users/{id}`, `GET/POST /api/v1/api-clients`, `DELETE /api/v1/api-clients/{id}` |
| Verify | `verify.html` (`verify.js`, `verifyreport.js`, `trail.js`) | none: casual-sign-wasm's `verify()` in the page; `audit-trail.json` read by pdf.js |

- **Every call is in `api.js`** (WEB-10 moved `api-extra.js` there; see below). **Mock mode** serves templates, users
  and API clients as the server does, and is remembered for the tab once `?mock=1` is seen on loopback (`?mock=0`
  forgets). Without mock or a server on loopback the app and signing
  page say "No OpenSeal server is running here".
- **Verifier build**: `tools/build-webapp-wasm.sh` builds casual-sign-wasm as `tools/wasm-parity.sh` ships it and
  copies it to `webapp/vendor/openseal-wasm/` (build output, not committed); without it Verify says so.
- **CSP**: `verify.html` alone adds `'wasm-unsafe-eval'` to `script-src` (meta tag and `tools/serve-webapp.py`
  header), which a browser requires to compile WebAssembly; no JavaScript eval is allowed anywhere.
- **Components** (`webapp/ui/`, one library): buttons and icon buttons with tooltips, fields, selects, checkboxes,
  radios, switches, tabs, menu buttons, modal, drawer, toasts, pills, cards, tables, step bar, empty states,
  skeletons, avatars and the PDF preview; screens import from `ui/index.js`.
- **Signer page details**: every field kind is a tab (inputs show their label inside, auto-filled ones show their
  value and cannot be edited); whether the location was shared is a chip in the bar, never a toast; toasts sit top
  centre under the bar so they never cover the page or the guide.
- **Theme**: light by default (as the reference products); dark and system from the account menu. Tokens gained a
  canvas colour, a medium shadow and the guide-tag colours; contrast tests cover them.

### Tests added

- Node: `tests/web02.test.mjs` (templates as data, verifier report, audit-trail links, zoom, mock persistence, the
  new mock endpoints, string families).
- Playwright: `web02.spec.mjs` (Home, Templates, Admin, Verify on real sealed fixtures, mock persistence, no-server
  state), `visual.spec.mjs` (every screen at 1440×900 and 390×844: full-page screenshots
  `target/e2e-screens/visual-*`; fails on horizontal overflow, overlapping controls, unstyled controls, or a blank PDF
  canvas, by sampling pixels), `redesign-screens.spec.mjs`; the send, keyboard, ceremony, a11y and empty-state specs
  follow the stepped flow and the review step.

## UX audit and document-first rebuild (WEB-06, 2026-11-11)

Owner instruction 22 (docs/03): after using the demo, the editor and the signing page gave the PDF far too little
room and scrolled badly; side panels (resizable, width remembered) instead of dialogs; rem instead of px, scaling with
the screen and browser zoom. The owner's points were examples; this section is the full audit that followed, then the
layout the editor and the signing page were rebuilt to.

### How the audit was done

Every task walked end to end in mock mode with Playwright at 1280×800, 1440×900, 1920×1080, 390×844 and at real
browser zoom 150 % and 200 % (Chromium at zoom z renders a W-wide window as a W/z CSS px viewport at device scale z,
which is how the spec reproduces it). Before-screenshots: `target/before/visual-*`. Each screen judged against
Nielsen's ten heuristics (H1–H10), WCAG 2.2 AA, and how the reference products do the same task (docs/48, docs/49, and
SignNow's public help pages read 2026-11-11: add-edit-fields, keyboard-shortcuts-editor, guide-me-document-signing,
signing-process-guide, dashboard-overview; DocuSign's help pages served only a script shell or 404 to the fetcher,
so its column rests on docs/48). Clicks counted from the code paths.

| Task | Before | After |
| --- | --- | --- |
| Send one PDF to two signers in order with a CC, one signature each | 17 clicks | 15 (Next and Send in the toolbar; recipient chips switch in one click) |
| Place 10 fields across 3 pages | 10 palette clicks, 2 thumbnail clicks, scrolling a ~690 px stage | the same clicks in a stage of the full height |
| Signer: open the field list and jump to a field | 2, the document hidden meanwhile | 1; the panel stays open beside the pages |

### Findings

Severity: **P0** blocks or badly hurts the task, or is the owner's complaint; **P1** a major friction, a WCAG 2.2 AA
failure or a missing safeguard; **P2** a detail users of the reference products expect; **P3** polish. Status as of
this branch's last commit.

| # | Screen | Problem | Heuristic / SC | Sev | Fix | Status |
| --- | --- | --- | --- | --- | --- | --- |
| A1 | Editor | The pages get 56 % of the width at 1440 and ~690 px of height: app bar, demo banner, step bar, zoom bar and wizard footer stack ~290 px of chrome | H8; owner | P0 | Editor frame `100dvh` without the app bar; one toolbar row; panels 13.5 / 15 rem; pages ≥ 65 % of the width | Fixed |
| A2 | Editor, phone | Palette, zoom bar and a 60–75 vh stage inside a scrolling body: two scrollbars, the page scroll fights the stage | H8; owner | P0 | One scroll container; palette and properties in bottom sheets | Fixed |
| A3 | Editor, signer, previews | Zoom repaints every page and jumps to the top; "Fit width" sets 100 % (capped at 1.5× fit); no fit page, presets, Ctrl/Cmd +/−/0 or trackpad pinch | H4, H7; owner | P0 | `docview.js`: fit width, fit page, 50–200 %; keys; Ctrl+wheel and touch pinch; scroll anchored at the pointer or the centre | Fixed |
| A4 | Editor, signer, previews | Every page and thumbnail painted at once; long documents are slow and hold every bitmap | H7 | P1 | Pages near the viewport painted, far ones released; placeholders keep their size | Fixed |
| A5 | Editor, signer | No "Page n of N"; thumbnails neither follow the scroll nor mark the current page | H1 | P1 | Page indicator (announced); current thumbnail marked and kept in view | Fixed |
| A6 | Editor | Panels fixed at 264 / 280 px | owner | P1 | `ui/panel.js`: drag and arrow-key resize, min/max, collapse to an icon rail, remembered per panel | Fixed |
| A7 | Signer | Field list is a modal that hides the document | H6; owner | P1 | Right side panel (bottom sheet on phones) | Fixed |
| A8 | Signer | Adopt signature is a modal over the field being signed | owner | P1 | Side panel on desktop, bottom sheet on phones; Escape closes; focus returns | Fixed |
| A9 | Signer, phone | ~590 of 844 px for the document; the sender's message sits above page 1 | H8 | P1 | Full-height frame; the message moves into the fields panel | Fixed |
| A10 | All | Sizes in px; root size fixed; nothing scales with the screen | owner | P1 | rem everywhere (1 px borders kept); root size by `clamp()` (§Root size) | Fixed |
| A11 | Editor | Thumbnail numbers 11 px; 12 px labels would fall to 11.25 px at a 15 px root | 1.4.4 | P1 | Smallest text `max(0.75rem, 12px)` | Fixed |
| A12 | Editor | Leaving by a link (Agreements, Start, Back) discards unsaved work silently; only a reload asks | H3, H5 | P1 | Route guard: "Leave without saving?" (a destructive confirmation, so a modal) | Fixed |
| A13 | Editor | No sign that work is unsaved | H1 | P1 | Status: "Unsaved changes" / "Saving…" / "Saved at 14:05" | Fixed |
| A14 | Editor | Undo and redo only as keys | H3, H6 | P1 | Undo and Redo buttons, enabled with the history | Fixed |
| A15 | Editor | Back and Next in a footer that repeats the step bar and costs 64 px | H8 | P1 | Back, Next, Send and Save in the toolbar | Fixed |
| A16 | Editor | Send problems in a modal, no way to jump to the cause | H9 | P1 | Problems in a side panel; each a button to its step | Fixed |
| A17 | Signer | A rejected text value shows only a toast | H9; 3.3.1 | P1 | Inline message under the field (`aria-describedby`) | Fixed |
| A18 | Signer | Finish disabled with no reason | H1; 3.3.2 | P1 | Reason as tooltip and accessible description ("2 required fields left") | Fixed |
| A19 | Editor, signer | Skip link goes to `main`, not the document | 2.4.1 | P2 | "Skip to document" | Fixed |
| A20 | Editor, signer | No announcements for page, zoom or selection | 4.1.3 | P1 | One polite live region per view | Fixed |
| A21 | Editor | Recipient switcher is a select without colour; keys 1–9 undiscoverable | H6 | P2 | Recipient chips with colour, number and key hint | Fixed |
| A22 | Editor | Shortcut help unreachable once the app bar is gone | H10 | P2 | Keyboard button in the editor toolbar | Fixed |
| A23 | Editor | Paste lands on the original page; no way to copy a field to another page | H7 | P2 | Paste lands on the page in view | Fixed |
| A24 | Editor | Deleting a field gives no undo affordance | H3 | P2 | Toast with Undo | Fixed |
| A25 | Editor | No multi-select, align or distribute | H7 | P2 | Shift+click selection; align edges, same size, space evenly, move and delete together | Fixed |
| A26 | Editor | Snapping to a 4 pt grid only; no alignment guides (SignNow has field snapping) | H7 | P2 | Guides to other fields' edges while dragging | Open (`WEB-07` proposed) |
| A27 | Envelope, Templates, Verify | Preview is a fixed 640 px box inside a scrolling page; zoom resets the scroll | H8 | P1 | Preview on `docview.js` | Fixed |
| A28 | Admin, Templates, shortcuts | Add or rename user, new API client, rename template, shortcut list are modals | owner | P2 | Side panels (`openPanel`); modals only for void, delete, decline, remove, leave-without-saving | Fixed |
| A29 | Tables | Headers scroll away | H6 | P2 | Sticky headers | Fixed |
| A30 | Envelope | No Correct for a sent envelope (DocuSign Correct) | H3 | P1 | Side panel over `POST …/correct` (§Manage screens, E-01) | Fixed |
| A31 | Agreements, Home | No notice when an envelope changes status while the list is open | H1 | P2 | Refresh on focus and every minute | Open (`WEB-07` proposed) |
| A32 | Signer | No "saved" feedback after a fill (values are saved per field) | H1 | P2 | "Saved" in the bar after each fill | Fixed |
| A33 | Signer | Required vs optional shown by outline colour plus a star | 1.4.1 | P2 | Names say "required"; optional dashed; list says it in words | Kept (already met) |
| A34 | Editor | Palette drag is HTML drag and drop only (no touch) | 2.5.7 | P2 | Tap places on the page in view | Kept (already met) |
| A35 | Verify | The server image lacks the WASM verifier and its CSP blocks it | — | P1 | `WEB-05`: Dockerfile builds it; server adds `'wasm-unsafe-eval'` for `verify.html` only | Fixed |

#### Independent review, merged (send flow)

An independent reviewer walked the current app (scripts and shots kept with the session). Its findings are split
across three workers by screen: the send flow (this table), the signing pages and the manage screens (their own
sections). Findings that repeat a row above point to it.

| # | Problem | Sev | Fix | Status |
| --- | --- | --- | --- | --- |
| P-01 | "Placing fields for" defaulted to the last recipient added (a CC) | P0 | Fields step starts with the first signer; copies never offered; the field's recipient list holds signers | Fixed |
| P-02 | Fields left on a CC were dropped at send without a word | P0 | Sending (and the problems panel) blocks with "X receives a copy … has N fields" and a Fix button | Fixed |
| P-03 | At 400 % zoom (320×256) the header, steps and footer covered the step | P0 | No footer; under 31.25em tall nothing is pinned and the page scrolls | Fixed |
| P-04 | Leaving the editor lost work without a prompt | P0 | Leave prompt (A12), beforeunload, and autosave 4 s after the last change when the draft is savable | Fixed |
| G-01 | Editor chrome took 240 of 900 px | P1 | = A1 | Fixed |
| S-02 | No inline email validation | P1 | Message under the field on leaving it, `aria-invalid` | Fixed |
| S-03 | Recipients step starts empty, no "Add me", placeholder-only labels | P1 | "Add me" when the app knows the sender; visible Name and Email labels; contacts autocomplete on the server's `GET /contacts` | Partly (autocomplete waits for the server merge) |
| F-01 | New fields stack mid-page | P1 | A new field goes below the one placed last on that page, lined up, or in the part of the page on screen; detection uses the server's `detect-fields` | Partly (detection waits for the server merge) |
| F-02 | Field chips do not show the recipient | P1 | Recipient's initials on each field, beside its colour | Fixed |
| F-03 | No multi-select, marquee, align, distribute; paste overlaps | P1 | Shift+click selection with align, size, spacing, group move and delete (A25); paste lands on the page in view (A23); marquee open | Mostly |
| F-04 | Missing field types | P1 | The palette takes the types the server adds | Open (server) |
| F-07 | Coordinates in the main properties | P2 | Under a closed "Advanced" | Fixed |
| F-08 | Phone: palette took 75 % of the screen | P1 | Palette is a bottom sheet behind "Add field" | Fixed |
| F-06 | Thumbnails: no current page, no page x of y, no field counts | P2 | Current marked and followed; "Page n of N"; a count of fields on each thumbnail | Fixed |
| F-09 | Fit width is very large at 1920 | P2 | Kept: fit width is what the reference viewers do; presets are one click away | Kept |
| F-05 | A checkbox field is hidden under its resize handle | P2 | The handle is at most 35 % of the field | Fixed |
| S-04 | Recipients reorder only upward; no drag; no parallel groups | P2 | Up, down and drag by the card's head; parallel groups need per-recipient order numbers | Partly (groups open) |
| R-01 | Review summary below the fold, counts only | P1 | Summary first; each recipient with the kinds of field they fill, or "gets a copy" | Fixed |
| R-02 | Send confirmation silent about order and copies | P2 | "They sign in order: A → B. C will get a copy when it is complete." | Fixed |
| R-03 | Reminder and expiry defaults unseen | P2 | Empty boxes say "Account default" | Fixed |
| R-04 | No ticks on completed steps; no step name on phones | P2 | Done steps ticked (number kept for screen readers); the current step keeps its name on phones | Fixed |
| T-02 | "1 fields" | P2 | Singular forms for fields, pages and counts | Fixed |
### Manage screens (second audit, WEB-06)

Home, Agreements, envelope details, Templates and template use, Admin and Reports, walked at 1440, 1920, 390, 320
and 200 % zoom. Fixed in `home.js`, `dashboard.js`, `envelope.js`, `envactions.js` (what Agreements and the envelope
page share), `templates.js`, `admin.js`, `acceptinvite.js`, `reports.js` and their own stylesheet `manage.css`;
covered by `e2e/manage.spec.mjs` (axe on each screen, no sideways scroll at 320 px, screenshots at every size).

| # | Screen | Problem | Sev | Fix | Status |
| --- | --- | --- | --- | --- | --- |
| G-02 | All manage screens | Sideways scroll at 320 px (top bar, tables, admin tabs); titles broke inside words | P1 | Tables become cards below 37.5em (`.os-table--cards`, each cell labelled); titles wrap between words; the top bar drops the theme button below 22.5em (it is in the account menu); tabs scroll | Fixed |
| G-03 | Home | Six ways to start a new envelope | P2 | Top bar's Start only; the drop zone's button is quiet; the Start card becomes Recent templates | Fixed |
| A-01 | Agreements | No "waiting for whom", sender or expiry; no sort; no date or sender filter | P1 | Status line in words, Sender and Expires columns, sortable Subject, Status, Last change, Expires; sender and date-range filters | Fixed on the loaded rows; server-side sort and filters needed for more than what is loaded (row needed) |
| A-02 | Agreements, Home | A draft opened its detail page, not the editor | P2 | Drafts open in the editor | Fixed |
| A-03 | Agreements | Row menu lacked Download in progress, Copy, Correct, Save as template, Delete, History | P1 | All of them, by state; History is a side panel; Delete for drafts and envelopes that ended without completing (never a completed one) | Fixed in the web app; the server deletes drafts only today (row needed) |
| A-04 | Home, Agreements | "Action required" meant declined or expired; dates unlabelled | P2 | "Declined or expired"; "Last change" with "Created" under it | Fixed |
| E-01 | Envelope | No Correct (DocuSign's) | P1 | Side panel: name, email and access code of each recipient who has not acted; one `POST …/correct` (If-Match), then a new invitation to those changed | Fixed |
| E-02 | Envelope | No download while in progress | P2 | Download current PDF (`content?version=current`) | Fixed |
| E-03 | Envelope | Resend only for everyone; "Reminder" and "Resend" both used | P2 | Resend on each waiting recipient's row; "Resent" everywhere | Fixed |
| E-04 | Envelope | CC rows showed Sent/Opened/Signed; Opened had no time | P2 | A CC row says when its copy goes; Opened takes the first opening event's time | Fixed |
| E-05 | Envelope | Audit events without who did them; seeded audit dates disagreed with the header | P1 | "By" column (sender, recipient, OpenSeal); the mock's seeded histories carry their own times | Fixed |
| E-06 | All manage screens | Toasts covered table columns and row actions | P2 | Toasts bottom-left and narrow, away from the actions and status columns; 7rem kept below the content so a last row scrolls clear | Fixed (a toast can still sit over the left of a row while it shows) |
| T-01 | Templates | No edit, delete, duplicate, search, owner or last use | P1 | Search, Owner, Last used; Edit details in a side panel; Duplicate; Delete (confirmation) | Fixed; reopening a template's fields in the editor needs `prepare.js` to load a template (row needed) |
| T-03 | Use template | Form, document and Send stacked in one long page | P1 | Document left; roles, email and Send in a sticky panel that fits the window; form first below 60em | Fixed |
| AD-01 | Admin | No invite, no profile change or disabling, no account settings | P1 | Invite user (side panel; `POST /users` with `invite: true`), Resend invitation, Edit user (name, profile, disable) in a side panel, Status column; Account tab with Settings and Branding edited in side panels; `#/accept-invite?token=` sets the password without a session and takes the token out of the address bar at once | Fixed |
| RP-01 | Reports | No period; two statuses shared a colour; a stray border under the last row | P2 | Period filter (by creation date); one colour per status with a key; border fixed | Fixed |

### Layout spec: editor (fields step) and signing page

Both are a full-height frame (`100dvh`; the page itself never scrolls) built from the same parts:

```
┌ toolbar 3.5rem (the only chrome) ─────────────────────────────────────────────────────────────┐
├ left panel ┬ document scroller (the one scroll container) ─────────────────────┬ right panel ┤
│ 13.5rem    │ pages centred, 1.5rem apart; fit width by default                  │ 15rem       │
│ min 11     │ placeholders sized at the current scale; canvases painted within   │ min 13      │
│ max 24     │ one viewport above and below, released beyond three                │ max 30      │
│ or a 3rem  │                                                                    │ or a 3rem   │
│ icon rail  │                                                                    │ icon rail   │
└────────────┴────────────────────────────────────────────────────────────────────┴─────────────┘
```

- **Toolbar**, editor: back, title, steps; on the fields step undo, redo, shortcuts; then save status, Save draft,
  Back, Next or Send. Below 90em the save status is a dot (its words in the tooltip and for screen readers) and Save
  and Back are icons. Signer: mark, subject and progress, Fields, More, Finish.
- **Document bar**: floating at the bottom centre of the pages (Acrobat's and Drive's place for it), so the toolbar
  stays one row at 1280: zoom out, zoom preset (fit width, fit page, 50–200 %, and the current custom zoom), zoom in,
  "Page 3 of 12". On phones it shows the page only (pinch zooms).
- **Left panel**, editor: recipient chips (colour, number, key), the field palette, and the page thumbnails, which
  scroll on their own, follow the document and jump on click. Signer: page thumbnails (collapsed by default).
- **Right panel**, editor: properties of the selected field, or the list of placed fields. Signer: the sender's
  message and the field list with states; on review, the values and Finish. Adopt signature opens as a side panel
  over it.
- **Panels** are `aside` landmarks with a heading; the inner edge is a `separator` handle (pointer drag; ←/→ 1 rem,
  Shift ×4, Home/End to min/max); collapse turns the panel into a 3 rem icon rail; width and state are stored per panel
  in `localStorage["openseal.panel.<id>"]` (try/catch: a blocked store just forgets).
- **Below 48em** (phones, and a 1440 window at 200 % zoom): no side panels; the document takes the width; the palette
  and properties (editor) and adopt (signer) are bottom sheets up to 85 dvh, the signer's field list up to 55 dvh, opened from the toolbar or by
  selecting a field; thumbnails hidden; the signer's Next and Finish sit in a bottom bar.
- **Zoom** is a scale on PDF points. Fit width = (scroller width − 3 rem) / widest page; fit page also fits the tallest
  page's height; steps 50, 75, 100, 125, 150, 200 %; pinch and Ctrl+wheel are continuous between 25 % and 400 %. A
  zoom keeps the document point under the pointer (wheel, pinch) or under the viewport centre (buttons, keys) in place.
  Ctrl/Cmd + = / − / 0 act on the document while the view is mounted.
- **Fields** are positioned in PDF points × scale (px), independent of rem; everything else is rem.
- **Order**: "Skip to document" → toolbar → left panel → pages (fields in reading order) → right panel. Page, zoom and
  selection changes are announced in one polite live region.

### Root size

`html { font-size: 100% }`, and from 64em `clamp(0.9375rem, 0.4375rem + 0.625vw, 1.125rem)`: 15 px at 1280, 16 at
1440, 18 from 1760. `rem` inside the root's `font-size` and `em` in media queries both mean the browser's default size,
so a user who set 20 px gets everything 25 % larger; browser zoom shrinks the CSS viewport, so 1440 at 200 % is the
phone layout at 16 px. The smallest text token is `max(0.75rem, 12px)`.

### Signer findings, second pass (WEB-06, 2026-11-12)

Observed in mock mode at 1440×900, 1920×1080, 390×844, 320 wide and 1440 at 200 %. Spec:
`webapp/e2e/guided-ceremony.spec.mjs` (seen red on `f10da57`, except the 200 % footer, which already held and is kept
as a guard); `webapp/tests/signfields.test.mjs`.

| # | Problem | Fix | Status |
| --- | --- | --- | --- |
| P-05 | Phone fields tiny (a text field 122×13 px, a checkbox 10×10) | Every field has a touch area of at least 44 px under its control; a tap on a text field opens a full-width sheet with a large input (SignNow); Start/Next zoom until the field is a 44 px target as far as it fits the width (DocuSign) | Fixed |
| M-01 | Phone body text about 5 px | Zoom-to-field on Start/Next brings it to about 15 px; pinch kept. The signer's and review's scrollers were flex-centred, so a page zoomed wider than the view overflowed to the left out of reach; they are blocks now | Fixed |
| M-02 | Phone bar: Start/Next and Fields as bare icons, title cut to "Offer…" | Worded Start/Next and Fields; a two-line title; More an icon below 26.25em | Fixed |
| M-03 | Adopt on a phone: small pad; actions out of reach at 200 % | Draw full screen, turned a quarter on an upright phone so the signature runs along the long edge; adopt is a side panel on desktop (in the field list's place) and a bottom sheet on phones with its actions pinned | Fixed |
| G-S1 | No Start cue on arrival | Start/Next in the bar; arrival scrolls to the first required field and flags it, without taking focus | Fixed |
| G-S2 | More had only Finish later and Decline (and showed empty on the access-code screen) | Download, Print, Assign to someone else (only with `signing_options.allow_reassign`), View history, Help, Finish later, Decline; Help only before the access code; a copy, history and help after finishing | Fixed; history and reassign need server endpoints (`GET /s/{token}/history`, `POST /s/{token}/reassign`, mock only so far) |
| G-S3 | Done screen had no copy and no next steps | Download a copy (`GET /s/{token}/document?doc=`) and what happens next | Fixed |
| G-S4 | Finish later was a dead end | Continue signing | Fixed |
| G-S5 | Decline did not say what it does | Says it ends the envelope for everyone; filled danger button; still a true modal (destructive) | Fixed |
| G-S6 | Phone field list covered the document (85 dvh) | At most 55 dvh; the document stays visible above | Fixed |
| G-S7 | Review omitted automatic values; two Finish buttons in a row | Every value in page order, date signed, notes and locked values included; opens at the top; one Finish pinned under the values | Fixed |
| G-S8 | Fields without a visible label | A label tab above each field on hover and focus, and for the next one | Fixed |

The field kinds of the server's WEB-06 branch are rendered and filled in the ceremony: company, title and number
(typed, `inputmode` by rule), radio group (a panel of radios), dropdown (the platform select; a panel with a typed value
when `allow_custom`), attachment (PDF, PNG or JPEG up to 10 MiB, `PUT …/fields/{f}/attachment`, listed by name in
review, not drawn on the page), note and sender-locked values (shown, never editable). Text presets (email, phone, ZIP,
length) and number rules (min, max, decimals) are checked inline as the field is left, in the engine's terms
(`webapp/signfields.js`); the server checks again on every fill and at finish. Download before finishing is the
delivered document (`409` from `/document` until the signer finishes).

## As built (WEB-09 and WEB-10, 2026-11-12)

### One API client, checked against the server (WEB-10)

`webapp/api-extra.js` is gone: every call is a method of `api.js`'s client, named as the server names it, and its
request and response were checked against `api/openapi.yaml` and the handlers in `server/casual-sign-server/src/api/`.
`mock.js` answers in the same shapes, so the browser tests catch a client that drifts. What the check found and changed:

| Call | Was | Now |
| --- | --- | --- |
| Correct (`envactions.js`) | `POST …/correct` with `update_recipient` carrying a partial recipient and `access_code`. The engine's `RecipientSpec` refuses unknown members (`access_code`: 400) and `update_recipient` replaces the whole spec, so delivery, phone, time zone and date format would have been reset | One `PATCH …/recipients/{r}` per changed recipient, with only what changed (`people.js` `recipientCorrection`); the server applies it as a correction of a sent envelope, keeps the rest of the spec, and stores the access code. `api.correctEnvelope` stays for the engine change list, documented as such |
| Template fields | `role: <role name>` | `role_id`: the server matches roles by id only. Adding a template document or role answers the whole template, so the new one is the id that was not there (`templatesync.js` `added`); the editor and Save as template used the template's id as the document's |
| Use a template | Fields matched by role name | By `role_id` (`templatemodel.js`), so a server template's fields reach the envelope |
| `PATCH /accounts/me` | `{name, settings}`, answer taken as the account | `{settings}` only (`AccountPatch`), answer `{settings}` merged into the account; the account's name is shown, not edited (the API has no rename) |
| Members' profiles | `permission_profile_id` read as `profile-<name>` | Named through `settings.builtin_profiles` (name → id), else the id (`people.js` `profileName`) |
| Invitations | `invited` flag on the list; name optional | The list has no invitation state, so Admin reads each local member (`GET /users/{id}`, at most 100) for `invitation`; a name is required (`UserCreate`); `POST /users/{id}/invite` answers 202 |
| Accept invitation | `{token, password, name?}` | `{token, password}` (`AcceptInvite` refuses other members); the name field is gone from the page |
| Duplicate template | "… (copy)" in the mock | "Copy of …", the server's default |

Findings for the server (rows for the main session): the users list should carry `invitation` (one read per member
today); the recipient JSON lacks `date_format` and `witness_for`, so no client can send a whole `RecipientSpec` to
`/correct` safely; there is no account rename.

### Send editor (WEB-09)

Spec: `webapp/e2e/editor.spec.mjs`; pure rules in `webapp/tests/editor.test.mjs`. Screenshots at 1440 and 390:
`target/e2e-screens/chromium-editor-*.png`.

- **Templates reopen in the editor.** Templates' row menu has **Edit** (`#/templates/{id}/edit`): the template's
  documents (fetched and opened), its roles in routing order and its fields (by `role_id`) load into the same editor;
  **Save template** compares the editor with the template as last read and sends only the differences, removals first,
  each change with If-Match (`templatesync.js` `templatePlan`, `applyTemplate`). A template's saved document can be
  removed (`DELETE …/documents/{doc}`, taking its fields). "Edit details" (the side panel) stays for name and email.
- **Signing steps with parallel groups** (DocuSign's "Set signing order", `routing.js`). With the order on, each
  recipient has a step; recipients who share a step get the envelope at the same time. The recipients step draws one
  box per step ("Step 2 · 2 sign at the same time", a `group` named by its heading). To put people together: type
  the same number in a card's step box, or drag a card (by its grip) onto another step's box. A card dropped on the
  space between boxes gets a step of its own there. Up/down on a card move it a step: out of a shared step first, to
  a step just before (after) it, else past the neighbouring step; each box has "Move step n earlier/later". Every
  change is one undo step and is announced ("Ben signs at step 2, at the same time as Cleo"). With the order off,
  signers are all step 1 and copies step 2, as before. The routing order sent is the step; a draft or template is
  read back the same way, and the send confirmation names the steps ("Dev → Ana → Ben & Cleo").
- **Marquee selection and snapping guides** (`guides.js`). Dragging on an empty part of a page (mouse or pen; a
  finger scrolls) draws a box that selects every field it touches, Shift adding to the selection; a click there
  clears it. Dragging a field of the selection moves the group as one box; a click on one selects just it. While a
  field or group moves, its edges and centre snap to the page's edges and centre and to other fields' edges and
  centres on that page within 6 screen pixels at any zoom, and a line shows each one it lined up with; resizing snaps
  the moving corner. Holding Alt turns snapping off (the old 4-point grid is gone). Keyboard parity: Ctrl/Cmd+A selects
  the fields of the page in view (not while typing, where it selects the text); Alt+Shift+arrows move the selection
  to the next guide on that side; any keyboard move shows for a moment the guides it lands on.
- **Detect fields** (`detect.js`; DocuSign's and SignNow's auto-place). A button under the field types calls
  `POST …/documents/{doc}/detect-fields` for each document (saving the draft first when a document is new, since
  detection reads the stored file) and draws the suggestions as ghost fields: dashed, in the colour of the signer
  fields are being placed for, each with its cue as the label where the kind alone would not say it. A suggestion on
  a field already placed, past the document's pages, or with unreadable geometry is left out; kinds the palette does
  not place (title, company, a form field's own kind) become text fields labelled with the cue. Click or Enter on a
  ghost accepts it for that signer; its × or Delete dismisses it; the properties panel accepts or dismisses them all.
  Each is one undo step. Templates do not offer it (the API detects on an envelope's documents).
- Found on the way: a save (including autosave) put "placing fields for" back to the first signer; it now keeps
  the one chosen.
