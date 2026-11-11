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
`1`–`9` switch recipient, `?` shortcut list.

## What we measure

Time to send for first-time senders; signer completion time on mobile; error rate on required fields; screen-reader
completion (`UXR-01`, `A11Y-01`).

## As built (WEB-01, 2026-11-11)

Slice 1's web app, in `webapp/`: plain ES modules, no framework or bundler (ADR-018), served as static files.

| Screen | Where | Calls |
| --- | --- | --- |
| Sign-in | `app.html#/signin` (`signin.js`) | `POST /api/v1/auth/login`, `GET /api/v1/auth/session`, `POST /api/v1/auth/logout` |
| Agreements | `app.html#/agreements[?status=]` (`dashboard.js`) | `GET /api/v1/envelopes?status=&cursor=&limit=`; search filters the loaded rows (the API's `q`, `WEB-04`, is in `api.js` for the screen to use) |
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
| Agreements | Folders (Inbox, Sent, Drafts, Deleted) and quick views; list with status and last change; row actions (Correct, Void, Resend, Download, History…); search and filters | Folder tree, status/type/date filters, sort, bulk select (move, archive), row actions panel | Folder rail with counts (all, drafts; action required, waiting, completed; declined, voided, expired); dense table (select, subject with recipients, status pill, last change, row menu: open, edit, resend, void, download, certificate); bulk bar (resend, download, void); the top search filters subject and recipients |
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
| Templates | `#/templates`, `#/templates/new`, `#/templates/{id}` (`templates.js`, `prepare.js` in template mode) | `GET/POST /api/v1/templates`, `GET/PATCH /api/v1/templates/{id}`; slice-3 design `POST /templates/{id}/documents`, `GET …/documents/{doc}/content`, `POST /templates/{id}/fields` (404 or 405 today: roles kept, the editor says so); using one is a single `POST /api/v1/envelopes` (`templatemodel.js`) |
| Reports | `#/reports` (`reports.js`, `reportmodel.js`) | `GET /api/v1/envelopes` (up to 1,000) and `GET …/{id}` for completed ones |
| Admin | `#/admin[?tab=api]` (`admin.js`) | `GET/POST /api/v1/users`, `PATCH/DELETE /api/v1/users/{id}`, `GET/POST /api/v1/api-clients`, `DELETE /api/v1/api-clients/{id}` |
| Verify | `verify.html` (`verify.js`, `verifyreport.js`, `trail.js`) | none: casual-sign-wasm's `verify()` in the page; `audit-trail.json` read by pdf.js |

- **Calls added outside api.js** are in `api-extra.js`. **Mock mode** serves templates (with the slice-3 design;
  `sessionStorage["openseal.mock.no-template-docs"]="1"` turns it off), users and API clients, and is remembered for the
  tab once `?mock=1` is seen on loopback (`?mock=0` forgets). Without mock or a server on loopback the app and signing
  page say "No OpenSeal server is running here".
- **Verifier build**: `tools/build-webapp-wasm.sh` builds casual-sign-wasm as `tools/wasm-parity.sh` ships it and
  copies it to `webapp/vendor/openseal-wasm/` (build output, not committed); without it Verify says so.
- **CSP**: `verify.html` alone adds `'wasm-unsafe-eval'` to `script-src` (meta tag and `tools/serve-webapp.py`
  header), which a browser requires to compile WebAssembly; no JavaScript eval is allowed anywhere.
- **Components** (`webapp/ui/`, one library): buttons and icon buttons with tooltips, fields, selects, checkboxes,
  radios, switches, tabs, menu buttons, modal, drawer, toasts, pills, cards, tables, step bar, empty states,
  skeletons, avatars and the PDF preview; screens import from `ui/index.js`.
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
