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

As built (UX-06): Other actions has Download, Print, Assign to someone else (when allowed), Change signature (once
one is adopted), View history, Help, Finish later and Decline. **Language** waits for a second locale (`FG-125`) and
**Session information** and **View certificate** for their rows (`UX-06` returned rows); neither is in the menu yet.

- **Start / Next** flag in the margin moves to the next required field; a progress count ("3 of 7 required").
- **Required** fields have a solid outline and an accessible name ending "required"; optional fields dashed.
- **Adopt signature** dialog: name and initials prefilled and editable; tabs **Style** (typed in one of 4 bundled
  script fonts), **Draw** (pointer and touch, with clear and undo), **Upload** (PNG or JPEG, background removed
  client-side, then re-validated server-side); one "Adopt and sign" button; the adoption applies to later fields
  until changed. As built (UX-06): name and initials adopted together, **2** bundled script fonts so far (Great
  Vibes, Allura; the other two are a returned row), a signed field offers Remove and Change.
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
  agreements; it shows a "Demo mode" banner and is never evidence of anything. The one exception is the website's
  public demo (SITE-04): `tools/build-site.py --publish` copies the app to the site's `app/` with
  `<meta name="openseal-demo" content="static">` in each page, which forces mock mode on any host (`isDemoBuild`);
  only whoever publishes the HTML can add it, never a link. There, sign-in starts filled in with the demo account,
  the mock's signing link is `sign.html?t=…` (relative, as the copy is not at the origin's root), and `sign.html`'s
  root-relative URLs are made relative.
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

**Superseded in part by owner instruction 44 (2026-11-13):** the approved canvas in
[assets/design-canvas](assets/design-canvas/) is the design of record (Geist, warm neutrals, seal red for the one
primary action, violet for model suggestions, a fluid rem root); `WEB-17` rebuilds the screens on it. Where this section
disagrees with the canvas, the canvas holds.

One tokens file, `webapp/tokens.css`; shared components in `webapp/app.css`. Each part of the app has its own
stylesheet loaded after it (UX-02): `shell.css` (top bar, sections, sign-in, verify), `prepare.css` (the editor),
`sign.css` (the signing page), `manage.css` (Home, Agreements, envelope) and `admin.css` (Templates, Reports, Admin).
`app.html` loads app, shell, prepare, manage and admin; `sign.html` app and sign; `verify.html` app and shell.
Messages are split the same way: `strings.en.js` merges `strings/{common,shell,prepare,sign,manage,admin}.en.js`,
and a key lives in exactly one part. Light and dark by `data-theme` or the OS.

| Token family | Values |
| --- | --- |
| Brand | seal red: accent text `#b3141f` (light) / `#ff8a92` (dark); fill `#b3141f` with white text, `#8e0b14` under the pointer (`--os-accent-hover-fill`); logo gradient `#c01622 → #8e0b14`. Focus ring blue, distinct from the accent and from errors |
| Danger | destructive, declined and error: burnt orange, a different hue from the seal red (UX-02, owner instruction 26): text `#ad4609` (light) / `#fb923c` (dark); fill `#ad4609` with white text, `#8c3a06` under the pointer (`--os-danger-fill`, `--os-on-danger`, `--os-danger-hover`). Outlined danger buttons fill on hover; a destructive dialog's confirming button is the filled danger button with an icon, and its consequence is a warning callout. Error toasts and field errors use the fill |
| Selection | a selected row is tinted info blue (`--os-select-soft`), never accent-soft |
| Status badges | icon and word on a 10–12 % tint of the colour: Completed green, Sent / Delivered / Completing blue, Expired amber, Declined danger, Voided and Draft neutral (Voided with its ban icon); neutral badges keep a `--os-border-strong` outline in dark |
| Type | Inter (OFL, `fonts/ui/`, Latin and Latin Extended, variable weight) then the system UI stack; 12 / 14 / 16 / 20 / 24 / 32 px at a 16 px root; body 14 px in the app, 16 px on the signing page and below 760 px; line height 1.5 body, 1.25 headings |
| Root size | the user's default (100 %) below 64em; 93.75 % (15 px at the default) from 64em, the same in every desktop window (UX-02: it followed the viewport before) |
| Space | 4 px grid: 4, 8, 12, 16, 24, 32, 48 |
| Radius | 6, 8, 12 |
| Icons | Lucide (ISC), inlined by `icon(name, {size, label})`: 16 dense, 20 default, 24 toolbars and empty states; stroke 2 (1.75 at 24); `aria-hidden` unless labelled. Aliases: `align-start/end/top/bottom`, `help-circle` |
| Controls | buttons 32 / 36 / 44 px; targets ≥ 24 px (SC 2.5.8) and ≥ 44 px on the signing page and phones (SC 2.5.5), as `max(rem, px)` so a smaller root never shrinks them; row checkboxes are drawn 18 px in a 44 px target; focus ring 2 px, offset 2 px |
| Motion | 150 / 200 / 250 ms, `cubic-bezier(.2,0,0,1)`; all zero under `prefers-reduced-motion: reduce` |
| Recipients | six colours, each ≥ 3:1 against the page as an outline |

Rules: status is never colour alone (badge = icon + word); every list and first-run screen has an empty state
(illustration, one-line title, one sentence, the primary action; illustrations are original line drawings in
`illustrations.js`, `aria-hidden`; error drawings use `.il-danger`); lists and pages show skeletons while loading;
dialogs and toasts enter and leave in 150–200 ms; a sent envelope and a finished signing show the seal stamping in
once; no looping animation except loading shimmer and spinners. The `hidden` attribute always hides
(`[hidden] { display: none !important }`). Menus from `menuButton` open in the top layer (a popover), placed from
their button inside the viewport, above it when there is more room, scrolling when taller; items may include a
separator. `openPanel({ dismissible: false })` is for a secret shown once (only its actions close it);
`toast(…, { scope: "view" })` toasts go when the router calls `clearViewToasts()`. Contrast is measured, not
asserted: `webapp/tests/pure.test.mjs` fails if any text colour falls under 4.5:1 (also each status colour on its
own badge tint, and white on the accent and danger fills), a control edge, focus ring or recipient colour under 3:1,
or the accent and danger colours (and fills, and danger and warning) are less than CIEDE2000 10 apart, in either
theme. `webapp/e2e/visual.spec.mjs` checks menus stay in the viewport at 1440, 1366 and 390, hidden elements are not
shown, the badge colours, the font, checkbox targets, and the panel and toast options.

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
| Templates | `#/templates`, `#/templates/new`, `#/templates/{id}`, `#/templates/{id}/edit` (`templates.js`, `prepare.js` in template mode); `#/templates/{id}/bulk` (`bulk.js`, `UXW-04`: from the row menu's Bulk send) | `GET/POST /api/v1/templates`, `GET/PATCH/DELETE /api/v1/templates/{id}`, the template's documents, roles and fields (`templatesync.js`, WEB-09 and WEB-10 below); using one is a single `POST /api/v1/envelopes` (`templatemodel.js`); bulk send is `POST /api/v1/bulk-sends` (check with `validate_only`, then make), `POST …/{id}/send` repeated with progress until no row is pending, `GET /api/v1/bulk-sends` for earlier batches (`bulkmodel.js`). Sharing (`UXW-06`): pill tabs All, Mine, Shared with me, Favourites (`GET /templates?view=`), a star per row (`PUT`/`DELETE …/favourite`), Share in a side panel (`GET`/`PUT …/shares`, `GET /groups`), built from the tabs, icon button, side panel, field, select, checkbox and the Use panel's person row; the row menu offers what the caller's `access` allows |
| Reports | `#/reports` (`reports.js`, `reportmodel.js`) | `GET /api/v1/envelopes` (up to 1,000; the summaries' `sent_at` and `completed_at` give the median, UX-08), `GET /api/v1/users` for sender names when allowed |
| Admin | `#/admin[?section=…]` (account, users, webhooks, api, …) (`admin.js`, `adminmodel.js`; the older `?tab=` still lands) | `GET/PATCH /api/v1/accounts/me`, `GET/POST /api/v1/users`, `GET/PATCH/DELETE /api/v1/users/{id}`, `POST …/invite`, `GET/POST /api/v1/api-clients`, `DELETE /api/v1/api-clients/{id}`, `GET/POST /api/v1/webhooks`, `DELETE /api/v1/webhooks/{id}`, `GET …/deliveries` (UX-08); `PATCH /webhooks/{id}` (edit, pause, resume), `POST …/test`, `POST …/deliveries/{d}/redeliver` (UXW-31..33, UXW-10); `GET /api/v1/admin-events` (the Audit log page, UXW-09); `settings.workflow_policy.expiry_warning_days` through `PATCH /accounts/me` (RTE-03); Members and roles as pill tabs Users, Groups, Permission profiles (`?section=users\|groups\|profiles`; `GET/POST /api/v1/groups`, `GET/PATCH/DELETE /api/v1/groups/{id}`, `PUT …/members`, `GET/POST /api/v1/permission-profiles`, `GET/PATCH/DELETE /api/v1/permission-profiles/{id}`, UXW-07), built from the tabs, table, row menu, side panel, field, checkbox and confirm dialog of API and webhooks |
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

## As built: shell, sign-in, verify and site (UX-04, 2026-11-12)

The UX-01 audit's package P2: the app's chrome on phones, and what a DocuSign user expects of it.

- **Top bar** (`app.html`, `app.js`, `shell.css`): brand, sections, Start, search, Help (?), Notifications (bell),
  account. The theme and keyboard buttons are gone from the bar; theme is in the account menu, shortcuts under Help.
  Start lists Send an envelope, Use a template, then (after a rule) Verify a signed PDF.
- **Phone drawer** (below 60em): opens under the bar as measured when it opens (so never over the demo banner or the
  bar), with a scrim that closes it on a tap; Escape closes it and returns focus to Menu; focus goes to its first link
  on open; while closed it is `inert` (no link in the tab order), and while open the content under the scrim
  (`#content`) is `inert` (WEB-17: the drawer is modal); opening any other menu, or any navigation, closes it.
- **Search everywhere**: below 60em a search button opens the same `#top-search` as a full-width row under the bar
  (Escape closes it, focus back on the button); `/` focuses it from every screen with the bar (`search.focus`, global),
  not only Agreements. Enter outside Agreements opens Agreements with `?q=`.
- **Navigation clears the screen's leftovers**: `route()` closes the side panel (`closePanel()`) and the view-scoped
  toasts (`clearViewToasts()`). A panel the user has typed into asks first ("Discard your changes?"); Cancel keeps the
  panel and the address. Choosing the section already shown starts it over.
- **Missing page**: an address no route matches shows "This page does not exist" with Go to Home (it showed Home).
- **Account menu**: name and email, Profile and signature, Notification settings, the three themes (the current one
  ticked), Help and shortcuts, About OpenSeal, Sign out. **Profile and signature** (`profile.js`, a side panel): name,
  email (read-only), saved signature and initials adopted with the signer's own component (`signature.js`, its styles
  loaded on demand), email notification choices (completed, declined, viewed) and a password change that needs the
  current password. Its calls are `GET`/`PATCH /users/me`, served (`UXW-37`); a password change ends the user's other
  sessions.
- **Help menu**: Keyboard shortcuts, Verify a signed PDF, About OpenSeal. The **shortcuts panel** lists every table,
  grouped (Everywhere, with ⌘K for the command menu; Send editor; Placing fields, the editor's single-key tools from
  `preparemodel.TOOL_KEYS`, V and S I D N E O T C, which prepare.js dispatches itself on the Fields step), one row per
  action with its keys (Delete or Backspace; Redo's two; four arrows as one ←↑→↓ key; the nine recipient digits as
  1–9), with ⌘ ⌥ ⇧ on a Mac.
- **Notifications**: the bell lists the latest completed, declined, viewed, voided and expired envelopes (newest
  change first, from `GET /envelopes?status=…&sort=updated_at`; no notification store exists), each opening its
  envelope, and View all agreements. A dot and "Notifications, n new" mark changes since it was last opened (a
  per-browser convenience in localStorage).
- **Sign-in** (`signin.js`): a message under each missing field (in that field's `aria-describedby`); a refused
  sign-in is an alert callout above the fields ("Incorrect email or password."); a Show toggle beside the password field
  (`aria-pressed`); "Forgot password?" opens the reset request in the card (`POST /auth/password-reset`, served, `UXW-38`,
  the same answer for any address; the page the emailed link opens is `UXW-38A`); a company sign-in button only
  when the server names an identity provider (`GET /auth/providers`, served and empty until SSO, `UXW-39`); a footer (Verify a signed PDF,
  About OpenSeal); edge to edge below 30em. The demo hint gives only the credentials (the banner says demo).
- **Verify page** (`verify.html`, `verify.js`): the app's bar height and logo, Open OpenSeal on the right, the demo
  banner and `?mock=1` kept on its links in demo mode. Plain copy ("Check who signed a PDF and whether it changed after
  signing"); without the browser verifier it says checking is not available here and to contact the administrator (no
  build command). `verify.html?envelope={id}&document={id}` checks that envelope's current (sealed) document, read with
  the user's session, as if chosen: the envelope page's Verify link (UX-07) hands over this way.
- **Site** (`index.html`, `site.css`, `site.js`): the brand is a link; Sign in in the bar is secondary so Open the app is
  the one primary; four feature tiles (Send and track, Sign anywhere, Verify offline, Self-host and API) and a footer
  (licence, Sign in, Verify); no internal document reference; the app's theme default (light unless chosen), via
  `theme.js`.
- Tests: `tests/shell.test.mjs` (shortcut grouping and Mac symbols, `/` global, the three calls refused at once
  against a server and served by the mock); `e2e/shell.spec.mjs` at 1440 and 390 (drawer Escape, scrim, top, tab
  order, closing on another menu; search at 390 and `/`; panel closed on navigation and the discard question; 404;
  sign-in errors, alert, show password, reset, SSO button; account, help, shortcuts, notifications; profile save;
  verify bar, demo mode and hand-over; site), with screens under `target/e2e-screens/chromium-shell-*`.

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
| A1 | Editor | The pages get 56 % of the width at 1440 and ~690 px of height: app bar, demo banner, step bar, zoom bar and wizard footer stack ~290 px of chrome | H8; owner | P0 | Editor frame `100dvh` without the app bar; one toolbar row; panels 13.5 / 15 rem (now following the window, 13 / 14 to 16.5 / 17.5 rem, WEB-17); pages ≥ 65 % of the width | Fixed |
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

### Tests (WEB-09, WEB-10)

- Node (`cd webapp && npm test`): `tests/editor.test.mjs` (signing steps, snapping guides, marquee helpers,
  suggestions), `tests/web02.test.mjs` (the template, account, member, correction and detection calls against the
  mock in the server's shapes; `templatePlan` and `applyTemplate`). Each new test was seen to fail against the code
  before the change.
- Playwright, mock: `e2e/editor.spec.mjs` (template round trip and document removal, signing steps by number, drag
  and keys with undo and the routing orders saved, order off and on, marquee and group drag, snapping with and
  without Alt, keyboard parity, Detect fields accept/dismiss/undo, no Detect in templates); `send.spec.mjs` and
  `real-stack.spec.mjs` read the step boxes; `manage.spec.mjs` asks an invite for a name and shows the account name
  read-only; `guided-ceremony.spec.mjs` checks the signer's history in the server's dotted types.
- Playwright, Compose stack: `e2e/real-api.spec.mjs` runs api.js in the signed-in page against the server (template
  documents, roles and fields by id with the editor's plan applied, account settings, invitations, a correction by
  PATCH while `/correct` refuses `access_code`, detection) and the editor's template round trip, a parallel step and
  Detect fields through the UI.
- The reduced-motion project matched `guided-ceremony.spec.mjs` as well as `ceremony.spec.mjs`, running its phone
  tests on desktop; its pattern is exact now.

Further findings for the main session: the staff audit view (`envactions.js` `eventLabel`, `envelope.js`'s recipient
timeline) still reads the mock's underscore event names and `event.recipient_id`, while the server answers dotted types
with `event.data.recipient_id`, so on a real server the audit table shows raw types and the timeline misses "opened".

## As built (UX-06, signer ceremony, 2026-11-12)

The signer package of the UX-01 audit (the bar: a DocuSign or SignNow signer switching misses nothing). Observed in
mock mode at 1024, 1280 and 1440 wide and 390×844. Spec: `webapp/e2e/sign-layout.spec.mjs` (its 12 tests seen red:
the three fit-width tests on `e851426`, 98 px of horizontal overflow at each width; the other nine against the
signer files before this change); `guided-ceremony.spec.mjs` follows the radio popover and the signature image in
review.

| # | Problem | Fix | Status |
| --- | --- | --- | --- |
| 1 | Fit width did not fit: the page ran about 98 px under the field list and the view scrolled sideways (the Start flag's 6.5 rem room was in the pages' padding, never in the fit) | `docView` takes `padLeft` as a function read at each layout; the signer answers the pages' padding beyond the usual margin; review, which has no flag, has no room | Fixed |
| 2 | The sender was never named | The consent card says "<Name> (<email>) sent you documents to review and sign", on whose behalf when the account differs, and "Sign by <date>"; the field list shows "From <name> (<email>)" above the message and the deadline; Help names the sender to ask | Fixed in the UI; the view's `sender` and `envelope.expires_at` are the mock's until `NOT_ON_SERVER.disclosure` (`UXW-34`) lands; without them nothing is shown |
| 3 | A placed signature could not be removed or changed | A signed field opens a menu: Remove (`DELETE /s/{token}/fields/{f}`, a new `recipient.field_cleared` event; offered only where the server has it, `NOT_ON_SERVER.clearField`, `UXW-35`) and Change signature (adopt anew, then every field signed with that mark gets the new one, each a new field event); More has Change signature once one is adopted | Fixed in the UI; Remove mock only until `UXW-35` |
| 4 | Initials needed a second adopt step | The dialog asks for full name and initials together, previews both in each style, draws both on two pads, and adopts both (two `POST /s/{token}/adopt`); an upload is the mark being placed only | Fixed |
| 5 | Adopt panel inherited the 18 rem field list (85 px draw pad) | A side panel of 34 rem (30 to 48, resizable), pads 3:1; the field list it covers is hidden while it is open | Fixed |
| 6 | Adopt errors only as toasts; upload a bare file input | One `role="alert"` line under the controls; a drop zone (drop or choose, guidance, the cleaned image shown in it) | Fixed |
| 7 | Only 2 typed styles (this page promises 4) | Not done: two more OFL script faces need a provenance-checked download (and the flattener's copy, docs/30) | Returned row |
| 8 | Arrival landed mid-page | First arrival opens at the top of page 1 with the Start flag beside the first required field; coming back still goes to the next field | Fixed |
| 9 | Phone fit width: label tabs and fixed-size text overflowed small fields | Below 48em only the next field (or the one in use) shows its tab, and field text is sized in container units of the field until it is in use | Partly: DocuSign-style compact markers that expand on Next are a returned row |
| 10 | Radio groups needed a panel and Save | A popover on the field: a click, Space or Enter picks and saves; arrow keys move. A dropdown that takes a typed value keeps its panel | Fixed (radios drawn at their own placements need option placements, docs/22: returned row) |
| 11 | Phone review put Finish above the document | The pages full height; a bottom bar "Review values (n)" (the values as a sheet) and Finish; desktop shows one heading (the panel head is gone) and the adopted mark in the values list | Fixed |
| 12 | Required looked like an error | Required: a strong neutral outline and a red asterisk; optional: a dashed neutral outline; red outlines only for an invalid value; the in-field placeholder hides while the tab shows; the field list's icons are neutral | Fixed |
| 13 | Finish looked disabled but acted | Full contrast: an outlined secondary until every required field is done, then the filled primary; `aria-disabled` and its reason kept | Fixed |
| 14 | Consent had no full disclosure and no visible alternative | "Read the full disclosure" opens the account's text by version (`GET /s/{token}/disclosure`, offered only where the server has it); "Other actions" opens More | Fixed in the UI; the text is the mock's until `UXW-34` |
| 15 | History printed raw types, times without a zone | Every audit type the server can send has words; an unknown type is left out; times carry their zone | Fixed |
| 16 | Finish later left stale progress | The bar's progress is cleared on every closing screen; "This envelope expires on <date>" when it does | Fixed |
| 17 | Done page: Verify named not linked, no Print, brand copy | A link to `/verify.html`, a Print button, "The completed documents are sealed…" | Fixed |
| 18 | Print had an external-link icon and opened a tab unannounced | A printer icon and "Print (opens the PDF)" | Fixed |

Also: `playwright.config.mjs` runs `sign-layout.spec.mjs` with the signer specs; `docview.js` (shared) gained the
`padLeft` function form, additive.

## As built: manage screens (UX-07, 2026-11-12)

The UX-01 package P5 (Home, Agreements, envelope page), after DocuSign's Manage and envelope pages. Files:
`envelope.js`, `dashboard.js`, `home.js`, `envactions.js`, `dom.js`, `managemodel.js` (the pure rules: action
hierarchy per state, the Agreements address, "expiring soon", CSV), `manage.css`, `strings/manage.en.js`.

### Envelope page

- **One primary and one secondary action per state**, everything else in a grouped **More** menu with the
  destructive group last (`managemodel.js` `envelopeActions`):

  | State | Primary | Secondary | More |
  | --- | --- | --- | --- |
  | Draft | Edit draft | — | Copy, Save as template · Delete draft |
  | Sent, delivered | Correct | Resend | Download current PDF, Copy, Save as template, History · Void |
  | Completed | Download signed PDF | Certificate | Copy, Save as template, History |
  | Declined, voided, expired | Copy and resend | Download (the document as it ended, `version=current`) | Certificate (only where the server serves it, `NOT_ON_SERVER.certificateEnded`, `UXW-30`), Save as template, History · Delete |

  Below 47.5em the primary is full width with the secondary and More beside each other under it.
- **Why it ended**, under the title: who declined and their reason, the void reason, or when it expired, and that
  Copy and resend starts again.
- **Summary card**, two columns: Envelope ID (monospace, Copy), created, sent, ended, sender, documents (each opens
  the Documents tab at that file) | subject, message, expiry, reminders, signing order (in order or at once) and
  authentication (who needs an access code).
- **Evidence card** for every sent envelope: what the audit trail is, the chain head with Copy and a line on what it
  proves; for a completed one, "Verify in OpenSeal Verify" (`verify.html`, a new tab) and how to check the downloaded
  PDF there. Handing the sealed file to Verify directly needs `verify.js` to accept a hand-off (not in this package).
- **Void** is one dialog: the reason, the consequence ("cannot be undone; recipients get your reason") and a filled
  danger button (`envactions.js` `voidEnvelopes`, also used for bulk void with the count in the title).

### Correct panel

The side panel corrects, for each recipient who has not acted: name, email, access code and signing order (one
`PATCH …/recipients/{r}` each, which keeps members the API does not show), or removes them; it adds recipients
(name, email, role, order) and sets the expiry (end of the chosen day) and the reminders. Adds, removes, expiry and
reminders go first as one `POST /correct` change list (`add_recipient`, `remove_recipient`, `set_expiry`,
`set_reminders`), all or none. At least one person who signs or approves must remain. Recipients whose name, email or
code changed and who are still sent it get a new invitation; added ones are invited by routing. Fields and documents
of an envelope in flight are the editor-based Correct, `UXW-19`.

### Agreements

- **Density:** dates in lists are one line ("Today, 5:28 PM", "Yesterday, …", "Nov 12", the year only when it
  differs; `dom.js` `fmtShortDate`) with the full time in a tooltip; the "Created" sub-line is gone (it is on the
  envelope page); the table has a fixed layout and set column widths; subject, recipients and status line truncate
  with an ellipsis; the Sender column shows only when a loaded envelope was sent by someone else. Rows are 64 px or
  less at 1440.
- **Search in the address:** typing in the top search replaces the hash with `#/agreements?folder=…&q=…` (no history
  entry, no remount), so reload, Back and a shared link keep it; rail links keep the search; the subtitle says
  `All envelopes matching "offer"`.
- **Expiring soon** quick view (sent and delivered, `expires_at` within 7 days, filtered in the page until the API
  filters by expiry, `UXW-03`); Home's card links to it, so the count and the list agree.
- **Row menu** grouped with separators: Open (was "Open and history") or Edit | Correct, Resend, Download … |
  Copy, Save as template, History | Void, Delete. Ended envelopes get Copy and resend and Download.
- **Bulk bar** is sticky under the top bar (a fixed bottom bar on phones): Resend, Download (signed PDF when
  completed, else as it stands), Export CSV (formula-safe cells), Void and Delete in the danger colour on the dark bar.
- **New envelope** left the page head: the top bar's Start is the one way in (the empty state keeps its button).
- **Phones (below 47.5em):** a folder select with counts replaces the rail; filters sit behind a Filters button with a
  count; checkboxes appear after Select.
- **History panel** (44rem) is a timeline: the event as a plain verb ("Signed", "Opened", "Reminder sent"), who and
  when under it, the event hash in a Details disclosure with Copy. The envelope page's audit table keeps the audit
  trail's own labels.
- Row checkboxes sit in a 2rem hit area (WCAG 2.2 SC 2.5.8).

### Home

Five counters (Declined or expired, Waiting for others, Expiring soon, Drafts, Completed). The drop zone is one slim
line. Recent envelopes are the six last changed: subject, "To: …", status badge and line, and the last change; the
whole row opens it. "Needs your signature" waits for the Inbox (`UXW-01`).

### Tests

- Node: `tests/manage.test.mjs` (action hierarchy per state, row-menu groups, the address, expiring soon, CSV cells,
  the short date); the CSV formula guard was mutated and seen red.
- Playwright (`e2e/manage.spec.mjs`, chromium): the four acceptance tests (Download on a declined envelope, a primary
  action on it, the search surviving a reload, rows of 64 px or less at 1440) each seen red with the screen files
  reverted to `main` and green after; grouped row menu and one void dialog, sticky bulk bar with CSV export, bulk
  void and delete; Expiring soon card and view agree; summary, evidence card and History timeline; Correct adds,
  removes and sets expiry and reminders; phones (folder select, Filters, Select, full-width primary); screenshots at
  1440 and 390. `send.spec.mjs`, `real-stack.spec.mjs` and `signin-dashboard.spec.mjs` follow the new way in (Start)
  and Void's place in More.

## As built (UX-08, 2026-11-12): Templates, Reports, Admin

Package P6 of the UX-01 audit. The bar: a DocuSign customer finds Admin, Reports and template use where they
expect them, and nothing silently wrong.

**Admin** (`admin.js`, pure rules in `adminmodel.js`) is a section rail after DocuSign eSignature Admin, replacing the
three tabs. Groups and sections (`SECTIONS`): **Account** (Account: settings and branding; Signing and sending;
Electronic disclosure; Retention), **Users and groups** (Users; Groups; Permission profiles), **Integrations**
(Webhooks; API clients), **Security** (Single sign-on and domains; Seal and timestamp; Audit log). Below 37.5em the
rail becomes a select with the same groups. A section whose endpoints the server does not have yet is a row marked
**Soon**, never hidden; opened, it says what it will hold and that it is not on this server yet. Each slots in as its
endpoint lands (rows in docs/14). `#/admin?section=<id>`; the older `?tab=` links still land.

- **Users**: one primary **Add user** panel with a **Send an invitation email** switch, on by default (`POST /users`
  with `invite: true`); switched off, a password of at least 12 characters is required and set there. Search (name
  or email) and Permission profile and Status filters above the table, with a count. **Edit** stays in the row;
  **Resend invitation** and **Remove** move to the row's menu (Remove is the danger item; nobody removes themselves).
  On phones Edit is in the menu too, so a card has one menu button.
- **Webhooks** (docs/40 §4): the subscriptions (endpoint, events, Active or Off), **New webhook** in a side panel (an
  https:// public address, events grouped by subject, three envelope events checked by default, and the **names** of
  the operator's signing secrets: the secret never passes through the API, so there is nothing to show once; a
  refused address, `CS-API-0013`, is said beside the field), and the selected subscription's latest deliveries
  (event, Delivered/Failed/Pending, attempts, HTTP status) with **Deliver again** on a failed one, **Send test
  event**, and Pause, Resume and Turn off in the row menu. Pause, resume, test and redelivery are served
  (UXW-31, -32, -33); on a server a test event or redelivery shows Pending until the worker has tried it (the mock
  delivers at once).
  Deliveries have no time column: the server's delivery has no timestamp yet (row in docs/14).
- **API clients**: a **For developers** card with the Account ID and API base URL, each with Copy; Expires with an
  "In N days" badge within 30 days and Expired after; **Show revoked (n)**, off by default; Revoke in the row menu.
  The New API client panel groups all ten server scopes (Envelopes, Templates, Administration) with a one-line
  description each. Created and Last used columns appear as soon as the server's client carries `created_at` and
  `last_used_at` (row in docs/14). The one-time key or secret opens in a side panel with no close button that
  Escape and navigating away leave open (`openPanel({dismissible: false})`, UX-02); only **I have copied it** closes it.
- **Account**: Settings and Branding cards. Branding pairs a colour picker with the hex field, checks white text on
  the colour against WCAG 4.5:1 (`contrastRatio`), and previews the email header and the signing page's bar live.
  At phone width the cards' definition lists stack, so no word breaks mid-word.

**Reports** (`reports.js`, `reportmodel.js`): every tile says what it rests on ("of 6 envelopes loaded", "of 5
sent", "from 4 completed"), and "of the newest 1,000" when the account has more than a report loads. The median
uses every completed envelope's `sent_at` and `completed_at` from the list (the server's summary carries both;
the mock now does too), falling back to reading the newest 50 one by one, and saying so, on a server without them.
Period presets plus a **Custom range** (From, To, by creation date), a **Sender** filter (all, me, each member), the
period note on the same row, each status row a link to `#/agreements?status=…`, and a CSV of id, subject, status,
sender, created, sent, completed, expires and last change. Lede: "Envelopes your account sent, by status and time to
complete." Recipient and usage reports wait for REP-01.

**Template use** (`templates.js`, `templatemodel.js`): inputs are labelled **Name** and **Email**, the role named in
their description; both suggest the account's contacts (`GET /contacts`) and complete each other. **Add recipient**
adds a copy or another signer after every role (an added signer's fields are placed in the editor, so Send asks for
Edit before sending). The field count and a key of the roles' colours sit above the pages, and each role's fields are
outlined on the preview in its colour (`pdfPreview({decorate})`, an additive hook). Templates list: **Use** keeps its
word on phones.

Tests: Node `tests/ux08.test.mjs` (sections and old links, scopes, event groups and secret names, expiry, member
filters, contrast, the median from summaries, custom range, CSV columns, added recipients). Playwright
`e2e/admin.spec.mjs` at 1440 and 390 px: the rail and a waiting section; a webhook created, a refused address, a test
event's delivery row, a failed delivery delivered again, pause; the secret surviving Escape and navigation, the
expiry badge, revoke and Show revoked; Add user with and without an invitation, search and filters, Remove from the
menu; branding contrast and preview; Reports sample sizes, custom range, sender, a status row to Agreements; template
use with role labels, outlines, an added copy recipient sent. The webhook, secret and Reports tests fail on the code
before UX-08; the Escape check was also seen to fail with the panel made dismissible. `manage.spec.mjs`,
`web02.spec.mjs` and `visual.spec.mjs` follow the rail, the single Add user panel and the row menus.

## As built (UX-05, 2026-11-13): the prepare editor and template authoring

**Toolbar** (`prepare.js`, `prepare.css`): Back and Next, then Send or Save template, are one group at the bar's end
that never shrinks or wraps; the title and the step labels give way first. The bar compacts by the editor's own width
(container queries in `rem`, because `em` inside a container query is the container's 13 px text): under 100 rem the
save state is a dot (words for assistive technology and as a tooltip), under 90 rem Save and Back are icons, under
80 rem the steps not open lose their names. On phones the bar is two rows on purpose: title and actions, then steps.
The audit's wrap reproduced at 1440 px in the system font (the web font blocked); the spec checks 1366, 1440 and 1536
in both fonts, for envelopes and templates.

**Placing fields**: a click on a field type arms it, a ghost of its default size follows the pointer, and the next
click on a page places the field centred there; a double click keeps the type armed; Escape (`field.deselect`) or a
second click disarms (commands `field.arm-*`, `field.disarm`). Enter or Space on a type still places on the page in
view, now in the visible part of the page across as well as down. Touch screens get touch help text.

**Field kinds**: the palette places the 16 kinds the ceremony fills or shows (`api.js` `FIELD_TYPES_READY`), in three
groups: Signing (signature, initials, date signed), About the recipient (name, first name, last name, email, company,
title; first and last name cut from the name as docs/24 §5, `S1-03`), Recipient
enters (text, number, checkbox, radio group, dropdown, attachment, note). Text, company, title, number and choices
start required. **Properties** are sections: General (recipient, required, read only or locked (`S1-04`) with the
sender's value or a checkbox checked when sent, a note's text, data label, tooltip, placeholder), Options (one per line,
repeats and blanks dropped, a dropdown's typed answer), Formatting (font, size, alignment, hide on the document, several
lines for text: a text area for the signer, `S1-01`) and Validation
(email, phone, ZIP, SSN, number with range, at most N characters, pattern, with a message). Members travel by their
wire names on create and as a JSON merge on change (`null` removes one); reopening reads them back. A choice with no
options is a send problem. A field's accessible name starts with the label it shows. Required is a corner flag; focus
is an outline outside the selection ring; a field narrower than its words shows its icon only, and smaller still
loses its handle (container queries on the field).

**Recipients**: each row offers Needs to sign, Approver, Viewer and Receives a copy, and In-person signer where staff
can host one (`client.available("hostInPerson")`: the mock only until `UXW-36`). A row is one line (type and step,
name, email, move and remove) with **More options**: a labelled access code and the emailed code. Name and email
suggest contacts (`GET /contacts`); choosing one fills the other box. Approvers and viewers act in their turn and take
no fields; with signing order off everyone who acts is step 1 and copies come after. Not built: a per-recipient
private message and language (no API member yet; row proposed).

**Pages and documents**: the thumbnails are pinned at the foot of the fields panel, always in view, grouped by
document (`thumbnails({byDocument})`); several documents get a name band above each one's first page. Next on the
documents step waits for a PDF.

**Review**: a signer with no fields is a warning with **Place fields**; **Preview as** opens the fields step with
that recipient's fields standing out and the others faded, under a bar that ends it. The send confirmation follows the
routing (`people.js` `sendSummary`): with steps, only the first step is emailed now, then "A → B & C"; approvers and
viewers review in their turn; copies last. Suggestions neither accepted nor dismissed stop Send, and the detection
toast closes when the step is left. Template mode: the last step is **Review and save**, and the documents step has
the template lede and **Name this template**.

**Detection**: the server's detector sits a field on its line (`detect.rs`: bottom on the line) and `detect.js` keeps
that geometry; the mock had suggested fields below its own PDF's lines and now matches the server.

**Phones**: the editor opens at 1 CSS px a point (fit width drew 11 pt text at about 6 px) and pans; one bottom bar
holds the page indicator, Field settings (an icon) and Add field.

Tests: `e2e/prepare-layout.spec.mjs` (19 tests; 1440 and 390 px screenshots): the toolbar at three widths in two
fonts, click-to-place within 2 pt, every new kind configured and round-tripped through the mock, Next waiting for a
PDF, template Review and save, the review warning, preview and order-aware confirmation, undecided suggestions, the
pages panel, the phone editor, recipients at 1440 and 390. Each change's tests were seen to fail on the code before
it (the toolbar at 1440 px in the system font; the toolbar at 1366 and 1536 and the template bar passed before and
stay as guards). Node
`tests/editor.test.mjs`: the palette's kinds and groups, validation presets, options, and a detected field's bottom
on the mock PDF's line. Specs that placed fields by clicking a palette button now press Enter on it (the keyboard path
that keeps their meaning); `empty-states.spec.mjs` opens Recipients from the step bar.

Not done in UX-05 (rows proposed): a context menu on fields from the command registry; resize dots outside the field;
schedule send (waits on its server row); the field members in template mode (`templatesync.js` sends required and
label only); a recipient's type change after the draft is saved (the API's recipient patch has no type).

## As built: design foundation (WEB-17, 2026-11-13)

The foundation every screen of the approved canvas ([assets/design-canvas](assets/design-canvas/), owner instruction
44) is rebuilt on. It supersedes the token values, root size, motion and shell described in "As built (WEB-01)"
§Design system, §Root size and "As built: shell" above; their rules (status never colour alone, `hidden` always
hides, menus in the top layer, contrast measured) still hold. The screens themselves move to the canvas in later
`WEB-17` lanes (Agreements, Prepare, signing, Admin, console).

**Tokens** (`webapp/tokens.css`). Every `--os-*` name screens used is kept; the values are the canvas's. Light:
window `#f4f3f0` (`--os-canvas`), surfaces white (`--os-bg`, `--os-raised`), row hover `#fafaf9` (`--os-surface`),
subtle fills `#f4f3f0` (`--os-surface-2`), ink `#18181b`, body secondary `#52525b` (`--os-text-2`, new), muted
`#6b6b74` (the canvas's `#71717a` measures 4.36:1 on the window colour), hairlines `rgba(24,24,27,.06)` and `.08`
(`--os-hairline`, `--os-border`), control edges `#8b8b94` (≥ 3:1). Seal red `#c01622`, `#a8121d` under the
pointer, for the one primary action; the focus ring is the canvas's 2 px seal red. Destructive is a burgundy rose
`#9d174d` (CIEDE2000 17.8 from the seal red). Status pairs exactly as the canvas's pills (`--os-st-you`, `-wait`,
`-done`, `-draft` with `-soft` tints: red, amber `#b45309`/`#fdf6ec`, green `#15803d`/`#eff8f2`, zinc); the generic
`--os-warning` `#a54b08` and `--os-success` `#14763a` are one step deeper so a 12 % tint badge passes 4.5:1. Model
suggestions only: `--os-ml` `#6d28d9`, `--os-ml-soft` `#f5f3ff`, `--os-ml-edge`, `--os-ml-mark`. Personal data:
`--os-pii*` amber on cream. Radii 6 / 7 (controls) / 8 / 12 / 14; shadows are a hairline ring plus a soft drop
(`--os-shadow`, `-sm`, `-md`, `-pop` = the command menu's). Easing `--os-ease-out` `cubic-bezier(.16,1,.3,1)`
(entrances), `--os-ease-state` `(.2,.8,.2,1)` (state changes), `--os-ease-spring` `(.34,1.56,.64,1)` (knobs, placed
fields, the seal). Controls 28 / 32 / 44 px. Dark is the same structure in zinc (window `#0f0f11`, card `#18181b`,
text `#f4f4f5`, muted `#a1a1aa`, accent text `#ff7a83`, fills keep `#c01622`); the explicit and OS-preference dark
blocks are identical (tested). Type is Geist and Geist Mono 1.3.1 (OFL, `fonts/ui/`, variable); Inter is gone.

**Root size** (`app.css`): `html { font-size: clamp(15px, calc(11.5px + .3vw), 18px) }`, 16 px under 48em: 15 px at
1280, 16 at 1440, about 17 at 1920, 18 from 2560. Everything is rem. `pure.test.mjs` pins this rule (it replaced the
WEB-06 test that forbade a viewport term, by instruction 44). **No control label wraps:** buttons, tabs, pills, menu
items, nav links and the jump button are `white-space: nowrap`, never shrink below their content, and ellipsize a
long label where their box is constrained.

**Motion** (`app.css`, shared): keyframes and classes `os-rise` (fade and 6 px up; every screen enters with it),
`os-pop` (scale .98 and fade; menus, dialogs, the command menu), `os-fade`, `os-slide`, `os-shimmer` / `.os-skel`
(the warm skeleton), `os-sweep` and `os-scan` (scanning lines), `os-spin`, `os-float` (empty-state illustrations),
`os-ink` (a clip-path reveal for signatures), `os-seal` (spring pop), `os-drop-in`, `os-indet` (indeterminate bar),
`os-stagger` (list rows 40 ms apart). All are off under `prefers-reduced-motion: reduce`.

**Shell** (`app.html`, `app.js`, `shell.css`; the Main artboard). A 15.5rem sidebar on the window colour: the
workspace row (seal mark, workspace name, product; a menu with, for a person in more than one workspace, "Switch
workspace" and each workspace grouped by organization, the current one checked (`ORG-04`, command
`workspace.switch`, which reloads on Home), then workspace settings for admins, verify, about),
"Search or jump to… ⌘K" (`#palette-btn`), **New agreement** (`#start-btn`, the Start menu's send / from a template /
verify, `N` hint), Home, Agreements, Templates, Reports, an empty labelled group `#nav-views` for the Agreements
screen's saved views, then at the bottom the demo tag, Admin (admins only) and the account row (`#account-btn`:
avatar and name; the menu as before, with the theme) beside notifications (`#bell-btn`) and help (`#help-btn`).
The active section is a white pill with a hairline and a soft shadow. The routed screen renders in a white content
card inset 0.5rem from the window's top, right and bottom, as wide as the space left (no width cap), scrolling inside
the card (`#main`). Frame routes (the editor) and chromeless routes (sign-in) take the whole window. Below 60em the
sidebar is the drawer (scrim, Escape, inert while closed, starts under the bar) and a top row shows Menu, the logo,
search, notifications and the account; the same bell and account controls are moved there, not copied. A screen
that sets `ctx.onSearch` gets `#top-search` in a row at the top of the card (Agreements today, until its lane
replaces it). `ctx.setNavCount(nav, n)` puts the canvas's red count beside a section; the shell does not ask the
server for it. A route switch never blanks the card: the new view is added hidden, the old one stays inert until the
new one has content (or its mount ends, or 400 ms), then it is removed, the card scrolls to the top and the new view
rises in.

**Command menu** (`ui/palette.js`). ⌘K / Ctrl+K from anywhere (also while typing; again to close), the sidebar's
button, the phone's search button and `/`. A modal `<dialog>` (40rem, 6rem from the top, the canvas's radius and
shadow) with the WAI-ARIA combobox + listbox pattern: the input owns `aria-activedescendant`; ↑ ↓ wrap, Home and End
jump, Enter runs, Escape closes, the pointer sets the active option, focus returns to the opener. Sections come from
providers, `registerPaletteProvider({id, title, icon, order, titleTone?, note?, sync?, search(query, signal)})`
(also `ctx.registerPaletteProvider`), returning items `{id, label, sub?, snippet?: [{text, mark?}], hint?,
hintTone?, icon?, kbd?, run()}`; a slow section shows a skeleton row until it answers, typing pauses 150 ms before
asking, and a newer query aborts the older one. Built in: **Actions** (new agreement, use a template, verify, go to
each section, theme, shortcuts, and the verbs screens register; with a query, "Search agreements for “…”" first) and
**Agreements** (titles matching, from the envelope list; envelopes waiting for the user's signature first, "Needs
your signature", where the Inbox call exists). Empty: "No results for “…”". The Agreements lane adds "Matches by
meaning" (`api.searchByMeaning`, violet title).

**Primitives** (`ui/`, exported from `ui/index.js`). Buttons: `primary` (seal red, once per screen), `strong` (the
inspector's ink button), `secondary` (white with a hairline ring), `subtle` (warm fill), `ghost`, `ml` (violet),
`danger` and `danger-fill`; a `kbd` inside a button is styled. `tabs({variant: "underline" | "pill"})` with an optional
per-tab `badge`. `statusPill(text, {tone, dot, ic})` and `statusBadge(status)` in the canvas's pill shape;
`avatarStack(names)`; `switchButton(label, {checked, onChange, tone})` (`role="switch"`, spring knob, busy and rolled
back when `onChange` rejects) beside the checkbox `toggle`; `skeletonRows` (the canvas's agreement-row shape),
`skeletonLines`, `skeletonBlock`; `emptyState` with illustrations redrawn in the canvas's style (ellipse shadow,
hairline paper, one coloured accent, confetti dots, floating) — the existing set plus `calendar` (nothing expiring),
`fields` / `page-field` (no fields yet), `chart` (all clear) and `scanning` (reading the document); `suggestion(s,
{onAccept, onDismiss})` (violet edge, label, confidence with "· check this" under 75 %, value, page, Save to details /
Dismiss, then the decided state), `mlHeading()`, the `.os-pii` callout; `progressRing({value, total, tone})`.
Toasts are an ink pill; dialogs take the command menu's radius, shadow and soft blurred scrim. Icons default to a
1.5 stroke, and `icons.js` adds the canvas's own glyphs (`os-agreements`, `os-grid`, `os-bars`, `os-shield`,
`os-updown`, `os-search`, `os-sparkle`, …).

**Model layer** (`webapp/ml.js`, `WEB-18`; the contract the screen lanes consume). `api.js` adds `getMlSettings`,
`patchMlSettings`, `requestAnalysis`, `getAnalysis`, `listSuggestions(env, {kind, state})`, `acceptSuggestion`,
`dismissSuggestion` (docs/33 §6) and `searchByMeaning(q, {signal})` (planned, docs/33 §6, `WEB-19`); `request` takes
an abort `signal`. `mlStatus()` resolves once per session to `{available, features: {ocr, template_matching,
extraction, personal_data}, notInPlan, notInstalled, known}`: a 404, `CS-ML-0011` or a refused call means
unavailable, and **every ML surface hides**; a non-admin's 403 on the settings means "not known here" and each surface
hides on its own call's 404 or `CS-ML-0011` (`isUnavailable(err)`). The suggestion store per envelope
(`loadSuggestions`, `suggestions`, `openCount`, `acceptSuggestion`, `dismissSuggestion`, `onSuggestions`) changes
state at once, rolls back when the server refuses, and tells listeners; `isLowConfidence(s)` is under 0.75 and
`percent(s)` reads it. The mock serves all of it with all four features on and the canvas's examples (an offer
letter's start date, salary, notice period and personal data; a vendor agreement's payment terms and a 64 %
governing law; the draft "Lease renewal 2027" matching the template "MSA v4" at 96 % with its page 3 (or last) read
by OCR; analysis `running` for about 2 s after it is requested); `sessionStorage["openseal.mock.ml"] = "off"` answers
404 as the real server does today, `"no-plan"` answers `403 CS-ML-0011`.

**Tests.** `tests/ml.test.mjs` (pure decisions, the mock endpoints, the optimistic store; seen red with the rollback
removed), `tests/pure.test.mjs` (contrast and the dark blocks on the new values; the fluid root; Geist bundled with
its licence).
## As built: Admin, Document intelligence, Templates, Reports, Profile on the canvas (WEB-17, WEB-18, 2026-11-13)

Spec: `docs/assets/design-canvas/Intelligence.dc.html` (and Main for the list language).

- **Admin nav** (`admin.js`, `adminmodel.js` `NAV`, `routeFrom`, `navHref`): a secondary nav inside the content card in
  the canvas's order: Organization, Members and roles, Security and sign-in, Signing and seals, Branding, Document
  intelligence (with the violet sparkle), Retention, API and webhooks, Audit log; "Back to agreements" and
  "{workspace} · Admin" above. The current page is raised on white. Pages whose endpoints the server lacks are marked
  "Soon" and open an illustrated page naming what they will hold (one card per part), never a dead link. Every old
  `?section=`/`?tab=` id lands on the page that now holds it (`account` → Organization, `seal` → Signing and seals,
  `api`/`webhooks` → the tabs of API and webhooks). Each page has the canvas head (h1, lede, actions right). Below
  48em the nav is a "Section" select. Each nav page is a command (`admin.go.*`), so ⌘K reaches it.
- **API and webhooks**: one page, pill tabs (`tabs({variant: "pill"})`, arrow keys); the URL follows the tab
  (`history.replaceState`) so a reload or link opens the same one. Organization and Branding are separate pages over
  `/accounts/me`. Members says groups and custom profiles are not on this server yet. A webhook's row menu has Edit
  (UXW-10): the address and events prefilled, only what changed sent to `PATCH /webhooks/{id}` (a new address is
  checked again, `CS-API-0013` said in place); its signing secrets are named, not editable.
- **Organization** also holds "Warn signers before expiry (days)" (RTE-03): 0 to 365, 0 for none, shown as "No
  warning" or "n days before". The server takes `settings.workflow_policy` only whole, so the page reads the
  account's policy again on save and sends it (its disclosure kept) or the engine's defaults with the new days
  (`adminmodel.js` `expiryWarningPatch`).
- **Audit log** (UXW-09, `GET /admin-events`): the workspace's admin log, newest first of the events loaded (pages of
  1,000, five at a time, then "Load more"), with When, Action, Made by (a member's or API client's name, or "The
  server") and the changed keys; a search box and Action and Made by filters over the loaded events (the route takes
  no filters, UXW-44); Details opens a side panel with the targets, each change before and after, and the event's
  hash and previous hash. Head actions: Export CSV (the server's own CSV, every page, one header) and Verify the log
  (`verify=full`; a broken chain, `CS-DB-0014`, is said as such). Commands `adminlog.export`, `adminlog.verify`.
- **Document intelligence** (`intelmodel.js` pure and tested, `adminintel.js` view): "n of 5 on" chip; the three
  promises; one card per feature with model name, description and a violet spring switch bound to
  `PATCH /account/settings/ml`: it changes at once, the count follows, a polite live region says "… is on/off", and a
  refusal puts it back with an error toast (switchButton). After a change `mlStatus({refresh})` updates the session.
  **Detect fields on upload has no server setting** (docs/33 §6 merges OCR suggestions into detect-fields), so its
  switch follows Read scanned pages, is disabled, and says so. OCR script chips (installed / installing with stripes /
  ask your operator), the personal-data language note, "Models on this server" (name, status, licence · size ·
  purpose, short SHA-256 as the server reports it, "pending" while installing), and the footer line. States: loading
  (page-shaped skeleton), **not installed on this server** (404 today, or `installed: false`: an illustrated empty
  state naming the operator; no switch, count or model list), **not in your plan** (`403 CS-ML-0011`: a note, every
  switch off and disabled; a partial `not_in_plan` disables only those cards with the reason), other refusals in place.
  The page reads two additive, read-only members of the settings answer: `models: [{id, name, profile, status:
  ready|installing|failed, licence, bytes, sha256}]` and `ocr_packs: [{script, state: installed|installing|missing}]`
  (the mock serves the canvas's values); without them the models card is hidden and `ocr_scripts` count as installed.
  Deviation from the canvas: an off card is not drawn at 72 % opacity (its muted text would fall under 4.5:1); it is
  told apart by its surface and grey glyph.
- **Templates**: rows with the canvas's page thumbnail, name over subject with ellipsis. **Reports**: a skeleton shaped
  like the four tiles and the chart (no layout shift), tiles and chart card with hairline rings. **Profile**: an
  identity row (avatar, name, email) and signature rows as cards (notifications stay checkboxes: the foundation `toggle` hides its input under the track, so a click on the input is intercepted).
- **Tests**: `tests/intel.test.mjs` (page states, plan, detect follows OCR, PATCH key guard, sizes, hashes, model
  rows, script chips), `tests/ux08.test.mjs` (nav order, old links, hrefs round-trip); `e2e/admin.spec.mjs` adds the
  nav (order, no wrapped label, waiting parts, old links), Document intelligence (count, switches, scripts, models,
  save and reload, refused change rolls back, not installed hides every ML control, not in plan), and the pill tabs.

## As built: electronic disclosure in Admin (ERSD-01, UXW-12, 2026-11-13)

The Signing and seals page draws the part the server now has, **Electronic disclosure** (`adminersd.js`; pure rules
`ersdProblem`, `ersdPreview`, `nextErsdVersion`, `shortHash` in `adminmodel.js`; `NAV` marks it `live`), above the
illustrated "not on this server yet" block that still holds Signing and sending and Seal and timestamp. The page is no
longer marked "Soon" and has its own lede. Built from existing components only: the account card (title, Publish new
version, lede), a definition list (version, language, published, short SHA-256), a preview of the text (280
characters, cut at a word), and the published versions, newest first. **Publish new version** opens a side panel with
the current text to start from and its language tag; the server's rules (not blank, no NUL, at most 100,000 bytes, a
language tag) are said in place before the request, and publishing is one `POST /ersd-versions` that also requires
the new version, so envelopes already sent ask for consent to it. The panel says published versions are kept
unchanged. With no disclosure required the card says so. The mock serves `/ersd-versions` as the server and its
signer view follows the published version. Who accepted which version is `ERSD-02`.

## As built: sign-in, accept invite and Verify on the approved canvas (WEB-18 lane E, 2026-11-13)

The signed-out pages and the Verify page rebuilt on the design of record (`docs/assets/design-canvas`: Main's seal
mark and buttons, Signer's secure-open loader and sealed receipt). Styles are in `webapp/auth.css` (linked from
`app.html` and `verify.html`); colours use the `--os-*` token names, and the few the tokens lack (seal gradients, the
receipt frame, the warm glow) are `--auth-*` in that file, with dark values.

- **Model and view apart.** `authmodel.js` (pure) holds every rule: sign-in field errors (missing, and a malformed
  email), the reset address, the invitation checklist (length at least 12, both fields match) and what stops the form,
  the invitation token's shape, which company sign-in links are usable (same-origin paths only; `//host` and `/\host`
  refused), and which refusal gets "Incorrect email or password.". `authview.js` draws the shared pieces: the layout
  with seal mark and receipt-framed card, a text field and a password field with a reveal toggle (named "Show
  password", state in `aria-pressed`), field errors in `aria-describedby`, one alert, the green-seal done state, and a
  restrained side panel (a drawn receipt and three plain lines) shown only at 64em and wider.
- **Sign-in** (`signin.js`): errors appear on submit and are checked again as the person types (they clear the moment
  the field is fixed); busy submit; a refused sign-in is one alert above the fields; Forgot password and the reset
  request in the same card; company sign-in only when the server names a provider; footer links. Verbs carry
  `data-os-command` (`auth.sign-in`, `auth.forgot-password`, `auth.toggle-password`, `auth.send-reset`,
  `auth.back-to-sign-in`).
- **Accept invite** (`acceptinvite.js`): the rules show as a checklist that ticks while typing (polite, not an alert);
  one `role="alert"` line names what stops the form or the server's refusal; reveal on both fields; success is the
  green seal with Go to sign in. The token still leaves the address bar at once.
- **Verify** (`verify.js` flow, `verifyview.js` render, `verifyreport.js` rules): an illustrated drop zone; a line under
  it that is a skeleton while the WebAssembly verifier loads, then "Verifier ready" or "not available on this server";
  a scanning screen (the canvas loader: a page with a scan line, and the three stages the page really runs: read the
  file, run the verifier, read the attached audit trail, each ticked only when it has finished; shown at least 600 ms
  unless reduced motion); then the sealed receipt: green seal only for the verifier's `valid`, red for invalid or
  unreadable, amber for not confirmed or unsigned, with file, size, the verifier's tally of signatures, revisions,
  trusted certificates and the check time. Under it, each signature with all seven checks exactly as the verifier
  reports them (passed, failed, not run, with its reason and code), changes after signing, the audit trail (links
  checked; hashes stated as not recomputed here) and the document. Pure presentation helpers: `stepStates`,
  `verdictTone`, `checkTone`, `tally`, `fileSize`.
- Tests: `tests/auth.test.mjs`, `tests/verify.test.mjs`; `e2e/signin-dashboard.spec.mjs` adds inline email validation,
  the side panel at 1440 and not at 390, the invitation checklist, a link with no token, the verifier's ready line and
  scanning stage, the green receipt with seven checks, and the red receipt with its failing check. The hand-over test
  in `e2e/shell.spec.mjs` now asserts that no build tool is named anywhere on the page (it failed whenever the verifier
  was installed, because it asserted on an element that is then absent).
## As built: signing ceremony on the approved canvas (WEB-18, lane C, 2026-11-13)

The signer page rebuilt on `docs/assets/design-canvas/Signer.dc.html` and `SignerPhone.dc.html`. Files: `sign.html`,
`sign.js`, `sign.css`, `signature.js`, `signfields.js`, `strings/sign.en.js`.

- **Model and view.** What the page shows is computed by pure functions in `signfields.js` (`guideState`, `nextAction`,
  `ringDash`, `loaderSteps`, `pageCounts`, `pageTotal`, `filledKinds`, `firstName`, `orgMark`, `askLine`, `dateField`,
  `phoneSegments`), unit-tested in `webapp/tests/signfields.test.mjs`; `sign.js` renders from them.
- **Secure-open loader.** A seal with an orbiting ring over the page and three steps ticked only when they happen: the
  signing session opened (`POST /s/{token}/session` answered), the document bytes arrived, the first page was drawn
  (its canvas painted, or after 4 s). The canvas's "Checking the document is unchanged since it was sent" step is
  **not** shown: the page compares no hash. Its title is "Opening your document" (not "securely": the page cannot
  verify that).
- **Header.** The organisation's two-letter mark, the subject, "<sender> at <org> asked you to sign" (only from the
  view's `sender`; nothing when absent), a neutral "Secured by OpenSeal" chip, Decline (ghost) and More (⋯). Phones:
  the compact header with a two-segment progress bar (fields done, finished).
- **Document.** A 6 rem thumbnail rail (current page ringed, a red count of required fields left per page), the pages
  at fit width capped at 48 rem and centred, a 6 rem right margin at 80 em and wider, zoom in a small pill bottom
  right. Required fields are tinted light red, the next one ringed; filled values in ink with a blue hairline; a placed
  mark inks in left to right; the date-signed field says "Fills in when you sign" until a mark is placed. The yellow
  Start flag of WEB-06 is gone (the ring and the guide bar replace it). The field list moved to More → All fields (a
  side panel; a bottom sheet capped at 55 dvh on phones); the sender's message is also on the consent card.
- **Nothing covers a field.** The document view keeps 7 rem of scroll padding under the floating guide bar; Next
  centres the field in the part of the view the bar does not cover, and a field that is focused or becomes next is
  scrolled clear of the bar and the zoom pill (`keepClear`). Label tabs show on hover and focus only (the next field is
  ringed instead), below the field when another field is above, and not at all when both would cover one. Style tiles
  stack the signature over the initials and shrink the sample until it fits (never cut off). On phones the page pill is
  hidden, only a field being typed into grows, and the page is fitted to the width again once everything is filled.
- **Guide bar.** Dark, floating, bottom centre: a progress ring "n/N", the next action ("Sign the agreement", "Initial
  page 1", "Fill in Job title", …), "n required fields left", and Start / Next; once nothing required is left, Finish
  (red, pulsing). Phones: the white bottom action bar. `#guide-progress` keeps the "n of N required" status for
  assistive technology. Finish still goes through review (ADR-020).
- **Adopt dialog.** A modal (`openDialog`: focus trap, Escape, focus returned) with Type / Draw / Upload as a segmented
  tablist (arrow keys), name and initials inputs, two style tiles in Great Vibes and Allura (the faces the flattener
  embeds; the canvas shows three, a third would need a font the PDF does not have), a hinted draw pad on a dashed
  baseline, the drop zone, the consent line, Cancel / Adopt and sign. Phones: a bottom sheet with a drag handle (drag
  down a quarter of its height to dismiss); Adopt and sign full width above Cancel; full-screen drawing kept.
- **Receipt and states.** A tinted frame around a white card: the seal pops in, "Signed. Thank you, <first name>.",
  what happens next, when they signed (with its zone) and the kinds of field filled, the Verify page link, Download a
  copy and Print. The document fingerprint row is not shown: the ceremony view carries none (a row when the API adds
  it). Declined, closed (voided), expired, reassigned, saved for later, not found and error use the same card with a
  quieter disc.
- **Commands.** Every verb is registered in `commands.js` as `signer.*` (`next`, `finish`, `fields`, `download`,
  `print`, `change-signature`, `reassign`, `history`, `help`, `finish-later`, `decline`); the guide bar, the header and
  More run them.
- **Not matched to the canvas.** Two style tiles, not three (fonts); no fingerprint (API); the loader's integrity step
  (not verified); the review step stays between Finish and the receipt (ADR-020); zoom controls kept (a small pill);
  the thumbnail count is 12 px, not the canvas's 9 px (the 12 px floor). Geist is declared in `sign.css` under the
  page's own family name until the foundation serves it.
- **Tests.** `ceremony`, `guided-ceremony`, `decline`, `sign-layout` and `a11y-sign` specs updated to the new UI with
  their behavioural assertions kept (Finish hidden until ready instead of `aria-disabled`; the field list through More;
  the page centred instead of the Start flag; the receipt's facts and Verify link instead of the "What happens next"
  list); `decline.spec` scopes the sender's "Reason given" to the callout. It matched twice because the recipient row
  repeated it; the row no longer does, and the spec checks it is said once (integration fix).

## As built: Agreements, the inspector, the envelope page and Home on the approved canvas (WEB-17 / WEB-18 lane A, 2026-11-13)

Spec: `docs/assets/design-canvas/Main.dc.html`. Replaces the UX-07 folder rail and table.

- **Agreements** (`dashboard.js`) fills the content card edge to edge. Header: pill tabs All, Needs me, Waiting,
  Completed, Drafts, Expiring (Needs me only where the server has the Inbox, `NOT_ON_SERVER.inbox`); Search (a row
  under the header, the server's `q`, kept in the address); Filter (sender, last change); Display (sort within groups,
  Select agreements for bulk, Export CSV); New agreement. Narrower lists keep every tab: a container query drops
  Filter and Display to icons, then New agreement. Older addresses (`?status=`, `?folder=declined|voided|expired|action`)
  still open their filter, named above the list.
- **List**: every agreement up to 1000 (`GET /envelopes`, 200 a page) plus the Inbox, grouped Needs your signature,
  Waiting on others, Completed, Drafts, Declined/voided/expired, with sticky group headers (dot, label, count). Rows
  are the canvas grid: page thumbnail with a status-coloured signature line, name and sub line (ellipsis), recipient
  avatars, signing progress segments and n/m, status pill in words, the violet suggestion chip, relative time with
  tabular numerals. A WAI-ARIA grid: roving focus, ↑/↓/Home/End move the selection, Enter opens, Space ticks while
  selecting; click selects, double-click opens. Skeleton rows in the same grid while loading; empty states for a
  first run (New agreement, Use a template), a search, filters, and each view (Expiring: calendar-check, "Nothing is
  about to expire", See all agreements); error state with retry.
- **Inspector** (`inspector.js`, 23.5rem): status pill, name, sub line, primary action by state (Sign now through
  `sign-link`, Remind <first name> through `resend`, Download, Continue editing, Copy and resend), Open, and More (the
  UX-07 row actions). Underline tabs: Recipients (signing order with numbered / ✓ badges), Activity (latest audit events,
  Full history opens the History panel), Insights, Evidence. Docked from 75rem, a slide-over below (a dialog with a
  scrim, Escape closes and returns focus to the row), a full page on phones.
- **Insights** exist only when `ml.js` reports extraction or personal-data detection; a 404 (the real server today)
  hides the tab, the row chip, the envelope page's card and the ⌘K section. Cards for `entity` suggestions (Save to
  details / Dismiss, "check this" under 75 %) and one amber card for personal data whose "Review for redaction" lists
  each item to add to the redaction proposal (docs/33 §6) or dismiss. Optimistic through `ml.js`, rolled back with an
  error toast when refused. While a draft's analysis is queued or running, the canvas's "Reading the document" state.
- **Evidence** says only what the code checks: `auditLinks` (managemodel.js) checks the API trail's seq, prev and head
  links in the page and the card says "Audit trail linked … Verify recomputes every hash from the sealed PDF" (never
  "verified" or "unchanged"); the chain head; a document fingerprint only when the server returns
  `delivered_sha256` / `upload_sha256` (the mock returns none, so none shows); Download certificate and Verify for a
  completed agreement. There is no "evidence package" download because the app has none.
- **Views** (`agreementparts.renderNavViews`): the sidebar's `#nav-views` with dots and live counts, filled by
  Agreements and Home; on Agreements they switch in place and keep the search in their links. The shell draws them
  once, without counts, on whatever screen comes first (`app.js` `drawNavViews`), never over what a screen drew.
- **Matches by meaning** (`meaning.js`): a ⌘K provider over `api.searchByMeaning`, registered by Agreements, the
  envelope page and Home only when extraction is available; snippets drawn as text nodes and `<mark>`.
- **Envelope page** (`envelope.js`): header in the inspector's language (pill and status line, name, sent date and
  pages, the UX-07 actions), then summary, documents (PDF preview) and the audit trail, with the inspector's
  Recipients (detailed: steps, Resend, demo link), Insights and Evidence as cards beside them.
- **Home** (`home.js`): greeting, five counts (each opens its view), Needs your attention (waiting for my signature,
  expiring, ended without everyone signing), Quick actions (upload PDFs, also a drop target; start from a template;
  verify a sealed PDF), Recent activity, Recent templates; skeletons and empty states.
- **Pure rules** (`managemodel.js`): `VIEWS`, `GROUPS`, `viewFrom`, `groupOf`, `toneOf`, `inView`, `viewCounts`,
  `groupRows`, `flatIds`, `moveSelection`, `signingProgress`, `primaryVerb`, `relativeWhen`, `recipientBadge`,
  `piiSummary`, `auditLinks`, `documentFingerprint`; shared view parts in `agreementparts.js`.
- **Tests**: `tests/manage.test.mjs` (one per rule above); `e2e/manage.spec.mjs` (grid keyboard and inspector, Needs
  me and Sign now, Expiring empty, Insights accept/dismiss and PII review, rollback on a refused suggestion, ML
  unavailable hides every ML surface, ⌘K by meaning, the reading state, the More menu, bulk, phone inspector page,
  plus the UX-07 behaviours moved to the new UI), `e2e/signin-dashboard.spec.mjs`, `e2e/empty-states.spec.mjs`.

## As built: the prepare editor on the approved canvas (WEB-17 lane B, 2026-11-13)

The send editor and template authoring rebuilt on `docs/assets/design-canvas/Editor.dc.html` (owner instruction 44),
one frame for both. **Pattern**: `preparemodel.js` decides (pure, Node-tested: the library and tool bar with their
keys, step done marks, when Continue is held and why, the Ready-to-send checks, the recipients list, the template
offer and how a template lands on a draft, OCR pages, the personal-data summary); `prepareview.js` builds the canvas's
pieces from data and callbacks (step control, recipient row, library row, tool, hint chip, suggestion bar, template
banner and applied chip, loading page, checks, personal-data card, assign list, OCR badges); `prepare.js` wires state,
commands and the server, as before.

- **Top bar**: back, "Agreements /" breadcrumb, title, the save state (a green dot and "Saved", amber "Unsaved
  changes", a spinner while saving; the time is its tooltip) with a save icon; the segmented step control, done steps
  ticked; **Preview as signer** (`editor.preview`) and one primary **Continue**. On the fields step Continue is held
  (`aria-disabled`, the canvas's pink) while a signer has no field or a suggestion is undecided, the existing send
  rules; a press says why in a popover beside it and picks the signer who still needs a field. Steps stay clickable,
  so Review is reachable (it still lists a signer without fields). The Back button is gone (the canvas has none).
- **Left panel**: Recipients (colour chip with the number, name, "Needs to sign · step n", field count; the radio group
  "Placing fields for"; + opens the recipients step and adds one), **Detect fields** in violet ("Reading the page…"
  with a spinner while it runs), the library (the canvas's eight kinds with keys S I D N E O T C, then "More fields"),
  and Pages pinned at the foot with an **OCR** tag on pages the analysis read by OCR (`ocr_pages`).
- **Centre**: pages on the dotted canvas with the canvas's shadow; the dark floating tool bar (Select V, six kinds,
  Detect, zoom as "105%" over the fit/preset select, undo, redo). Pick a tool (click or key), the page takes a crosshair
  and the dark chip says "Click on the page to place Signature for Jordan · Esc". Placed fields are tinted in the
  recipient's colour with the label over the first name; the selected one has the canvas's blue ring and corner
  handles (bottom-right resizes). Drag, resize, snapping, marquee and every keyboard command are unchanged.
- **Detect fields** (`detect.js`, the server's detector): dashed ghosts in the current signer's colour with the cue, a ✓
  and a × each, a violet sweep over the pages while it runs, and the floating "N suggested fields for Jordan · Accept
  all · Dismiss all" bar (it replaces the old toast). A suggestion whose source is a scan's text (`source: "ocr"`) says
  "from scanned text"; the server's detector has no such source today, so the note never shows yet. Autosave waits while
  suggestions are undecided: a save reloads the draft and empties undo, which took back the undo of an accept or a
  dismiss (found by the detect spec).
- **Template match (ML)**: the open `template` suggestion with the best score, offered only when its template places
  at least one field on this draft: "Looks like your “MSA v4” template · 96% match · apply its 3 roles and 4 fields".
  **Apply template** maps the template's roles onto the draft's people in routing order (extra roles become new
  recipients named after the role) and its fields onto the same document and page (`applyTemplatePlan`, the
  `envelopeFromTemplate` path for a draft that already has documents), as one undo step, and records the suggestion
  accepted (rolled back with an error toast if refused); the dark chip "Applied … Undo" undoes it and offers it again.
  **Not now** hides it for this visit without dismissing it on the server.
- **Right panel**: a selected field shows the canvas's head (chip, kind, Delete), Assigned to (a radio list), Behaviour
  (Required as a switch, Tooltip), the existing General, Options, Formatting and Validation sections, and Position (X,
  Y, W, H in points, editable). With nothing selected: "No fields yet" (Detect fields, Place a signature), else
  "Ready to send?" (each signer's signature field, suggestions waiting, scanned pages read by OCR) and, when the model
  found personal data, the amber card by label and count (never the values). The canvas's "Review for redaction" is not
  shown: there is no redaction feature to open.
- **Loading**: a saved draft or template opens on the canvas's page skeleton with "Preparing pages…" until its first
  page paints; never a blank stage.
- **ML hidden when unavailable**: everything model-made (banner, OCR tags and check, personal-data card, the fine print)
  reads `ml.js`; with the mock's `openseal.mock.ml = off` (the real server's 404 today) none of it appears.
- **Phones**: the bar is two rows (title and Continue, then the steps); the tool bar becomes the bottom bar with the page
  indicator, Field settings and Add field; the library and properties are bottom sheets as before.
- **Panel widths** (integration fix): the canvas's 16.5 / 17.5 rem panels left the pages 59 % of a 1280 window and 63 %
  of a 1440 one, under the 65 % rule (owner instruction 22). Their default widths now follow the window: 13 / 14 rem at
  1280 px and below, the canvas's widths from 1700 px up, half-rem steps between (14.5 / 15.5 rem at 1440). Resizing,
  the rail and memory are unchanged. The canvas hides the dock header while a panel is open, which also hid the
  collapse control; **Hide Fields** now sits beside Pages. The right panel collapses from its handle (Enter) and
  folds itself below 75em.
- **ML found missing late**: a suggestions call that answers 404 or `CS-ML-0011` marks ML unavailable for the session
  (`ml.js`), so the fine print hides even when the status was read before the server stopped answering.

Tests: `tests/editor.test.mjs` (10 new: library and keys, key to tool, step marks, Continue held, checks, recipients
list, template offer, template plan, OCR pages, personal data). `e2e/editor.spec.mjs` adds three canvas specs
(single-key tools, hint and held Continue; template match apply, undo and the model's results; nothing ML with the
model service absent); `prepare-layout.spec.mjs` and `editor.spec.mjs` were updated to the new bar, library, checks and
suggestion bar with their behavioural assertions kept.

## As built: organization admin, first cut (ORG-06, 2026-11-13)

`#/org` (`webapp/org.js`; pure rules in `orgmodel.js`: `ORG_NAV`, `orgRouteFrom`, `orgHref`, `orgCan`, counts,
`auditRow`, `auditAll`, `changeText`, `filterAudit`), for a person who holds an organization role (`GET /organizations/me` read once after
sign-in): "Organization settings" in the workspace menu and in ⌘K. There is no canvas artboard for it, so it is built
from the Admin screen's parts only, with no new CSS: the secondary nav inside the content card ("Back to
agreements", "{organization} · Organization", five pages) and the "Section" select below 48em, the page head (h1,
lede, actions right), the Reports counters, the account card's definition list, `os-table--cards` row tables, side
panels for every form, and the danger confirmation for archive and remove.

- **Overview**: active workspaces (archived count below), administrators (owners below), the organization's name,
  your role, created; Rename organization (`org.settings.update`). Plan and usage, identity, policy, retention and
  branding are named as coming.
- **Workspaces**: name, status, whether you are a member or are here (from `GET /auth/workspaces`); New workspace,
  Join (owners and admins, with a permission profile; the panel says the join is logged in both logs), Archive.
- **Users**: the session workspace's members with their organization role, and a line saying the directory across
  workspaces is not on this server yet (`ORG-33`).
- **Administrators**: name, email, role, since; owners add a member as admin or owner, change a role, remove, or step
  down; the last owner's refusal (`CS-ORG-0008`) is a toast with its code.
- **Audit log**: newest first, a sentence per known action with its changed keys, who acted (the server for a system
  event), what it was about; filter, Verify chain (`verify=full`). The server pages oldest first, so the screen
  reads every page (`auditAll`, at most 50 of 1,000, said on screen when cut) before showing newest first; a
  newest-first route is `ORG-35`.

Buttons follow the role (`orgCan`); the server decides every request. The mock serves `/organizations/me…` as
`api/org.rs`, with a chained log. Tests: `tests/org.test.mjs`; `e2e/org.spec.mjs` (mock, 1440 and 390 px, axe on
each page). Left: the real-stack run, `ORG-33` to `ORG-36`.
