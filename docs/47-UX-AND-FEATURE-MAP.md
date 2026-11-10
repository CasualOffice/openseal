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
| Agreements | `app.html#/agreements[?status=]` (`dashboard.js`) | `GET /api/v1/envelopes?status=&cursor=&limit=`; search filters the loaded rows (no text query in the API yet) |
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
`Permissions-Policy: geolocation=(self), camera=(), microphone=()`. `tools/serve-webapp.py` sends the same headers.

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

### Not yet

Home counters, Templates, Reports, Admin, Verify; a field list view as an alternative to the page; fields enlarging
on focus on phones; pinch zoom; page thumbnails; auto-place by text; preview as recipient; the flattened review step
of ADR-020 (the review dialog lists values; it does not show engine-flattened pages yet); two of the four script
fonts; languages beyond English.
