# Design canvas (design of record)

The interactive canvas the owner approved on 2026-11-13 (owner instruction 44, `WEB-17`, `WEB-18`, `CON-17`).
Each file is one artboard of a claude.ai Design canvas, kept here so the design does not depend on that page.
They are reference material, not shipped code: they load the canvas runtime (`support.js`) and Google Fonts,
which the web app never does (it vendors Geist and keeps its strict CSP).

| File | Screen |
| --- | --- |
| `Main.dc.html` | Agreements: quiet sidebar, grouped list, inspector (Recipients, Activity, Insights, Evidence), ⌘K with search by meaning, skeleton, Expiring empty state |
| `Editor.dc.html` | Prepare: docked panels, floating tool bar, pick a tool then click to place, template-match banner, Detect fields, OCR badge, send checks |
| `Signer.dc.html` | Signing, desktop: secure-open loader, guide bar with progress ring, adopt-signature dialog, sealed receipt |
| `SignerPhone.dc.html` | Signing on a phone: bottom bar and bottom sheet |
| `Intelligence.dc.html` | Admin › Document intelligence: per-feature switches, model list |
| `Console.dc.html` | Platform console: health tiles with usual-range bands, anomaly alerts, model service |

Tokens taken from it: root `font-size: clamp(15px, calc(11.5px + .3vw), 18px)` (16 px under 48em); ink `#18181b`,
canvas `#f4f3f0`, muted `#71717a`, hairline `rgba(24,24,27,.06–.08)`; seal red `#c01622` (hover `#a8121d`) for the
one primary action; violet `#6d28d9` on `#f5f3ff` for model suggestions only; status amber `#b45309`, green `#15803d`;
radii 6/8/12/14; easing `cubic-bezier(.16,1,.3,1)` for entrances, `cubic-bezier(.2,.8,.2,1)` for state changes.
