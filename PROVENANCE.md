# Provenance

What was copied from the sister repositories, from where, and what changed (docs/19 §Provenance). OpenPresent lives
in the folder `openslide/`; its commit at the time of copying was `e61277d`.

| Here | From | Changed |
| --- | --- | --- |
| `LICENSE` | OpenPresent `LICENSE` | Nothing |
| `rust-toolchain.toml` | OpenPresent | Provenance comment |
| `deny.toml` | OpenPresent | Advisory ignore comments removed; list empty |
| `Cargo.toml` `[workspace.lints]`, `[profile.release]` | OpenPresent `Cargo.toml` | Added `missing_docs` and clippy lints for panics on untrusted input (`unwrap_used`, `expect_used`, `indexing_slicing`, `arithmetic_side_effects`, `panic`) |
| `.githooks/commit-msg`, `.githooks/pre-commit` | OpenPresent | Nothing |
| `tools/tracker_rows.py`, `tools/check-tracker-shape.py` | OpenPresent (from OpenCalc) | Nothing |
| `tools/check-commits.py` | OpenPresent | Example message |
| `tools/check-crate-deps.py` | OpenPresent | Reserved server crate names |
| `tools/check-repo.py` | OpenPresent | Gate list; XML-walker check replaced by unsafe and `#[allow]` checks; skills' links checked |
| `.github/workflows/ci.yml` | OpenPresent | OOXML jobs and fuzz build removed; `validators` job added |
| `CODE_OF_CONDUCT.md` | OpenPresent | Reporting link |
| `GOVERNANCE.md` | OpenPresent | Roles and protected areas for e-signature |
| `.claude/skills/*` | OpenPresent `openslide-*` skills | Rewritten for OpenSeal |
| `crates/casual-sign-flatten/src/subset.rs` | OpenPresent `crates/casual-slide-render/src/subset.rs` at `e61277d` | Every read and sum checked (no panics on untrusted fonts) |
| `crates/casual-sign-flatten/fonts/` (Liberation Sans, Serif, Mono Regular) | OpenPresent `crates/casual-slide-text/fonts/liberation/` at `e61277d` | Regular faces only; details in that folder's PROVENANCE.md |
| `server/casual-sign-secrets/` (`src/lib.rs`, `tests/secrets.rs`) | OpenCalc `server/casual-calc-secrets/` at `b23c67c` | `Secret` type (redacted `Debug`, zeroized on drop) returned instead of `String`; `code()` giving `CS-KEY-0005`; `OPENSEAL_` prefix; tests moved to `tests/` with a scratch dir under `target/` and a test that a secret never prints (T-2E) |
| `server/casual-sign-server/` (router setup with per-route `DefaultBodyLimit`, in-process `tower::ServiceExt::oneshot` tests) | OpenCalc `server/casual-calc-host/src/main.rs` at `e65e202` | Conventions only, no code lines: axum 0.8 router and body limits, tests through `oneshot`; everything else (auth, problems, command pipeline, ceremony) is new (T-2C) |
| `server/casual-sign-server/tests/common/mod.rs` | This repository's `server/casual-sign-store/tests/common/mod.rs` (T-2B) | Unchanged but for its module list and a note (T-2C) |
| `server/casual-sign-host/src/{apply,jobs,ids}.rs` | This repository's `server/casual-sign-worker/src/{apply,jobs}.rs` (T-2D) | Moved at the integration of 2C and 2D: errors made `HostError`; the projection merged with the server's (every envelope column, recipients upserted and pruned); `RevokeTokens` performed in the transaction instead of queued |
| `server/casual-sign-server/tests/common/mmdb.rs` | This repository's `server/casual-sign-server/src/geo.rs` unit-test database builder (T-2C) | Made a test module of its own for `tests/location.rs` |
| `webapp/commands.js` | OpenPresent `webapp/commands.js` at `e61277d` (OpenCalc's at `b23c67c`) | `data-os-command`; ribbon exclusions dropped; `unregisterPrefix`; `run` passes arguments; `CSS.escape` guarded for Node tests (WEB-01) |
| `webapp/keys.js` | OpenPresent `webapp/editor.keys.js` at `e61277d` | Tables per context (editor, global); plain keys ignored while typing; absent or disabled commands fall through to the browser (WEB-01) |
| `webapp/i18n.js` | OpenCalc `webapp/editor.i18n.js` `t`/`setMessages` at `b23c67c` | Reduced to a message map with `{name}` placeholders filled as text; `applyI18n` for `data-i18n` (WEB-01) |
| `webapp/ui.js` dialogs | OpenPresent `webapp/editor.dialogs.js` at `e61277d` | On the native `<dialog>` element; bodies built from nodes; actions with busy state (WEB-01) |
| `webapp/dom.js` `h()` | OpenPresent `webapp/ribbon.js` `h()` at `e61277d` | Takes attributes, events and children (WEB-01) |
| `webapp/tokens.css` colour structure | OpenPresent `webapp/editor.css` token block at `e61277d` | Renamed `--os-*`; OpenSeal brand red; owner's size scale (WEB-01) |
| `tools/serve-webapp.py` | OpenCalc `webapp/serve.py` idea at `b23c67c` (no-store, identity endpoint) | Rewritten: `/s/{token}` serves sign.html, CSP header, loopback only, quiet log (WEB-01) |
| `webapp/e2e/playwright.config.mjs` | OpenCalc `tests/browser/playwright.config.mjs` at `b23c67c` | Refuse-a-foreign-server check, one worker, no retries; four projects; real-server mode by `OPENSEAL_E2E_BASE_URL` (WEB-01) |
| `webapp/fonts/script/` (Great Vibes, Allura) | This repository's `crates/casual-sign-flatten/fonts/script/` | Copied with their OFL texts, so the typed signature on screen is the face the flattener embeds |
| `webapp/fonts/ui/` (Inter, the UI font) | `@fontsource-variable/inter@5.2.8` from npm (tarball SHA-256 `de400e4154a9cbd8ecdaf99183b39a1277a217d967472bfa8b33af1dafc324a7`), Inter by The Inter Project Authors, OFL-1.1 | `files/inter-latin-wght-normal.woff2` and `files/inter-latin-ext-wght-normal.woff2` renamed with the version, and `LICENSE` as `OFL-1.1-Inter.txt`; unmodified (UX-02) |
| `webapp/fonts/ui/` (Geist and Geist Mono, the UI faces from WEB-17) | `geist@1.3.1` from npm, `dist/fonts/geist-sans/Geist-Variable.woff2` (SHA-256 `28258d0621216948416a859d32487ab6ad1c9effa0d08795698e70be3c917630`) and `dist/fonts/geist-mono/GeistMono-Variable.woff2` (SHA-256 `5bc6413e82be410dc057feccee55160495b999d0fe212b7b6c6499b29b8b1e4a`), Geist by Vercel with basement.studio | Unmodified, renamed with the version; `OFL-1.1-Geist.txt` is the package's `LICENSE.TXT` (SIL OFL 1.1). Owner instruction 44 |
| `console-ui/fonts/` (Geist and Geist Mono, the console UI's faces) | This repository's `webapp/fonts/ui/` (`geist@1.3.1`, SHA-256 as above) | Copied unchanged with `OFL-1.1-Geist.txt`, so the console binary embeds its own fonts (CON-17) |
| `console-ui/dom.js` `h()`, `append()`, `clear()`, `$` | This repository's `webapp/dom.js` | Copied unchanged; `svg()` and `reducedMotion()` added (CON-17) |
| `webapp/vendor/pdfjs/` | `pdfjs-dist@4.10.38` from npm (tarball SHA-256 `1011b38553532d7078c59f26b15a471f8dae00f101b60e2add9b8511737a1ce0`) | `build/pdf.min.mjs`, `build/pdf.worker.min.mjs`, `cmaps/`, `standard_fonts/`, `LICENSE` only; unmodified (ADR-007) |
| `webapp/vendor/lucide/icons/` | `lucide-static@1.62.0` from npm (tarball SHA-256 `386f9080c440d6f5049cefe3456ae8357f7a0c7f76e59670cd1cb83bc7050a44`) | The 93 SVGs the app uses and `LICENSE`, unmodified; `nodes.js` generated from them by `build.py` |
| `site/` header, footer and page-head shape (`tools/sitelib.py`) | OpenCalc `webapp/docs.html` and `index.html` at `b23c67c` | Structure only (brand, nav links, primary action, a `<details>` menu on phones); markup, styles and copy are new (SITE-01) |
| `.github/workflows/pages.yml` | OpenCalc `.github/workflows/pages.yml` at `59742cf` | Same pinned actions; regenerates `site/` with `tools/build-site.py`, checks links, drops `site/_src/`, asserts the pages exist (SITE-01) |
| `tools/serve-site.py` | This repository's `tools/serve-webapp.py` | Serves `site/`, hides `site/_src/` (SITE-01) |
| `site/_src/lucide/` | `lucide-static@1.62.0` from npm (tarball SHA-256 `386f9080c440d6f5049cefe3456ae8357f7a0c7f76e59670cd1cb83bc7050a44`) | The SVGs the website uses beyond the app's set, and `LICENSE`, unmodified; inlined into the pages by `tools/sitelib.py` (SITE-01) |
| `site/assets/tokens.css`, `site/assets/logo.svg`, `logo-dark.svg`, `mark.svg` | This repository's `webapp/tokens.css` and `docs/assets/` | Copied unchanged by `tools/build-site.py` (SITE-01) |
| `crates/casual-sign-pii/src/` (recognisers' patterns, context words, checksums, SSN and NINO invalidation rules, IBAN formats, phone regions and score) | Presidio (MIT, `crates/casual-sign-pii/LICENSE-PRESIDIO`), `presidio-analyzer/presidio_analyzer/predefined_recognizers/` at tag 2.2.364, commit `779dbd286d5ef4d1fbe2514275fb1bce358f2417` (https://github.com/data-privacy-stack/presidio, formerly microsoft/presidio) | Ported from Python to Rust, not copied: look-arounds became checks in code for the linear-time `regex` crate; scores in thousandths; IBAN formats for PT, MU, PS and QA corrected to the SWIFT IBAN registry; Mastercard 2-series added; `tldextract` replaced by a data-free domain check; phone matching by candidate pattern plus `phonenumber` validation with a trunk-prefix rule, as the Rust port has no `PhoneNumberMatcher`; grouped-number tail rule and date-of-birth recogniser are ours (`ML-08`, docs/33 §5.4). Not ported: `src/ids.rs`, `src/vat.rs`, `src/mrz.rs`, `src/coin.rs` and the `ML-08C` functions of `src/checksum.rs` are written from each identifier's published specification (IRS, Federal Reserve, NHS Data Dictionary, ATO, BZSt, INSEE, ICAO Doc 9303, ISO 7064, ISO 9362, 3GPP TS 23.003, BIP 173 and 350); they share only Presidio's entity labels and the context boost above (`ML-08C`) |
