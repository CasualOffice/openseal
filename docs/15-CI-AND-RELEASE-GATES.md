# 15 — CI and release gates

**Status: built and running on GitHub since 2026-11-10** (first run all green at `fd5e8f3`). `ci.yml` jobs: `checks` (fmt, clippy, rustdoc, wasm32, repository gates, hostile and corpus manifest checks), `commit-messages`, `test` (Linux, macOS, Windows), `msrv`, `dependency-policy`, `validators` (pyHanko and EU DSS self-test). The table below is the target; rows not in that list are planned. `tools/ci-local.sh` mirrors `ci.yml` for use before pushing. Adapted from OpenPresent's docs/15. CI on GitHub is

## Jobs on every push to `main` and every pull request

| Job | What | Platforms |
| --- | --- | --- |
| `fmt-clippy` | `cargo fmt --check`; `cargo clippy -D warnings` | Linux |
| `test` | `cargo test --workspace --locked` | Linux, macOS, Windows |
| `wasm` | `cargo check --target wasm32-unknown-unknown -p casual-sign-wasm`; WASM vs native verdict parity over the corpus | Linux |
| `docs` | `cargo doc -D warnings` | Linux |
| `deny` | `cargo deny check` (advisories, licences, bans, sources) | Linux |
| `repo` | `tools/check-repo.py`: tracker ids unique and well-formed, doc references resolve, crate DAG, docs/00 lists every doc | Linux |
| `validators` | `tools/verify-sealed.py`: pyHanko and EU DSS (container) over `fixtures/sealed` and `fixtures/tampered`; expected verdicts in a manifest | Linux |
| `server` | Postgres service container; migrations up from empty; API tests; tenant isolation tests; crash tests (Phase 2) | Linux |
| `e2e` | Compose deployment; Playwright browser run of the slice scenarios, including mobile viewport and axe accessibility checks (slices) | Linux |
| `fuzz-smoke` | Each fuzz target 60 s | Linux |

Only the newest commit on `main` runs: a new push cancels older runs in every workflow (the sisters' rule).

## Scheduled

| Job | Cadence |
| --- | --- |
| Fuzz, 1 hour per target, corpus kept as an artifact | Nightly |
| TSA and OCSP live check against public endpoints (never a merge gate) | Nightly |
| Dependency audit | Daily |

## Flakes

No retries. A flaky test is a P1 row and is fixed or removed with a row, never re-run until green.

## Release gates

A tag (`v*`) builds release artefacts; it never publishes without the gates below passing, and publishing defaults to
a dry run.

| Gate | Evidence |
| --- | --- |
| All CI jobs green on the tagged commit | Workflow run |
| `PV-01`: sealed fixtures shown valid in Adobe Acrobat Reader with the test root trusted, run in a Windows CI container or by hand on a machine that is not the owner's | Screenshots and Acrobat's signature panel export |
| `SEC-REV-01`: external review of ceremony, sealing, keyd (before 1.0) | Report, findings closed |
| `LEG-01`: NOTICE and licence review; `LEG-02`: counsel review of legal claims and default ERSD (before 1.0) | Sign-off rows |
| Images signed (cosign), SBOM attached, provenance attested | Release page |
| Upgrade test from the previous release with real data shapes | Workflow run |
