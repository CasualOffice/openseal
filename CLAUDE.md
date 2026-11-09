# CLAUDE.md

The working rules for this repository. [AGENTS.md](AGENTS.md) holds the full contract and applies to every agent.
Sister repos `../opencalc` and `../openslide` (OpenPresent) are the architecture reference: copy from them with provenance, and never modify them. **Don't re-solve what a sister has solved:** before building anything, find OpenCalc's or OpenPresent's solution and its recorded mistakes, start from that, and change only what e-signature needs.

## Owner instructions come first

**[docs/03](docs/03-OWNER-INSTRUCTIONS.md) records everything the owner has instructed. Follow it without deviating.** Record each new instruction there in the same turn. If something seems wrong or conflicts, raise it; do not quietly choose. Within those instructions, make decisions yourself, thinking of the goal and the future, rather than asking.

## Do not repeat these mistakes

**Read [docs/04](docs/04-MISTAKES-AND-RULES.md) before starting work; its rules bind every session.** The ones that cost most, inherited from the sisters:
- Until Phase 1 closes, work only on the PDF and evidence core: bounded PDF reading, incremental writing, field flattening, sealing, audit chain, verification. No UI, no server, no email.
- Biggest remaining work starts first. Independent stages all start at once.
- Every status update gives the phase percentage, from the tracker, merged only. Short, plain language.
- Say "stopped", "done" or "tested" only after checking by running. Read gate output before committing.
- Nothing that can pop up or crash on the owner's desktop.
- Check machine load (`uptime`) before adding a session. Sessions run only `cargo test -p` on what they changed, with `CARGO_BUILD_JOBS=2 RUST_TEST_THREADS=2`; full gates run on CI.
- No new gates, audit rules or repository checks unless the owner asks.
- Decide, record it, carry on. Commit often, keep the disk clear.

## What this is

An **enterprise-grade**, Apache-2.0 electronic-signature platform: the agreement workflow of DocuSign eSignature, with SignNow's editor speed, on **web and desktop**, self-hostable, embeddable, and API-first. Not an MVP or a demo.
**Evidence integrity is the most critical property.** A completed agreement must be provably the document every party saw, signed by whom, when and how, verifiable offline by anyone, for decades. PDF core and evidence come first, then the envelope engine and API, then UI.

## One roadmap, one tracker

- **[docs/06](docs/06-ROADMAP-AND-DELIVERY.md) is the only roadmap. [docs/14](docs/14-EXECUTION-TRACKER.md) is the only tracker.** No parallel plans, TODO files, or lists in conversation.
- **No work without a tracker row.** Read the id space first; ids are never reused.
- **[docs/05](docs/05-PHASES-AND-TASKS.md) defines phases, slices and tasks, and how each opens and closes.** Only the owner closes a phase. Starting early needs a recorded waiver, and exit criteria are never bent to fit what was built.
- **Findings become rows immediately,** including those out of scope.
- **Built is not done.** A phase or slice counts only when every item of its exit gate in docs/06 is met.

## Update every document

**A change is not done until every document it affects is true, in the same commit.** Check:

| If you changed | Update |
| --- | --- |
| Any work's status | [docs/14](docs/14-EXECUTION-TRACKER.md); the phase checkbox in docs/06 if it meets a criterion |
| Feature coverage | [docs/96](docs/96-FEATURE-FIT-GAP.md) status column |
| A threat's control or test | [docs/07](docs/07-SECURITY-THREAT-MODEL.md) |
| A limit or error code | [docs/20](docs/20-ERROR-CODE-REGISTRY.md), [docs/21](docs/21-PARSER-LIMITS.md), docs/07 |
| A crate, or its dependencies | [docs/19](docs/19-WORKSPACE-SCAFFOLD-DESIGN.md) |
| A design decision | [docs/08](docs/08-ADR-REGISTER.md) and the owning design note |
| The data model or state machine | [docs/22](docs/22-DATA-MODEL.md), [docs/24](docs/24-ENVELOPE-LIFECYCLE-AND-ROUTING.md) |
| PDF, sealing, audit | [docs/30](docs/30-PDF-PIPELINE.md), [docs/31](docs/31-SEALING-AND-SIGNATURES.md), [docs/32](docs/32-AUDIT-TRAIL-AND-EVIDENCE.md) |
| The public API or webhooks | [docs/40](docs/40-API-DESIGN.md) |
| A legal or compliance claim | [docs/09](docs/09-LEGAL-AND-COMPLIANCE.md) |
| A new document | [docs/00](docs/00-README.md) |
| Phase or project state | "Current state" in AGENTS.md, status in README.md |

A document stating something the code does not do is a defect: fix the code or add a row. Never quietly lower a promise. **Never claim legal validity, compliance or certification** (ESIGN, eIDAS, Part 11, SOC 2) that has not been established by the process named in docs/09; say "designed to support".

## The cycle

Every task: **design → execute → check → find issues → fix → commit, with tests.**

- **Check means running it,** not re-reading it.
- **Find issues** asks what would have to be true for this to be wrong, then goes and looks.
- **A test counts only if it was seen to fail without the change.** Definition of Done is in docs/05.
- Substantial designs are discussed first. An ADR trigger needs an Accepted ADR.

## Engineering standards

Industry-standard practice applies everywhere, with these specifics.

**Rust**
- Follow the [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/). `cargo fmt` and `cargo clippy -- -D warnings` are clean. No `#[allow]` without a comment saying why.
- `unsafe` is forbidden in `crates/`. Toolchain and MSRV are pinned. Engine crates compile to `wasm32-unknown-unknown`, with no `#[cfg]` forks.
- **Untrusted input never panics.** No `unwrap`, `expect`, indexing or unchecked arithmetic on values from a file or a request. Return a typed error with a stable code from docs/20. Tests may unwrap.
- Errors are typed enums, never strings. Messages carry object numbers, ids and counts, never document content or personal data.
- Public items have doc comments saying what and why. `pub(crate)` by default.
- Pure functions where possible. **Time, randomness and keys are supplied, never sampled** by an engine crate. Same input ⇒ same bytes.
- Layers depend downward only, per docs/19. No new crate without a first consumer.
- **Clean room for copyleft competitors.** Documenso, DocuSeal, OpenSign (OpenSign Labs), LibreSign and Docuseal-derived code are AGPL; LibreOffice is MPL. Take ideas from their documentation and behaviour; never copy or adapt their code. OpenCalc and OpenPresent, ours, are the only code to copy from.
- New dependencies need a reason, a licence that passes `deny.toml`, and an ADR for the engine. **Cryptography is never hand-rolled:** primitives come from the libraries named in ADR-006.

**Security, evidence and privacy** ([docs/07](docs/07-SECURITY-THREAT-MODEL.md))
- Every uploaded file is hostile. Every parser is bounded, has hostile fixtures, and has a fuzz target. PDF JavaScript, launch actions, embedded files and external references are never executed or followed.
- **The audit trail is append-only and hash-chained.** No code path updates or deletes an audit event. Corrections are new events.
- **A sealed document is never modified.** Anything after sealing is an incremental update with its own signature, or a new document.
- Signing keys live behind the `KeyProvider` seam (PKCS#11, cloud KMS, or a file in development only). No private key in code, logs, the database or a container image.
- Personal data (names, emails, IPs, phone numbers, signature images, ID evidence) is classified in docs/07 and never logged in clear. No document text in logs.
- Access is enforced on the server per request and per object, deny-by-default. Hiding a button is never a control.

**Tests**
- Unit tests beside the code; integration in `tests/`; corpus-driven where a fixture can express it. Names describe behaviour. Tests are deterministic, with no network and no sleeps.
- Every bug fix starts with a failing test. Every sealed-PDF test also verifies the output with an independent validator (docs/31 §Verification ladder).

**JavaScript** (`webapp/`): ES modules, no framework or bundler, as OpenCalc and OpenPresent. `textContent` for every user string. Strict CSP. Every verb is a registered command. PDF pages are drawn by vendored pdf.js (ADR-007) in a worker, with scripting disabled.

**Python** (`tools/`): standard library where possible; tools fail non-zero and name the problem.

**SQL**: migrations are forward-only and numbered; every query is parameterized; every table that holds tenant data carries `account_id` and is reached only through the tenancy-scoped repository (docs/22).

**Git**
- [Conventional Commits](https://www.conventionalcommits.org/): `feat(scope):`, `fix(scope):`, `docs:`, `chore:`, citing tracker ids. One coherent change per commit, with the reason in the message.
- Branching (`DEC-11`, owner instruction 5): work lands on `main`, parallel workers use worktree branches the main session verifies and merges. Never force-push `main`. Never skip hooks; enable them with `git config core.hooksPath .githooks`.
- Never commit build output, keys, certificates with private parts, real signed agreements, or personal data.

**The list CI runs** (`.github/workflows/ci.yml`; sessions do not run it). **While the repository is private** (owner instruction 7), GitHub cannot run it; the main session runs `tools/ci-local.sh`, which mirrors it job for job, before every merge to `main`.

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps --locked
cargo check --target wasm32-unknown-unknown --workspace --locked
cargo +1.88.0 check --workspace --locked
cargo deny check bans licenses sources && cargo audit --deny warnings
python3 tools/check-repo.py
python3 -I fixtures/tools/generate.py --check
python3 tools/verify-sealed.py --self-test                 # pyHanko must tell sealed from tampered
python3 tools/verify-sealed.py fixtures/sealed fixtures/tampered   # once Phase 1 writes sealed fixtures
```

## Working in parallel

Run independent work in parallel worktree-isolated sessions rather than serially. A worker gets one job, the files it owns, and its acceptance test. **A worker's report is not evidence:** the main session verifies by running, reverting the fix to see the test go red, then merging. Two workers never touch one invariant. See the `openseal-worker` and `openseal-merge` skills.

## Skills

| Skill | When |
| --- | --- |
| `openseal-task` | Starting any tracked task |
| `openseal-pdf` | Adding or changing anything that reads, writes or signs a PDF |
| `openseal-worker` | Briefing a parallel session |
| `openseal-merge` | Verifying and merging a worker's branch |
| `openseal-docs` | Before committing, to bring every document into line; or to audit them |

Start reading at [docs/00](docs/00-README.md).
