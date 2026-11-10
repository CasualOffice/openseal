#!/bin/sh
# The CI list (.github/workflows/ci.yml), run locally by the main session at each merge
# while the repository is private and GitHub Actions cannot run (owner instruction 7, W-2).
# Mirrors every job; Linux-only jobs run here on macOS, and the validators in Docker.
# Exits non-zero at the first failing job and names it.
set -eu
cd "$(dirname "$0")/.."
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-4}" RUST_TEST_THREADS="${RUST_TEST_THREADS:-4}"
step() { printf '\n== %s\n' "$1"; }

step "checks: fmt";        cargo fmt --all -- --check
step "checks: clippy";     cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
step "checks: rustdoc";    RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps --locked -q
step "checks: wasm32";     cargo check --target wasm32-unknown-unknown --workspace --exclude casual-sign-store --exclude casual-sign-keyd --exclude casual-sign-secrets --locked -q   # hosts under server/ are native only
step "checks: repository"; python3 tools/check-repo.py
step "checks: fixtures";   python3 -I fixtures/tools/generate.py --check && python3 -I fixtures/corpus/fetch.py --check
step "commit messages";    python3 tools/check-commits.py --range "$(git rev-list --max-parents=0 HEAD | tail -1)..HEAD"
step "test";               cargo test --workspace --all-features --locked --no-fail-fast -q
step "msrv 1.88";          cargo +1.88.0 check --workspace --locked -q
step "dependency policy";  cargo deny check bans licenses sources && cargo audit --deny warnings
step "validators"
VENV=target/tools-venv
[ -x "$VENV/bin/python" ] || { ~/.local/bin/uv venv -q -p 3.12 "$VENV" && ~/.local/bin/uv pip install -q -p "$VENV/bin/python" "pyhanko==0.38.1" cryptography; }
docker build -q -t openseal-eu-dss tools/eu-dss >/dev/null
"$VENV/bin/python" -I tools/verify-sealed.py --self-test --dss openseal-eu-dss
step "wasm parity";       tools/wasm-parity.sh   # WASM-01: native and WASM byte-identical over the corpus
printf '\nci-local: every job passed\n'
