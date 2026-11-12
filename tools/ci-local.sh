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
step "checks: wasm32";     cargo check --target wasm32-unknown-unknown --workspace --exclude casual-sign-store --exclude casual-sign-keyd --exclude casual-sign-modeld --exclude casual-sign-secrets --exclude casual-sign-host --exclude casual-sign-worker --exclude casual-sign-server --locked -q   # hosts under server/ are native only
step "checks: repository"; python3 tools/check-repo.py
# One command per line: under `set -e`, a failure on the left of `&&` does not stop the
# script (docs/04 rule 31).
step "checks: fixtures";   python3 -I fixtures/tools/generate.py --check
                           python3 -I fixtures/corpus/fetch.py --check
step "commit messages";    python3 tools/check-commits.py --range "$(git rev-list --max-parents=0 HEAD | tail -1)..HEAD"
step "test";               cargo test --workspace --all-features --locked --no-fail-fast -q
step "msrv 1.94";          cargo +1.94.0 check --workspace --locked -q
step "dependency policy";  cargo deny check bans licenses sources
                           cargo audit --deny warnings
step "validators"
VENV=target/tools-venv
[ -x "$VENV/bin/python" ] || { ~/.local/bin/uv venv -q -p 3.12 "$VENV" && ~/.local/bin/uv pip install -q -p "$VENV/bin/python" "pyhanko==0.38.1" cryptography; }
docker build -q -t openseal-eu-dss tools/eu-dss >/dev/null
"$VENV/bin/python" -I tools/verify-sealed.py --self-test --dss openseal-eu-dss
step "keyd softhsm";      OPENSEAL_VERIFY_PYTHON="$PWD/$VENV/bin/python" cargo test -q -p casual-sign-keyd --test softhsm --locked
step "store db and server db"   # Postgres 17 in Docker, as ci.yml's store-db and server-db jobs (S3 tests skip without an endpoint)
[ -x target/sqlx-cli/bin/sqlx ] || cargo install -q sqlx-cli --version 0.9.0 --no-default-features --features postgres,rustls --locked --root target/sqlx-cli
docker rm -f openseal-ci-pg >/dev/null 2>&1 || true
docker run -d --rm --name openseal-ci-pg -e POSTGRES_PASSWORD=ci-only -p 127.0.0.1:55433:5432 postgres:17-alpine >/dev/null
# The container stops however this step ends; one check per line (docs/04 rule 31).
trap 'docker stop openseal-ci-pg >/dev/null 2>&1 || true' EXIT
until docker exec openseal-ci-pg pg_isready -U postgres -q 2>/dev/null; do sleep 1; done
export OPENSEAL_TEST_DATABASE_URL=postgres://postgres:ci-only@127.0.0.1:55433/postgres SQLX_OFFLINE=true SQLX_CLI_BIN="$PWD/target/sqlx-cli/bin"
server/casual-sign-store/sqlx-prepare.sh --check
OPENSEAL_VERIFY_PYTHON="$PWD/$VENV/bin/python" cargo test -q -p casual-sign-store -p casual-sign-host -p casual-sign-worker -p casual-sign-server --locked
# P2-CRASH (Phase 2 exit item 2): the real server and worker binaries SIGKILLed at every effect boundary
cargo build -q -p casual-sign-server --features crash-points --locked
OPENSEAL_VERIFY_PYTHON="$PWD/$VENV/bin/python" cargo test -q -p casual-sign-worker --features crash-points --test process_crash --locked
docker stop openseal-ci-pg >/dev/null
trap - EXIT
unset OPENSEAL_TEST_DATABASE_URL SQLX_OFFLINE SQLX_CLI_BIN
step "compose e2e"   # T-2F, E2E-01: as ci.yml's compose-e2e job, on its own project and ports so a dev stack is untouched
export COMPOSE_PROJECT_NAME=openseal-ci OPENSEAL_HTTP_PORT=18080 OPENSEAL_MAIL_PORT=18025
export OPENSEAL_E2E_BASE_URL=http://localhost:18080 OPENSEAL_E2E_MAIL_URL=http://127.0.0.1:18025 OPENSEAL_E2E_EMAIL=e2e@openseal.test OPENSEAL_E2E_PASSWORD=e2e-only-passphrase
export OPENSEAL_E2E_CHROMIUM_CHANNEL="${OPENSEAL_E2E_CHROMIUM_CHANNEL:-chromium}"   # the new headless; the old shell can crash on macOS
# The stack and its volumes go however this step ends; one check per line (docs/04 rule 31).
trap 'docker compose down -v >/dev/null 2>&1 || true' EXIT
docker compose down -v >/dev/null 2>&1 || true
docker compose up -d --build --wait --quiet-pull
docker compose exec -T -e OPENSEAL_ADMIN_PASSWORD="$OPENSEAL_E2E_PASSWORD" server casual-sign-server bootstrap "E2E" "$OPENSEAL_E2E_EMAIL" "E2E Admin"
npm --prefix webapp/e2e ci --no-audit --no-fund --silent
webapp/e2e/node_modules/.bin/playwright install chromium webkit
rm -rf target/e2e-sealed
webapp/e2e/node_modules/.bin/playwright test -c webapp/e2e/playwright.config.mjs --project=chromium --project=webkit
docker compose exec -T keyd cat /secrets/ca.pem > target/e2e-sealed/trust-root.pem
"$VENV/bin/python" -I tools/verify-sealed.py target/e2e-sealed
docker compose down -v >/dev/null
trap - EXIT
unset COMPOSE_PROJECT_NAME OPENSEAL_HTTP_PORT OPENSEAL_MAIL_PORT OPENSEAL_E2E_BASE_URL OPENSEAL_E2E_MAIL_URL OPENSEAL_E2E_EMAIL OPENSEAL_E2E_PASSWORD
step "wasm parity";       tools/wasm-parity.sh   # WASM-01: native and WASM byte-identical over the corpus
printf '\nci-local: every job passed\n'
