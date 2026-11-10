#!/bin/sh
# Regenerate (or, with --check, verify) the committed offline query cache `.sqlx/` that
# lets `query!` build with SQLX_OFFLINE=true and no database (ADR-014, owner
# instruction 14).
#
# Needs sqlx-cli 0.9 on PATH (`cargo install sqlx-cli --version 0.9.0
# --no-default-features --features postgres,rustls --locked`) and
# OPENSEAL_TEST_DATABASE_URL, a superuser URL to a PostgreSQL server. A scratch database
# is created on that server, every migration in ../../migrations applied, the cache
# prepared or checked against it, and the database dropped. `--check` fails non-zero when
# a query or a migration changed and the cache was not regenerated.
#
#   OPENSEAL_TEST_DATABASE_URL=postgres://postgres:pw@127.0.0.1:5432/postgres \
#     server/casual-sign-store/sqlx-prepare.sh [--check]
set -eu

if [ -z "${OPENSEAL_TEST_DATABASE_URL:-}" ]; then
    echo "sqlx-prepare: set OPENSEAL_TEST_DATABASE_URL to a PostgreSQL superuser URL" >&2
    exit 2
fi
# SQLX_CLI_BIN: a directory holding `sqlx` and `cargo-sqlx`, when not on PATH.
if [ -n "${SQLX_CLI_BIN:-}" ]; then PATH="$SQLX_CLI_BIN:$PATH"; export PATH; fi
command -v sqlx >/dev/null 2>&1 || { echo "sqlx-prepare: sqlx-cli 0.9 is not on PATH" >&2; exit 2; }

cd "$(dirname "$0")"
server="${OPENSEAL_TEST_DATABASE_URL%/*}"
DATABASE_URL="$server/openseal_sqlx_prepare_$$"
export DATABASE_URL
# The offline cache must come from the database, never from a stale cache.
SQLX_OFFLINE=false
export SQLX_OFFLINE

sqlx database create
trap 'sqlx database drop -y >/dev/null 2>&1 || true' EXIT INT TERM
sqlx migrate run --source ../../migrations >/dev/null
cargo sqlx prepare "$@" -- --lib
