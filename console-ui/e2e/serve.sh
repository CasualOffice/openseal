#!/usr/bin/env bash
# Start a real platform console for the UI's browser tests (CON-17).
#
# Needs OPENSEAL_TEST_DATABASE_URL (a PostgreSQL superuser URL, as the console crate's
# tests), psql, and a built `casual-sign-console` binary (CONSOLE_BIN). Creates a fresh
# database, applies every migration as the owner, adds the console's LOGIN role, seeds
# tenant metadata (organizations, workspaces, a dead job, a resolved alert, two service
# targets), bootstraps the first platform owner, and serves on CONSOLE_PORT. Writes the
# bootstrap enrolment token to $STATE_DIR/token. Runs in the foreground until killed;
# the database is dropped on exit.
set -euo pipefail

: "${OPENSEAL_TEST_DATABASE_URL:?set OPENSEAL_TEST_DATABASE_URL to a PostgreSQL superuser URL}"
: "${CONSOLE_BIN:?set CONSOLE_BIN to the casual-sign-console binary}"
: "${STATE_DIR:?set STATE_DIR to a scratch folder}"
PORT="${CONSOLE_PORT:-8191}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"

DB="openseal_ui_$(date +%s)_$$"
BASE="${OPENSEAL_TEST_DATABASE_URL%/*}"
OWNER_URL="$BASE/$DB"
# The console's own LOGIN role, as production (docs/23 §5.1).
CONSOLE_URL="$(echo "$BASE" | sed -E 's#//[^@]*@#//openseal_console_ui:openseal-console-ui-only@#')/$DB"

cleanup() {
  [[ -n "${CONSOLE_PID:-}" ]] && kill "$CONSOLE_PID" 2>/dev/null || true
  psql -q "$OPENSEAL_TEST_DATABASE_URL" -c "DROP DATABASE IF EXISTS $DB WITH (FORCE)" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

mkdir -p "$STATE_DIR"
psql -q -v ON_ERROR_STOP=1 "$OPENSEAL_TEST_DATABASE_URL" -c "CREATE DATABASE $DB" >/dev/null
for f in "$REPO"/migrations/*.sql; do
  psql -q -v ON_ERROR_STOP=1 "$OWNER_URL" -f "$f" >/dev/null
done
psql -q -v ON_ERROR_STOP=1 "$OWNER_URL" >/dev/null <<'SQL'
DO $$ BEGIN CREATE ROLE openseal_console_ui LOGIN PASSWORD 'openseal-console-ui-only' IN ROLE openseal_console;
EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL; END $$;
INSERT INTO organizations (id, name) VALUES
  ('0190c8e2-0000-7000-8000-000000000001', 'Acme Holdings'),
  ('0190c8e2-0000-7000-8000-000000000002', 'Northwind Legal'),
  ('0190c8e2-0000-7000-8000-000000000003', 'Globex Field Services');
UPDATE organizations SET data_regions = ARRAY['eu-west', 'eu-central'] WHERE id = '0190c8e2-0000-7000-8000-000000000001';
INSERT INTO accounts (id, name, organization_id) VALUES
  ('0190c8e2-0000-7000-8000-0000000000a1', 'Contracts', '0190c8e2-0000-7000-8000-000000000001'),
  ('0190c8e2-0000-7000-8000-0000000000a2', 'People team', '0190c8e2-0000-7000-8000-000000000001'),
  ('0190c8e2-0000-7000-8000-0000000000b1', 'Litigation', '0190c8e2-0000-7000-8000-000000000002'),
  ('0190c8e2-0000-7000-8000-0000000000c1', 'Field ops', '0190c8e2-0000-7000-8000-000000000003');
INSERT INTO jobs (id, account_id, kind, idempotency_key, status, run_at, attempts, last_error_code, finished_at)
  VALUES ('0190c8e2-0000-7000-8000-0000000000d1', '0190c8e2-0000-7000-8000-0000000000a1', 'send_invitation', 'ui-1', 'dead', now(), 15, 'CS-MAIL-0001', now() - interval '20 minutes');
INSERT INTO jobs (id, account_id, kind, idempotency_key, status, run_at)
  VALUES ('0190c8e2-0000-7000-8000-0000000000d2', '0190c8e2-0000-7000-8000-0000000000b1', 'deliver_webhook', 'ui-2', 'queued', now() - interval '90 seconds');
INSERT INTO platform.alerts (id, at, source, code) VALUES
  ('0190c8e2-0000-7000-8000-0000000000e1', now() - interval '2 hours', 'worker', 'CS-TSA-0001');
INSERT INTO platform.alerts (id, at, source, code, resolves) VALUES
  ('0190c8e2-0000-7000-8000-0000000000e2', now() - interval '1 hour', 'worker', 'CS-TSA-0001', '0190c8e2-0000-7000-8000-0000000000e1');
SQL

export OPENSEAL_MIGRATE_DATABASE_URL="$OWNER_URL"
"$CONSOLE_BIN" set-service-target console console http "http://127.0.0.1:$PORT/livez"
"$CONSOLE_BIN" set-service-target keyd keyd tcp "127.0.0.1:9"
unset OPENSEAL_MIGRATE_DATABASE_URL

export OPENSEAL_CONSOLE_DATABASE_URL="$CONSOLE_URL"
OPENSEAL_CONSOLE_MFA_KEY="$(head -c 32 /dev/urandom | base64)"
export OPENSEAL_CONSOLE_MFA_KEY
export OPENSEAL_CONSOLE_LISTEN="127.0.0.1:$PORT"
"$CONSOLE_BIN" bootstrap-operator owner@console.example | sed -n 's/^enrolment token.*: //p' > "$STATE_DIR/token"
test -s "$STATE_DIR/token"

"$CONSOLE_BIN" serve &
CONSOLE_PID=$!
wait "$CONSOLE_PID"
