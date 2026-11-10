#!/bin/sh
# Runs once, when the Compose stack's database is first created (T-2F): the login role
# the server and worker use, a member of `openseal_app`, the role migration 0001 grants
# to (it creates `openseal_app` itself when missing, and tolerates it existing). The
# migrations run as the superuser, the schema owner; `openseal` owns nothing, so
# row-level security applies to it and it cannot change `audit_events` (docs/22 §9).
set -eu
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
    -v pw="$(cat /secrets/postgres-app-password)" <<'SQL'
CREATE ROLE openseal_app NOLOGIN;
CREATE ROLE openseal LOGIN PASSWORD :'pw' IN ROLE openseal_app;
SQL
