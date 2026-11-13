#!/bin/sh
# Runs once, when the production profile's database is first created (HRD-06). As the
# development stack's (deploy/postgres): `openseal_app` holds the application's grants
# (migration 0001 grants to it), and the server and worker log in as `openseal`, a member
# that owns nothing, so row-level security applies and `audit_events` cannot be changed.
#
# Logins are rotated by adding another member of `openseal_app` and retiring this one
# (docs/65 §Rotation), never by changing the password under running connections.
set -eu
pw="$(cat "$OPENSEAL_APP_PASSWORD_FILE")"
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" -v pw="$pw" <<'SQL'
CREATE ROLE openseal_app NOLOGIN;
CREATE ROLE openseal LOGIN PASSWORD :'pw' IN ROLE openseal_app;
SQL
