#!/bin/sh
# The restore drill (ASVS-14, ASVS 8.1.5; docs/65 §Backups and restore; CI job
# `backup-drill`, tools/ci-local.sh). From a checkout, with Docker (Compose v2),
# python3 and openssl 3:
#
#   tools/backup/drill.sh
#
# 1. The backup tool's own tests.
# 2. Stack A (Compose project `openseal-drill-a`): built, bootstrapped, and given two
#    envelopes through the API and the emailed links: one signed and sealed, one with the
#    first of two signers signed (tools/backup/drill_flow.py seed).
# 3. A backup of A with a fresh recipient key and signing key, verified with the signing
#    key's public half, with and without the recipient's private key; a copy with one
#    payload byte flipped, and one with an edited manifest, must fail verification.
# 4. A destroyed (`down -v`: database, store, keyd's log, its keys, all gone).
# 5. Stack B (`openseal-drill-b`), a fresh install with its own keys: only the database
#    and the store started, the backup restored (roles, database, blobs, keyd's log, then
#    verify-evidence: every audit chain, admin log and the operator log, every blob the
#    evidence names, the backup's row counts and blob keys), the rest started.
# 6. On B: the sealed PDF is byte-identical, the open envelope is as it was, and its second
#    signer signs with the link emailed by A; B's worker seals it; verify-evidence passes
#    again with one more envelope completed, and keyd's log verifies from its restored
#    lines on.
#
# Writes target/backup-drill/report.json (restore time: the measured RTO of this data set,
# counts) and leaves no stack running. Exits non-zero naming the step that failed.
# OPENSEAL_DRILL_BUILD=0 skips `--build` (images already built from this checkout).
set -eu
cd "$(dirname "$0")/../.."
A=openseal-drill-a
B=openseal-drill-b
PORT_A=18180 MAIL_A=18125 PORT_B=18280 MAIL_B=18225
WORK=target/backup-drill
TOOL="python3 -I tools/backup/openseal_backup.py"
FLOW="python3 -I tools/backup/drill_flow.py"
export OPENSEAL_DRILL_EMAIL=drill@openseal.test OPENSEAL_DRILL_PASSWORD=drill-only-passphrase
BUILD=--build
[ "${OPENSEAL_DRILL_BUILD:-1}" = 0 ] && BUILD=
step() { printf '\n== drill: %s\n' "$1"; }
down() { docker compose -p "$1" down -v >/dev/null 2>&1 || true; }
fail() { printf 'drill: FAILED: %s\n' "$1" >&2; exit 1; }
logs() { [ -d "$WORK" ] && docker compose -p "$1" logs --no-color > "$WORK/compose-$1.log" 2>&1 || true; }
# Both stacks and their volumes go however the drill ends; on a failure their logs are
# kept in $WORK first.
trap 'rc=$?; if [ "$rc" -ne 0 ]; then logs "$A"; logs "$B"; fi; down "$A"; down "$B"; exit "$rc"' EXIT
down "$A"
down "$B"
rm -rf "$WORK"
mkdir -p "$WORK"

step "backup tool tests"
python3 -I -m unittest discover -s tools/backup -p 'test_*.py'

step "stack A: up and seeded"
OPENSEAL_HTTP_PORT=$PORT_A OPENSEAL_MAIL_PORT=$MAIL_A docker compose -p "$A" up -d $BUILD --wait --quiet-pull
docker compose -p "$A" exec -T -e OPENSEAL_ADMIN_PASSWORD="$OPENSEAL_DRILL_PASSWORD" server \
    casual-sign-server bootstrap "Drill" "$OPENSEAL_DRILL_EMAIL" "Drill Admin"
$FLOW seed --base "http://localhost:$PORT_A" --mail "http://127.0.0.1:$MAIL_A" --state "$WORK/state.json"

step "backup of A"
$TOOL keygen "$WORK/keys"
RECIPIENT="--recipient $WORK/keys/backup-recipient.pem"
KEYS="--verify-key $WORK/keys/backup-signing.pub $RECIPIENT"
$TOOL create --compose-project "$A" --out "$WORK/backups" --signing-key "$WORK/keys/backup-signing.key" $RECIPIENT > "$WORK/backup-path"
BACKUP=$(cat "$WORK/backup-path")
$TOOL verify "$BACKUP" --verify-key "$WORK/keys/backup-signing.pub"
$TOOL verify "$BACKUP" $KEYS --key "$WORK/keys/backup-recipient.key"
# The payload is CMS AuthEnvelopedData with the key wrapped by RSA-OAEP.
openssl cms -cmsout -print -inform DER -in "$BACKUP/payload.cms" > "$WORK/payload-structure.txt"
grep -q 'authEnvelopedData' "$WORK/payload-structure.txt" || fail "payload is not AuthEnvelopedData"
grep -q 'rsaesOaep' "$WORK/payload-structure.txt" || fail "content key not wrapped with RSA-OAEP"

step "tampered copies fail verification"
cp -R "$BACKUP" "$WORK/flipped"
python3 -I -c 'import sys; p = sys.argv[1]; b = bytearray(open(p, "rb").read()); b[len(b) // 2] ^= 1; open(p, "wb").write(b)' "$WORK/flipped/payload.cms"
if $TOOL verify "$WORK/flipped" $KEYS --key "$WORK/keys/backup-recipient.key" 2>"$WORK/flipped.err"; then fail "a flipped payload byte verified"; fi
grep -q 'payload.cms differs' "$WORK/flipped.err" || fail "flipped payload: wrong reason"
cp -R "$BACKUP" "$WORK/edited"
sed 's/"schema_version": [0-9]*/"schema_version": 1/' "$BACKUP/manifest.json" > "$WORK/edited/manifest.json"
if $TOOL verify "$WORK/edited" --verify-key "$WORK/keys/backup-signing.pub" 2>"$WORK/edited.err"; then fail "an edited manifest verified"; fi
grep -q 'signature does not verify' "$WORK/edited.err" || fail "edited manifest: wrong reason"

step "stack A destroyed"
docker compose -p "$A" down -v

step "stack B: fresh, restored"
export OPENSEAL_HTTP_PORT=$PORT_B OPENSEAL_MAIL_PORT=$MAIL_B
docker compose -p "$B" up -d --wait postgres s3
$TOOL restore "$BACKUP" --compose-project "$B" $KEYS --key "$WORK/keys/backup-recipient.key" --report "$WORK/restore.json"
docker compose -p "$B" up -d --wait

step "B: sealed PDF byte-identical, open envelope intact"
$FLOW check --base "http://localhost:$PORT_B" --state "$WORK/state.json"

step "B: the open envelope resumes and is sealed"
$FLOW resume --base "http://localhost:$PORT_B" --state "$WORK/state.json"
docker compose -p "$B" run --rm --no-deps -T -e OPENSEAL_MIGRATE_DATABASE_URL_FILE=/secrets/migrate-database-url \
    server verify-evidence > "$WORK/evidence-after.txt"
cat "$WORK/evidence-after.txt"
docker compose -p "$B" exec -T keyd casual-sign-keyd verify-oplog /var/lib/keyd/oplog > "$WORK/oplog-after.txt"
cat "$WORK/oplog-after.txt"
python3 -I - "$WORK" <<'PY'
import json, pathlib, re, sys
work = pathlib.Path(sys.argv[1])
restore = json.loads((work / "restore.json").read_text())
before = restore["counts"]
after = dict(kv.split("=") for kv in re.search(r"evidence verified: (.*)", (work / "evidence-after.txt").read_text()).group(1).split())
lines = int(re.search(r"lines=(\d+)", (work / "oplog-after.txt").read_text()).group(1))
problems = []
if int(after["envelopes"]) != before["envelopes"]:
    problems.append("envelope count changed")
if int(after["audit_events"]) <= before["audit_events"]:
    problems.append("no audit events after the restore")
if restore["keyd_oplog"]["present"] and lines <= restore["keyd_oplog"]["lines"]:
    problems.append("keyd's log did not continue from its restored lines")
report = {"restore_seconds": restore["seconds"], "restored": before, "after_resume": {k: int(v) for k, v in after.items()},
          "keyd_oplog": {"restored_lines": restore["keyd_oplog"].get("lines", 0), "lines_after_resume": lines}}
(work / "report.json").write_text(json.dumps(report, indent=1, sort_keys=True) + "\n")
if problems:
    sys.exit("drill: FAILED: " + "; ".join(problems))
print(f"drill: restore took {restore['seconds']} s; {before['envelopes']} envelopes, {before['audit_events']} audit events restored; "
      f"{int(after['audit_events']) - before['audit_events']} events and {lines - restore['keyd_oplog'].get('lines', 0)} keyd lines after the resume")
PY
docker compose -p "$B" down -v
printf '\ndrill: passed (target/backup-drill/report.json)\n'
