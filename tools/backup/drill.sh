#!/bin/sh
# The restore drill (ASVS-14, ASVS 8.1.5; docs/65 §Backups and restore; CI job
# `backup-drill`, tools/ci-local.sh). From a checkout, with Docker (Compose v2),
# python3, openssl 3, and a Python with pyHanko for step 7:
#
#   OPENSEAL_DRILL_VALIDATOR_PYTHON=/path/to/venv/bin/python tools/backup/drill.sh
#
# 1. The backup tool's and the drill's own tests.
# 2. Stack A (Compose project `openseal-drill-a`): built, bootstrapped, and given two
#    envelopes through the API and the emailed links: one signed and sealed, one with the
#    first of two signers signed (tools/backup/drill_flow.py seed). A's seal root and
#    keyd's operation log are read from A itself.
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
# 7. Checks that do not trust the backup or the restored database: both audit chains
#    begin with the event hashes A's API showed before the backup (drill_flow.py); keyd's
#    log on B begins with the exact bytes of A's log read before the backup; B's seal root
#    is not A's (keys come from B's own HSM, never from the backup); and an independent
#    validator (pyHanko, tools/verify-sealed.py) validates A's sealed PDF against A's root
#    and B's against B's, and refuses B's against A's root.
#
# Writes target/backup-drill/report.json (verdict, commit, restore time: the measured RTO
# of this data set, counts, each check) and leaves no stack running. Exits non-zero naming
# the step that failed. OPENSEAL_DRILL_BUILD=0 skips `--build` (images already built from
# this checkout). OPENSEAL_DRILL_VALIDATOR_PYTHON names a Python with pyHanko and
# cryptography (default python3); without them the drill fails before building anything.
set -eu
cd "$(dirname "$0")/../.."
A=openseal-drill-a
B=openseal-drill-b
PORT_A=18180 MAIL_A=18125 PORT_B=18280 MAIL_B=18225
WORK=target/backup-drill
TOOL="python3 -I tools/backup/openseal_backup.py"
FLOW="python3 -I tools/backup/drill_flow.py"
VALIDATOR="${OPENSEAL_DRILL_VALIDATOR_PYTHON:-python3}"
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
STARTED=$(date -u +%Y-%m-%dT%H:%M:%SZ)
COMMIT=$(git rev-parse HEAD 2>/dev/null || echo unknown)
# The validator is checked before ten minutes of image builds, not after.
"$VALIDATOR" -I -c 'import pyhanko, cryptography' || fail "no pyHanko for the independent seal check (set OPENSEAL_DRILL_VALIDATOR_PYTHON)"

step "backup tool and drill tests"
python3 -I -m unittest discover -s tools/backup -p 'test_*.py'

step "stack A: up and seeded"
OPENSEAL_HTTP_PORT=$PORT_A OPENSEAL_MAIL_PORT=$MAIL_A docker compose -p "$A" up -d $BUILD --wait --quiet-pull
docker compose -p "$A" exec -T -e OPENSEAL_ADMIN_PASSWORD="$OPENSEAL_DRILL_PASSWORD" server \
    casual-sign-server bootstrap "Drill" "$OPENSEAL_DRILL_EMAIL" "Drill Admin"
$FLOW seed --base "http://localhost:$PORT_A" --mail "http://127.0.0.1:$MAIL_A" --state "$WORK/state.json" --pdf-dir "$WORK/sealed-a"
# Read from A itself, before the backup: what the restore is compared with, so no check
# below compares the backup only with itself.
docker compose -p "$A" exec -T keyd cat /secrets/ca.pem > "$WORK/sealed-a/trust-root.pem"
docker compose -p "$A" exec -T keyd cat /var/lib/keyd/oplog > "$WORK/oplog-a"
[ -s "$WORK/oplog-a" ] || fail "A's keyd has no operation log after sealing"

step "backup of A"
$TOOL keygen "$WORK/keys"
RECIPIENT="--recipient $WORK/keys/backup-recipient.pem"
KEYS="--verify-key $WORK/keys/backup-signing.pub $RECIPIENT"
$TOOL create --compose-project "$A" --out "$WORK/backups" --signing-key "$WORK/keys/backup-signing.key" $RECIPIENT > "$WORK/backup-path"
BACKUP=$(cat "$WORK/backup-path")
# No key of any kind travels with the backup: it holds exactly its three files.
[ "$(ls -A "$BACKUP" | sort | tr '\n' ' ')" = "manifest.json manifest.json.sig payload.cms " ] || fail "the backup directory holds more than its three files"
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
rm -rf "$WORK/flipped" "$WORK/edited"

step "stack A destroyed"
docker compose -p "$A" down -v

step "stack B: fresh, restored"
export OPENSEAL_HTTP_PORT=$PORT_B OPENSEAL_MAIL_PORT=$MAIL_B
docker compose -p "$B" up -d --wait postgres s3
$TOOL restore "$BACKUP" --compose-project "$B" $KEYS --key "$WORK/keys/backup-recipient.key" --report "$WORK/restore.json"
docker compose -p "$B" up -d --wait
mkdir -p "$WORK/sealed-b" "$WORK/sealed-cross"
docker compose -p "$B" exec -T keyd cat /secrets/ca.pem > "$WORK/sealed-b/trust-root.pem"
if cmp -s "$WORK/sealed-a/trust-root.pem" "$WORK/sealed-b/trust-root.pem"; then
    fail "B's seal root is A's: keys must come from B's own HSM, never from the backup"
fi

step "B: sealed PDF byte-identical, open envelope intact"
$FLOW check --base "http://localhost:$PORT_B" --state "$WORK/state.json"

step "B: the open envelope resumes and is sealed"
$FLOW resume --base "http://localhost:$PORT_B" --state "$WORK/state.json" --pdf-dir "$WORK/sealed-b"
docker compose -p "$B" run --rm --no-deps -T -e OPENSEAL_MIGRATE_DATABASE_URL_FILE=/secrets/migrate-database-url \
    server verify-evidence > "$WORK/evidence-after.txt"
cat "$WORK/evidence-after.txt"
docker compose -p "$B" exec -T keyd casual-sign-keyd verify-oplog /var/lib/keyd/oplog > "$WORK/oplog-after.txt"
cat "$WORK/oplog-after.txt"
docker compose -p "$B" exec -T keyd cat /var/lib/keyd/oplog > "$WORK/oplog-b"

step "independent seal validation (pyHanko)"
# A `level` manifest (as compose-e2e's): every signature intact, valid and trusted under the
# directory's root, so the cross row fails exactly when B's seal does not chain to A's root.
printf 'file\texpect\twhy\tlevel\ncompleted.pdf\tintact\tsealed on A before the backup, read back from B\tB-T\n' > "$WORK/sealed-a/manifest.tsv"
printf 'file\texpect\twhy\tlevel\nresumed.pdf\tintact\tsealed by B after the restore\tB-T\n' > "$WORK/sealed-b/manifest.tsv"
cp "$WORK/sealed-b/resumed.pdf" "$WORK/sealed-cross/resumed.pdf"
cp "$WORK/sealed-a/trust-root.pem" "$WORK/sealed-cross/trust-root.pem"
printf "file\texpect\twhy\tlevel\nresumed.pdf\ttampered\tsealed by B's own key: must not be trusted under A's root\tB-T\n" > "$WORK/sealed-cross/manifest.tsv"
"$VALIDATOR" -I tools/verify-sealed.py "$WORK/sealed-a" "$WORK/sealed-b" "$WORK/sealed-cross" > "$WORK/verify-sealed.txt"
cat "$WORK/verify-sealed.txt"

step "report"
python3 -I tools/backup/drill_report.py "$WORK" --started "$STARTED" --commit "$COMMIT"
docker compose -p "$B" down -v
printf '\ndrill: passed (target/backup-drill/report.json)\n'
