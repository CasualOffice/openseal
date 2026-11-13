#!/bin/sh
# Prepare the secret files deploy/compose.production.yml mounts (HRD-06, docs/65
# §Production deployment). Run once, as root, on the Docker host:
#
#   deploy/production/init-secrets.sh /srv/openseal/secrets
#
# It writes the deployment's internal TLS: a private CA and the identities of Postgres,
# the object store, keyd and the worker (each certificate names its service), random
# passwords and keys, and the database URLs, each file owned by the one container user
# that reads it and readable by no one else. The CA's private key goes to
# DIR/offline/: move it off the host after this run; it is needed again only to issue
# a rotated identity (docs/65 §Rotation).
#
# It does not write what only you can supply, and the stack refuses to start until you
# add them: seal-chain.pem (your seal certificate chain; the key stays in the HSM),
# keyd-pkcs11-pin, trust-anchors.pem, smtp-password. keyd-config-manifest and
# worker-config-manifest start empty, so keyd and the worker refuse to start
# (CS-KEY-0014) until you record them with `config-manifest` (docs/65).
#
# This is not the seal key's PKI: the internal CA only authenticates services to each
# other. Never reuse it for signing.
set -eu

DIR="${1:?usage: init-secrets.sh DIR}"
DAYS="${OPENSEAL_INTERNAL_TLS_DAYS:-397}"
# Container users (deploy/compose.production.yml): postgres (alpine) 70, seaweedfs 1000,
# keyd 10001, server and worker (distroless nonroot) 65532.
PG=70 S3=1000 KEYD=10001 APP=65532

if [ -e "$DIR" ] && [ -n "$(ls -A "$DIR" 2>/dev/null)" ]; then
    echo "init-secrets: $DIR is not empty; refusing to overwrite secrets" >&2
    exit 1
fi
command -v openssl >/dev/null || { echo "init-secrets: openssl is required" >&2; exit 1; }
mkdir -p "$DIR/offline"
chmod 0700 "$DIR/offline"
cd "$DIR"
umask 077

rand_b64() { openssl rand -base64 "$1" | tr -d '\n'; }
# URL-safe: no characters that need escaping in a database URL.
rand_hex() { openssl rand -hex "$1"; }
eckey() { openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1"; }

# The internal CA.
eckey offline/internal-ca.key
openssl req -x509 -new -key offline/internal-ca.key -sha256 -days 3650 -out internal-ca.pem \
    -subj "/O=OpenSeal deployment/CN=OpenSeal internal TLS CA" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
    -addext "keyUsage=critical,keyCertSign,cRLSign"

# identity NAME CN EKU [SAN]: NAME.key and NAME-chain.pem (leaf then CA).
identity() {
    name="$1" cn="$2" eku="$3" san="${4:-}"
    eckey "$name.key"
    {
        echo "basicConstraints=critical,CA:FALSE"
        echo "keyUsage=critical,digitalSignature"
        echo "extendedKeyUsage=$eku"
        if [ -n "$san" ]; then echo "subjectAltName=$san"; fi
    } > "$name.ext"
    openssl req -new -key "$name.key" -subj "/O=OpenSeal deployment/CN=$cn" -out "$name.csr"
    openssl x509 -req -in "$name.csr" -CA internal-ca.pem -CAkey offline/internal-ca.key \
        -sha256 -days "$DAYS" -set_serial "0x$(rand_hex 16)" -extfile "$name.ext" \
        -out "$name.pem" 2>/dev/null
    cat "$name.pem" internal-ca.pem > "$name-chain.pem"
    rm -f "$name.csr" "$name.ext" "$name.pem"
}
identity postgres-tls postgres serverAuth DNS:postgres
identity s3-tls s3 serverAuth DNS:s3
identity keyd-tls keyd serverAuth DNS:keyd
identity worker-client worker clientAuth

# keyd answers the worker's certificate only.
fp="$(openssl x509 -in worker-client-chain.pem -outform DER | openssl dgst -sha256 -r | cut -d' ' -f1)"
printf '%s worker\n' "$fp" > keyd-allow-list

# Passwords and keys.
rand_hex 24 > postgres-password
app_pw="$(rand_hex 24)"
printf '%s\n' "$app_pw" > postgres-app-password
pg_pw="$(cat postgres-password)"
tls="sslmode=verify-full&sslrootcert=/run/secrets/internal-ca.pem"
printf 'postgres://openseal:%s@postgres:5432/openseal?%s\n' "$app_pw" "$tls" > database-url
printf 'postgres://postgres:%s@postgres:5432/openseal?%s\n' "$pg_pw" "$tls" > migrate-database-url
s3_secret="$(rand_hex 32)"
printf '%s\n' "$s3_secret" > s3-secret-key
cat > s3-identities.json <<JSON
{"identities": [{"name": "openseal",
  "credentials": [{"accessKey": "openseal", "secretKey": "$s3_secret"}],
  "actions": ["Read:openseal", "Write:openseal", "List:openseal", "Tagging:openseal", "Admin:openseal"]}]}
JSON
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out jwt-signing-key
rand_b64 32 > mfa-key
: > keyd-config-manifest
: > worker-config-manifest

# Owners and modes: each private file readable by its one reader; public files by all.
chmod 0444 internal-ca.pem postgres-tls-chain.pem s3-tls-chain.pem keyd-tls-chain.pem \
    worker-client-chain.pem keyd-allow-list keyd-config-manifest worker-config-manifest
chmod 0400 postgres-password postgres-app-password s3-tls.key s3-identities.json \
    keyd-tls.key worker-client.key database-url migrate-database-url s3-secret-key \
    jwt-signing-key mfa-key
# PostgreSQL insists on 0600 or stricter for its key, owned by its user.
chmod 0600 postgres-tls.key
if [ "$(id -u)" = 0 ]; then
    chown "$PG:$PG" postgres-password postgres-app-password postgres-tls.key
    chown "$S3:$S3" s3-tls.key s3-identities.json
    chown "$KEYD:$KEYD" keyd-tls.key
    chown "$APP:$APP" worker-client.key database-url migrate-database-url s3-secret-key \
        jwt-signing-key mfa-key
else
    echo "init-secrets: not root; set owners yourself (docs/65 §Production deployment)" >&2
fi

echo "init-secrets: wrote $DIR"
echo "init-secrets: move $DIR/offline/internal-ca.key off this host now"
echo "init-secrets: still to add: seal-chain.pem keyd-pkcs11-pin (owner $KEYD, 0400)," \
    "trust-anchors.pem, smtp-password (owner $APP, 0400); then record the manifests"
