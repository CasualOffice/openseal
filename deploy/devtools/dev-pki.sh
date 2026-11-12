#!/bin/sh
# Development secrets for the Compose stack (T-2F), written once into $OUT (the
# `secrets` volume) and kept across restarts; `docker compose down -v` discards them.
# Never for production: every key here is generated on a laptop, and the seal made with
# them is a development seal (docs/65 §Production checklist).
#
# Files are readable by every container user (0644, in a volume only this stack mounts),
# because each service runs as its own non-root user and the volume has no shared group.
#
# modeld (Compose profile `ml`, ML-01) never mounts that volume: it runs model code over
# hostile documents, so it gets its own, $MODELD_OUT (the `modeld-secrets` volume),
# holding only its TLS chain and key, the root's certificate and its allow list. That
# part runs on its own marker, so an existing stack gains it without a new root.
# tools/ml/check-modeld-isolation.py checks both.
set -eu
OUT="${OUT:-/secrets}"
MODELD_OUT="${MODELD_OUT:-/modeld-secrets}"
umask 022
DAYS=3650
rand() { openssl rand -hex "$1"; }
eckey() { openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1"; }

# leaf NAME SUBJECT EXTENSIONS...: a key and a certificate issued by the root in $OUT,
# written in the current directory.
leaf() {
    name="$1"; subject="$2"; shift 2
    eckey "$name.key"
    printf '%s\n' "basicConstraints=critical,CA:FALSE" "$@" > "$name.ext"
    openssl req -new -key "$name.key" -subj "$subject" -out "$name.csr"
    openssl x509 -req -in "$name.csr" -CA "$OUT/ca.pem" -CAkey "$OUT/ca.key" -sha256 -days "$DAYS" \
        -set_serial "0x$(rand 16)" -extfile "$name.ext" -out "$name.pem" 2>/dev/null
    rm -f "$name.csr" "$name.ext"
}

# modeld's TLS identity, into its own directory (after the shared secrets exist).
modeld_identity() {
    if [ -f "$MODELD_OUT/.complete" ]; then
        echo "dev-pki: modeld identity already present"
        return 0
    fi
    mkdir -p "$MODELD_OUT"
    (
        cd "$MODELD_OUT"
        leaf modeld-tls "/O=OpenSeal development/CN=modeld" \
            "keyUsage=critical,digitalSignature" "extendedKeyUsage=serverAuth" "subjectAltName=DNS:modeld"
        cat modeld-tls.pem "$OUT/ca.pem" > modeld-tls-chain.pem
        rm -f modeld-tls.pem
        cp "$OUT/ca.pem" ca.pem
        # modeld answers the worker's certificate only, as keyd does.
        fp="$(openssl x509 -in "$OUT/worker-client.pem" -outform DER | openssl dgst -sha256 -r | cut -d' ' -f1)"
        printf '%s worker\n' "$fp" > modeld-allow-list
        chmod 0444 ca.pem modeld-tls-chain.pem modeld-allow-list
        # The key is for modeld's user alone (distroless `nonroot`, uid 65532).
        chmod 0400 modeld-tls.key
        if [ "$(id -u)" = 0 ]; then chown 65532:65532 modeld-tls.key; fi
        touch .complete
    )
    echo "dev-pki: modeld identity written"
}

if [ -f "$OUT/.complete" ]; then
    echo "dev-pki: secrets already present"
    modeld_identity
    exit 0
fi
mkdir -p "$OUT"
cd "$OUT"

# The development root.
eckey ca.key
openssl req -x509 -new -key ca.key -sha256 -days "$DAYS" -out ca.pem \
    -subj "/O=OpenSeal development/CN=OpenSeal development root" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign"

leaf keyd-tls "/O=OpenSeal development/CN=keyd" \
    "keyUsage=critical,digitalSignature" "extendedKeyUsage=serverAuth" "subjectAltName=DNS:keyd"
leaf worker-client "/O=OpenSeal development/CN=worker" \
    "keyUsage=critical,digitalSignature" "extendedKeyUsage=clientAuth"
leaf seal "/O=OpenSeal development/CN=OpenSeal development seal" \
    "keyUsage=critical,digitalSignature,nonRepudiation"
leaf tsa "/O=OpenSeal development/CN=OpenSeal development TSA" \
    "keyUsage=critical,digitalSignature" "extendedKeyUsage=critical,timeStamping"
cat seal.pem ca.pem > seal-chain.pem
cat keyd-tls.pem ca.pem > keyd-tls-chain.pem
cat worker-client.pem ca.pem > worker-client-chain.pem
# keyd answers the worker's certificate only (its SHA-256, as keyd names a caller).
fp="$(openssl x509 -in worker-client.pem -outform DER | openssl dgst -sha256 -r | cut -d' ' -f1)"
printf '%s worker\n' "$fp" > keyd-allow-list

# The API's token key (P-256, PKCS#8 PEM).
eckey jwt.key

# Passwords and the URLs that carry them.
rand 24 > postgres-password
rand 24 > postgres-app-password
rand 8 > softhsm-pin
rand 8 > softhsm-so-pin
rand 24 > s3-secret-key
printf 'postgres://openseal:%s@postgres:5432/openseal\n' "$(cat postgres-app-password)" > database-url
printf 'postgres://postgres:%s@postgres:5432/openseal\n' "$(cat postgres-password)" > migrate-database-url
cat > s3.json <<EOF
{"identities": [{"name": "openseal", "credentials": [{"accessKey": "openseal", "secretKey": "$(cat s3-secret-key)"}],
  "actions": ["Admin", "Read", "List", "Tagging", "Write"]}]}
EOF

chmod 0644 ./*.key ./*.pem postgres-password postgres-app-password softhsm-pin softhsm-so-pin \
    s3-secret-key database-url migrate-database-url s3.json keyd-allow-list
touch .complete
echo "dev-pki: development secrets written"
modeld_identity
