#!/bin/sh
# Throwaway secrets for the chaos run on the production profile (HRD-10; run by
# tools/chaos/chaos_compose.py inside the devtools image, as root, never on its own).
#
#   prepare-secrets.sh WORK HOST_UID
#
# 1. deploy/production/init-secrets.sh WORK/secrets, exactly as an operator runs it: the
#    internal TLS CA, every service identity, passwords, keys, owners and modes.
# 2. What init-secrets.sh leaves to the operator, made up here for CI only: a chaos seal
#    PKI (a root, the seal certificate and a time-stamping authority's, as dev-pki.sh
#    makes them) giving seal-chain.pem and trust-anchors.pem; keyd's PKCS#11 PIN; the
#    SMTP password; and a TLS identity for the CI mail sink (Mailpit, STARTTLS), issued
#    by the deployment's internal CA so the worker verifies it.
# 3. WORK/pki, owned by HOST_UID, readable: the seal key (imported into SoftHSM by the
#    driver), the PIN, the TSA's key and certificate, the mail sink's identity and the
#    trust root for pyHanko. CI-only material; the driver deletes WORK/secrets and
#    WORK/pki when it ends.
set -eu
WORK="${1:?usage: prepare-secrets.sh WORK HOST_UID}"
HOST_UID="${2:?usage: prepare-secrets.sh WORK HOST_UID}"
KEYD=10001 APP=65532

sh /repo/deploy/production/init-secrets.sh "$WORK/secrets"

mkdir -p "$WORK/pki"
cd "$WORK/pki"
umask 022
rand() { openssl rand -hex "$1"; }
eckey() { openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1"; }
# leaf NAME SUBJECT CA CAKEY EXTENSIONS...
leaf() {
    name="$1" subject="$2" ca="$3" cakey="$4"
    shift 4
    eckey "$name.key"
    printf '%s\n' "basicConstraints=critical,CA:FALSE" "$@" > "$name.ext"
    openssl req -new -key "$name.key" -subj "$subject" -out "$name.csr"
    openssl x509 -req -in "$name.csr" -CA "$ca" -CAkey "$cakey" -sha256 -days 30 \
        -set_serial "0x$(rand 16)" -extfile "$name.ext" -out "$name.pem" 2>/dev/null
    rm -f "$name.csr" "$name.ext"
}

# The chaos seal root: the seal and the TSA chain to it (as the evaluation stack's
# dev-pki.sh); it is the worker's trust anchor and pyHanko's trust root.
eckey ca.key
openssl req -x509 -new -key ca.key -sha256 -days 30 -out ca.pem \
    -subj "/O=OpenSeal chaos test/CN=OpenSeal chaos test root" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign"
leaf seal "/O=OpenSeal chaos test/CN=OpenSeal chaos test seal" ca.pem ca.key \
    "keyUsage=critical,digitalSignature,nonRepudiation"
leaf tsa "/O=OpenSeal chaos test/CN=OpenSeal chaos test TSA" ca.pem ca.key \
    "keyUsage=critical,digitalSignature" "extendedKeyUsage=critical,timeStamping"
cat seal.pem ca.pem > seal-chain.pem
cp ca.pem trust-root.pem
# The mail sink's STARTTLS identity, from the deployment's internal CA.
leaf mail-tls "/O=OpenSeal deployment/CN=mailpit" \
    "$WORK/secrets/internal-ca.pem" "$WORK/secrets/offline/internal-ca.key" \
    "keyUsage=critical,digitalSignature" "extendedKeyUsage=serverAuth" "subjectAltName=DNS:mailpit"
cat mail-tls.pem "$WORK/secrets/internal-ca.pem" > mail-tls-chain.pem
rand 8 > pin
rm -f ca.key

# What the operator adds (docs/65 §Production deployment), owners and modes as stated.
S="$WORK/secrets"
install -o "$KEYD" -g "$KEYD" -m 0400 seal-chain.pem "$S/seal-chain.pem"
install -o "$KEYD" -g "$KEYD" -m 0400 pin "$S/keyd-pkcs11-pin"
install -m 0444 ca.pem "$S/trust-anchors.pem"
rand 16 > smtp-password
install -o "$APP" -g "$APP" -m 0400 smtp-password "$S/smtp-password"
rm -f smtp-password

chmod 0644 ./*
chown -R "$HOST_UID" "$WORK/pki"
echo "prepare-secrets: wrote $S and $WORK/pki"
