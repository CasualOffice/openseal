#!/bin/sh
# keyd's start (T-2F). With OPENSEAL_KEYD_IMPORT_KEY (development: the Compose stack's
# generated seal key), the first start creates the SoftHSM token and imports the key
# into it; later starts find the token and leave it alone. In production the key is
# generated inside the HSM and this variable is not set.
set -eu
: "${SOFTHSM2_CONF:=/var/lib/keyd/softhsm2.conf}"
: "${OPENSEAL_KEYD_PKCS11_TOKEN:=openseal}"
: "${OPENSEAL_KEYD_PKCS11_KEY_LABEL:=platform}"
export SOFTHSM2_CONF OPENSEAL_KEYD_PKCS11_TOKEN OPENSEAL_KEYD_PKCS11_KEY_LABEL

if [ ! -f "$SOFTHSM2_CONF" ]; then
    mkdir -p /var/lib/keyd/tokens
    printf 'directories.tokendir = /var/lib/keyd/tokens\nobjectstore.backend = file\nlog.level = ERROR\n' > "$SOFTHSM2_CONF"
fi

if [ -n "${OPENSEAL_KEYD_IMPORT_KEY:-}" ] \
    && ! softhsm2-util --show-slots | grep -q "Label: *$OPENSEAL_KEYD_PKCS11_TOKEN *\$"; then
    pin="$(cat "$OPENSEAL_KEYD_PKCS11_PIN_FILE")"
    so_pin="$(cat "$OPENSEAL_KEYD_SO_PIN_FILE")"
    softhsm2-util --init-token --free --label "$OPENSEAL_KEYD_PKCS11_TOKEN" \
        --so-pin "$so_pin" --pin "$pin" >/dev/null
    softhsm2-util --import "$OPENSEAL_KEYD_IMPORT_KEY" --token "$OPENSEAL_KEYD_PKCS11_TOKEN" \
        --label "$OPENSEAL_KEYD_PKCS11_KEY_LABEL" --id 01 --pin "$pin" >/dev/null
    echo "keyd: SoftHSM token $OPENSEAL_KEYD_PKCS11_TOKEN created (development)" >&2
fi
unset OPENSEAL_KEYD_IMPORT_KEY OPENSEAL_KEYD_SO_PIN_FILE
exec /usr/local/bin/casual-sign-keyd
