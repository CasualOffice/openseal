#!/bin/sh
# Regenerate the ESP answers signed by xmlsec1, the independent XML Signature
# implementation (ADR-047 §4): `tests/xmlsec.rs` verifies each with our profile and
# refuses every altered copy. Fresh throwaway keys each run; only the public
# certificates and the signed answers are kept (no private key is committed).
#
#   sh server/casual-sign-esign/tests/fixtures/make.sh
#
# Needs `openssl` and the development image with xmlsec1
# (`docker build -f deploy/devtools/Dockerfile -t openseal-devtools:dev .`).
set -eu
here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

key() {
    openssl req -x509 -nodes -days 7300 -subj "/CN=$3/O=OpenSeal tests" \
        -newkey "$2" -keyout "$work/$1.key" -out "$work/$1.pem" 2>/dev/null
}
key esp-rsa rsa:2048 "Test ESP response signing (RSA)"
key other-rsa rsa:2048 "Another key"
openssl ecparam -name prime256v1 -genkey -noout -out "$work/esp-p256.ec"
openssl pkcs8 -topk8 -nocrypt -in "$work/esp-p256.ec" -out "$work/esp-p256.key"
openssl req -x509 -days 7300 -subj "/CN=Test ESP response signing (P-256)/O=OpenSeal tests" \
    -key "$work/esp-p256.key" -out "$work/esp-p256.pem"

C14N=http://www.w3.org/TR/2001/REC-xml-c14n-20010315
EXC=http://www.w3.org/2001/10/xml-exc-c14n#
RSA=http://www.w3.org/2001/04/xmldsig-more#rsa-sha256
ECDSA=http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256

variant() { # name key c14n sigalg transform
    sed -e "s|@C14N@|$3|" -e "s|@SIGALG@|$4|" -e "s|@TRANSFORM@|$5|" \
        "$here/response.tmpl.xml" > "$work/$1.tmpl.xml"
    # The devtools image's xmlsec1 is 1.2 (Debian 12); from 1.3 add --lax-key-search.
    docker run --rm -v "$work:/w" -w /w openseal-devtools:dev \
        xmlsec1 --sign --privkey-pem "$2.key,$2.pem" --output "$1.xml" "$1.tmpl.xml"
    cp "$work/$1.xml" "$here/$1.xml"
}
variant response-rsa-c14n esp-rsa "$C14N" "$RSA" ""
variant response-rsa-exc esp-rsa "$EXC" "$RSA" "<Transform Algorithm=\"$EXC\"/>"
variant response-p256-c14n esp-p256 "$C14N" "$ECDSA" "<Transform Algorithm=\"$C14N\"/>"
for c in esp-rsa esp-p256 other-rsa; do
    openssl x509 -in "$work/$c.pem" -outform DER -out "$here/$c.der"
done
echo "signed: response-rsa-c14n.xml response-rsa-exc.xml response-p256-c14n.xml"
