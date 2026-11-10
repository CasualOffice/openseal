#!/bin/sh
# Build the browser verifier for the web app's Verify page (WEB-02): casual-sign-wasm
# compiled to WebAssembly exactly as tools/wasm-parity.sh ships it (opt-level "z", fat
# LTO, no wasm-opt), then copied into webapp/vendor/openseal-wasm/, which verify.js
# loads. Build output, so it is not committed (webapp/vendor/openseal-wasm/.gitignore);
# a deployment runs this script, and verify.html says so when the files are absent.
#
#   tools/build-webapp-wasm.sh                 # build, then copy
#   tools/build-webapp-wasm.sh --from DIR      # copy an existing wasm-pack --target web pkg
#
# Needs wasm-pack 0.14.0 and the wasm32-unknown-unknown target (as wasm-parity.sh).
# Exits non-zero, naming the problem, when a file is missing.
set -eu
cd "$(dirname "$0")/.."
DEST=webapp/vendor/openseal-wasm

if [ "${1:-}" = --from ]; then
    PKG=${2:?"--from needs a directory"}
else
    PKG=target/wasm-parity/pkg
    CARGO_PROFILE_RELEASE_OPT_LEVEL=z CARGO_PROFILE_RELEASE_LTO=true \
        wasm-pack --quiet build crates/casual-sign-wasm --release --target web --no-pack \
        --out-dir "../../$PKG" -- --locked
fi

for f in casual_sign_wasm.js casual_sign_wasm_bg.wasm; do
    if [ ! -f "$PKG/$f" ]; then
        echo "build-webapp-wasm: $PKG/$f is missing" >&2
        exit 1
    fi
done
mkdir -p "$DEST"
cp "$PKG/casual_sign_wasm.js" "$PKG/casual_sign_wasm_bg.wasm" "$DEST/"
echo "build-webapp-wasm: copied the verifier into $DEST ($(wc -c < "$DEST/casual_sign_wasm_bg.wasm" | tr -d ' ') bytes of WebAssembly)"
