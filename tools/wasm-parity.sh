#!/bin/sh
# WASM parity (`WASM-01`, Phase 1 exit item 6): build casual-sign-wasm for the browser and
# natively, then compare their answers byte for byte with tools/wasm-parity.mjs.
#
#   tools/wasm-parity.sh [CORPUS_DIR]   # default fixtures/corpus/files (python3 -I fixtures/corpus/fetch.py)
#   tools/wasm-parity.sh --no-corpus    # fixtures and the case table only
#
# Needs wasm-pack 0.14.0 (`cargo install wasm-pack --version 0.14.0 --locked`), the
# wasm32-unknown-unknown target and Node 24. The module is built as shipped: opt-level
# "z", fat LTO, no wasm-opt pass. Generates the hostile fixtures when they are absent.
# Exits non-zero on any difference and names it.
set -eu
cd "$(dirname "$0")/.."
OUT=target/wasm-parity
CORPUS="${1:-fixtures/corpus/files}"
if [ "$CORPUS" != --no-corpus ] && ! ls "$CORPUS"/*.pdf >/dev/null 2>&1; then
    echo "wasm-parity: no corpus PDFs in $CORPUS (fetch them, or pass --no-corpus)" >&2
    exit 2
fi

# Profile overrides for the WASM builds only (the native release build keeps the
# workspace profile). Symbols stay stripped (the workspace profile): wasm-bindgen keeps a
# name section it is given, which adds about 0.8 MB.
wasm_build() {
    dir=$1
    shift
    CARGO_PROFILE_RELEASE_OPT_LEVEL=z CARGO_PROFILE_RELEASE_LTO=true \
        wasm-pack --quiet build crates/casual-sign-wasm --release --target web --no-pack \
        --out-dir "../../$OUT/$dir" -- --locked "$@"
}
wasm_build pkg
wasm_build pkg-parity --features parity
cargo build -q --release --locked -p casual-sign-wasm --features parity --example native_parity

ls fixtures/hostile/*.pdf >/dev/null 2>&1 || python3 -I fixtures/tools/generate.py >/dev/null

set -- --pkg "$OUT/pkg" --parity-pkg "$OUT/pkg-parity" --native target/release/examples/native_parity
[ "$CORPUS" = --no-corpus ] || set -- "$@" --corpus "$CORPUS"
node tools/wasm-parity.mjs "$@"
