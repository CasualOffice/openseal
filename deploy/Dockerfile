# syntax=docker/dockerfile:1
# OpenSeal's images (T-2F, docs/65): one build, three targets, and a fourth, `modeld`,
# for the optional pretrained models (ML-01, ADR-029; Compose profile `ml`).
#
#   docker build -f deploy/Dockerfile --target server .
#   docker build -f deploy/Dockerfile --target worker .
#   docker build -f deploy/Dockerfile --target keyd .
#   docker build -f deploy/Dockerfile --target modeld .
#
# Every base image is pinned by digest (docs/04 rule 31): a floating tag can change what
# runs under the same name. The runtime images hold the binary and nothing else that
# could be a secret: keys, passwords and certificates are files mounted at run time.
# server and worker run on distroless (no shell, no package manager) as `nonroot`; keyd
# on Debian slim, which carries the SoftHSM PKCS#11 module, as its own user.

ARG RUST_IMAGE=rust:1.96.0-slim-bookworm@sha256:4732ca96fd086cb9be682050c3f0176288eebaac2b80aa2bcefccfaf198e1950
ARG RUNTIME_IMAGE=gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f
ARG DEBIAN_IMAGE=debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc

FROM ${RUST_IMAGE} AS build
# aws-lc-sys builds its C with cmake when no prebuilt bindings match.
RUN apt-get update -q \
 && apt-get install -y -q --no-install-recommends cmake perl g++ make \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
# The query cache in server/casual-sign-store/.sqlx: no database while building (ADR-014).
ENV SQLX_OFFLINE=true CARGO_TERM_COLOR=never CARGO_INCREMENTAL=0
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked \
        -p casual-sign-server -p casual-sign-worker -p casual-sign-keyd \
 && mkdir -p /out \
 && cp target/release/casual-sign-server target/release/casual-sign-worker \
       target/release/casual-sign-keyd /out/

# ---- wasm: the browser verifier for verify.html (WEB-05) ---------------------------
# casual-sign-wasm built exactly as tools/build-webapp-wasm.sh and tools/wasm-parity.sh
# ship it (wasm-pack 0.14.0, --target web, opt-level "z", fat LTO, no wasm-opt), so the
# server's Verify page runs the same verifier the parity job checks.
FROM ${RUST_IMAGE} AS wasm
RUN rustup target add wasm32-unknown-unknown
# wasm-bindgen's CLI built here at the version Cargo.lock pins (wasm-pack uses it from
# PATH): the prebuilt binary wasm-pack would download needs a newer glibc than Debian 12.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    cargo install wasm-pack --version 0.14.0 --locked \
 && cargo install wasm-bindgen-cli --version 0.2.130 --locked
WORKDIR /src
COPY . .
ENV CARGO_TERM_COLOR=never CARGO_INCREMENTAL=0
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    CARGO_PROFILE_RELEASE_OPT_LEVEL=z CARGO_PROFILE_RELEASE_LTO=true \
    wasm-pack --quiet build crates/casual-sign-wasm --release --target web --no-pack \
        --out-dir /out/pkg -- --locked \
 && mkdir -p /out/openseal-wasm \
 && cp /out/pkg/casual_sign_wasm.js /out/pkg/casual_sign_wasm_bg.wasm /out/openseal-wasm/

# ---- server: the API, the ceremony and the web app ---------------------------------
FROM ${RUNTIME_IMAGE} AS server
COPY --from=build /out/casual-sign-server /usr/local/bin/casual-sign-server
# The web app's files (.dockerignore leaves out its tests); read once at start. The
# verifier comes from the wasm stage; the server sends verify.html alone a policy with
# 'wasm-unsafe-eval' (casual-sign-server src/web.rs, VERIFY_CSP).
COPY webapp /srv/webapp
COPY --from=wasm /out/openseal-wasm /srv/webapp/vendor/openseal-wasm
ENV OPENSEAL_WEBAPP_DIR=/srv/webapp OPENSEAL_LISTEN=0.0.0.0:8080
USER nonroot
EXPOSE 8080
HEALTHCHECK --interval=5s --timeout=5s --retries=24 CMD ["/usr/local/bin/casual-sign-server", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/casual-sign-server"]

# ---- worker: the job runner (email, seal, webhooks) --------------------------------
FROM ${RUNTIME_IMAGE} AS worker
COPY --from=build /out/casual-sign-worker /usr/local/bin/casual-sign-worker
USER nonroot
ENTRYPOINT ["/usr/local/bin/casual-sign-worker"]

# ---- keyd: the key daemon, PKCS#11 (SoftHSM here; an HSM's module in production) ----
FROM ${DEBIAN_IMAGE} AS keyd
RUN apt-get update -q \
 && apt-get install -y -q --no-install-recommends softhsm2 \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --home-dir /var/lib/keyd --create-home keyd
COPY --from=build /out/casual-sign-keyd /usr/local/bin/casual-sign-keyd
COPY --chmod=0755 deploy/keyd/entrypoint.sh /usr/local/bin/keyd-entrypoint
ENV OPENSEAL_KEYD_LISTEN=0.0.0.0:7443 \
    OPENSEAL_KEYD_PKCS11_MODULE=/usr/lib/softhsm/libsofthsm2.so \
    SOFTHSM2_CONF=/var/lib/keyd/softhsm2.conf
USER keyd
WORKDIR /var/lib/keyd
EXPOSE 7443
HEALTHCHECK --interval=5s --timeout=5s --retries=24 CMD ["bash", "-c", "exec 3<>/dev/tcp/127.0.0.1/7443"]
ENTRYPOINT ["/usr/local/bin/keyd-entrypoint"]

# ---- models: the pinned model bundle for modeld (ML-01, ADR-029, docs/33 §8) -------
# The only network use in the ML path. tools/ml/fetch-models.py downloads the chosen
# profiles, checks every file's size and SHA-256 against tools/ml/models.toml, refuses
# any licence outside deny.toml's allow list (save owner instruction 32's scoped
# exception for the ONNX Runtime library), and writes bundle.json. A mismatch fails
# the build. The cache mount only saves downloads; every cached file is re-hashed.
# `docker build --build-arg OPENSEAL_ML_PROFILES="ocr templates" --target modeld .`
# picks profiles. The GLiNER profiles (`personal_data`, `extraction`, `extraction-en`)
# are pinned to the fp16 exports the parity ran on (ML-21) and join the default once
# OpenSeal's mirror serves them (ML-15); until then asking for one fails the build.
FROM ${DEBIAN_IMAGE} AS models
RUN apt-get update -q \
 && apt-get install -y -q --no-install-recommends python3 ca-certificates \
 && rm -rf /var/lib/apt/lists/*
ARG TARGETARCH
ARG OPENSEAL_ML_PROFILES="ocr templates"
COPY tools/ml/fetch-models.py tools/ml/models.toml /src/tools/ml/
RUN --mount=type=cache,target=/var/cache/openseal-models \
    set -- \
 && for p in ${OPENSEAL_ML_PROFILES}; do set -- "$@" --profile "$p"; done \
 && python3 -I /src/tools/ml/fetch-models.py "$@" --arch "${TARGETARCH:-amd64}" \
        --cache /var/cache/openseal-models --dest /out/models \
 && python3 -I /src/tools/ml/fetch-models.py --verify /out/models \
 && mkdir -p /out/state /out/doc \
 && cp /out/models/runtime/ThirdPartyNotices.txt /out/doc/ThirdPartyNotices.txt \
 && cp /out/models/runtime/LICENSE /out/doc/ONNXRUNTIME-LICENSE
COPY deploy/modeld/NOTICE.txt /out/doc/NOTICE.txt

# ---- build-modeld: the model daemon, built on its own -------------------------------
# A separate build so ONNX Runtime's binding, the OCR pipeline and the rasteriser never
# enter the server, worker or keyd builds (ADR-029 review defect 4). The ONNX Runtime
# library itself comes from the bundle above (`load-dynamic`), never from a build-time
# download.
FROM ${RUST_IMAGE} AS build-modeld
RUN apt-get update -q \
 && apt-get install -y -q --no-install-recommends cmake perl g++ make \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
ENV SQLX_OFFLINE=true CARGO_TERM_COLOR=never CARGO_INCREMENTAL=0
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked -p casual-sign-modeld \
 && mkdir -p /out \
 && cp target/release/casual-sign-modeld /out/

# ---- modeld: pretrained models over mTLS, no secrets, no egress (ADR-029) ----------
# The bundle is owned by root and every file is mode 0444, so `nonroot` can read but
# never change a weight; Compose also mounts the root filesystem read-only. modeld
# re-hashes the bundle at start and refuses to serve on any mismatch (CS-ML-0002).
# /var/lib/modeld (the op log) is the only writable path, as a volume.
FROM ${RUNTIME_IMAGE} AS modeld
COPY --from=build-modeld /out/casual-sign-modeld /usr/local/bin/casual-sign-modeld
COPY --from=models /out/models /opt/openseal/models
# ONNX Runtime's licence and ThirdPartyNotices (Eigen MPL-2.0 with a pointer to its
# source, Boost BSL-1.0): owner instruction 32's condition for shipping the binary.
COPY --from=models /out/doc /usr/share/doc/openseal-modeld
COPY --from=models --chown=nonroot:nonroot /out/state /var/lib/modeld
ENV OPENSEAL_MODELD_LISTEN=0.0.0.0:7444 \
    OPENSEAL_MODELD_MODELS=/opt/openseal/models \
    ORT_DYLIB_PATH=/opt/openseal/models/runtime/libonnxruntime.so
USER nonroot
WORKDIR /var/lib/modeld
EXPOSE 7444
ENTRYPOINT ["/usr/local/bin/casual-sign-modeld"]
