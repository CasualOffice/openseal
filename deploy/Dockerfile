# syntax=docker/dockerfile:1
# OpenSeal's images (T-2F, docs/65): one build, three targets.
#
#   docker build -f deploy/Dockerfile --target server .
#   docker build -f deploy/Dockerfile --target worker .
#   docker build -f deploy/Dockerfile --target keyd .
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

# ---- server: the API, the ceremony and the web app ---------------------------------
FROM ${RUNTIME_IMAGE} AS server
COPY --from=build /out/casual-sign-server /usr/local/bin/casual-sign-server
# The web app's files (.dockerignore leaves out its tests); read once at start.
COPY webapp /srv/webapp
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
