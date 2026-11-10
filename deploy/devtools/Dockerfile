# syntax=docker/dockerfile:1
# Development helpers for the Compose stack (T-2F), never for production:
#   - dev-pki.sh: a throwaway CA, keyd's TLS and the worker's client certificate, the
#     seal key and certificate, a time-stamping authority's, the token key and random
#     passwords, written once into the `secrets` volume at first start.
#   - dev-tsa.py: an RFC 3161 time-stamping authority over HTTP, answering with
#     `openssl ts -reply` (the cryptography is OpenSSL's; this only carries bytes).
# Pinned by digest (docs/04 rule 31).
ARG DEBIAN_IMAGE=debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc
FROM ${DEBIAN_IMAGE}
RUN apt-get update -q \
 && apt-get install -y -q --no-install-recommends openssl python3 \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10002 --home-dir /var/lib/tsa --create-home tsa
COPY deploy/devtools/dev-pki.sh /usr/local/bin/dev-pki
COPY deploy/devtools/dev-tsa.py /usr/local/bin/dev-tsa
COPY deploy/devtools/tsa.cnf /etc/openseal/tsa.cnf
