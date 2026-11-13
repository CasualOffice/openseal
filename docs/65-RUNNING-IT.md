# 65 — Running it

**Status:** the single-node stack runs (stage 2F, `T-2F`, 2026-11-11); the cluster (slice 20) is design. How an
operator deploys OpenSeal. Adapted in shape from OpenCalc's docs/65.

## Single node (evaluation and development)

From a checkout, with Docker (Compose v2):

```sh
docker compose up -d --build --wait          # builds the images, waits until every service is healthy
docker compose exec -e OPENSEAL_ADMIN_PASSWORD='a long passphrase' server \
    casual-sign-server bootstrap "Acme" admin@acme.example "Ada Admin"     # the first account and administrator
open http://localhost:8080                   # the web app: sign in as admin@acme.example
open http://localhost:8025                   # Mailpit: every email the stack sends (signing links, completions)
docker compose logs -f server worker         # what it is doing
docker compose down -v                       # stop, and discard every volume (data, keys, mail)
```

**Released images instead of building:** `OPENSEAL_IMAGE_PREFIX=ghcr.io/casualoffice/openseal OPENSEAL_VERSION=0.0.1 docker compose up -d --wait`
pulls the published v0.0.1 images (`docker compose pull` first) rather than building from source.

`bootstrap` prints the account and administrator ids; run it once (a second run with the same email is refused).
Ports bind to `127.0.0.1` only: `OPENSEAL_HTTP_PORT` (default 8080) and `OPENSEAL_MAIL_PORT` (default 8025) move them.

| Service | Image | What it does |
| --- | --- | --- |
| `pki` | `deploy/devtools/Dockerfile` | One-shot, first start only: a development CA; keyd's TLS and the worker's client certificate; the seal key and certificate; a TSA certificate; the API token key; random database, S3 and SoftHSM passwords. Written to the `secrets` volume, which every other service mounts read-only. Nothing is baked into an image |
| `postgres` | `postgres:17-alpine` | The database; `deploy/postgres/10-openseal-roles.sh` creates the login role `openseal` (member of `openseal_app`, owns nothing, so row-level security binds it) |
| `migrate` | the server image, `casual-sign-server migrate` | One-shot: every migration, as the schema owner, before the server starts |
| `s3` | `chrislusf/seaweedfs` | S3-compatible blob store (bucket `openseal`, created by the server). MinIO no longer publishes images, so SeaweedFS, as CI's store tests |
| `mailpit` | `axllent/mailpit` | Catches all email; web UI and API at <http://localhost:8025> |
| `keyd` | `deploy/Dockerfile` target `keyd` | The key daemon over mTLS; the seal key in a SoftHSM token, imported from the generated key on first start |
| `tsa` | `deploy/devtools/Dockerfile` | A development RFC 3161 time-stamping authority (`openssl ts -reply`) |
| `server` | `deploy/Dockerfile` target `server` (distroless, `nonroot`) | The API, the ceremony and the web app (`webapp/`) on port 8080 |
| `worker` | `deploy/Dockerfile` target `worker` (distroless, `nonroot`) | Email through Mailpit, sealing through keyd and the TSA, webhooks |
| `modeld` (profile `ml` only) | `deploy/Dockerfile` target `modeld` (distroless, `nonroot`) | Pretrained models, on an internal network; see §Pretrained models. The image builds; the worker is not yet on its network (`ML-09`) |

Every image is pinned by digest (docs/04 rule 31). **This stack is for evaluation and development only:** its keys are
generated on the machine, its CA is trusted by nothing else, its seals are development seals, and the server sends
cookies over plain HTTP (`OPENSEAL_DEV_INSECURE_KEY=1`). A sealed PDF from it validates against the generated root
(`docker compose exec keyd cat /secrets/ca.pem`), not in Acrobat.

**End-to-end test on the stack** (`E2E-01`, Phase 2 exit item 1; CI job `compose-e2e`, `tools/ci-local.sh`):

```sh
docker compose up -d --build --wait
docker compose exec -e OPENSEAL_ADMIN_PASSWORD=e2e-only-passphrase server \
    casual-sign-server bootstrap "E2E" e2e@openseal.test "E2E Admin"
cd webapp/e2e && npm ci && npx playwright install chromium
OPENSEAL_E2E_BASE_URL=http://localhost:8080 OPENSEAL_E2E_EMAIL=e2e@openseal.test \
    OPENSEAL_E2E_PASSWORD=e2e-only-passphrase npx playwright test --project=chromium
cd ../.. && docker compose exec -T keyd cat /secrets/ca.pem > target/e2e-sealed/trust-root.pem
target/tools-venv/bin/python tools/verify-sealed.py target/e2e-sealed     # pyHanko over the sealed PDF and certificate
```

## Pretrained models (optional, Compose profile `ml`)

**Status:** the bundle tooling is built and checked (`ML-01`), and `casual-sign-modeld` is built with its OCR, HASH,
EMBED, ENTITIES and PERSONAL operations (`ML-02`, `ML-05`, `ML-07`, `ML-08`, `ML-09`). The worker's analysis jobs call it
when `OPENSEAL_MODELD_ADDR` is set (`WEB-19`), but the Compose file does not yet put the worker on the `ml` network,
so in this stack nothing reaches it; that run is `ML-09`'s exit (ADR-029, docs/33).

Assistive features (OCR of scanned pages, template matching, personal-data highlights) run in a separate process,
`modeld`. It holds no secrets other than its own TLS identity: it never mounts the shared `secrets` volume, only its
own `modeld-secrets`, into which `pki` writes modeld's certificate chain and key, the root certificate and its allow
list (the worker's certificate), nothing else. `python3 -I tools/ml/check-modeld-isolation.py` checks the Compose
mounts and what `dev-pki` writes. It sits only on the Compose network `ml`, which is
`internal: true` and so has no route out. Its root filesystem is read-only, it has a 4 GiB memory limit and a limit
of 256 processes, core dumps are off, and every capability is dropped. All of it is off unless the profile is asked
for: `docker compose --profile ml up -d --build`.

The weights and the ONNX Runtime library are fetched once, while the image builds, by `tools/ml/fetch-models.py`.
Every file is pinned in `tools/ml/models.toml` by source revision, SHA-256 and size. The build fails on any mismatch,
and on any licence that is not on deny.toml's allow list. Files are baked into the image read-only (`0444`, owned
by root), and modeld hashes them again at start. The one licence exception is described below. `OPENSEAL_ML_PROFILES` chooses the profiles (the default is
`ocr templates`); `runtime` is always added.

| Profile | What | Size |
| --- | --- | ---: |
| `runtime` | ONNX Runtime 1.28.3, CPU (MIT, bundling MPL-2.0 Eigen and BSL-1.0 Boost), with its `LICENSE` and `ThirdPartyNotices.txt` | 24.6 MB |
| `ocr` | PP-OCRv6 small detection and recognition (Apache-2.0) | 31.2 MB |
| `templates` | multilingual-e5-small, fp32 (MIT) | 487.4 MB |
| `templates-small` | all-MiniLM-L6-v2, fp32, English (Apache-2.0) | 90.9 MB |
| `personal_data`, `extraction`, `extraction-en` | GLiNER-PII base (English), GLiNER multi-v2.1 and small-v2.1 (English), our fp16 exports (Apache-2.0): pinned by SHA-256 to the files the parity tests ran on, but not hosted until OpenSeal's mirror holds them (`ML-15`); asking for them fails, and modeld answers `CS-ML-0010` for a model it does not have | 333.0 MB, 579.7 MB, 306.2 MB (models) |
| `ocr-arabic`, `ocr-devanagari`, `ocr-orientation` | Pending: built by offline exports, not yet pinned; asking for them fails | — |

The default bundle is 543.2 MB. Caps are 1 GiB per file and 2 GiB per bundle.

**Air-gapped hosts.** On a connected machine, run
`python3 -I tools/ml/fetch-models.py --profile ocr --profile templates --arch x86_64 --dest DIR`. Copy `DIR` across,
check it there with `python3 -I tools/ml/fetch-models.py --verify DIR`, and mount it read-only at
`/opt/openseal/models`. `--verify` re-hashes every file against the manifest, and refuses a symlink, a file the bundle
does not list, and a bundle missing any manifest file of the profiles it names; modeld checks the same again at start.

**Licence note.** The ONNX Runtime binary is MIT, and bundles third-party code listed in its `ThirdPartyNotices.txt`,
including Eigen (MPL-2.0) and Boost (BSL-1.0). Neither licence is on the allow list. Owner instruction 32 allows them
inside the unmodified ONNX Runtime library in the modeld image only. `models.toml` records this as
`licence = "MIT AND MPL-2.0 AND BSL-1.0"` with `licence_exception = "owner-instruction-32"` on the two library
entries, and `fetch-models.py` honours that exception for those entry ids alone, and only in a bundle that also holds
`ThirdPartyNotices.txt` from the same archive. The image carries the notices in `/usr/share/doc/openseal-modeld/`
(`NOTICE.txt`, which points to the Eigen revision's source; `ThirdPartyNotices.txt`; `ONNXRUNTIME-LICENSE`), and
beside the library in `/opt/openseal/models/runtime/`.

## Platform console (operators)

The console (`casual-sign-console`, docs/23 §5) is a separate binary for the people who run a deployment: health,
organizations, approvals, keys and certificates, timestamp authorities, plans, operators and the operator log. It is
**not yet a Compose service or a release image** (`CON-02`); build it with `cargo build --release -p
casual-sign-console` and run it beside the stack. It connects to PostgreSQL as a LOGIN role that is a member of
`openseal_console` (created by the migrations, with no grant on the application's tables), never as the application's
role, and listens on `127.0.0.1:8090` unless told otherwise; a non-loopback bind needs `OPENSEAL_CONSOLE_PUBLIC=1` and
`OPENSEAL_TRUSTED_PROXIES`, with TLS at the proxy, and its origin must differ from the web app's.

```sh
casual-sign-console bootstrap-operator owner@ops.example    # the first platform owner: prints a one-time enrolment token
casual-sign-console serve                                   # verifies the operator log first, refuses to start if it does not verify
casual-sign-console verify-log
casual-sign-console set-service-target <name> <role> <http|tcp> <target>    # what the health page probes (as the schema owner)
```

Its settings (`server/casual-sign-console/src/main.rs`): `OPENSEAL_CONSOLE_DATABASE_URL` and `OPENSEAL_CONSOLE_MFA_KEY`
(32 bytes, base64, sealing operators' TOTP seeds) as secrets; `OPENSEAL_CONSOLE_LISTEN`, `OPENSEAL_CONSOLE_ORIGIN`;
`OPENSEAL_CONSOLE_KEYD_ADDR`, `_KEYD_CA`, `_KEYD_CLIENT_CERT`, `_KEYD_CLIENT_KEY` and `_KEYD_SERVER_NAME` for the Keys
page, with the console's certificate on keyd's admin allow list only; `OPENSEAL_CONSOLE_TSA_ALLOW` for TSA addresses
that are not public. Operators sign in with a password and a mandatory TOTP code; risky changes (suspending an
organization, a TSA change) need a second operator's approval.

## Production checklist

| Area | Do |
| --- | --- |
| Signing key | Obtain a document-signing certificate from an AATL member CA (or a qualified seal certificate for eIDAS) with its key generated in your HSM or cloud KMS; configure `keyd` with PKCS#11 or the KMS backend; never a file key ([09](09-LEGAL-AND-COMPLIANCE.md) §7) |
| Timestamps | Configure at least two RFC 3161 TSAs with an SLA (qualified, if you need eIDAS qualified time). Key custodians add and change them in the platform console, two people per change (`CON-07`); the worker reads them from the database and falls back to `OPENSEAL_TSA_URLS` when none is configured |
| Email | A sending domain with SPF, DKIM and DMARC (`p=quarantine` or stricter); a provider plugin or SMTP relay; bounce handling webhook |
| SMS / IDV / payments | Enable only the providers you have contracts with. SMS and voice one-time codes (`sms_otp`, `voice_otp`) go through an HTTPS gateway you run or rent: set `OPENSEAL_SMS_GATEWAY_URL` and `OPENSEAL_SMS_GATEWAY_SECRET` (or `_FILE`) on the worker; it posts `{"channel":"sms"\|"voice","to":"+…","text":"…","id":"…"}` with `Authorization: Bearer`. Unset, such codes are never sent (`CS-WRK-0013`). Recipient sign-in through an identity provider (`sso`): list the OpenID Connect providers signers may use in a JSON file named by `OPENSEAL_RECIPIENT_IDPS_FILE` on the server, `{"providers": [{"id", "name", "issuer", "authorization_endpoint", "token_endpoint", "jwks_uri", "client_id", "client_secret", "redirect_uri"?}]}`; it holds client secrets, so mount it as a secret. Register `{OPENSEAL_PUBLIC_URL}/s/oidc` (the default `redirect_uri`) with each provider, with the `openid email` scopes. Endpoints must be HTTPS (HTTP only to a loopback address). Unset, `sso` cannot pass (`CS-API-0014`) |
| Database | PostgreSQL 15+, encrypted, PITR backups, a separate role for migrations; the application role has no `UPDATE`/`DELETE` on `audit_events` |
| Object store | S3-compatible, versioning on, encryption on; Object Lock (compliance mode) for regulated tenants |
| Edge | TLS 1.2+ (1.3 preferred), HSTS, a WAF if you have one; `OPENSEAL_PUBLIC_URL` must be HTTPS |
| Trust | Bundle your organization's roots for verification; enable the EU LOTL if you verify EU signatures |
| ERSD | Have counsel review the consumer disclosure for your jurisdictions before sending to consumers |
| Observability | Ship the logs off the box (§Logs: `deploy/compose.log-forwarding.yml`, syslog over mutual TLS) and set `OPENSEAL_LOG_PSEUDONYM_KEY` on the server and the console; alert on the security events §Logs lists, seal failures, `transport.backend_failed` (keyd, TSA failover), email bounce rate and job backlog. OTLP traces and metrics are not built yet (`CON-11`) |
| Retention | Set account retention policies before go-live; document them in your records schedule |

## Logs

**One format.** The server, worker, keyd, modeld and console write one JSON object per line to standard error
(`server/casual-sign-seclog`, `ASVS-08`): `ts` (RFC 3339, UTC), `level` (`DEBUG`, `INFO`, `WARN`, `ERROR`), `service`
(`server`, `worker`, `keyd`, `modeld`, `console`), `event`, then the event's fields. The server's access log is
`"event":"request"` with `request_id`, `method`, `route` (the template, never the path), `status` and `ms`. `RUST_LOG`
filters the server's and console's operational lines (default `info`); modeld's filter is fixed (docs/33 §3.4). No
line carries a name, an e-mail address, a client address, a token, a password or document text (`SEC-D01`,
`SEC-D06`).
A process's own lines are JSON too: `start_failed` (`ERROR`, with `code` where there is one and the setting that
failed) whenever a binary does not start, and `development_token_key`, `development_mfa_key` (server) and
`development_file_key` (keyd) as `WARN` lines when a development key is in use; alert on these in production.

**Security events** are `"event":"security"` lines, never filtered by `RUST_LOG`, with `kind`, `outcome` (`success`,
`failure`; a failure is `WARN`), and where known `request_id`, `route`, `code` (docs/20), `account_id`, `principal`
and `client`:

| `kind` | Emitted by | When |
| --- | --- | --- |
| `auth.sign_in` | server, console | A password sign-in passed or was refused (`via: password`) |
| `auth.sign_out` | server, console | A session ended by its holder |
| `auth.mfa` | server, console | A second factor checked (`factor: totp` or `recovery_code`); `reason: reused` for a code of a time step already used (ASVS 2.8.5) |
| `auth.mfa_enrol` | server, console | A TOTP factor confirmed, or its confirmation refused |
| `auth.password_reset_request`, `auth.password_reset`, `auth.password_change` | server | Reset asked for (alike for any address), a reset link spent or refused, a password changed or the current one refused |
| `auth.invite_accept` | server | An invitation link spent or refused |
| `auth.token` | server | An OAuth client-credentials token issued or refused |
| `auth.lockout` | server | A recipient locked out by failed authentications, and each later request refused for it (`CS-AUTH-0004`) |
| `access.unauthenticated`, `access.denied`, `access.rate_limited` | server, console (keyd: denied, rate limited) | Every `401`, `403` and `429`; keyd: an admin operation asked by a signing caller, a signature over the caller's rate |
| `input.upload_refused` | server | An upload over its size (`413`) or refused by admission (its `CS-PDF-*` or other admission code) |
| `admin.change` | server, console | A committed change on an administrative route (users, groups, profiles, API clients, webhooks, account and organization settings; every console change), with `method` and the `objects` (ids) the path named |
| `data.document_read` | server | A staff read of a document, the combined PDF, the certificate, an attachment, form data, an audit trail, a document's analysis, the suggestions analysis found (values read from the text) or the envelope's fields with their values (ASVS 8.3.5), with the `objects` |
| `key.use` | keyd | A signature or a chain given or refused (`op`, `alias`, `envelope_id`; never the digest) |
| `transport.caller_refused` | keyd, modeld | An mTLS caller refused: a failed handshake (`reason: handshake`) or a certificate off the allow list (`reason: not_allowed`, named by fingerprint) |
| `transport.backend_failed` | worker | keyd not reached or refusing (its `CS-KEY-*` code) or a time-stamping authority not answering (`CS-WRK-0018`, `backend: tsa`, its `index` in the list and a `reason`: `connect`, `tls`, `timeout`, `status`, `answer`, `address_refused`; never its URL) |

`principal` is `user:<id>`, `client:<id>`, `operator:<id>`, `recipient:<id>`, `caller:<fingerprint>`, or, for an
identifier presented before anyone is known (the e-mail of a refused sign-in, a client id that matched nothing),
`subject:p1:<32 hex>`: HMAC-SHA-256 of the value under `OPENSEAL_LOG_PSEUDONYM_KEY`. `client` is the client address
the same way. Set the key (32 random bytes as base64, or `OPENSEAL_LOG_PSEUDONYM_KEY_FILE`) to the same value on the
server and the console so the same address gives the same pseudonym in both and across restarts; unset, each process
draws its own. A malformed key stops every service that reads it (server, console, worker, keyd and modeld, each with
a `start_failed` line, `CS-LOG-0001`). Whoever holds the key and a candidate address
can confirm it, so keep the key with the other secrets, not with the logs.

**Shipping them off the box** (ASVS 1.7.2). The processes open no log socket: the container runtime ships what they
write. `deploy/compose.log-forwarding.yml` switches every service to Docker's `syslog` driver over mutual TLS
(RFC 5425 transport, RFC 5424 messages tagged `openseal/<container>`, facility `authpriv`, non-blocking with a 4 MB
buffer):

```sh
OPENSEAL_SYSLOG_ADDRESS=tcp+tls://logs.example.internal:6514 \
OPENSEAL_SYSLOG_CA=/etc/openseal/syslog/ca.pem \
OPENSEAL_SYSLOG_CERT=/etc/openseal/syslog/client.pem \
OPENSEAL_SYSLOG_KEY=/etc/openseal/syslog/client.key \
docker compose -f docker-compose.yml -f deploy/compose.log-forwarding.yml up -d
```

All four are required (Compose refuses to start without them) and the three files are read by the Docker daemon on
the host. The collector can be rsyslog or syslog-ng with a TLS listener, or an OpenTelemetry Collector whose `syslog`
receiver (`tcp` with `tls`, `protocol: rfc5424`) forwards as OTLP to your log platform; each message's body is the
JSON line. On Kubernetes, the node's log agent (Fluent Bit, the OpenTelemetry Collector's `filelog` receiver) reads the
same lines from the container runtime and sends them over TLS. `docker compose logs` reads nothing once the syslog
driver is on: read the collector. Alert on: `auth.sign_in` failures per `principal` or `client`, `auth.lockout`,
`auth.mfa` with `reason: reused`, `access.denied` bursts, `transport.caller_refused`, `transport.backend_failed`, and
on the collector receiving nothing from a service for five minutes (a dropped buffer is otherwise silent). Checked:
`docker compose -f docker-compose.yml -f deploy/compose.log-forwarding.yml --profile ml config` gives every service
the driver with these options (2026-11-14); a delivery to a live TLS collector is to be shown on a Linux host
(`ASVS-08A`).

## Configuration

All configuration through environment variables; every secret also accepted as `NAME_FILE` (the sisters'
`-secrets` rule: both set is an error). Each binary's module documentation lists its variables
(`server/casual-sign-server/src/main.rs`, `-worker`, `-keyd`); `docker-compose.yml` sets the ones the stack needs and leaves the optional ones unset
(`OPENSEAL_MFA_KEY`, where `OPENSEAL_DEV_INSECURE_KEY` draws a throwaway key instead, `OPENSEAL_RECIPIENT_IDPS_FILE`,
`OPENSEAL_TRUSTED_PROXIES`, `OPENSEAL_GEOIP_DB`, the SMS gateway, the model service, `OPENSEAL_WEBHOOK_ALLOW` and
`OPENSEAL_KEYD_ADMIN_ALLOW_LIST`, checked 2026-11-13, `DOC-008`). A list
generated from the code into this page is still to come. The server's: `OPENSEAL_DATABASE_URL`,
`OPENSEAL_JWT_SIGNING_KEY`, `OPENSEAL_BLOB_DIR` or `OPENSEAL_S3_*`, `OPENSEAL_PUBLIC_URL`, `OPENSEAL_LISTEN`,
`OPENSEAL_TRUSTED_PROXIES`, `OPENSEAL_GEOIP_DB`, `OPENSEAL_WEBAPP_DIR`, `OPENSEAL_RECIPIENT_IDPS_FILE`,
`OPENSEAL_LOG_PSEUDONYM_KEY` (§Logs; also the console's),
`OPENSEAL_MFA_KEY` (32 random bytes as base64, sealing staff TOTP seeds; keep it with the database backups, since a
seed sealed under a lost key cannot be opened and its users must enrol again; ASVS-01); `migrate` reads
`OPENSEAL_MIGRATE_DATABASE_URL`. The worker's SMS and voice gateway is `OPENSEAL_SMS_GATEWAY_URL` and
`OPENSEAL_SMS_GATEWAY_SECRET`; its model service `OPENSEAL_MODELD_ADDR` with `OPENSEAL_MODELD_CA`,
`_CLIENT_CERT`, `_CLIENT_KEY` and `_SERVER_NAME`. keyd's read-only admin operations answer only the certificates on
`OPENSEAL_KEYD_ADMIN_ALLOW_LIST`, which must not overlap its signing list (`CON-06`).

## Upgrades

Rolling: migrations are forward-compatible for one release, so old and new nodes run together during a deploy. Never
skip a minor version without reading the release notes.
