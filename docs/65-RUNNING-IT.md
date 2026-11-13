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
| Observability | OTLP endpoint for traces and metrics; alert on seal failures, TSA failover, email bounce rate, job backlog |
| Retention | Set account retention policies before go-live; document them in your records schedule |

## Production deployment (hardened profile, `HRD-06`)

`deploy/compose.production.yml` is the production Compose profile; `docker-compose.yml` stays the evaluation stack.
What the profile guarantees, and `python3 -I tools/check-deploy.py` checks on every CI run (it renders the file with
`docker compose config` and fails naming each `service: rule`; `--self-test` breaks each of its 43 rules in turn and
proves each is caught):

- **Containers.** Every service runs as a named non-root user (Postgres 70, SeaweedFS 1000, keyd 10001, server and
  worker 65532), with a read-only root file system (tmpfs only for sockets and scratch), every capability dropped and
  none added, `no-new-privileges`, memory, CPU and process limits, no core dumps, bounded logs and a health check
  (the worker writes a heartbeat while its database answers, `casual-sign-worker healthcheck`; the one-shot
  `migrate` alone has none). No privileged mode, host namespace or Docker socket. Images are pinned by digest or
  are OpenSeal's own at an `OPENSEAL_VERSION` you built and signed. The server stops on `SIGINT`, which drains it.
- **Secrets** are Docker secrets: files under `/run/secrets/`, each mounted only into the services that read it (the
  seal key's PIN and chain and keyd's identity into keyd alone, never the server), never an environment value (`docker inspect` and `/proc/1/environ` show only paths). Development switches
  (`OPENSEAL_DEV_INSECURE_KEY`, file keys) are refused by the checker.
- **TLS between services.** Postgres serves TLS 1.3 only, with an `hba_file` that has no plain `host` line (only
  `hostssl` and `local`, SCRAM), and the database URLs say `sslmode=verify-full` against the internal CA. The object
  store's S3 gateway serves TLS with a certificate from the internal CA, which the server and worker trust through
  `OPENSEAL_S3_CA`; SeaweedFS's master, volume and filer ports listen on its loopback address only, and its vendor
  telemetry is off (`-master.telemetry=false`, also in the evaluation stack). keyd is mutual TLS (unchanged). SMTP
  is `starttls`. TLS to browsers terminates at your edge proxy (HSTS there), which forwards to the server's port on
  the host's loopback address. The server refuses to start with an `http` `OPENSEAL_PUBLIC_URL` (other than to a
  loopback address) unless `OPENSEAL_DEV_INSECURE_KEY=1`.
- **Networks.** `data` (Postgres, object store, server, worker, migrate) and `signing` (keyd and the worker) are
  internal: no route out. Only the server is on `edge` (its published port) and only the worker on `egress` (SMTP,
  TSAs, webhooks, under the `SEC-W01` address policy). A network HSM needs keyd on a network that routes to the HSM
  alone: add it as an `external` network for keyd only.
- **Configuration integrity** (below): keyd and the worker refuse to start unless their security settings match the
  manifests.

Bringing it up: run `deploy/production/init-secrets.sh DIR` once as root on the Docker host. It writes the internal
TLS CA (its key into `DIR/offline/`: move it off the host), the Postgres, object store, keyd and worker identities,
random passwords, the database URLs, the S3 identities, the token and second-factor keys, and keyd's allow list,
each owned by the one container user that reads it, mode 0400 (Postgres's key 0600). Add what only you have:
`seal-chain.pem` and `keyd-pkcs11-pin` (owner 10001, 0400), `trust-anchors.pem`, `smtp-password` (owner 65532,
0400). Set the variables the file requires (`OPENSEAL_SECRETS_DIR`, `OPENSEAL_VERSION`, `OPENSEAL_PUBLIC_URL`,
`OPENSEAL_TRUSTED_PROXIES`, the PKCS#11 module, token and label, mail, SMTP, TSA and seal name; `docker compose`
names any that is missing), record the manifests, then `docker compose -f deploy/compose.production.yml up -d --wait`.
Checked by running (2026-11-14, Docker 29.8 on macOS): Postgres and the object store start healthy under this profile as
their non-root users; a `verify-full` client gets TLS 1.3, a plain connection is refused (`no pg_hba.conf entry …
no encryption`) and a wrong host name fails verification; the S3 gateway answers TLS 1.3 with the internal CA and
every other SeaweedFS port is closed to the network. The whole stack end to end on this profile, with failure
injection, is `HRD-01`'s.

### Configuration integrity (ASVS 14.1.5, `ASVS-24`)

keyd and the worker read their security settings once, at start, so a change on disk does nothing until a restart.
At start each logs `config NAME sha256:…` for every such setting and `security configuration sha256:…` over them
all: for keyd its TLS certificate, client CA, allow lists, seal chain, PKCS#11 module (the library's bytes), alias,
token and key label; for the worker its trust anchors, TSA list, keyd and model service addresses and CAs, its
client certificates, webhook allowances, object store, SMTP host and SMS gateway. Never a PIN, key or password.
With `OPENSEAL_CONFIG_MANIFEST` (the production profile sets it) the daemon refuses to start, `CS-KEY-0013` naming
the setting, when any setting differs from the manifest, is set but not listed, or is listed but not set. After an
approved change, record the new manifest and replace the secret file:

    docker compose -f deploy/compose.production.yml run --rm --no-deps keyd config-manifest > keyd-config-manifest
    docker compose -f deploy/compose.production.yml run --rm --no-deps worker config-manifest > worker-config-manifest

The console's TSA list is outside the manifest: it is in the database, changed by two key custodians (`CON-07`).

### Rotation (`HRD-06`, `ASVS-28`)

Each runbook keeps signers working throughout; each is exercised by a test, named.

| Secret | How | Downtime | Test |
| --- | --- | --- | --- |
| Database login | Create a second login in `openseal_app` (`CREATE ROLE openseal_2 LOGIN PASSWORD '…' IN ROLE openseal_app`); rewrite `database-url` **in place** (`cat new > database-url`: Docker mounts the file, so a new inode is not seen); the server and worker read it again every `OPENSEAL_SECRET_RELOAD_SECONDS` (30) and open every new connection with it; `ALTER ROLE openseal NOLOGIN` (open sessions continue); after 15 minutes, the pool's connection lifetime, no session of the old login is left (`pg_stat_activity`): `DROP ROLE openseal`. The superuser's `migrate-database-url` changes with the next migration | None | `casual-sign-store` `tests/rotation.rs`: eight signer tasks over a rotation with the old login retired at once, 0 failed requests, every session the new login's within one lifetime; seen red with the reload removed (146 to 223 failed requests) |
| keyd and worker mTLS identities | Issue the new worker certificate from the internal CA (`openssl` as in `init-secrets.sh`); add its fingerprint to `keyd-allow-list` next to the old; record keyd's manifest; restart keyd; switch the worker's `worker-client.key` and chain, record its manifest, restart the worker; remove the old fingerprint, record, restart keyd. keyd's server certificate: issue a new one under the same CA, replace, record, restart. A new CA: list both CAs in `internal-ca.pem` first | Sealing pauses for a keyd restart (seconds); seal jobs retry, signers are not affected | `casual-sign-keyd` `tests/mtls.rs` `a_worker_identity_rotates_with_an_overlap…`; seen red with the allow-list check removed |
| API token signing key (sessions' counterpart for API clients) | Generate a new P-256 key; mount the old one as `OPENSEAL_JWT_PREVIOUS_KEY_FILE` and the new as `OPENSEAL_JWT_SIGNING_KEY_FILE`; restart the server. Tokens signed by the old key verify until they expire and both keys are in `/.well-known/jwks.json`; after `access_token_ttl` (1 hour) remove the previous key | A server restart; staff and signer sessions survive it (they are database rows) | `casual-sign-server` `crypto::tests::a_rotated_key_keeps_the_previous_keys_tokens_valid…`; seen red verifying with the current key only |
| Staff sessions and CSRF tokens | No key to rotate: each session and its CSRF token are random values stored hashed per session (docs/40 §2), unaffected by any key rotation; signing out ends one | — | — |
| Webhook secrets | Provision the new secret as a file (`NAME_FILE`) for the worker; add its reference to the subscription's `secret_refs` (up to 4); deliveries now carry one signature per secret; once the receiver has switched, remove the old reference | None | `casual-sign-worker` `webhook::tests::during_rotation_a_receiver_holding_either_secret_accepts…`; seen red signing with the first secret only |
| Object store credentials | Add a second identity to `s3-identities.json`, restart the store; switch `s3-secret-key` (and the access key) and restart the server and worker; remove the old identity | Server restart | runbook; not yet automated (`HRD-07`) |
| Second-factor key (`OPENSEAL_MFA_KEY`) | Not rotatable yet: staff TOTP seeds are sealed under it; a re-seal path is `HRD-08` | — | — |
| Seal key alias (`CON-10`) | Generate the new key in the HSM and obtain its certificate; serve it beside the current one (`OPENSEAL_KEYD_NEXT_ALIAS`, `_NEXT_PKCS11_KEY_LABEL` or `_KEY_ID`, `_NEXT_CHAIN`), record keyd's manifest, restart keyd; a key custodian proposes the alias with a start (`POST /console/v1/seal/changes`; refused unless keyd serves it with a certificate valid then), a second grants, the first applies; from the start every seal uses it, no restart; once no seal job can still use the old alias, make the new key the only one (`OPENSEAL_KEYD_ALIAS`) and restart keyd | None for signers; keyd restarts pause sealing for seconds, jobs retry | `casual-sign-worker` `tests/keyd.rs` `the_seal_key_follows_the_approved_alias…` (pyHanko agrees on the rotated seal), `casual-sign-console` `tests/keys.rs` `a_seal_alias_change_needs_two_custodians…`, `casual-sign-keyd` `tests/two_keys.rs`; seen red |

A single server is restarted for the token key and object store credentials; run two server replicas behind the edge
proxy for zero-downtime restarts (`HRD-07`).

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
`OPENSEAL_JWT_PREVIOUS_KEY` (during a rotation), `OPENSEAL_S3_CA` (also the worker's), `OPENSEAL_SECRET_RELOAD_SECONDS`
(also the worker's),
`OPENSEAL_MFA_KEY` (32 random bytes as base64, sealing staff TOTP seeds; keep it with the database backups, since a
seed sealed under a lost key cannot be opened and its users must enrol again; ASVS-01); `migrate` reads
`OPENSEAL_MIGRATE_DATABASE_URL`. The worker's SMS and voice gateway is `OPENSEAL_SMS_GATEWAY_URL` and
`OPENSEAL_SMS_GATEWAY_SECRET`; its model service `OPENSEAL_MODELD_ADDR` with `OPENSEAL_MODELD_CA`,
`_CLIENT_CERT`, `_CLIENT_KEY` and `_SERVER_NAME`; its health file `OPENSEAL_HEALTH_FILE`. keyd and the worker check
`OPENSEAL_CONFIG_MANIFEST` (above). keyd's read-only admin operations answer only the certificates on
`OPENSEAL_KEYD_ADMIN_ALLOW_LIST`, which must not overlap its signing list (`CON-06`).

## Upgrades

Rolling: migrations are forward-compatible for one release, so old and new nodes run together during a deploy. Never
skip a minor version without reading the release notes.
