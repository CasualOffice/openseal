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

**Released images instead of building:** `OPENSEAL_IMAGE_PREFIX=ghcr.io/casualoffice/openseal OPENSEAL_VERSION=0.1.0 docker compose up -d --wait`
pulls that release's published images (`docker compose pull` first) rather than building from source. v0.1.0 is the
first release built by the signed release workflow below (prepared 2026-11-19, published when its tag runs); v0.0.1's
images (`OPENSEAL_VERSION=0.0.1`) are the earlier, unsigned pre-release.

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
export COMPOSE_FILE=docker-compose.yml:tools/e2e/compose.e2e.yml   # test stubs (below); test only
docker compose up -d --build --wait
docker compose exec -e OPENSEAL_ADMIN_PASSWORD=e2e-only-passphrase server \
    casual-sign-server bootstrap "E2E" e2e@openseal.test "E2E Admin"
cd webapp/e2e && npm ci && npx playwright install chromium
OPENSEAL_E2E_BASE_URL=http://localhost:8080 OPENSEAL_E2E_EMAIL=e2e@openseal.test \
    OPENSEAL_E2E_PASSWORD=e2e-only-passphrase npx playwright test --project=chromium
cd ../.. && docker compose exec -T keyd cat /secrets/ca.pem > target/e2e-sealed/trust-root.pem
target/tools-venv/bin/python tools/verify-sealed.py target/e2e-sealed     # pyHanko over the sealed PDF and certificate
```

**Recipient authentication in the test stack** (`RAUTH-02`, slice 5; test only). The CI-only overlay
`tools/e2e/compose.e2e.yml` adds two stand-ins for providers an operator brings, so `e2e/recipient-auth.spec.mjs` runs
its access code, emailed, texted and spoken codes, and identity-provider sign-in against the real server. Never deploy
it: it accepts any number and any typed email. Neither `docker-compose.yml` nor `deploy/compose.production.yml` names
it (`tools/e2e/test_auth_stubs.py` checks this; `tools/check-deploy.py` is unchanged).

- `sms-gateway` (`tools/e2e/auth_stubs.py sms`): the worker's `OPENSEAL_SMS_GATEWAY_URL` contract, over HTTPS with a
  certificate the development root issues at start (the worker trusts that root through `SSL_CERT_FILE` in the
  overlay). It keeps what it receives in memory and serves it, as Mailpit serves mail, at
  `http://127.0.0.1:8026/messages?to=+…` (`OPENSEAL_E2E_SMS_PORT`, `OPENSEAL_E2E_SMS_URL` for the spec).
- `oidc` (`auth_stubs.py oidc`): an OpenID Connect provider for `tools/e2e/recipient-idps.json`, the server's
  `OPENSEAL_RECIPIENT_IDPS_FILE` in the overlay. It runs in the server container's network namespace, so the server
  reaches its token and JWKS endpoints on the loopback address and the browser its sign-in page at
  `http://localhost:8090`. The page asks only for an email; the ID token (RS256, a key OpenSSL draws at start) asserts
  it as verified, with the request's nonce, after checking the client secret, the redirect URI and the PKCE verifier.

The stubs' tests run without Docker: `python3 -I -m unittest discover -s tools/e2e -p 'test_*.py'`. The run on the
stack records the signer's screens into `target/e2e-demo/vs05-*.webm`, uploaded by `compose-e2e` as `slice-5-demo`.

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

## Malware scanning (Compose profile `production`)

Every upload (an envelope's or a template's document, a signer's attachment, an adopted signature image, a saved
profile mark) can be scanned by ClamAV before the server reads or stores it (`ASVS-11`, docs/07 `SEC-P17`). The
server speaks clamd's `INSTREAM` protocol over TCP to a `clamav` container (`clamav/clamav-debian:1.4`, pinned by
digest; the Debian build has arm64 images), which also runs freshclam to keep its signatures current in the `clamav`
volume, so it needs outbound HTTPS to the ClamAV mirrors. Its port is never published.

```sh
OPENSEAL_CLAMD_ADDR=clamav:3310 docker compose --profile production up -d --build --wait
```

clamd loads its signatures for up to a few minutes after a start (the container's health check allows six) and holds
about 1 GB of memory, about twice that while it reloads new signatures (the service's limit is 3 GB). The server's settings:

| Variable | Default | Meaning |
| --- | --- | --- |
| `OPENSEAL_CLAMD_ADDR` | unset | clamd's `host:port`. Unset or empty: nothing is scanned, and the server warns at start |
| `OPENSEAL_CLAMD_TIMEOUT_SECS` | 60 | Most seconds one scan may take, waiting for a slot included (1 to 600) |
| `OPENSEAL_CLAMD_MAX_BYTES` | 104857600 | Largest file sent; keep it equal to clamd's `StreamMaxLength` (`CLAMD_CONF_StreamMaxLength: 100M` in Compose). The server refuses to start when it is below the 50 MiB document limit |
| `OPENSEAL_CLAMD_CONCURRENCY` | 4 | Scans at once (1 to 64); keep it under clamd's `MaxThreads` (10) |
| `OPENSEAL_CLAMD_FAIL_OPEN` | 0 | `1` admits an upload clamd could not judge instead of refusing it |

What happens:

- **Malware:** `422 CS-SCAN-0001`; nothing of the file is stored; the workspace's admin log (`GET /admin-events`)
  gets `upload.malware_refused` with the kind of upload, the envelope, template, recipient, field or user it was
  for, the scanner's signature name, the file's SHA-256 and length. Never its name or content.
- **Clean:** the upload goes on to admission as before; a document's admission report says `"malware_scan":
  "clean"`, and the envelope's audit chain binds that report's hash.
- **clamd cannot judge it** (not reachable, timeout, larger than it takes, an error, an answer that is not
  clamd's): by default `503 CS-SCAN-0002` with `Retry-After: 30`, recorded as `upload.unscanned_refused` with the
  reason. With `OPENSEAL_CLAMD_FAIL_OPEN=1` the upload is admitted, recorded as `upload.unscanned_admitted`, and a
  document's report says `"malware_scan": "unscanned"`. Fail-open trades this control for availability; alert on
  `upload.unscanned_*` events and on the server's `upload not scanned` warnings if you choose it.
- **Waiting:** a request waits for its scan holding no database connection or lock, so a slow or stopped clamd delays
  uploads (up to `OPENSEAL_CLAMD_TIMEOUT_SECS`) without starving other requests of the server's 16 connections.
- **Bulk send** scans its template's documents again on each send call that has rows pending (a template may be
  older than the scanner): malware sends nothing and is recorded with the template and the batch.

Signature scanning finds known malware only. The PDF pipeline still removes active content, embedded files and
external references from every document whatever the scanner says (docs/07 `SEC-P06` to `SEC-P08`). To check a
deployment, upload the EICAR test file (the 68-byte string from eicar.org) as a document: it must be refused with
`CS-SCAN-0001` and appear in the admin log. The server's tests run the same check against a real clamd when
`OPENSEAL_TEST_CLAMD_ADDR` names one (`server/casual-sign-server/tests/malware.rs`); CI does not set it yet (`SCAN-04`).

## Word conversion (`convertd`, ADR-042)

Word documents (`.docx`) uploaded to an envelope or a template are converted to PDF by `convertd`, a service of the
development stack and of the production profile (`VS-06C`). It runs `docxide-pdf` (Apache-2.0) in a fresh child
process for each document, with no network at all (`network_mode: none`), no secrets, a read-only root, every
capability dropped, and memory (3 GB), CPU (2) and process (64) limits; each child is further capped at 2 GiB of
address space and 60 seconds and writes no file (docs/07 `SEC-P13`, docs/21 §DOCX conversion). The server reaches it
over a Unix socket on the `convertd` volume, which only the server's containers mount. Macro-enabled documents are
refused; links to pictures or pages outside the document are never fetched. The original `.docx` is kept as the
document's original version; the converted PDF is what recipients see and sign.

| Variable | Service | Default | Meaning |
| --- | --- | --- | --- |
| `OPENSEAL_CONVERTD_SOCKET` | server | unset | The socket (`/run/convertd/convertd.sock` in Compose). Unset: Word uploads are refused (`415 CS-CNV-0002`), and the server warns at start |
| `OPENSEAL_CONVERTD_TIMEOUT` | server | 90 | Most seconds the server waits for one conversion (1 to 600) |
| `OPENSEAL_CONVERTD_SOCKET` | convertd | `/run/convertd/convertd.sock` | Where it listens; owner-only permissions |
| `OPENSEAL_CONVERTD_SLOTS` | convertd | 2 | Conversions at once (1 to 64); more are refused at once (`503 CS-CNV-0005 busy`) |
| `OPENSEAL_CONVERTD_JOB_SECONDS` | convertd | 60 | Wall-clock and CPU seconds per document (1 to 600) |
| `OPENSEAL_CONVERTD_MEMORY` | convertd | 2048 | A child's address-space limit in MiB (256 to 16384) |
| `OPENSEAL_CONVERTD_FONTS` | convertd | unset | A font directory searched before the image's own |

The image ships Debian's Croscore fonts (Arimo, Tinos, Cousine; Apache-2.0), metric-compatible with Arial, Times New
Roman and Courier New. Word's own fonts (Calibri, Cambria) are not shipped: a document set in them is drawn in the
Croscore faces, so its lines may break differently from Word's (`VS-06G`). To add fonts you are licensed to use, mount
a directory read-only into the container and set `OPENSEAL_CONVERTD_FONTS`. Each conversion logs one line with its
code, reason and milliseconds, never a name or content. To check a deployment, upload a `.docx` as a document: it is
admitted with the PDF's page count, and `GET …/content?version=original` answers the Word document.

## Failure recovery

What each failure leaves, and what brings the deployment back (`HRD-01`; tested in
`server/casual-sign-worker/tests/process_crash.rs` with the real server and worker binaries, keyd over mTLS, a TSA
and PostgreSQL 17). In every case an envelope ends `completed` on one verified seal or waits safely in
`completing`; nothing sealed is served before the envelope is `completed`; the audit chain verifies.

| Failure | What happens | What brings it back |
| --- | --- | --- |
| Worker killed (crash, OOM, `SIGKILL`) at any point of a job | The job's lease (300 s) lapses and any worker claims it again; an act already recorded is not repeated (docs/24 §Idempotency and crashes) | A restart of the worker process: Compose restarts it (`restart: unless-stopped`); under another orchestrator run it as a service that restarts on exit |
| Worker paused or partitioned past its lease while another takes its job over | The paused worker records nothing when it resumes: storing a seal first renews the job's lease in the same transaction, which fails for a lease it lost (`CS-WRK-0015`); the other worker seals once | Nothing |
| keyd unreachable while sealing | The seal fails (`CS-SEAL-0001`, or `CS-KEY-0011` if the worker never reached keyd); the engine raises a `seal_failed` operator alert and schedules a new seal job 60 s later, again and again; the envelope stays `completing`. A worker started while keyd is down (refused, reset, timed out, closed before TLS answered: `CS-KEY-0011`) still starts (it logs `keyd_unavailable`) and runs every other job. A keyd that refuses the worker is a configuration error, not an outage: a TLS refusal (`CS-KEY-0013`: `OPENSEAL_KEYD_CA` or `OPENSEAL_KEYD_SERVER_NAME` not keyd's, the client certificate untrusted, expired or revoked) or keyd's own refusal (`CS-KEY-0001`, `CS-KEY-0002`) stops the worker at start, non-zero, naming the code | keyd back: the next seal job completes the envelope. Alert on `seal_failed`. A worker that exits `CS-KEY-0013` at start: fix its keyd settings or certificate |
| keyd refuses the seal token (`KEYD-02`) | keyd holds `OPENSEAL_KEYD_SEAL_TOKEN_KEY` and the request carried no token it accepts: the database has no key installed (the worker then sends none), a different key, or a clock more than five minutes from keyd's. keyd answers `CS-KEY-0015` and records it in its log; the worker logs `transport.backend_failed` with that code; the seal fails (`CS-SEAL-0001`), raises `seal_failed` and retries every 60 s; the envelope stays `completing`. The database minting no token at all (the envelope owes no seal) fails the seal `CS-KEY-0015` before keyd is asked | Install the same key in both (`casual-sign-server migrate` with `OPENSEAL_KEYD_SEAL_TOKEN_KEY`; keyd's file; restart keyd), keep both clocks on NTP; the next seal job completes the envelope. `casual-sign-worker` `tests/keyd.rs` `a_database_without_the_token_key_seals_nothing_until_it_is_installed` |
| PostgreSQL restarted or unreachable | API requests answer a `5xx` problem while it is down (the pool waits up to 10 s for a connection) and the server keeps running; the worker logs `claim_failed` and keeps polling. A job interrupted mid-flight runs again after its back-off when its failure was recorded once the database returned, or once its lease lapses when it could not be (up to 300 s) | The database back: both reconnect without a restart. A signer whose request failed retries it; it is applied once |
| Object store refuses writes | The seal job retries with back-off (`CS-BLOB-0001`); no sealed bytes land and none are served; on its last attempt (15) the job hands over to a new seal job through the engine's `SealFailed` with an operator alert. The same holds for a database failure anywhere before the seal is stored (reading the envelope or the job's steps). Still dead-lettered, with a `job_dead` alert and the envelope `completing`: a failure no retry cures (`CS-DB-0008`–`0010`, `CS-BLOB-0003`/`0005`), a database failure after the seal is stored on the last attempt, and a database outage that lasts through the last attempt, so the handover itself cannot be written | The store back: the next attempt completes the envelope. Alert on `job_dead` and `seal_failed`; after a `job_dead` for `seal_envelope`, once the cause is fixed re-queue that job (`UPDATE jobs SET status = 'queued', attempts = 0, run_at = now() WHERE id = …`): a seal it already stored is read back, not made again |

**The same cases on the production profile** (`HRD-10`): `tools/chaos/chaos_compose.py run` (CI job `chaos-compose`;
needs Docker with Compose v2; `--no-build` reuses images built from this checkout) brings up
`deploy/compose.production.yml` with throwaway secrets from `deploy/production/init-secrets.sh`, a CI seal PKI, the
seal key in a SoftHSM token in keyd's volume (the PKCS#11 module mounted as an HSM vendor's would be) and recorded
configuration manifests. The CI-only `tools/chaos/compose.chaos.yml` adds what an operator brings from outside: a
mail sink that requires STARTTLS with a certificate from the internal CA (the worker trusts that CA through
`SSL_CERT_FILE`), the development TSA behind a gate that holds each request six seconds so a seal can be caught in
flight, and `verify-evidence` as a service; it sets no development switch (its unit tests check it against
`tools/check-deploy.py`'s list). Two workers run. Each envelope has one signer who passes an access code through the
API and the emailed link: a worker paused (`docker pause`) mid-seal past its lease while the other takes over, then
resumed (it must record nothing); a worker `SIGKILL`ed from the host's PID namespace mid-seal and right after a
finish (Docker's restart policy must restart it); keyd stopped while sealing (a `seal_failed` alert, nothing served,
workers restarted meanwhile stay up); PostgreSQL killed (`docker compose stop -t 0`) between adopt and finish (the
finish answers `5xx`, the retry signs once) and mid-seal; the object store killed mid-seal and its seal job pushed
to its last attempt (it hands over, never dead); and, last (`HRD-11`), the object store credential rotation and two
rolling restarts of the server replicas while two signers read their envelopes through `proxy` (§Rotation: not one
of their requests may fail, the old pair must be refused by the store, an envelope seals under the new pair; a few
minutes more, in the same job because it reuses the stack the run already built and started, where a workflow of
its own would build every image again). Retries are made due with `UPDATE jobs SET run_at = now()`; leases
lapse in real time (the run takes about 20 minutes after the build). It then requires every envelope `completed` on
exactly one sealed version, served (or `completing` with a `job_dead` alert and nothing served), `verify-evidence`
and keyd's `verify-oplog` to pass, and pyHanko (`tools/verify-sealed.py`) to validate every sealed PDF; it writes
`target/chaos-compose/report.json` and exits non-zero naming each problem. The driver's logic has unit tests
(`python3 -I -m unittest discover -s tools/chaos -p 'test_*.py'`).

A seal that failed after keyd signed signs again on the next attempt (keyd's log then shows two signatures for the
envelope, `KEYD-03` reconciles); sealed bytes stored by an attempt that was not recorded stay in the write-once blob
store unreferenced, are never served, and are not yet reclaimed (`HRD-09`).

## Load and recovery numbers (`HRD-04`)

`tools/load/load_compose.py run` (workflow `load`: by hand and weekly, never on push or pull request; needs Docker
with Compose v2) brings up the same hardened stack as the chaos run above (`deploy/compose.production.yml` built
from the commit, `tools/chaos/compose.chaos.yml` with the TSA gate holding nothing, two workers) plus the CI-only
`tools/load/compose.load.yml` (the mail sink keeps every message). The edge proxy is trusted as in production
(`OPENSEAL_TRUSTED_PROXIES` covers Docker's address pools) and each signer's requests carry their own address, so
the per-address ceremony limit counts per signer as it would behind a real proxy.

- **Load.** Senders create and send envelopes through the API (one signer, access code, one signature field), never
  more than `--in-flight` agreements open at once: a slot frees only when the envelope is sealed, so a stalled seal
  slows the senders. Signers take the link from the e-mail and run session, authenticate, consent, view, adopt and
  finish. A failed request is retried as a client would (finish is applied once).
- **Steady state.** After a 60 s warm-up, `--baseline` seconds (default 300) give completed envelopes per minute and
  latency percentiles (p50, p95, p99, linear between ranks).
- **Chaos under load.** Every worker `SIGKILL`ed from the host (Docker restarts them; the jobs they held wait for
  their 300 s lease), keyd stopped for `--hold` seconds (default 30), PostgreSQL killed (`stop -t 0`) for `--hold`
  seconds. Nothing is made due early: back-offs and leases run in real time.
- **Recovery time**, from the moment the service is back: *throughput back* is the first completion from which a
  whole minute completes at least 80 % of the steady-state rate; *backlog sealed* is when the last envelope sent before
  the service returned is sealed; *recovery* is the later of the two. A case not recovered within
  `--recover-timeout` (900 s) fails the run.
- **Where numbers come from.** Seal time is `envelope.completing` to `envelope.completed` in the audit trail;
  end-to-end is `envelope.sent` to `envelope.completed`; invitation is `envelope.sent` to the invitation job's
  `finished_at`; throughput counts `envelope.completed`. Send and sign have no server start time, so they are the
  driver's round trips over loopback (`POST /api/v1/envelopes`, `POST …/finish`).
- **Verdict.** Every envelope ends `completed` on exactly one sealed version (never two), `verify-evidence` and
  keyd's `verify-oplog` pass, and pyHanko validates a sample of 20 sealed PDFs. It writes
  `target/load-compose/report.json` and `report.md` (also shown on the run's summary page and uploaded as the
  `load-report` artifact), and exits non-zero naming each problem.

Run it: **Actions → load → Run workflow** (inputs: senders, signers, most open, steady-state seconds, chaos cases),
or `gh workflow run load.yml -f senders=2 -f signers=8`. Locally on a Linux host with Docker:
`python3 -I tools/load/load_compose.py run [--no-build] --verify-python PY`. The driver's statistics and verdict have
unit tests (`python3 -I -m unittest discover -s tools/load -p 'test_*.py'`).

**Published numbers.** From the first green `load` run on `main`: run 44403312475, commit `562e174`, 2026-11-18,
hardened profile, 2 workers, 2 senders, 8 signers, at most 16 agreements open. Measured, not estimated. A worker
kill shows the 300 s lease by design: the killed worker's envelopes wait for their leases, the others keep sealing.

| Measure | Value | Run |
| --- | --- | --- |
| Runner (CPUs, memory) | ubuntu-latest, 4 CPUs, 15.6 GiB | [44403312475](https://github.com/CasualOffice/openseal/actions/runs/44403312475) |
| Completed envelopes per minute, steady state | 194.6 (3601 of 3601 completed in the run) | [44403312475](https://github.com/CasualOffice/openseal/actions/runs/44403312475) |
| Send latency p50 / p95 / p99 (s) | 0.085 / 0.125 / 0.164 (client round trip) | [44403312475](https://github.com/CasualOffice/openseal/actions/runs/44403312475) |
| Sign latency p50 / p95 / p99 (s) | 0.025 / 0.050 / 0.065 (client round trip) | [44403312475](https://github.com/CasualOffice/openseal/actions/runs/44403312475) |
| Seal time p50 / p95 / p99 (s) | 1.894 / 2.830 / 3.181 (server, `completing` → `completed`) | [44403312475](https://github.com/CasualOffice/openseal/actions/runs/44403312475) |
| Recovery after every worker killed (s) | throughput back 1.1; backlog sealed 300.1 (the lease) | [44403312475](https://github.com/CasualOffice/openseal/actions/runs/44403312475) |
| Recovery after keyd down 30 s (s) | 28.1 (down 36.9) | [44403312475](https://github.com/CasualOffice/openseal/actions/runs/44403312475) |
| Recovery after PostgreSQL down 30 s (s) | throughput back 0.2; backlog sealed 263.3 (down 37.0) | [44403312475](https://github.com/CasualOffice/openseal/actions/runs/44403312475) |
| Envelopes sealed twice | 0 | [44403312475](https://github.com/CasualOffice/openseal/actions/runs/44403312475) |

## Production checklist

| Area | Do |
| --- | --- |
| Signing key | Obtain a document-signing certificate from an AATL member CA (or a qualified seal certificate for eIDAS) with its key generated in your HSM or cloud KMS; configure `keyd` with PKCS#11 or the KMS backend; never a file key ([09](09-LEGAL-AND-COMPLIANCE.md) §7) |
| Timestamps | Configure at least two RFC 3161 TSAs with an SLA (qualified, if you need eIDAS qualified time). Key custodians add and change them in the platform console, two people per change (`CON-07`); the worker reads them from the database and falls back to `OPENSEAL_TSA_URLS` when none is configured |
| Anchoring | Each day the worker anchors every account's changed audit chain heads (docs/32 §5): a Merkle root time-stamped by your TSAs, stored with each envelope's proof. It is on by default (`OPENSEAL_ANCHORING=daily`; `off` stops queuing new days). To make anchors public, set `OPENSEAL_ANCHOR_LOG` to a file the worker may append to (one JSON line per anchor, no envelope or account ids) and publish that file where you cannot quietly rewrite it (a public repository, a transparency page, a mailing list); a line can appear twice after a crash. Anyone checks an envelope's proof offline with `openseal anchor verify PROOF.json --trail audit-trail.json --trust TSA-ROOT.pem`. An anchor shows a chain head existed at the TSA's time; it is not a legal or regulatory attestation |
| Email | A sending domain with SPF, DKIM and DMARC (`p=quarantine` or stricter); a provider plugin or SMTP relay; bounce handling webhook |
| SMS / IDV / payments | Enable only the providers you have contracts with. SMS and voice one-time codes (`sms_otp`, `voice_otp`) go through an HTTPS gateway you run or rent: set `OPENSEAL_SMS_GATEWAY_URL` and `OPENSEAL_SMS_GATEWAY_SECRET` (or `_FILE`) on the worker; it posts `{"channel":"sms"\|"voice","to":"+…","text":"…","id":"…"}` with `Authorization: Bearer`. Unset, such codes are never sent (`CS-WRK-0013`). Recipient sign-in through an identity provider (`sso`): list the OpenID Connect providers signers may use in a JSON file named by `OPENSEAL_RECIPIENT_IDPS_FILE` on the server, `{"providers": [{"id", "name", "issuer", "authorization_endpoint", "token_endpoint", "jwks_uri", "client_id", "client_secret", "redirect_uri"?, "max_age_seconds"?}]}`; it holds client secrets, so mount it as a secret. `max_age_seconds` (0 to 86400, default 600) is sent as OpenID Connect `max_age`: the provider makes the signer authenticate again when their session there is older, and an ID token without `auth_time`, or whose `auth_time` is older than that (with 120 seconds of clock skew), is refused (ASVS 3.6.1, `ASVS-22`); a provider that does not honour `max_age` or send `auth_time` cannot pass `sso`. Register `{OPENSEAL_PUBLIC_URL}/s/oidc` (the default `redirect_uri`) with each provider, with the `openid email` scopes. Endpoints must be HTTPS (HTTP only to a loopback address). Unset, `sso` cannot pass (`CS-API-0014`). Remote-provider signatures (`RSP-01`, ADR-046): list the CSC providers in a JSON file named by `OPENSEAL_SIGNING_PROVIDERS_FILE` on the server and the worker, `{"providers": [{"id", "kind": "csc", "name", "base_uri", "authorization_endpoint", "token_endpoint", "client_id", "client_secret_ref", "trust_anchors_file", "accounts": ["*" or account ids], "redirect_uri"?}]}`; `client_secret_ref` names a secret read as `NAME` or `NAME_FILE` (never the secret itself), `trust_anchors_file` a PEM of the roots its signers' certificates chain to. It needs `OPENSEAL_PROVIDER_SECRETS_KEY` (32 bytes as base64, or `_FILE`; `OPENSEAL_PROVIDER_SECRETS_PREVIOUS_KEY` during a rotation): it seals an account's own client secret and each session's PKCE verifier and code; keep it with the backups. A malformed file, or the file without the key, stops the start (`CS-RSP-0010`, `CS-RSP-0009`). Register `{OPENSEAL_PUBLIC_URL}/s/rsp` (the default `redirect_uri`) with each provider. Each account then enables a provider (`PUT /api/v1/signing-providers/{id}`). The worker calls the provider's token endpoint and CSC API (HTTPS, or HTTP to a loopback address only, through its address policy) and completes each remote signature to B-LT at once, so it must reach the OCSP responder or CRL distribution point of the provider's certificates and of your TSA's. The development stack's TSA certificate names a CRL that `dev-tsa` serves (`http://tsa:8318/ca.crl`; a stack whose secrets were written before 2026-11-21 lacks it: `docker compose down -v` and start again); CI's `compose-e2e` runs a CSC stub (`tools/e2e/compose.e2e.yml`) |
| Malware scanning | Run the `clamav` service (Compose profile `production`) and set `OPENSEAL_CLAMD_ADDR`; keep fail-open off unless availability matters more than the scan; check with the EICAR file (§Malware scanning) |
| Database | PostgreSQL 15+, encrypted, PITR backups and the scheduled, encrypted backups of §Backups and restore (with a restore drill on your hardware), a separate role for migrations; the application role has no `UPDATE`/`DELETE` on `audit_events` |
| Object store | S3-compatible, versioning on, encryption on; Object Lock (compliance mode) for regulated tenants |
| Edge | TLS 1.2+ (1.3 preferred), HSTS, a WAF if you have one; `OPENSEAL_PUBLIC_URL` must be HTTPS |
| Trust | Bundle your organization's roots for verification; enable the EU LOTL if you verify EU signatures. `OPENSEAL_TRUST_ANCHORS` on the worker must hold the root of your seal certificate **and** the root of every TSA you configure: a CA hands out the certificate and its issuing CA, never the offline root, and a TSA's token stops below its root too, so B-LT and B-LTA seals take the root from these anchors when they collect revocation data (and the seal's self-check needs them anyway) |
| Interoperability | Before going live, rehearse with `tools/interop/interop.py check` (a real-style PKI and TSA served locally; docs/31 §Verification ladder), and with your production TSA: `OPENSEAL_INTEROP_NETWORK=1 … check --tsa-url URL --tsa-root ROOT.pem`. DigiCert's TSA passed on 2026-11-14; a TSA whose tokens use ESSCertID v1 (SHA-1), such as FreeTSA, is refused with `CS-SEAL-0005` until `SEAL-14` |
| ERSD | Have counsel review the consumer disclosure for your jurisdictions before sending to consumers |
| Observability | Ship the logs off the box (§Logs: `deploy/compose.log-forwarding.yml`, syslog over mutual TLS) and set `OPENSEAL_LOG_PSEUDONYM_KEY` on the server and the console; alert on the security events §Logs lists, seal failures, `transport.backend_failed` (keyd, TSA failover), email bounce rate and job backlog. OTLP traces and metrics are not built yet (`CON-11`) |
| Retention | Set account retention policies before go-live; document them in your records schedule |

## Production deployment (hardened profile, `HRD-06`)

`deploy/compose.production.yml` is the production Compose profile; `docker-compose.yml` stays the evaluation stack.
What the profile guarantees, and `python3 -I tools/check-deploy.py` checks on every CI run (it renders the file with
`docker compose config` and fails naming each `service: rule`; `--self-test` breaks each of its 44 rules in turn and
proves each is caught):

- **Containers.** Every service runs as a named non-root user (Postgres 70, SeaweedFS 1000, keyd 10001, both server
  replicas and the worker 65532, the HAProxy proxy 99), with a read-only root file system (tmpfs only for sockets and scratch), every capability dropped and
  none added, `no-new-privileges`, memory, CPU and process limits, no core dumps, bounded logs and a health check
  (the worker writes a heartbeat while its database answers, `casual-sign-worker healthcheck`; the one-shot
  `migrate` alone has none). No privileged mode, host namespace or Docker socket. Images are pinned by digest or
  are OpenSeal's own at an `OPENSEAL_VERSION` you built and signed; a release's `compose.release.yml` pins OpenSeal's
  own by their signed digests too (§Releases). The server stops on `SIGINT`, which drains it (below).
- **Secrets** are Docker secrets: files under `/run/secrets/`, each mounted only into the services that read it (the
  seal key's PIN and chain and keyd's identity into keyd alone, never the server), never an environment value (`docker inspect` and `/proc/1/environ` show only paths). Development switches
  (`OPENSEAL_DEV_INSECURE_KEY`, file keys) are refused by the checker.
- **TLS between services.** Postgres serves TLS 1.3 only, with an `hba_file` that has no plain `host` line (only
  `hostssl` and `local`, SCRAM), and the database URLs say `sslmode=verify-full` against the internal CA. The object
  store's S3 gateway serves TLS with a certificate from the internal CA, which the server and worker trust through
  `OPENSEAL_S3_CA`; SeaweedFS's master, volume and filer ports listen on its loopback address only, and its vendor
  telemetry is off (`-master.telemetry=false`, also in the evaluation stack). keyd is mutual TLS (unchanged). SMTP
  is `starttls`. TLS to browsers terminates at your edge proxy (HSTS there), which forwards to the `proxy`
  service's port on the host's loopback address; `proxy` forwards to the server replicas over the `edge` bridge
  in plain HTTP, as the hop from your edge proxy is. The server refuses to start with an `http` `OPENSEAL_PUBLIC_URL` (other than to a
  loopback address) unless `OPENSEAL_DEV_INSECURE_KEY=1`.
- **Networks.** `data` (Postgres, object store, server, worker, migrate) and `signing` (keyd and the worker) are
  internal: no route out. Only `proxy` publishes a port; it and the two server replicas are on `edge` (which
  also carries the servers' calls to recipients' identity providers), and only the worker is on `egress` (SMTP,
  TSAs, webhooks, under the `SEC-W01` address policy). A network HSM needs keyd on a network that routes to the HSM
  alone: add it as an `external` network for keyd only.
- **Configuration integrity** (below): keyd and the worker refuse to start unless their security settings match the
  manifests.
- **Zero-downtime restarts** (`HRD-11`). Two server replicas, `server` and `server-2`, run behind `proxy`
  (HAProxy, `deploy/production/haproxy.cfg`), which checks each at `GET /readyz` on its ops listener (port 9090,
  `OPENSEAL_OPS_LISTEN`, never published) every second and takes one out after two failed checks. A replica whose
  database does not answer is taken out; one told to stop (`SIGINT`) answers `503` there for
  `OPENSEAL_DRAIN_SECONDS` (5) while it still serves whatever reaches it, then takes no new connections and finishes
  the requests in hand (`stop_grace_period` 40 s). The proxy opens one connection per request (no idle connection to
  a stopping replica is reused), sends a request whose connection a replica refused to the other, and retries
  nothing that reached a replica. No request is logged (signing links carry bearer tokens). Restart them one at a
  time: `docker compose -f deploy/compose.production.yml restart server`, wait until it is healthy
  (`docker compose ps`) and a drain period more, then `server-2`. Because the forwarded client address now comes
  through `proxy`, set `OPENSEAL_TRUSTED_PROXIES` to the `edge` network's subnet (`docker network inspect
  openseal-production_edge`). Each replica keeps its own in-memory rate-limit counters and abnormal-activity
  windows (`HRD-15`).

Bringing it up: run `deploy/production/init-secrets.sh DIR` once as root on the Docker host. It writes the internal
TLS CA (its key into `DIR/offline/`: move it off the host), the Postgres, object store, keyd and worker identities,
random passwords, the database URLs, the S3 identities, the token and second-factor keys, keyd's allow list, and
keyd's seal token key twice (`keyd-seal-token-key` for keyd, `migrate-seal-token-key` for the migrate job, which
installs it in the database: `KEYD-02`, below), each owned by the one container user that reads it, mode 0400
(Postgres's key 0600). Add what only you have:
`seal-chain.pem` and `keyd-pkcs11-pin` (owner 10001, 0400), `trust-anchors.pem`, `smtp-password` (owner 65532,
0400). Set the variables the file requires (`OPENSEAL_SECRETS_DIR`, `OPENSEAL_VERSION`, `OPENSEAL_PUBLIC_URL`,
`OPENSEAL_TRUSTED_PROXIES`, the PKCS#11 module, token and label, mail, SMTP, TSA and seal name; `docker compose`
names any that is missing), record the manifests, then `docker compose -f deploy/compose.production.yml up -d --wait`
(with a published release: verify it and add its `compose.release.yml`, §Releases).
Checked by running (2026-11-14, Docker 29.8 on macOS): Postgres and the object store start healthy under this profile as
their non-root users; a `verify-full` client gets TLS 1.3, a plain connection is refused (`no pg_hba.conf entry …
no encryption`) and a wrong host name fails verification; the S3 gateway answers TLS 1.3 with the internal CA and
every other SeaweedFS port is closed to the network. The whole stack end to end on this profile, with failure
injection, is CI's `chaos-compose` job (§Failure recovery, `HRD-10`).

### Configuration integrity (ASVS 14.1.5, `ASVS-24`)

keyd and the worker read their security settings once, at start, so a change on disk does nothing until a restart.
At start each logs a JSON line `"event":"config"` (`setting`, `digest`: `sha256:…`) for every such setting and one `"event":"security_configuration"` (`digest`, `settings`, `manifest`: `matches` or `not_set`) over them
all: for keyd its TLS certificate, client CA, allow lists, seal chain, PKCS#11 module (the library's bytes), alias,
token and key label, and the path of its signature operations log (`OPENSEAL_KEYD_OPLOG`); for the worker its
trust anchors, TSA list, keyd and model service addresses and CAs, its client certificates, keyd alias, webhook
allowances, object store endpoint and bucket, SMTP host, port, user and security, SMS gateway, and the public base
URL (`OPENSEAL_BASE_URL`) that signer invitation links, which carry bearer tokens, point at. Never a PIN, key or
password.
With `OPENSEAL_CONFIG_MANIFEST` (the production profile sets it) the daemon refuses to start, `CS-KEY-0014` naming
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
| API token signing key (sessions' counterpart for API clients) | Generate a new P-256 key. With two replicas, in two rolling restarts (§Production deployment), so that no replica ever meets a token it cannot verify: **1.** mount the new key as `OPENSEAL_JWT_PREVIOUS_KEY_FILE` (verify only) beside the current signing key, rolling restart; **2.** swap them, the new key as `OPENSEAL_JWT_SIGNING_KEY_FILE` and the old as `OPENSEAL_JWT_PREVIOUS_KEY_FILE`, rolling restart. Tokens signed by either key verify on both replicas throughout and both keys are in `/.well-known/jwks.json`; after `access_token_ttl` (1 hour) remove the previous key, rolling restart. (A single server: step 2 alone, a restart) | None with two replicas: each restart drains, the proxy sends signers to the other; staff and signer sessions are database rows | `casual-sign-server` `crypto::tests::a_rotated_key_keeps_the_previous_keys_tokens_valid…`; seen red verifying with the current key only. The rolling restart: `tests/rotation.rs` `on_sigint_the_server_drains_then_stops` and `a_draining_server_is_not_ready_but_still_serves` (seen red with the drain removed and with `/readyz` ignoring it), and CI `chaos-compose` case 8 (two rolling restarts under signer traffic, 0 failed requests) |
| Staff sessions and CSRF tokens | No key to rotate: each session and its CSRF token are random values stored hashed per session (docs/40 §2), unaffected by any key rotation; signing out ends one | — | — |
| Webhook secrets | Provision the new secret as a file (`NAME_FILE`) for the worker; add its reference to the subscription's `secret_refs` (up to 4); deliveries now carry one signature per secret; once the receiver has switched, remove the old reference | None | `casual-sign-worker` `webhook::tests::during_rotation_a_receiver_holding_either_secret_accepts…`; seen red signing with the first secret only |
| Object store credentials | **1.** Add a second identity to `s3-identities.json` (the same `actions`, a new `accessKey` and `secretKey`), **rewriting the file in place** (`cat new > s3-identities.json`), and tell the store to reload it: `docker compose -f deploy/compose.production.yml kill -s SIGHUP s3` (no restart; both identities now work). **2.** Rewrite `s3-access-key` and `s3-secret-key` in place with the new pair; rolling restart of `server` and `server-2`; restart the worker. **3.** Remove the old identity from `s3-identities.json` in place; `kill -s SIGHUP s3` again; the old pair is refused | None: the store reloads without a restart, the servers restart one at a time behind the proxy, seal jobs retry across a worker restart | CI `chaos-compose` case 8, `tools/chaos/chaos_compose.py` `Run.rotation`: two signers reading their envelopes (view and document bytes from the store) through the proxy throughout, 0 failed requests required; the old pair refused (`403`) and the new accepted by the store, an envelope sealed under the new pair alone. Rehearsed locally (2026-11-19, the branch's server binary, the profile's HAProxy image and configuration, SeaweedFS at the profile's digest): 0 of 913 requests failed; seen red: replica `server-2` left on the old pair, 26 document reads failed (`503`); one replica restarted alone, 188 of 520 failed |
| Second-factor key (`OPENSEAL_MFA_KEY`, `HRD-12`) | Generate 32 random bytes (`openssl rand -base64 32`). With two replicas, in rolling restarts, so no replica meets a seed sealed under a key it lacks: **1.** mount the new key as `OPENSEAL_MFA_PREVIOUS_KEY_FILE` beside the current one, rolling restart; **2.** swap them, the new key as `OPENSEAL_MFA_KEY_FILE` and the old as `OPENSEAL_MFA_PREVIOUS_KEY_FILE`, rolling restart: each seed under the old key is re-sealed under the new one when its user next proves a code; **3.** `casual-sign-server mfa-reseal` as the schema owner (`docker compose … run --rm` with `OPENSEAL_MIGRATE_DATABASE_URL_FILE` and both key files) re-seals the rest and prints `mfa seeds: resealed=… current=… changed=… unopened=…`; it fails while any seed opens under neither key; **4.** once it reports `resealed=0 unopened=0`, remove the previous key, rolling restart. Keep the old key with the backups made before step 3 (§Backups) | None with two replicas (a single server: a restart per step) | `casual-sign-server` `tests/rotation.rs` `second_factor_seeds_under_the_old_key_still_verify_and_end_under_the_new_one` (on use, `mfa-reseal`, then the new key alone verifies both users; a session that owes the factor cannot re-seal it), `an_enrolment_begun_under_the_old_key_is_confirmed_under_the_new_one`, `mfa::tests::a_seed_under_the_previous_key_opens_and_is_resealed_under_the_new_one`; seen red with the re-seal on use removed, the previous key ignored, the re-seal on confirmation removed, the database guard removed and `mfa-reseal` not writing |
| Staff password pepper (`OPENSEAL_PASSWORD_PEPPER`, `ASVS-29`) | Generate 32 new random bytes as base64 (`openssl rand -base64 32`); mount the current pepper as `OPENSEAL_PASSWORD_PEPPER_PREVIOUS_FILE` and the new one as `OPENSEAL_PASSWORD_PEPPER_FILE` on both replicas; restart them in turn (each waits for the other to be healthy, `HRD-11`). Each hash names its pepper (the PHC `keyid`), so hashes under either verify, and each user's is re-made under the new pepper at their next successful password sign-in (migration 0044). Keep the previous pepper until every active user has signed in; then remove it and restart. A user whose hash is still under the removed pepper cannot sign in with their password until they reset it (`POST /auth/password-reset`). Hashes made before any pepper verify too and are re-made the same way. Never lose the current pepper: no hash under it verifies without it | None with both replicas restarted in turn; sessions survive it | `casual-sign-server` `crypto::tests::a_rotated_pepper_keeps_old_hashes_until_they_are_rehashed`, `tests/password_pepper.rs` (an old hash re-made at sign-in; a server on the same database without the pepper refuses the right password); seen red |
| Seal key alias (`CON-10`) | Generate the new key in the HSM and obtain its certificate; serve it beside the current one (`OPENSEAL_KEYD_NEXT_ALIAS`, `_NEXT_PKCS11_KEY_LABEL` or `_KEY_ID`, `_NEXT_CHAIN`; in the production profile set `OPENSEAL_SEAL_NEXT_ALIAS` and `OPENSEAL_PKCS11_NEXT_KEY_LABEL`, the chain read from the token), record keyd's manifest, restart keyd; a key custodian proposes the alias with a start (`POST /console/v1/seal/changes`; refused unless keyd serves it with a certificate valid then), a second grants, the first applies; from the start every seal uses it, no restart (a change proposed without a start begins when it is applied; a version stays approved if its approving custodian is later disabled); once no seal job can still use the old alias, make the new key the only one: set `OPENSEAL_SEAL_ALIAS` and `OPENSEAL_PKCS11_KEY_LABEL` to the new key's, put its chain in `seal-chain.pem`, and clear `OPENSEAL_SEAL_NEXT_ALIAS` and `OPENSEAL_PKCS11_NEXT_KEY_LABEL` (outside the profile: keyd's `OPENSEAL_KEYD_ALIAS`, key and chain, and the worker's `OPENSEAL_KEYD_ALIAS`); record **both** manifests, keyd's and the worker's (`OPENSEAL_SEAL_ALIAS` sets the worker's `OPENSEAL_KEYD_ALIAS`, which its manifest holds), then restart keyd and the worker. Skipping the worker leaves it with a manifest that no longer matches, so its next restart is refused (`CS-KEY-0014`), or, with the manifest re-recorded but the worker not restarted, still configured for an alias keyd no longer serves | None for signers; keyd restarts pause sealing for seconds, jobs retry | `casual-sign-worker` `tests/keyd.rs` `the_seal_key_follows_the_approved_alias…` (pyHanko agrees on the rotated seal), `casual-sign-console` `tests/keys.rs` `a_seal_alias_change_needs_two_custodians…` and `a_seal_alias_without_a_start_applies_now_and_outlives_its_approver` (seen red with the approver's present state judged), `casual-sign-keyd` `tests/two_keys.rs`; seen red |
| keyd seal token key (`KEYD-02`) | Write 32 new random bytes as 64 hex digits (`openssl rand -hex 32`) to both `keyd-seal-token-key` and `migrate-seal-token-key`; run the migrate job (`docker compose -f deploy/compose.production.yml run --rm migrate`), which installs it in the database; restart keyd. Outside the profile: `casual-sign-server migrate` with `OPENSEAL_KEYD_SEAL_TOKEN_KEY_FILE`, and keyd's `OPENSEAL_KEYD_SEAL_TOKEN_KEY_FILE` | Seals between the two steps fail `CS-KEY-0015` and retry 60 s later; signers are not affected | `casual-sign-server` `tests/backup_commands.rs` `migrate_installs_the_keyd_seal_token_key`; `casual-sign-worker` `tests/keyd.rs` `a_database_without_the_token_key_seals_nothing_until_it_is_installed`; seen red |

The token key, second-factor key and object store credentials need a server restart: the production profile runs
two server replicas behind `proxy`, so a rolling restart has no outage (`HRD-11`, §Production deployment).

A previous key (`OPENSEAL_MFA_PREVIOUS_KEY_FILE`, likewise `OPENSEAL_JWT_PREVIOUS_KEY_FILE`) is mounted into both
replicas with an override beside the profile, removed again in the last step; write the file as `mfa-key` is
written (owner 65532, mode 0400). Checked with `docker compose config`
and `tools/check-deploy.py --json` over the merged result, 2026-11-19:

    # compose.rotation.yml: docker compose -f deploy/compose.production.yml -f compose.rotation.yml ...
    services:
      server:
        environment: {OPENSEAL_MFA_PREVIOUS_KEY_FILE: /run/secrets/mfa-previous-key}
        secrets: [mfa-previous-key]
      server-2:
        environment: {OPENSEAL_MFA_PREVIOUS_KEY_FILE: /run/secrets/mfa-previous-key}
        secrets: [mfa-previous-key]
    secrets:
      mfa-previous-key: {file: "${OPENSEAL_SECRETS_DIR}/mfa-previous-key"}

`mfa-reseal` runs as the one-shot `migrate` service, the only one holding the schema owner's login, with both keys
mounted for the run:

    S="$OPENSEAL_SECRETS_DIR"
    docker compose -f deploy/compose.production.yml run --rm --no-deps \
      -v "$S/mfa-key:/run/secrets/mfa-key:ro" -v "$S/mfa-previous-key:/run/secrets/mfa-previous-key:ro" \
      -e OPENSEAL_MFA_KEY_FILE=/run/secrets/mfa-key -e OPENSEAL_MFA_PREVIOUS_KEY_FILE=/run/secrets/mfa-previous-key \
      migrate mfa-reseal

## Logs

**One format.** The server, worker, keyd, modeld and console write one JSON object per line to standard error
(`server/casual-sign-seclog`, `ASVS-08`): `ts` (RFC 3339, UTC), `level` (`DEBUG`, `INFO`, `WARN`, `ERROR`), `service`
(`server`, `worker`, `keyd`, `modeld`, `console`), `event`, then the event's fields. The server's access log is
`"event":"request"` with `request_id`, `method`, `route` (the template, never the path), `status` and `ms`. `RUST_LOG`
filters the server's and console's operational lines (default `info`); modeld's filter is fixed (docs/33 §3.4). No
line carries a name, an e-mail address, a client address, a token, a password or document text (`SEC-D01`,
`SEC-D06`).
A process's own lines are JSON too: `start_failed` (`ERROR`, with the setting that failed in `error` and, whenever
the failure has a docs/20 code, that code in its own `code` field, so alert on `code`) whenever a binary does not
start, and `development_token_key`, `development_mfa_key` (server) and
`development_file_key` (keyd) as `WARN` lines when a development key is in use, and `seal_token_not_enforced` (keyd)
when it runs without the seal token key, signing for any envelope id (`KEYD-02`); alert on these in production.

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
| `auth.reauthenticate` | server | A re-authentication before a sensitive action (`ASVS-07`): passed or refused (`factor: password`, `totp` or `recovery_code`; the code of the refusal) |
| `auth.session_end` | server | Other sessions of a staff user ended by them (`ASVS-06`): `scope: one` or `others`, and `count` |
| `auth.mfa_remove` | server | A staff second factor removed (`ASVS-32`, `CON-13`): `factor` (`passkey`, `totp`, or `all` for an administrator's reset, with `member`) and `by` (`self` or `admin`) |
| `auth.token` | server | An OAuth client-credentials token issued or refused |
| `auth.lockout` | server | A recipient locked out by failed authentications, and each later request refused for it (`CS-AUTH-0004`) |
| `access.unauthenticated`, `access.denied`, `access.rate_limited` | server, console (keyd: denied, rate limited) | Every `401`, `403` and `429`; keyd: an admin operation asked by a signing caller, a signature over the caller's rate |
| `input.upload_refused` | server | An upload over its size (`413`) or refused by admission (its `CS-PDF-*` or other admission code) |
| `admin.change` | server, console | A committed change on an administrative route (users, groups, profiles, API clients, webhooks, account and organization settings; every console change), with `method` and the `objects` (ids) the path named |
| `data.document_read` | server | A staff read (`GET`) of a document, the combined PDF, the certificate, an attachment, form data, an audit trail, a document's analysis, the suggestions analysis found (values read from the text), the envelope's fields or one field with their values, or the envelope itself (it embeds every field's value) (ASVS 8.3.5), with the `objects`. Not yet: a change to an envelope or a field answers with the field values without a read line (`ASVS-08C`) |
| `key.use` | keyd | A signature or a chain given or refused (`op`, `alias`, `envelope_id`; never the digest) |
| `transport.caller_refused` | keyd, modeld | An mTLS caller refused: a failed handshake (`reason: handshake`) or a certificate off the allow list (`reason: not_allowed`, named by fingerprint) |
| `transport.backend_failed` | worker | keyd not reached or refusing (its `CS-KEY-*` code) or a time-stamping authority not answering (`CS-WRK-0018`, `backend: tsa`, its `index` in the list and a `reason`: `connect`, `tls`, `timeout`, `status`, `answer`, `address_refused`; never its URL) |
| `alert.abnormal_activity` | server | Abnormal activity detected (§Abnormal activity below): `rule`, `count`, `threshold`, `window_s`, `suppressed`, `dropped`, code `CS-LOG-0002` (a threshold reached) or `CS-LOG-0003` (`rule: tracking_full`), and the `principal` and/or `client` over the threshold |

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
`auth.mfa` with `reason: reused`, `access.denied` bursts, `transport.caller_refused`, `transport.backend_failed`,
`abnormal_activity` (§Abnormal activity), and
on the collector receiving nothing from a service for five minutes (a dropped buffer is otherwise silent). Checked:
`docker compose -f docker-compose.yml -f deploy/compose.log-forwarding.yml --profile ml config` gives every service
the driver with these options (2026-11-14); a delivery to a live TLS collector is to be shown on a Linux host
(`ASVS-08A`).

### Abnormal activity (`ASVS-13`)

The server counts, per principal and per client address (by id or keyed pseudonym, never in clear), what an attack
or a misuse looks like, over a sliding window (`server/casual-sign-server/src/anomaly.rs`). When a count reaches its
threshold it writes one `alert.abnormal_activity` security event and raises one **operator alert**: by default a
`WARN` line `"event":"abnormal_activity"` (`rule`, `code`, `count`, `threshold`, `window_s`, `principal`, `client`,
`suppressed`, `dropped`), the same channel as the worker's `job_dead` and `seal_failed` lines (`ERROR`, with `code`,
`account`, `envelope` and `job`; `ASVS-13B`). Route it to the
operator's pager or chat from the collector, as those. An embedder can pass its own sink
(`AppState::set_alert_sink`).

| Rule (`rule`) | Counts | Per | Variable | Default per window |
| --- | --- | --- | --- | --- |
| `requests` | Every request | principal, address | `OPENSEAL_ALERT_REQUESTS` | 6000 |
| `rate_limited` | Answers `429` | principal, address | `OPENSEAL_ALERT_RATE_LIMITED` | 30 |
| `auth_failures` | Refused sign-ins, second factors, tokens, reset and invitation links, password changes, `401`s and recipient lockouts (one per request) | principal (or the presented e-mail's pseudonym), address | `OPENSEAL_ALERT_AUTH_FAILURES` | 20 |
| `access_denied` | Answers `403` | principal, address | `OPENSEAL_ALERT_DENIED` | 50 |
| `document_reads` | Staff reads (`data.document_read`): mass download | principal, address | `OPENSEAL_ALERT_DOCUMENT_READS` | 500 |
| `voids` | Envelopes voided | principal, address | `OPENSEAL_ALERT_VOIDS` | 25 |
| `sends` | Envelopes sent one at a time (`POST /envelopes` with `status: sent`, `POST /envelopes/{id}/send`; a draft is not counted) | principal, address | `OPENSEAL_ALERT_SENDS` | 300 |
| `bulk_sends` | Bulk sends made (`POST /bulk-sends` answered `201`; a check of the list is not counted) | principal, address | `OPENSEAL_ALERT_BULK_SENDS` | 10 |

`OPENSEAL_ALERT_WINDOW_SECS` (default 300, 10 to 86,400) is the window; a threshold of `0` turns its rule off. **One
alert per burst:** after an alert the subject is quiet for `OPENSEAL_ALERT_COOLDOWN_SECS` (default 900); trips
meanwhile are counted and reported as `suppressed` in its next alert. At most `OPENSEAL_ALERT_MAX_PER_MINUTE`
(default 20) alerts go out a minute across all subjects; those held back are `dropped` in the next. **Bounded
memory:** at most `OPENSEAL_ALERT_MAX_TRACKED` subjects (default 50,000, 1,000 to 10,000,000; a few MB) are counted;
when the table is full, subjects idle for two windows are swept, and if it is still full new subjects are not
counted, which is itself alerted (`rule: tracking_full`, `CS-LOG-0003`, `count` = subjects not tracked), while the
subjects already counted keep their counts (spraying addresses cannot reset one). A value out of range stops the
server at start (`start_failed` naming the variable).

**Several server instances.** Each instance counts only its own traffic, so behind a load balancer a spread attack
may stay under every instance's threshold. Divide the thresholds by the number of instances, or (better) apply the
same rules at the collector over every instance's lines. For example, over 5 minutes:

| Alert when | Group by |
| --- | --- |
| `event = security` and `kind = access.rate_limited`, count ≥ 30 | `client`; and `principal` |
| `kind` one of `auth.sign_in`, `auth.mfa`, `auth.token`, `auth.password_reset`, `auth.invite_accept`, `auth.lockout` with `outcome = failure`, count ≥ 20 | `client`; and `principal` |
| `kind = access.denied`, count ≥ 50 | `client`; and `principal` |
| `kind = data.document_read`, count ≥ 500 | `principal` |
| `event = abnormal_activity` or `kind = alert.abnormal_activity` | any: page at once |

The access log (`event = request`) carries neither principal nor client (`ASVS-13C`), so the `requests`, `voids`,
`sends` and `bulk_sends` rules have no collector-side equivalent per subject; across instances, alert on the total rate
of `route = /api/v1/envelopes/{id}/void` with `status = 200` (and of `/api/v1/envelopes/{id}/send` with `200`,
`/api/v1/bulk-sends` with `201`), and rely on each instance's own rules.

## Retention and erasure (`ASVS-16`, `ASVS-18`)

Nothing is purged until an account administrator sets a retention rule (Admin › Retention, or `PUT /api/v1/retention`).
A worker with `OPENSEAL_RETENTION=daily` (the default; `off` to stop queuing) queues one `retention_sweep` job per
account with a rule each UTC day; any worker runs it. Its log line `retention_swept` carries counts per class, the
sessions deleted and the envelopes skipped (held, or changed meanwhile), never names. A purge deletes database records,
not blob bytes: until the orphan sweep exists (`HRD-09`) the bytes of purged envelopes stay in the object store,
unreachable through the API; size the store accordingly. `verify-evidence` and the backup keep working across purges
(they read only what records name). A member's erasure (`DELETE /api/v1/users/me`, or an administrator's
`POST /api/v1/users/{id}/erase`) is immediate and cannot be undone; a person in several workspaces is removed by each
other workspace's administrators first. Operators publish their own privacy notice saying what is kept (docs/09 §5).

## Configuration

All configuration through environment variables; every secret also accepted as `NAME_FILE` (the sisters'
`-secrets` rule: both set is an error). Each binary's module documentation lists its variables
(`server/casual-sign-server/src/main.rs`, `-worker`, `-keyd`); `docker-compose.yml` sets the ones the stack needs and leaves the optional ones unset
(`OPENSEAL_RECIPIENT_IDPS_FILE`,
`OPENSEAL_TRUSTED_PROXIES`, `OPENSEAL_GEOIP_DB`, the SMS gateway, the model service, `OPENSEAL_WEBHOOK_ALLOW` and
`OPENSEAL_KEYD_ADMIN_ALLOW_LIST`, checked 2026-11-13, `DOC-008`; `OPENSEAL_CLAMD_ADDR` is passed through empty unless set, `ASVS-11`). The website's
configuration reference (`site/docs/configuration.html`, `SITE-12`) is generated from those module docs and the production profile by `tools/site_config.py`. The server's: `OPENSEAL_DATABASE_URL`,
`OPENSEAL_JWT_SIGNING_KEY`, `OPENSEAL_BLOB_DIR` or `OPENSEAL_S3_*`, `OPENSEAL_PUBLIC_URL`, `OPENSEAL_LISTEN`,
`OPENSEAL_TRUSTED_PROXIES`, `OPENSEAL_GEOIP_DB`, `OPENSEAL_WEBAPP_DIR`, `OPENSEAL_RECIPIENT_IDPS_FILE`,
`OPENSEAL_JWT_PREVIOUS_KEY` (during a rotation), `OPENSEAL_S3_CA` (also the worker's), `OPENSEAL_SECRET_RELOAD_SECONDS`
(also the worker's), `OPENSEAL_LOG_PSEUDONYM_KEY` (§Logs; also the console's),
`OPENSEAL_MFA_KEY` (32 random bytes as base64, sealing staff TOTP seeds, ASVS-01; **required**: administrators owe
a second factor by default, so the server does not start without it outside development, ASVS-31; the development
stack keeps one in its secrets volume as `mfa-key`; keep it with the database backups, since a seed sealed under a
lost key cannot be opened and its users can then sign in only with their recovery codes until the factor can be
replaced, or an administrator resets them, `ASVS-32`), `OPENSEAL_PASSWORD_PEPPER` (optional, 32 random bytes as base64: the pepper staff password
hashes are keyed with, held outside the database, ASVS 2.4.5, `ASVS-29`; the production profile mounts one,
`password-pepper`, made by `init-secrets.sh`; a hash made before it is re-made under it at the user's next sign-in;
keep it with the database backups, since no password hashed under a lost pepper verifies and those users must reset
their passwords), `OPENSEAL_PASSWORD_PEPPER_PREVIOUS` (during its rotation, §Rotation),
`OPENSEAL_MFA_PREVIOUS_KEY` (during its rotation, §Rotation, `HRD-12`), `OPENSEAL_WEBAUTHN_RP_ID` (optional: the
WebAuthn RP id of staff passkeys, `CON-13`, when it should be a parent domain of `OPENSEAL_PUBLIC_URL`'s host rather
than the host itself; passkeys work only on the public URL's origin, are unavailable when its host is an IP address,
and stop working for every user if the RP id later changes, so choose it once),
`OPENSEAL_OPS_LISTEN` (the ops listener, `CON-05`: `GET /livez` and `GET /readyz`, `204` or `503`, never the public
port; unset, none), `OPENSEAL_DRAIN_SECONDS` (on `SIGINT`, seconds to keep serving while `/readyz` answers `503`,
default 0; the production profile sets 5, `HRD-11`), `OPENSEAL_CLAMD_*` (§Malware
scanning); `migrate` reads
`OPENSEAL_MIGRATE_DATABASE_URL` and, when set, `OPENSEAL_KEYD_SEAL_TOKEN_KEY` (64 hex digits), which it installs in
the database after the migrations (`KEYD-02`); the server itself is never given that key. The worker's SMS and voice gateway is `OPENSEAL_SMS_GATEWAY_URL` and
`OPENSEAL_SMS_GATEWAY_SECRET`; its model service `OPENSEAL_MODELD_ADDR` with `OPENSEAL_MODELD_CA`,
`_CLIENT_CERT`, `_CLIENT_KEY` and `_SERVER_NAME`; its health file `OPENSEAL_HEALTH_FILE`; anchoring of chain heads `OPENSEAL_ANCHORING` (`daily`, the default, or `off`) and
its published file `OPENSEAL_ANCHOR_LOG` (both in the worker's configuration manifest). keyd and the worker check
`OPENSEAL_CONFIG_MANIFEST` (above). keyd's read-only admin operations answer only the certificates on
`OPENSEAL_KEYD_ADMIN_ALLOW_LIST`, which must not overlap its signing list (`CON-06`).

**keyd signs only for envelopes that owe a seal** (`KEYD-02`, ADR-036, docs/31 §5) when it holds
`OPENSEAL_KEYD_SEAL_TOKEN_KEY` (or `_FILE`): 32 random bytes as 64 hex digits (`openssl rand -hex 32`). The database
needs the same key, installed by `casual-sign-server migrate` with that variable (as the schema owner; the
application role can neither read nor replace it); migration 0040 needs the `pgcrypto` extension, which ships with
PostgreSQL and is a trusted extension, so the migration role creates it. The production profile wires both and
`init-secrets.sh` writes them. keyd without the key signs for any envelope id and logs `seal_token_not_enforced` at
start; the evaluation stack (`docker-compose.yml`) runs that way. Keep the database's and keyd's clocks on NTP: a
token lives ten minutes and keyd allows five more for skew.

## Backups and restore

**Status:** built and tested; the restore drill is written but has not yet run to completion (its first CI runs stopped at a unit test, then at the drill's own envelope request, both fixed), so no restore time is measured yet (`ASVS-14`, ASVS 8.1.5 and 8.1.6; docs/07 `SEC-D02`). The tool is
`tools/backup/openseal_backup.py` (Python standard library and the `openssl` command, OpenSSL 3.0 or later); the drill
is `tools/backup/drill.sh`, run by CI's `backup-drill` job and `tools/ci-local.sh`.

**What a backup holds.** One snapshot of the database (`pg_dump`, custom format, taken in a `REPEATABLE READ`
snapshot together with the row counts the restore must reproduce), the cluster's roles without passwords
(`pg_dumpall --roles-only --no-role-passwords`), every blob of the object store (`casual-sign-server blobs-export`,
each checked against its SHA-256 name on the way out), and keyd's operation log, cut at its last whole line. The
database holds the audit chains, the admin logs and the platform's operator log. Blobs are copied after the database
snapshot: they are written before the rows that name them and never replaced. The backup checks that rather than
trusting it: in the dump's own snapshot it reads every blob key the evidence names (the documents' versions, template
documents, certificates of completion, adopted signatures' captures, brand logos, and signers' attachments, which the
envelope's workflow state names; the same query as `casual-sign-server verify-evidence`), then reads each capture in
the export for the signature image it names, and refuses to write a backup that lacks any of them. The keys go into
`contents.json`, so `verify --key` and `restore` check them again.

**What a backup never holds.** A private key, a role password, or the platform's secrets. The seal key stays in the
HSM or KMS, which keeps its own backup (below). The JWT signing key, `OPENSEAL_MFA_KEY` (without it, staff TOTP seeds
cannot be opened), `OPENSEAL_PASSWORD_PEPPER` (without it, no staff password hashed under it verifies; a restore onto
a new pepper means every staff user resets their password), database and S3 credentials, and keyd's TLS identity live in your secret store, which you back up
by its own procedure; certificates and chains are public and kept with the configuration.

**Format and keys.** A backup is a directory `openseal-backup-<UTC time>/` with three files: `payload.cms`, CMS
AuthEnvelopedData (RFC 5083: AES-256-GCM, the content key wrapped with RSA-OAEP-SHA-256 for a recipient certificate)
of a tar holding the files above and `contents.json` (each file's SHA-256 and size, the row counts, the blob keys the
database names, keyd's line count and head); `manifest.json` (format `openseal-backup/2`, time, schema version, the
payload's size and SHA-256, the recipient certificate's SHA-256, the signing key's SHA-256); and `manifest.json.sig`,
an Ed25519 signature (RFC 8032, made by `openssl pkeyutl`) of the manifest's exact bytes. Two key pairs, both
separate from every platform key. `keygen` makes them:

```sh
python3 -I tools/backup/openseal_backup.py keygen backup-keys
#   backup-recipient.pem  the backup host: encrypts (public)
#   backup-signing.key    the backup host only: signs manifests (mode 0600; refused otherwise)
#   backup-signing.pub    everyone who checks or restores backups: verifies manifests (public)
#   backup-recipient.key  offline, with the people who restore: the only key that decrypts
```

The backup host never holds the decryption key, so a compromised backup host or store cannot read past backups. Keep
`backup-recipient.key` offline (a password manager vault or an HSM-backed escrow, two custodians), and test that it
opens a backup at every drill. Only the backup host can sign: the off-site store, a monitoring job and the restore
host hold `backup-signing.pub`, which checks a backup but cannot make one. That matters because a restore runs the
backup's roles script with `psql` and its dump with `pg_restore`, both as the database superuser, so a backup someone
could forge would run their SQL (and, through `psql`, commands) on the restore host. A restore therefore trusts only a
backup whose manifest the signing key signed, and even then lets through from `roles.sql` only blank and `--` comment
lines and CREATE ROLE, ALTER ROLE, GRANT and SET statements, one per line, with no backslash anywhere (no psql
meta-command), nothing outside quotes that starts a comment or a dollar quote, and no `$` in a role name (the restore
wraps each CREATE ROLE in a dollar quote); PostgreSQL 17.6's `\restrict`
guard lines are dropped. Anything else fails the backup when it is taken, and the restore naming the line. Keep
Each check runs on the bytes the restore then uses: `verify` and `restore` read `manifest.json`,
`manifest.json.sig` and `payload.cms` from the store once each, into a fresh `0700` directory, check the signature over
those manifest bytes, hash the payload as they copy it, and decrypt only that copy. A store that serves one file to the
checks and another to a later read (a network or FUSE mount someone else controls) therefore cannot get unsigned bytes
restored; `--work-dir` needs room for the payload as well as its plaintext. Keep
`backup-signing.key` as you keep the backup host's database credentials: whoever holds it can make a backup that a
restore will load. If it may have leaked, make a new pair with `keygen`, and check the next backups with the new
public key.

**Taking backups.** On the Compose stack (`--compose-project` names the stack; the tools run in its own containers):

```sh
python3 -I tools/backup/openseal_backup.py create --compose-project openseal --out /backups \
    --recipient backup-keys/backup-recipient.pem --signing-key backup-keys/backup-signing.key --keep 48
```

Elsewhere, `--direct` runs `pg_dump`, `pg_dumpall`, `psql`, `pg_restore`, `casual-sign-server` and `casual-sign-keyd`
from this host: the database from `OPENSEAL_BACKUP_DATABASE_URL` or `_FILE` (a superuser, or the schema owner with
`pg_dumpall` rights), the object store from the server's own `OPENSEAL_BLOB_DIR` or `OPENSEAL_S3_*`, keyd's log from
`--keyd-oplog PATH`. Plaintext is staged only while a backup is taken, in a fresh `0700` directory under `--work-dir`
(put it on an encrypted disk), and removed however the run ends. Schedule it with cron or a systemd timer, for example
hourly with `--keep 48`, and copy each finished directory to off-site, write-once storage (S3 Object Lock, compliance
mode). A backup directory appears only when complete (it is written under a hidden name and renamed).

**Checking backups.** `verify` with only the public `backup-signing.pub` checks the manifest's signature and the
payload's SHA-256, so the off-site store or a monitoring job can check every copy without the private key and without
the power to sign one; with `--key` and `--recipient` it also decrypts, checks every file against `contents.json`, and
checks that every blob key the database named is in the payload:

```sh
python3 -I tools/backup/openseal_backup.py verify /backups/openseal-backup-20261114T020000Z --verify-key backup-signing.pub
python3 -I tools/backup/openseal_backup.py verify /backups/openseal-backup-20261114T020000Z --verify-key backup-signing.pub \
    --key backup-recipient.key --recipient backup-recipient.pem
```

**Restoring.** Only into a fresh install: an empty database (before `migrate` ever ran) and a keyd that has not
started, so a restore can never overwrite evidence. With Compose:

```sh
docker compose up -d --wait postgres s3                      # nothing else yet
python3 -I tools/backup/openseal_backup.py restore /backups/openseal-backup-20261114T020000Z \
    --compose-project openseal --verify-key backup-signing.pub --key backup-recipient.key --recipient backup-recipient.pem
docker compose up -d --wait                                  # migrate finds every migration applied
```

`restore` checks the signature and the payload, decrypts (OpenSSL checks the GCM tag), refuses any tar entry that is not
a regular file with a backup's name, any file that differs from `contents.json` and a payload lacking any blob the
database named, then checks and loads the roles (only the statements above; an existing role is kept), the database in
one transaction (`pg_restore --single-transaction --exit-on-error`), and compares the row counts and the blob keys the
restored database names with the backup's; it imports the blobs (`casual-sign-server blobs-import`, each refused unless its bytes
are its name), restores keyd's log (`casual-sign-keyd verify-oplog` first; keyd continues the chain from its last line
on start), and runs `casual-sign-server verify-evidence` as the schema owner: every envelope's audit chain rebuilt and
checked against its stored head, every workspace's and organization's admin log, the platform's operator log
(`platform.operator_events`, against its stored head, as `casual-sign-console verify-log` does), every blob the
evidence names read back against its SHA-256 (each capture also read for the signature image it names, and that
image read too), and the counts equal to the backup's. Any difference fails the restore, naming the step. Login
roles come back without passwords: set them from your secret store before the services start (the Compose stack's
own `openseal` role keeps the password its fresh install made). The log of a failed step carries the tools' error
lines but not PostgreSQL's DETAIL and CONTEXT lines, which can quote row values; an error line itself can still name
a value (an invalid input), so keep the restore's log where personal data may be kept.

**The HSM's own backup.** keyd never exports a private key, and no OpenSeal backup carries one. Back the key up with
the HSM's own mechanism: a backup HSM or cloning within the security domain (keys leave only wrapped under the
domain key; Thales Luna, Entrust nShield), AWS CloudHSM's automatic encrypted cluster backups, or a cloud KMS key that
is non-exportable and replicated by the provider (multi-region keys). Record the HSM's backup in your key ceremony
records and include restoring it in the drill on your production hardware. If the key is lost, documents already
sealed still verify (their certificate is embedded); only new seals need a new key and certificate. The Compose
stack's SoftHSM token is development only: a fresh stack imports a fresh generated key.

**RPO and RTO.**

| | Objective | How |
| --- | --- | --- |
| RPO, database | At most the backup interval (one hour with the schedule above); 5 minutes with PITR | Logical backups by this tool; for production also PostgreSQL point-in-time recovery (WAL archiving: the managed service's, or pgBackRest), restored to just before the incident, then `verify-evidence` |
| RPO, documents | The backup interval; zero with a replicated bucket | Blobs are write-once and content-addressed: bucket versioning, Object Lock and cross-region replication keep every blob the database can name |
| RPO, keyd's log | The backup interval | keyd's log lists signatures the database also records; a lost tail loses no evidence a sealed document needs |
| RTO | 4 hours for a production install (a target, not yet measured at production size) | The drill records the restore time of its data set in its report; it grows with the dump size (`pg_restore` speed) and the number of blobs. Measured: 8.6 s for the drill's data set (CI run 43519062719, commit 66b808c, 2026-11-14) |

What an RPO window loses: changes after the backup, including envelopes signed or sealed after it. Sealed PDFs already
delivered still verify on their own; the restored audit chain simply ends at the backup's head, and those envelopes
are resent (the signing links already emailed keep working, since only their hash is stored).

**The drill.** `tools/backup/drill.sh` (CI job `backup-drill`) takes a stack, signs and seals one envelope and half
signs another through the emailed links, backs it up, proves that a flipped payload byte and an edited manifest fail
verification, destroys the stack with every volume, restores into a fresh stack with its own keys, and requires: the
sealed PDF byte-identical, the half-signed envelope as it was, its second signer able to sign with the link emailed
before the backup, the new worker sealing it, `verify-evidence` passing again, and keyd's log verifying from its
restored lines on.

`verify-evidence` checks the restored database against itself: each chain against the head stored beside it. So the
drill also compares the restore with what it read from the first stack *before* the backup, which neither the backup
nor the restored database can supply: both envelopes' audit chains on the new stack must begin with the event hashes
the first stack's API answered; the sealed PDF's SHA-256 is the one that API answered; keyd's log on the new stack must
begin with the exact bytes of the first stack's log, and the backup must carry at least as many lines; the new stack's
seal root must differ from the first's (keys come from the new HSM, never from a backup, which carries none: the
backup directory holds only its three files); and pyHanko (`tools/verify-sealed.py`) must validate the first stack's
sealed PDF against the first stack's root, the new stack's against its own, and refuse the new stack's against the
first stack's root. A backup that held no envelopes, no keyd log, or no growth after the resume fails too.

*Rerunning it.* On a host with Docker (Compose v2), `python3`, OpenSSL 3, and a virtual environment with pyHanko
(`python3 -m venv /tmp/v && /tmp/v/bin/pip install "pyhanko==0.38.1" cryptography`), from a checkout:

```sh
OPENSEAL_DRILL_VALIDATOR_PYTHON=/tmp/v/bin/python tools/backup/drill.sh
```

It builds the images (`OPENSEAL_DRILL_BUILD=0` reuses images built from the same checkout), uses Compose projects
`openseal-drill-a` and `openseal-drill-b` on ports 18180, 18125, 18280 and 18225, removes both stacks and their
volumes however it ends, and exits non-zero naming the step or check that failed. To rerun it on CI, run the `ci`
workflow again (Actions, the run, "Re-run jobs", `backup-drill`); it runs on every push to `main`. On your production
hardware, also restore the HSM's own backup (above) and time the whole procedure; the drill measures only the data.

*Where the evidence is.* `target/backup-drill/report.json`: `verdict` (`passed` or `failed`), `problems`, the
`commit` drilled, `started` and `finished` (UTC), `restore_seconds` (the measured restore time of this data set),
the counts restored and after the resume, keyd's log lines on the first stack, restored and after the resume, the
sealed PDFs' hashes, and the list of checks. Beside it: `restore.json` (the restore's own report), `evidence-after.txt`
and `oplog-after.txt` (`verify-evidence` and `verify-oplog` after the resume), `verify-sealed.txt` (pyHanko's verdict),
`sealed-a/`, `sealed-b/` and `sealed-cross/` (the sealed PDFs, each stack's seal root and the validator's
manifests), `payload-structure.txt`, `flipped.err` and `edited.err` (the encryption and the tamper refusals), and, on
a failure, each stack's Compose logs. CI uploads these and the console log (`target/backup-drill.log`) as the artifact
`backup-drill` of the run, kept 90 days: `gh run download <run id> -n backup-drill`. Copy the report of each drill you
count into your audit records before then; the artifact holds no backup, no key and no signing link.

## Releases: verify, then pin (`REL-01`)

**Status:** the workflow below is written and linted (`actionlint` with `shellcheck`), its pinning tool is unit-tested,
and the pinned profile was rendered and passed `tools/check-deploy.py` on a workstation (2026-11-17). It has not yet
run on a tag: v0.0.1 was built by its first version (images with BuildKit's SBOM and provenance only, no cosign
signature, no release assets). The first tag after this change is its first real run: v0.1.0, prepared 2026-11-19
(owner instruction 61; `REL-04`).

**What a release is.** `.github/workflows/release.yml` runs on a `v*` tag pushed by the owner, never on an ordinary
push. For each of `server`, `worker` and `keyd` it builds `deploy/Dockerfile`'s target for `linux/amd64` (base images
pinned by digest) and pushes `ghcr.io/casualoffice/openseal-<service>:<version>` to GitHub Container Registry. Every
image digest then carries: BuildKit's SPDX SBOM and SLSA provenance (mode `max`) attached to the image index; a
keyless cosign signature (Sigstore, the workflow's GitHub OIDC identity, recorded in the public Rekor log); and a
GitHub build provenance attestation. The release's assets are:

| Asset | What |
| --- | --- |
| `openseal-<service>-<version>.spdx.json` | SPDX SBOM of each pushed image (syft, pinned) |
| `openseal-rust-<version>.cdx.tar.gz` | CycloneDX 1.5 SBOM of every workspace crate, Linux x86-64, all features (`cargo-cyclonedx`, pinned) |
| `images.json` | The version and, per service, repository, tag and digest |
| `compose.release.yml`, `openseal-release.env` | The production profile pinned to those digests (below) |
| `RELEASE-NOTES.md` | The `CHANGELOG.md` section, the image digests and a pointer here |
| `SHA256SUMS`, `SHA256SUMS.sigstore.json` | SHA-256 of every asset above, and a keyless cosign signature over that list |

Every asset also has a build provenance attestation. Versions `0.x` and `x.y.z-pre` are published as pre-releases.
Run by hand (Actions, `release`, Run workflow) it is a dry run: it builds every image to a local archive and every
asset, pushes and signs nothing, and keeps the assets as the run's `release-dry-run` artifact. It publishes by hand
only when `publish` is ticked and the run was started on a `v*` tag (to finish a tag run that failed part-way).

**Verifying a release** (cosign 3 and the GitHub CLI; nothing here needs a GitHub account once the packages are
public). `V` is the tag, `REPO=CasualOffice/openseal`:

```sh
gh release download "$V" -R "$REPO" -D "openseal-$V"; cd "openseal-$V"
ID="https://github.com/$REPO/.github/workflows/release.yml@refs/tags/$V"
ISSUER=https://token.actions.githubusercontent.com
# 1. The checksum list was signed by this repository's release workflow at this tag, then every asset matches it.
cosign verify-blob SHA256SUMS --bundle SHA256SUMS.sigstore.json --certificate-identity "$ID" --certificate-oidc-issuer "$ISSUER"
sha256sum -c SHA256SUMS                       # macOS: shasum -a 256 -c SHA256SUMS
# 2. Each image digest is signed by the same identity and has build provenance from this repository.
for ref in $(jq -r '.images[] | "\(.repository)@\(.digest)"' images.json); do
  cosign verify "$ref" --certificate-identity "$ID" --certificate-oidc-issuer "$ISSUER" > /dev/null && echo "signed: $ref"
  gh attestation verify "oci://$ref" -R "$REPO" --signer-workflow "$REPO/.github/workflows/release.yml"
done
# 3. Optionally, each asset's provenance, and the SBOM attached to an image.
gh attestation verify openseal-rust-*.cdx.tar.gz -R "$REPO"
docker buildx imagetools inspect "$(jq -r '.images.server | "\(.repository)@\(.digest)"' images.json)" --format '{{ json .SBOM }}'
```

To accept any release tag rather than one, use `--certificate-identity-regexp
'^https://github\.com/CasualOffice/openseal/\.github/workflows/release\.yml@refs/tags/v'` in place of
`--certificate-identity`. A signature from any other workflow, branch or repository fails these checks.

**Running exactly what was verified.** Check out the source at the same tag (the profile, `deploy/production/` and
the checker come from it), then start the production profile with the override, which sets `keyd`, `migrate`,
`server` and `worker` to `repository:tag@sha256:…`; Docker pulls by digest, so a moved or re-pushed tag changes
nothing:

```sh
docker compose -f deploy/compose.production.yml -f "openseal-$V/compose.release.yml" \
    --env-file "openseal-$V/openseal-release.env" up -d --wait
```

`openseal-release.env` sets `OPENSEAL_IMAGE_PREFIX` and `OPENSEAL_VERSION`, which the profile requires; the other
variables (§Production deployment) still come from your environment. The files can be written again from a verified
`images.json`, for example after mirroring the images to your own registry and editing the repositories:
`python3 -I tools/release/pin_release.py --from images.json --out DIR`. It refuses an image not given by `sha256`
digest, a missing or unknown service, mixed repository prefixes and a tag other than the version. The release
workflow renders the pinned profile and runs `tools/check-deploy.py --json` over it before publishing; you can do the
same: `docker compose -f deploy/compose.production.yml -f compose.release.yml config --format json --no-interpolate >
merged.json && python3 -I tools/check-deploy.py --json merged.json`.

**Owner's steps, once per package.** GitHub Container Registry makes a package pushed by a workflow private, and
the workflow's token cannot change that. After the first tag run, for each of `openseal-server`, `openseal-worker` and
`openseal-keyd`: the organization's Packages, the package, Package settings, Change visibility, Public (and link it to
the repository, so the repository's workflows keep write access). Until then pulls, `cosign verify` and `gh
attestation verify` on the images need a GitHub login with read access. The images are built for `linux/amd64` only:
arm64 hosts run them under emulation or build from source.

## Sandbox workspaces (ADR-041, `VS-08D`)

An organization administrator makes a sandbox workspace in Organization settings → Workspaces ("Sandbox workspace",
fixed at creation). Its envelopes are sealed with the sandbox key only: the Compose stack generates one
(`dev-pki`: `sandbox-seal.key`, `sandbox-seal-chain.pem`), imports it into keyd's token under the label `sandbox` and
sets `OPENSEAL_KEYD_SANDBOX_ALIAS=sandbox` on keyd and the worker. In production, generate the sandbox key in the HSM
with a certificate whose subject says "not for agreements", then set keyd's `OPENSEAL_KEYD_SANDBOX_ALIAS`,
`OPENSEAL_KEYD_SANDBOX_PKCS11_KEY_LABEL` (or `_KEY_ID`) and `OPENSEAL_KEYD_SANDBOX_CHAIN`, and the worker's
`OPENSEAL_KEYD_SANDBOX_ALIAS`, and record both manifests. Without them, sandbox envelopes wait unsealed
(`CS-WRK-0020`) and the operator is alerted; nothing is ever sealed for a sandbox with the platform key.

## Upgrades

Rolling: migrations are forward-compatible for one release, so old and new nodes run together during a deploy. Never
skip a minor version without reading the release notes.

## Demos

Recordings of each slice's flow, made by CI on a green `main` run (docs/06: "demo recorded" is part of every slice's
end point). They are GitHub Actions artifacts of the private repository: open the run, then Artifacts, or
`gh run download <run> -n <artifact>`. Artifacts expire after 90 days; a later green run records them again and this
table moves to it. Videos are never committed.

All four below come from `main` at `ebac68e`, run
[44023485128](https://github.com/CasualOffice/openseal/actions/runs/44023485128) (2026-11-17, every job green),
expiring 2027-02-15. Each was downloaded and checked frame by frame (2026-11-18): every video plays and shows the
flow named.

| Slice | Artifact (id, size) | Recorded by | What it shows (chromium and webkit each) |
| --- | --- | --- | --- |
| 1 Send and sign (`S1-02`) | `slice-1-demo` (14303626789, 7.2 MB) | `compose-e2e`, `real-stack.spec.mjs` VS-01 | `vs01-*-1-3-sender-sends-and-downloads.webm` (14–19 s): the editor, "Sent. Recipients are being notified.", the envelope page from Sent to Completed, Download signed PDF and Certificate. `vs01-*-2-signer-signs-on-a-phone.webm` (5 s, iPhone 13 size): the ERSD consent, the document opening, Sign, Adopt and sign, "Signed. Thank you, Cara.". `vs01-*-4-signer-downloads.webm`: the signer's done screen through the completion email's link with Download a copy and Certificate of completion. Also the eight downloaded PDFs (sealed and certificate, sender and signer) |
| 2 Routing and recipient types (`RTE-04`) | `slice-2-demo` (14303182320, 11.7 MB) | `compose-e2e`, `routing.spec.mjs` | `vs02-*-1-6-sender-sends-and-downloads.webm` (24–35 s): send to an approver, a viewer, an agent and a signer in order; the envelope page as each acts, to Completed and the downloads. `-2-approver-approves`, `-3-viewer-views`, `-4-agent-names-the-signer` (the agent's "Who signs next" form), `-5-named-signer-signs`: each through the link the worker emailed. Also the sealed PDFs and certificates |
| 5 Recipient authentication and consent (`RAUTH-02`) | `slice-5-demo` (14303611682, 5.0 MB) | `compose-e2e`, `recipient-auth.spec.mjs` | `vs05-*-codes-on-a-phone.webm` (68–70 s, phone size): the email, SMS ("Text me a code", "Code sent") and voice ("Call me with a code") code steps. `vs05-*-identity-provider-sign-in.webm`: "Sign in to continue" through the OpenID Connect stub, the document, the Withdraw consent dialog and "You withdrew your consent" |
| 7 Verify (`VS-07A`) | `slice-7-demo` (14304121907, 2.0 MB) | `e2e`, `verify-demo.spec.mjs` | `vs07-*-verify.webm` (7–8 s): `verify.html` in the browser, a trusted certificate added, a sealed PDF "Signed and unchanged" with every check passed, then a tampered one "Changed or broken" with the document digest failed. Recorded in the `e2e` job's mock mode (the page shows its "Demo mode" banner); the check itself is the WebAssembly verifier running in the page, as on a real server |

Slices 3, 4, 6 and 8 (`DOC-016`) come from `main` run
[44813535957](https://github.com/CasualOffice/openseal/actions/runs/44813535957) (`9c20a0e`, 2026-11-20, every job
green, expiring 2027-02-18; the run also carries `slice-3-demo-4`, `slice-4-demo-3`, `slice-6-demo-4` and
`slice-8-demo-4`). The main session watched each frame by frame on 2026-11-21: each shows its slice's outcome on the
real stack.

| Slice | Artifact | Watched |
| --- | --- | --- |
| 3 Templates (`VS-03`) | `slice-3-demo-2` | 2026-11-21, the slice's outcome on the real stack |
| 4 Every field (`VS-04`) | `slice-4-demo-1` | 2026-11-21, the slice's outcome on the real stack; the fixture's fields sit over its heading and intro line, so the recording looks messy (`E2E-15`) |
| 6 Manage and correct (`VS-06`) | `slice-6-demo-2` | 2026-11-21, the slice's outcome on the real stack |
| 8 API and webhooks (`VS-08`) | `slice-8-demo-2` | 2026-11-21, the slice's outcome on the real stack |

Seen while checking: in the slice-1 and slice-2 sender videos the envelope page's Evidence card says "Audit trail
links do not match" on a real envelope: the page read only bare hex, and the server writes `sha256:<hex>` (`S1-10`,
fixed with a test; the evidence itself was never wrong, only its display).
