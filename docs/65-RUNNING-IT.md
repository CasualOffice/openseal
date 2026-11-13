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
| Database | PostgreSQL 15+, encrypted, PITR backups and the scheduled, encrypted backups of §Backups and restore (with a restore drill on your hardware), a separate role for migrations; the application role has no `UPDATE`/`DELETE` on `audit_events` |
| Object store | S3-compatible, versioning on, encryption on; Object Lock (compliance mode) for regulated tenants |
| Edge | TLS 1.2+ (1.3 preferred), HSTS, a WAF if you have one; `OPENSEAL_PUBLIC_URL` must be HTTPS |
| Trust | Bundle your organization's roots for verification; enable the EU LOTL if you verify EU signatures |
| ERSD | Have counsel review the consumer disclosure for your jurisdictions before sending to consumers |
| Observability | OTLP endpoint for traces and metrics; alert on seal failures, TSA failover, email bounce rate, job backlog |
| Retention | Set account retention policies before go-live; document them in your records schedule |

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
`OPENSEAL_MFA_KEY` (32 random bytes as base64, sealing staff TOTP seeds; keep it with the database backups, since a
seed sealed under a lost key cannot be opened and its users must enrol again; ASVS-01); `migrate` reads
`OPENSEAL_MIGRATE_DATABASE_URL`. The worker's SMS and voice gateway is `OPENSEAL_SMS_GATEWAY_URL` and
`OPENSEAL_SMS_GATEWAY_SECRET`; its model service `OPENSEAL_MODELD_ADDR` with `OPENSEAL_MODELD_CA`,
`_CLIENT_CERT`, `_CLIENT_KEY` and `_SERVER_NAME`. keyd's read-only admin operations answer only the certificates on
`OPENSEAL_KEYD_ADMIN_ALLOW_LIST`, which must not overlap its signing list (`CON-06`).

## Backups and restore

**Status:** built and tested; the restore drill is written but has not yet run to completion, so no restore time is measured yet (`ASVS-14`, ASVS 8.1.5 and 8.1.6; docs/07 `SEC-D02`). The tool is
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
cannot be opened), database and S3 credentials, and keyd's TLS identity live in your secret store, which you back up
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
meta-command) and nothing outside quotes that starts a comment or a dollar quote; PostgreSQL 17.6's `\restrict`
guard lines are dropped. Anything else fails the backup when it is taken, and the restore naming the line. Keep
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
| RTO | 4 hours for a production install (a target, not yet measured) | The drill records the restore time of its data set in its report; it grows with the dump size (`pg_restore` speed) and the number of blobs |

What an RPO window loses: changes after the backup, including envelopes signed or sealed after it. Sealed PDFs already
delivered still verify on their own; the restored audit chain simply ends at the backup's head, and those envelopes
are resent (the signing links already emailed keep working, since only their hash is stored).

**The drill.** `tools/backup/drill.sh` (CI job `backup-drill`) takes a stack, signs and seals one envelope and half
signs another through the emailed links, backs it up, proves that a flipped payload byte and an edited manifest fail
verification, destroys the stack with every volume, restores into a fresh stack with its own keys, and requires: the
sealed PDF byte-identical, the half-signed envelope as it was, its second signer able to sign with the link emailed
before the backup, the new worker sealing it, `verify-evidence` passing again, and keyd's log verifying from its
restored lines on. It writes `target/backup-drill/report.json`, with the measured restore time.

## Upgrades

Rolling: migrations are forward-compatible for one release, so old and new nodes run together during a deploy. Never
skip a minor version without reading the release notes.
