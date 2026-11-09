# 65 — Running it

**Status: design; nothing runs yet.** How an operator will deploy OpenSeal. Written ahead so Phase 2 builds toward it;
every command here becomes true in Phase 2 stage 2F (single node) and slice 20 (cluster). Adapted in shape from
OpenCalc's docs/65.

## Single node (evaluation)

```sh
cp .env.example .env            # set OPENSEAL_PUBLIC_URL, SMTP settings; secrets as *_FILE paths
docker compose up --build
open http://localhost:8080      # first user created from OPENSEAL_BOOTSTRAP_ADMIN_EMAIL
```

Services: `server`, `worker`, `keyd` (development file key, which stamps every seal "Development key — not for
production"), `postgres`, `minio`, `mailpit` (catches all email at http://localhost:8025).

## Production checklist

| Area | Do |
| --- | --- |
| Signing key | Obtain a document-signing certificate from an AATL member CA (or a qualified seal certificate for eIDAS) with its key generated in your HSM or cloud KMS; configure `keyd` with PKCS#11 or the KMS backend; never a file key ([09](09-LEGAL-AND-COMPLIANCE.md) §7) |
| Timestamps | Configure at least two RFC 3161 TSAs with an SLA (qualified, if you need eIDAS qualified time) |
| Email | A sending domain with SPF, DKIM and DMARC (`p=quarantine` or stricter); a provider plugin or SMTP relay; bounce handling webhook |
| SMS / IDV / payments | Enable only the providers you have contracts with |
| Database | PostgreSQL 15+, encrypted, PITR backups, a separate role for migrations; the application role has no `UPDATE`/`DELETE` on `audit_events` |
| Object store | S3-compatible, versioning on, encryption on; Object Lock (compliance mode) for regulated tenants |
| Edge | TLS 1.2+ (1.3 preferred), HSTS, a WAF if you have one; `OPENSEAL_PUBLIC_URL` must be HTTPS |
| Trust | Bundle your organization's roots for verification; enable the EU LOTL if you verify EU signatures |
| ERSD | Have counsel review the consumer disclosure for your jurisdictions before sending to consumers |
| Observability | OTLP endpoint for traces and metrics; alert on seal failures, TSA failover, email bounce rate, job backlog |
| Retention | Set account retention policies before go-live; document them in your records schedule |

## Configuration

All configuration through environment variables; every secret also accepted as `NAME_FILE` (the sisters'
`-secrets` rule: both set is an error). The full list is generated from the code into `docs/65` in Phase 2.

## Upgrades

Rolling: migrations are forward-compatible for one release, so old and new nodes run together during a deploy. Never
skip a minor version without reading the release notes.
