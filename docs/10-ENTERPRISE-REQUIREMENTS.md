# 10 — Enterprise requirements

**Status: Draft for owner.** The bar that makes OpenSeal enterprise-grade rather than an MVP. Each item names the slice
or phase that meets it. Targets are proposed, not measured.

## Security

- OWASP ASVS 4.0 Level 2 for the whole server; Level 3 for the ceremony, sealing and keyd paths (`SEC-ASVS-01`).
- External penetration test and cryptographic review before 1.0 (`SEC-REV-01`).
- Every threat in [07](07-SECURITY-THREAT-MODEL.md) Tested.
- Key custody in HSM or cloud KMS; FIPS 140-3 validated crypto module available (`aws-lc-rs` FIPS build).
- Signed images, SBOM, SLSA provenance (slice 20).
- Coordinated disclosure policy ([SECURITY.md](../SECURITY.md)).

## Identity and access

- SSO with SAML 2.0 and OIDC; enforced SSO; just-in-time provisioning; SCIM 2.0 (slice 10).
- MFA: WebAuthn and TOTP for local accounts.
- Permission profiles, groups, delegated administration, send on behalf (slice 10).
- Admin audit log of every configuration change, exportable (slice 10).

## Data governance

- Retention policies per account and per template; legal hold; purge with tombstones (slice 15).
- Data region tags and single-region deployments; no cross-region replication by default.
- BYOK: per-tenant data keys wrapped by a customer-managed KMS key; revocation makes data unreadable (slice 15).
- Export of all envelopes with evidence in a documented format (slice 6).

## Reliability and operations

- Stateless application tiers; horizontal scaling; zero-downtime rolling upgrades with forward-compatible migrations.
- Backup and point-in-time restore documented and drilled; RPO ≤ 5 min, RTO ≤ 1 h for the reference HA deployment
  (slice 20).
- OpenTelemetry traces, metrics and structured logs with no personal data; health and readiness endpoints; alerting
  runbooks for TSA, email, HSM and seal failures.
- Capacity: 50 envelopes per second sent, 200 completions per second sealed, on a documented reference cluster
  (benchmarked in slice 20).

## Compliance support

Designed to support, never claimed ([09](09-LEGAL-AND-COMPLIANCE.md)): ESIGN and UETA (slices 1, 5), eIDAS SES (slice 1),
AES and QES through QTSPs (slice 18), Part 11 (slice 19), GDPR and DPDP (slices 6, 15), SOC 2 and ISO 27001 control
mapping for operators (slice 20), HIPAA operator guide (slice 20).

## Accessibility and language

WCAG 2.2 AA for every UI with an audit before 1.0 (`A11Y-01`); keyboard-only and screen-reader signing; 20+ languages
and right-to-left (slice 12).

## Integration

Versioned API with a 12-month deprecation policy; OpenAPI; generated SDKs; webhooks with delivery logs; embedding;
sandbox accounts; MCP access.

## Support for the long term

- **Verifiability for decades**: PAdES B-LTA with renewal, PDF/A-3, published verification algorithm, offline
  verifier with reproducible builds.
- **Semantic versioning** of the engine crates, the API and the audit schema.
- **LTS releases** once 1.0 ships (policy in `GOVERNANCE.md`, Phase 0).
