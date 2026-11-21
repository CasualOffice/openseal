-- 0051: remote-provider signatures per recipient (`RSP-01`, ADR-046 §3.4, §3.11; docs/22).
--
-- The provider catalogue is the operator's (`OPENSEAL_SIGNING_PROVIDERS_FILE`, read by
-- the server and the worker; docs/65), as the recipient identity providers are
-- (RAUTH-01); these tables hold only what is the account's or the session's.
--
-- 1. `account_signing_providers`: a provider the account enabled from the catalogue, its
--    options (the `signatureQualifier` values it requires, whether a certificate name
--    that differs from the recipient's name refuses the signature instead of being
--    recorded, the session timeout) and, when the account brought its own contract, its
--    OAuth client secret sealed with AES-256-GCM under `OPENSEAL_PROVIDER_SECRETS_KEY`
--    (12-byte nonce ‖ ciphertext ‖ 16-byte tag; the associated data binds it to this
--    account, provider and secret name), never in clear and never returned.
-- 2. `remote_signing_sessions`: one signer's session with a provider (ADR-046 §3.4), from
--    the first redirect to the embedded signature or a failure. The OAuth `state` is kept
--    only as SHA-256, changed at each redirect and spent at first use; the PKCE verifier
--    and the authorization code are sealed under the provider secrets key and cleared at
--    first use. Access tokens and the SAD never reach the database. `prepared` holds, per
--    document, the hashes and the ByteRange the provider's signature binds (the prepared
--    bytes themselves are a content-addressed blob); `credential` the chain and key the
--    provider's `credentials/info` named. At most one session open per envelope.

CREATE TABLE account_signing_providers (
    account_id            uuid NOT NULL REFERENCES accounts (id),
    provider_id           text NOT NULL CHECK (provider_id ~ '^[a-z0-9][a-z0-9-]{0,31}$'),
    enabled               boolean NOT NULL,
    required_qualifiers   text[] NOT NULL DEFAULT '{}'
        CHECK (cardinality(required_qualifiers) <= 8),
    refuse_name_mismatch  boolean NOT NULL DEFAULT false,
    session_minutes       integer NOT NULL DEFAULT 15 CHECK (session_minutes BETWEEN 5 AND 60),
    client_secret_sealed  bytea
        CHECK (client_secret_sealed IS NULL OR octet_length(client_secret_sealed) BETWEEN 29 AND 2076),
    updated_at            timestamptz NOT NULL,
    PRIMARY KEY (account_id, provider_id)
);
SELECT openseal_tenant_table('account_signing_providers', true);

CREATE TABLE remote_signing_sessions (
    id                 uuid PRIMARY KEY,
    account_id         uuid NOT NULL REFERENCES accounts (id),
    envelope_id        uuid NOT NULL,
    recipient_id       uuid NOT NULL,
    provider_id        text NOT NULL CHECK (provider_id ~ '^[a-z0-9][a-z0-9-]{0,31}$'),
    status             text NOT NULL CHECK (status IN (
        'authorizing_service', 'preparing', 'choosing', 'prepared', 'authorizing_credential',
        'signing', 'completed', 'failed')),
    state_sha256       bytea UNIQUE CHECK (state_sha256 IS NULL OR octet_length(state_sha256) = 32),
    pkce_sealed        bytea CHECK (pkce_sealed IS NULL OR octet_length(pkce_sealed) BETWEEN 29 AND 300),
    code_sealed        bytea CHECK (code_sealed IS NULL OR octet_length(code_sealed) BETWEEN 29 AND 4124),
    credential_id      text CHECK (credential_id IS NULL OR char_length(credential_id) BETWEEN 1 AND 255),
    credentials        jsonb CHECK (credentials IS NULL OR octet_length(credentials::text) <= 1048576),
    prepared           jsonb CHECK (prepared IS NULL OR octet_length(prepared::text) <= 262144),
    failure            text CHECK (failure IN ('cancelled', 'expired', 'provider_unavailable',
        'provider_refused', 'response_invalid', 'no_eligible_credential',
        'placeholder_overflow', 'envelope_ended')),
    provider_code      text CHECK (provider_code IS NULL OR provider_code ~ '^[A-Za-z0-9_.-]{1,64}$'),
    created_at         timestamptz NOT NULL,
    expires_at         timestamptz NOT NULL,
    closed_at          timestamptz,
    UNIQUE (account_id, id),
    CHECK (expires_at > created_at),
    CHECK ((status IN ('completed', 'failed')) = (closed_at IS NOT NULL)),
    CHECK ((status = 'failed') = (failure IS NOT NULL)),
    FOREIGN KEY (account_id, envelope_id) REFERENCES envelopes (account_id, id),
    FOREIGN KEY (account_id, recipient_id) REFERENCES recipients (account_id, id)
);
CREATE UNIQUE INDEX remote_signing_sessions_one_open
    ON remote_signing_sessions (account_id, envelope_id) WHERE closed_at IS NULL;
CREATE INDEX remote_signing_sessions_recipient
    ON remote_signing_sessions (account_id, recipient_id, created_at);
SELECT openseal_tenant_table('remote_signing_sessions', true);
