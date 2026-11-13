-- 0030: recipient sign-in through an OpenID Connect provider (`sso`, slice 5, RAUTH-01).
--
-- A recipient whose sender requires `sso` starts a sign-in from the signing page: the
-- server opens a row here and sends the browser to the provider's authorization endpoint
-- with `state`, `nonce` and a PKCE challenge (S256). The browser comes back with a code;
-- the server finds the row by the SHA-256 of `state`, exchanges the code with the stored
-- verifier, and checks the ID token's issuer, audience, expiry and nonce, and that its
-- verified email is the recipient's.
--
-- `state` itself is never stored (only its hash). The nonce and the verifier are
-- short-lived secrets used once: a row closes at its first use, pass or fail (`used`), or
-- when a newer sign-in starts (`superseded`), so a replayed `state` or nonce finds
-- nothing open. At most one open row per recipient (the partial unique index). Rows stay
-- as the record of attempts; the audit chain holds the outcome.

CREATE TABLE recipient_sso_challenges (
    id             uuid PRIMARY KEY,
    account_id     uuid NOT NULL REFERENCES accounts (id),
    recipient_id   uuid NOT NULL,
    -- The operator's id for the provider (OPENSEAL_RECIPIENT_IDPS_FILE).
    provider       text NOT NULL CHECK (provider ~ '^[a-z0-9-]{1,32}$'),
    state_sha256   bytea NOT NULL CHECK (octet_length(state_sha256) = 32),
    nonce          text NOT NULL CHECK (length(nonce) BETWEEN 32 AND 128),
    code_verifier  text NOT NULL CHECK (length(code_verifier) BETWEEN 43 AND 128),
    created_at     timestamptz NOT NULL,
    expires_at     timestamptz NOT NULL,
    closed_at      timestamptz,
    closed_reason  text CHECK (closed_reason IN ('used', 'superseded')),
    UNIQUE (account_id, id),
    CHECK (expires_at > created_at),
    CHECK ((closed_at IS NULL) = (closed_reason IS NULL)),
    FOREIGN KEY (account_id, recipient_id) REFERENCES recipients (account_id, id)
);
CREATE UNIQUE INDEX recipient_sso_challenges_one_open
    ON recipient_sso_challenges (account_id, recipient_id) WHERE closed_at IS NULL;
SELECT openseal_tenant_table('recipient_sso_challenges', true);
