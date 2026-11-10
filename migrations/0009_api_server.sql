-- 0008: what the API server (stage 2C, docs/40) needs beyond 0001 to 0007.
--
-- 1. The workflow engine's aggregate (`casual_sign_workflow::EnvelopeState`) as the
--    authority for an envelope; the columns of `envelopes`, and the `recipients` rows,
--    are projections the server writes from it in the same transaction (docs/22 §10).
-- 2. The API client that created an envelope: an embedding host may act only for the
--    envelopes it created (tracker row WF-05).
-- 3. A recipient token's browser binding (docs/40 §6: exchanged on first use for a
--    session bound to the browser).
-- 4. Idempotency records (docs/40 §1: replays within 24 h return the first response).
-- 5. Staff sessions (docs/40 §2: session cookie and CSRF token), hashed at rest.

ALTER TABLE envelopes
    ADD COLUMN engine_state jsonb
        CHECK (engine_state IS NULL OR jsonb_typeof(engine_state) = 'object'),
    ADD COLUMN host_client_id uuid,
    ADD FOREIGN KEY (account_id, host_client_id) REFERENCES api_clients (account_id, id);
-- Cursor pagination over every envelope of an account, newest first.
CREATE INDEX envelopes_account_cursor ON envelopes (account_id, created_at DESC, id DESC);

ALTER TABLE recipient_tokens
    ADD COLUMN session_sha256 bytea
        CHECK (session_sha256 IS NULL OR octet_length(session_sha256) = 32);

-- The first response to a POST carrying `Idempotency-Key`, per principal. `body` is the
-- response the client already received; it holds what that response held (personal
-- data at most, never a secret: responses that reveal a secret store no body).
CREATE TABLE idempotency_keys (
    account_id      uuid NOT NULL REFERENCES accounts (id),
    principal       text NOT NULL CHECK (char_length(principal) BETWEEN 1 AND 128),
    key             text NOT NULL CHECK (char_length(key) BETWEEN 1 AND 255),
    request_sha256  bytea NOT NULL CHECK (octet_length(request_sha256) = 32),
    status          integer NOT NULL CHECK (status BETWEEN 100 AND 599),
    body            bytea,
    created_at      timestamptz NOT NULL,
    PRIMARY KEY (account_id, principal, key)
);
CREATE INDEX idempotency_keys_account_created ON idempotency_keys (account_id, created_at);
SELECT openseal_tenant_table('idempotency_keys', true);

-- A signed-in staff user's session. The cookie's secret and the CSRF token are stored
-- as SHA-256 only.
CREATE TABLE staff_sessions (
    id             uuid PRIMARY KEY,
    account_id     uuid NOT NULL REFERENCES accounts (id),
    user_id        uuid NOT NULL,
    token_sha256   bytea NOT NULL UNIQUE CHECK (octet_length(token_sha256) = 32),
    csrf_sha256    bytea NOT NULL CHECK (octet_length(csrf_sha256) = 32),
    method         text NOT NULL CHECK (method IN ('password', 'oidc', 'webauthn')),
    created_at     timestamptz NOT NULL,
    expires_at     timestamptz NOT NULL,
    revoked_at     timestamptz,
    UNIQUE (account_id, id),
    -- Removing the member ends their sessions here (sessions are not evidence).
    FOREIGN KEY (account_id, user_id) REFERENCES account_memberships (account_id, user_id)
        ON DELETE CASCADE
);
CREATE INDEX staff_sessions_account_user ON staff_sessions (account_id, user_id);
SELECT openseal_tenant_table('staff_sessions', true);

-- The live session a cookie's hash names, while its user is enabled and still a member.
CREATE FUNCTION openseal_resolve_staff_session(p_token_sha256 bytea, p_now timestamptz)
RETURNS TABLE (account_id uuid, session_id uuid, user_id uuid, csrf_sha256 bytea)
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
    SELECT s.account_id, s.id, s.user_id, s.csrf_sha256 FROM staff_sessions AS s
      JOIN account_memberships AS m ON m.account_id = s.account_id AND m.user_id = s.user_id
      JOIN users AS u ON u.id = s.user_id
     WHERE s.token_sha256 = p_token_sha256 AND s.revoked_at IS NULL AND s.expires_at > p_now
       AND u.disabled_at IS NULL
$$;

REVOKE ALL ON FUNCTION openseal_resolve_staff_session(bytea, timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openseal_resolve_staff_session(bytea, timestamptz) TO openseal_app;
