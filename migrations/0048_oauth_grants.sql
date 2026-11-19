-- 0048: OAuth 2.1 authorization code with PKCE, rotating refresh tokens, and the JWT
-- bearer grant (RFC 7523) acting for a consenting member (slice 8 `VS-08`, docs/40 §2).
--
-- 1. `oauth_consents`: a member's consent that an API client of the workspace acts as
--    them with these scopes. Given on the consent screen (`POST /oauth/authorize`); at
--    most one live consent per client and member; revoked, never deleted, so a token
--    naming it is refused on its next request.
-- 2. `oauth_codes`: an authorization code, stored as its SHA-256 only, bound to its
--    consent, the redirect URI and the PKCE S256 challenge; spent once, short-lived.
-- 3. `oauth_refresh_tokens`: refresh tokens, stored as SHA-256, rotated on every use.
--    A token spent twice revokes its whole family (OAuth 2.1 §4.3.1, the replay rule).
-- 4. `openseal_resolve_jwt_client`: the workspace a live JWT integration belongs to,
--    found by its id (the assertion's `iss`) before any tenant is known, as
--    `openseal_resolve_api_key` (0007) finds a key's.

CREATE TABLE oauth_consents (
    id           uuid PRIMARY KEY,
    account_id   uuid NOT NULL REFERENCES accounts (id),
    client_id    uuid NOT NULL,
    user_id      uuid NOT NULL,
    scopes       text[] NOT NULL CHECK (cardinality(scopes) BETWEEN 1 AND 32),
    granted_at   timestamptz NOT NULL,
    revoked_at   timestamptz,
    UNIQUE (account_id, id),
    FOREIGN KEY (account_id, client_id) REFERENCES api_clients (account_id, id),
    FOREIGN KEY (account_id, user_id)
        REFERENCES account_memberships (account_id, user_id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX oauth_consents_live
    ON oauth_consents (account_id, client_id, user_id) WHERE revoked_at IS NULL;
SELECT openseal_tenant_table('oauth_consents', true);

CREATE TABLE oauth_codes (
    id              uuid PRIMARY KEY,
    account_id      uuid NOT NULL REFERENCES accounts (id),
    consent_id      uuid NOT NULL,
    code_sha256     bytea NOT NULL UNIQUE CHECK (octet_length(code_sha256) = 32),
    redirect_uri    text NOT NULL CHECK (char_length(redirect_uri) BETWEEN 1 AND 2048),
    code_challenge  text NOT NULL CHECK (char_length(code_challenge) BETWEEN 43 AND 128),
    scopes          text[] NOT NULL,
    expires_at      timestamptz NOT NULL,
    used_at         timestamptz,
    UNIQUE (account_id, id),
    FOREIGN KEY (account_id, consent_id) REFERENCES oauth_consents (account_id, id) ON DELETE CASCADE
);
SELECT openseal_tenant_table('oauth_codes', true);

CREATE TABLE oauth_refresh_tokens (
    id             uuid PRIMARY KEY,
    account_id     uuid NOT NULL REFERENCES accounts (id),
    consent_id     uuid NOT NULL,
    family_id      uuid NOT NULL,
    token_sha256   bytea NOT NULL UNIQUE CHECK (octet_length(token_sha256) = 32),
    scopes         text[] NOT NULL,
    created_at     timestamptz NOT NULL,
    expires_at     timestamptz NOT NULL,
    used_at        timestamptz,
    revoked_at     timestamptz,
    UNIQUE (account_id, id),
    FOREIGN KEY (account_id, consent_id) REFERENCES oauth_consents (account_id, id) ON DELETE CASCADE
);
CREATE INDEX oauth_refresh_tokens_family ON oauth_refresh_tokens (account_id, family_id);
SELECT openseal_tenant_table('oauth_refresh_tokens', true);

CREATE FUNCTION openseal_resolve_jwt_client(p_client_id uuid, p_now timestamptz)
RETURNS TABLE (account_id uuid)
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
    SELECT c.account_id FROM api_clients AS c
     WHERE c.id = p_client_id AND c.kind = 'jwt_integration' AND c.revoked_at IS NULL
       AND (c.expires_at IS NULL OR c.expires_at > p_now)
$$;
REVOKE ALL ON FUNCTION openseal_resolve_jwt_client(uuid, timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openseal_resolve_jwt_client(uuid, timestamptz) TO openseal_app;
