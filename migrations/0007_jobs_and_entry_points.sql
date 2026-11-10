-- 0007: the job queue (ADR-012: in PostgreSQL) and the entry points that find an account
-- from a secret before any account is known.
--
-- These SECURITY DEFINER functions are the only paths that read across accounts. Each
-- takes a hash or a supplied lease token, returns ids only, and is executable by the
-- application role alone. Everything after them runs through the tenancy-scoped
-- repository with the account they returned.

CREATE TABLE jobs (
    id               uuid PRIMARY KEY,
    account_id       uuid NOT NULL REFERENCES accounts (id),
    envelope_id      uuid,
    -- `send_invitation`, `seal_envelope`, `deliver_webhook`, ... (docs/24 §1 effects).
    kind             text NOT NULL CHECK (kind ~ '^[a-z][a-z0-9_]{0,63}$'),
    -- Effects are performed idempotently, keyed by (envelope, effect id) (docs/24 §1).
    idempotency_key  text NOT NULL CHECK (char_length(idempotency_key) BETWEEN 1 AND 255),
    payload          jsonb NOT NULL DEFAULT '{}'::jsonb,
    status           text NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'running', 'done', 'dead')),
    run_at           timestamptz NOT NULL,
    attempts         integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    max_attempts     integer NOT NULL DEFAULT 15 CHECK (max_attempts > 0),
    lease_token      uuid,
    locked_until     timestamptz,
    locked_by        text CHECK (locked_by IS NULL OR char_length(locked_by) <= 255),
    last_error_code  text CHECK (last_error_code IS NULL OR char_length(last_error_code) <= 32),
    created_at       timestamptz NOT NULL DEFAULT now(),
    finished_at      timestamptz,
    UNIQUE (account_id, id),
    UNIQUE (account_id, idempotency_key),
    FOREIGN KEY (account_id, envelope_id) REFERENCES envelopes (account_id, id)
);
CREATE INDEX jobs_ready ON jobs (run_at) WHERE status IN ('queued', 'running');
SELECT openseal_tenant_table('jobs', true);

-- Claim up to `p_max` due jobs of the given kinds for a worker, under a lease. A running
-- job whose lease has lapsed is claimable again (its worker died). Time and the lease
-- token are supplied by the caller.
CREATE FUNCTION openseal_claim_jobs(
    p_worker text, p_kinds text[], p_max integer, p_now timestamptz,
    p_lease_seconds integer, p_lease_token uuid)
RETURNS TABLE (id uuid, account_id uuid, envelope_id uuid, kind text, payload jsonb, attempts integer)
    LANGUAGE sql SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
    -- A job whose last allowed attempt's worker died is dead, not running forever.
    UPDATE jobs SET status = 'dead', lease_token = NULL, locked_until = NULL, finished_at = p_now
     WHERE status = 'running' AND locked_until < p_now AND attempts >= max_attempts
       AND kind = ANY (p_kinds);
    UPDATE jobs AS j
       SET status = 'running',
           attempts = j.attempts + 1,
           lease_token = p_lease_token,
           locked_until = p_now + make_interval(secs => p_lease_seconds),
           locked_by = p_worker
     WHERE j.id IN (
        SELECT c.id FROM jobs AS c
         WHERE c.kind = ANY (p_kinds)
           AND c.attempts < c.max_attempts
           AND ((c.status = 'queued' AND c.run_at <= p_now)
             OR (c.status = 'running' AND c.locked_until < p_now))
         ORDER BY c.run_at
         LIMIT LEAST(GREATEST(p_max, 0), 1000)
         FOR UPDATE SKIP LOCKED)
    RETURNING j.id, j.account_id, j.envelope_id, j.kind, j.payload, j.attempts
$$;

CREATE FUNCTION openseal_resolve_recipient_token(p_token_sha256 bytea, p_now timestamptz)
RETURNS TABLE (account_id uuid, envelope_id uuid, recipient_id uuid)
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
    SELECT t.account_id, t.envelope_id, t.recipient_id FROM recipient_tokens AS t
     WHERE t.token_sha256 = p_token_sha256 AND t.revoked_at IS NULL AND t.expires_at > p_now
$$;

CREATE FUNCTION openseal_resolve_api_key(p_secret_sha256 bytea, p_now timestamptz)
RETURNS TABLE (account_id uuid, api_client_id uuid)
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
    SELECT c.account_id, c.id FROM api_clients AS c
     WHERE c.secret_sha256 = p_secret_sha256 AND c.revoked_at IS NULL
       AND (c.expires_at IS NULL OR c.expires_at > p_now)
$$;

CREATE FUNCTION openseal_resolve_signing_link(p_token_sha256 bytea, p_now timestamptz)
RETURNS TABLE (account_id uuid, signing_link_id uuid)
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
    SELECT l.account_id, l.id FROM signing_links AS l
     WHERE l.token_sha256 = p_token_sha256 AND l.disabled_at IS NULL
       AND (l.expires_at IS NULL OR l.expires_at > p_now)
       AND (l.max_uses IS NULL OR l.use_count < l.max_uses)
$$;

-- Login: the user an email or an identity provider subject names, and their accounts.
CREATE FUNCTION openseal_resolve_user_login(p_email_normalized text, p_idp_issuer text, p_idp_subject text)
RETURNS TABLE (user_id uuid, account_id uuid)
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
    SELECT u.id, m.account_id FROM users AS u
      JOIN account_memberships AS m ON m.user_id = u.id
     WHERE u.disabled_at IS NULL
       AND ((p_email_normalized IS NOT NULL AND u.email_normalized = p_email_normalized)
         OR (p_idp_issuer IS NOT NULL AND u.idp_issuer = p_idp_issuer AND u.idp_subject = p_idp_subject))
$$;

-- Add an existing user (of another account) to the current account. A user id alone is
-- not enough: the caller must also present the user's normalized email, as an accepted
-- invitation does, so an account cannot enrol (and then read) a stranger by guessing or
-- learning their id.
CREATE FUNCTION openseal_add_existing_member(p_user_id uuid, p_email_normalized text, p_profile_id uuid)
RETURNS boolean
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
DECLARE
    acct uuid := openseal_current_account();
BEGIN
    IF acct IS NULL THEN
        RETURN false;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM users u WHERE u.id = p_user_id
                   AND u.email_normalized = p_email_normalized AND u.disabled_at IS NULL) THEN
        RETURN false;
    END IF;
    INSERT INTO account_memberships (account_id, user_id, permission_profile_id)
        VALUES (acct, p_user_id, p_profile_id);
    RETURN true;
END
$$;

REVOKE ALL ON FUNCTION openseal_add_existing_member(uuid, text, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openseal_add_existing_member(uuid, text, uuid) TO openseal_app;
REVOKE ALL ON FUNCTION openseal_claim_jobs(text, text[], integer, timestamptz, integer, uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION openseal_resolve_recipient_token(bytea, timestamptz) FROM PUBLIC;
REVOKE ALL ON FUNCTION openseal_resolve_api_key(bytea, timestamptz) FROM PUBLIC;
REVOKE ALL ON FUNCTION openseal_resolve_signing_link(bytea, timestamptz) FROM PUBLIC;
REVOKE ALL ON FUNCTION openseal_resolve_user_login(text, text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openseal_claim_jobs(text, text[], integer, timestamptz, integer, uuid) TO openseal_app;
GRANT EXECUTE ON FUNCTION openseal_resolve_recipient_token(bytea, timestamptz) TO openseal_app;
GRANT EXECUTE ON FUNCTION openseal_resolve_api_key(bytea, timestamptz) TO openseal_app;
GRANT EXECUTE ON FUNCTION openseal_resolve_signing_link(bytea, timestamptz) TO openseal_app;
GRANT EXECUTE ON FUNCTION openseal_resolve_user_login(text, text, text) TO openseal_app;
