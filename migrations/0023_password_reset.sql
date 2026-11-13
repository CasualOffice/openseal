-- 0023: self-service password reset (UXW-38) and a member's own profile settings (UXW-37).
-- One migration number was given to this work, so both live here.
--
-- Password reset. `POST /auth/password-reset {email}` answers 202 whatever the address;
-- only for a local, enabled user with an enabled membership does it record a reset and
-- queue the job that emails a one-time link. The worker draws the token (256 random
-- bits) and stores only its SHA-256, with a one-hour expiry; the link is spent once, by
-- `POST /auth/password-reset/confirm {token, password}`, which sets the password and
-- ends the user's sessions in every account. The token reached the user's own address,
-- so this is the user acting (as accepting an invitation is, 0013): the shared-user
-- guard does not apply. Personal data: none here beyond ids; the email is never stored.

CREATE TABLE password_resets (
    id              uuid PRIMARY KEY,
    -- The account whose worker sends the email (the user's earliest enabled membership).
    account_id      uuid NOT NULL REFERENCES accounts (id),
    user_id         uuid NOT NULL,
    requested_at    timestamptz NOT NULL,
    -- Set by the worker as it emails the link; only the hash.
    token_sha256    bytea UNIQUE CHECK (token_sha256 IS NULL OR octet_length(token_sha256) = 32),
    sent_at         timestamptz,
    expires_at      timestamptz,
    used_at         timestamptz,
    revoked_at      timestamptz,
    UNIQUE (account_id, id),
    FOREIGN KEY (account_id, user_id) REFERENCES account_memberships (account_id, user_id)
        ON DELETE CASCADE
);
CREATE INDEX password_resets_user ON password_resets (user_id, requested_at DESC);
SELECT openseal_tenant_table('password_resets', true);

-- Record a reset for the local, enabled user whose normalized email is `p_email`, unless
-- one was requested for them in the last minute (so a flood of requests for one address
-- still sends at most one email a minute), and queue the job that emails its link (the
-- caller supplies the job: kind, key, payload and attempts, as `NewJob` builds them).
-- Earlier open resets of the user, in every account, are revoked. Returns the account
-- whose worker sends the email, or NULL (no such user, not local, disabled, or
-- throttled): the caller answers alike either way. Reset and job are written by this one
-- statement, so an address with an account costs the caller no extra round trip, which
-- would time apart known from unknown addresses (SEC-A13, UXW-38C).
CREATE FUNCTION openseal_request_password_reset(
    p_email text, p_reset_id uuid, p_job_id uuid, p_job_kind text, p_job_key text,
    p_job_payload jsonb, p_job_max_attempts integer, p_now timestamptz)
RETURNS uuid
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
DECLARE
    uid uuid;
    acct uuid;
BEGIN
    SELECT u.id, m.account_id INTO uid, acct FROM users AS u
      JOIN account_memberships AS m ON m.user_id = u.id AND m.disabled_at IS NULL
     WHERE u.email_normalized = p_email AND u.login_kind = 'local' AND u.disabled_at IS NULL
     ORDER BY m.created_at, m.account_id
     LIMIT 1;
    IF uid IS NULL THEN
        RETURN NULL;
    END IF;
    IF EXISTS (SELECT 1 FROM password_resets
                WHERE user_id = uid AND requested_at > p_now - interval '1 minute') THEN
        RETURN NULL;
    END IF;
    UPDATE password_resets SET revoked_at = p_now
     WHERE user_id = uid AND used_at IS NULL AND revoked_at IS NULL;
    INSERT INTO password_resets (id, account_id, user_id, requested_at)
         VALUES (p_reset_id, acct, uid, p_now);
    INSERT INTO jobs (id, account_id, kind, idempotency_key, payload, run_at, max_attempts)
         VALUES (p_job_id, acct, p_job_kind, p_job_key, p_job_payload, p_now, p_job_max_attempts);
    RETURN acct;
END
$$;
REVOKE ALL ON FUNCTION openseal_request_password_reset(text, uuid, uuid, text, text, jsonb, integer, timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openseal_request_password_reset(text, uuid, uuid, text, text, jsonb, integer, timestamptz) TO openseal_app;

-- The open, sent, unexpired reset a link's hash names, while its user and membership are
-- enabled: its account, id and user.
CREATE FUNCTION openseal_resolve_password_reset(p_token_sha256 bytea, p_now timestamptz)
RETURNS TABLE (account_id uuid, reset_id uuid, user_id uuid)
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
    SELECT r.account_id, r.id, r.user_id FROM password_resets AS r
      JOIN account_memberships AS m ON m.account_id = r.account_id AND m.user_id = r.user_id
      JOIN users AS u ON u.id = r.user_id
     WHERE r.token_sha256 = p_token_sha256 AND r.used_at IS NULL AND r.revoked_at IS NULL
       AND r.sent_at IS NOT NULL AND r.expires_at > p_now
       AND m.disabled_at IS NULL AND u.disabled_at IS NULL AND u.login_kind = 'local'
$$;
REVOKE ALL ON FUNCTION openseal_resolve_password_reset(bytea, timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openseal_resolve_password_reset(bytea, timestamptz) TO openseal_app;

-- Spend an open reset of the current account and set its user's password (an Argon2id
-- PHC string). The user's other open resets are revoked and their sessions end in every
-- account. Returns the user's id, or NULL when the reset was not open (a second use).
CREATE FUNCTION openseal_use_password_reset(p_reset_id uuid, p_password_hash text, p_now timestamptz)
RETURNS uuid
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
DECLARE
    acct uuid := openseal_current_account();
    uid uuid;
BEGIN
    UPDATE password_resets AS r SET used_at = p_now
     WHERE r.account_id = acct AND r.id = p_reset_id
       AND r.used_at IS NULL AND r.revoked_at IS NULL
       AND r.sent_at IS NOT NULL AND r.expires_at > p_now
       AND EXISTS (SELECT 1 FROM account_memberships m JOIN users u ON u.id = m.user_id
                    WHERE m.account_id = acct AND m.user_id = r.user_id
                      AND m.disabled_at IS NULL AND u.disabled_at IS NULL
                      AND u.login_kind = 'local')
    RETURNING r.user_id INTO uid;
    IF uid IS NULL THEN
        RETURN NULL;
    END IF;
    UPDATE users SET password_hash = p_password_hash WHERE id = uid;
    UPDATE password_resets SET revoked_at = p_now
     WHERE user_id = uid AND used_at IS NULL AND revoked_at IS NULL;
    PERFORM openseal_revoke_user_sessions(uid, p_now);
    RETURN uid;
END
$$;
REVOKE ALL ON FUNCTION openseal_use_password_reset(uuid, text, timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openseal_use_password_reset(uuid, text, timestamptz) TO openseal_app;

-- The user of a live session of the current account changes their own password, proving
-- the current one first (the server verifies it against `password_hash`, which the
-- application role reads only through this pair). Unlike 0013's function, the session
-- making the change stays live: every other session of the user, in every account, ends.

-- The Argon2id PHC string of the live session's user, for the server to verify the
-- current password against; NULL when the session is not live or the user has none.
CREATE FUNCTION openseal_own_password_hash(p_session_id uuid, p_now timestamptz)
RETURNS text
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
    SELECT u.password_hash FROM staff_sessions AS s
      JOIN account_memberships AS m ON m.account_id = s.account_id AND m.user_id = s.user_id
      JOIN users AS u ON u.id = s.user_id
     WHERE s.account_id = openseal_current_account() AND s.id = p_session_id
       AND s.revoked_at IS NULL AND s.expires_at > p_now
       AND m.disabled_at IS NULL AND u.disabled_at IS NULL AND u.login_kind = 'local'
$$;
REVOKE ALL ON FUNCTION openseal_own_password_hash(uuid, timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openseal_own_password_hash(uuid, timestamptz) TO openseal_app;

-- Set the live session's user's password, only while their stored hash is still
-- `p_expected_hash` (the one the server verified), and end every other session of theirs
-- in every account, as well as their open resets. Returns the user's id, or NULL.
CREATE FUNCTION openseal_change_own_password(
    p_session_id uuid, p_expected_hash text, p_password_hash text, p_now timestamptz)
RETURNS uuid
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
DECLARE
    uid uuid;
BEGIN
    SELECT s.user_id INTO uid FROM staff_sessions AS s
      JOIN account_memberships AS m ON m.account_id = s.account_id AND m.user_id = s.user_id
      JOIN users AS u ON u.id = s.user_id
     WHERE s.account_id = openseal_current_account() AND s.id = p_session_id
       AND s.revoked_at IS NULL AND s.expires_at > p_now
       AND m.disabled_at IS NULL AND u.disabled_at IS NULL AND u.login_kind = 'local'
       AND u.password_hash = p_expected_hash
       FOR UPDATE OF u;
    IF uid IS NULL THEN
        RETURN NULL;
    END IF;
    UPDATE users SET password_hash = p_password_hash WHERE id = uid;
    UPDATE staff_sessions SET revoked_at = p_now
     WHERE user_id = uid AND id <> p_session_id AND revoked_at IS NULL;
    UPDATE password_resets SET revoked_at = p_now
     WHERE user_id = uid AND used_at IS NULL AND revoked_at IS NULL;
    RETURN uid;
END
$$;
REVOKE ALL ON FUNCTION openseal_change_own_password(uuid, text, text, timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openseal_change_own_password(uuid, text, text, timestamptz) TO openseal_app;

-- A member's own settings in this account (UXW-37): which notices they want, and a saved
-- signature and initials (PNG or JPEG, at most 5 MiB each; personal data, never logged,
-- removed by setting NULL). Removing the member removes the row.
CREATE TABLE member_profiles (
    account_id       uuid NOT NULL REFERENCES accounts (id),
    user_id          uuid NOT NULL,
    notifications    jsonb NOT NULL CHECK (jsonb_typeof(notifications) = 'object'),
    signature_image  bytea CHECK (signature_image IS NULL OR octet_length(signature_image) BETWEEN 1 AND 5242880),
    initials_image   bytea CHECK (initials_image IS NULL OR octet_length(initials_image) BETWEEN 1 AND 5242880),
    updated_at       timestamptz NOT NULL,
    PRIMARY KEY (account_id, user_id),
    FOREIGN KEY (account_id, user_id) REFERENCES account_memberships (account_id, user_id)
        ON DELETE CASCADE
);
SELECT openseal_tenant_table('member_profiles', true);
