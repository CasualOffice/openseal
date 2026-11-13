-- 0032: staff multi-factor authentication in the tenant server (ASVS-01, docs/40 §2).
--
-- A staff user's second factor is a TOTP authenticator (RFC 6238, 30-second steps, six
-- digits), with ten one-time recovery codes. The factor belongs to the person, not to an
-- account, so it lives on `users` beside the password and holds in every account the
-- user belongs to. The seed is stored only sealed (AES-256-GCM under the server's
-- `OPENSEAL_MFA_KEY`, the user id as associated data); the key never reaches the
-- database. Recovery codes are stored only as SHA-256 (each carries 112 random bits).
--
-- A session records when it passed the second factor (`staff_sessions.mfa_at`). The
-- server refuses every `/api/v1` call of a session that owes a factor and has not passed
-- one: a user with a confirmed factor always owes it; an account's `settings.mfa_policy`
-- (`optional`, `administrators` or `everyone`) makes users without one enrol first.
--
-- Every change to the factor goes through the functions below, keyed by the caller's own
-- live session, as 0013's own-user functions are: an administrator of one account can
-- neither read nor change the factor of a user who also belongs to another.

ALTER TABLE users
    ADD COLUMN totp_seed_sealed bytea
        CHECK (octet_length(totp_seed_sealed) BETWEEN 29 AND 128),
    ADD COLUMN totp_confirmed_at timestamptz,
    -- The newest time step a code was accepted for; a code is accepted only for a later
    -- step, so no code is used twice.
    ADD COLUMN totp_last_step bigint CHECK (totp_last_step >= 0),
    ADD COLUMN recovery_code_sha256 bytea[] NOT NULL DEFAULT '{}'
        CHECK (cardinality(recovery_code_sha256) <= 16),
    ADD CONSTRAINT users_totp_confirmed_has_seed
        CHECK (totp_confirmed_at IS NULL OR totp_seed_sealed IS NOT NULL);

ALTER TABLE staff_sessions ADD COLUMN mfa_at timestamptz;

-- The application role reads none of the new columns (0014 grants `users` SELECT per
-- column) and may not write them either: only the definer functions below, which run as
-- the schema owner and are keyed by the user's own live session, change a factor.
-- (`users` UPDATE is granted per table, so a trigger, not a grant, holds the line.)
CREATE FUNCTION openseal_users_factor_guard() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = public, pg_catalog
AS $$
BEGIN
    -- The definer functions run as the schema owner, who owns `users`; any other role
    -- (the application's login role, a member of `openseal_app`) is refused.
    IF current_user <> (SELECT pg_get_userbyid(c.relowner) FROM pg_class AS c WHERE c.oid = TG_RELID) THEN
        RAISE EXCEPTION 'a second factor changes only through its own functions'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    RETURN NEW;
END
$$;
CREATE TRIGGER users_factor_guard
    BEFORE UPDATE OF totp_seed_sealed, totp_confirmed_at, totp_last_step, recovery_code_sha256 ON users
    FOR EACH ROW EXECUTE FUNCTION openseal_users_factor_guard();

-- The resolver also answers the session's factor state and the account's policy, so the
-- server decides on every request without another query.
DROP FUNCTION openseal_resolve_staff_session(bytea, timestamptz);
CREATE FUNCTION openseal_resolve_staff_session(p_token_sha256 bytea, p_now timestamptz)
RETURNS TABLE (account_id uuid, session_id uuid, user_id uuid, csrf_sha256 bytea,
               mfa_verified boolean, mfa_enrolled boolean, mfa_policy text)
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
    SELECT s.account_id, s.id, s.user_id, s.csrf_sha256,
           s.mfa_at IS NOT NULL, u.totp_confirmed_at IS NOT NULL,
           COALESCE(a.settings ->> 'mfa_policy', 'optional')
      FROM staff_sessions AS s
      JOIN account_memberships AS m ON m.account_id = s.account_id AND m.user_id = s.user_id
      JOIN users AS u ON u.id = s.user_id
      JOIN accounts AS a ON a.id = s.account_id
     WHERE s.token_sha256 = p_token_sha256 AND s.revoked_at IS NULL AND s.expires_at > p_now
       AND u.disabled_at IS NULL
$$;
REVOKE ALL ON FUNCTION openseal_resolve_staff_session(bytea, timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openseal_resolve_staff_session(bytea, timestamptz) TO openseal_app;

-- The local user of a live session of the current account, or NULL. Internal: called
-- only by the functions below, never granted to the application role.
CREATE FUNCTION openseal_mfa_session_user(p_session_id uuid, p_now timestamptz)
RETURNS uuid
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
    SELECT s.user_id FROM staff_sessions AS s
      JOIN account_memberships AS m ON m.account_id = s.account_id AND m.user_id = s.user_id
      JOIN users AS u ON u.id = s.user_id
     WHERE s.account_id = openseal_current_account() AND s.id = p_session_id
       AND s.revoked_at IS NULL AND s.expires_at > p_now
       AND m.disabled_at IS NULL AND u.disabled_at IS NULL AND u.login_kind = 'local'
$$;
REVOKE ALL ON FUNCTION openseal_mfa_session_user(uuid, timestamptz) FROM PUBLIC;

-- The session's user, their sealed seed (NULL before enrolment starts) and whether the
-- factor is confirmed; no row when the session is not live.
CREATE FUNCTION openseal_own_totp(p_session_id uuid, p_now timestamptz)
RETURNS TABLE (user_id uuid, seed_sealed bytea, confirmed boolean)
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
    SELECT u.id, u.totp_seed_sealed, u.totp_confirmed_at IS NOT NULL FROM users AS u
     WHERE u.id = openseal_mfa_session_user(p_session_id, p_now)
$$;
REVOKE ALL ON FUNCTION openseal_own_totp(uuid, timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openseal_own_totp(uuid, timestamptz) TO openseal_app;

-- Start (or restart) enrolment with a new sealed seed, only while no factor is
-- confirmed: replacing a confirmed factor is a separate, re-authenticated path.
CREATE FUNCTION openseal_begin_own_totp(p_session_id uuid, p_seed_sealed bytea, p_now timestamptz)
RETURNS uuid
    LANGUAGE sql SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
    UPDATE users SET totp_seed_sealed = p_seed_sealed, totp_last_step = NULL
     WHERE id = openseal_mfa_session_user(p_session_id, p_now) AND totp_confirmed_at IS NULL
    RETURNING id;
$$;
REVOKE ALL ON FUNCTION openseal_begin_own_totp(uuid, bytea, timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openseal_begin_own_totp(uuid, bytea, timestamptz) TO openseal_app;

-- Confirm enrolment: a code for step `p_step` proved the seed `p_seed_sealed` (the one
-- the server opened, so a concurrent restart cannot be confirmed by an older code). The
-- recovery codes replace any earlier ones and this session has passed the factor.
CREATE FUNCTION openseal_confirm_own_totp(
    p_session_id uuid, p_seed_sealed bytea, p_step bigint, p_codes bytea[], p_now timestamptz)
RETURNS uuid
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
DECLARE
    uid uuid;
BEGIN
    IF cardinality(p_codes) <> 10
       OR EXISTS (SELECT 1 FROM unnest(p_codes) AS c WHERE octet_length(c) <> 32) THEN
        RETURN NULL;
    END IF;
    UPDATE users SET totp_confirmed_at = p_now, totp_last_step = p_step,
                     recovery_code_sha256 = p_codes
     WHERE id = openseal_mfa_session_user(p_session_id, p_now)
       AND totp_confirmed_at IS NULL AND totp_seed_sealed = p_seed_sealed
    RETURNING id INTO uid;
    IF uid IS NULL THEN
        RETURN NULL;
    END IF;
    UPDATE staff_sessions SET mfa_at = p_now
     WHERE account_id = openseal_current_account() AND id = p_session_id;
    RETURN uid;
END
$$;
REVOKE ALL ON FUNCTION openseal_confirm_own_totp(uuid, bytea, bigint, bytea[], timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openseal_confirm_own_totp(uuid, bytea, bigint, bytea[], timestamptz) TO openseal_app;

-- Pass the factor with a code for step `p_step`, only when that step is later than every
-- step accepted before (single use, docs/07 SEC-A09). Returns the user, or NULL.
CREATE FUNCTION openseal_verify_own_totp(p_session_id uuid, p_step bigint, p_now timestamptz)
RETURNS uuid
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
DECLARE
    uid uuid;
BEGIN
    UPDATE users SET totp_last_step = p_step
     WHERE id = openseal_mfa_session_user(p_session_id, p_now)
       AND totp_confirmed_at IS NOT NULL
       AND (totp_last_step IS NULL OR totp_last_step < p_step)
    RETURNING id INTO uid;
    IF uid IS NULL THEN
        RETURN NULL;
    END IF;
    UPDATE staff_sessions SET mfa_at = p_now
     WHERE account_id = openseal_current_account() AND id = p_session_id;
    RETURN uid;
END
$$;
REVOKE ALL ON FUNCTION openseal_verify_own_totp(uuid, bigint, timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openseal_verify_own_totp(uuid, bigint, timestamptz) TO openseal_app;

-- Pass the factor with a recovery code, spending it. Returns how many codes are left,
-- or NULL when the code is not one of the user's unspent codes.
CREATE FUNCTION openseal_use_own_recovery_code(
    p_session_id uuid, p_code_sha256 bytea, p_now timestamptz)
RETURNS integer
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
DECLARE
    remaining integer;
BEGIN
    UPDATE users SET recovery_code_sha256 = array_remove(recovery_code_sha256, p_code_sha256)
     WHERE id = openseal_mfa_session_user(p_session_id, p_now)
       AND totp_confirmed_at IS NOT NULL
       AND p_code_sha256 = ANY (recovery_code_sha256)
    RETURNING cardinality(recovery_code_sha256) INTO remaining;
    IF remaining IS NULL THEN
        RETURN NULL;
    END IF;
    UPDATE staff_sessions SET mfa_at = p_now
     WHERE account_id = openseal_current_account() AND id = p_session_id;
    RETURN remaining;
END
$$;
REVOKE ALL ON FUNCTION openseal_use_own_recovery_code(uuid, bytea, timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openseal_use_own_recovery_code(uuid, bytea, timestamptz) TO openseal_app;
