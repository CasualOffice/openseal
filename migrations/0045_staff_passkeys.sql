-- 0045: staff passkeys (WebAuthn) as a second factor, and the administrator's reset of a
-- member's lost factors (CON-13, ASVS-32; ASVS 2.3.2, 2.5.7; docs/40 §2, ADR-039).
--
-- A passkey, like the TOTP authenticator (0032), is the person's factor: once they have
-- one, every session of theirs owes a factor, in every workspace they belong to. A row
-- carries the workspace it was registered in (`account_id`, so the table follows the
-- tenant rules of docs/22: RLS, a policy, a leading index) but is read and changed only
-- through the definer functions below, keyed by the caller's own live session, as the
-- TOTP columns are. The application role may read rows of its account (a public key and
-- a credential id are not secrets) and write none.
--
-- What is stored is what the relying party needs to verify an assertion: the credential
-- id, the public key as SubjectPublicKeyInfo DER (the browser's `getPublicKey()`), the
-- COSE algorithm (ES256 -7, EdDSA -8, RS256 -257) and the signature counter. Attestation
-- is "none": nothing about the authenticator's make is kept or trusted.
--
-- A WebAuthn ceremony's challenge is kept on the staff session (one outstanding at a
-- time, for one purpose, five minutes) and spent by the call that answers it, so an
-- assertion is accepted once.
--
-- Lost factors (ASVS 2.5.7): an administrator of the user's only workspace, after
-- re-authenticating and recording how they proved the person's identity, resets the
-- user's factors: the TOTP seed, recovery codes and passkeys go, every session of theirs
-- in the workspace ends, and `users.factor_reset_at` makes their next sign-in enrol a new
-- factor before anything else, whatever the workspace's policy. Enrolling clears it.

ALTER TABLE users ADD COLUMN factor_reset_at timestamptz;

-- The guard of 0032 now covers the reset mark as well.
DROP TRIGGER users_factor_guard ON users;
CREATE TRIGGER users_factor_guard
    BEFORE UPDATE OF totp_seed_sealed, totp_confirmed_at, totp_last_step, recovery_code_sha256,
                     factor_reset_at ON users
    FOR EACH ROW EXECUTE FUNCTION openseal_users_factor_guard();

ALTER TABLE staff_sessions
    ADD COLUMN webauthn_challenge bytea CHECK (octet_length(webauthn_challenge) = 32),
    ADD COLUMN webauthn_purpose text
        CHECK (webauthn_purpose IN ('register', 'verify', 'reauthenticate')),
    ADD COLUMN webauthn_challenge_expires_at timestamptz,
    ADD CONSTRAINT staff_sessions_webauthn_challenge_whole CHECK (
        (webauthn_challenge IS NULL) = (webauthn_purpose IS NULL)
        AND (webauthn_challenge IS NULL) = (webauthn_challenge_expires_at IS NULL));

CREATE TABLE staff_passkeys (
    account_id     uuid NOT NULL REFERENCES accounts (id),
    id             uuid NOT NULL,
    user_id        uuid NOT NULL REFERENCES users (id),
    credential_id  bytea NOT NULL CHECK (octet_length(credential_id) BETWEEN 1 AND 1023),
    public_key     bytea NOT NULL CHECK (octet_length(public_key) BETWEEN 32 AND 2048),
    algorithm      integer NOT NULL CHECK (algorithm IN (-7, -8, -257)),
    sign_count     bigint NOT NULL CHECK (sign_count BETWEEN 0 AND 4294967295),
    name           text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 64),
    transports     text[] NOT NULL DEFAULT '{}' CHECK (cardinality(transports) <= 8),
    backup_eligible boolean NOT NULL,
    created_at     timestamptz NOT NULL,
    last_used_at   timestamptz,
    PRIMARY KEY (account_id, id),
    -- A credential belongs to one person.
    UNIQUE (credential_id)
);
CREATE INDEX staff_passkeys_account_user ON staff_passkeys (account_id, user_id);
CREATE INDEX staff_passkeys_user ON staff_passkeys (user_id);
SELECT openseal_tenant_table('staff_passkeys', false);
-- Read-only for the application role: every change is a definer function's.
REVOKE INSERT ON staff_passkeys FROM openseal_app;

-- Whether the user has a second factor: a confirmed TOTP or a passkey. Internal.
CREATE FUNCTION openseal_user_has_factor(p_user uuid) RETURNS boolean
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
    SELECT EXISTS (SELECT 1 FROM users WHERE id = p_user AND totp_confirmed_at IS NOT NULL)
        OR EXISTS (SELECT 1 FROM staff_passkeys WHERE user_id = p_user)
$$;
REVOKE ALL ON FUNCTION openseal_user_has_factor(uuid) FROM PUBLIC;

-- The session's own user, when the session has passed its factor or the user has none
-- yet; NULL otherwise. Adding a factor needs this: a session that owes a factor cannot
-- add a second one to get past the first. Internal.
CREATE FUNCTION openseal_mfa_session_user_passed(p_session_id uuid, p_now timestamptz)
RETURNS uuid
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
    SELECT u FROM (SELECT openseal_mfa_session_user(p_session_id, p_now) AS u) AS x
     WHERE x.u IS NOT NULL
       AND (NOT openseal_user_has_factor(x.u)
            OR EXISTS (SELECT 1 FROM staff_sessions AS s
                        WHERE s.account_id = openseal_current_account()
                          AND s.id = p_session_id AND s.mfa_at IS NOT NULL))
$$;
REVOKE ALL ON FUNCTION openseal_mfa_session_user_passed(uuid, timestamptz) FROM PUBLIC;

-- The resolver: a passkey counts as enrolled, and a user whose factors an administrator
-- reset owes enrolment whatever the workspace's policy.
DROP FUNCTION openseal_resolve_staff_session(bytea, timestamptz);
CREATE FUNCTION openseal_resolve_staff_session(p_token_sha256 bytea, p_now timestamptz)
RETURNS TABLE (account_id uuid, session_id uuid, user_id uuid, csrf_sha256 bytea,
               mfa_verified boolean, mfa_enrolled boolean, mfa_policy text,
               organization_policy jsonb, settings jsonb, created_at timestamptz,
               last_seen_at timestamptz, reauth_at timestamptz)
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
    SELECT s.account_id, s.id, s.user_id, s.csrf_sha256,
           s.mfa_at IS NOT NULL,
           u.totp_confirmed_at IS NOT NULL
               OR EXISTS (SELECT 1 FROM staff_passkeys AS k WHERE k.user_id = u.id),
           CASE WHEN u.factor_reset_at IS NOT NULL THEN 'everyone'
                ELSE COALESCE(a.settings ->> 'mfa_policy', 'administrators') END,
           o.policy, a.settings, s.created_at, s.last_seen_at, s.reauth_at
      FROM staff_sessions AS s
      JOIN account_memberships AS m ON m.account_id = s.account_id AND m.user_id = s.user_id
      JOIN users AS u ON u.id = s.user_id
      JOIN accounts AS a ON a.id = s.account_id
      JOIN organizations AS o ON o.id = a.organization_id
     WHERE s.token_sha256 = p_token_sha256 AND s.revoked_at IS NULL AND s.expires_at > p_now
       AND u.disabled_at IS NULL
$$;
REVOKE ALL ON FUNCTION openseal_resolve_staff_session(bytea, timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openseal_resolve_staff_session(bytea, timestamptz) TO openseal_app;

-- The session's own user's factors: a confirmed TOTP, how many passkeys, how many unspent
-- recovery codes, and whether an administrator's reset is waiting for a new enrolment.
CREATE FUNCTION openseal_own_factors(p_session_id uuid, p_now timestamptz)
RETURNS TABLE (user_id uuid, totp boolean, passkeys integer, recovery_codes_left integer,
               factor_reset boolean)
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
    SELECT u.id, u.totp_confirmed_at IS NOT NULL,
           (SELECT count(*)::integer FROM staff_passkeys AS k WHERE k.user_id = u.id),
           cardinality(u.recovery_code_sha256), u.factor_reset_at IS NOT NULL
      FROM users AS u
     WHERE u.id = openseal_mfa_session_user(p_session_id, p_now)
$$;
REVOKE ALL ON FUNCTION openseal_own_factors(uuid, timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openseal_own_factors(uuid, timestamptz) TO openseal_app;

-- The session's own user's passkeys, in every workspace (at most 10), oldest first.
CREATE FUNCTION openseal_own_passkeys(p_session_id uuid, p_now timestamptz)
RETURNS TABLE (id uuid, credential_id bytea, public_key bytea, algorithm integer,
               sign_count bigint, name text, transports text[], backup_eligible boolean,
               created_at timestamptz, last_used_at timestamptz)
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
    SELECT k.id, k.credential_id, k.public_key, k.algorithm, k.sign_count, k.name,
           k.transports, k.backup_eligible, k.created_at, k.last_used_at
      FROM staff_passkeys AS k
     WHERE k.user_id = openseal_mfa_session_user(p_session_id, p_now)
     ORDER BY k.created_at, k.id
     LIMIT 10
$$;
REVOKE ALL ON FUNCTION openseal_own_passkeys(uuid, timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openseal_own_passkeys(uuid, timestamptz) TO openseal_app;

-- Register a passkey for the session's own user. Refused (NULL) when the session owes a
-- factor it has not passed, when the user already has 10, or when the credential is
-- registered already. The user's first factor also sets the ten recovery codes `p_codes`
-- (`codes_set`); a later one leaves theirs as they are. The session has passed its
-- factor, and a reset waiting for enrolment is cleared.
CREATE FUNCTION openseal_add_own_passkey(
    p_session_id uuid, p_id uuid, p_credential_id bytea, p_public_key bytea,
    p_algorithm integer, p_sign_count bigint, p_name text, p_transports text[],
    p_backup_eligible boolean, p_codes bytea[], p_now timestamptz)
RETURNS TABLE (user_id uuid, codes_set boolean)
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
DECLARE
    uid uuid := openseal_mfa_session_user_passed(p_session_id, p_now);
    first boolean;
BEGIN
    IF uid IS NULL
       OR (SELECT count(*) FROM staff_passkeys WHERE staff_passkeys.user_id = uid) >= 10
       OR EXISTS (SELECT 1 FROM staff_passkeys WHERE credential_id = p_credential_id)
       OR cardinality(p_codes) <> 10
       OR EXISTS (SELECT 1 FROM unnest(p_codes) AS c WHERE octet_length(c) <> 32) THEN
        RETURN;
    END IF;
    first := NOT openseal_user_has_factor(uid);
    INSERT INTO staff_passkeys (account_id, id, user_id, credential_id, public_key, algorithm,
                                sign_count, name, transports, backup_eligible, created_at)
    VALUES (openseal_current_account(), p_id, uid, p_credential_id, p_public_key, p_algorithm,
            p_sign_count, p_name, p_transports, p_backup_eligible, p_now);
    UPDATE users SET factor_reset_at = NULL,
                     recovery_code_sha256 = CASE WHEN first THEN p_codes
                                                 ELSE recovery_code_sha256 END
     WHERE id = uid;
    UPDATE staff_sessions SET mfa_at = p_now
     WHERE account_id = openseal_current_account() AND id = p_session_id;
    user_id := uid;
    codes_set := first;
    RETURN NEXT;
END
$$;
REVOKE ALL ON FUNCTION openseal_add_own_passkey(uuid, uuid, bytea, bytea, integer, bigint, text, text[], boolean, bytea[], timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openseal_add_own_passkey(uuid, uuid, bytea, bytea, integer, bigint, text, text[], boolean, bytea[], timestamptz) TO openseal_app;

-- Pass the session's factor with the user's passkey `p_id`, whose assertion the server
-- verified and which reported the counter `p_count`. A counter that does not move past
-- the stored one (except an authenticator that keeps none: both zero) means the
-- credential may have been cloned: refused (NULL), the counter left as it is.
CREATE FUNCTION openseal_use_own_passkey(
    p_session_id uuid, p_id uuid, p_count bigint, p_now timestamptz)
RETURNS uuid
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
DECLARE
    uid uuid;
BEGIN
    UPDATE staff_passkeys AS k SET sign_count = p_count, last_used_at = p_now
     WHERE k.id = p_id AND k.user_id = openseal_mfa_session_user(p_session_id, p_now)
       AND ((p_count = 0 AND k.sign_count = 0) OR p_count > k.sign_count)
    RETURNING k.user_id INTO uid;
    IF uid IS NULL THEN
        RETURN NULL;
    END IF;
    UPDATE staff_sessions SET mfa_at = p_now
     WHERE account_id = openseal_current_account() AND id = p_session_id;
    RETURN uid;
END
$$;
REVOKE ALL ON FUNCTION openseal_use_own_passkey(uuid, uuid, bigint, timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openseal_use_own_passkey(uuid, uuid, bigint, timestamptz) TO openseal_app;

-- Rename one of the session's own user's passkeys; false when it is not theirs. Only a
-- session that has passed its factor.
CREATE FUNCTION openseal_rename_own_passkey(
    p_session_id uuid, p_id uuid, p_name text, p_now timestamptz)
RETURNS boolean
    LANGUAGE sql SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
    WITH done AS (
        UPDATE staff_passkeys SET name = p_name
         WHERE id = p_id AND user_id = openseal_mfa_session_user_passed(p_session_id, p_now)
        RETURNING id
    )
    SELECT EXISTS (SELECT 1 FROM done);
$$;
REVOKE ALL ON FUNCTION openseal_rename_own_passkey(uuid, uuid, text, timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openseal_rename_own_passkey(uuid, uuid, text, timestamptz) TO openseal_app;

-- Remove one of the session's own user's passkeys; false when it is not theirs. When it
-- was their last factor, the recovery codes go with it (they recover a factor that no
-- longer exists).
CREATE FUNCTION openseal_remove_own_passkey(p_session_id uuid, p_id uuid, p_now timestamptz)
RETURNS boolean
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
DECLARE
    uid uuid := openseal_mfa_session_user_passed(p_session_id, p_now);
BEGIN
    IF uid IS NULL THEN
        RETURN false;
    END IF;
    DELETE FROM staff_passkeys WHERE id = p_id AND user_id = uid;
    IF NOT FOUND THEN
        RETURN false;
    END IF;
    IF NOT openseal_user_has_factor(uid) THEN
        UPDATE users SET recovery_code_sha256 = '{}' WHERE id = uid;
        -- No session of theirs counts as having passed a factor they no longer have:
        -- the workspace's policy applies again at once.
        UPDATE staff_sessions SET mfa_at = NULL WHERE user_id = uid;
    END IF;
    RETURN true;
END
$$;
REVOKE ALL ON FUNCTION openseal_remove_own_passkey(uuid, uuid, timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openseal_remove_own_passkey(uuid, uuid, timestamptz) TO openseal_app;

-- Remove the session's own user's TOTP authenticator (to replace it, ASVS-32); false when
-- they have none confirmed or the session has not passed its factor. The recovery codes
-- go too when no passkey is left.
CREATE FUNCTION openseal_remove_own_totp(p_session_id uuid, p_now timestamptz)
RETURNS boolean
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
DECLARE
    uid uuid := openseal_mfa_session_user_passed(p_session_id, p_now);
BEGIN
    IF uid IS NULL THEN
        RETURN false;
    END IF;
    UPDATE users SET totp_seed_sealed = NULL, totp_confirmed_at = NULL, totp_last_step = NULL
     WHERE id = uid AND totp_confirmed_at IS NOT NULL;
    IF NOT FOUND THEN
        RETURN false;
    END IF;
    IF NOT openseal_user_has_factor(uid) THEN
        UPDATE users SET recovery_code_sha256 = '{}' WHERE id = uid;
        -- No session of theirs counts as having passed a factor they no longer have:
        -- the workspace's policy applies again at once.
        UPDATE staff_sessions SET mfa_at = NULL WHERE user_id = uid;
    END IF;
    RETURN true;
END
$$;
REVOKE ALL ON FUNCTION openseal_remove_own_totp(uuid, timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openseal_remove_own_totp(uuid, timestamptz) TO openseal_app;

-- Replace the session's own user's recovery codes with ten new ones; false when they
-- have no factor or the session has not passed it.
CREATE FUNCTION openseal_replace_own_recovery_codes(
    p_session_id uuid, p_codes bytea[], p_now timestamptz)
RETURNS boolean
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
DECLARE
    uid uuid := openseal_mfa_session_user_passed(p_session_id, p_now);
BEGIN
    IF uid IS NULL OR NOT openseal_user_has_factor(uid)
       OR cardinality(p_codes) <> 10
       OR EXISTS (SELECT 1 FROM unnest(p_codes) AS c WHERE octet_length(c) <> 32) THEN
        RETURN false;
    END IF;
    UPDATE users SET recovery_code_sha256 = p_codes WHERE id = uid;
    RETURN true;
END
$$;
REVOKE ALL ON FUNCTION openseal_replace_own_recovery_codes(uuid, bytea[], timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openseal_replace_own_recovery_codes(uuid, bytea[], timestamptz) TO openseal_app;

-- An administrator's reset of a member's lost factors (ASVS 2.5.7): only for a member of
-- the current account who belongs to no other (SEC-ID-01: a person's factor is theirs
-- in every account, so no single account's administrator resets it for the others). The
-- TOTP seed, recovery codes and passkeys go, and the user must enrol at their next
-- sign-in. Who may ask, after what proof, is the server's (docs/40 §2); it also ends the
-- user's sessions and records the event. Answers what was removed, or no row when
-- refused.
CREATE FUNCTION openseal_reset_member_factors(p_user uuid, p_now timestamptz)
RETURNS TABLE (had_totp boolean, passkeys integer)
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
DECLARE
    t boolean;
    n integer;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM account_memberships AS m
                    WHERE m.account_id = openseal_current_account() AND m.user_id = p_user)
       OR openseal_user_in_other_account(p_user) THEN
        RETURN;
    END IF;
    SELECT u.totp_confirmed_at IS NOT NULL INTO t FROM users AS u WHERE u.id = p_user;
    DELETE FROM staff_passkeys WHERE user_id = p_user;
    GET DIAGNOSTICS n = ROW_COUNT;
    UPDATE users SET totp_seed_sealed = NULL, totp_confirmed_at = NULL, totp_last_step = NULL,
                     recovery_code_sha256 = '{}', factor_reset_at = p_now
     WHERE id = p_user;
    had_totp := COALESCE(t, false);
    passkeys := n;
    RETURN NEXT;
END
$$;
REVOKE ALL ON FUNCTION openseal_reset_member_factors(uuid, timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openseal_reset_member_factors(uuid, timestamptz) TO openseal_app;

-- 0032's recovery code now recovers either factor.
CREATE OR REPLACE FUNCTION openseal_use_own_recovery_code(
    p_session_id uuid, p_code_sha256 bytea, p_now timestamptz)
RETURNS integer
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
DECLARE
    remaining integer;
    uid uuid := openseal_mfa_session_user(p_session_id, p_now);
BEGIN
    IF uid IS NULL OR NOT openseal_user_has_factor(uid) THEN
        RETURN NULL;
    END IF;
    UPDATE users SET recovery_code_sha256 = array_remove(recovery_code_sha256, p_code_sha256)
     WHERE id = uid AND p_code_sha256 = ANY (recovery_code_sha256)
    RETURNING cardinality(recovery_code_sha256) INTO remaining;
    IF remaining IS NULL THEN
        RETURN NULL;
    END IF;
    UPDATE staff_sessions SET mfa_at = p_now
     WHERE account_id = openseal_current_account() AND id = p_session_id;
    RETURN remaining;
END
$$;

-- 0032's TOTP enrolment: a user who has a passkey adds a TOTP authenticator only from a
-- session that has passed the passkey (otherwise enrolling a second factor would get a
-- session past the first). Confirming also clears a reset waiting for enrolment.
CREATE OR REPLACE FUNCTION openseal_begin_own_totp(
    p_session_id uuid, p_seed_sealed bytea, p_now timestamptz)
RETURNS uuid
    LANGUAGE sql SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
    UPDATE users SET totp_seed_sealed = p_seed_sealed, totp_last_step = NULL
     WHERE id = openseal_mfa_session_user_passed(p_session_id, p_now)
       AND totp_confirmed_at IS NULL
    RETURNING id;
$$;

CREATE OR REPLACE FUNCTION openseal_confirm_own_totp(
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
                     recovery_code_sha256 = p_codes, factor_reset_at = NULL
     WHERE id = openseal_mfa_session_user_passed(p_session_id, p_now)
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
