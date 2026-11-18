-- 0042: re-sealing staff TOTP seeds under a new second-factor key (HRD-12, ASVS 1.6.3,
-- docs/65 §Rotation).
--
-- A seed is sealed under the server's `OPENSEAL_MFA_KEY` (0032). To rotate that key the
-- operator gives the server the new key and the old one as `OPENSEAL_MFA_PREVIOUS_KEY`:
-- the server opens a seed under either, and moves it under the new key in two ways,
-- both through the functions below, since the application role may not write a factor
-- itself (0032's trigger):
--
-- - on use: when the user's own session proves a code (sign-in step or enrolment
--   confirmation), the server re-seals the seed it just opened;
-- - in bulk: `casual-sign-server mfa-reseal`, as the schema owner, re-seals every seed
--   still under the previous key, so the previous key can be retired without waiting
--   for every user to sign in.
--
-- Both replace a seed only when it is still the exact sealed value the server opened
-- (compare and set), so a concurrent enrolment restart or a second re-seal is never
-- overwritten. The database cannot tell that the new value seals the same seed; what it
-- can hold is who may ask: a confirmed factor is re-sealed through a session only after
-- that session has passed the factor.

CREATE FUNCTION openseal_reseal_own_totp(
    p_session_id uuid, p_old_sealed bytea, p_new_sealed bytea, p_now timestamptz)
RETURNS uuid
    LANGUAGE sql SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
    UPDATE users AS u SET totp_seed_sealed = p_new_sealed
     WHERE u.id = openseal_mfa_session_user(p_session_id, p_now)
       AND u.totp_seed_sealed = p_old_sealed
       AND (u.totp_confirmed_at IS NULL
            OR EXISTS (SELECT 1 FROM staff_sessions AS s
                        WHERE s.account_id = openseal_current_account()
                          AND s.id = p_session_id AND s.mfa_at IS NOT NULL))
    RETURNING u.id;
$$;
REVOKE ALL ON FUNCTION openseal_reseal_own_totp(uuid, bytea, bytea, timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openseal_reseal_own_totp(uuid, bytea, bytea, timestamptz) TO openseal_app;

-- The bulk re-seal, for the schema owner alone (never granted to the application role):
-- replace one user's sealed seed, only when it is still `p_old_sealed`.
CREATE FUNCTION openseal_reseal_totp_seed(p_user uuid, p_old_sealed bytea, p_new_sealed bytea)
RETURNS boolean
    LANGUAGE sql SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
    WITH done AS (
        UPDATE users SET totp_seed_sealed = p_new_sealed
         WHERE id = p_user AND totp_seed_sealed = p_old_sealed
        RETURNING id
    )
    SELECT EXISTS (SELECT 1 FROM done);
$$;
REVOKE ALL ON FUNCTION openseal_reseal_totp_seed(uuid, bytea, bytea) FROM PUBLIC;
