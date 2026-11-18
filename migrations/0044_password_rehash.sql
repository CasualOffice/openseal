-- 0044: re-hash a staff password under the current pepper at sign-in (ASVS 2.4.5,
-- `ASVS-29`, docs/65 §Rotation).
--
-- The server keys staff password hashes with a pepper held outside the database. A hash
-- made before the pepper was configured, or under the previous pepper during a rotation,
-- still verifies; once a sign-in has verified the password, the server stores a new hash
-- under the current pepper. The application role cannot select `users.password_hash`
-- (0014), so it cannot compare it in an UPDATE either: this function replaces the hash
-- only while it is still the one verified (a concurrent change wins), for an enabled
-- local member of the current account. The password itself is unchanged, so no session
-- ends and no notice is sent.

CREATE FUNCTION openseal_rehash_password(p_user uuid, p_expected_hash text, p_password_hash text)
RETURNS boolean
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
DECLARE
    n integer;
BEGIN
    UPDATE users AS u SET password_hash = p_password_hash
      FROM account_memberships AS m
     WHERE u.id = p_user AND m.user_id = u.id AND m.account_id = openseal_current_account()
       AND m.disabled_at IS NULL AND u.disabled_at IS NULL AND u.login_kind = 'local'
       AND u.password_hash = p_expected_hash;
    GET DIAGNOSTICS n = ROW_COUNT;
    RETURN n = 1;
END
$$;
REVOKE ALL ON FUNCTION openseal_rehash_password(uuid, text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openseal_rehash_password(uuid, text, text) TO openseal_app;
