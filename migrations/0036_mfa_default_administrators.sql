-- 0036: administrators owe a second factor by default (ASVS-31, docs/40 §2).
--
-- Until now an account with no `settings.mfa_policy` read as `optional`. From here an
-- unset policy reads as `administrators`, so every account created from now on, and
-- every existing account that never chose a policy (the old default), requires its
-- administrators to sign in with a second factor; one without a factor enrols at their
-- next sign-in, and the server refuses everything else until they do (`403
-- CS-AUTH-0011`, detail `enrol`).
--
-- An explicit choice stands. `administrators` and `everyone` are left as they are. An
-- explicit `optional` is kept too: it was written deliberately by an administrator of
-- the account through `PATCH /accounts/me` after `optional` stopped being something one
-- needed to write, and silently overriding a tenant's recorded choice is not done by a
-- migration (docs/40 §2 records the decision). `settings.mfa_policy: null` removes the
-- choice and returns the account to the default. No row is changed: the default lives
-- in the one function that reads the setting.

DROP FUNCTION openseal_resolve_staff_session(bytea, timestamptz);
CREATE FUNCTION openseal_resolve_staff_session(p_token_sha256 bytea, p_now timestamptz)
RETURNS TABLE (account_id uuid, session_id uuid, user_id uuid, csrf_sha256 bytea,
               mfa_verified boolean, mfa_enrolled boolean, mfa_policy text)
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
    SELECT s.account_id, s.id, s.user_id, s.csrf_sha256,
           s.mfa_at IS NOT NULL, u.totp_confirmed_at IS NOT NULL,
           COALESCE(a.settings ->> 'mfa_policy', 'administrators')
      FROM staff_sessions AS s
      JOIN account_memberships AS m ON m.account_id = s.account_id AND m.user_id = s.user_id
      JOIN users AS u ON u.id = s.user_id
      JOIN accounts AS a ON a.id = s.account_id
     WHERE s.token_sha256 = p_token_sha256 AND s.revoked_at IS NULL AND s.expires_at > p_now
       AND u.disabled_at IS NULL
$$;
REVOKE ALL ON FUNCTION openseal_resolve_staff_session(bytea, timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openseal_resolve_staff_session(bytea, timestamptz) TO openseal_app;
