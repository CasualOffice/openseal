-- 0038: the organization policy reaches every staff request (ORG-08, docs/23 §3).
--
-- `organizations.policy` (migration 0014, keys defined by ORG-08 in
-- `casual-sign-policy::org`) holds the organization's keys, each `{value, locked}`.
-- The second-factor key, `login.mfa_required`, is tighten-only: a workspace's own
-- `settings.mfa_policy` may be stricter, never looser, and the stricter of the two
-- applies on every request without rewriting the workspace's row. The resolver
-- therefore answers the organization's policy beside the workspace's setting, and the
-- server combines them with `casual_sign_policy::org::effective_mfa`.
--
-- Nothing else changes: the same rows, the same default (`administrators`, 0036).

DROP FUNCTION openseal_resolve_staff_session(bytea, timestamptz);
CREATE FUNCTION openseal_resolve_staff_session(p_token_sha256 bytea, p_now timestamptz)
RETURNS TABLE (account_id uuid, session_id uuid, user_id uuid, csrf_sha256 bytea,
               mfa_verified boolean, mfa_enrolled boolean, mfa_policy text,
               organization_policy jsonb)
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
    SELECT s.account_id, s.id, s.user_id, s.csrf_sha256,
           s.mfa_at IS NOT NULL, u.totp_confirmed_at IS NOT NULL,
           COALESCE(a.settings ->> 'mfa_policy', 'administrators'),
           o.policy
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
