-- 0042: staff session activity, idle timeout, a person's list of their own sessions,
-- and recent re-authentication (ASVS-06, ASVS-07; docs/40 §2, docs/22 §8).
--
-- `last_seen_at` is when the session last made a request (written at most every 15 s,
-- by the server after it authenticated the request); `reauth_at` is when its holder last
-- proved the password (and the second factor, when they have one): at sign-in and
-- through `POST /auth/reauthenticate`. `client_label` is a coarse browser and system
-- name drawn from a closed list by the server ("Firefox on macOS"), never the raw
-- User-Agent: it lets a person tell their sessions apart, and is not personal data.
--
-- The idle and absolute limits are not stored on the row: the server reads the
-- workspace's settings (`session_idle`, `session_max_age`, seconds) tightened by its
-- organization's `session.idle` and `session.max_age` (ORG-08) on every request, so a
-- shorter limit applies to sessions already open. The resolver therefore answers the
-- workspace's settings and the activity times beside what it answered before.
--
-- Existing sessions count as seen when they started; one idle for longer than the
-- default 30 minutes ends at its next request.

ALTER TABLE staff_sessions ADD COLUMN last_seen_at timestamptz;
ALTER TABLE staff_sessions ADD COLUMN reauth_at timestamptz;
ALTER TABLE staff_sessions ADD COLUMN client_label text
    CHECK (client_label IS NULL OR char_length(client_label) BETWEEN 1 AND 64);
UPDATE staff_sessions SET last_seen_at = created_at;
ALTER TABLE staff_sessions ALTER COLUMN last_seen_at SET NOT NULL;

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
           s.mfa_at IS NOT NULL, u.totp_confirmed_at IS NOT NULL,
           COALESCE(a.settings ->> 'mfa_policy', 'administrators'),
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

-- The user of a live session of the current account (any login kind), or NULL.
-- Internal: called only by the two functions below, never granted.
CREATE FUNCTION openseal_live_session_user(p_session_id uuid, p_now timestamptz)
RETURNS uuid
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
    SELECT s.user_id FROM staff_sessions AS s
      JOIN account_memberships AS m ON m.account_id = s.account_id AND m.user_id = s.user_id
      JOIN users AS u ON u.id = s.user_id
     WHERE s.account_id = openseal_current_account() AND s.id = p_session_id
       AND s.revoked_at IS NULL AND s.expires_at > p_now
       AND m.disabled_at IS NULL AND u.disabled_at IS NULL
$$;
REVOKE ALL ON FUNCTION openseal_live_session_user(uuid, timestamptz) FROM PUBLIC;

-- The unrevoked, unexpired sessions of the live session's own user, in every workspace
-- they are an enabled member of, with what the server needs to apply each workspace's
-- idle and absolute limits (its settings and organization policy) and to name it. A
-- person sees only their own sessions; another user's never.
CREATE FUNCTION openseal_own_sessions(p_session_id uuid, p_now timestamptz)
RETURNS TABLE (session_id uuid, account_id uuid, account_name text, method text,
               created_at timestamptz, last_seen_at timestamptz, expires_at timestamptz,
               client_label text, settings jsonb, organization_policy jsonb)
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
    SELECT s.id, s.account_id, a.name, s.method, s.created_at, s.last_seen_at,
           s.expires_at, s.client_label, a.settings, o.policy
      FROM staff_sessions AS s
      JOIN account_memberships AS m ON m.account_id = s.account_id AND m.user_id = s.user_id
      JOIN accounts AS a ON a.id = s.account_id
      JOIN organizations AS o ON o.id = a.organization_id
     WHERE s.user_id = openseal_live_session_user(p_session_id, p_now)
       AND s.revoked_at IS NULL AND s.expires_at > p_now AND m.disabled_at IS NULL
     ORDER BY s.last_seen_at DESC, s.id
     LIMIT 200
$$;
REVOKE ALL ON FUNCTION openseal_own_sessions(uuid, timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openseal_own_sessions(uuid, timestamptz) TO openseal_app;

-- End sessions of the live session's own user, in any workspace: `p_target` alone, or
-- every other one when `p_target` is NULL. Never the calling session itself (that is
-- `POST /auth/logout`), never another user's. Answers how many ended; 0 for a session
-- that is not the user's, already ended, or does not exist.
CREATE FUNCTION openseal_end_own_sessions(p_session_id uuid, p_target uuid, p_now timestamptz)
RETURNS integer
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
DECLARE
    uid uuid := openseal_live_session_user(p_session_id, p_now);
    n integer;
BEGIN
    IF uid IS NULL THEN
        RETURN 0;
    END IF;
    UPDATE staff_sessions SET revoked_at = p_now
     WHERE user_id = uid AND id <> p_session_id AND revoked_at IS NULL
       AND (p_target IS NULL OR id = p_target);
    GET DIAGNOSTICS n = ROW_COUNT;
    RETURN n;
END
$$;
REVOKE ALL ON FUNCTION openseal_end_own_sessions(uuid, uuid, timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openseal_end_own_sessions(uuid, uuid, timestamptz) TO openseal_app;
