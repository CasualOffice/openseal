-- 0013: a user who belongs to more than one account (SEC-ID-01, docs/07).
--
-- `users` has no account column: its row (password, name, email, global disabled state)
-- is seen by every account the user belongs to. Until organizations exist, an account
-- may change that row only while the user's one membership is in that account; a user
-- who also belongs to another account changes their own row, through their own live
-- session or a set-password invitation sent to their own address, and a new password
-- then ends their sessions in every account.
--
-- 0002's `member_of_current_account` policy applied to every command; it now governs
-- reading only, and updating needs the user to be a member of no other account.

-- True when `p_user_id` is a member of the current account and also of another one.
-- Answers false for a user of no membership here, so it cannot probe other accounts.
CREATE FUNCTION openseal_user_in_other_account(p_user_id uuid) RETURNS boolean
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
    SELECT EXISTS (SELECT 1 FROM account_memberships m
                    WHERE m.user_id = p_user_id AND m.account_id = openseal_current_account())
       AND EXISTS (SELECT 1 FROM account_memberships o
                    WHERE o.user_id = p_user_id AND o.account_id <> openseal_current_account())
$$;
REVOKE ALL ON FUNCTION openseal_user_in_other_account(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openseal_user_in_other_account(uuid) TO openseal_app;

DROP POLICY member_of_current_account ON users;
CREATE POLICY member_of_current_account ON users FOR SELECT
    USING (EXISTS (
        SELECT 1 FROM account_memberships m
        WHERE m.user_id = users.id AND m.account_id = openseal_current_account()));
CREATE POLICY sole_member_of_current_account ON users FOR UPDATE
    USING (EXISTS (
            SELECT 1 FROM account_memberships m
            WHERE m.user_id = users.id AND m.account_id = openseal_current_account())
        AND NOT openseal_user_in_other_account(users.id));

-- End every session of `p_user_id`, in every account. Internal: called only by the two
-- functions below, never granted to the application role.
CREATE FUNCTION openseal_revoke_user_sessions(p_user_id uuid, p_now timestamptz) RETURNS void
    LANGUAGE sql SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
    UPDATE staff_sessions SET revoked_at = p_now WHERE user_id = p_user_id AND revoked_at IS NULL;
$$;
REVOKE ALL ON FUNCTION openseal_revoke_user_sessions(uuid, timestamptz) FROM PUBLIC;

-- The user of a live session of the current account changes their own name and/or
-- password (an Argon2id PHC string; NULL leaves either unchanged). A new password ends
-- their sessions in every account. Returns the user's id, or NULL when the session is
-- not live, not this account's, or its member is disabled.
CREATE FUNCTION openseal_update_own_user(
    p_session_id uuid, p_name text, p_password_hash text, p_now timestamptz)
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
       AND m.disabled_at IS NULL AND u.disabled_at IS NULL;
    IF uid IS NULL THEN
        RETURN NULL;
    END IF;
    IF p_name IS NOT NULL THEN
        UPDATE users SET name = p_name WHERE id = uid;
    END IF;
    IF p_password_hash IS NOT NULL THEN
        UPDATE users SET password_hash = p_password_hash WHERE id = uid;
        PERFORM openseal_revoke_user_sessions(uid, p_now);
    END IF;
    RETURN uid;
END
$$;
REVOKE ALL ON FUNCTION openseal_update_own_user(uuid, text, text, timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openseal_update_own_user(uuid, text, text, timestamptz) TO openseal_app;

-- Spend an open, sent, unexpired invitation of the current account and set its user's
-- password: the token reached the user's own address, so this is the user acting. Their
-- other open invitations here are revoked and their sessions end in every account.
-- Returns the user's id, or NULL when the invitation was not open (a second use).
CREATE FUNCTION openseal_accept_user_invitation(
    p_invitation_id uuid, p_password_hash text, p_now timestamptz)
RETURNS uuid
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
DECLARE
    acct uuid := openseal_current_account();
    uid uuid;
BEGIN
    UPDATE user_invitations AS i SET accepted_at = p_now
     WHERE i.account_id = acct AND i.id = p_invitation_id
       AND i.accepted_at IS NULL AND i.revoked_at IS NULL
       AND i.sent_at IS NOT NULL AND i.expires_at > p_now
       AND EXISTS (SELECT 1 FROM account_memberships m JOIN users u ON u.id = m.user_id
                    WHERE m.account_id = acct AND m.user_id = i.user_id
                      AND m.disabled_at IS NULL AND u.disabled_at IS NULL)
    RETURNING i.user_id INTO uid;
    IF uid IS NULL THEN
        RETURN NULL;
    END IF;
    UPDATE users SET password_hash = p_password_hash WHERE id = uid;
    UPDATE user_invitations SET revoked_at = p_now
     WHERE account_id = acct AND user_id = uid AND accepted_at IS NULL AND revoked_at IS NULL;
    PERFORM openseal_revoke_user_sessions(uid, p_now);
    RETURN uid;
END
$$;
REVOKE ALL ON FUNCTION openseal_accept_user_invitation(uuid, text, timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openseal_accept_user_invitation(uuid, text, timestamptz) TO openseal_app;
