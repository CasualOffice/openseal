-- 0010: inviting users, and disabling a member in one account (WEB-06).
--
-- 1. A member disabled in this account only (`account_memberships.disabled_at`): a user
--    may belong to several accounts, and one account's administrator must not lock
--    them out of the others. `users.disabled_at` stays the platform-wide switch.
-- 2. User invitations: an administrator adds a member by email; the worker mails a
--    one-time link to set a password. The link's token is 256 random bits minted by the
--    worker as it sends, stored as SHA-256 only, with an expiry; accepting it sets the
--    password and spends the invitation; sending again replaces the token.
-- 3. The entry point that finds an invitation from its token's hash before any account
--    is known, and the staff-session resolver refusing a member disabled here.

ALTER TABLE account_memberships ADD COLUMN disabled_at timestamptz;

CREATE TABLE user_invitations (
    id             uuid PRIMARY KEY,
    account_id     uuid NOT NULL REFERENCES accounts (id),
    user_id        uuid NOT NULL,
    -- Who invited (personal data by reference only).
    invited_by     uuid NOT NULL,
    -- Set by the worker when it sends; NULL until then.
    token_sha256   bytea UNIQUE CHECK (token_sha256 IS NULL OR octet_length(token_sha256) = 32),
    expires_at     timestamptz,
    sent_at        timestamptz,
    accepted_at    timestamptz,
    revoked_at     timestamptz,
    created_at     timestamptz NOT NULL,
    UNIQUE (account_id, id),
    CHECK ((token_sha256 IS NULL) = (expires_at IS NULL)),
    -- Removing the member removes their invitations (an invitation is not evidence).
    FOREIGN KEY (account_id, user_id) REFERENCES account_memberships (account_id, user_id)
        ON DELETE CASCADE
);
CREATE INDEX user_invitations_account_user ON user_invitations (account_id, user_id);
SELECT openseal_tenant_table('user_invitations', true);

-- The open invitation a token's hash names: sent, not accepted, not revoked, not
-- expired, its member still in the account and enabled. Ids only.
CREATE FUNCTION openseal_resolve_user_invitation(p_token_sha256 bytea, p_now timestamptz)
RETURNS TABLE (account_id uuid, invitation_id uuid, user_id uuid)
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
    SELECT i.account_id, i.id, i.user_id FROM user_invitations AS i
      JOIN account_memberships AS m ON m.account_id = i.account_id AND m.user_id = i.user_id
      JOIN users AS u ON u.id = i.user_id
     WHERE i.token_sha256 = p_token_sha256 AND i.accepted_at IS NULL
       AND i.revoked_at IS NULL AND i.expires_at > p_now
       AND m.disabled_at IS NULL AND u.disabled_at IS NULL
$$;
REVOKE ALL ON FUNCTION openseal_resolve_user_invitation(bytea, timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openseal_resolve_user_invitation(bytea, timestamptz) TO openseal_app;

-- As 0009's, and also refusing a member disabled in the session's account.
CREATE OR REPLACE FUNCTION openseal_resolve_staff_session(p_token_sha256 bytea, p_now timestamptz)
RETURNS TABLE (account_id uuid, session_id uuid, user_id uuid, csrf_sha256 bytea)
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
    SELECT s.account_id, s.id, s.user_id, s.csrf_sha256 FROM staff_sessions AS s
      JOIN account_memberships AS m ON m.account_id = s.account_id AND m.user_id = s.user_id
      JOIN users AS u ON u.id = s.user_id
     WHERE s.token_sha256 = p_token_sha256 AND s.revoked_at IS NULL AND s.expires_at > p_now
       AND u.disabled_at IS NULL AND m.disabled_at IS NULL
$$;
