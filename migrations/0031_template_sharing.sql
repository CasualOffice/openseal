-- 0031: template sharing, Shared with me and Favourites (UXW-06; docs/22 §7).
--
-- 1. Access to a template is deny-by-default and decided by the server on every request
--    (docs/07 §Access): its owner and the account's administrators hold every right; a
--    member reached by a share (to them, to a group they belong to, or to the whole
--    account) may read and use it, and also edit it when that share has `can_edit`.
--    Anyone else is answered 404, as for another account's template. Moving it to the
--    Deleted view, restoring it, purging it and changing its shares are the owner's (or
--    an administrator's) alone.
-- 2. `openseal_template_share_right` answers what the shares give a member: `edit`,
--    `use` or NULL. It runs with the caller's rights, so row-level security still
--    confines it to the current account.
-- 3. `template_shares` (0003, never written before) gets one share per target and
--    template (the partial unique indexes), a creation time, and cascades: a share goes
--    with its template, with the membership it names (a removed member keeps no share)
--    and with the group it names.
-- 4. Templates made before this migration were readable and editable by every member;
--    each gets a whole-account share with `can_edit`, so nobody loses access on upgrade.
--    A template made from now on is its owner's alone until shared.
-- 5. `template_favourites`: each member's own starred templates (Favourites). Starring
--    is the member's view, not a change of the template: no version bump.

CREATE FUNCTION openseal_template_share_right(acct uuid, tpl uuid, member uuid) RETURNS text
    LANGUAGE sql STABLE
    SET search_path = public, pg_catalog
AS $$
    SELECT CASE WHEN bool_or(s.can_edit) THEN 'edit' WHEN count(*) > 0 THEN 'use' END
    FROM template_shares s
    WHERE s.account_id = acct AND s.template_id = tpl
      AND (s.whole_account OR s.user_id = member
           OR s.group_id IN (SELECT g.group_id FROM group_members g
                             WHERE g.account_id = acct AND g.user_id = member))
$$;

ALTER TABLE template_shares ADD COLUMN created_at timestamptz NOT NULL DEFAULT now();
ALTER TABLE template_shares DROP CONSTRAINT template_shares_account_id_template_id_fkey;
ALTER TABLE template_shares DROP CONSTRAINT template_shares_account_id_user_id_fkey;
ALTER TABLE template_shares DROP CONSTRAINT template_shares_account_id_group_id_fkey;
ALTER TABLE template_shares
    ADD CONSTRAINT template_shares_account_id_template_id_fkey
        FOREIGN KEY (account_id, template_id) REFERENCES templates (account_id, id) ON DELETE CASCADE,
    ADD CONSTRAINT template_shares_account_id_user_id_fkey
        FOREIGN KEY (account_id, user_id)
        REFERENCES account_memberships (account_id, user_id) ON DELETE CASCADE,
    ADD CONSTRAINT template_shares_account_id_group_id_fkey
        FOREIGN KEY (account_id, group_id) REFERENCES groups (account_id, id) ON DELETE CASCADE;
CREATE UNIQUE INDEX template_shares_one_user
    ON template_shares (account_id, template_id, user_id) WHERE user_id IS NOT NULL;
CREATE UNIQUE INDEX template_shares_one_group
    ON template_shares (account_id, template_id, group_id) WHERE group_id IS NOT NULL;
CREATE UNIQUE INDEX template_shares_one_account
    ON template_shares (account_id, template_id) WHERE whole_account;
CREATE INDEX template_shares_template ON template_shares (account_id, template_id);
CREATE INDEX group_members_user ON group_members (account_id, user_id);

INSERT INTO template_shares (id, account_id, template_id, whole_account, can_edit)
    SELECT gen_random_uuid(), t.account_id, t.id, true, true FROM templates t;

CREATE TABLE template_favourites (
    account_id   uuid NOT NULL REFERENCES accounts (id),
    user_id      uuid NOT NULL,
    template_id  uuid NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, user_id, template_id),
    FOREIGN KEY (account_id, user_id)
        REFERENCES account_memberships (account_id, user_id) ON DELETE CASCADE,
    FOREIGN KEY (account_id, template_id) REFERENCES templates (account_id, id) ON DELETE CASCADE
);
CREATE INDEX template_favourites_template ON template_favourites (account_id, template_id);
SELECT openseal_tenant_table('template_favourites', true);
