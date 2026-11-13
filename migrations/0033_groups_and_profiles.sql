-- 0033: admin groups and custom permission profiles (UXW-07; docs/22 §8, docs/23 §12).
--
-- 1. `group_members` cascades: a member's place in a group goes with the group, and
--    with their membership of the account. Before this, a member who belonged to a
--    group could not be removed from the account (the foreign key refused the delete),
--    and a group with members could not be deleted.
-- 2. A permission profile names only known permissions: the scopes of docs/40 §2 and
--    `view_all_envelopes` (server `auth.rs` `SCOPES`, `profile_scopes`). Anything else is
--    refused by the database as well as by the API, so no stored profile can carry a
--    name a later server would read as a grant it never meant. Built-in profiles store
--    none (their grants come from their kind).
-- 3. Groups decide who may use a shared template (0031), so a change to a group or to
--    its members is an administrator's change: the same deferred commit check as
--    `permission_profiles` (0020) refuses one by the application role whose transaction
--    appended no admin event to the workspace's log (CS-DB-0008).
--
-- Row-level security on both tables is 0002's (`openseal_tenant_table`): unchanged.

ALTER TABLE group_members DROP CONSTRAINT group_members_account_id_group_id_fkey;
ALTER TABLE group_members DROP CONSTRAINT group_members_account_id_user_id_fkey;
ALTER TABLE group_members
    ADD CONSTRAINT group_members_account_id_group_id_fkey
        FOREIGN KEY (account_id, group_id) REFERENCES groups (account_id, id) ON DELETE CASCADE,
    ADD CONSTRAINT group_members_account_id_user_id_fkey
        FOREIGN KEY (account_id, user_id)
        REFERENCES account_memberships (account_id, user_id) ON DELETE CASCADE;

ALTER TABLE permission_profiles
    ADD CONSTRAINT permission_profiles_known_permissions CHECK (permissions <@ ARRAY[
        'envelopes:read', 'envelopes:write', 'envelopes:send', 'templates:read',
        'templates:write', 'bulk:send', 'webhooks:manage', 'admin:users', 'admin:account',
        'audit:read', 'view_all_envelopes']::text[]);

-- As 0026, with `groups` and `group_members` read by `account_id`, as
-- `permission_profiles`.
CREATE OR REPLACE FUNCTION openseal_admin_change_has_event() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = public, pg_catalog
AS $$
DECLARE
    r record;
    acct uuid;
    org uuid;
    app boolean := pg_has_role(current_user, 'openseal_app', 'MEMBER');
    console boolean := pg_has_role(current_user, 'openseal_console', 'MEMBER');
BEGIN
    IF NOT (app OR console)
       OR (SELECT rolsuper FROM pg_roles WHERE rolname = current_user) THEN
        RETURN NULL;
    END IF;
    IF TG_OP = 'DELETE' THEN r := OLD; ELSE r := NEW; END IF;
    CASE TG_TABLE_NAME
        WHEN 'accounts' THEN acct := r.id;
        WHEN 'account_memberships', 'permission_profiles', 'groups', 'group_members' THEN
            acct := r.account_id;
        WHEN 'organizations' THEN org := r.id;
        ELSE org := r.organization_id;
    END CASE;
    -- Separate statements: each role may execute only its own check, and an expression
    -- naming both would be refused (42501) whichever branch it needed.
    IF app THEN
        IF NOT openseal_xact_has_admin_event(acct, org) THEN
            RAISE EXCEPTION '% on % committed without its admin event', TG_OP, TG_TABLE_NAME
                USING ERRCODE = '23514', CONSTRAINT = 'admin_change_has_event';
        END IF;
    ELSIF NOT platform.xact_copied_to_org_log(acct, org) THEN
        RAISE EXCEPTION '% on % committed without its operator.* copy', TG_OP, TG_TABLE_NAME
            USING ERRCODE = '23514', CONSTRAINT = 'admin_change_has_event';
    END IF;
    RETURN NULL;
END
$$;

CREATE CONSTRAINT TRIGGER groups_admin_change_has_event
    AFTER INSERT OR UPDATE OR DELETE ON groups
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION openseal_admin_change_has_event();
CREATE CONSTRAINT TRIGGER group_members_admin_change_has_event
    AFTER INSERT OR UPDATE OR DELETE ON group_members
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION openseal_admin_change_has_event();
