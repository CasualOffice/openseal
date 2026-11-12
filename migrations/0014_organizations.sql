-- 0014: organizations above accounts (ORG-02, ADR-028, docs/23 §2.1, §2.2).
--
-- An account is now a workspace of exactly one organization. Content tables are not
-- touched: every `openseal_tenant_table` keeps its one policy on
-- `openseal_current_account()`, so a transaction in organization scope (where that is
-- NULL) reads no envelope, document, field value or event. What changes:
--
-- 1. `openseal_current_org()`, NULL whenever an account is set, so an account scope never
--    also reads as an organization scope.
-- 2. `organizations`; each existing account gets an organization with the account's own
--    UUID and name (deterministic, no randomness in SQL), and `accounts.organization_id`
--    becomes NOT NULL. `accounts.status` (active or archived) and the admin-log chain
--    head (written from ORG-05).
-- 3. A workspace never changes organization: a trigger refuses it (SQLSTATE OS004,
--    CS-DB-0013) for every role but `openseal_org_mover`, a NOLOGIN role with no members
--    that owns nothing until ORG-20's two-person link. The application role loses INSERT
--    on `accounts` and keeps UPDATE only on `name`, `settings` and `data_region`;
--    workspaces are created only by the definer functions below.
-- 4. Organization tables are declared through `openseal_org_table()`; their one policy is
--    `organization_id = openseal_current_org()`. `org_permission_sets` and
--    `organization_admins` are created here so the owner backfill has somewhere to write;
--    every enabled member holding the built-in `admin` profile becomes an owner. An
--    account with none gets an organization with no owner, which the console lists for
--    recovery (docs/23 §5.1). A deferred constraint trigger then refuses a commit that
--    removes or demotes an owner and leaves an active organization with no enabled one
--    (CS-ORG-0008; constraint `organization_keeps_an_owner`).
-- 5. Organization scope reads `accounts`, `account_memberships` and `users` of its own
--    workspaces through `FOR SELECT` policies only; it writes to a workspace only through
--    a single-account transaction (`Store::for_workspace_of`) or a definer function.
-- 6. `users.password_hash` is no longer readable by the application role; the login path
--    reads it through `openseal_login_password_hash`, for an enabled member of the
--    current account only.
--
-- Every predicate that existed before this migration is unchanged.

-- 1. The organization of the current transaction ----------------------------------------

CREATE FUNCTION openseal_current_org() RETURNS uuid
    LANGUAGE sql STABLE PARALLEL SAFE
    SET search_path = pg_catalog
AS $$
    -- Fail closed both ways: an account scope never also reads as an organization scope.
    SELECT CASE WHEN NULLIF(current_setting('openseal.account_id', true), '') IS NOT NULL THEN NULL
                ELSE NULLIF(current_setting('openseal.organization_id', true), '')::uuid END
$$;
GRANT EXECUTE ON FUNCTION openseal_current_org() TO openseal_app;

-- Make `tbl` an organization table: row-level security on, one policy keyed on the
-- current organization for every command, and the application role's grants (`writable`
-- false: SELECT and INSERT only). Every `public` table with `organization_id`, `accounts`
-- excepted, is declared through this function; a catalog test checks it.
CREATE FUNCTION openseal_org_table(tbl regclass, writable boolean) RETURNS void
    LANGUAGE plpgsql
    SET search_path = public, pg_catalog
AS $$
BEGIN
    EXECUTE format('ALTER TABLE %s ENABLE ROW LEVEL SECURITY', tbl);
    EXECUTE format(
        'CREATE POLICY organization_isolation ON %s USING (organization_id = openseal_current_org()) '
        'WITH CHECK (organization_id = openseal_current_org())', tbl);
    IF writable THEN
        EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON %s TO openseal_app', tbl);
    ELSE
        EXECUTE format('GRANT SELECT, INSERT ON %s TO openseal_app', tbl);
    END IF;
END
$$;
REVOKE ALL ON FUNCTION openseal_org_table(regclass, boolean) FROM PUBLIC;

-- 2. Organizations and the workspace columns ---------------------------------------------

CREATE TABLE organizations (
    id               uuid PRIMARY KEY,
    name             text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 255),
    -- `suspended` and `closed` are set by the platform console only (docs/23 §5.3).
    status           text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'closed')),
    -- Organization policy (docs/23 §3); keys are defined by ORG-08.
    policy           jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(policy) = 'object'),
    data_regions     text[] NOT NULL DEFAULT '{}',
    -- Head of the organization's admin log (ORG-05); NULL until its first event.
    admin_chain_head bytea CHECK (admin_chain_head IS NULL OR octet_length(admin_chain_head) = 32),
    created_at       timestamptz NOT NULL DEFAULT now()
);
-- The organization table keyed on `id`, so declared by hand with the same policy shape.
ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;
CREATE POLICY organization_isolation ON organizations
    USING (id = openseal_current_org())
    WITH CHECK (id = openseal_current_org());
GRANT SELECT ON organizations TO openseal_app;
GRANT UPDATE (name, policy) ON organizations TO openseal_app;

ALTER TABLE accounts ADD COLUMN organization_id uuid REFERENCES organizations (id);
ALTER TABLE accounts ADD COLUMN status text NOT NULL DEFAULT 'active'
    CHECK (status IN ('active', 'archived'));
-- Head of the workspace's admin log (ORG-05); NULL until its first event.
ALTER TABLE accounts ADD COLUMN admin_chain_head bytea
    CHECK (admin_chain_head IS NULL OR octet_length(admin_chain_head) = 32);
-- Backfill: one organization per account, with the account's UUID.
INSERT INTO organizations (id, name, created_at) SELECT id, name, created_at FROM accounts;
UPDATE accounts SET organization_id = id;
ALTER TABLE accounts ALTER COLUMN organization_id SET NOT NULL;
CREATE INDEX accounts_organization ON accounts (organization_id);

-- A workspace reads its own organization (name, status, policy).
CREATE POLICY workspace_reads_its_organization ON organizations FOR SELECT
    USING (id = (SELECT a.organization_id FROM accounts a WHERE a.id = openseal_current_account()));

-- 3. A workspace never changes organization ----------------------------------------------

-- Roles are cluster-wide: another database of this cluster may have created it.
DO $$
BEGIN
    CREATE ROLE openseal_org_mover NOLOGIN NOINHERIT;
EXCEPTION
    WHEN duplicate_object OR unique_violation THEN NULL;
END
$$;
-- The role must have no member. A superuser migrator (as Compose runs migrations) gets
-- none. A non-superuser CREATEROLE migrator is made an ADMIN member of every role it
-- creates (PostgreSQL 16+), a grant it cannot revoke: such an install has a superuser
-- create this role first (`CREATE ROLE openseal_org_mover NOLOGIN NOINHERIT`), and this
-- migration refuses to finish otherwise.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_auth_members WHERE roleid = 'openseal_org_mover'::regrole) THEN
        RAISE EXCEPTION 'openseal_org_mover must have no members; create it as a superuser first'
            USING ERRCODE = '42501';
    END IF;
END
$$;

-- RLS cannot see the old row, so a trigger does. Only `openseal_org_mover` passes: a
-- NOLOGIN role with no members owning, from ORG-20, exactly one SECURITY DEFINER function
-- (`platform.apply_link_workspaces`). A setting would not do: any role may set one.
CREATE FUNCTION openseal_refuse_org_change() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog
AS $$
BEGIN
    IF current_user = 'openseal_org_mover' THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'organization of a workspace is fixed' USING ERRCODE = 'OS004';  -- CS-DB-0013
END
$$;
CREATE TRIGGER accounts_organization_fixed BEFORE UPDATE OF organization_id ON accounts
    FOR EACH ROW WHEN (OLD.organization_id IS DISTINCT FROM NEW.organization_id)
    EXECUTE FUNCTION openseal_refuse_org_change();

-- Workspaces are created only through definer functions; the app updates three columns.
REVOKE INSERT, UPDATE ON accounts FROM openseal_app;
GRANT UPDATE (name, settings, data_region) ON accounts TO openseal_app;

-- 4. Organization administrators ---------------------------------------------------------

CREATE TABLE org_permission_sets (
    id               uuid PRIMARY KEY,
    organization_id  uuid NOT NULL REFERENCES organizations (id),
    name             text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 255),
    -- Organization actions (docs/23 §2.2), checked by `casual-sign-server::authz`.
    permissions      text[] NOT NULL DEFAULT '{}',
    UNIQUE (organization_id, id),
    UNIQUE (organization_id, name)
);
SELECT openseal_org_table('org_permission_sets', true);

CREATE TABLE organization_admins (
    organization_id    uuid NOT NULL REFERENCES organizations (id),
    user_id            uuid NOT NULL REFERENCES users (id),
    role               text NOT NULL CHECK (role IN ('owner', 'admin', 'delegated')),
    -- Required iff the role is `delegated`.
    permission_set_id  uuid,
    -- NULL: every workspace of the organization.
    workspace_scope    uuid[],
    created_at         timestamptz NOT NULL,
    PRIMARY KEY (organization_id, user_id),
    FOREIGN KEY (organization_id, permission_set_id)
        REFERENCES org_permission_sets (organization_id, id),
    CHECK ((role = 'delegated') = (permission_set_id IS NOT NULL))
);
CREATE INDEX organization_admins_user ON organization_admins (user_id);
SELECT openseal_org_table('organization_admins', true);

-- Backfill: every enabled member holding the built-in `admin` profile owns its
-- account's organization. Runs before the constraint trigger below exists.
INSERT INTO organization_admins (organization_id, user_id, role, created_at)
SELECT a.organization_id, m.user_id, 'owner', m.created_at
  FROM account_memberships m
  JOIN accounts a ON a.id = m.account_id
  JOIN permission_profiles p ON p.account_id = m.account_id AND p.id = m.permission_profile_id
 WHERE p.kind = 'admin' AND m.disabled_at IS NULL;

-- Refuse a commit that removed or demoted an owner and left an active organization with
-- no owner whose identity is enabled (CS-ORG-0008). An organization that never had one
-- (an account with no admin at the migration) is not blocked from gaining admins.
CREATE FUNCTION openseal_check_org_keeps_owner() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
BEGIN
    IF OLD.role = 'owner'
       AND EXISTS (SELECT 1 FROM organizations o
                    WHERE o.id = OLD.organization_id AND o.status = 'active')
       AND NOT EXISTS (SELECT 1 FROM organization_admins oa JOIN users u ON u.id = oa.user_id
                        WHERE oa.organization_id = OLD.organization_id AND oa.role = 'owner'
                          AND u.disabled_at IS NULL) THEN
        RAISE EXCEPTION 'organization must keep an enabled owner'
            USING ERRCODE = '23514', CONSTRAINT = 'organization_keeps_an_owner';
    END IF;
    RETURN NULL;
END
$$;
REVOKE ALL ON FUNCTION openseal_check_org_keeps_owner() FROM PUBLIC;
CREATE CONSTRAINT TRIGGER organization_keeps_an_owner
    AFTER UPDATE OR DELETE ON organization_admins
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION openseal_check_org_keeps_owner();

-- 5. Organization scope reads its workspaces, their members and users (SELECT only) -------

CREATE POLICY organization_scope ON accounts FOR SELECT
    USING (organization_id = openseal_current_org());
CREATE POLICY organization_scope ON account_memberships FOR SELECT
    USING (EXISTS (SELECT 1 FROM accounts a
                    WHERE a.id = account_memberships.account_id
                      AND a.organization_id = openseal_current_org()));
CREATE POLICY organization_scope ON users FOR SELECT
    USING (EXISTS (SELECT 1 FROM account_memberships m JOIN accounts a ON a.id = m.account_id
                    WHERE m.user_id = users.id AND a.organization_id = openseal_current_org()));

-- 6. Password hashes are read only through the login path --------------------------------

-- Column privileges cannot narrow a table-wide grant, so SELECT is regranted per column.
-- A column added to `users` later is unreadable by the application until granted.
REVOKE SELECT ON users FROM openseal_app;
GRANT SELECT (id, email, email_normalized, name, login_kind, idp_issuer, idp_subject,
              disabled_at, created_at) ON users TO openseal_app;

-- The Argon2id PHC string of `p_user` for a local login, while they are an enabled member
-- of `p_account`, which must be the current account. NULL otherwise.
CREATE FUNCTION openseal_login_password_hash(p_user uuid, p_account uuid) RETURNS text
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
    SELECT u.password_hash FROM users u
      JOIN account_memberships m ON m.user_id = u.id
     WHERE u.id = p_user AND m.account_id = p_account
       AND p_account = openseal_current_account()
       AND u.disabled_at IS NULL AND m.disabled_at IS NULL
$$;
REVOKE ALL ON FUNCTION openseal_login_password_hash(uuid, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openseal_login_password_hash(uuid, uuid) TO openseal_app;

-- 7. Creating and archiving workspaces ---------------------------------------------------

-- Insert workspace `p_id` of organization `p_org` with its three built-in permission
-- profiles (ids supplied by the host: no randomness in SQL), recorded in its settings as
-- `bootstrap` has always recorded them. Internal: never granted to the application role.
CREATE FUNCTION openseal_insert_workspace(
    p_org uuid, p_id uuid, p_name text,
    p_admin_profile uuid, p_sender_profile uuid, p_viewer_profile uuid) RETURNS void
    LANGUAGE sql SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
    INSERT INTO accounts (id, organization_id, name, settings)
    VALUES (p_id, p_org, p_name, jsonb_build_object('builtin_profiles', jsonb_build_object(
        'admin', p_admin_profile::text, 'sender', p_sender_profile::text,
        'viewer', p_viewer_profile::text)));
    INSERT INTO permission_profiles (id, account_id, name, kind)
    VALUES (p_admin_profile, p_id, 'Administrator', 'admin'),
           (p_sender_profile, p_id, 'Sender', 'sender'),
           (p_viewer_profile, p_id, 'Viewer', 'viewer');
$$;
REVOKE ALL ON FUNCTION openseal_insert_workspace(uuid, uuid, text, uuid, uuid, uuid) FROM PUBLIC;

-- Organization scope only: a new workspace of the current organization. ORG-05's
-- migration replaces this with a version that also appends the admin events; no route
-- calls it before then. True when created; false outside organization scope or for an
-- organization that is not active.
CREATE FUNCTION openseal_create_workspace(
    p_id uuid, p_name text,
    p_admin_profile uuid, p_sender_profile uuid, p_viewer_profile uuid) RETURNS boolean
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
DECLARE
    org uuid := openseal_current_org();
BEGIN
    IF org IS NULL OR NOT EXISTS (SELECT 1 FROM organizations o
                                   WHERE o.id = org AND o.status = 'active') THEN
        RETURN false;
    END IF;
    PERFORM openseal_insert_workspace(org, p_id, p_name,
                                      p_admin_profile, p_sender_profile, p_viewer_profile);
    RETURN true;
END
$$;
REVOKE ALL ON FUNCTION openseal_create_workspace(uuid, text, uuid, uuid, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openseal_create_workspace(uuid, text, uuid, uuid, uuid) TO openseal_app;

-- Organization scope only: archive a workspace of the current organization. True when it
-- is (now or already) archived; false for any other id.
CREATE FUNCTION openseal_archive_workspace(p_id uuid) RETURNS boolean
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
DECLARE
    org uuid := openseal_current_org();
BEGIN
    IF org IS NULL THEN
        RETURN false;
    END IF;
    UPDATE accounts SET status = 'archived' WHERE id = p_id AND organization_id = org;
    RETURN FOUND;
END
$$;
REVOKE ALL ON FUNCTION openseal_archive_workspace(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openseal_archive_workspace(uuid) TO openseal_app;

-- The first organization and workspace of an install (`casual-sign-server bootstrap`):
-- succeeds only while no organization exists, and only in the account scope of the new
-- workspace, so the rest of the bootstrap (its first administrator) commits with it.
-- Later organizations come from the platform console (docs/23 §5.3).
CREATE FUNCTION openseal_bootstrap_organization(
    p_org uuid, p_account uuid, p_name text,
    p_admin_profile uuid, p_sender_profile uuid, p_viewer_profile uuid) RETURNS boolean
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
BEGIN
    IF p_account IS DISTINCT FROM openseal_current_account() THEN
        RETURN false;
    END IF;
    -- Two concurrent bootstraps: the second waits, then sees the first's organization.
    LOCK TABLE organizations IN EXCLUSIVE MODE;
    IF EXISTS (SELECT 1 FROM organizations) THEN
        RETURN false;
    END IF;
    INSERT INTO organizations (id, name) VALUES (p_org, p_name);
    PERFORM openseal_insert_workspace(p_org, p_account, p_name,
                                      p_admin_profile, p_sender_profile, p_viewer_profile);
    RETURN true;
END
$$;
REVOKE ALL ON FUNCTION openseal_bootstrap_organization(uuid, uuid, text, uuid, uuid, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openseal_bootstrap_organization(uuid, uuid, text, uuid, uuid, uuid) TO openseal_app;

-- The bootstrap's first administrator becomes the organization's owner: only for an
-- organization inserted by this very transaction (its row's `xmin` is the current
-- transaction id, so a row from a savepoint fails closed), only while it has no
-- administrator at all and this is its only workspace, and only for an enabled member of
-- it holding the built-in admin profile. An organization that already existed without an
-- owner is never claimable here: its owner is named through the console (docs/23 §5.1).
CREATE FUNCTION openseal_bootstrap_owner(p_user uuid, p_now timestamptz) RETURNS boolean
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
DECLARE
    acct uuid := openseal_current_account();
    org uuid;
BEGIN
    SELECT a.organization_id INTO org FROM accounts a
      JOIN organizations o ON o.id = a.organization_id
     WHERE a.id = acct AND o.xmin = pg_current_xact_id()::xid;
    IF org IS NULL
       OR EXISTS (SELECT 1 FROM organization_admins oa WHERE oa.organization_id = org)
       OR EXISTS (SELECT 1 FROM accounts a WHERE a.organization_id = org AND a.id <> acct)
       OR NOT EXISTS (SELECT 1 FROM account_memberships m
                        JOIN permission_profiles p
                          ON p.account_id = m.account_id AND p.id = m.permission_profile_id
                        JOIN users u ON u.id = m.user_id
                       WHERE m.account_id = acct AND m.user_id = p_user AND p.kind = 'admin'
                         AND m.disabled_at IS NULL AND u.disabled_at IS NULL) THEN
        RETURN false;
    END IF;
    INSERT INTO organization_admins (organization_id, user_id, role, created_at)
    VALUES (org, p_user, 'owner', p_now);
    RETURN true;
END
$$;
REVOKE ALL ON FUNCTION openseal_bootstrap_owner(uuid, timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openseal_bootstrap_owner(uuid, timestamptz) TO openseal_app;

-- 8. The workspaces a signed-in person can switch to -------------------------------------

-- From a live session (never a user id the caller names): every enabled membership of its
-- enabled user, with the workspace's name and status and its organization's name.
CREATE FUNCTION openseal_user_workspaces(p_session_token_sha256 bytea, p_now timestamptz)
RETURNS TABLE (account_id uuid, account_name text, account_status text,
               organization_id uuid, organization_name text)
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
    WITH me AS (
        SELECT s.user_id FROM staff_sessions s
          JOIN account_memberships m ON m.account_id = s.account_id AND m.user_id = s.user_id
          JOIN users u ON u.id = s.user_id
         WHERE s.token_sha256 = p_session_token_sha256 AND s.revoked_at IS NULL
           AND s.expires_at > p_now AND u.disabled_at IS NULL AND m.disabled_at IS NULL)
    SELECT a.id, a.name, a.status, o.id, o.name
      FROM me
      JOIN account_memberships m ON m.user_id = me.user_id AND m.disabled_at IS NULL
      JOIN accounts a ON a.id = m.account_id
      JOIN organizations o ON o.id = a.organization_id
     ORDER BY o.name, o.id, a.name, a.id
$$;
REVOKE ALL ON FUNCTION openseal_user_workspaces(bytea, timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openseal_user_workspaces(bytea, timestamptz) TO openseal_app;
