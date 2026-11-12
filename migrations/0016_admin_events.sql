-- 0016: admin audit logs (ORG-05, ADR-028, docs/23 §2.5, §12).
--
-- Two logs, separate from envelope evidence and built the same way:
--
-- * `admin_events`, a tenant table, chained per workspace; head in
--   `accounts.admin_chain_head` (added by 0014);
-- * `org_admin_events`, an organization table, chained per organization; head in
--   `organizations.admin_chain_head`.
--
-- Each is append-only three ways, as `audit_events` (0005): the application role has
-- SELECT and INSERT only; row triggers refuse UPDATE and DELETE, and a statement trigger
-- TRUNCATE, for every role, the owner included (OS001, CS-DB-0004); an insert trigger
-- refuses an event that does not extend its chain (OS005, CS-DB-0014): its hash must be
-- SHA-256 of its canonical bytes (RFC 8785, made in Rust by `casual-sign-audit`), its
-- `seq`, `prev`, owner and action must be the ones the canonical bytes state, `seq` the
-- next and `prev` the head, read under a row lock on the head column.
--
-- A change is not committed without its event. A deferred constraint trigger on every
-- table an administrator changes (`accounts`, `account_memberships`,
-- `permission_profiles`, `organizations`, `organization_admins`, `org_permission_sets`)
-- refuses, at commit, a change by the application role when the same transaction appended
-- no event to the log of that workspace or of its organization (23514, constraint
-- `admin_change_has_event`, CS-DB-0008). The owner role (migrations) is outside, as it is
-- outside the audit chain (docs/07 SEC-S07).
--
-- Cross-scope appends go through definer functions that lock the head and append:
-- `openseal_append_org_event` (from a workspace, for an event its organization must see).
-- `openseal_create_workspace` and `openseal_archive_workspace` are replaced by versions
-- that append their organization event in the same transaction.

-- 1. The tables ---------------------------------------------------------------------------

CREATE TABLE admin_events (
    account_id   uuid NOT NULL REFERENCES accounts (id),
    seq          bigint NOT NULL CHECK (seq >= 0 AND seq <= 9007199254740991),
    prev_hash    bytea CHECK (prev_hash IS NULL OR octet_length(prev_hash) = 32),
    hash         bytea NOT NULL CHECK (octet_length(hash) = 32),
    action       text NOT NULL CHECK (char_length(action) BETWEEN 1 AND 64),
    at           timestamptz NOT NULL,
    -- RFC 8785 canonical JSON of the event: exactly the bytes hashed.
    canonical    bytea NOT NULL CHECK (octet_length(canonical) BETWEEN 2 AND 65536),
    -- The top-level transaction that appended it, set by the insert trigger (never by
    -- the caller): what the commit check below looks for.
    xact         xid8 NOT NULL DEFAULT pg_current_xact_id(),
    recorded_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, seq),
    CHECK ((seq = 0) = (prev_hash IS NULL))
);
CREATE INDEX admin_events_xact ON admin_events (account_id, xact);
SELECT openseal_tenant_table('admin_events', false);

CREATE TABLE org_admin_events (
    organization_id  uuid NOT NULL REFERENCES organizations (id),
    seq              bigint NOT NULL CHECK (seq >= 0 AND seq <= 9007199254740991),
    prev_hash        bytea CHECK (prev_hash IS NULL OR octet_length(prev_hash) = 32),
    hash             bytea NOT NULL CHECK (octet_length(hash) = 32),
    action           text NOT NULL CHECK (char_length(action) BETWEEN 1 AND 64),
    at               timestamptz NOT NULL,
    canonical        bytea NOT NULL CHECK (octet_length(canonical) BETWEEN 2 AND 65536),
    xact             xid8 NOT NULL DEFAULT pg_current_xact_id(),
    recorded_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (organization_id, seq),
    CHECK ((seq = 0) = (prev_hash IS NULL))
);
CREATE INDEX org_admin_events_xact ON org_admin_events (organization_id, xact);
SELECT openseal_org_table('org_admin_events', false);

-- 2. Append-only ---------------------------------------------------------------------------

-- `openseal_audit_refuse_change` (0005) raises OS001, CS-DB-0004, naming the table.
CREATE TRIGGER admin_events_no_update_delete
    BEFORE UPDATE OR DELETE ON admin_events
    FOR EACH ROW EXECUTE FUNCTION openseal_audit_refuse_change();
CREATE TRIGGER admin_events_no_truncate
    BEFORE TRUNCATE ON admin_events
    FOR EACH STATEMENT EXECUTE FUNCTION openseal_audit_refuse_change();
CREATE TRIGGER org_admin_events_no_update_delete
    BEFORE UPDATE OR DELETE ON org_admin_events
    FOR EACH ROW EXECUTE FUNCTION openseal_audit_refuse_change();
CREATE TRIGGER org_admin_events_no_truncate
    BEFORE TRUNCATE ON org_admin_events
    FOR EACH STATEMENT EXECUTE FUNCTION openseal_audit_refuse_change();

-- 3. The chain -----------------------------------------------------------------------------

-- Checks shared by both logs: the hash, and that the columns are what the canonical bytes
-- say (owner, seq, prev, action). Raises OS005 (CS-DB-0014).
CREATE FUNCTION openseal_admin_event_check(
    p_owner uuid, p_owner_key text, p_seq bigint, p_prev bytea, p_hash bytea,
    p_action text, p_canonical bytea) RETURNS void
    LANGUAGE plpgsql
    SET search_path = pg_catalog
AS $$
DECLARE
    doc jsonb;
BEGIN
    IF sha256(p_canonical) <> p_hash THEN
        RAISE EXCEPTION 'admin event hash does not match its canonical bytes (seq %)', p_seq
            USING ERRCODE = 'OS005';
    END IF;
    BEGIN
        doc := convert_from(p_canonical, 'UTF8')::jsonb;
    EXCEPTION WHEN OTHERS THEN
        RAISE EXCEPTION 'admin event is not JSON (seq %)', p_seq USING ERRCODE = 'OS005';
    END;
    IF jsonb_typeof(doc) <> 'object'
       OR doc ->> p_owner_key IS DISTINCT FROM p_owner::text
       OR doc ->> 'seq' IS DISTINCT FROM p_seq::text
       OR doc ->> 'action' IS DISTINCT FROM p_action
       OR (doc ->> 'prev') IS DISTINCT FROM encode(p_prev, 'hex') THEN
        RAISE EXCEPTION 'admin event columns differ from its canonical bytes (seq %)', p_seq
            USING ERRCODE = 'OS005';
    END IF;
END
$$;
REVOKE ALL ON FUNCTION openseal_admin_event_check(uuid, text, bigint, bytea, bytea, text, bytea) FROM PUBLIC;

-- Definer: the head columns are not the application's to write. Row security still holds
-- for the insert itself (its WITH CHECK runs after this trigger, and a failure there
-- rolls back the head update with the statement).
CREATE FUNCTION openseal_admin_events_extend_chain() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
DECLARE
    head bytea;
    head_seq bigint;
BEGIN
    -- Only the current workspace's log, checked before anything about the chain is read,
    -- so another workspace's head and next `seq` are never revealed (row security's own
    -- WITH CHECK runs only after this trigger).
    IF NEW.account_id IS DISTINCT FROM openseal_current_account() THEN
        RAISE EXCEPTION 'admin event for another workspace' USING ERRCODE = '42501';
    END IF;
    PERFORM openseal_admin_event_check(NEW.account_id, 'account', NEW.seq, NEW.prev_hash,
                                       NEW.hash, NEW.action, NEW.canonical);
    SELECT admin_chain_head INTO head FROM accounts WHERE id = NEW.account_id FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'admin event for no workspace' USING ERRCODE = 'OS005';
    END IF;
    SELECT seq INTO head_seq FROM admin_events WHERE account_id = NEW.account_id
        ORDER BY seq DESC LIMIT 1;
    IF NEW.seq <> COALESCE(head_seq + 1, 0) OR NEW.prev_hash IS DISTINCT FROM head THEN
        RAISE EXCEPTION 'admin event % does not extend its chain (next %)',
            NEW.seq, COALESCE(head_seq + 1, 0) USING ERRCODE = 'OS005';
    END IF;
    UPDATE accounts SET admin_chain_head = NEW.hash WHERE id = NEW.account_id;
    NEW.xact := pg_current_xact_id();
    RETURN NEW;
END
$$;
REVOKE ALL ON FUNCTION openseal_admin_events_extend_chain() FROM PUBLIC;
CREATE TRIGGER admin_events_extend_chain
    BEFORE INSERT ON admin_events
    FOR EACH ROW EXECUTE FUNCTION openseal_admin_events_extend_chain();

CREATE FUNCTION openseal_org_admin_events_extend_chain() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
DECLARE
    head bytea;
    head_seq bigint;
BEGIN
    -- Only the current organization's log, or from a workspace its own organization's.
    IF NEW.organization_id IS DISTINCT FROM COALESCE(openseal_current_org(),
            (SELECT a.organization_id FROM accounts a WHERE a.id = openseal_current_account())) THEN
        RAISE EXCEPTION 'admin event for another organization' USING ERRCODE = '42501';
    END IF;
    PERFORM openseal_admin_event_check(NEW.organization_id, 'organization', NEW.seq,
                                       NEW.prev_hash, NEW.hash, NEW.action, NEW.canonical);
    SELECT admin_chain_head INTO head FROM organizations WHERE id = NEW.organization_id FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'admin event for no organization' USING ERRCODE = 'OS005';
    END IF;
    SELECT seq INTO head_seq FROM org_admin_events WHERE organization_id = NEW.organization_id
        ORDER BY seq DESC LIMIT 1;
    IF NEW.seq <> COALESCE(head_seq + 1, 0) OR NEW.prev_hash IS DISTINCT FROM head THEN
        RAISE EXCEPTION 'organization admin event % does not extend its chain (next %)',
            NEW.seq, COALESCE(head_seq + 1, 0) USING ERRCODE = 'OS005';
    END IF;
    UPDATE organizations SET admin_chain_head = NEW.hash WHERE id = NEW.organization_id;
    NEW.xact := pg_current_xact_id();
    RETURN NEW;
END
$$;
REVOKE ALL ON FUNCTION openseal_org_admin_events_extend_chain() FROM PUBLIC;
CREATE TRIGGER org_admin_events_extend_chain
    BEFORE INSERT ON org_admin_events
    FOR EACH ROW EXECUTE FUNCTION openseal_org_admin_events_extend_chain();

-- 4. Reading the head before building an event ------------------------------------------

-- The next `seq` and the head of the current scope's log (the workspace's in account
-- scope, the organization's in organization scope), with the head row locked until the
-- transaction ends, so the event built from them is the next one. No tenant parameter.
-- The lock is taken by one statement and the chain read by the next: a statement that
-- waited for the lock would otherwise read `seq` from the snapshot it started with, the
-- one before the other transaction's event, and its event would be refused (OS005).
CREATE FUNCTION openseal_admin_chain_tip() RETURNS TABLE (next_seq bigint, head bytea)
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
DECLARE
    acct uuid := openseal_current_account();
    org uuid := openseal_current_org();
BEGIN
    IF acct IS NOT NULL THEN
        PERFORM 1 FROM accounts a WHERE a.id = acct FOR UPDATE;
        RETURN QUERY
        SELECT COALESCE((SELECT e.seq + 1 FROM admin_events e WHERE e.account_id = acct
                          ORDER BY e.seq DESC LIMIT 1), 0),
               (SELECT a.admin_chain_head FROM accounts a WHERE a.id = acct);
    ELSIF org IS NOT NULL THEN
        PERFORM 1 FROM organizations o WHERE o.id = org FOR UPDATE;
        RETURN QUERY
        SELECT COALESCE((SELECT e.seq + 1 FROM org_admin_events e WHERE e.organization_id = org
                          ORDER BY e.seq DESC LIMIT 1), 0),
               (SELECT o.admin_chain_head FROM organizations o WHERE o.id = org);
    END IF;
END
$$;
REVOKE ALL ON FUNCTION openseal_admin_chain_tip() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openseal_admin_chain_tip() TO openseal_app;

-- From workspace scope: the organization of the current workspace, the next `seq` and
-- head of its log, locked.
CREATE FUNCTION openseal_org_chain_tip()
RETURNS TABLE (organization_id uuid, next_seq bigint, head bytea)
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
DECLARE
    org uuid := (SELECT a.organization_id FROM accounts a WHERE a.id = openseal_current_account());
BEGIN
    IF org IS NOT NULL THEN
        -- Lock, then read in a fresh statement (as `openseal_admin_chain_tip`).
        PERFORM 1 FROM organizations o WHERE o.id = org FOR UPDATE;
        RETURN QUERY
        SELECT org,
               COALESCE((SELECT e.seq + 1 FROM org_admin_events e WHERE e.organization_id = org
                          ORDER BY e.seq DESC LIMIT 1), 0),
               (SELECT o.admin_chain_head FROM organizations o WHERE o.id = org);
    END IF;
END
$$;
REVOKE ALL ON FUNCTION openseal_org_chain_tip() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openseal_org_chain_tip() TO openseal_app;

-- From workspace scope: append an event to the current workspace's organization log
-- (docs/23 §2.5). The organization is derived, never named by the caller; the chain
-- trigger checks the rest. `p_at` is the event's own time, which the bytes also state.
CREATE FUNCTION openseal_append_org_event(
    p_seq bigint, p_prev bytea, p_hash bytea, p_action text, p_at timestamptz,
    p_canonical bytea) RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
DECLARE
    org uuid := (SELECT a.organization_id FROM accounts a WHERE a.id = openseal_current_account());
BEGIN
    IF org IS NULL THEN
        RAISE EXCEPTION 'no workspace scope for an organization event' USING ERRCODE = 'OS005';
    END IF;
    INSERT INTO org_admin_events (organization_id, seq, prev_hash, hash, action, at, canonical, xact)
    VALUES (org, p_seq, p_prev, p_hash, p_action, p_at, p_canonical, pg_current_xact_id());
END
$$;
REVOKE ALL ON FUNCTION openseal_append_org_event(bigint, bytea, bytea, text, timestamptz, bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openseal_append_org_event(bigint, bytea, bytea, text, timestamptz, bytea) TO openseal_app;

-- 5. No change without its event -----------------------------------------------------------

-- Whether this transaction appended an event to workspace `p_account`'s log or to its
-- organization's (`p_org` when the change is the organization's own).
CREATE FUNCTION openseal_xact_has_admin_event(p_account uuid, p_org uuid) RETURNS boolean
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
    SELECT EXISTS (SELECT 1 FROM admin_events e
                    WHERE p_account IS NOT NULL AND e.account_id = p_account
                      AND e.xact = pg_current_xact_id())
        OR EXISTS (SELECT 1 FROM org_admin_events e
                    WHERE e.organization_id = COALESCE(p_org,
                              (SELECT a.organization_id FROM accounts a WHERE a.id = p_account))
                      AND e.xact = pg_current_xact_id())
$$;
REVOKE ALL ON FUNCTION openseal_xact_has_admin_event(uuid, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openseal_xact_has_admin_event(uuid, uuid) TO openseal_app;

-- Deferred to commit, as the role committing (never a definer): the application role's
-- changes need their event; the owner's (migrations, superuser recovery) are outside.
CREATE FUNCTION openseal_admin_change_has_event() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = public, pg_catalog
AS $$
DECLARE
    r record;
    acct uuid;
    org uuid;
BEGIN
    IF NOT pg_has_role(current_user, 'openseal_app', 'MEMBER')
       OR (SELECT rolsuper FROM pg_roles WHERE rolname = current_user) THEN
        RETURN NULL;
    END IF;
    IF TG_OP = 'DELETE' THEN r := OLD; ELSE r := NEW; END IF;
    CASE TG_TABLE_NAME
        WHEN 'accounts' THEN acct := r.id;
        WHEN 'account_memberships', 'permission_profiles' THEN acct := r.account_id;
        WHEN 'organizations' THEN org := r.id;
        ELSE org := r.organization_id;
    END CASE;
    IF NOT openseal_xact_has_admin_event(acct, org) THEN
        RAISE EXCEPTION '% on % committed without its admin event', TG_OP, TG_TABLE_NAME
            USING ERRCODE = '23514', CONSTRAINT = 'admin_change_has_event';
    END IF;
    RETURN NULL;
END
$$;
REVOKE ALL ON FUNCTION openseal_admin_change_has_event() FROM PUBLIC;

-- `accounts` only on the columns an administrator changes: the chain head moves with
-- every event and is not a change of its own.
CREATE CONSTRAINT TRIGGER accounts_admin_change_has_event
    AFTER INSERT OR UPDATE OF name, settings, data_region, status ON accounts
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION openseal_admin_change_has_event();
CREATE CONSTRAINT TRIGGER account_memberships_admin_change_has_event
    AFTER INSERT OR UPDATE OR DELETE ON account_memberships
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION openseal_admin_change_has_event();
CREATE CONSTRAINT TRIGGER permission_profiles_admin_change_has_event
    AFTER INSERT OR UPDATE OR DELETE ON permission_profiles
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION openseal_admin_change_has_event();
CREATE CONSTRAINT TRIGGER organizations_admin_change_has_event
    AFTER INSERT OR UPDATE OF name, policy, status, data_regions ON organizations
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION openseal_admin_change_has_event();
CREATE CONSTRAINT TRIGGER organization_admins_admin_change_has_event
    AFTER INSERT OR UPDATE OR DELETE ON organization_admins
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION openseal_admin_change_has_event();
CREATE CONSTRAINT TRIGGER org_permission_sets_admin_change_has_event
    AFTER INSERT OR UPDATE OR DELETE ON org_permission_sets
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION openseal_admin_change_has_event();

-- 6. Workspace creation and archiving write their event ----------------------------------

-- The event's bytes must name this action and this workspace as its target, so the
-- function cannot be called with an unrelated event.
CREATE FUNCTION openseal_admin_event_targets(p_canonical bytea, p_action text, p_target uuid)
RETURNS boolean
    LANGUAGE sql IMMUTABLE
    SET search_path = pg_catalog
AS $$
    SELECT (convert_from(p_canonical, 'UTF8')::jsonb ->> 'action') = p_action
       AND (convert_from(p_canonical, 'UTF8')::jsonb -> 'target' ->> 'workspace') = p_target::text
$$;
REVOKE ALL ON FUNCTION openseal_admin_event_targets(bytea, text, uuid) FROM PUBLIC;

DROP FUNCTION openseal_create_workspace(uuid, text, uuid, uuid, uuid);
DROP FUNCTION openseal_archive_workspace(uuid);

-- Organization scope only: a new workspace of the current organization, and its
-- `workspace.created` event in the organization log, in this transaction. True when
-- created; false outside organization scope or for an organization that is not active.
CREATE FUNCTION openseal_create_workspace(
    p_id uuid, p_name text,
    p_admin_profile uuid, p_sender_profile uuid, p_viewer_profile uuid,
    p_seq bigint, p_prev bytea, p_hash bytea, p_at timestamptz, p_canonical bytea) RETURNS boolean
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
    IF NOT openseal_admin_event_targets(p_canonical, 'workspace.created', p_id) THEN
        RAISE EXCEPTION 'workspace event names another action or workspace' USING ERRCODE = 'OS005';
    END IF;
    PERFORM openseal_insert_workspace(org, p_id, p_name,
                                      p_admin_profile, p_sender_profile, p_viewer_profile);
    INSERT INTO org_admin_events (organization_id, seq, prev_hash, hash, action, at, canonical, xact)
    VALUES (org, p_seq, p_prev, p_hash, 'workspace.created', p_at, p_canonical, pg_current_xact_id());
    RETURN true;
END
$$;
REVOKE ALL ON FUNCTION openseal_create_workspace(uuid, text, uuid, uuid, uuid, bigint, bytea, bytea, timestamptz, bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openseal_create_workspace(uuid, text, uuid, uuid, uuid, bigint, bytea, bytea, timestamptz, bytea) TO openseal_app;

-- Organization scope only: archive a workspace of the current organization, with its
-- `workspace.archived` event. True when it is (now or already) archived; false for any
-- other id. An already archived workspace writes no second event.
CREATE FUNCTION openseal_archive_workspace(
    p_id uuid, p_seq bigint, p_prev bytea, p_hash bytea, p_at timestamptz, p_canonical bytea)
RETURNS boolean
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
DECLARE
    org uuid := openseal_current_org();
    was text;
BEGIN
    IF org IS NULL THEN
        RETURN false;
    END IF;
    SELECT status INTO was FROM accounts WHERE id = p_id AND organization_id = org FOR UPDATE;
    IF NOT FOUND THEN
        RETURN false;
    END IF;
    IF was = 'archived' THEN
        RETURN true;
    END IF;
    IF NOT openseal_admin_event_targets(p_canonical, 'workspace.archived', p_id) THEN
        RAISE EXCEPTION 'workspace event names another action or workspace' USING ERRCODE = 'OS005';
    END IF;
    UPDATE accounts SET status = 'archived' WHERE id = p_id AND organization_id = org;
    INSERT INTO org_admin_events (organization_id, seq, prev_hash, hash, action, at, canonical, xact)
    VALUES (org, p_seq, p_prev, p_hash, 'workspace.archived', p_at, p_canonical, pg_current_xact_id());
    RETURN true;
END
$$;
REVOKE ALL ON FUNCTION openseal_archive_workspace(uuid, bigint, bytea, bytea, timestamptz, bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openseal_archive_workspace(uuid, bigint, bytea, bytea, timestamptz, bytea) TO openseal_app;
