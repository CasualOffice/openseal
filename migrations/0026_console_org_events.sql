-- 0026: every console write on an organization is copied into that organization's admin
-- log (CON-16, ADR-028, docs/23 §2.5, §5.1; docs/07 SEC-O13).
--
-- The console's definer writes (0018: rename, data-region labels, a workspace's label and
-- status; 0019: suspend and resume) change `organizations` and `accounts`. Until now they
-- committed with an event only in the operator log (`platform.operator_events`), because
-- `admin_change_has_event` (0020) checked the application role alone. Now:
--
-- * `platform.org_log_tip` gives the console the organization (of an organization, or of a
--   workspace), the next `seq` and the head of its log, the head row locked to the end of
--   the transaction, so the copy the console builds is the next event;
-- * `platform.copy_to_org_log` appends the copy, which the console builds in Rust (RFC 8785
--   bytes from `casual-sign-audit`, the organization log's own v1 format). It requires a
--   live operator session with the `operator` or `platform_owner` role, an `operator.*`
--   action, and an actor in the bytes that is exactly that session's operator, so no copy
--   names another operator; the 0020 chain trigger checks hash, `seq`, `prev`, owner,
--   action and time as for every event;
-- * `admin_change_has_event` now holds the console role too: a console commit that
--   changed an organization or a workspace without an `operator.*` event in that
--   organization's log, appended in the same transaction, fails (23514,
--   `admin_change_has_event`, CS-DB-0008). A copy that fails therefore rolls the change
--   back, and a write that skips its copy cannot commit.
--
-- The console's direct grants stay as they were: no `public` table or function; it reaches
-- the organization log only through these definer functions.

-- 1. The next event of an organization's log ---------------------------------------------

-- Exactly one of `p_org` and `p_workspace`. No row when there is no such organization or
-- workspace. The lock is taken by one statement and the chain read by the next, as in
-- `openseal_admin_chain_tip` (0020): a statement that waited for the lock would read `seq`
-- from the snapshot it started with.
CREATE FUNCTION platform.org_log_tip(p_session bytea, p_org uuid, p_workspace uuid, p_now timestamptz)
RETURNS TABLE (organization_id uuid, next_seq bigint, head bytea)
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
DECLARE
    org uuid;
BEGIN
    PERFORM platform.acting_operator(p_session, p_now, ARRAY['platform_owner', 'operator']);
    IF (p_org IS NULL) = (p_workspace IS NULL) THEN
        RAISE EXCEPTION 'name an organization or a workspace' USING ERRCODE = '22023';
    END IF;
    org := COALESCE(p_org, (SELECT a.organization_id FROM accounts a WHERE a.id = p_workspace));
    PERFORM 1 FROM organizations o WHERE o.id = org FOR UPDATE;
    IF NOT FOUND THEN
        RETURN;
    END IF;
    RETURN QUERY
    SELECT org,
           COALESCE((SELECT e.seq + 1 FROM org_admin_events e WHERE e.organization_id = org
                      ORDER BY e.seq DESC LIMIT 1), 0),
           (SELECT o.admin_chain_head FROM organizations o WHERE o.id = org);
END
$$;
GRANT EXECUTE ON FUNCTION platform.org_log_tip(bytea, uuid, uuid, timestamptz) TO openseal_console;

-- 2. The copy ------------------------------------------------------------------------------

CREATE FUNCTION platform.copy_to_org_log(
    p_session bytea, p_org uuid, p_seq bigint, p_prev bytea, p_hash bytea, p_action text,
    p_at timestamptz, p_canonical bytea, p_now timestamptz) RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
DECLARE
    op uuid := platform.acting_operator(p_session, p_now, ARRAY['platform_owner', 'operator']);
    doc jsonb;
    was_org text := current_setting('openseal.organization_id', true);
    was_acct text := current_setting('openseal.account_id', true);
BEGIN
    IF p_action IS NULL OR p_action !~ '^operator\.[a-z][a-z0-9_.]{0,54}$' THEN
        RAISE EXCEPTION 'a console copy is an operator.* action' USING ERRCODE = 'OS005';
    END IF;
    BEGIN
        doc := convert_from(p_canonical, 'UTF8')::jsonb;
    EXCEPTION WHEN OTHERS THEN
        RAISE EXCEPTION 'console copy is not JSON (seq %)', p_seq USING ERRCODE = 'OS005';
    END;
    IF jsonb_typeof(doc) IS DISTINCT FROM 'object'
       OR doc -> 'actor' IS DISTINCT FROM jsonb_build_object('kind', 'operator', 'id', op::text) THEN
        RAISE EXCEPTION 'console copy names another actor (seq %)', p_seq USING ERRCODE = 'OS005';
    END IF;
    -- A copy is of an operator event that exists: the one its bytes link (`seq`, hash),
    -- by this operator, of this action. No `operator.*` event in a tenant's log that the
    -- operator log does not hold.
    IF jsonb_typeof(doc -> 'operator_event') IS DISTINCT FROM 'object'
       OR jsonb_typeof(doc -> 'operator_event' -> 'seq') IS DISTINCT FROM 'number'
       OR (doc -> 'operator_event' ->> 'seq') !~ '^(0|[1-9][0-9]{0,15})$'
       OR (doc -> 'operator_event' ->> 'hash') IS NULL
       OR (doc -> 'operator_event' ->> 'hash') !~ '^[0-9a-f]{64}$'
       OR NOT EXISTS (SELECT 1 FROM platform.operator_events oe
                       WHERE oe.seq = (doc -> 'operator_event' ->> 'seq')::bigint
                         AND oe.hash = decode(doc -> 'operator_event' ->> 'hash', 'hex')
                         AND oe.operator_id = op
                         AND oe.action = p_action) THEN
        RAISE EXCEPTION 'console copy links no operator event of its own (seq %)', p_seq
            USING ERRCODE = 'OS005';
    END IF;
    -- The chain trigger (0020) accepts only the current scope's log: this organization's,
    -- for this one insert, then the caller's settings again.
    PERFORM set_config('openseal.account_id', '', true);
    PERFORM set_config('openseal.organization_id', p_org::text, true);
    INSERT INTO org_admin_events (organization_id, seq, prev_hash, hash, action, at, canonical, xact)
    VALUES (p_org, p_seq, p_prev, p_hash, p_action, p_at, p_canonical, pg_current_xact_id());
    PERFORM set_config('openseal.organization_id', COALESCE(was_org, ''), true);
    PERFORM set_config('openseal.account_id', COALESCE(was_acct, ''), true);
END
$$;
GRANT EXECUTE ON FUNCTION platform.copy_to_org_log(bytea, uuid, bigint, bytea, bytea, text, timestamptz,
    bytea, timestamptz) TO openseal_console;

-- 3. No console change without its copy ----------------------------------------------------

-- Whether this transaction appended an `operator.*` event to the log of organization
-- `p_org`, or of workspace `p_account`'s organization. What the commit check asks for a
-- console change; it reveals nothing beyond the caller's own transaction.
CREATE FUNCTION platform.xact_copied_to_org_log(p_account uuid, p_org uuid) RETURNS boolean
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
    SELECT EXISTS (SELECT 1 FROM org_admin_events e
                    WHERE e.organization_id = COALESCE(p_org,
                              (SELECT a.organization_id FROM accounts a WHERE a.id = p_account))
                      AND e.xact = pg_current_xact_id()
                      AND e.action LIKE 'operator.%')
$$;
GRANT EXECUTE ON FUNCTION platform.xact_copied_to_org_log(uuid, uuid) TO openseal_console;

-- As 0020, and the console role's changes need their copy. Still as the role committing,
-- never a definer; the owner's changes (migrations, superuser recovery) stay outside.
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
        WHEN 'account_memberships', 'permission_profiles' THEN acct := r.account_id;
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

REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA platform FROM PUBLIC;
