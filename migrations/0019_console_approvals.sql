-- 0019: the two-person rule in the database, and suspending and resuming an organization
-- with it (CON-04, second part; ADR-028, docs/23 §5.1 "Two-person rule", §5.3; SEC-X08).
--
-- A sensitive action is three steps by two operators:
--   1. `platform.request_approval` by operator A: the action and the SHA-256 of its payload, valid
--      for 24 hours. Needs A's second factor entered within 5 minutes.
--   2. `platform.grant_approval` by operator B, never A, with B's second factor entered within the
--      last 5 minutes (recorded on the grant).
--   3. `platform.apply_<action>` by A, again within 5 minutes of a second factor: the
--      function recomputes the payload hash from its own parameters, requires an unexpired,
--      unused request for that action and hash with a grant by another operator whose
--      second factor was at most 5 minutes old when granting, records the use (once,
--      `approval_uses` is keyed on the request), and applies the change.
-- The operator and the second-factor times come from live session rows, never from a
-- parameter. Requests, grants and uses are insert-only for every role. Refusals are
-- SQLSTATE OS009 (CS-CON-0004) or OS007 (CS-CON-0002, a stale second factor).
--
-- The organization's status column has no write grant for the console; only the apply
-- functions below change it. Enforcing `suspended` on tenant writes (CS-PLAN-0005) is the
-- server's, tracked with CON-04.

CREATE TABLE platform.approval_requests (
    id              uuid PRIMARY KEY,
    requester       uuid NOT NULL REFERENCES platform.operators (id),
    action          text NOT NULL CHECK (action IN ('organization.suspend', 'organization.resume')),
    payload_sha256  bytea NOT NULL CHECK (octet_length(payload_sha256) = 32),
    -- The organization (or other object) the action is for, for listing; ids only.
    target          uuid NOT NULL,
    created_at      timestamptz NOT NULL,
    expires_at      timestamptz NOT NULL CHECK (expires_at > created_at)
);
GRANT SELECT ON platform.approval_requests TO openseal_console;

CREATE TABLE platform.approval_grants (
    request_id  uuid NOT NULL REFERENCES platform.approval_requests (id),
    approver    uuid NOT NULL REFERENCES platform.operators (id),
    mfa_at      timestamptz NOT NULL,
    granted_at  timestamptz NOT NULL,
    PRIMARY KEY (request_id, approver)
);
GRANT SELECT ON platform.approval_grants TO openseal_console;

CREATE TABLE platform.approval_uses (
    request_id  uuid PRIMARY KEY REFERENCES platform.approval_requests (id),
    used_by     uuid NOT NULL REFERENCES platform.operators (id),
    used_at     timestamptz NOT NULL
);
GRANT SELECT ON platform.approval_uses TO openseal_console;

CREATE TRIGGER approval_requests_insert_only BEFORE UPDATE OR DELETE ON platform.approval_requests
    FOR EACH ROW EXECUTE FUNCTION platform.refuse_change();
CREATE TRIGGER approval_requests_no_truncate BEFORE TRUNCATE ON platform.approval_requests
    FOR EACH STATEMENT EXECUTE FUNCTION platform.refuse_change();
CREATE TRIGGER approval_grants_insert_only BEFORE UPDATE OR DELETE ON platform.approval_grants
    FOR EACH ROW EXECUTE FUNCTION platform.refuse_change();
CREATE TRIGGER approval_grants_no_truncate BEFORE TRUNCATE ON platform.approval_grants
    FOR EACH STATEMENT EXECUTE FUNCTION platform.refuse_change();
CREATE TRIGGER approval_uses_insert_only BEFORE UPDATE OR DELETE ON platform.approval_uses
    FOR EACH ROW EXECUTE FUNCTION platform.refuse_change();
CREATE TRIGGER approval_uses_no_truncate BEFORE TRUNCATE ON platform.approval_uses
    FOR EACH STATEMENT EXECUTE FUNCTION platform.refuse_change();

-- The payload hash of an organization action: SHA-256 of "<action>\n<organization id>".
-- The console computes the same bytes; the apply functions recompute it here.
CREATE FUNCTION platform.org_action_sha256(p_action text, p_org uuid) RETURNS bytea
    LANGUAGE sql IMMUTABLE
    SET search_path = pg_catalog
AS $$
    SELECT sha256(convert_to(p_action || E'\n' || p_org::text, 'UTF8'))
$$;

-- The acting operator with a second factor entered within 5 minutes. Internal.
CREATE FUNCTION platform.fresh_operator(p_token bytea, p_now timestamptz, p_roles text[])
RETURNS uuid
    LANGUAGE plpgsql STABLE SECURITY DEFINER
    SET search_path = pg_catalog
AS $$
DECLARE
    op uuid := platform.acting_operator(p_token, p_now, p_roles);
    mfa timestamptz;
BEGIN
    SELECT s.mfa_at INTO mfa FROM platform.operator_sessions s WHERE s.token_sha256 = p_token;
    IF mfa IS NULL OR p_now - mfa > interval '5 minutes' THEN
        RAISE EXCEPTION 'CS-CON-0002 second factor older than 5 minutes' USING ERRCODE = 'OS007';
    END IF;
    RETURN op;
END
$$;

-- Step 1. The request's id.
CREATE FUNCTION platform.request_approval(p_session bytea, p_id uuid, p_action text, p_target uuid, p_now timestamptz)
RETURNS uuid
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path = pg_catalog
AS $$
DECLARE
    op uuid := platform.fresh_operator(p_session, p_now, ARRAY['platform_owner', 'operator']);
BEGIN
    INSERT INTO platform.approval_requests (id, requester, action, payload_sha256, target, created_at, expires_at)
    VALUES (p_id, op, p_action, platform.org_action_sha256(p_action, p_target), p_target, p_now,
            p_now + interval '24 hours');
    RETURN p_id;
END
$$;
GRANT EXECUTE ON FUNCTION platform.request_approval(bytea, uuid, text, uuid, timestamptz) TO openseal_console;

-- Step 2. By another operator, with a fresh second factor; false when there is no such
-- live, unused request.
CREATE FUNCTION platform.grant_approval(p_session bytea, p_request uuid, p_now timestamptz)
RETURNS boolean
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path = pg_catalog
AS $$
DECLARE
    op uuid := platform.fresh_operator(p_session, p_now, ARRAY['platform_owner', 'operator']);
    r record;
    mfa timestamptz;
BEGIN
    SELECT * INTO r FROM platform.approval_requests
     WHERE id = p_request AND p_now < expires_at
       AND NOT EXISTS (SELECT 1 FROM platform.approval_uses u WHERE u.request_id = p_request);
    IF NOT FOUND THEN
        RETURN false;
    END IF;
    IF r.requester = op THEN
        RAISE EXCEPTION 'CS-CON-0004 the requester cannot approve their own request' USING ERRCODE = 'OS009';
    END IF;
    SELECT s.mfa_at INTO mfa FROM platform.operator_sessions s WHERE s.token_sha256 = p_session;
    INSERT INTO platform.approval_grants (request_id, approver, mfa_at, granted_at)
    VALUES (p_request, op, mfa, p_now)
    ON CONFLICT DO NOTHING;
    RETURN true;
END
$$;
GRANT EXECUTE ON FUNCTION platform.grant_approval(bytea, uuid, timestamptz) TO openseal_console;

-- Step 3's check, shared by every apply function: the acting operator (fresh second
-- factor, the requester) spends request `p_request` for `p_action` on `p_hash`. Internal.
CREATE FUNCTION platform.spend_approval(p_session bytea, p_request uuid, p_action text, p_hash bytea,
                                        p_now timestamptz)
RETURNS uuid
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path = pg_catalog
AS $$
DECLARE
    op uuid := platform.fresh_operator(p_session, p_now, ARRAY['platform_owner', 'operator']);
    r record;
BEGIN
    -- Serialize spends of one request.
    PERFORM pg_advisory_xact_lock(hashtextextended(p_request::text, 0));
    SELECT * INTO r FROM platform.approval_requests WHERE id = p_request;
    IF NOT FOUND OR r.action <> p_action OR r.payload_sha256 <> p_hash OR p_now >= r.expires_at
       OR r.requester <> op
       OR EXISTS (SELECT 1 FROM platform.approval_uses u WHERE u.request_id = p_request)
       OR NOT EXISTS (SELECT 1 FROM platform.approval_grants g
                       WHERE g.request_id = p_request AND g.approver <> r.requester
                         AND g.granted_at - g.mfa_at <= interval '5 minutes'
                         AND g.granted_at <= p_now) THEN
        RAISE EXCEPTION 'CS-CON-0004 no unused approval by another operator for this action'
            USING ERRCODE = 'OS009';
    END IF;
    INSERT INTO platform.approval_uses (request_id, used_by, used_at) VALUES (p_request, op, p_now);
    RETURN op;
END
$$;

-- Suspend an organization (two-person). False when there is no such active organization.
CREATE FUNCTION platform.apply_suspend_organization(p_session bytea, p_request uuid, p_org uuid, p_now timestamptz)
RETURNS boolean
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
BEGIN
    PERFORM platform.spend_approval(p_session, p_request, 'organization.suspend',
                                    platform.org_action_sha256('organization.suspend', p_org), p_now);
    UPDATE organizations SET status = 'suspended' WHERE id = p_org AND status = 'active';
    RETURN FOUND;
END
$$;
GRANT EXECUTE ON FUNCTION platform.apply_suspend_organization(bytea, uuid, uuid, timestamptz) TO openseal_console;

-- Resume a suspended organization (two-person).
CREATE FUNCTION platform.apply_resume_organization(p_session bytea, p_request uuid, p_org uuid, p_now timestamptz)
RETURNS boolean
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
BEGIN
    PERFORM platform.spend_approval(p_session, p_request, 'organization.resume',
                                    platform.org_action_sha256('organization.resume', p_org), p_now);
    UPDATE organizations SET status = 'active' WHERE id = p_org AND status = 'suspended';
    RETURN FOUND;
END
$$;
GRANT EXECUTE ON FUNCTION platform.apply_resume_organization(bytea, uuid, uuid, timestamptz) TO openseal_console;

REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA platform FROM PUBLIC;
