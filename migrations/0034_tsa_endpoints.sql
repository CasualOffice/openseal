-- 0034: time-stamping authorities in the database, changed only by two key custodians
-- (CON-07; ADR-028, docs/23 §5.4; SEC-X05, SEC-X06).
--
-- `platform.tsa_endpoints` replaces `OPENSEAL_TSA_URLS` when it holds an enabled row; the
-- environment stays the fallback when it is empty. The worker reads it through
-- `openseal_tsa_endpoints()` with a short cache and checks every address again when it
-- connects (`SEC-W01`); the console checks the address policy when a change is proposed.
--
-- A change is three steps by two key custodians, on the 0019 approval tables:
--   1. `platform.request_key_change` by custodian A: the action and its whole payload,
--      kept in `platform.approval_payloads` (insert-only) so the approver sees what they
--      approve; the request's `payload_sha256` is SHA-256 of the payload's jsonb text.
--   2. `platform.grant_key_change` by custodian B, never A, with a second factor entered
--      within 5 minutes.
--   3. `platform.apply_key_change` by A, within 5 minutes of a second factor: the stored
--      payload's hash is recomputed and compared, the approval spent once, the change made.
-- `platform.grant_approval` (operators, organization actions) no longer grants a key
-- change, so an operator who is not a key custodian cannot approve one. The console has
-- SELECT only on `tsa_endpoints`: these functions are its only way to change it.
-- Refusals: OS009 (CS-CON-0004), OS007 (CS-CON-0002), OS008 (CS-CON-0003), and OS012
-- (CS-CON-0006, a payload that fails its checks).

ALTER TABLE platform.approval_requests DROP CONSTRAINT approval_requests_action_check;
ALTER TABLE platform.approval_requests ADD CONSTRAINT approval_requests_action_check
    CHECK (action IN ('organization.suspend', 'organization.resume', 'tsa.set', 'tsa.remove'));

CREATE TABLE platform.approval_payloads (
    request_id  uuid PRIMARY KEY REFERENCES platform.approval_requests (id),
    payload     jsonb NOT NULL CHECK (octet_length(payload::text) <= 4096)
);
GRANT SELECT ON platform.approval_payloads TO openseal_console;
CREATE TRIGGER approval_payloads_insert_only BEFORE UPDATE OR DELETE ON platform.approval_payloads
    FOR EACH ROW EXECUTE FUNCTION platform.refuse_change();
CREATE TRIGGER approval_payloads_no_truncate BEFORE TRUNCATE ON platform.approval_payloads
    FOR EACH STATEMENT EXECUTE FUNCTION platform.refuse_change();

CREATE TABLE platform.tsa_endpoints (
    id           uuid PRIMARY KEY,
    url          text NOT NULL UNIQUE
                 CHECK (octet_length(url) <= 2048 AND url ~ '^https?://[^[:space:]@/?#]+([/?#][^[:space:]]*)?$'),
    -- The TSA policy OID the operator expects, or NULL.
    policy_oid   text CHECK (policy_oid ~ '^[0-2](\.(0|[1-9][0-9]{0,9})){1,31}$'),
    -- Tried in ascending order.
    priority     integer NOT NULL CHECK (priority BETWEEN 0 AND 1000),
    enabled      boolean NOT NULL,
    -- SHA-256 of the TSA's signing certificate the operator expects, or NULL.
    cert_sha256  bytea CHECK (octet_length(cert_sha256) = 32),
    changed_at   timestamptz NOT NULL,
    -- The approval that made this version.
    approval     uuid NOT NULL REFERENCES platform.approval_requests (id)
);
GRANT SELECT ON platform.tsa_endpoints TO openseal_console;

-- A key change's payload, checked: OS012 (CS-CON-0006) naming nothing but the action.
-- Internal.
CREATE FUNCTION platform.check_key_payload(p_action text, p_target uuid, p_payload jsonb)
RETURNS void
    LANGUAGE plpgsql IMMUTABLE
    SET search_path = pg_catalog
AS $$
DECLARE
    bad boolean := false;
BEGIN
    IF p_payload IS NULL OR jsonb_typeof(p_payload) <> 'object'
       OR p_payload->>'id' IS DISTINCT FROM p_target::text THEN
        bad := true;
    ELSIF p_action = 'tsa.set' THEN
        bad := coalesce(NOT (p_payload ?& ARRAY['id', 'url', 'policy_oid', 'priority', 'enabled', 'cert_sha256'])
            OR (SELECT count(*) FROM jsonb_object_keys(p_payload)) <> 6
            OR jsonb_typeof(p_payload->'url') <> 'string'
            OR jsonb_typeof(p_payload->'priority') <> 'number'
            OR jsonb_typeof(p_payload->'enabled') <> 'boolean'
            OR jsonb_typeof(p_payload->'policy_oid') NOT IN ('string', 'null')
            OR jsonb_typeof(p_payload->'cert_sha256') NOT IN ('string', 'null')
            OR octet_length(p_payload->>'url') > 2048
            OR NOT (p_payload->>'url') ~ '^https?://[^[:space:]@/?#]+([/?#][^[:space:]]*)?$'
            OR CASE WHEN (p_payload->>'priority') ~ '^[0-9]{1,4}$'
                    THEN (p_payload->>'priority')::integer > 1000 ELSE true END
            OR NOT coalesce(p_payload->>'policy_oid', '0.0') ~ '^[0-2](\.(0|[1-9][0-9]{0,9})){1,31}$'
            OR NOT coalesce(p_payload->>'cert_sha256', repeat('0', 64)) ~ '^[0-9a-f]{64}$', true);
    ELSIF p_action = 'tsa.remove' THEN
        bad := coalesce((SELECT count(*) FROM jsonb_object_keys(p_payload)) <> 1, true);
    ELSE
        bad := true;
    END IF;
    IF bad THEN
        RAISE EXCEPTION 'CS-CON-0006 % payload fails its checks', p_action USING ERRCODE = 'OS012';
    END IF;
END
$$;

-- Step 1. The request's id. Key custodians only, with a fresh second factor.
CREATE FUNCTION platform.request_key_change(p_session bytea, p_id uuid, p_action text, p_target uuid,
                                            p_payload jsonb, p_now timestamptz)
RETURNS uuid
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path = pg_catalog
AS $$
DECLARE
    op uuid := platform.fresh_operator(p_session, p_now, ARRAY['key_custodian']);
BEGIN
    IF p_action NOT IN ('tsa.set', 'tsa.remove') THEN
        RAISE EXCEPTION 'CS-CON-0006 not a key change' USING ERRCODE = 'OS012';
    END IF;
    PERFORM platform.check_key_payload(p_action, p_target, p_payload);
    INSERT INTO platform.approval_requests (id, requester, action, payload_sha256, target, created_at, expires_at)
    VALUES (p_id, op, p_action, sha256(convert_to(p_payload::text, 'UTF8')), p_target, p_now,
            p_now + interval '24 hours');
    INSERT INTO platform.approval_payloads (request_id, payload) VALUES (p_id, p_payload);
    RETURN p_id;
END
$$;
GRANT EXECUTE ON FUNCTION platform.request_key_change(bytea, uuid, text, uuid, jsonb, timestamptz) TO openseal_console;

-- Step 2. By another key custodian with a fresh second factor; false when there is no
-- live, unused key-change request with that id.
CREATE FUNCTION platform.grant_key_change(p_session bytea, p_request uuid, p_now timestamptz)
RETURNS boolean
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path = pg_catalog
AS $$
DECLARE
    op uuid := platform.fresh_operator(p_session, p_now, ARRAY['key_custodian']);
    r record;
    mfa timestamptz;
BEGIN
    SELECT * INTO r FROM platform.approval_requests
     WHERE id = p_request AND p_now < expires_at AND action IN ('tsa.set', 'tsa.remove')
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
GRANT EXECUTE ON FUNCTION platform.grant_key_change(bytea, uuid, timestamptz) TO openseal_console;

-- Organization approvals stay with operators, and no longer grant a key change.
CREATE OR REPLACE FUNCTION platform.grant_approval(p_session bytea, p_request uuid, p_now timestamptz)
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
       AND action IN ('organization.suspend', 'organization.resume')
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

-- Step 3. By the requesting custodian with a fresh second factor; the stored payload is
-- re-hashed and must be the one requested and approved by another custodian whose second
-- factor was at most 5 minutes old. Returns the action applied; false-y (NULL) never:
-- every refusal raises.
CREATE FUNCTION platform.apply_key_change(p_session bytea, p_request uuid, p_now timestamptz)
RETURNS text
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path = pg_catalog
AS $$
DECLARE
    op uuid := platform.fresh_operator(p_session, p_now, ARRAY['key_custodian']);
    r record;
    p jsonb;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended(p_request::text, 0));
    SELECT * INTO r FROM platform.approval_requests WHERE id = p_request;
    SELECT a.payload INTO p FROM platform.approval_payloads a WHERE a.request_id = p_request;
    IF NOT FOUND OR r.action NOT IN ('tsa.set', 'tsa.remove') OR p_now >= r.expires_at
       OR r.requester <> op
       OR r.payload_sha256 <> sha256(convert_to(p::text, 'UTF8'))
       OR EXISTS (SELECT 1 FROM platform.approval_uses u WHERE u.request_id = p_request)
       OR NOT EXISTS (SELECT 1 FROM platform.approval_grants g
                       JOIN platform.operators o ON o.id = g.approver
                       WHERE g.request_id = p_request AND g.approver <> r.requester
                         AND 'key_custodian' = ANY (o.roles) AND o.disabled_at IS NULL
                         AND g.granted_at - g.mfa_at <= interval '5 minutes'
                         AND g.granted_at <= p_now) THEN
        RAISE EXCEPTION 'CS-CON-0004 no unused approval by another key custodian for this change'
            USING ERRCODE = 'OS009';
    END IF;
    PERFORM platform.check_key_payload(r.action, r.target, p);
    INSERT INTO platform.approval_uses (request_id, used_by, used_at) VALUES (p_request, op, p_now);
    IF r.action = 'tsa.set' THEN
        INSERT INTO platform.tsa_endpoints (id, url, policy_oid, priority, enabled, cert_sha256, changed_at, approval)
        VALUES (r.target, p->>'url', p->>'policy_oid', (p->>'priority')::integer, (p->>'enabled')::boolean,
                decode(p->>'cert_sha256', 'hex'), p_now, p_request)
        ON CONFLICT (id) DO UPDATE SET url = EXCLUDED.url, policy_oid = EXCLUDED.policy_oid,
            priority = EXCLUDED.priority, enabled = EXCLUDED.enabled, cert_sha256 = EXCLUDED.cert_sha256,
            changed_at = EXCLUDED.changed_at, approval = EXCLUDED.approval;
    ELSE
        DELETE FROM platform.tsa_endpoints WHERE id = r.target;
    END IF;
    RETURN r.action;
END
$$;
GRANT EXECUTE ON FUNCTION platform.apply_key_change(bytea, uuid, timestamptz) TO openseal_console;

REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA platform FROM PUBLIC;

-- The worker's read: the enabled endpoints in the order to try them. URLs, policy OIDs
-- and certificate hashes only; no operator or approval.
CREATE FUNCTION openseal_tsa_endpoints()
RETURNS TABLE (url text, policy_oid text, cert_sha256 bytea)
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path = pg_catalog
AS $$
    SELECT t.url, t.policy_oid, t.cert_sha256 FROM platform.tsa_endpoints t
     WHERE t.enabled ORDER BY t.priority, t.id
$$;
REVOKE ALL ON FUNCTION openseal_tsa_endpoints() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openseal_tsa_endpoints() TO openseal_app;
