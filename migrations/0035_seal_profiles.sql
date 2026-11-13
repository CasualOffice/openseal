-- 0035: the seal key alias in the database, rotated only by two key custodians
-- (CON-10, HRD-06; docs/23 §5.4; SEC-X05).
--
-- `platform.seal_profiles` is insert-only: each row says "from `active_from`, seal with
-- the key keyd serves as `active_alias`", made by one approved key change. The alias in
-- force at an instant is the row with the latest `active_from` not after it; the
-- worker reads it per seal job through `openseal_seal_alias(at)`, which also says
-- whether that row's change is fully approved: a spent approval, granted by a key
-- custodian other than the requester with a second factor at most 5 minutes old, and
-- the console's `operator.seal.activated` event naming it in the operator chain. The
-- worker refuses an alias that is not (CS-CON-0006) rather than fall back to an older
-- one, and refuses one keyd does not serve. While the table is empty the worker uses
-- `OPENSEAL_KEYD_ALIAS`.
--
-- The change is the three steps of 0034 with action `seal.activate` and the payload
-- {"id", "alias", "active_from"}; `active_from` may not be before the moment the change
-- is applied, so no seal already made is ever attributed to a key after the fact. A null
-- `active_from` means "from when the change is applied": the row starts at that moment.
--
-- An approval is judged as it stood when it was given. A grant of a key change is made
-- only by `grant_key_change`, which admits only an active key custodian with a fresh
-- second factor (0034 took key changes out of `platform.grant_approval`), so the grant
-- row is the record that its approver was one then. Applying also needs the approver to
-- be an active key custodian still; the worker's read afterwards judges the grant as
-- given and the approval as spent when the version was applied, so disabling a departed
-- custodian, or taking the role away, does not stop sealing with an alias they approved.

ALTER TABLE platform.approval_requests DROP CONSTRAINT approval_requests_action_check;
ALTER TABLE platform.approval_requests ADD CONSTRAINT approval_requests_action_check
    CHECK (action IN ('organization.suspend', 'organization.resume', 'tsa.set', 'tsa.remove',
                      'seal.activate'));

CREATE TABLE platform.seal_profiles (
    id            uuid PRIMARY KEY,
    -- keyd's alias for the key: as keyd's own alias rule.
    active_alias  text NOT NULL CHECK (active_alias ~ '^[A-Za-z0-9._-]{1,64}$'),
    active_from   timestamptz NOT NULL,
    changed_at    timestamptz NOT NULL,
    -- The approval that made it; one row per approval.
    approval      uuid NOT NULL UNIQUE REFERENCES platform.approval_requests (id),
    CHECK (active_from >= changed_at)
);
CREATE INDEX seal_profiles_by_start ON platform.seal_profiles (active_from DESC, id DESC);
GRANT SELECT ON platform.seal_profiles TO openseal_console;
CREATE TRIGGER seal_profiles_insert_only BEFORE UPDATE OR DELETE ON platform.seal_profiles
    FOR EACH ROW EXECUTE FUNCTION platform.refuse_change();
CREATE TRIGGER seal_profiles_no_truncate BEFORE TRUNCATE ON platform.seal_profiles
    FOR EACH STATEMENT EXECUTE FUNCTION platform.refuse_change();

-- 0034's payload check, with `seal.activate`.
CREATE OR REPLACE FUNCTION platform.check_key_payload(p_action text, p_target uuid, p_payload jsonb)
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
    ELSIF p_action = 'seal.activate' THEN
        -- RFC 3339 in UTC with whole seconds, as the console writes it: parsed by the
        -- pattern first, so the cast below cannot fail.
        bad := coalesce(NOT (p_payload ?& ARRAY['id', 'alias', 'active_from'])
            OR (SELECT count(*) FROM jsonb_object_keys(p_payload)) <> 3
            OR jsonb_typeof(p_payload->'alias') <> 'string'
            OR jsonb_typeof(p_payload->'active_from') NOT IN ('string', 'null')
            OR NOT (p_payload->>'alias') ~ '^[A-Za-z0-9._-]{1,64}$'
            OR NOT coalesce(p_payload->>'active_from', '2000-01-01T00:00:00Z')
                ~ '^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$', true);
    ELSE
        bad := true;
    END IF;
    IF bad THEN
        RAISE EXCEPTION 'CS-CON-0006 % payload fails its checks', p_action USING ERRCODE = 'OS012';
    END IF;
END
$$;

-- 0034's three steps, with `seal.activate` among the key changes.
CREATE OR REPLACE FUNCTION platform.request_key_change(p_session bytea, p_id uuid, p_action text, p_target uuid,
                                                       p_payload jsonb, p_now timestamptz)
RETURNS uuid
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path = pg_catalog
AS $$
DECLARE
    op uuid := platform.fresh_operator(p_session, p_now, ARRAY['key_custodian']);
BEGIN
    IF p_action NOT IN ('tsa.set', 'tsa.remove', 'seal.activate') THEN
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

CREATE OR REPLACE FUNCTION platform.grant_key_change(p_session bytea, p_request uuid, p_now timestamptz)
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
     WHERE id = p_request AND p_now < expires_at AND action IN ('tsa.set', 'tsa.remove', 'seal.activate')
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

-- Whether key change `p_request` was granted, no later than `p_at`, by an operator other
-- than its requester (a key custodian then: only `grant_key_change` grants a key change)
-- with a second factor at most 5 minutes old. With `p_still`, the approver must also be
-- an active key custodian now (applying); without, the grant is judged as given (the
-- worker's read). Internal.
CREATE FUNCTION platform.key_change_granted(p_request uuid, p_requester uuid, p_at timestamptz,
                                            p_still boolean)
RETURNS boolean
    LANGUAGE sql STABLE
    SET search_path = pg_catalog
AS $$
    SELECT EXISTS (SELECT 1 FROM platform.approval_grants g
                     JOIN platform.operators o ON o.id = g.approver
                    WHERE g.request_id = p_request AND g.approver <> p_requester
                      AND (NOT p_still OR ('key_custodian' = ANY (o.roles) AND o.disabled_at IS NULL))
                      AND g.granted_at - g.mfa_at <= interval '5 minutes'
                      AND g.granted_at <= p_at)
$$;

CREATE OR REPLACE FUNCTION platform.apply_key_change(p_session bytea, p_request uuid, p_now timestamptz)
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
    IF NOT FOUND OR r.action NOT IN ('tsa.set', 'tsa.remove', 'seal.activate') OR p_now >= r.expires_at
       OR r.requester <> op
       OR r.payload_sha256 <> sha256(convert_to(p::text, 'UTF8'))
       OR EXISTS (SELECT 1 FROM platform.approval_uses u WHERE u.request_id = p_request)
       OR NOT platform.key_change_granted(p_request, r.requester, p_now, true) THEN
        RAISE EXCEPTION 'CS-CON-0004 no unused approval by another key custodian for this change'
            USING ERRCODE = 'OS009';
    END IF;
    PERFORM platform.check_key_payload(r.action, r.target, p);
    -- A null start is the moment of applying; a stated one may not have passed.
    IF r.action = 'seal.activate' AND (p->>'active_from')::timestamptz < p_now THEN
        RAISE EXCEPTION 'CS-CON-0006 seal.activate active_from is before the change is applied'
            USING ERRCODE = 'OS012';
    END IF;
    INSERT INTO platform.approval_uses (request_id, used_by, used_at) VALUES (p_request, op, p_now);
    IF r.action = 'tsa.set' THEN
        INSERT INTO platform.tsa_endpoints (id, url, policy_oid, priority, enabled, cert_sha256, changed_at, approval)
        VALUES (r.target, p->>'url', p->>'policy_oid', (p->>'priority')::integer, (p->>'enabled')::boolean,
                decode(p->>'cert_sha256', 'hex'), p_now, p_request)
        ON CONFLICT (id) DO UPDATE SET url = EXCLUDED.url, policy_oid = EXCLUDED.policy_oid,
            priority = EXCLUDED.priority, enabled = EXCLUDED.enabled, cert_sha256 = EXCLUDED.cert_sha256,
            changed_at = EXCLUDED.changed_at, approval = EXCLUDED.approval;
    ELSIF r.action = 'tsa.remove' THEN
        DELETE FROM platform.tsa_endpoints WHERE id = r.target;
    ELSE
        INSERT INTO platform.seal_profiles (id, active_alias, active_from, changed_at, approval)
        VALUES (r.target, p->>'alias', coalesce((p->>'active_from')::timestamptz, p_now), p_now,
                p_request);
    END IF;
    RETURN r.action;
END
$$;

REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA platform FROM PUBLIC;

-- The worker's read, per seal job: the alias in force at `p_at`, the approval that made
-- it and whether that approval is complete: spent when the version was applied, granted
-- before then by another operator who was then an active key custodian (judged as given,
-- not by the approver's state now), and recorded by the console as
-- `operator.seal.activated` in the operator chain. No row: no alias configured in the
-- database.
CREATE FUNCTION openseal_seal_alias(p_at timestamptz)
RETURNS TABLE (alias text, approval uuid, active_from timestamptz, approved boolean)
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path = pg_catalog
AS $$
    SELECT s.active_alias, s.approval, s.active_from,
           EXISTS (SELECT 1 FROM platform.approval_uses u
                    WHERE u.request_id = s.approval AND u.used_at = s.changed_at)
           AND platform.key_change_granted(s.approval, r.requester, s.changed_at, false)
           AND r.action = 'seal.activate' AND r.target = s.id
           AND EXISTS (SELECT 1 FROM platform.operator_events e
                        WHERE e.action = 'operator.seal.activated'
                          AND (convert_from(e.canonical, 'UTF8')::jsonb #>> '{details,approval}')
                              = s.approval::text)
      FROM platform.seal_profiles s
      JOIN platform.approval_requests r ON r.id = s.approval
     WHERE s.active_from <= p_at
     ORDER BY s.active_from DESC, s.id DESC
     LIMIT 1
$$;
REVOKE ALL ON FUNCTION openseal_seal_alias(timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openseal_seal_alias(timestamptz) TO openseal_app;
