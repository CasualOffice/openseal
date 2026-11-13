-- 0024: plans in the `platform` schema, and the application's one read of them (PLAN-02;
-- ADR-028, docs/23 §7.1).
--
-- 1. `plans` (one row per immutable version of a key), `plan_entitlements`, `plan_quotas`,
--    `plan_seat_rule`: written only by `platform.create_plan`, all in one call. A version
--    never changes; the only update is archiving it once (no new assignment may then
--    name it; current ones continue).
-- 2. `plan_assignments`: an organization's timeline. Each is current on
--    [starts_at, ends_at). Assigning a plan from an instant ends the assignment current
--    then at that same instant, so two are never current at once; an assignment starts
--    no earlier than now (history is not rewritten) and none may already start at or
--    after it. The only update is shortening `ends_at`.
-- 3. `plan_overrides`: one entitlement, one quota's limit or enforcement, or the seat
--    rule, for the organization or (quotas at workspace level only) one of its
--    workspaces, until `expires_at` (exclusive). The column is `workspace_id`, not
--    `account_id`: this is a `platform` table, outside the `public` tenant catalog rules
--    (docs/23 §7.1). The only update is shortening `expires_at` (expiring it early).
-- 4. A quota may not be `hard` on an approximate meter (`api_calls`, docs/23 §7.2), by a
--    plan or by an override: the functions refuse it with SQLSTATE OS010
--    (CS-PLAN-0006), and the table constraints refuse it again for any other writer.
--    Every other invalid plan, quota or override is OS010 as well.
-- 5. Reads. The console (SELECT on every `platform` table) calls `platform.plans_page()` and
--    `platform.plan_inputs(org, NULL, now, false)` (every assignment and override, for
--    history). The application has no grant in `platform`; it calls
--    `openseal_effective_plan(now)`, which derives the organization from the transaction's
--    account (or organization scope) and returns only the assignment current at `now`
--    and the overrides live at `now` for the organization and that workspace, without
--    reasons or operator ids. `casual-sign-policy::plans::effective` resolves either.
--
-- Times in the JSON are microseconds since the Unix epoch.
--
-- `accounts.settings` held no plan limits (the comment in 0002 was the only mention; no
-- code wrote any), so nothing is copied. The column's comment is corrected below.

COMMENT ON COLUMN accounts.settings IS
    'Workspace settings (docs/22 §8). Plan limits are not here: they live in platform.plans and its tables (0024, docs/23 §7.1).';

-- Names ------------------------------------------------------------------------------

CREATE FUNCTION platform.plan_feature_ok(p text) RETURNS boolean
    LANGUAGE sql IMMUTABLE
    SET search_path = pg_catalog
AS $$
    SELECT p IN ('bulk_send', 'sso_saml', 'scim', 'api', 'webhooks', 'sms_auth', 'conditional_routing',
                 'payments', 'branding_multi', 'seal_b_lta', 'ml_suggestions')
$$;

CREATE FUNCTION platform.plan_meter_ok(p text) RETURNS boolean
    LANGUAGE sql IMMUTABLE
    SET search_path = pg_catalog
AS $$
    SELECT p IN ('envelopes_sent', 'seats', 'storage_bytes', 'api_calls', 'sms_sent', 'phone_calls',
                 'idv_checks', 'kba_checks', 'timestamps', 'seals', 'bulk_send_rows',
                 'signing_link_submissions', 'webhook_deliveries', 'workspaces', 'templates')
$$;

-- Gauges measure what exists now, so they take no period.
CREATE FUNCTION platform.plan_meter_gauge(p text) RETURNS boolean
    LANGUAGE sql IMMUTABLE
    SET search_path = pg_catalog
AS $$
    SELECT p IN ('seats', 'storage_bytes', 'workspaces', 'templates')
$$;

-- Approximate meters are counted in memory and flushed: soft or notify only.
CREATE FUNCTION platform.plan_meter_approximate(p text) RETURNS boolean
    LANGUAGE sql IMMUTABLE
    SET search_path = pg_catalog
AS $$
    SELECT p = 'api_calls'
$$;

-- An override's key and value, and its scope (`p_workspace`: a workspace override).
--   feature.<feature>                       true | false            organization only
--   quota.<meter>.<level>.limit             0 .. 2^63-1             workspace: level workspace only
--   quota.<meter>.<level>.enforcement       hard | soft | notify    never hard on an approximate meter
--   seat_rule                               can_send | every_member organization only
CREATE FUNCTION platform.plan_override_ok(p_workspace boolean, p_key text, p_value text) RETURNS boolean
    LANGUAGE plpgsql IMMUTABLE
    SET search_path = pg_catalog
AS $$
DECLARE
    meter text;
    level text;
BEGIN
    IF p_key IS NULL OR p_value IS NULL THEN
        RETURN false;
    END IF;
    IF p_key = 'seat_rule' THEN
        RETURN NOT p_workspace AND p_value IN ('can_send', 'every_member');
    END IF;
    IF left(p_key, 8) = 'feature.' THEN
        RETURN NOT p_workspace AND platform.plan_feature_ok(substr(p_key, 9)) AND p_value IN ('true', 'false');
    END IF;
    IF p_key !~ '^quota\.[a-z_]+\.(organization|workspace)\.(limit|enforcement)$' THEN
        RETURN false;
    END IF;
    meter := split_part(p_key, '.', 2);
    level := split_part(p_key, '.', 3);
    IF NOT platform.plan_meter_ok(meter) OR (p_workspace AND level <> 'workspace') THEN
        RETURN false;
    END IF;
    IF split_part(p_key, '.', 4) = 'limit' THEN
        IF p_value !~ '^[0-9]{1,19}$' THEN
            RETURN false;
        END IF;
        RETURN p_value::numeric <= 9223372036854775807;
    END IF;
    RETURN p_value IN ('hard', 'soft', 'notify')
       AND NOT (platform.plan_meter_approximate(meter) AND p_value = 'hard');
END
$$;

-- Tables -----------------------------------------------------------------------------

CREATE TABLE platform.plans (
    id           uuid PRIMARY KEY,
    key          text NOT NULL CHECK (key ~ '^[a-z][a-z0-9_-]{0,63}$'),
    version      integer NOT NULL CHECK (version >= 1),
    name         text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 120 AND name !~ '[[:cntrl:]]'),
    created_by   uuid NOT NULL REFERENCES platform.operators (id),
    created_at   timestamptz NOT NULL,
    archived_at  timestamptz,
    UNIQUE (key, version)
);
GRANT SELECT ON platform.plans TO openseal_console;

CREATE TABLE platform.plan_entitlements (
    plan_id  uuid NOT NULL REFERENCES platform.plans (id),
    feature  text NOT NULL CHECK (platform.plan_feature_ok(feature)),
    enabled  boolean NOT NULL,
    PRIMARY KEY (plan_id, feature)
);
GRANT SELECT ON platform.plan_entitlements TO openseal_console;

CREATE TABLE platform.plan_quotas (
    plan_id      uuid NOT NULL REFERENCES platform.plans (id),
    meter        text NOT NULL CHECK (platform.plan_meter_ok(meter)),
    "limit"      bigint NOT NULL CHECK ("limit" >= 0),
    period       text NOT NULL CHECK (period IN ('month', 'year', 'none')),
    enforcement  text NOT NULL CHECK (enforcement IN ('hard', 'soft', 'notify')),
    level        text NOT NULL CHECK (level IN ('organization', 'workspace')),
    PRIMARY KEY (plan_id, meter, level),
    CONSTRAINT plan_quota_not_hard_on_approximate
        CHECK (NOT (platform.plan_meter_approximate(meter) AND enforcement = 'hard')),
    CONSTRAINT plan_quota_gauge_has_no_period CHECK (NOT platform.plan_meter_gauge(meter) OR period = 'none'),
    CONSTRAINT plan_quota_workspaces_per_organization CHECK (NOT (meter = 'workspaces' AND level = 'workspace'))
);
GRANT SELECT ON platform.plan_quotas TO openseal_console;

CREATE TABLE platform.plan_seat_rule (
    plan_id  uuid PRIMARY KEY REFERENCES platform.plans (id),
    rule     text NOT NULL CHECK (rule IN ('can_send', 'every_member'))
);
GRANT SELECT ON platform.plan_seat_rule TO openseal_console;

CREATE TABLE platform.plan_assignments (
    id               uuid PRIMARY KEY,
    organization_id  uuid NOT NULL REFERENCES organizations (id),
    plan_id          uuid NOT NULL REFERENCES platform.plans (id),
    starts_at        timestamptz NOT NULL,
    ends_at          timestamptz CHECK (ends_at IS NULL OR ends_at > starts_at),
    assigned_by      uuid NOT NULL REFERENCES platform.operators (id),
    assigned_at      timestamptz NOT NULL
);
CREATE INDEX plan_assignments_by_org ON platform.plan_assignments (organization_id, starts_at);
GRANT SELECT ON platform.plan_assignments TO openseal_console;

CREATE TABLE platform.plan_overrides (
    id               uuid PRIMARY KEY,
    organization_id  uuid NOT NULL REFERENCES organizations (id),
    workspace_id     uuid REFERENCES accounts (id),
    key              text NOT NULL,
    value            text NOT NULL,
    reason           text NOT NULL CHECK (char_length(reason) BETWEEN 1 AND 200 AND reason !~ '[[:cntrl:]]'),
    expires_at       timestamptz,
    operator_id      uuid NOT NULL REFERENCES platform.operators (id),
    created_at       timestamptz NOT NULL,
    CONSTRAINT plan_override_valid CHECK (platform.plan_override_ok(workspace_id IS NOT NULL, key, value)),
    CHECK (expires_at IS NULL OR expires_at >= created_at)
);
CREATE INDEX plan_overrides_by_org ON platform.plan_overrides (organization_id, created_at);
GRANT SELECT ON platform.plan_overrides TO openseal_console;

-- Immutability -----------------------------------------------------------------------

CREATE TRIGGER plan_entitlements_insert_only BEFORE UPDATE OR DELETE ON platform.plan_entitlements
    FOR EACH ROW EXECUTE FUNCTION platform.refuse_change();
CREATE TRIGGER plan_entitlements_no_truncate BEFORE TRUNCATE ON platform.plan_entitlements
    FOR EACH STATEMENT EXECUTE FUNCTION platform.refuse_change();
CREATE TRIGGER plan_quotas_insert_only BEFORE UPDATE OR DELETE ON platform.plan_quotas
    FOR EACH ROW EXECUTE FUNCTION platform.refuse_change();
CREATE TRIGGER plan_quotas_no_truncate BEFORE TRUNCATE ON platform.plan_quotas
    FOR EACH STATEMENT EXECUTE FUNCTION platform.refuse_change();
CREATE TRIGGER plan_seat_rule_insert_only BEFORE UPDATE OR DELETE ON platform.plan_seat_rule
    FOR EACH ROW EXECUTE FUNCTION platform.refuse_change();
CREATE TRIGGER plan_seat_rule_no_truncate BEFORE TRUNCATE ON platform.plan_seat_rule
    FOR EACH STATEMENT EXECUTE FUNCTION platform.refuse_change();

-- A plan version changes only by being archived, once.
CREATE FUNCTION platform.plans_archive_only() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog
AS $$
BEGIN
    IF TG_OP <> 'UPDATE' OR OLD.archived_at IS NOT NULL OR NEW.archived_at IS NULL
       OR (NEW.id, NEW.key, NEW.version, NEW.name, NEW.created_by, NEW.created_at)
          IS DISTINCT FROM (OLD.id, OLD.key, OLD.version, OLD.name, OLD.created_by, OLD.created_at) THEN
        RAISE EXCEPTION 'CS-DB-0004 a plan version is immutable: % refused', TG_OP USING ERRCODE = 'OS001';
    END IF;
    RETURN NEW;
END
$$;
CREATE TRIGGER plans_archive_only BEFORE UPDATE OR DELETE ON platform.plans
    FOR EACH ROW EXECUTE FUNCTION platform.plans_archive_only();
CREATE TRIGGER plans_no_truncate BEFORE TRUNCATE ON platform.plans
    FOR EACH STATEMENT EXECUTE FUNCTION platform.refuse_change();

-- An assignment changes only by ending earlier.
CREATE FUNCTION platform.plan_assignments_shorten_only() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog
AS $$
BEGIN
    IF TG_OP <> 'UPDATE' OR NEW.ends_at IS NULL OR (OLD.ends_at IS NOT NULL AND NEW.ends_at >= OLD.ends_at)
       OR (NEW.id, NEW.organization_id, NEW.plan_id, NEW.starts_at, NEW.assigned_by, NEW.assigned_at)
          IS DISTINCT FROM (OLD.id, OLD.organization_id, OLD.plan_id, OLD.starts_at, OLD.assigned_by, OLD.assigned_at) THEN
        RAISE EXCEPTION 'CS-DB-0004 a plan assignment only ends earlier: % refused', TG_OP USING ERRCODE = 'OS001';
    END IF;
    RETURN NEW;
END
$$;
CREATE TRIGGER plan_assignments_shorten_only BEFORE UPDATE OR DELETE ON platform.plan_assignments
    FOR EACH ROW EXECUTE FUNCTION platform.plan_assignments_shorten_only();
CREATE TRIGGER plan_assignments_no_truncate BEFORE TRUNCATE ON platform.plan_assignments
    FOR EACH STATEMENT EXECUTE FUNCTION platform.refuse_change();

-- An override changes only by expiring earlier.
CREATE FUNCTION platform.plan_overrides_expire_only() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog
AS $$
BEGIN
    IF TG_OP <> 'UPDATE' OR NEW.expires_at IS NULL
       OR (OLD.expires_at IS NOT NULL AND NEW.expires_at >= OLD.expires_at)
       OR (NEW.id, NEW.organization_id, NEW.workspace_id, NEW.key, NEW.value, NEW.reason, NEW.operator_id, NEW.created_at)
          IS DISTINCT FROM (OLD.id, OLD.organization_id, OLD.workspace_id, OLD.key, OLD.value, OLD.reason,
                            OLD.operator_id, OLD.created_at) THEN
        RAISE EXCEPTION 'CS-DB-0004 a plan override only expires earlier: % refused', TG_OP USING ERRCODE = 'OS001';
    END IF;
    RETURN NEW;
END
$$;
CREATE TRIGGER plan_overrides_expire_only BEFORE UPDATE OR DELETE ON platform.plan_overrides
    FOR EACH ROW EXECUTE FUNCTION platform.plan_overrides_expire_only();
CREATE TRIGGER plan_overrides_no_truncate BEFORE TRUNCATE ON platform.plan_overrides
    FOR EACH STATEMENT EXECUTE FUNCTION platform.refuse_change();

-- Writes (operators; each with its operator event, written by the console) -----------

-- A new version of plan `p_key` (1 for a new key). Its version number.
-- `p_entitlements`: {"<feature>": true|false, ...}; `p_quotas`: [{"meter", "limit",
-- "period", "enforcement", "level"}, ...] (at most 64).
CREATE FUNCTION platform.create_plan(p_session bytea, p_id uuid, p_key text, p_name text, p_entitlements jsonb,
                                     p_quotas jsonb, p_seat_rule text, p_now timestamptz)
RETURNS integer
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path = pg_catalog
AS $$
DECLARE
    op uuid := platform.acting_operator(p_session, p_now, ARRAY['platform_owner', 'operator']);
    v integer;
BEGIN
    IF jsonb_typeof(p_entitlements) IS DISTINCT FROM 'object' OR jsonb_typeof(p_quotas) IS DISTINCT FROM 'array'
       OR jsonb_array_length(p_quotas) > 64 THEN
        RAISE EXCEPTION 'CS-PLAN-0006 entitlements or quotas malformed' USING ERRCODE = 'OS010';
    END IF;
    IF EXISTS (SELECT 1 FROM jsonb_array_elements(p_quotas) q
                WHERE platform.plan_meter_approximate(q ->> 'meter') AND q ->> 'enforcement' = 'hard') THEN
        RAISE EXCEPTION 'CS-PLAN-0006 hard enforcement on an approximate meter' USING ERRCODE = 'OS010';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended('openseal-plan:' || COALESCE(p_key, ''), 0));
    SELECT COALESCE(max(version), 0) + 1 INTO v FROM platform.plans WHERE key = p_key;
    BEGIN
        INSERT INTO platform.plans (id, key, version, name, created_by, created_at)
        VALUES (p_id, p_key, v, p_name, op, p_now);
        INSERT INTO platform.plan_entitlements (plan_id, feature, enabled)
        SELECT p_id, e.key, e.value::boolean FROM jsonb_each(p_entitlements) e;
        INSERT INTO platform.plan_quotas (plan_id, meter, "limit", period, enforcement, level)
        SELECT p_id, q ->> 'meter', (q ->> 'limit')::bigint, q ->> 'period', q ->> 'enforcement', q ->> 'level'
          FROM jsonb_array_elements(p_quotas) q;
        INSERT INTO platform.plan_seat_rule (plan_id, rule) VALUES (p_id, p_seat_rule);
    EXCEPTION
        WHEN check_violation OR not_null_violation OR unique_violation OR invalid_parameter_value
             OR invalid_text_representation OR numeric_value_out_of_range OR datatype_mismatch THEN
            RAISE EXCEPTION 'CS-PLAN-0006 plan invalid' USING ERRCODE = 'OS010';
    END;
    RETURN v;
END
$$;
GRANT EXECUTE ON FUNCTION platform.create_plan(bytea, uuid, text, text, jsonb, jsonb, text, timestamptz)
    TO openseal_console;

-- Archive a plan version: no new assignment may name it. False when there is none.
CREATE FUNCTION platform.archive_plan(p_session bytea, p_plan uuid, p_now timestamptz)
RETURNS boolean
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path = pg_catalog
AS $$
BEGIN
    PERFORM platform.acting_operator(p_session, p_now, ARRAY['platform_owner', 'operator']);
    UPDATE platform.plans SET archived_at = p_now WHERE id = p_plan AND archived_at IS NULL;
    RETURN EXISTS (SELECT 1 FROM platform.plans WHERE id = p_plan);
END
$$;
GRANT EXECUTE ON FUNCTION platform.archive_plan(bytea, uuid, timestamptz) TO openseal_console;

-- Assign plan `p_plan` to organization `p_org` from `p_starts` (not before `p_now`) until
-- `p_ends` (NULL: open-ended). The assignment current at `p_starts` ends then. False when
-- the organization or the plan does not exist.
CREATE FUNCTION platform.assign_plan(p_session bytea, p_id uuid, p_org uuid, p_plan uuid, p_starts timestamptz,
                                     p_ends timestamptz, p_now timestamptz)
RETURNS boolean
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
DECLARE
    op uuid := platform.acting_operator(p_session, p_now, ARRAY['platform_owner', 'operator']);
    archived timestamptz;
BEGIN
    -- Serialize changes to one organization's timeline.
    PERFORM pg_advisory_xact_lock(hashtextextended('openseal-plan-org:' || p_org::text, 0));
    IF NOT EXISTS (SELECT 1 FROM organizations WHERE id = p_org) THEN
        RETURN false;
    END IF;
    SELECT p.archived_at INTO archived FROM platform.plans p WHERE p.id = p_plan;
    IF NOT FOUND THEN
        RETURN false;
    END IF;
    IF archived IS NOT NULL THEN
        RAISE EXCEPTION 'CS-PLAN-0006 the plan version is archived' USING ERRCODE = 'OS010';
    END IF;
    IF p_starts IS NULL OR p_starts < p_now OR (p_ends IS NOT NULL AND p_ends <= p_starts) THEN
        RAISE EXCEPTION 'CS-PLAN-0006 assignment interval invalid' USING ERRCODE = 'OS010';
    END IF;
    IF EXISTS (SELECT 1 FROM platform.plan_assignments a WHERE a.organization_id = p_org AND a.starts_at >= p_starts) THEN
        RAISE EXCEPTION 'CS-PLAN-0006 an assignment already starts at or after this one' USING ERRCODE = 'OS010';
    END IF;
    UPDATE platform.plan_assignments a SET ends_at = p_starts
     WHERE a.organization_id = p_org AND a.starts_at < p_starts AND (a.ends_at IS NULL OR a.ends_at > p_starts);
    INSERT INTO platform.plan_assignments (id, organization_id, plan_id, starts_at, ends_at, assigned_by, assigned_at)
    VALUES (p_id, p_org, p_plan, p_starts, p_ends, op, p_now);
    RETURN true;
END
$$;
GRANT EXECUTE ON FUNCTION platform.assign_plan(bytea, uuid, uuid, uuid, timestamptz, timestamptz, timestamptz)
    TO openseal_console;

-- Set an override for organization `p_org` (or its workspace `p_workspace`) until
-- `p_expires` (NULL: none; else later than `p_now`). False when the organization does not
-- exist or the workspace is not one of its own.
CREATE FUNCTION platform.set_plan_override(p_session bytea, p_id uuid, p_org uuid, p_workspace uuid, p_key text,
                                           p_value text, p_reason text, p_expires timestamptz, p_now timestamptz)
RETURNS boolean
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
DECLARE
    op uuid := platform.acting_operator(p_session, p_now, ARRAY['platform_owner', 'operator']);
BEGIN
    IF NOT EXISTS (SELECT 1 FROM organizations WHERE id = p_org) THEN
        RETURN false;
    END IF;
    IF p_workspace IS NOT NULL
       AND NOT EXISTS (SELECT 1 FROM accounts a WHERE a.id = p_workspace AND a.organization_id = p_org) THEN
        RETURN false;
    END IF;
    IF p_expires IS NOT NULL AND p_expires <= p_now THEN
        RAISE EXCEPTION 'CS-PLAN-0006 override already expired' USING ERRCODE = 'OS010';
    END IF;
    IF NOT platform.plan_override_ok(p_workspace IS NOT NULL, p_key, p_value) THEN
        RAISE EXCEPTION 'CS-PLAN-0006 override key, value or scope invalid' USING ERRCODE = 'OS010';
    END IF;
    BEGIN
        INSERT INTO platform.plan_overrides (id, organization_id, workspace_id, key, value, reason, expires_at,
                                             operator_id, created_at)
        VALUES (p_id, p_org, p_workspace, p_key, p_value, p_reason, p_expires, op, p_now);
    EXCEPTION
        WHEN check_violation OR not_null_violation THEN
            RAISE EXCEPTION 'CS-PLAN-0006 override invalid' USING ERRCODE = 'OS010';
    END;
    RETURN true;
END
$$;
GRANT EXECUTE ON FUNCTION platform.set_plan_override(bytea, uuid, uuid, uuid, text, text, text, timestamptz, timestamptz)
    TO openseal_console;

-- Expire an override now (if it is still live). False when there is none.
CREATE FUNCTION platform.expire_plan_override(p_session bytea, p_id uuid, p_now timestamptz)
RETURNS boolean
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path = pg_catalog
AS $$
BEGIN
    PERFORM platform.acting_operator(p_session, p_now, ARRAY['platform_owner', 'operator']);
    UPDATE platform.plan_overrides SET expires_at = greatest(p_now, created_at)
     WHERE id = p_id AND (expires_at IS NULL OR expires_at > p_now);
    RETURN EXISTS (SELECT 1 FROM platform.plan_overrides WHERE id = p_id);
END
$$;
GRANT EXECUTE ON FUNCTION platform.expire_plan_override(bytea, uuid, timestamptz) TO openseal_console;

-- Reads ------------------------------------------------------------------------------

CREATE FUNCTION platform.epoch_us(t timestamptz) RETURNS bigint
    LANGUAGE sql STABLE
    SET search_path = pg_catalog
AS $$
    SELECT (extract(epoch FROM t) * 1000000)::bigint
$$;

-- One plan version as JSON (`casual-sign-policy`'s wire shape). Internal.
CREATE FUNCTION platform.plan_json(p_plan uuid) RETURNS jsonb
    LANGUAGE sql STABLE
    SET search_path = pg_catalog
AS $$
    SELECT jsonb_build_object(
        'id', p.id, 'key', p.key, 'version', p.version, 'name', p.name,
        'archived', p.archived_at IS NOT NULL,
        'seat_rule', COALESCE((SELECT s.rule FROM platform.plan_seat_rule s WHERE s.plan_id = p.id), 'can_send'),
        'entitlements', COALESCE((SELECT jsonb_object_agg(e.feature, e.enabled)
                                    FROM platform.plan_entitlements e WHERE e.plan_id = p.id), '{}'::jsonb),
        'quotas', COALESCE((SELECT jsonb_agg(jsonb_build_object('meter', q.meter, 'limit', q."limit", 'period', q.period,
                                                                'enforcement', q.enforcement, 'level', q.level)
                                             ORDER BY q.meter, q.level)
                              FROM platform.plan_quotas q WHERE q.plan_id = p.id), '[]'::jsonb))
      FROM platform.plans p WHERE p.id = p_plan
$$;

-- An organization's assignments and overrides as JSON. `p_current`: only the assignment
-- current at `p_now` and the overrides live at `p_now` for the organization and workspace
-- `p_workspace`, without reasons or operator ids (the application's read); otherwise every
-- row, with them (the console's).
CREATE FUNCTION platform.plan_inputs(p_org uuid, p_workspace uuid, p_now timestamptz, p_current boolean)
RETURNS jsonb
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path = pg_catalog
AS $$
    SELECT jsonb_build_object(
        'organization', p_org,
        'workspace', p_workspace,
        'assignments', COALESCE((
            SELECT jsonb_agg(jsonb_build_object(
                       'id', a.id, 'plan', platform.plan_json(a.plan_id),
                       'starts_at', platform.epoch_us(a.starts_at),
                       'ends_at', platform.epoch_us(a.ends_at),
                       'assigned_by', CASE WHEN p_current THEN NULL ELSE a.assigned_by END,
                       'assigned_at', CASE WHEN p_current THEN NULL ELSE platform.epoch_us(a.assigned_at) END)
                   ORDER BY a.starts_at, a.id)
              FROM platform.plan_assignments a
             WHERE a.organization_id = p_org
               AND (NOT p_current OR (a.starts_at <= p_now AND (a.ends_at IS NULL OR p_now < a.ends_at)))),
            '[]'::jsonb),
        'overrides', COALESCE((
            SELECT jsonb_agg(jsonb_build_object(
                       'id', o.id, 'workspace', o.workspace_id, 'key', o.key, 'value', o.value,
                       'expires_at', platform.epoch_us(o.expires_at),
                       'created_at', platform.epoch_us(o.created_at),
                       'reason', CASE WHEN p_current THEN NULL ELSE o.reason END,
                       'operator', CASE WHEN p_current THEN NULL ELSE o.operator_id END)
                   ORDER BY o.created_at, o.id)
              FROM platform.plan_overrides o
             WHERE o.organization_id = p_org
               AND (NOT p_current OR ((o.workspace_id IS NULL OR o.workspace_id = p_workspace)
                                      AND (o.expires_at IS NULL OR p_now < o.expires_at)))),
            '[]'::jsonb))
$$;
GRANT EXECUTE ON FUNCTION platform.plan_inputs(uuid, uuid, timestamptz, boolean) TO openseal_console;

-- Every plan version, newest key first, with when it was archived and how many
-- organizations it is current for at `p_now`.
CREATE FUNCTION platform.plans_page(p_now timestamptz)
RETURNS TABLE (plan jsonb, created_at timestamptz, archived_at timestamptz, organizations bigint)
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path = pg_catalog
AS $$
    SELECT platform.plan_json(p.id), p.created_at, p.archived_at,
           (SELECT count(*) FROM platform.plan_assignments a
             WHERE a.plan_id = p.id AND a.starts_at <= p_now AND (a.ends_at IS NULL OR p_now < a.ends_at))
      FROM platform.plans p
     ORDER BY p.key, p.version DESC
$$;
GRANT EXECUTE ON FUNCTION platform.plans_page(timestamptz) TO openseal_console;

REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA platform FROM PUBLIC;
-- The internal helpers above run inside the granted functions as their owner; the
-- console's own direct reads need none of them.

-- The application's read: the effective-plan inputs for the transaction's organization,
-- derived from the current account (its workspace's overrides included) or, in
-- organization scope, from the current organization. NULL when neither is set.
CREATE FUNCTION openseal_effective_plan(p_now timestamptz) RETURNS jsonb
    LANGUAGE plpgsql STABLE SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
DECLARE
    acct uuid := openseal_current_account();
    org uuid;
BEGIN
    IF acct IS NOT NULL THEN
        SELECT a.organization_id INTO org FROM accounts a WHERE a.id = acct;
    ELSE
        org := openseal_current_org();
    END IF;
    IF org IS NULL THEN
        RETURN NULL;
    END IF;
    RETURN platform.plan_inputs(org, acct, p_now, true);
END
$$;
REVOKE ALL ON FUNCTION openseal_effective_plan(timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openseal_effective_plan(timestamptz) TO openseal_app;
