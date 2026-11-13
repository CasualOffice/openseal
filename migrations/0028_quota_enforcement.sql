-- 0028: quota enforcement (PLAN-04; ADR-028, docs/23 §7.3).
--
-- 1. `openseal_meter_apply` is redefined to move the organization's counter before the
--    workspace's: every writer now locks the organization row first, so a quota check
--    (which holds it) and a metering trigger in another transaction never wait on each
--    other in opposite orders.
-- 2. `quota_notices` (organization table, append-only, ids and counts only): what a `soft`
--    or `notify` quota records when usage passes its limit. `soft` records every action
--    over the limit with the part of it that is overage; `notify` records only the action
--    that crossed the limit, once per period and level. Organization admins read them;
--    delivering them by e-mail is `PLAN-16`.
-- 3. `openseal_consume_quota` (counter meters): the ledger row and, for `hard` quotas,
--    conditional updates `value + n <= limit` of the organization counter and then the
--    workspace counter, in one subtransaction. Zero rows on either refuses and rolls back
--    the ledger row and both counters. The organization row is the serialization point,
--    so parallel actions in two workspaces cannot overshoot an organization quota
--    (`SEC-U01`). A source already counted (a correction or retry of a sent envelope)
--    answers `replayed` before any check: nothing in a sent envelope's life is refused
--    (`SEC-U02`). A suspended organization refuses new counted work (`CS-PLAN-0005`).
-- 4. `openseal_quota_gauge_lock` and `openseal_quota_gauge_check` (gauges `seats`,
--    `storage_bytes`): lock the organization's then the workspace's counter row and read
--    them; after the change (whose trigger recounts under the same locks), refuse when a
--    `hard` limit is passed by an increase. A change that lowers or keeps the gauge is
--    never refused, even over the limit.
--
-- Limits come from `casual-sign-policy::plans::effective`, computed by the caller in the
-- same transaction and passed as JSON
-- `{"workspace": {"limit": n, "enforcement": "hard", "period": "month"}, "organization": …}`;
-- a level absent or null has no quota. Counters are monthly; a `year` quota counts the
-- earlier months of the calendar year, a `none` quota every earlier period.

-- 1. Organization row first ------------------------------------------------------------------

CREATE OR REPLACE FUNCTION openseal_meter_apply(
    p_account uuid, p_meter text, p_quantity bigint, p_org_quantity bigint, p_at timestamptz,
    p_source_kind text, p_source_id text) RETURNS boolean
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
DECLARE
    org uuid;
    period timestamptz := openseal_meter_period(p_meter, p_at);
BEGIN
    IF p_quantity = 0 AND p_org_quantity = 0 THEN
        RETURN false;
    END IF;
    SELECT a.organization_id INTO org FROM accounts a WHERE a.id = p_account;
    IF org IS NULL THEN
        RAISE EXCEPTION 'no such workspace' USING ERRCODE = '22023';
    END IF;
    INSERT INTO usage_ledger (account_id, meter, quantity, org_quantity, period_start, at,
                              source_kind, source_id)
    VALUES (p_account, p_meter, p_quantity, p_org_quantity, period, p_at, p_source_kind, p_source_id)
    ON CONFLICT DO NOTHING;
    IF NOT FOUND THEN
        RETURN false;
    END IF;
    -- Organization first (lock order, PLAN-04); update first: a CHECK is evaluated on the
    -- proposed row of an INSERT before ON CONFLICT, so a negative change is never offered
    -- as a new row's value.
    IF p_org_quantity <> 0 THEN
        UPDATE org_usage_counters c SET value = c.value + p_org_quantity
         WHERE c.organization_id = org AND c.meter = p_meter AND c.period_start = period;
        IF NOT FOUND THEN
            INSERT INTO org_usage_counters AS c (organization_id, meter, period_start, value)
            VALUES (org, p_meter, period, p_org_quantity)
            ON CONFLICT (organization_id, meter, period_start) DO UPDATE SET value = c.value + EXCLUDED.value;
        END IF;
    END IF;
    IF p_quantity <> 0 THEN
        UPDATE usage_counters c SET value = c.value + p_quantity
         WHERE c.account_id = p_account AND c.meter = p_meter AND c.period_start = period;
        IF NOT FOUND THEN
            INSERT INTO usage_counters AS c (account_id, meter, period_start, value)
            VALUES (p_account, p_meter, period, p_quantity)
            ON CONFLICT (account_id, meter, period_start) DO UPDATE SET value = c.value + EXCLUDED.value;
        END IF;
    END IF;
    RETURN true;
END
$$;

-- 2. Notices -----------------------------------------------------------------------------------

CREATE TABLE quota_notices (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id  uuid NOT NULL REFERENCES organizations (id),
    -- The workspace whose action it was. Named `workspace_id`, not `account_id`: this is
    -- an organization table, outside the tenant-table catalog rules (as `plan_overrides`).
    workspace_id     uuid NOT NULL REFERENCES accounts (id),
    meter            text NOT NULL,
    level            text NOT NULL CHECK (level IN ('organization', 'workspace')),
    enforcement      text NOT NULL CHECK (enforcement IN ('soft', 'notify')),
    period_start     timestamptz NOT NULL,
    quota_limit      bigint NOT NULL CHECK (quota_limit >= 0),
    used             bigint NOT NULL CHECK (used > quota_limit),
    overage          bigint NOT NULL CHECK (overage >= 0),
    source_kind      text NOT NULL,
    source_id        text NOT NULL,
    at               timestamptz NOT NULL,
    UNIQUE (organization_id, meter, level, workspace_id, source_kind, source_id)
);
SELECT openseal_org_table('quota_notices', false);
REVOKE INSERT ON quota_notices FROM openseal_app;
CREATE TRIGGER quota_notices_no_update_delete
    BEFORE UPDATE OR DELETE ON quota_notices
    FOR EACH ROW EXECUTE FUNCTION openseal_usage_refuse_change();
CREATE TRIGGER quota_notices_no_truncate
    BEFORE TRUNCATE ON quota_notices
    FOR EACH STATEMENT EXECUTE FUNCTION openseal_usage_refuse_change();

-- 3. Shared pieces -------------------------------------------------------------------------------

-- Whether `q` (one level of the caller's JSON) is well formed: null, or a limit ≥ 0 with an
-- enforcement and a period.
CREATE FUNCTION openseal_quota_valid(q jsonb) RETURNS boolean
    LANGUAGE sql IMMUTABLE
    SET search_path = pg_catalog
AS $$
    SELECT q IS NULL OR jsonb_typeof(q) = 'null' OR (
        jsonb_typeof(q) = 'object'
        AND jsonb_typeof(q -> 'limit') = 'number' AND (q ->> 'limit')::numeric >= 0
        AND (q ->> 'limit')::numeric <= 9223372036854775807
        AND q ->> 'enforcement' IN ('hard', 'soft', 'notify')
        AND q ->> 'period' IN ('month', 'year', 'none'))
$$;
REVOKE ALL ON FUNCTION openseal_quota_valid(jsonb) FROM PUBLIC;

-- Where a quota's window starts, for the counter period `p_period` (a month).
CREATE FUNCTION openseal_quota_window(q jsonb, p_period timestamptz) RETURNS timestamptz
    LANGUAGE sql IMMUTABLE
    SET search_path = pg_catalog
AS $$
    SELECT CASE q ->> 'period'
               WHEN 'year' THEN date_trunc('year', p_period, 'UTC')
               WHEN 'none' THEN timestamptz '-infinity'
               ELSE p_period END
$$;
REVOKE ALL ON FUNCTION openseal_quota_window(jsonb, timestamptz) FROM PUBLIC;

-- When a quota's window ends (null for `none` and for gauges).
CREATE FUNCTION openseal_quota_window_end(q jsonb, p_period timestamptz) RETURNS timestamptz
    LANGUAGE sql IMMUTABLE
    SET search_path = pg_catalog
AS $$
    SELECT CASE q ->> 'period'
               WHEN 'year' THEN (date_trunc('year', p_period, 'UTC') AT TIME ZONE 'UTC' + interval '1 year') AT TIME ZONE 'UTC'
               WHEN 'month' THEN (p_period AT TIME ZONE 'UTC' + interval '1 month') AT TIME ZONE 'UTC'
               ELSE NULL END
$$;
REVOKE ALL ON FUNCTION openseal_quota_window_end(jsonb, timestamptz) FROM PUBLIC;

-- Record a soft or notify quota passed: `used` after an action of `n`. Soft: every action
-- over the limit, with its overage. Notify: only the action that crossed the limit.
CREATE FUNCTION openseal_quota_notice(
    p_org uuid, p_account uuid, p_meter text, p_level text, q jsonb, p_period timestamptz,
    p_used bigint, p_n bigint, p_at timestamptz, p_source_kind text, p_source_id text)
RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
DECLARE
    lim bigint;
BEGIN
    IF q IS NULL OR jsonb_typeof(q) <> 'object' OR q ->> 'enforcement' NOT IN ('soft', 'notify') THEN
        RETURN;
    END IF;
    lim := (q ->> 'limit')::bigint;
    IF p_used <= lim OR p_n <= 0 THEN
        RETURN;
    END IF;
    IF q ->> 'enforcement' = 'notify' AND p_used - p_n > lim THEN
        RETURN;
    END IF;
    INSERT INTO quota_notices (organization_id, workspace_id, meter, level, enforcement, period_start,
                               quota_limit, used, overage, source_kind, source_id, at)
    VALUES (p_org, p_account, p_meter, p_level, q ->> 'enforcement', p_period, lim, p_used,
            CASE WHEN q ->> 'enforcement' = 'soft' THEN least(p_n, p_used - lim) ELSE 0 END,
            p_source_kind, p_source_id, p_at)
    ON CONFLICT DO NOTHING;
END
$$;
REVOKE ALL ON FUNCTION openseal_quota_notice(uuid, uuid, text, text, jsonb, timestamptz, bigint, bigint, timestamptz, text, text) FROM PUBLIC;

-- The transaction's workspace and its organization, refusing outside a workspace scope.
CREATE FUNCTION openseal_quota_scope(OUT acct uuid, OUT org uuid, OUT org_status text)
    LANGUAGE plpgsql STABLE SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
BEGIN
    acct := openseal_current_account();
    IF acct IS NULL THEN
        RAISE EXCEPTION 'quota checks need a workspace scope' USING ERRCODE = '42501';
    END IF;
    SELECT a.organization_id, o.status INTO org, org_status
      FROM accounts a JOIN organizations o ON o.id = a.organization_id WHERE a.id = acct;
    IF org IS NULL THEN
        RAISE EXCEPTION 'no such workspace' USING ERRCODE = '22023';
    END IF;
END
$$;
REVOKE ALL ON FUNCTION openseal_quota_scope() FROM PUBLIC;

-- 4. Counter meters -------------------------------------------------------------------------------

-- Count `p_n` of counter meter `p_meter` for the transaction's workspace, once per
-- `(source_kind, source_id)`, within the quotas `p_quota` (see the header). Answers
-- `{"result": "counted", "used": {"workspace": n, "organization": n}}`, `{"result":
-- "replayed"}` for a source already counted, `{"result": "suspended"}`, or `{"result":
-- "refused", "level": …, "limit": n, "used": n, "period_end": t}`; a refusal leaves no ledger
-- row and no counter change.
CREATE FUNCTION openseal_consume_quota(
    p_meter text, p_n bigint, p_at timestamptz, p_source_kind text, p_source_id text, p_quota jsonb)
RETURNS jsonb
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
DECLARE
    s record;
    period timestamptz;
    qw jsonb := p_quota -> 'workspace';
    qo jsonb := p_quota -> 'organization';
    ws_prior bigint := 0;
    org_prior bigint := 0;
    ws_used bigint;
    org_used bigint;
    refused text;
BEGIN
    SELECT * INTO s FROM openseal_quota_scope();
    IF p_meter IS NULL OR p_meter IN ('seats', 'storage_bytes', 'workspaces', 'templates')
       OR p_n IS NULL OR p_n <= 0 OR NOT openseal_quota_valid(qw) OR NOT openseal_quota_valid(qo) THEN
        RAISE EXCEPTION 'not a counter meter, quantity or quota' USING ERRCODE = '23514';
    END IF;
    IF jsonb_typeof(qw) = 'null' THEN qw := NULL; END IF;
    IF jsonb_typeof(qo) = 'null' THEN qo := NULL; END IF;
    period := openseal_meter_period(p_meter, p_at);
    BEGIN
        INSERT INTO usage_ledger (account_id, meter, quantity, org_quantity, period_start, at,
                                  source_kind, source_id)
        VALUES (s.acct, p_meter, p_n, p_n, period, p_at, p_source_kind, p_source_id)
        ON CONFLICT DO NOTHING;
        IF NOT FOUND THEN
            RETURN jsonb_build_object('result', 'replayed');
        END IF;
        IF s.org_status = 'suspended' THEN
            refused := 'suspended';
            RAISE EXCEPTION 'suspended' USING ERRCODE = 'OS011';
        END IF;
        INSERT INTO org_usage_counters (organization_id, meter, period_start, value)
        VALUES (s.org, p_meter, period, 0) ON CONFLICT DO NOTHING;
        INSERT INTO usage_counters (account_id, meter, period_start, value)
        VALUES (s.acct, p_meter, period, 0) ON CONFLICT DO NOTHING;
        -- Earlier months of a year or standing window: closed, so read without a lock.
        IF qo IS NOT NULL AND qo ->> 'period' <> 'month' THEN
            SELECT COALESCE(sum(c.value), 0) INTO org_prior FROM org_usage_counters c
             WHERE c.organization_id = s.org AND c.meter = p_meter
               AND c.period_start >= openseal_quota_window(qo, period) AND c.period_start < period;
        END IF;
        IF qw IS NOT NULL AND qw ->> 'period' <> 'month' THEN
            SELECT COALESCE(sum(c.value), 0) INTO ws_prior FROM usage_counters c
             WHERE c.account_id = s.acct AND c.meter = p_meter
               AND c.period_start >= openseal_quota_window(qw, period) AND c.period_start < period;
        END IF;
        -- The organization row is the serialization point: a parallel action in another
        -- workspace waits here, then re-checks the condition on the committed value.
        UPDATE org_usage_counters c SET value = c.value + p_n
         WHERE c.organization_id = s.org AND c.meter = p_meter AND c.period_start = period
           AND (qo IS NULL OR qo ->> 'enforcement' <> 'hard'
                OR org_prior + c.value + p_n <= (qo ->> 'limit')::bigint)
        RETURNING org_prior + c.value INTO org_used;
        IF NOT FOUND THEN
            refused := 'organization';
            RAISE EXCEPTION 'over quota' USING ERRCODE = 'OS011';
        END IF;
        UPDATE usage_counters c SET value = c.value + p_n
         WHERE c.account_id = s.acct AND c.meter = p_meter AND c.period_start = period
           AND (qw IS NULL OR qw ->> 'enforcement' <> 'hard'
                OR ws_prior + c.value + p_n <= (qw ->> 'limit')::bigint)
        RETURNING ws_prior + c.value INTO ws_used;
        IF NOT FOUND THEN
            refused := 'workspace';
            RAISE EXCEPTION 'over quota' USING ERRCODE = 'OS011';
        END IF;
    EXCEPTION WHEN SQLSTATE 'OS011' THEN
        -- Everything in the block is rolled back: the ledger row and both counters.
        IF refused = 'suspended' THEN
            RETURN jsonb_build_object('result', 'suspended');
        ELSIF refused = 'organization' THEN
            SELECT org_prior + COALESCE(sum(c.value), 0) INTO org_used FROM org_usage_counters c
             WHERE c.organization_id = s.org AND c.meter = p_meter AND c.period_start = period;
            RETURN jsonb_build_object('result', 'refused', 'level', 'organization',
                'limit', (qo ->> 'limit')::bigint, 'used', org_used,
                'period_end', openseal_quota_window_end(qo, period));
        END IF;
        SELECT ws_prior + COALESCE(sum(c.value), 0) INTO ws_used FROM usage_counters c
         WHERE c.account_id = s.acct AND c.meter = p_meter AND c.period_start = period;
        RETURN jsonb_build_object('result', 'refused', 'level', 'workspace',
            'limit', (qw ->> 'limit')::bigint, 'used', ws_used,
            'period_end', openseal_quota_window_end(qw, period));
    END;
    PERFORM openseal_quota_notice(s.org, s.acct, p_meter, 'organization', qo, period, org_used, p_n,
                                  p_at, p_source_kind, p_source_id);
    PERFORM openseal_quota_notice(s.org, s.acct, p_meter, 'workspace', qw, period, ws_used, p_n,
                                  p_at, p_source_kind, p_source_id);
    RETURN jsonb_build_object('result', 'counted',
        'used', jsonb_build_object('workspace', ws_used, 'organization', org_used));
END
$$;
REVOKE ALL ON FUNCTION openseal_consume_quota(text, bigint, timestamptz, text, text, jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openseal_consume_quota(text, bigint, timestamptz, text, text, jsonb) TO openseal_app;

-- 5. Gauges -------------------------------------------------------------------------------------

-- Lock the organization's, then the workspace's, counter row of gauge `p_meter` until the
-- transaction ends and read them: `{"workspace": n, "organization": n, "suspended": bool}`.
-- A seat or storage change made after this, in this transaction, is recounted under the
-- same locks, so a parallel change waits for this transaction's commit.
CREATE FUNCTION openseal_quota_gauge_lock(p_meter text) RETURNS jsonb
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
DECLARE
    s record;
    epoch timestamptz;
    ws_v bigint;
    org_v bigint;
BEGIN
    SELECT * INTO s FROM openseal_quota_scope();
    IF p_meter IS NULL OR p_meter NOT IN ('seats', 'storage_bytes') THEN
        RAISE EXCEPTION 'not an enforced gauge' USING ERRCODE = '23514';
    END IF;
    epoch := openseal_meter_period(p_meter, now());
    INSERT INTO org_usage_counters (organization_id, meter, period_start, value)
    VALUES (s.org, p_meter, epoch, 0) ON CONFLICT DO NOTHING;
    INSERT INTO usage_counters (account_id, meter, period_start, value)
    VALUES (s.acct, p_meter, epoch, 0) ON CONFLICT DO NOTHING;
    SELECT c.value INTO org_v FROM org_usage_counters c
     WHERE c.organization_id = s.org AND c.meter = p_meter AND c.period_start = epoch FOR UPDATE;
    SELECT c.value INTO ws_v FROM usage_counters c
     WHERE c.account_id = s.acct AND c.meter = p_meter AND c.period_start = epoch FOR UPDATE;
    RETURN jsonb_build_object('workspace', ws_v, 'organization', org_v,
                              'suspended', s.org_status = 'suspended');
END
$$;
REVOKE ALL ON FUNCTION openseal_quota_gauge_lock(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openseal_quota_gauge_lock(text) TO openseal_app;

-- After a change locked by `openseal_quota_gauge_lock`: refuse when it raised the gauge past
-- a `hard` limit (`{"result": "refused", "level", "limit", "used"}`; the caller rolls back),
-- else record soft or notify notices and answer `{"result": "counted", "used": …}`.
CREATE FUNCTION openseal_quota_gauge_check(
    p_meter text, p_ws_before bigint, p_org_before bigint, p_at timestamptz,
    p_source_kind text, p_source_id text, p_quota jsonb)
RETURNS jsonb
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
DECLARE
    s record;
    epoch timestamptz;
    qw jsonb := p_quota -> 'workspace';
    qo jsonb := p_quota -> 'organization';
    ws_v bigint;
    org_v bigint;
BEGIN
    SELECT * INTO s FROM openseal_quota_scope();
    IF p_meter IS NULL OR p_meter NOT IN ('seats', 'storage_bytes')
       OR NOT openseal_quota_valid(qw) OR NOT openseal_quota_valid(qo) THEN
        RAISE EXCEPTION 'not an enforced gauge or quota' USING ERRCODE = '23514';
    END IF;
    IF jsonb_typeof(qw) = 'null' THEN qw := NULL; END IF;
    IF jsonb_typeof(qo) = 'null' THEN qo := NULL; END IF;
    epoch := openseal_meter_period(p_meter, p_at);
    SELECT COALESCE(sum(c.value), 0) INTO org_v FROM org_usage_counters c
     WHERE c.organization_id = s.org AND c.meter = p_meter AND c.period_start = epoch;
    SELECT COALESCE(sum(c.value), 0) INTO ws_v FROM usage_counters c
     WHERE c.account_id = s.acct AND c.meter = p_meter AND c.period_start = epoch;
    IF qo IS NOT NULL AND qo ->> 'enforcement' = 'hard' AND org_v > p_org_before
       AND org_v > (qo ->> 'limit')::bigint THEN
        RETURN jsonb_build_object('result', 'refused', 'level', 'organization',
            'limit', (qo ->> 'limit')::bigint, 'used', p_org_before);
    END IF;
    IF qw IS NOT NULL AND qw ->> 'enforcement' = 'hard' AND ws_v > p_ws_before
       AND ws_v > (qw ->> 'limit')::bigint THEN
        RETURN jsonb_build_object('result', 'refused', 'level', 'workspace',
            'limit', (qw ->> 'limit')::bigint, 'used', p_ws_before);
    END IF;
    PERFORM openseal_quota_notice(s.org, s.acct, p_meter, 'organization', qo, epoch, org_v,
                                  org_v - p_org_before, p_at, p_source_kind, p_source_id);
    PERFORM openseal_quota_notice(s.org, s.acct, p_meter, 'workspace', qw, epoch, ws_v,
                                  ws_v - p_ws_before, p_at, p_source_kind, p_source_id);
    RETURN jsonb_build_object('result', 'counted',
        'used', jsonb_build_object('workspace', ws_v, 'organization', org_v));
END
$$;
REVOKE ALL ON FUNCTION openseal_quota_gauge_check(text, bigint, bigint, timestamptz, text, text, jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openseal_quota_gauge_check(text, bigint, bigint, timestamptz, text, text, jsonb) TO openseal_app;
