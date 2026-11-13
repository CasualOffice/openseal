-- 0025: usage metering (PLAN-03; ADR-028, docs/23 §7.2).
--
-- 1. `usage_ledger` (tenant table, append-only): one row per counted change, keyed
--    `(account_id, meter, source_kind, source_id)`, so a retried job or a decision
--    recorded again counts once. `quantity` moves the workspace's counter and
--    `org_quantity` the organization's. They are equal for every meter but `seats`, whose
--    organization value is distinct identities across workspaces (one person in two
--    workspaces is two workspace seats and one organization seat). Ids and counts only.
-- 2. `usage_counters` (per workspace, tenant table) and `org_usage_counters` (per
--    organization, organization table): `(meter, period_start) → value`, written only in
--    the transaction that writes the ledger row, by `openseal_meter_apply`. So each counter
--    equals the sum of its ledger column for that meter and period at both levels.
--    Counters are by calendar month (UTC); gauges (`seats`, `storage_bytes`,
--    `workspaces`) have one period starting at the Unix epoch.
-- 3. Who writes. The application role has SELECT only on all three tables. It counts
--    `envelopes_sent` (and later counter meters) through `openseal_meter_record`, which
--    refuses gauges. Gauges are kept by triggers in the transaction of the change itself:
--      storage_bytes  `document_versions` and `template_documents` insert and delete, one
--                     count per content-addressed blob per workspace (`usage_blob_refs`);
--      seats          membership insert, delete, enable or disable, re-profile; profile
--                     permission change; user disable; workspace archive or restore; plan
--                     assignment or override written (the seat rule may change), each a
--                     recount under a lock on the organization's `seats` counter row;
--      workspaces     workspace created, archived, restored.
-- 4. Existing data is counted once, below, so counters start equal to what exists.
--
-- Not counted yet: signer captures in `storage_bytes` (no byte length is stored;
-- PLAN-12); a seat rule that changes only by time passing (an assignment starting, an
-- override expiring) is recounted at the next seat change (PLAN-13).

-- 1. Periods ------------------------------------------------------------------------------

CREATE FUNCTION openseal_meter_period(p_meter text, p_at timestamptz) RETURNS timestamptz
    LANGUAGE sql STABLE
    SET search_path = pg_catalog
AS $$
    SELECT CASE WHEN p_meter IN ('seats', 'storage_bytes', 'workspaces', 'templates')
                THEN timestamptz '1970-01-01 00:00:00+00'
                ELSE date_trunc('month', p_at, 'UTC') END
$$;
REVOKE ALL ON FUNCTION openseal_meter_period(text, timestamptz) FROM PUBLIC;

-- 2. Tables -------------------------------------------------------------------------------

CREATE TABLE usage_ledger (
    account_id    uuid NOT NULL REFERENCES accounts (id),
    meter         text NOT NULL CHECK (meter IN (
                      'envelopes_sent', 'seats', 'storage_bytes', 'api_calls', 'sms_sent', 'phone_calls',
                      'idv_checks', 'kba_checks', 'timestamps', 'seals', 'bulk_send_rows',
                      'signing_link_submissions', 'webhook_deliveries', 'workspaces', 'templates')),
    quantity      bigint NOT NULL,
    org_quantity  bigint NOT NULL,
    period_start  timestamptz NOT NULL,
    at            timestamptz NOT NULL,
    source_kind   text NOT NULL CHECK (source_kind ~ '^[a-z][a-z0-9_.]{0,63}$'),
    source_id     text NOT NULL CHECK (source_id ~ '^[0-9A-Za-z._:-]{1,128}$'),
    recorded_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, meter, source_kind, source_id),
    CHECK (quantity <> 0 OR org_quantity <> 0)
);
CREATE INDEX usage_ledger_period ON usage_ledger (account_id, meter, period_start);
SELECT openseal_tenant_table('usage_ledger', false);
REVOKE INSERT ON usage_ledger FROM openseal_app;

CREATE FUNCTION openseal_usage_refuse_change() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog
AS $$
BEGIN
    RAISE EXCEPTION 'CS-DB-0004 the usage ledger is append-only: % refused on %', TG_OP, TG_TABLE_NAME
        USING ERRCODE = 'OS001';
END
$$;
CREATE TRIGGER usage_ledger_no_update_delete
    BEFORE UPDATE OR DELETE ON usage_ledger
    FOR EACH ROW EXECUTE FUNCTION openseal_usage_refuse_change();
CREATE TRIGGER usage_ledger_no_truncate
    BEFORE TRUNCATE ON usage_ledger
    FOR EACH STATEMENT EXECUTE FUNCTION openseal_usage_refuse_change();

CREATE TABLE usage_counters (
    account_id    uuid NOT NULL REFERENCES accounts (id),
    meter         text NOT NULL,
    period_start  timestamptz NOT NULL,
    value         bigint NOT NULL CHECK (value >= 0),
    PRIMARY KEY (account_id, meter, period_start)
);
SELECT openseal_tenant_table('usage_counters', false);
REVOKE INSERT ON usage_counters FROM openseal_app;

CREATE TABLE org_usage_counters (
    organization_id  uuid NOT NULL REFERENCES organizations (id),
    meter            text NOT NULL,
    period_start     timestamptz NOT NULL,
    value            bigint NOT NULL CHECK (value >= 0),
    PRIMARY KEY (organization_id, meter, period_start)
);
SELECT openseal_org_table('org_usage_counters', false);
REVOKE INSERT ON org_usage_counters FROM openseal_app;

-- How many rows of a workspace name each content-addressed blob, and its size, so a blob
-- is counted once per workspace however many versions or templates name it. No grant.
CREATE TABLE usage_blob_refs (
    account_id  uuid NOT NULL REFERENCES accounts (id),
    sha256      bytea NOT NULL CHECK (octet_length(sha256) = 32),
    byte_len    bigint NOT NULL CHECK (byte_len > 0),
    refs        bigint NOT NULL CHECK (refs > 0),
    PRIMARY KEY (account_id, sha256)
);
SELECT openseal_tenant_table('usage_blob_refs', false);
REVOKE ALL ON usage_blob_refs FROM openseal_app;

-- 3. The one writer -----------------------------------------------------------------------

-- Append one ledger row and move both counters by it, or do nothing when that
-- `(account, meter, source_kind, source_id)` is already counted. True when counted.
-- Runs as the owner; not granted.
CREATE FUNCTION openseal_meter_apply(
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
    IF p_quantity <> 0 THEN
        INSERT INTO usage_counters AS c (account_id, meter, period_start, value)
        VALUES (p_account, p_meter, period, p_quantity)
        ON CONFLICT (account_id, meter, period_start) DO UPDATE SET value = c.value + EXCLUDED.value;
    END IF;
    IF p_org_quantity <> 0 THEN
        INSERT INTO org_usage_counters AS c (organization_id, meter, period_start, value)
        VALUES (org, p_meter, period, p_org_quantity)
        ON CONFLICT (organization_id, meter, period_start) DO UPDATE SET value = c.value + EXCLUDED.value;
    END IF;
    RETURN true;
END
$$;
REVOKE ALL ON FUNCTION openseal_meter_apply(uuid, text, bigint, bigint, timestamptz, text, text) FROM PUBLIC;

-- The application's call: count `p_quantity` of a counter meter for the transaction's
-- workspace, once per `(source_kind, source_id)`. Gauges are refused (only their triggers
-- move them), as are a non-positive quantity and a call outside a workspace scope.
CREATE FUNCTION openseal_meter_record(
    p_meter text, p_quantity bigint, p_at timestamptz, p_source_kind text, p_source_id text)
RETURNS boolean
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
DECLARE
    acct uuid := openseal_current_account();
BEGIN
    IF acct IS NULL THEN
        RAISE EXCEPTION 'metering needs a workspace scope' USING ERRCODE = '42501';
    END IF;
    IF p_meter IS NULL OR p_meter IN ('seats', 'storage_bytes', 'workspaces', 'templates')
       OR p_quantity IS NULL OR p_quantity <= 0 THEN
        RAISE EXCEPTION 'not a counter meter or quantity' USING ERRCODE = '22023';
    END IF;
    RETURN openseal_meter_apply(acct, p_meter, p_quantity, p_quantity, p_at, p_source_kind, p_source_id);
END
$$;
REVOKE ALL ON FUNCTION openseal_meter_record(text, bigint, timestamptz, text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openseal_meter_record(text, bigint, timestamptz, text, text) TO openseal_app;

-- 4. storage_bytes ------------------------------------------------------------------------

-- One more or one fewer row naming blob `p_sha` in workspace `p_account`. The first
-- reference counts the blob's bytes; the last one gone takes them off.
CREATE FUNCTION openseal_meter_blob(
    p_account uuid, p_sha bytea, p_len bigint, p_delta integer, p_source_kind text, p_source_id text)
RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
DECLARE
    left_refs bigint;
BEGIN
    IF p_delta > 0 THEN
        INSERT INTO usage_blob_refs AS r (account_id, sha256, byte_len, refs)
        VALUES (p_account, p_sha, p_len, 1)
        ON CONFLICT (account_id, sha256) DO UPDATE SET refs = r.refs + 1
        RETURNING r.refs INTO left_refs;
        IF left_refs = 1 THEN
            PERFORM openseal_meter_apply(p_account, 'storage_bytes', p_len, p_len, now(),
                                         p_source_kind, p_source_id);
        END IF;
    ELSE
        UPDATE usage_blob_refs r SET refs = r.refs - 1
         WHERE r.account_id = p_account AND r.sha256 = p_sha AND r.refs > 1
        RETURNING r.refs INTO left_refs;
        IF NOT FOUND THEN
            DELETE FROM usage_blob_refs r WHERE r.account_id = p_account AND r.sha256 = p_sha
            RETURNING r.byte_len INTO p_len;
            IF FOUND THEN
                PERFORM openseal_meter_apply(p_account, 'storage_bytes', -p_len, -p_len, now(),
                                             p_source_kind, p_source_id);
            END IF;
        END IF;
    END IF;
END
$$;
REVOKE ALL ON FUNCTION openseal_meter_blob(uuid, bytea, bigint, integer, text, text) FROM PUBLIC;

CREATE FUNCTION openseal_meter_storage_trigger() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
DECLARE
    kind text := CASE TG_TABLE_NAME WHEN 'document_versions' THEN 'document_version'
                                    ELSE 'template_document' END;
BEGIN
    IF TG_OP = 'INSERT' THEN
        PERFORM openseal_meter_blob(NEW.account_id, NEW.sha256, NEW.byte_len, 1,
                                    kind || '.write', NEW.id::text);
        RETURN NEW;
    END IF;
    PERFORM openseal_meter_blob(OLD.account_id, OLD.sha256, OLD.byte_len, -1,
                                kind || '.remove', OLD.id::text);
    RETURN OLD;
END
$$;
CREATE TRIGGER document_versions_meter_storage
    AFTER INSERT OR DELETE ON document_versions
    FOR EACH ROW EXECUTE FUNCTION openseal_meter_storage_trigger();
CREATE TRIGGER template_documents_meter_storage
    AFTER INSERT OR DELETE ON template_documents
    FOR EACH ROW EXECUTE FUNCTION openseal_meter_storage_trigger();

-- 5. seats ---------------------------------------------------------------------------------

-- The organization's seat rule at `p_at`: the latest live organization `seat_rule`
-- override, else the current assignment's plan rule, else `can_send` (docs/23 Q6; the
-- same order as `casual-sign-policy::plans::effective`).
CREATE FUNCTION openseal_org_seat_rule(p_org uuid, p_at timestamptz) RETURNS text
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
    SELECT COALESCE(
        (SELECT o.value FROM platform.plan_overrides o
          WHERE o.organization_id = p_org AND o.workspace_id IS NULL AND o.key = 'seat_rule'
            AND (o.expires_at IS NULL OR p_at < o.expires_at)
          ORDER BY o.created_at DESC, o.id DESC LIMIT 1),
        (SELECT r.rule FROM platform.plan_assignments a
           JOIN platform.plan_seat_rule r ON r.plan_id = a.plan_id
          WHERE a.organization_id = p_org AND a.starts_at <= p_at
            AND (a.ends_at IS NULL OR p_at < a.ends_at)
          ORDER BY a.starts_at DESC LIMIT 1),
        'can_send')
$$;
REVOKE ALL ON FUNCTION openseal_org_seat_rule(uuid, timestamptz) FROM PUBLIC;

-- Whether a membership holds a seat under `p_rule`: an enabled member, enabled user, in
-- an active workspace, and (`can_send`) a profile that can send.
CREATE FUNCTION openseal_holds_seat(p_account uuid, p_user uuid, p_rule text) RETURNS boolean
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
    SELECT EXISTS (
        SELECT 1 FROM account_memberships m
          JOIN users u ON u.id = m.user_id
          JOIN accounts a ON a.id = m.account_id
          JOIN permission_profiles p ON p.account_id = m.account_id AND p.id = m.permission_profile_id
         WHERE m.account_id = p_account AND m.user_id = p_user
           AND m.disabled_at IS NULL AND u.disabled_at IS NULL AND a.status = 'active'
           AND (p_rule = 'every_member' OR p.kind IN ('admin', 'sender')
                OR (p.kind = 'custom' AND 'envelopes:send' = ANY (p.permissions))))
$$;
REVOKE ALL ON FUNCTION openseal_holds_seat(uuid, uuid, text) FROM PUBLIC;

-- Seats of an organization: distinct identities holding a seat in any of its workspaces
-- (docs/23 §7.3 names it; PLAN-04 checks quotas against it).
CREATE FUNCTION openseal_org_seats(p_org uuid, p_at timestamptz) RETURNS bigint
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
    SELECT count(DISTINCT m.user_id)
      FROM account_memberships m JOIN accounts a ON a.id = m.account_id
     WHERE a.organization_id = p_org
       AND openseal_holds_seat(m.account_id, m.user_id, openseal_org_seat_rule(p_org, p_at))
$$;
REVOKE ALL ON FUNCTION openseal_org_seats(uuid, timestamptz) FROM PUBLIC;

-- Recount workspace `p_account`'s seats and its organization's, under a lock on the
-- organization's `seats` counter row, and record any difference as one ledger row on
-- that workspace (the organization's difference rides on it).
CREATE FUNCTION openseal_meter_recount_seats(p_account uuid) RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
DECLARE
    org uuid;
    at timestamptz := now();
    epoch timestamptz := openseal_meter_period('seats', at);
    rule text;
    ws_now bigint;
    ws_was bigint;
    org_now bigint;
    org_was bigint;
BEGIN
    SELECT a.organization_id INTO org FROM accounts a WHERE a.id = p_account;
    IF org IS NULL THEN
        RETURN;
    END IF;
    INSERT INTO org_usage_counters (organization_id, meter, period_start, value)
    VALUES (org, 'seats', epoch, 0) ON CONFLICT DO NOTHING;
    -- One statement takes the lock, later ones count: each reads after it is held.
    PERFORM 1 FROM org_usage_counters c
     WHERE c.organization_id = org AND c.meter = 'seats' AND c.period_start = epoch FOR UPDATE;
    SELECT c.value INTO org_was FROM org_usage_counters c
     WHERE c.organization_id = org AND c.meter = 'seats' AND c.period_start = epoch;
    rule := openseal_org_seat_rule(org, at);
    SELECT count(*) INTO ws_now FROM account_memberships m
     WHERE m.account_id = p_account AND openseal_holds_seat(m.account_id, m.user_id, rule);
    SELECT COALESCE((SELECT c.value FROM usage_counters c
                      WHERE c.account_id = p_account AND c.meter = 'seats' AND c.period_start = epoch), 0)
      INTO ws_was;
    org_now := openseal_org_seats(org, at);
    PERFORM openseal_meter_apply(p_account, 'seats', ws_now - ws_was, org_now - org_was, at,
                                 'seats.recount', gen_random_uuid()::text);
END
$$;
REVOKE ALL ON FUNCTION openseal_meter_recount_seats(uuid) FROM PUBLIC;

CREATE FUNCTION openseal_meter_seats_trigger() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
DECLARE
    acct uuid;
BEGIN
    CASE TG_TABLE_NAME
    WHEN 'account_memberships', 'permission_profiles' THEN
        PERFORM openseal_meter_recount_seats(CASE WHEN TG_OP = 'DELETE' THEN OLD.account_id
                                                  ELSE NEW.account_id END);
    WHEN 'accounts' THEN
        PERFORM openseal_meter_recount_seats(NEW.id);
    WHEN 'users' THEN
        FOR acct IN SELECT m.account_id FROM account_memberships m WHERE m.user_id = NEW.id
                     ORDER BY m.account_id LOOP
            PERFORM openseal_meter_recount_seats(acct);
        END LOOP;
    ELSE
        -- platform.plan_assignments, platform.plan_overrides: the rule may have changed.
        FOR acct IN SELECT a.id FROM accounts a WHERE a.organization_id = NEW.organization_id
                     ORDER BY a.id LOOP
            PERFORM openseal_meter_recount_seats(acct);
        END LOOP;
    END CASE;
    RETURN NULL;
END
$$;
CREATE TRIGGER account_memberships_meter_seats
    AFTER INSERT OR DELETE OR UPDATE OF permission_profile_id, disabled_at ON account_memberships
    FOR EACH ROW EXECUTE FUNCTION openseal_meter_seats_trigger();
CREATE TRIGGER permission_profiles_meter_seats
    AFTER UPDATE OF kind, permissions ON permission_profiles
    FOR EACH ROW EXECUTE FUNCTION openseal_meter_seats_trigger();
CREATE TRIGGER users_meter_seats
    AFTER UPDATE OF disabled_at ON users
    FOR EACH ROW EXECUTE FUNCTION openseal_meter_seats_trigger();
CREATE TRIGGER accounts_meter_seats
    AFTER UPDATE OF status ON accounts
    FOR EACH ROW WHEN (OLD.status IS DISTINCT FROM NEW.status)
    EXECUTE FUNCTION openseal_meter_seats_trigger();
CREATE TRIGGER plan_assignments_meter_seats
    AFTER INSERT OR UPDATE ON platform.plan_assignments
    FOR EACH ROW EXECUTE FUNCTION openseal_meter_seats_trigger();
CREATE TRIGGER plan_overrides_meter_seats
    AFTER INSERT OR UPDATE ON platform.plan_overrides
    FOR EACH ROW WHEN (NEW.key = 'seat_rule' AND NEW.workspace_id IS NULL)
    EXECUTE FUNCTION openseal_meter_seats_trigger();

-- 6. workspaces ----------------------------------------------------------------------------

CREATE FUNCTION openseal_meter_workspaces_trigger() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.status = 'active' THEN
            PERFORM openseal_meter_apply(NEW.id, 'workspaces', 1, 1, now(), 'workspace.create', NEW.id::text);
        END IF;
    ELSIF NEW.status = 'archived' THEN
        PERFORM openseal_meter_apply(NEW.id, 'workspaces', -1, -1, now(), 'workspace.archive',
                                     gen_random_uuid()::text);
    ELSE
        PERFORM openseal_meter_apply(NEW.id, 'workspaces', 1, 1, now(), 'workspace.restore',
                                     gen_random_uuid()::text);
    END IF;
    RETURN NULL;
END
$$;
CREATE TRIGGER accounts_meter_workspaces_insert
    AFTER INSERT ON accounts
    FOR EACH ROW EXECUTE FUNCTION openseal_meter_workspaces_trigger();
CREATE TRIGGER accounts_meter_workspaces_status
    AFTER UPDATE OF status ON accounts
    FOR EACH ROW WHEN (OLD.status IS DISTINCT FROM NEW.status)
    EXECUTE FUNCTION openseal_meter_workspaces_trigger();

-- 7. What exists already --------------------------------------------------------------------

SELECT openseal_meter_apply(a.id, 'workspaces', 1, 1, now(), 'workspace.create', a.id::text)
  FROM accounts a WHERE a.status = 'active' ORDER BY a.id;

SELECT openseal_meter_blob(b.account_id, b.sha256, b.byte_len, 1, b.kind || '.write', b.id::text)
  FROM (SELECT v.account_id, v.sha256, v.byte_len, 'document_version' AS kind, v.id
          FROM document_versions v
        UNION ALL
        SELECT t.account_id, t.sha256, t.byte_len, 'template_document', t.id
          FROM template_documents t) b
 ORDER BY b.account_id, b.id;

SELECT openseal_meter_recount_seats(a.id) FROM accounts a ORDER BY a.id;

SELECT openseal_meter_apply(e.account_id, 'envelopes_sent', 1, 1, min(e.at), 'envelope', e.envelope_id::text)
  FROM audit_events e WHERE e.event_type = 'envelope.sent'
 GROUP BY e.account_id, e.envelope_id ORDER BY e.account_id, e.envelope_id;
