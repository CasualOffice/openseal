-- 0049: sandbox workspaces (slice 8 `VS-08D`, ADR-041, owner instruction 69; docs/23 §2.1).
--
-- 1. `accounts.sandbox`: a workspace is a sandbox from its creation and for good. The
--    value is taken at insert from the transaction-local setting `openseal.new_sandbox`
--    (set by `OrgTx::create_workspace` when the organization administrator asks for a
--    sandbox), so no definer function needs a new parameter; afterwards no UPDATE may
--    change it, whoever runs it (`openseal_accounts_sandbox_fixed`).
-- 2. Not metered: `openseal_meter_apply`, the one writer of the usage ledger and every
--    counter (0025, 0028), is wrapped so a sandbox workspace's usage is never counted:
--    the original is renamed `openseal_meter_apply_counted` and the wrapper of the same
--    name and signature returns false for a sandbox before calling it. Every caller
--    (`openseal_meter_record`, the storage and seat triggers) reaches the wrapper by name.

ALTER TABLE accounts ADD COLUMN sandbox boolean NOT NULL
    DEFAULT coalesce(nullif(current_setting('openseal.new_sandbox', true), '')::boolean, false);

CREATE FUNCTION openseal_accounts_sandbox_fixed() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = public, pg_catalog
AS $$
BEGIN
    IF NEW.sandbox IS DISTINCT FROM OLD.sandbox THEN
        RAISE EXCEPTION 'a workspace is a sandbox, or not, for good' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;
CREATE TRIGGER accounts_sandbox_fixed BEFORE UPDATE OF sandbox ON accounts
    FOR EACH ROW EXECUTE FUNCTION openseal_accounts_sandbox_fixed();

ALTER FUNCTION openseal_meter_apply(uuid, text, bigint, bigint, timestamptz, text, text)
    RENAME TO openseal_meter_apply_counted;

CREATE FUNCTION openseal_meter_apply(
    p_account uuid, p_meter text, p_quantity bigint, p_org_quantity bigint, p_at timestamptz,
    p_source_kind text, p_source_id text) RETURNS boolean
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM accounts a WHERE a.id = p_account AND a.sandbox) THEN
        RETURN false;
    END IF;
    RETURN openseal_meter_apply_counted(p_account, p_meter, p_quantity, p_org_quantity, p_at,
                                        p_source_kind, p_source_id);
END
$$;
REVOKE ALL ON FUNCTION openseal_meter_apply(uuid, text, bigint, bigint, timestamptz, text, text) FROM PUBLIC;

-- 3. The application's counter meters with quotas (`openseal_consume_quota`, 0028) write
--    the ledger themselves: wrapped the same way. A sandbox is never counted or refused
--    by a quota, but a suspended organization still stops it.
ALTER FUNCTION openseal_consume_quota(text, bigint, timestamptz, text, text, jsonb)
    RENAME TO openseal_consume_quota_counted;
REVOKE ALL ON FUNCTION openseal_consume_quota_counted(text, bigint, timestamptz, text, text, jsonb) FROM openseal_app;

CREATE FUNCTION openseal_consume_quota(
    p_meter text, p_n bigint, p_at timestamptz, p_source_kind text, p_source_id text, p_quota jsonb)
RETURNS jsonb
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
DECLARE
    s record;
BEGIN
    SELECT * INTO s FROM openseal_quota_scope();
    IF EXISTS (SELECT 1 FROM accounts a WHERE a.id = s.acct AND a.sandbox) THEN
        IF s.org_status = 'suspended' THEN
            RETURN jsonb_build_object('result', 'suspended');
        END IF;
        RETURN jsonb_build_object('result', 'counted',
                                  'used', jsonb_build_object('workspace', 0, 'organization', 0));
    END IF;
    RETURN openseal_consume_quota_counted(p_meter, p_n, p_at, p_source_kind, p_source_id, p_quota);
END
$$;
REVOKE ALL ON FUNCTION openseal_consume_quota(text, bigint, timestamptz, text, text, jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openseal_consume_quota(text, bigint, timestamptz, text, text, jsonb) TO openseal_app;
