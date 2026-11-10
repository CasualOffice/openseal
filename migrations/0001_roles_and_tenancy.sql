-- 0001: the application role and the tenancy helpers every later migration uses
-- (docs/22 §9, ADR-013). Forward-only: never edit an applied migration; add a new one.
--
-- Roles are cluster-wide. `openseal_app` is what the server and worker run as (directly,
-- or through a LOGIN role granted membership). It owns nothing, so row-level security
-- applies to it; the migrator role owns every table.

DO $$
BEGIN
    CREATE ROLE openseal_app NOLOGIN;
EXCEPTION
    -- Another database in this cluster already created it, or a concurrent migrator did.
    WHEN duplicate_object OR unique_violation THEN NULL;
END
$$;

-- The account of the current transaction, or NULL when none is set. The store sets
-- `openseal.account_id` with `set_config(..., true)`, so it lasts one transaction. An
-- unset or empty setting yields NULL, and `account_id = NULL` matches no row: fail closed.
CREATE FUNCTION openseal_current_account() RETURNS uuid
    LANGUAGE sql STABLE PARALLEL SAFE
    SET search_path = pg_catalog
AS $$
    SELECT NULLIF(current_setting('openseal.account_id', true), '')::uuid
$$;

-- Make `tbl` a tenant table: row-level security on, one policy keyed on the current
-- account for every command, and the application role's grants. `writable` false grants
-- SELECT and INSERT only (append-only tables). Every tenant table is declared through
-- this function, and a test checks the catalog for any table it missed.
CREATE FUNCTION openseal_tenant_table(tbl regclass, writable boolean) RETURNS void
    LANGUAGE plpgsql
    SET search_path = public, pg_catalog
AS $$
BEGIN
    EXECUTE format('ALTER TABLE %s ENABLE ROW LEVEL SECURITY', tbl);
    EXECUTE format(
        'CREATE POLICY tenant_isolation ON %s USING (account_id = openseal_current_account()) '
        'WITH CHECK (account_id = openseal_current_account())', tbl);
    IF writable THEN
        EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON %s TO openseal_app', tbl);
    ELSE
        EXECUTE format('GRANT SELECT, INSERT ON %s TO openseal_app', tbl);
    END IF;
END
$$;

REVOKE ALL ON FUNCTION openseal_tenant_table(regclass, boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openseal_current_account() TO openseal_app;

-- The default `public` schema lets every role create objects in PostgreSQL < 15; the
-- application role creates nothing.
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO openseal_app;
