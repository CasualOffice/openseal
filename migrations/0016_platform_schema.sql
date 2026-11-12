-- 0016: the `platform` schema and the console's database role (CON-02, ADR-028, docs/23
-- §5.1, §5.2, §5.5).
--
-- The platform console connects as `openseal_console` (through a LOGIN role granted
-- membership), never as `openseal_app`. What it may do:
--
-- 1. USAGE on schema `platform`, SELECT on the platform tables, and INSERT only on the two
--    append-only ones (`alerts` here, `operator_events` from CON-03). Nothing else directly.
-- 2. No grant at all on any `public` table, and no EXECUTE on any `public` function: a
--    catalog test (`SEC-X01`) checks every table and every SECURITY DEFINER function.
-- 3. Tenant metadata only through the definer functions below, which return ids, names,
--    statuses, counts and timestamps: never an e-mail, a person's name, an IP address,
--    a document, a field value, a subject or a job payload.
--
-- `openseal_app` gets nothing in `platform` here; plans (PLAN-02) and the worker's TSA
-- and trust-anchor reads (CON-07) add their own definer functions.

-- Roles are cluster-wide: another database of this cluster may have created it.
DO $$
BEGIN
    CREATE ROLE openseal_console NOLOGIN;
EXCEPTION
    WHEN duplicate_object OR unique_violation THEN NULL;
END
$$;

CREATE SCHEMA platform;
REVOKE ALL ON SCHEMA platform FROM PUBLIC;
GRANT USAGE ON SCHEMA platform TO openseal_console;

-- Every migration that adds functions to `platform` ends by revoking EXECUTE from PUBLIC on
-- all of them, so that only the ones granted by name are callable by the console.

-- Platform settings (docs/23 §10 Platform settings). Written by later rows through
-- two-person definer functions (self-sign-up, CON-04); the console only reads.
CREATE TABLE platform.settings (
    key    text PRIMARY KEY CHECK (key ~ '^[a-z][a-z0-9_.]{0,63}$'),
    value  jsonb NOT NULL
);
INSERT INTO platform.settings (key, value) VALUES ('self_sign_up', 'false'::jsonb);
GRANT SELECT ON platform.settings TO openseal_console;

-- What the Services page probes (docs/23 §5.5, `SEC-X06`): set by deployment
-- configuration (the migrator role, `casual-sign-console service-target`), never typed into
-- the console, so the console cannot be pointed at an arbitrary address.
CREATE TABLE platform.service_targets (
    name   text PRIMARY KEY CHECK (name ~ '^[a-z][a-z0-9_-]{0,63}$'),
    -- server, worker, keyd, tsa, database, blob, email, console (what the target is).
    role   text NOT NULL CHECK (role IN ('server', 'worker', 'keyd', 'tsa', 'blob', 'email', 'console', 'other')),
    -- `http`: GET the URL, healthy on 2xx. `tcp`: healthy when `host:port` accepts a
    -- connection (keyd and SMTP until their admin probes land, CON-05, CON-06).
    probe  text NOT NULL CHECK (probe IN ('http', 'tcp')),
    target text NOT NULL CHECK (char_length(target) BETWEEN 1 AND 512)
);
GRANT SELECT ON platform.service_targets TO openseal_console;

-- Operational alerts (docs/23 §5.5). Append-only: a resolution is a new row. Ids and
-- codes only.
CREATE TABLE platform.alerts (
    id          uuid PRIMARY KEY,
    at          timestamptz NOT NULL,
    source      text NOT NULL CHECK (source ~ '^[a-z][a-z0-9_-]{0,63}$'),
    code        text NOT NULL CHECK (code ~ '^CS-[A-Z]{2,5}-[0-9]{4}$'),
    -- Ids only (organization, workspace, envelope, job, alias): checked by shape below.
    subject     jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(subject) = 'object'),
    resolves    uuid REFERENCES platform.alerts (id),
    recorded_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX alerts_at ON platform.alerts (at DESC);
GRANT SELECT, INSERT ON platform.alerts TO openseal_console;

-- Append-only, for every role, the owner included (as `audit_events`, migration 0005).
CREATE FUNCTION platform.refuse_change() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog
AS $$
BEGIN
    RAISE EXCEPTION 'CS-DB-0004 platform log rows are append-only: % refused on %', TG_OP, TG_TABLE_NAME
        USING ERRCODE = 'OS001';
END
$$;
CREATE TRIGGER alerts_no_update_delete BEFORE UPDATE OR DELETE ON platform.alerts
    FOR EACH ROW EXECUTE FUNCTION platform.refuse_change();
CREATE TRIGGER alerts_no_truncate BEFORE TRUNCATE ON platform.alerts
    FOR EACH STATEMENT EXECUTE FUNCTION platform.refuse_change();

-- Tenant metadata for the console -------------------------------------------------------
--
-- SECURITY DEFINER, owned by the migrator (who owns the tenant tables, so row-level
-- security does not filter it). Each returns ids, names, statuses, counts and times.
-- Organization and workspace names are *tenant metadata* (docs/07): shown to operators,
-- never logged.

-- One page of organizations, ordered by id, after `p_after` (NULL: from the start).
CREATE FUNCTION platform.organizations_page(p_after uuid, p_limit integer)
RETURNS TABLE (id uuid, name text, status text, data_regions text[], created_at timestamptz,
               workspaces bigint, members bigint, envelopes bigint)
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
    SELECT o.id, o.name, o.status, o.data_regions, o.created_at,
           (SELECT count(*) FROM accounts a WHERE a.organization_id = o.id),
           (SELECT count(DISTINCT m.user_id) FROM account_memberships m JOIN accounts a ON a.id = m.account_id
             WHERE a.organization_id = o.id AND m.disabled_at IS NULL),
           (SELECT count(*) FROM envelopes e JOIN accounts a ON a.id = e.account_id WHERE a.organization_id = o.id)
      FROM organizations o
     WHERE p_after IS NULL OR o.id > p_after
     ORDER BY o.id
     LIMIT LEAST(GREATEST(p_limit, 1), 200)
$$;
GRANT EXECUTE ON FUNCTION platform.organizations_page(uuid, integer) TO openseal_console;

-- One organization, or no row.
CREATE FUNCTION platform.organization(p_id uuid)
RETURNS TABLE (id uuid, name text, status text, data_regions text[], created_at timestamptz,
               workspaces bigint, members bigint, envelopes bigint, owners bigint)
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
    SELECT o.id, o.name, o.status, o.data_regions, o.created_at,
           (SELECT count(*) FROM accounts a WHERE a.organization_id = o.id),
           (SELECT count(DISTINCT m.user_id) FROM account_memberships m JOIN accounts a ON a.id = m.account_id
             WHERE a.organization_id = o.id AND m.disabled_at IS NULL),
           (SELECT count(*) FROM envelopes e JOIN accounts a ON a.id = e.account_id WHERE a.organization_id = o.id),
           (SELECT count(*) FROM organization_admins oa WHERE oa.organization_id = o.id AND oa.role = 'owner')
      FROM organizations o
     WHERE o.id = p_id
$$;
GRANT EXECUTE ON FUNCTION platform.organization(uuid) TO openseal_console;

-- The workspaces of one organization with their counts (at most 1,000).
CREATE FUNCTION platform.organization_workspaces(p_org uuid)
RETURNS TABLE (id uuid, name text, status text, data_region text, created_at timestamptz,
               members bigint, templates bigint, envelopes bigint,
               envelopes_draft bigint, envelopes_in_progress bigint, envelopes_completed bigint)
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
    SELECT a.id, a.name, a.status, a.data_region, a.created_at,
           (SELECT count(*) FROM account_memberships m WHERE m.account_id = a.id AND m.disabled_at IS NULL),
           (SELECT count(*) FROM templates t WHERE t.account_id = a.id),
           (SELECT count(*) FROM envelopes e WHERE e.account_id = a.id),
           (SELECT count(*) FROM envelopes e WHERE e.account_id = a.id AND e.status = 'draft'),
           (SELECT count(*) FROM envelopes e WHERE e.account_id = a.id
               AND e.status IN ('sent', 'delivered', 'completing')),
           (SELECT count(*) FROM envelopes e WHERE e.account_id = a.id AND e.status = 'completed')
      FROM accounts a
     WHERE a.organization_id = p_org
     ORDER BY a.created_at, a.id
     LIMIT 1000
$$;
GRANT EXECUTE ON FUNCTION platform.organization_workspaces(uuid) TO openseal_console;

-- Job queue depth by kind and status, with the oldest queued job's age (docs/23 §5.5).
CREATE FUNCTION platform.job_stats(p_now timestamptz)
RETURNS TABLE (kind text, status text, jobs bigint, oldest_seconds bigint)
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
    SELECT j.kind, j.status, count(*),
           CASE WHEN j.status = 'queued'
                THEN GREATEST(0, EXTRACT(EPOCH FROM p_now - min(j.run_at)))::bigint END
      FROM jobs j
     WHERE j.status IN ('queued', 'running', 'dead')
     GROUP BY j.kind, j.status
     ORDER BY j.kind, j.status
$$;
GRANT EXECUTE ON FUNCTION platform.job_stats(timestamptz) TO openseal_console;

-- Dead letters, newest first: ids, kind, error code, attempts and time; never the payload.
CREATE FUNCTION platform.dead_jobs(p_limit integer)
RETURNS TABLE (id uuid, kind text, workspace_id uuid, envelope_id uuid, error_code text,
               attempts integer, finished_at timestamptz)
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
    SELECT j.id, j.kind, j.account_id, j.envelope_id, j.last_error_code, j.attempts, j.finished_at
      FROM jobs j
     WHERE j.status = 'dead'
     ORDER BY j.finished_at DESC NULLS LAST, j.id
     LIMIT LEAST(GREATEST(p_limit, 1), 200)
$$;
GRANT EXECUTE ON FUNCTION platform.dead_jobs(integer) TO openseal_console;

-- Database connections by state (docs/23 §5.5 `pool_stats`): counts only, no query text.
CREATE FUNCTION platform.pool_stats()
RETURNS TABLE (state text, connections bigint)
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path = pg_catalog
AS $$
    SELECT COALESCE(s.state, 'background'), count(*)
      FROM pg_stat_activity s
     WHERE s.datname = current_database()
     GROUP BY 1
     ORDER BY 1
$$;
GRANT EXECUTE ON FUNCTION platform.pool_stats() TO openseal_console;

REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA platform FROM PUBLIC;
