-- 0018: the console's single-operator writes to organizations and workspaces (CON-04, first
-- part; ADR-028, docs/23 §5.3).
--
-- Each is a definer function that takes the acting operator from a live session with its
-- second factor and the `operator` role (platform owners included), and changes only
-- business metadata: an organization's name and data-region labels, a workspace's
-- data-region label and its active or archived status. Data regions are labels only
-- (docs/23 §7.5): nothing here moves data.
--
-- Suspending, resuming or closing an organization, creating one and owner recovery are
-- two-person actions (docs/23 §5.1) and arrive with the approval tables (CON-04, second
-- part); there is no function for them here, so the console cannot do them yet.
--
-- The console writes the operator event for each change in the same transaction.

CREATE FUNCTION platform.rename_organization(p_session bytea, p_org uuid, p_name text, p_now timestamptz)
RETURNS boolean
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
BEGIN
    PERFORM platform.acting_operator(p_session, p_now, ARRAY['platform_owner', 'operator']);
    UPDATE organizations SET name = p_name WHERE id = p_org;
    RETURN FOUND;
END
$$;
GRANT EXECUTE ON FUNCTION platform.rename_organization(bytea, uuid, text, timestamptz) TO openseal_console;

-- Labels: at most 16, each `[a-z0-9-]`, 1 to 32 characters, no repeats.
CREATE FUNCTION platform.region_labels_ok(p_labels text[]) RETURNS boolean
    LANGUAGE sql IMMUTABLE
    SET search_path = pg_catalog
AS $$
    SELECT cardinality(p_labels) <= 16
       AND NOT EXISTS (SELECT 1 FROM unnest(p_labels) l WHERE l IS NULL OR l !~ '^[a-z0-9][a-z0-9-]{0,31}$')
       AND (SELECT count(DISTINCT l) FROM unnest(p_labels) l) = cardinality(p_labels)
$$;

CREATE FUNCTION platform.set_organization_regions(p_session bytea, p_org uuid, p_regions text[], p_now timestamptz)
RETURNS boolean
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
BEGIN
    PERFORM platform.acting_operator(p_session, p_now, ARRAY['platform_owner', 'operator']);
    IF NOT platform.region_labels_ok(p_regions) THEN
        RAISE EXCEPTION 'data-region labels invalid' USING ERRCODE = '22023';
    END IF;
    UPDATE organizations SET data_regions = p_regions WHERE id = p_org;
    RETURN FOUND;
END
$$;
GRANT EXECUTE ON FUNCTION platform.set_organization_regions(bytea, uuid, text[], timestamptz) TO openseal_console;

-- A workspace's label must be one of its organization's labels, or NULL.
CREATE FUNCTION platform.set_workspace_region(p_session bytea, p_workspace uuid, p_region text, p_now timestamptz)
RETURNS boolean
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
DECLARE
    regions text[];
BEGIN
    PERFORM platform.acting_operator(p_session, p_now, ARRAY['platform_owner', 'operator']);
    SELECT o.data_regions INTO regions FROM accounts a JOIN organizations o ON o.id = a.organization_id
     WHERE a.id = p_workspace;
    IF NOT FOUND THEN
        RETURN false;
    END IF;
    IF p_region IS NOT NULL AND NOT (p_region = ANY (regions)) THEN
        RAISE EXCEPTION 'data-region label not allowed for the organization' USING ERRCODE = '22023';
    END IF;
    UPDATE accounts SET data_region = p_region WHERE id = p_workspace;
    RETURN true;
END
$$;
GRANT EXECUTE ON FUNCTION platform.set_workspace_region(bytea, uuid, text, timestamptz) TO openseal_console;

-- Archive or restore a workspace. An archived workspace refuses new envelopes, members
-- and settings; envelopes already sent continue (docs/23 §5.3, ORG-03 enforces).
CREATE FUNCTION platform.set_workspace_status(p_session bytea, p_workspace uuid, p_status text, p_now timestamptz)
RETURNS boolean
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
BEGIN
    PERFORM platform.acting_operator(p_session, p_now, ARRAY['platform_owner', 'operator']);
    IF p_status NOT IN ('active', 'archived') THEN
        RAISE EXCEPTION 'workspace status invalid' USING ERRCODE = '22023';
    END IF;
    UPDATE accounts SET status = p_status WHERE id = p_workspace;
    RETURN FOUND;
END
$$;
GRANT EXECUTE ON FUNCTION platform.set_workspace_status(bytea, uuid, text, timestamptz) TO openseal_console;

REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA platform FROM PUBLIC;
