-- 0037: reconciling keyd's signatures with the seals recorded (CON-09, KEYD-03; ADR-028,
-- docs/23 §5.4; docs/07 SEC-S05).
--
-- keyd's operation log records, for every signature, the digest it signed (the hash of the
-- CMS signed attributes) and the envelope id the worker named. No audit event carries that
-- digest, and the console has no blob access, so the worker also writes an operational row
-- per signature in `seal_signatures`, in the transaction that stores the sealed bytes
-- (the `seal.stored` step) or the envelope certificate of an envelope that ended. It is a
-- tenant table of ids and hashes, not evidence: the audit schema is unchanged.
--
-- The console pages keyd's log (`oplog-range`, its admin identity) and matches each
-- signature against these rows through two definer functions that return envelope ids and
-- digests only. Each run is a row in `platform.reconciliation_runs` (append-only): a
-- signature with no row whose envelope has another one is an *orphaned retry* (a seal
-- job that signed, then lost its lease or failed its checks, and sealed again), listed in
-- the run; any other mismatch, in either direction, is an alert (`CS-CON-0009`).

CREATE TABLE seal_signatures (
    account_id   uuid NOT NULL REFERENCES accounts (id),
    envelope_id  uuid NOT NULL,
    -- The digest keyd signed: SHA-256, -384 or -512 of the signed attributes.
    digest       bytea NOT NULL CHECK (octet_length(digest) IN (32, 48, 64)),
    -- keyd's alias that signed it.
    alias        text NOT NULL CHECK (alias ~ '^[A-Za-z0-9._-]{1,64}$'),
    at           timestamptz NOT NULL,
    PRIMARY KEY (account_id, envelope_id, digest),
    FOREIGN KEY (account_id, envelope_id) REFERENCES envelopes (account_id, id)
);
SELECT openseal_tenant_table('seal_signatures', false);
CREATE INDEX seal_signatures_at ON seal_signatures (at);
CREATE INDEX seal_signatures_envelope ON seal_signatures (envelope_id);

-- The rows recorded in [p_from, p_to): envelope ids and digests. Owned by the migrator,
-- which owns `seal_signatures`, so row-level security does not filter it.
CREATE FUNCTION platform.seal_digests(p_from timestamptz, p_to timestamptz)
RETURNS TABLE (envelope_id uuid, digest bytea, at timestamptz)
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
    SELECT s.envelope_id, s.digest, s.at FROM seal_signatures s
     WHERE s.at >= p_from AND s.at < p_to
     ORDER BY s.at, s.envelope_id, s.digest
     LIMIT 100000
$$;
GRANT EXECUTE ON FUNCTION platform.seal_digests(timestamptz, timestamptz) TO openseal_console;

-- Every row of the envelopes named (at most 1,000 ids a call): envelope ids and digests.
CREATE FUNCTION platform.seal_digests_of(p_envelopes uuid[])
RETURNS TABLE (envelope_id uuid, digest bytea)
    LANGUAGE plpgsql STABLE SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
BEGIN
    IF coalesce(cardinality(p_envelopes), 0) > 1000 THEN
        RAISE EXCEPTION 'at most 1000 envelope ids' USING ERRCODE = '22023';
    END IF;
    RETURN QUERY SELECT s.envelope_id, s.digest FROM seal_signatures s
                  WHERE s.envelope_id = ANY (p_envelopes)
                  ORDER BY s.envelope_id, s.digest;
END
$$;
GRANT EXECUTE ON FUNCTION platform.seal_digests_of(uuid[]) TO openseal_console;

-- One reconciliation run: what keyd's log was read from and to, the cut-off up to which
-- signatures and rows were judged, and what was found. The next run starts reading at
-- `next_seq` and judges from `cutoff`. Orphaned retries are listed by keyd sequence and
-- envelope id; unmatched ones are alerts. Append-only.
CREATE TABLE platform.reconciliation_runs (
    id          uuid PRIMARY KEY,
    at          timestamptz NOT NULL,
    from_seq    bigint NOT NULL CHECK (from_seq >= 1),
    upto_seq    bigint NOT NULL CHECK (upto_seq >= 0),
    next_seq    bigint NOT NULL CHECK (next_seq >= 1),
    cutoff      timestamptz NOT NULL,
    signatures  integer NOT NULL CHECK (signatures >= 0),
    matched     integer NOT NULL CHECK (matched >= 0),
    unmatched   integer NOT NULL CHECK (unmatched >= 0),
    -- [{"seq": n, "envelope_id": "..."}], at most 1,000 listed.
    orphaned    jsonb NOT NULL CHECK (jsonb_typeof(orphaned) = 'array' AND jsonb_array_length(orphaned) <= 1000)
);
CREATE INDEX reconciliation_runs_at ON platform.reconciliation_runs (at DESC);
GRANT SELECT, INSERT ON platform.reconciliation_runs TO openseal_console;
CREATE TRIGGER reconciliation_runs_no_update_delete BEFORE UPDATE OR DELETE ON platform.reconciliation_runs
    FOR EACH ROW EXECUTE FUNCTION platform.refuse_change();
CREATE TRIGGER reconciliation_runs_no_truncate BEFORE TRUNCATE ON platform.reconciliation_runs
    FOR EACH STATEMENT EXECUTE FUNCTION platform.refuse_change();

REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA platform FROM PUBLIC;
