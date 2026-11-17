-- 0041: public anchoring of audit chain heads (docs/32 §5, FG-158, ADR-037).
--
-- Per account and UTC day, the worker builds an RFC 6962 Merkle tree over the chain head
-- (as of the end of the day) of every envelope whose chain gained an event that day, gets
-- an RFC 3161 timestamp over the tree's statement (root and size) from the configured
-- time-stamping authority, stores the anchor here and each envelope's inclusion proof
-- beside it, and publishes the anchor (no envelope or account named) to the operator's
-- sink. Evidence, so append-only like the audit chain: the application role may select
-- and insert, and triggers refuse UPDATE, DELETE and TRUNCATE for every role.

CREATE TABLE chain_anchors (
    account_id       uuid NOT NULL REFERENCES accounts (id),
    id               uuid NOT NULL,
    -- The UTC day whose changed heads it covers: one anchor per account and day.
    period           date NOT NULL,
    tree_size        bigint NOT NULL CHECK (tree_size BETWEEN 1 AND 1000000),
    root             bytea NOT NULL CHECK (octet_length(root) = 32),
    -- The DER TimeStampToken over SHA-256("openseal.anchor.v1" 0x00 size root).
    timestamp_token  bytea NOT NULL CHECK (octet_length(timestamp_token) BETWEEN 1 AND 65536),
    -- The token's genTime, as read by the worker (the token is the evidence).
    tsa_time         timestamptz NOT NULL,
    created_at       timestamptz NOT NULL,
    PRIMARY KEY (account_id, id),
    UNIQUE (account_id, period)
);
SELECT openseal_tenant_table('chain_anchors', false);

CREATE TABLE chain_anchor_leaves (
    account_id   uuid NOT NULL,
    anchor_id    uuid NOT NULL,
    leaf_index   bigint NOT NULL CHECK (leaf_index >= 0 AND leaf_index < 1000000),
    envelope_id  uuid NOT NULL,
    -- The event that was the head, and its hash: the leaf.
    seq          bigint NOT NULL CHECK (seq >= 0 AND seq <= 9007199254740991),
    head         bytea NOT NULL CHECK (octet_length(head) = 32),
    -- The audit path from the leaf up, 32 bytes per sibling (RFC 9162 §2.1.3).
    path         bytea NOT NULL CHECK (octet_length(path) % 32 = 0 AND octet_length(path) <= 2048),
    PRIMARY KEY (account_id, anchor_id, leaf_index),
    -- A head is anchored once.
    UNIQUE (account_id, envelope_id, head),
    FOREIGN KEY (account_id, anchor_id) REFERENCES chain_anchors (account_id, id),
    FOREIGN KEY (account_id, envelope_id) REFERENCES envelopes (account_id, id)
);
SELECT openseal_tenant_table('chain_anchor_leaves', false);

CREATE TRIGGER chain_anchors_no_update_delete
    BEFORE UPDATE OR DELETE ON chain_anchors
    FOR EACH ROW EXECUTE FUNCTION openseal_audit_refuse_change();
CREATE TRIGGER chain_anchors_no_truncate
    BEFORE TRUNCATE ON chain_anchors
    FOR EACH STATEMENT EXECUTE FUNCTION openseal_audit_refuse_change();
CREATE TRIGGER chain_anchor_leaves_no_update_delete
    BEFORE UPDATE OR DELETE ON chain_anchor_leaves
    FOR EACH ROW EXECUTE FUNCTION openseal_audit_refuse_change();
CREATE TRIGGER chain_anchor_leaves_no_truncate
    BEFORE TRUNCATE ON chain_anchor_leaves
    FOR EACH STATEMENT EXECUTE FUNCTION openseal_audit_refuse_change();

-- The day's events of an account, for the anchor job and the enqueue below.
CREATE INDEX audit_events_account_at ON audit_events (account_id, at);

-- Queue the anchor job of day `p_period` ([p_start, p_end)) for every account with an
-- event in it and no anchor for it yet. The only path that reads across accounts for
-- anchoring: it returns a count, and the job's idempotency key (`anchor:<day>`) makes a
-- second call, by this worker or another, queue nothing more. Time is supplied.
CREATE FUNCTION openseal_enqueue_anchor_jobs(
    p_period date, p_start timestamptz, p_end timestamptz, p_now timestamptz)
RETURNS integer
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
DECLARE
    n integer;
BEGIN
    IF p_end <= p_start OR p_end - p_start > interval '1 day' THEN
        RAISE EXCEPTION 'CS-DB-0008 anchor period out of shape' USING ERRCODE = '23514';
    END IF;
    INSERT INTO jobs (id, account_id, envelope_id, kind, idempotency_key, payload, run_at, max_attempts)
    SELECT gen_random_uuid(), a.id, NULL, 'anchor_chain_heads', 'anchor:' || p_period::text,
           jsonb_build_object('period', p_period::text), p_now, 15
      FROM accounts AS a
     WHERE EXISTS (SELECT 1 FROM audit_events AS e
                    WHERE e.account_id = a.id AND e.at >= p_start AND e.at < p_end)
       AND NOT EXISTS (SELECT 1 FROM chain_anchors AS c
                        WHERE c.account_id = a.id AND c.period = p_period)
    ON CONFLICT (account_id, idempotency_key) DO NOTHING;
    GET DIAGNOSTICS n = ROW_COUNT;
    RETURN n;
END
$$;
REVOKE ALL ON FUNCTION openseal_enqueue_anchor_jobs(date, timestamptz, timestamptz, timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openseal_enqueue_anchor_jobs(date, timestamptz, timestamptz, timestamptz) TO openseal_app;
