-- 0005: the audit chain (docs/32). Append-only three ways:
--   1. the application role is granted SELECT and INSERT only;
--   2. row triggers refuse UPDATE and DELETE, and a statement trigger refuses TRUNCATE,
--      for every role, the owner included;
--   3. an insert trigger refuses an event that does not extend its envelope's chain: its
--      hash must be SHA-256 of its canonical bytes, `seq` the next, `prev` the head.
-- Superusers can disable triggers; that is the operator trust boundary docs/07 SEC-S07
-- names, and the chain head inside every sealed document is what detects it.

CREATE TABLE audit_events (
    account_id    uuid NOT NULL REFERENCES accounts (id),
    envelope_id   uuid NOT NULL,
    seq           bigint NOT NULL CHECK (seq >= 0 AND seq <= 9007199254740991),
    prev_hash     bytea CHECK (prev_hash IS NULL OR octet_length(prev_hash) = 32),
    hash          bytea NOT NULL CHECK (octet_length(hash) = 32),
    event_type    text NOT NULL CHECK (char_length(event_type) BETWEEN 1 AND 64),
    at            timestamptz NOT NULL,
    -- RFC 8785 canonical JSON of the event without `hash`: exactly the bytes hashed.
    canonical     bytea NOT NULL CHECK (octet_length(canonical) BETWEEN 2 AND 1048576),
    recorded_at   timestamptz NOT NULL DEFAULT now(),
    -- Keys lead with the account, so a cross-tenant insert fails on the reference, never
    -- on a uniqueness collision that would reveal another account's row exists.
    PRIMARY KEY (account_id, envelope_id, seq),
    CHECK ((seq = 0) = (prev_hash IS NULL)),
    -- No ON DELETE action: an envelope with evidence cannot be deleted (docs/32 §7 purge
    -- keeps a tombstone instead).
    FOREIGN KEY (account_id, envelope_id) REFERENCES envelopes (account_id, id)
);
SELECT openseal_tenant_table('audit_events', false);

CREATE FUNCTION openseal_audit_refuse_change() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog
AS $$
BEGIN
    RAISE EXCEPTION 'CS-DB-0004 audit events are append-only: % refused on %', TG_OP, TG_TABLE_NAME
        USING ERRCODE = 'OS001';
END
$$;

CREATE TRIGGER audit_events_no_update_delete
    BEFORE UPDATE OR DELETE ON audit_events
    FOR EACH ROW EXECUTE FUNCTION openseal_audit_refuse_change();
CREATE TRIGGER audit_events_no_truncate
    BEFORE TRUNCATE ON audit_events
    FOR EACH STATEMENT EXECUTE FUNCTION openseal_audit_refuse_change();

-- Runs as the inserting role, so row-level security applies to the lookup; the
-- composite foreign key already ties the event to an envelope of the same account.
CREATE FUNCTION openseal_audit_extend_chain() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = public, pg_catalog
AS $$
DECLARE
    head bytea;
    head_seq bigint;
BEGIN
    IF sha256(NEW.canonical) <> NEW.hash THEN
        RAISE EXCEPTION 'CS-DB-0005 audit event hash does not match its canonical bytes (seq %)', NEW.seq
            USING ERRCODE = 'OS002';
    END IF;
    -- Serialize appends per envelope: the chain head is read under the envelope row lock.
    SELECT chain_head INTO head FROM envelopes
        WHERE account_id = NEW.account_id AND id = NEW.envelope_id FOR UPDATE;
    SELECT seq INTO head_seq FROM audit_events
        WHERE account_id = NEW.account_id AND envelope_id = NEW.envelope_id
        ORDER BY seq DESC LIMIT 1;
    IF NEW.seq <> COALESCE(head_seq + 1, 0) THEN
        RAISE EXCEPTION 'CS-DB-0005 audit event seq % is not the next (%)', NEW.seq, COALESCE(head_seq + 1, 0)
            USING ERRCODE = 'OS002';
    END IF;
    IF NEW.prev_hash IS DISTINCT FROM head THEN
        RAISE EXCEPTION 'CS-DB-0005 audit event prev is not the chain head (seq %)', NEW.seq
            USING ERRCODE = 'OS002';
    END IF;
    UPDATE envelopes SET chain_head = NEW.hash
        WHERE account_id = NEW.account_id AND id = NEW.envelope_id;
    RETURN NEW;
END
$$;

CREATE TRIGGER audit_events_extend_chain
    BEFORE INSERT ON audit_events
    FOR EACH ROW EXECUTE FUNCTION openseal_audit_extend_chain();

-- What a purge keeps (docs/32 §7): envelope id, chain head, sealed hash, purge time and
-- policy, no personal data. Append-only like the chain.
CREATE TABLE envelope_tombstones (
    account_id     uuid NOT NULL REFERENCES accounts (id),
    envelope_id    uuid NOT NULL,
    chain_head     bytea NOT NULL CHECK (octet_length(chain_head) = 32),
    event_count    bigint NOT NULL CHECK (event_count > 0),
    sealed_sha256  bytea CHECK (sealed_sha256 IS NULL OR octet_length(sealed_sha256) = 32),
    purged_at      timestamptz NOT NULL,
    policy         text NOT NULL CHECK (char_length(policy) BETWEEN 1 AND 255),
    PRIMARY KEY (account_id, envelope_id)
);
SELECT openseal_tenant_table('envelope_tombstones', false);
CREATE TRIGGER envelope_tombstones_no_update_delete
    BEFORE UPDATE OR DELETE ON envelope_tombstones
    FOR EACH ROW EXECUTE FUNCTION openseal_audit_refuse_change();
CREATE TRIGGER envelope_tombstones_no_truncate
    BEFORE TRUNCATE ON envelope_tombstones
    FOR EACH STATEMENT EXECUTE FUNCTION openseal_audit_refuse_change();
