-- 0017: operator identity, sessions and the hash-chained operator log (CON-03, ADR-028,
-- docs/23 §5.1).
--
-- Operators are not tenant users: a separate table in `platform`, a separate password
-- (Argon2id, checked by the console), a mandatory TOTP second factor whose seed is
-- stored sealed under a console key the database never sees, and separate sessions.
--
-- The console reads these tables (SELECT on `platform.*`) and writes them only through
-- the definer functions below, which take the acting operator from a live session row,
-- never from a parameter. The database cannot check a password or a TOTP code itself;
-- docs/23 §5.1 states that residual and its controls.
--
-- `platform.operator_events` is append-only (grants and triggers) and hash-chained: an
-- insert must carry `hash = sha256(canonical)`, the next `seq` and the head as `prev`, and
-- its canonical JSON must name the same seq, action and operator as its columns
-- (SQLSTATE OS005, CS-DB-0014). The canonical bytes are made in Rust by
-- `casual-sign-audit` (RFC 8785), as for every other chain.
--
-- SQLSTATEs raised by the session checks: OS006 no live session (CS-CON-0001), OS007 no
-- fresh second factor (CS-CON-0002), OS008 role lacks the action (CS-CON-0003), OS009 the
-- action needs a second operator's approval (CS-CON-0004).

CREATE TABLE platform.operators (
    id             uuid PRIMARY KEY,
    -- Normalized (lower case) by the console before it reaches here.
    email          text NOT NULL UNIQUE
                       CHECK (char_length(email) BETWEEN 3 AND 254 AND email = lower(email) AND position('@' IN email) > 1),
    -- Argon2id PHC string; NULL until the operator enrols (sets it themself).
    password_hash  text CHECK (password_hash IS NULL OR char_length(password_hash) BETWEEN 16 AND 512),
    roles          text[] NOT NULL
                       CHECK (cardinality(roles) BETWEEN 1 AND 4
                              AND roles <@ ARRAY['platform_owner', 'operator', 'key_custodian', 'observer']),
    created_at     timestamptz NOT NULL,
    disabled_at    timestamptz
);
GRANT SELECT ON platform.operators TO openseal_console;

-- The TOTP seed, sealed (AES-256-GCM, nonce || ciphertext || tag) under the console's MFA
-- key, with the operator id as associated data. `last_step` makes each code single-use:
-- a code is accepted only for a time step later than the last accepted one.
CREATE TABLE platform.operator_mfa (
    operator_id  uuid PRIMARY KEY REFERENCES platform.operators (id),
    seed_sealed  bytea NOT NULL CHECK (octet_length(seed_sealed) BETWEEN 48 AND 128),
    last_step    bigint NOT NULL DEFAULT 0 CHECK (last_step >= 0),
    enrolled_at  timestamptz NOT NULL
);
GRANT SELECT ON platform.operator_mfa TO openseal_console;

-- One-time enrolment links (docs/23 §5.1): an operator is created without a password or a
-- second factor and sets both themself through the link, so whoever created them never
-- knows either. Only SHA-256 of the token is stored. `pending_seed` holds the sealed seed
-- shown to the operator until they confirm it with a code.
CREATE TABLE platform.operator_enrolments (
    token_sha256  bytea PRIMARY KEY CHECK (octet_length(token_sha256) = 32),
    operator_id   uuid NOT NULL REFERENCES platform.operators (id),
    created_at    timestamptz NOT NULL,
    expires_at    timestamptz NOT NULL CHECK (expires_at > created_at),
    pending_seed  bytea CHECK (pending_seed IS NULL OR octet_length(pending_seed) BETWEEN 48 AND 128),
    used_at       timestamptz
);
CREATE INDEX operator_enrolments_operator ON platform.operator_enrolments (operator_id);
GRANT SELECT ON platform.operator_enrolments TO openseal_console;

-- Sessions: 8 hours at most, 30 minutes idle (docs/23 §5.1). Only SHA-256 of the session
-- token and of its CSRF token are stored. `mfa_at` is NULL until the second factor is
-- entered; a session without it reaches nothing but the TOTP step.
CREATE TABLE platform.operator_sessions (
    token_sha256  bytea PRIMARY KEY CHECK (octet_length(token_sha256) = 32),
    operator_id   uuid NOT NULL REFERENCES platform.operators (id),
    csrf_sha256   bytea NOT NULL CHECK (octet_length(csrf_sha256) = 32),
    -- The operator's own address, for the operator log's session-creation event.
    ip            text CHECK (ip IS NULL OR char_length(ip) <= 64),
    created_at    timestamptz NOT NULL,
    last_seen_at  timestamptz NOT NULL,
    expires_at    timestamptz NOT NULL CHECK (expires_at > created_at),
    mfa_at        timestamptz,
    revoked_at    timestamptz
);
CREATE INDEX operator_sessions_operator ON platform.operator_sessions (operator_id);
GRANT SELECT ON platform.operator_sessions TO openseal_console;

-- The operator log ------------------------------------------------------------------------

CREATE TABLE platform.operator_events (
    seq          bigint PRIMARY KEY CHECK (seq >= 0 AND seq <= 9007199254740991),
    prev_hash    bytea CHECK (prev_hash IS NULL OR octet_length(prev_hash) = 32),
    hash         bytea NOT NULL CHECK (octet_length(hash) = 32),
    action       text NOT NULL CHECK (action ~ '^operator\.[a-z][a-z0-9_.]{0,62}$'),
    -- NULL for an event with no signed-in operator (a refused sign-in, the bootstrap).
    operator_id  uuid REFERENCES platform.operators (id),
    at           timestamptz NOT NULL,
    -- RFC 8785 canonical JSON of the event without `hash`: exactly the bytes hashed.
    canonical    bytea NOT NULL CHECK (octet_length(canonical) BETWEEN 2 AND 65536),
    recorded_at  timestamptz NOT NULL DEFAULT now(),
    CHECK ((seq = 0) = (prev_hash IS NULL))
);
GRANT SELECT, INSERT ON platform.operator_events TO openseal_console;

-- The chain head, one row, written only by the insert trigger.
CREATE TABLE platform.operator_chain (
    singleton  boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    seq        bigint,
    head       bytea CHECK (head IS NULL OR octet_length(head) = 32),
    CHECK ((seq IS NULL) = (head IS NULL))
);
INSERT INTO platform.operator_chain (singleton) VALUES (true);
GRANT SELECT ON platform.operator_chain TO openseal_console;

CREATE TRIGGER operator_events_no_update_delete BEFORE UPDATE OR DELETE ON platform.operator_events
    FOR EACH ROW EXECUTE FUNCTION platform.refuse_change();
CREATE TRIGGER operator_events_no_truncate BEFORE TRUNCATE ON platform.operator_events
    FOR EACH STATEMENT EXECUTE FUNCTION platform.refuse_change();

-- SECURITY DEFINER: it updates the head, which the console cannot.
CREATE FUNCTION platform.extend_operator_chain() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path = pg_catalog
AS $$
DECLARE
    chain record;
    body jsonb;
BEGIN
    IF sha256(NEW.canonical) <> NEW.hash THEN
        RAISE EXCEPTION 'CS-DB-0014 operator event hash does not match its canonical bytes (seq %)', NEW.seq
            USING ERRCODE = 'OS005';
    END IF;
    -- Serialize appends: the head is read under its row lock.
    SELECT c.seq, c.head INTO chain FROM platform.operator_chain c WHERE c.singleton FOR UPDATE;
    IF NEW.seq <> COALESCE(chain.seq + 1, 0) THEN
        RAISE EXCEPTION 'CS-DB-0014 operator event seq % is not the next (%)', NEW.seq, COALESCE(chain.seq + 1, 0)
            USING ERRCODE = 'OS005';
    END IF;
    IF NEW.prev_hash IS DISTINCT FROM chain.head THEN
        RAISE EXCEPTION 'CS-DB-0014 operator event prev is not the chain head (seq %)', NEW.seq
            USING ERRCODE = 'OS005';
    END IF;
    BEGIN
        body := convert_from(NEW.canonical, 'UTF8')::jsonb;
    EXCEPTION WHEN OTHERS THEN
        RAISE EXCEPTION 'CS-DB-0014 operator event canonical bytes are not JSON (seq %)', NEW.seq
            USING ERRCODE = 'OS005';
    END;
    IF jsonb_typeof(body) <> 'object'
       OR (body ->> 'seq') IS DISTINCT FROM NEW.seq::text
       OR (body ->> 'action') IS DISTINCT FROM NEW.action
       OR (body ->> 'operator') IS DISTINCT FROM NEW.operator_id::text
       OR (body ->> 'prev') IS DISTINCT FROM encode(NEW.prev_hash, 'hex') THEN
        RAISE EXCEPTION 'CS-DB-0014 operator event canonical bytes disagree with its columns (seq %)', NEW.seq
            USING ERRCODE = 'OS005';
    END IF;
    UPDATE platform.operator_chain SET seq = NEW.seq, head = NEW.hash WHERE singleton;
    RETURN NEW;
END
$$;
CREATE TRIGGER operator_events_extend_chain BEFORE INSERT ON platform.operator_events
    FOR EACH ROW EXECUTE FUNCTION platform.extend_operator_chain();

-- Sessions -------------------------------------------------------------------------------

-- The live session for a token hash at `p_now`, or no row: not revoked, not expired, not
-- idle for more than 30 minutes, operator enabled. Internal: not granted.
CREATE FUNCTION platform.live_session(p_token bytea, p_now timestamptz)
RETURNS TABLE (operator_id uuid, roles text[], mfa_at timestamptz, csrf_sha256 bytea, expires_at timestamptz)
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path = pg_catalog
AS $$
    SELECT s.operator_id, o.roles, s.mfa_at, s.csrf_sha256, s.expires_at
      FROM platform.operator_sessions s JOIN platform.operators o ON o.id = s.operator_id
     WHERE s.token_sha256 = p_token
       AND s.revoked_at IS NULL
       AND p_now < s.expires_at
       AND p_now - s.last_seen_at <= interval '30 minutes'
       AND o.disabled_at IS NULL
$$;

-- The acting operator of a write: a live session with its second factor, holding one of
-- `p_roles`. Raises OS006, OS007 or OS008. Internal: not granted.
CREATE FUNCTION platform.acting_operator(p_token bytea, p_now timestamptz, p_roles text[])
RETURNS uuid
    LANGUAGE plpgsql STABLE SECURITY DEFINER
    SET search_path = pg_catalog
AS $$
DECLARE
    s record;
BEGIN
    SELECT * INTO s FROM platform.live_session(p_token, p_now);
    IF NOT FOUND THEN
        RAISE EXCEPTION 'CS-CON-0001 no live operator session' USING ERRCODE = 'OS006';
    END IF;
    IF s.mfa_at IS NULL THEN
        RAISE EXCEPTION 'CS-CON-0002 second factor required' USING ERRCODE = 'OS007';
    END IF;
    IF NOT (s.roles && p_roles) THEN
        RAISE EXCEPTION 'CS-CON-0003 operator role lacks the action' USING ERRCODE = 'OS008';
    END IF;
    RETURN s.operator_id;
END
$$;

-- Resolve a session for a request and mark it seen. No row when it is not live.
CREATE FUNCTION platform.resolve_session(p_token bytea, p_now timestamptz)
RETURNS TABLE (operator_id uuid, roles text[], mfa_at timestamptz, csrf_sha256 bytea, expires_at timestamptz)
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path = pg_catalog
AS $$
BEGIN
    RETURN QUERY SELECT * FROM platform.live_session(p_token, p_now);
    IF FOUND THEN
        UPDATE platform.operator_sessions SET last_seen_at = p_now WHERE token_sha256 = p_token;
    END IF;
END
$$;
GRANT EXECUTE ON FUNCTION platform.resolve_session(bytea, timestamptz) TO openseal_console;

-- A new session for an enrolled, enabled operator, after the console checked the
-- password; it reaches nothing until `confirm_mfa`. False when the operator cannot sign in.
CREATE FUNCTION platform.open_session(p_operator uuid, p_token bytea, p_csrf bytea, p_ip text,
                                      p_now timestamptz, p_expires timestamptz)
RETURNS boolean
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path = pg_catalog
AS $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM platform.operators o JOIN platform.operator_mfa m ON m.operator_id = o.id
                    WHERE o.id = p_operator AND o.disabled_at IS NULL) THEN
        RETURN false;
    END IF;
    IF p_expires > p_now + interval '8 hours' THEN
        RAISE EXCEPTION 'operator session longer than 8 hours' USING ERRCODE = '22023';
    END IF;
    INSERT INTO platform.operator_sessions (token_sha256, operator_id, csrf_sha256, ip, created_at, last_seen_at, expires_at)
    VALUES (p_token, p_operator, p_csrf, p_ip, p_now, p_now, p_expires);
    RETURN true;
END
$$;
GRANT EXECUTE ON FUNCTION platform.open_session(uuid, bytea, bytea, text, timestamptz, timestamptz) TO openseal_console;

-- Record a second factor the console checked for time step `p_step`: accepted only for a
-- step later than the operator's last (a code is single-use), on a live session. Also
-- the TOTP re-entry for sensitive actions. False when refused.
CREATE FUNCTION platform.confirm_mfa(p_token bytea, p_step bigint, p_now timestamptz)
RETURNS boolean
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path = pg_catalog
AS $$
DECLARE
    op uuid;
BEGIN
    SELECT s.operator_id INTO op FROM platform.live_session(p_token, p_now) s;
    IF op IS NULL THEN
        RETURN false;
    END IF;
    UPDATE platform.operator_mfa SET last_step = p_step WHERE operator_id = op AND last_step < p_step;
    IF NOT FOUND THEN
        RETURN false;
    END IF;
    UPDATE platform.operator_sessions SET mfa_at = p_now, last_seen_at = p_now WHERE token_sha256 = p_token;
    RETURN true;
END
$$;
GRANT EXECUTE ON FUNCTION platform.confirm_mfa(bytea, bigint, timestamptz) TO openseal_console;

-- End a session (sign-out). Idempotent.
CREATE FUNCTION platform.revoke_session(p_token bytea, p_now timestamptz)
RETURNS boolean
    LANGUAGE sql SECURITY DEFINER
    SET search_path = pg_catalog
AS $$
    UPDATE platform.operator_sessions SET revoked_at = p_now
     WHERE token_sha256 = p_token AND revoked_at IS NULL
    RETURNING true
$$;
GRANT EXECUTE ON FUNCTION platform.revoke_session(bytea, timestamptz) TO openseal_console;

-- Operators --------------------------------------------------------------------------------

-- Issue an enrolment link for a not-yet-enrolled operator. Internal: not granted.
CREATE FUNCTION platform.issue_enrolment(p_operator uuid, p_token bytea, p_now timestamptz, p_expires timestamptz)
RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path = pg_catalog
AS $$
BEGIN
    IF p_expires > p_now + interval '7 days' THEN
        RAISE EXCEPTION 'enrolment link longer than 7 days' USING ERRCODE = '22023';
    END IF;
    INSERT INTO platform.operator_enrolments (token_sha256, operator_id, created_at, expires_at)
    VALUES (p_token, p_operator, p_now, p_expires);
END
$$;

-- The first platform owner (`casual-sign-console bootstrap-operator`), with an enrolment
-- link: only while no operator exists. False otherwise.
CREATE FUNCTION platform.bootstrap_operator(p_id uuid, p_email text, p_token bytea,
                                            p_now timestamptz, p_expires timestamptz)
RETURNS boolean
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path = pg_catalog
AS $$
BEGIN
    LOCK TABLE platform.operators IN EXCLUSIVE MODE;
    IF EXISTS (SELECT 1 FROM platform.operators) THEN
        RETURN false;
    END IF;
    INSERT INTO platform.operators (id, email, roles, created_at)
    VALUES (p_id, p_email, ARRAY['platform_owner'], p_now);
    PERFORM platform.issue_enrolment(p_id, p_token, p_now, p_expires);
    RETURN true;
END
$$;
GRANT EXECUTE ON FUNCTION platform.bootstrap_operator(uuid, text, bytea, timestamptz, timestamptz) TO openseal_console;

-- A new operator with an enrolment link, by a platform owner. Adding a platform owner is
-- a two-person action (docs/23 §5.1), refused here until approvals exist (CON-04):
-- OS009. False when the e-mail is already an operator's.
CREATE FUNCTION platform.create_operator(p_session bytea, p_id uuid, p_email text, p_roles text[],
                                         p_token bytea, p_now timestamptz, p_expires timestamptz)
RETURNS boolean
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path = pg_catalog
AS $$
BEGIN
    PERFORM platform.acting_operator(p_session, p_now, ARRAY['platform_owner']);
    IF 'platform_owner' = ANY (p_roles) THEN
        RAISE EXCEPTION 'CS-CON-0004 adding a platform owner needs a second operator''s approval'
            USING ERRCODE = 'OS009';
    END IF;
    INSERT INTO platform.operators (id, email, roles, created_at)
    VALUES (p_id, p_email, p_roles, p_now)
    ON CONFLICT (email) DO NOTHING;
    IF NOT FOUND THEN
        RETURN false;
    END IF;
    PERFORM platform.issue_enrolment(p_id, p_token, p_now, p_expires);
    RETURN true;
END
$$;
GRANT EXECUTE ON FUNCTION platform.create_operator(bytea, uuid, text, text[], bytea, timestamptz, timestamptz) TO openseal_console;

-- The live enrolment for a token: unused, unexpired, operator enabled and not enrolled.
CREATE FUNCTION platform.live_enrolment(p_token bytea, p_now timestamptz)
RETURNS TABLE (operator_id uuid, pending_seed bytea)
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path = pg_catalog
AS $$
    SELECT e.operator_id, e.pending_seed
      FROM platform.operator_enrolments e JOIN platform.operators o ON o.id = e.operator_id
     WHERE e.token_sha256 = p_token AND e.used_at IS NULL AND p_now < e.expires_at
       AND o.disabled_at IS NULL
       AND NOT EXISTS (SELECT 1 FROM platform.operator_mfa m WHERE m.operator_id = o.id)
$$;

-- Step 1 of enrolment: store the sealed seed the console generated and shows the
-- operator once. Returns the operator id, or NULL when the link is not live.
CREATE FUNCTION platform.begin_enrolment(p_token bytea, p_seed bytea, p_now timestamptz)
RETURNS uuid
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path = pg_catalog
AS $$
DECLARE
    op uuid;
BEGIN
    SELECT e.operator_id INTO op FROM platform.live_enrolment(p_token, p_now) e;
    IF op IS NULL THEN
        RETURN NULL;
    END IF;
    UPDATE platform.operator_enrolments SET pending_seed = p_seed WHERE token_sha256 = p_token;
    RETURN op;
END
$$;
GRANT EXECUTE ON FUNCTION platform.begin_enrolment(bytea, bytea, timestamptz) TO openseal_console;

-- Step 2: the console checked a code against the pending seed (time step `p_step`); set
-- the password, make the seed the operator's second factor with that step used, and spend
-- the link. Returns the operator id, or NULL when the link is not live or has no seed.
CREATE FUNCTION platform.finish_enrolment(p_token bytea, p_phc text, p_step bigint, p_now timestamptz)
RETURNS uuid
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path = pg_catalog
AS $$
DECLARE
    e record;
BEGIN
    SELECT * INTO e FROM platform.live_enrolment(p_token, p_now);
    IF NOT FOUND OR e.pending_seed IS NULL THEN
        RETURN NULL;
    END IF;
    UPDATE platform.operators SET password_hash = p_phc WHERE id = e.operator_id;
    INSERT INTO platform.operator_mfa (operator_id, seed_sealed, last_step, enrolled_at)
    VALUES (e.operator_id, e.pending_seed, p_step, p_now);
    UPDATE platform.operator_enrolments SET used_at = p_now WHERE token_sha256 = p_token;
    RETURN e.operator_id;
END
$$;
GRANT EXECUTE ON FUNCTION platform.finish_enrolment(bytea, text, bigint, timestamptz) TO openseal_console;

-- Disable an operator and end every session of theirs, by a platform owner; never
-- oneself (the last owner cannot lock the console). False when no such enabled operator.
CREATE FUNCTION platform.disable_operator(p_session bytea, p_id uuid, p_now timestamptz)
RETURNS boolean
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path = pg_catalog
AS $$
DECLARE
    actor uuid := platform.acting_operator(p_session, p_now, ARRAY['platform_owner']);
BEGIN
    IF actor = p_id THEN
        RAISE EXCEPTION 'CS-CON-0003 an operator cannot disable themself' USING ERRCODE = 'OS008';
    END IF;
    UPDATE platform.operators SET disabled_at = p_now WHERE id = p_id AND disabled_at IS NULL;
    IF NOT FOUND THEN
        RETURN false;
    END IF;
    UPDATE platform.operator_sessions SET revoked_at = p_now WHERE operator_id = p_id AND revoked_at IS NULL;
    RETURN true;
END
$$;
GRANT EXECUTE ON FUNCTION platform.disable_operator(bytea, uuid, timestamptz) TO openseal_console;

REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA platform FROM PUBLIC;
