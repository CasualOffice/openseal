-- 0040: keyd signs only for envelopes that owe a seal (KEYD-02, ADR-036; docs/07 SEC-S05,
-- docs/31 §5).
--
-- Before keyd signs a digest, the worker presents a seal token for the envelope: an
-- HMAC-SHA-256 over 'openseal-keyd-seal-token-v1' LF <envelope id> LF <expiry, Unix
-- seconds> under a 32-byte key that keyd holds (OPENSEAL_KEYD_SEAL_TOKEN_KEY) and that
-- this database holds in `openseal_keyd.seal_token_key`, which no application role can
-- read. Only `openseal_keyd_seal_token` mints one, as the migrator, and only for an
-- envelope of the transaction's account that owes a seal: `completing`, or declined,
-- voided or expired without its envelope certificate (UXW-30). keyd stays off the data
-- network; the database is the authority on envelope state, so it vouches.
--
-- The key is installed by the operator through `openseal_keyd.set_seal_token_key`, which
-- only the migrator can execute (`casual-sign-server migrate` does it from
-- OPENSEAL_KEYD_SEAL_TOKEN_KEY, docs/65). Until then the function mints a token with no
-- MAC: the worker then signs without one, which a keyd without the key accepts and a keyd
-- with it refuses (CS-KEY-0015).

-- HMAC from pgcrypto (a trusted extension since PostgreSQL 13; ADR-006 names the
-- primitives, never hand-rolled). Installed where the application role cannot create.
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE SCHEMA openseal_keyd;
REVOKE ALL ON SCHEMA openseal_keyd FROM PUBLIC;

-- One row at most: the key in force.
CREATE TABLE openseal_keyd.seal_token_key (
    one     boolean PRIMARY KEY DEFAULT true CHECK (one),
    key     bytea NOT NULL CHECK (octet_length(key) = 32),
    set_at  timestamptz NOT NULL
);
REVOKE ALL ON openseal_keyd.seal_token_key FROM PUBLIC;

-- Install or replace the key (rotation: replace here and in keyd, then restart keyd;
-- seal jobs in flight fail CS-KEY-0015 and retry).
CREATE FUNCTION openseal_keyd.set_seal_token_key(p_key bytea) RETURNS void
    LANGUAGE sql
    SET search_path = pg_catalog
AS $$
    INSERT INTO openseal_keyd.seal_token_key (one, key, set_at) VALUES (true, p_key, now())
    ON CONFLICT (one) DO UPDATE SET key = EXCLUDED.key, set_at = EXCLUDED.set_at
$$;
REVOKE ALL ON FUNCTION openseal_keyd.set_seal_token_key(bytea) FROM PUBLIC;

-- The seal token for `p_envelope` in the transaction's account, valid ten minutes: one
-- row (expires, mac) while the envelope owes a seal (mac NULL while no key is
-- installed), no row otherwise. Owned by the migrator, which owns `envelopes`, so
-- row-level security does not filter it; the account is matched explicitly.
CREATE FUNCTION openseal_keyd_seal_token(p_envelope uuid)
RETURNS TABLE (expires bigint, mac bytea)
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
    WITH owed AS (
        SELECT e.id FROM envelopes e
         WHERE e.id = p_envelope
           AND e.account_id = openseal_current_account()
           AND (e.status = 'completing'
                OR (e.status IN ('declined', 'voided', 'expired') AND e.certificate_sha256 IS NULL))
    ), t AS (
        SELECT owed.id, floor(extract(epoch FROM statement_timestamp()))::bigint + 600 AS expires
          FROM owed
    )
    SELECT t.expires,
           hmac(convert_to('openseal-keyd-seal-token-v1' || chr(10) || t.id::text || chr(10)
                           || t.expires::text, 'UTF8'),
                (SELECT k.key FROM openseal_keyd.seal_token_key k),
                'sha256')
      FROM t
$$;
REVOKE ALL ON FUNCTION openseal_keyd_seal_token(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openseal_keyd_seal_token(uuid) TO openseal_app;
