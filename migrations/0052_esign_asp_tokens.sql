-- 0052: India eSign as an ASP (`RSP-02`, ADR-047 §3.5, §3.6; docs/22, docs/07 SEC-S14, SEC-S15).
--
-- 1. ASP tokens. keyd signs with an ASP request-signing key (alias `asp-*`) only for a
--    request carrying an ASP token: an HMAC-SHA-256 over 'openseal-keyd-asp-token-v1' LF
--    <session id> LF <expiry, Unix seconds> under a 32-byte key keyd holds
--    (OPENSEAL_KEYD_ASP_TOKEN_KEY) and this database holds in
--    `openseal_keyd.asp_token_key`, which no application role can read; its own key and
--    label, so a seal token never opens an ASP key nor an ASP token the seal key. Only
--    `openseal_keyd_asp_token` mints one, and only for a remote signing session of the
--    transaction's account that is open, within its time and being prepared (the one
--    step that signs requests). Until a key is installed it mints a token with no MAC,
--    which keyd refuses.
-- 2. The ESP's answer arrives at a public endpoint with no account in hand.
--    `openseal_esign_session_account` names the account of an open session of that
--    provider, and nothing for any other id, so the endpoint can open the account's
--    transaction; everything else is checked there under row-level security.

CREATE TABLE openseal_keyd.asp_token_key (
    one     boolean PRIMARY KEY DEFAULT true CHECK (one),
    key     bytea NOT NULL CHECK (octet_length(key) = 32),
    set_at  timestamptz NOT NULL
);
REVOKE ALL ON openseal_keyd.asp_token_key FROM PUBLIC;

CREATE FUNCTION openseal_keyd.set_asp_token_key(p_key bytea) RETURNS void
    LANGUAGE sql
    SET search_path = pg_catalog
AS $$
    INSERT INTO openseal_keyd.asp_token_key (one, key, set_at) VALUES (true, p_key, now())
    ON CONFLICT (one) DO UPDATE SET key = EXCLUDED.key, set_at = EXCLUDED.set_at
$$;
REVOKE ALL ON FUNCTION openseal_keyd.set_asp_token_key(bytea) FROM PUBLIC;

-- The ASP token for `p_session` in the transaction's account, valid ten minutes: one row
-- (expires, mac) while the session is open, within its time and `preparing`; no row
-- otherwise.
CREATE FUNCTION openseal_keyd_asp_token(p_session uuid)
RETURNS TABLE (expires bigint, mac bytea)
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
    WITH open_session AS (
        SELECT s.id FROM remote_signing_sessions s
         WHERE s.id = p_session
           AND s.account_id = openseal_current_account()
           AND s.closed_at IS NULL
           AND s.status = 'preparing'
           AND s.expires_at > statement_timestamp()
    ), t AS (
        SELECT o.id, floor(extract(epoch FROM statement_timestamp()))::bigint + 600 AS expires
          FROM open_session o
    )
    SELECT t.expires,
           hmac(convert_to('openseal-keyd-asp-token-v1' || chr(10) || t.id::text || chr(10)
                           || t.expires::text, 'UTF8'),
                (SELECT k.key FROM openseal_keyd.asp_token_key k),
                'sha256')
      FROM t
$$;
REVOKE ALL ON FUNCTION openseal_keyd_asp_token(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openseal_keyd_asp_token(uuid) TO openseal_app;

-- The account of the open session `p_session` of provider `p_provider`, or nothing.
CREATE FUNCTION openseal_esign_session_account(p_session uuid, p_provider text)
RETURNS uuid
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
    SELECT s.account_id FROM remote_signing_sessions s
     WHERE s.id = p_session AND s.provider_id = p_provider AND s.closed_at IS NULL
$$;
REVOKE ALL ON FUNCTION openseal_esign_session_account(uuid, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openseal_esign_session_account(uuid, text) TO openseal_app;
