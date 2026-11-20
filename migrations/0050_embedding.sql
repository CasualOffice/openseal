-- 0050: embedding (slice 9 `VS-09`, docs/40 §5, SEC-A06, SEC-A08).
--
-- 1. `recipient_tokens`: an embedded signing view (`purpose = 'embedded'`) may name the
--    origin of the host page that frames it (`frame_origin`: the page's
--    `frame-ancestors` and the only origin its events are posted to), where the
--    signer's browser goes when the view ends (`return_url`), and an opaque value the
--    host passed (`return_state`) given back with each event. Only an embedded token
--    carries them.
-- 2. `embed_views`: the prepare and correct views (`POST /envelopes/{id}/views/prepare`,
--    `/views/correct`). A view link is a 256-bit token stored as its SHA-256, living
--    five minutes, bound to the API client that asked and the member it acts as, and
--    spent once: its first `POST /e/{token}/session` sets `used_at` and a second secret,
--    the view session (stored as SHA-256 only), that authenticates the embedded editor
--    on that one envelope until `session_expires_at`.
-- 3. `openseal_resolve_embed_view` and `openseal_resolve_embed_session`: the workspace a
--    live view link or view session belongs to, found before any tenant is known, as
--    `openseal_resolve_recipient_token` (0007) finds a ceremony link's.

ALTER TABLE recipient_tokens
    ADD COLUMN frame_origin text
        CHECK (frame_origin IS NULL OR char_length(frame_origin) BETWEEN 1 AND 255),
    ADD COLUMN return_url text
        CHECK (return_url IS NULL OR char_length(return_url) BETWEEN 1 AND 2048),
    ADD COLUMN return_state text
        CHECK (return_state IS NULL OR char_length(return_state) <= 1024),
    ADD CONSTRAINT recipient_tokens_embedding_only_embedded
        CHECK (purpose = 'embedded'
            OR (frame_origin IS NULL AND return_url IS NULL AND return_state IS NULL));

CREATE TABLE embed_views (
    id                  uuid PRIMARY KEY,
    account_id          uuid NOT NULL REFERENCES accounts (id),
    envelope_id         uuid NOT NULL,
    kind                text NOT NULL CHECK (kind IN ('prepare', 'correct')),
    client_id           uuid NOT NULL,
    user_id             uuid NOT NULL,
    token_sha256        bytea NOT NULL UNIQUE CHECK (octet_length(token_sha256) = 32),
    expires_at          timestamptz NOT NULL,
    used_at             timestamptz,
    session_sha256      bytea UNIQUE
        CHECK (session_sha256 IS NULL OR octet_length(session_sha256) = 32),
    session_expires_at  timestamptz,
    frame_origin        text CHECK (frame_origin IS NULL OR char_length(frame_origin) BETWEEN 1 AND 255),
    return_url          text CHECK (return_url IS NULL OR char_length(return_url) BETWEEN 1 AND 2048),
    return_state        text CHECK (return_state IS NULL OR char_length(return_state) <= 1024),
    created_at          timestamptz NOT NULL,
    UNIQUE (account_id, id),
    -- Spent once, and spending it is what makes the session.
    CHECK ((used_at IS NULL) = (session_sha256 IS NULL)),
    CHECK ((session_sha256 IS NULL) = (session_expires_at IS NULL)),
    FOREIGN KEY (account_id, envelope_id) REFERENCES envelopes (account_id, id),
    FOREIGN KEY (account_id, client_id) REFERENCES api_clients (account_id, id),
    FOREIGN KEY (account_id, user_id)
        REFERENCES account_memberships (account_id, user_id) ON DELETE CASCADE
);
CREATE INDEX embed_views_account_envelope ON embed_views (account_id, envelope_id);
SELECT openseal_tenant_table('embed_views', true);

CREATE FUNCTION openseal_resolve_embed_view(p_token_sha256 bytea, p_now timestamptz)
RETURNS TABLE (account_id uuid)
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
    SELECT v.account_id FROM embed_views AS v
     WHERE v.token_sha256 = p_token_sha256 AND v.used_at IS NULL AND v.expires_at > p_now
$$;

CREATE FUNCTION openseal_resolve_embed_session(p_session_sha256 bytea, p_now timestamptz)
RETURNS TABLE (account_id uuid)
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
    SELECT v.account_id FROM embed_views AS v
     WHERE v.session_sha256 = p_session_sha256 AND v.session_expires_at > p_now
$$;

REVOKE ALL ON FUNCTION openseal_resolve_embed_view(bytea, timestamptz) FROM PUBLIC;
REVOKE ALL ON FUNCTION openseal_resolve_embed_session(bytea, timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openseal_resolve_embed_view(bytea, timestamptz) TO openseal_app;
GRANT EXECUTE ON FUNCTION openseal_resolve_embed_session(bytea, timestamptz) TO openseal_app;
