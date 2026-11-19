-- ASVS-16 and ASVS-18 (ASVS 8.3.2, 8.3.8; docs/07 §Data classification, docs/22 §9,
-- docs/32 §7): a staff user's erasure, account retention rules per data class, legal
-- holds, and the daily retention job.
--
-- 1. `users.erased_at`: the person's identity was erased (name, email, login binding,
--    password and second factor replaced or removed); the row stays because the records
--    an envelope keeps (its sender, the admin log's actor) name its id.
-- 2. `retention_rules`: one optional rule per account and data class, the days a record
--    of that class is kept after its last change; no rule keeps it for ever (the default:
--    nothing is deleted unless an administrator sets a rule). Replaces the unused
--    `retention_policies` (schema only since 0002, never read or written).
-- 3. `envelopes.legal_hold_at`: an envelope under legal hold is never purged by a rule.
-- 4. `openseal_enqueue_retention_jobs`: one `retention_sweep` job per account with a rule,
--    per UTC day, through a definer (the worker has no account to scope it).

ALTER TABLE users ADD COLUMN erased_at timestamptz;
GRANT SELECT (erased_at) ON users TO openseal_app;

DROP TABLE retention_policies;

CREATE TABLE retention_rules (
    account_id  uuid NOT NULL REFERENCES accounts (id),
    -- `draft`: drafts never sent; `ended`: declined, voided or expired envelopes;
    -- `completed`: completed envelopes (documents, certificate and personal data; the
    -- audit chain and a tombstone stay); `sessions`: ended staff sessions.
    data_class  text NOT NULL CHECK (data_class IN ('draft', 'ended', 'completed', 'sessions')),
    keep_days   integer NOT NULL CHECK (keep_days BETWEEN 1 AND 36500),
    updated_at  timestamptz NOT NULL,
    PRIMARY KEY (account_id, data_class)
);
SELECT openseal_tenant_table('retention_rules', true);

ALTER TABLE envelopes ADD COLUMN legal_hold_at timestamptz;

CREATE FUNCTION openseal_enqueue_retention_jobs(p_day date, p_now timestamptz)
RETURNS integer
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
DECLARE
    n integer;
BEGIN
    INSERT INTO jobs (id, account_id, envelope_id, kind, idempotency_key, payload, run_at, max_attempts)
    SELECT gen_random_uuid(), a.id, NULL, 'retention_sweep', 'retention:' || p_day::text,
           jsonb_build_object('day', p_day::text), p_now, 15
      FROM accounts AS a
     WHERE EXISTS (SELECT 1 FROM retention_rules AS r WHERE r.account_id = a.id)
    ON CONFLICT (account_id, idempotency_key) DO NOTHING;
    GET DIAGNOSTICS n = ROW_COUNT;
    RETURN n;
END
$$;
REVOKE ALL ON FUNCTION openseal_enqueue_retention_jobs(date, timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openseal_enqueue_retention_jobs(date, timestamptz) TO openseal_app;

-- 5. Erase the identity of `p_user`, a member of the current account and of no other
--    (SEC-ID-01: an attribute of a user of several accounts changes only by the person in
--    each of them), and disable their membership here. Through a definer because the
--    second-factor columns change only as the schema owner (0032's guard). True when
--    erased now; false when not a member here, a member of another account too, or
--    already erased. The admin event goes in the caller's transaction (the store).
CREATE FUNCTION openseal_erase_user(p_user uuid, p_now timestamptz) RETURNS boolean
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
DECLARE
    acct uuid := openseal_current_account();
    marker text := 'erased-' || replace(p_user::text, '-', '') || '@erased.invalid';
BEGIN
    IF acct IS NULL
       OR NOT EXISTS (SELECT 1 FROM account_memberships AS m
                       WHERE m.account_id = acct AND m.user_id = p_user)
       OR openseal_user_in_other_account(p_user) THEN
        RETURN false;
    END IF;
    UPDATE users
       SET email = marker, email_normalized = marker, name = 'Erased user',
           login_kind = 'local', idp_issuer = NULL, idp_subject = NULL, password_hash = NULL,
           totp_seed_sealed = NULL, totp_confirmed_at = NULL, totp_last_step = NULL,
           recovery_code_sha256 = '{}', disabled_at = COALESCE(disabled_at, p_now),
           erased_at = p_now
     WHERE id = p_user AND erased_at IS NULL;
    IF NOT FOUND THEN
        RETURN false;
    END IF;
    UPDATE account_memberships SET disabled_at = COALESCE(disabled_at, p_now)
     WHERE account_id = acct AND user_id = p_user;
    RETURN true;
END
$$;
REVOKE ALL ON FUNCTION openseal_erase_user(uuid, timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openseal_erase_user(uuid, timestamptz) TO openseal_app;
