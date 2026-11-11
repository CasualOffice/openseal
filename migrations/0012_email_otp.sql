-- 0012: email one-time codes for recipient authentication (SEC-A02, docs/07).
--
-- A recipient whose sender requires `email_otp` asks for a code from the signing page;
-- the server opens a row here and queues a job, and the worker draws a 6-digit code as
-- it sends, stores only its Argon2id PHC string, and emails it. The code itself is never
-- stored, queued, logged or recorded in the audit chain.
--
-- At most one open code per recipient (the partial unique index): asking again closes
-- the earlier one (`superseded`). A code closes when it passes (`used`, so a replay is
-- refused), after five wrong tries (`exhausted`), or when the recipient is locked
-- (`revoked`). Every row stays: the count of rows in the last hour limits resends.

CREATE TABLE recipient_otp_codes (
    id            uuid PRIMARY KEY,
    account_id    uuid NOT NULL REFERENCES accounts (id),
    recipient_id  uuid NOT NULL,
    -- Argon2id PHC string of the code, set by the worker as it sends; NULL until then.
    code_hash     text,
    created_at    timestamptz NOT NULL,
    expires_at    timestamptz NOT NULL,
    sent_at       timestamptz,
    attempts      integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    closed_at     timestamptz,
    closed_reason text CHECK (closed_reason IN ('used', 'superseded', 'exhausted', 'revoked')),
    UNIQUE (account_id, id),
    CHECK (expires_at > created_at),
    CHECK ((code_hash IS NULL) = (sent_at IS NULL)),
    CHECK ((closed_at IS NULL) = (closed_reason IS NULL)),
    FOREIGN KEY (account_id, recipient_id) REFERENCES recipients (account_id, id)
);
CREATE INDEX recipient_otp_codes_recent
    ON recipient_otp_codes (account_id, recipient_id, created_at DESC);
CREATE UNIQUE INDEX recipient_otp_codes_one_open
    ON recipient_otp_codes (account_id, recipient_id) WHERE closed_at IS NULL;
SELECT openseal_tenant_table('recipient_otp_codes', true);
