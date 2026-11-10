-- 0006: signing links (PowerForms, docs/24 §9) and webhooks (docs/40 §4, ADR-016).

CREATE TABLE signing_links (
    id              uuid PRIMARY KEY,
    account_id      uuid NOT NULL REFERENCES accounts (id),
    template_id     uuid NOT NULL,
    owner_user_id   uuid NOT NULL,
    -- The public URL carries a 256-bit random token; only its SHA-256 is stored.
    token_sha256    bytea NOT NULL UNIQUE CHECK (octet_length(token_sha256) = 32),
    -- The template role the visitor takes.
    role_id         uuid NOT NULL,
    verify_email    boolean NOT NULL DEFAULT true,
    max_uses        integer CHECK (max_uses IS NULL OR max_uses > 0),
    use_count       integer NOT NULL DEFAULT 0 CHECK (use_count >= 0),
    expires_at      timestamptz,
    disabled_at     timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (account_id, id),
    CHECK (max_uses IS NULL OR use_count <= max_uses),
    FOREIGN KEY (account_id, template_id) REFERENCES templates (account_id, id),
    FOREIGN KEY (account_id, owner_user_id) REFERENCES account_memberships (account_id, user_id),
    FOREIGN KEY (account_id, role_id) REFERENCES template_roles (account_id, id)
);
SELECT openseal_tenant_table('signing_links', true);

CREATE TABLE webhook_subscriptions (
    id              uuid PRIMARY KEY,
    account_id      uuid NOT NULL REFERENCES accounts (id),
    -- Per-envelope subscriptions (DocuSign's `eventNotification`) set this.
    envelope_id     uuid,
    url             text NOT NULL CHECK (char_length(url) BETWEEN 9 AND 2048 AND url LIKE 'https://%'),
    event_types     text[] NOT NULL CHECK (cardinality(event_types) > 0),
    -- Filters by sender and template (docs/40 §4).
    sender_user_id  uuid,
    template_id     uuid,
    -- References into the secrets store (several active for rotation); never the secrets.
    secret_refs     text[] NOT NULL CHECK (cardinality(secret_refs) BETWEEN 1 AND 4),
    status          text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    failing_since   timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (account_id, id),
    FOREIGN KEY (account_id, envelope_id) REFERENCES envelopes (account_id, id),
    FOREIGN KEY (account_id, sender_user_id) REFERENCES account_memberships (account_id, user_id),
    FOREIGN KEY (account_id, template_id) REFERENCES templates (account_id, id)
);
SELECT openseal_tenant_table('webhook_subscriptions', true);

-- Operational log, not evidence (docs/32 §3: `webhook.delivered` is not in the chain).
CREATE TABLE webhook_deliveries (
    id               uuid PRIMARY KEY,
    account_id       uuid NOT NULL REFERENCES accounts (id),
    subscription_id  uuid NOT NULL,
    event_id         uuid NOT NULL,
    event_type       text NOT NULL CHECK (char_length(event_type) BETWEEN 1 AND 64),
    -- `{id, type, created_at, account_id, data}`; never documents (ADR-016).
    payload          jsonb NOT NULL CHECK (jsonb_typeof(payload) = 'object'),
    status           text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'delivered', 'failed')),
    attempts         integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    next_attempt_at  timestamptz,
    last_status_code integer,
    created_at       timestamptz NOT NULL DEFAULT now(),
    delivered_at     timestamptz,
    UNIQUE (account_id, id),
    UNIQUE (subscription_id, event_id),
    FOREIGN KEY (account_id, subscription_id) REFERENCES webhook_subscriptions (account_id, id)
);
CREATE INDEX webhook_deliveries_account_subscription ON webhook_deliveries (account_id, subscription_id, created_at DESC);
SELECT openseal_tenant_table('webhook_deliveries', true);
