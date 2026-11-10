-- 0004: envelopes and everything inside one (docs/22 §3 to §6, docs/24 states).

CREATE TABLE bulk_sends (
    id             uuid PRIMARY KEY,
    account_id     uuid NOT NULL REFERENCES accounts (id),
    sender_user_id uuid NOT NULL,
    template_id    uuid NOT NULL,
    name           text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 255),
    status         text NOT NULL CHECK (status IN ('queued', 'sending', 'completed', 'cancelled')),
    row_count      integer NOT NULL CHECK (row_count >= 0),
    created_at     timestamptz NOT NULL DEFAULT now(),
    finished_at    timestamptz,
    UNIQUE (account_id, id),
    FOREIGN KEY (account_id, sender_user_id) REFERENCES account_memberships (account_id, user_id),
    FOREIGN KEY (account_id, template_id) REFERENCES templates (account_id, id)
);
SELECT openseal_tenant_table('bulk_sends', true);

CREATE TABLE envelopes (
    id                   uuid PRIMARY KEY,
    account_id           uuid NOT NULL REFERENCES accounts (id),
    sender_user_id       uuid NOT NULL,
    status               text NOT NULL CHECK (status IN (
                             'draft', 'sent', 'delivered', 'completing', 'completed',
                             'declined', 'voided', 'expired')),
    subject              text NOT NULL DEFAULT '' CHECK (char_length(subject) <= 255),
    message              text NOT NULL DEFAULT '' CHECK (char_length(message) <= 10000),
    routing_mode         text NOT NULL DEFAULT 'sequential'
                             CHECK (routing_mode IN ('sequential', 'parallel', 'mixed')),
    expires_at           timestamptz,
    -- First reminder after N days, then every M days (docs/22 §3).
    reminder_policy      jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(reminder_policy) = 'object'),
    signing_options      jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(signing_options) = 'object'),
    seal_profile         text NOT NULL DEFAULT 'pades-b-t'
                             CHECK (seal_profile IN ('pades-b-t', 'pades-b-lt', 'pades-b-lta')),
    completion_delivery  jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(completion_delivery) = 'object'),
    brand_id             uuid,
    template_ids         uuid[] NOT NULL DEFAULT '{}',
    bulk_send_id         uuid,
    folder_id            uuid,
    -- Optimistic concurrency (docs/24 §1, CS-WF-0002).
    version              integer NOT NULL DEFAULT 1 CHECK (version > 0),
    -- Hash of the last audit event; maintained by the audit table's insert trigger.
    chain_head           bytea CHECK (chain_head IS NULL OR octet_length(chain_head) = 32),
    created_at           timestamptz NOT NULL DEFAULT now(),
    sent_at              timestamptz,
    completed_at         timestamptz,
    voided_at            timestamptz,
    void_reason          text CHECK (void_reason IS NULL OR char_length(void_reason) <= 10000),
    UNIQUE (account_id, id),
    FOREIGN KEY (account_id, sender_user_id) REFERENCES account_memberships (account_id, user_id),
    FOREIGN KEY (account_id, brand_id) REFERENCES brands (account_id, id),
    FOREIGN KEY (account_id, bulk_send_id) REFERENCES bulk_sends (account_id, id),
    FOREIGN KEY (account_id, folder_id) REFERENCES folders (account_id, id),
    CHECK ((status = 'voided') = (voided_at IS NOT NULL))
);
CREATE INDEX envelopes_account_status ON envelopes (account_id, status, created_at DESC);
CREATE INDEX envelopes_account_sender ON envelopes (account_id, sender_user_id, created_at DESC);
SELECT openseal_tenant_table('envelopes', true);

CREATE TABLE bulk_send_rows (
    id            uuid PRIMARY KEY,
    account_id    uuid NOT NULL REFERENCES accounts (id),
    bulk_send_id  uuid NOT NULL,
    row_index     integer NOT NULL CHECK (row_index >= 0),
    -- Recipients and field values for this row; personal data.
    input         jsonb NOT NULL CHECK (jsonb_typeof(input) = 'object'),
    status        text NOT NULL CHECK (status IN ('pending', 'sent', 'failed', 'cancelled')),
    envelope_id   uuid,
    error_code    text,
    UNIQUE (account_id, id),
    UNIQUE (bulk_send_id, row_index),
    FOREIGN KEY (account_id, bulk_send_id) REFERENCES bulk_sends (account_id, id),
    FOREIGN KEY (account_id, envelope_id) REFERENCES envelopes (account_id, id)
);
SELECT openseal_tenant_table('bulk_send_rows', true);

CREATE TABLE documents (
    id            uuid PRIMARY KEY,
    account_id    uuid NOT NULL REFERENCES accounts (id),
    envelope_id   uuid NOT NULL,
    ord           integer NOT NULL CHECK (ord >= 0),
    -- Display only; never used as a path (docs/22 §4).
    name          text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 255),
    created_at    timestamptz NOT NULL DEFAULT now(),
    UNIQUE (account_id, id),
    UNIQUE (envelope_id, ord) DEFERRABLE INITIALLY IMMEDIATE,
    FOREIGN KEY (account_id, envelope_id) REFERENCES envelopes (account_id, id)
);
CREATE INDEX documents_account_envelope ON documents (account_id, envelope_id);
SELECT openseal_tenant_table('documents', true);

-- Immutable blob references (docs/22 §4). `blob_key` is the content's SHA-256.
CREATE TABLE document_versions (
    id                 uuid PRIMARY KEY,
    account_id         uuid NOT NULL REFERENCES accounts (id),
    document_id        uuid NOT NULL,
    kind               text NOT NULL CHECK (kind IN ('original', 'normalized', 'flattened', 'sealed')),
    sha256             bytea NOT NULL CHECK (octet_length(sha256) = 32),
    byte_len           bigint NOT NULL CHECK (byte_len > 0),
    page_count         integer NOT NULL CHECK (page_count >= 0),
    -- What admission found and neutralized (docs/30); NULL for kinds other than normalized.
    admission_report   jsonb,
    -- Per page mediabox, cropbox, rotate and size in points.
    pages              jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(pages) = 'array'),
    created_at         timestamptz NOT NULL DEFAULT now(),
    UNIQUE (account_id, id),
    FOREIGN KEY (account_id, document_id) REFERENCES documents (account_id, id)
);
CREATE INDEX document_versions_account_document ON document_versions (account_id, document_id);
SELECT openseal_tenant_table('document_versions', true);

CREATE TABLE recipients (
    id                       uuid PRIMARY KEY,
    account_id               uuid NOT NULL REFERENCES accounts (id),
    envelope_id              uuid NOT NULL,
    routing_order            integer NOT NULL CHECK (routing_order BETWEEN 1 AND 999),
    type                     text NOT NULL CHECK (openseal_is_recipient_type(type)),
    role_name                text CHECK (role_name IS NULL OR char_length(role_name) BETWEEN 1 AND 255),
    -- Personal data (docs/07 §Data classification): never logged.
    name                     text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 255),
    email                    text CHECK (email IS NULL OR char_length(email) BETWEEN 3 AND 320),
    phone                    text CHECK (phone IS NULL OR char_length(phone) BETWEEN 3 AND 32),
    status                   text NOT NULL DEFAULT 'created' CHECK (status IN (
                                 'created', 'sent', 'delivered', 'authenticated', 'completed',
                                 'declined', 'auto_responded', 'reassigned')),
    delivery                 text NOT NULL DEFAULT 'email' CHECK (delivery IN ('email', 'sms', 'none')),
    embedded_client_user_id  text CHECK (embedded_client_user_id IS NULL
                                 OR char_length(embedded_client_user_id) BETWEEN 1 AND 255),
    signing_group_id         uuid,
    -- ERSD version accepted and when; the audit chain is the evidence, this is the index.
    consent                  jsonb,
    language                 text CHECK (language IS NULL OR char_length(language) BETWEEN 2 AND 35),
    declined_reason          text CHECK (declined_reason IS NULL OR char_length(declined_reason) <= 10000),
    reassigned_to            uuid,
    created_at               timestamptz NOT NULL DEFAULT now(),
    UNIQUE (account_id, id),
    FOREIGN KEY (account_id, envelope_id) REFERENCES envelopes (account_id, id),
    FOREIGN KEY (account_id, signing_group_id) REFERENCES groups (account_id, id),
    FOREIGN KEY (account_id, reassigned_to) REFERENCES recipients (account_id, id)
);
CREATE INDEX recipients_account_envelope ON recipients (account_id, envelope_id, routing_order);
SELECT openseal_tenant_table('recipients', true);

-- One row per authentication requirement on a recipient (docs/22 §5 `auth`).
CREATE TABLE recipient_auth_requirements (
    id              uuid PRIMARY KEY,
    account_id      uuid NOT NULL REFERENCES accounts (id),
    recipient_id    uuid NOT NULL,
    kind            text NOT NULL CHECK (kind IN (
                        'access_code', 'email_otp', 'sms_otp', 'phone_call', 'idp', 'idv', 'kba')),
    -- Argon2id PHC string, `access_code` only (SEC-A03).
    access_code_hash text,
    -- OIDC issuer, IDV provider or KBA plugin name, and their settings.
    config          jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(config) = 'object'),
    failed_attempts integer NOT NULL DEFAULT 0 CHECK (failed_attempts >= 0),
    locked_at       timestamptz,
    UNIQUE (account_id, id),
    CHECK ((kind = 'access_code') = (access_code_hash IS NOT NULL)),
    FOREIGN KEY (account_id, recipient_id) REFERENCES recipients (account_id, id)
);
SELECT openseal_tenant_table('recipient_auth_requirements', true);

-- Invitation tokens (docs/22 §2, SEC-A01): 256-bit random, stored only as SHA-256,
-- bound to one recipient, expiring, revocable.
CREATE TABLE recipient_tokens (
    id             uuid PRIMARY KEY,
    account_id     uuid NOT NULL REFERENCES accounts (id),
    envelope_id    uuid NOT NULL,
    recipient_id   uuid NOT NULL,
    token_sha256   bytea NOT NULL UNIQUE CHECK (octet_length(token_sha256) = 32),
    purpose        text NOT NULL CHECK (purpose IN ('invitation', 'reminder', 'embedded', 'completed_copy')),
    expires_at     timestamptz NOT NULL,
    revoked_at     timestamptz,
    first_used_at  timestamptz,
    created_at     timestamptz NOT NULL DEFAULT now(),
    UNIQUE (account_id, id),
    FOREIGN KEY (account_id, envelope_id) REFERENCES envelopes (account_id, id),
    FOREIGN KEY (account_id, recipient_id) REFERENCES recipients (account_id, id)
);
CREATE INDEX recipient_tokens_account_recipient ON recipient_tokens (account_id, recipient_id);
SELECT openseal_tenant_table('recipient_tokens', true);

CREATE TABLE signature_adoptions (
    id             uuid PRIMARY KEY,
    account_id     uuid NOT NULL REFERENCES accounts (id),
    recipient_id   uuid NOT NULL,
    mark           text NOT NULL CHECK (mark IN ('signature', 'initials', 'stamp')),
    method         text NOT NULL CHECK (method IN ('draw', 'type', 'upload')),
    -- The re-encoded image's SHA-256 (its blob key); personal data.
    image_sha256   bytea NOT NULL CHECK (octet_length(image_sha256) = 32),
    adopted_at     timestamptz NOT NULL,
    UNIQUE (account_id, id),
    FOREIGN KEY (account_id, recipient_id) REFERENCES recipients (account_id, id)
);
SELECT openseal_tenant_table('signature_adoptions', true);

CREATE TABLE fields (
    id            uuid PRIMARY KEY,
    account_id    uuid NOT NULL REFERENCES accounts (id),
    envelope_id   uuid NOT NULL,
    document_id   uuid NOT NULL,
    recipient_id  uuid NOT NULL,
    type          text NOT NULL CHECK (openseal_is_field_type(type)),
    page          integer NOT NULL CHECK (page >= 1),
    -- Displayed page space, points, origin top-left (ADR-019). Never pixels.
    x             numeric NOT NULL,
    y             numeric NOT NULL,
    width         numeric NOT NULL CHECK (width > 0),
    height        numeric NOT NULL CHECK (height > 0),
    required      boolean NOT NULL DEFAULT true,
    read_only     boolean NOT NULL DEFAULT false,
    locked        boolean NOT NULL DEFAULT false,
    label         text CHECK (label IS NULL OR octet_length(label) BETWEEN 1 AND 255),
    -- anchor, default, validation, format, group, conditional, formula, options,
    -- allow_custom, tooltip, placeholder (docs/22 §6), as the model serializes them.
    spec          jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(spec) = 'object'),
    UNIQUE (account_id, id),
    FOREIGN KEY (account_id, envelope_id) REFERENCES envelopes (account_id, id),
    FOREIGN KEY (account_id, document_id) REFERENCES documents (account_id, id),
    FOREIGN KEY (account_id, recipient_id) REFERENCES recipients (account_id, id)
);
CREATE INDEX fields_account_envelope ON fields (account_id, envelope_id);
SELECT openseal_tenant_table('fields', true);

-- The value a recipient (or the server, for `date_signed` and formulas) gave a field.
-- Document content: never logged. The audit chain records only `value_sha256`.
CREATE TABLE field_values (
    field_id       uuid PRIMARY KEY,
    account_id     uuid NOT NULL REFERENCES accounts (id),
    envelope_id    uuid NOT NULL,
    recipient_id   uuid NOT NULL,
    value          jsonb NOT NULL,
    value_sha256   bytea NOT NULL CHECK (octet_length(value_sha256) = 32),
    set_at         timestamptz NOT NULL,
    UNIQUE (account_id, field_id),
    FOREIGN KEY (account_id, field_id) REFERENCES fields (account_id, id),
    FOREIGN KEY (account_id, envelope_id) REFERENCES envelopes (account_id, id),
    FOREIGN KEY (account_id, recipient_id) REFERENCES recipients (account_id, id)
);
CREATE INDEX field_values_account_envelope ON field_values (account_id, envelope_id);
SELECT openseal_tenant_table('field_values', true);

-- Conditional routing (slice 29).
CREATE TABLE routing_rules (
    id            uuid PRIMARY KEY,
    account_id    uuid NOT NULL REFERENCES accounts (id),
    envelope_id   uuid NOT NULL,
    ord           integer NOT NULL CHECK (ord >= 0),
    rule          jsonb NOT NULL CHECK (jsonb_typeof(rule) = 'object'),
    UNIQUE (account_id, id),
    FOREIGN KEY (account_id, envelope_id) REFERENCES envelopes (account_id, id)
);
SELECT openseal_tenant_table('routing_rules', true);

-- Integrator metadata, searchable by name (docs/22 §3 `custom_fields`; 100 per envelope, docs/21).
CREATE TABLE envelope_custom_fields (
    account_id    uuid NOT NULL REFERENCES accounts (id),
    envelope_id   uuid NOT NULL,
    name          text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 100),
    value         text NOT NULL CHECK (char_length(value) <= 1000),
    show_to_recipients boolean NOT NULL DEFAULT false,
    PRIMARY KEY (account_id, envelope_id, name),
    FOREIGN KEY (account_id, envelope_id) REFERENCES envelopes (account_id, id)
);
CREATE INDEX envelope_custom_fields_search ON envelope_custom_fields (account_id, name, value);
SELECT openseal_tenant_table('envelope_custom_fields', true);

-- Comments (slice 26). Personal data in `body`.
CREATE TABLE comments (
    id                  uuid PRIMARY KEY,
    account_id          uuid NOT NULL REFERENCES accounts (id),
    envelope_id         uuid NOT NULL,
    author_user_id      uuid,
    author_recipient_id uuid,
    thread_id           uuid,
    body                text NOT NULL CHECK (char_length(body) BETWEEN 1 AND 10000),
    created_at          timestamptz NOT NULL,
    UNIQUE (account_id, id),
    CHECK (num_nonnulls(author_user_id, author_recipient_id) = 1),
    FOREIGN KEY (account_id, envelope_id) REFERENCES envelopes (account_id, id),
    FOREIGN KEY (account_id, author_user_id) REFERENCES account_memberships (account_id, user_id),
    FOREIGN KEY (account_id, author_recipient_id) REFERENCES recipients (account_id, id),
    FOREIGN KEY (account_id, thread_id) REFERENCES comments (account_id, id)
);
SELECT openseal_tenant_table('comments', true);
