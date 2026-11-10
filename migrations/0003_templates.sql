-- 0003: templates (docs/22 §7). A template is an envelope without people: documents,
-- roles, role-bound fields, message, settings and matching rules. Creating an envelope
-- copies from a template, never references it.

-- Every field type of docs/22 §6, shared by template and envelope fields.
CREATE FUNCTION openseal_is_field_type(t text) RETURNS boolean
    LANGUAGE sql IMMUTABLE PARALLEL SAFE
    SET search_path = pg_catalog
AS $$
    SELECT t IN (
        'signature', 'initials', 'stamp', 'date_signed',
        'name', 'first_name', 'last_name', 'email', 'company', 'title',
        'text', 'number', 'date', 'email_address', 'phone', 'ssn', 'zip',
        'envelope_id', 'checkbox', 'radio_group', 'dropdown', 'formula',
        'attachment', 'note', 'approve', 'decline', 'hyperlink', 'payment', 'drawing')
$$;

-- Every recipient type of docs/22 §5.
CREATE FUNCTION openseal_is_recipient_type(t text) RETURNS boolean
    LANGUAGE sql IMMUTABLE PARALLEL SAFE
    SET search_path = pg_catalog
AS $$
    SELECT t IN (
        'signer', 'in_person_signer', 'approver', 'viewer', 'cc', 'editor',
        'intermediary', 'agent', 'witness', 'seal', 'notary')
$$;

CREATE TABLE templates (
    id               uuid PRIMARY KEY,
    account_id       uuid NOT NULL REFERENCES accounts (id),
    owner_user_id    uuid NOT NULL,
    folder_id        uuid,
    name             text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 255),
    description      text CHECK (description IS NULL OR char_length(description) <= 10000),
    email_subject    text CHECK (email_subject IS NULL OR char_length(email_subject) <= 255),
    email_message    text CHECK (email_message IS NULL OR char_length(email_message) <= 10000),
    -- Envelope settings carried to envelopes made from this template.
    settings         jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(settings) = 'object'),
    -- Template matching on upload (slice 3).
    matching_rules   jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(matching_rules) = 'array'),
    -- Increments on every saved edit; optimistic concurrency, as envelopes.
    version          integer NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    UNIQUE (account_id, id),
    FOREIGN KEY (account_id, owner_user_id) REFERENCES account_memberships (account_id, user_id),
    FOREIGN KEY (account_id, folder_id) REFERENCES folders (account_id, id)
);
SELECT openseal_tenant_table('templates', true);

-- Sharing with a user, a group, or the whole account (exactly one).
CREATE TABLE template_shares (
    id            uuid PRIMARY KEY,
    account_id    uuid NOT NULL REFERENCES accounts (id),
    template_id   uuid NOT NULL,
    user_id       uuid,
    group_id      uuid,
    whole_account boolean NOT NULL DEFAULT false,
    can_edit      boolean NOT NULL DEFAULT false,
    UNIQUE (account_id, id),
    CHECK (num_nonnulls(user_id, group_id) + (CASE WHEN whole_account THEN 1 ELSE 0 END) = 1),
    FOREIGN KEY (account_id, template_id) REFERENCES templates (account_id, id),
    FOREIGN KEY (account_id, user_id) REFERENCES account_memberships (account_id, user_id),
    FOREIGN KEY (account_id, group_id) REFERENCES groups (account_id, id)
);
SELECT openseal_tenant_table('template_shares', true);

CREATE TABLE template_roles (
    id              uuid PRIMARY KEY,
    account_id      uuid NOT NULL REFERENCES accounts (id),
    template_id     uuid NOT NULL,
    name            text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 255),
    routing_order   integer NOT NULL CHECK (routing_order BETWEEN 1 AND 999),
    recipient_type  text NOT NULL CHECK (openseal_is_recipient_type(recipient_type)),
    -- Default authentication requirements, as `recipient_auth_requirements`.
    default_auth    jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(default_auth) = 'array'),
    UNIQUE (account_id, id),
    UNIQUE (account_id, template_id, name),
    FOREIGN KEY (account_id, template_id) REFERENCES templates (account_id, id)
);
SELECT openseal_tenant_table('template_roles', true);

CREATE TABLE template_documents (
    id            uuid PRIMARY KEY,
    account_id    uuid NOT NULL REFERENCES accounts (id),
    template_id   uuid NOT NULL,
    ord           integer NOT NULL CHECK (ord >= 0),
    -- Display only; never used as a path (docs/22 §4).
    name          text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 255),
    -- The normalized PDF's SHA-256, which is its blob key.
    sha256        bytea NOT NULL CHECK (octet_length(sha256) = 32),
    byte_len      bigint NOT NULL CHECK (byte_len > 0),
    page_count    integer NOT NULL CHECK (page_count > 0),
    pages         jsonb NOT NULL CHECK (jsonb_typeof(pages) = 'array'),
    UNIQUE (account_id, id),
    UNIQUE (account_id, template_id, ord),
    FOREIGN KEY (account_id, template_id) REFERENCES templates (account_id, id)
);
SELECT openseal_tenant_table('template_documents', true);

CREATE TABLE template_fields (
    id                    uuid PRIMARY KEY,
    account_id            uuid NOT NULL REFERENCES accounts (id),
    template_id           uuid NOT NULL,
    template_document_id  uuid NOT NULL,
    -- Bound to a role; envelope fields are bound to a recipient instead (docs/22 §6).
    role_id               uuid NOT NULL,
    type                  text NOT NULL CHECK (openseal_is_field_type(type)),
    page                  integer NOT NULL CHECK (page >= 1),
    -- Displayed page space, points, origin top-left (ADR-019).
    x                     numeric NOT NULL,
    y                     numeric NOT NULL,
    width                 numeric NOT NULL CHECK (width > 0),
    height                numeric NOT NULL CHECK (height > 0),
    required              boolean NOT NULL DEFAULT true,
    read_only             boolean NOT NULL DEFAULT false,
    locked                boolean NOT NULL DEFAULT false,
    label                 text CHECK (label IS NULL OR octet_length(label) BETWEEN 1 AND 255),
    -- The rest of docs/22 §6: anchor, default, validation, format, group, conditional,
    -- formula, options, allow_custom, tooltip, placeholder, as the model serializes them.
    spec                  jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(spec) = 'object'),
    UNIQUE (account_id, id),
    FOREIGN KEY (account_id, template_id) REFERENCES templates (account_id, id),
    FOREIGN KEY (account_id, template_document_id) REFERENCES template_documents (account_id, id),
    FOREIGN KEY (account_id, role_id) REFERENCES template_roles (account_id, id)
);
SELECT openseal_tenant_table('template_fields', true);
