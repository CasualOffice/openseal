-- 0002: accounts, staff users and what hangs off the account (docs/22 §1, §8).
--
-- Every tenant table has `account_id uuid NOT NULL`, `UNIQUE (account_id, id)` so that
-- children reference their parent through `(account_id, parent_id)` (a row can never
-- point at another tenant's row, enforced by the database), and an index leading with
-- `account_id`. Enumerations are text with CHECK constraints; widening one is a new
-- migration.

-- The tenant itself. Row-level security keys on `id`: an account sees only itself.
CREATE TABLE accounts (
    id               uuid PRIMARY KEY,
    name             text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 255),
    -- Plan limits, default ERSD, allowed auth methods, data region tag, date formats,
    -- reminder defaults, seal profile, TSA list, signature font set (docs/22 §8).
    settings         jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(settings) = 'object'),
    data_region      text,
    created_at       timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE accounts ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON accounts
    USING (id = openseal_current_account())
    WITH CHECK (id = openseal_current_account());
GRANT SELECT, INSERT, UPDATE ON accounts TO openseal_app;

-- Staff users. The one identity table without `account_id`: a user belongs to one or more
-- accounts through `account_memberships`, and is visible to an account only through a
-- membership (policy below). Recipients are never users (docs/22 §8).
CREATE TABLE users (
    id                  uuid PRIMARY KEY,
    -- Personal data (docs/07 §Data classification): never logged.
    email               text NOT NULL CHECK (char_length(email) BETWEEN 3 AND 320),
    email_normalized    text NOT NULL UNIQUE CHECK (char_length(email_normalized) BETWEEN 3 AND 320),
    name                text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 255),
    -- `oidc`, `saml` or `local` (password with TOTP or WebAuthn).
    login_kind          text NOT NULL CHECK (login_kind IN ('oidc', 'saml', 'local')),
    -- Issuer and subject for OIDC/SAML; NULL for local logins.
    idp_issuer          text,
    idp_subject         text,
    -- Argon2id PHC string for local logins; never returned by the store.
    password_hash       text,
    disabled_at         timestamptz,
    created_at          timestamptz NOT NULL DEFAULT now(),
    UNIQUE (idp_issuer, idp_subject)
);

CREATE TABLE permission_profiles (
    id           uuid PRIMARY KEY,
    account_id   uuid NOT NULL REFERENCES accounts (id),
    name         text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 255),
    -- `admin`, `sender`, `viewer` built in, or `custom`.
    kind         text NOT NULL CHECK (kind IN ('admin', 'sender', 'viewer', 'custom')),
    -- Send, use templates, create templates, bulk send, manage users, manage brands,
    -- view all envelopes, API access (docs/22 §8).
    permissions  text[] NOT NULL DEFAULT '{}',
    created_at   timestamptz NOT NULL DEFAULT now(),
    UNIQUE (account_id, id),
    UNIQUE (account_id, name)
);
SELECT openseal_tenant_table('permission_profiles', true);

CREATE TABLE account_memberships (
    account_id             uuid NOT NULL REFERENCES accounts (id),
    user_id                uuid NOT NULL REFERENCES users (id),
    permission_profile_id  uuid NOT NULL,
    created_at             timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, user_id),
    FOREIGN KEY (account_id, permission_profile_id) REFERENCES permission_profiles (account_id, id)
);
CREATE INDEX account_memberships_user ON account_memberships (user_id);
SELECT openseal_tenant_table('account_memberships', true);

ALTER TABLE users ENABLE ROW LEVEL SECURITY;
-- A user row is visible and changeable only through a membership of the current account.
-- Insertion is open so that a user and their first membership are written in one
-- transaction; a user row with no membership is visible to no tenant.
CREATE POLICY member_of_current_account ON users
    USING (EXISTS (
        SELECT 1 FROM account_memberships m
        WHERE m.user_id = users.id AND m.account_id = openseal_current_account()));
CREATE POLICY insert_user ON users FOR INSERT WITH CHECK (openseal_current_account() IS NOT NULL);
GRANT SELECT, INSERT, UPDATE ON users TO openseal_app;

CREATE TABLE groups (
    id           uuid PRIMARY KEY,
    account_id   uuid NOT NULL REFERENCES accounts (id),
    name         text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 255),
    created_at   timestamptz NOT NULL DEFAULT now(),
    UNIQUE (account_id, id),
    UNIQUE (account_id, name)
);
SELECT openseal_tenant_table('groups', true);

CREATE TABLE group_members (
    account_id   uuid NOT NULL,
    group_id     uuid NOT NULL,
    user_id      uuid NOT NULL,
    PRIMARY KEY (account_id, group_id, user_id),
    FOREIGN KEY (account_id, group_id) REFERENCES groups (account_id, id),
    FOREIGN KEY (account_id, user_id) REFERENCES account_memberships (account_id, user_id)
);
SELECT openseal_tenant_table('group_members', true);

CREATE TABLE brands (
    id           uuid PRIMARY KEY,
    account_id   uuid NOT NULL REFERENCES accounts (id),
    name         text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 255),
    -- Colours, logo blob key, email texts, signing-page texts, `frame-ancestors`.
    settings     jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(settings) = 'object'),
    logo_sha256  bytea CHECK (logo_sha256 IS NULL OR octet_length(logo_sha256) = 32),
    created_at   timestamptz NOT NULL DEFAULT now(),
    UNIQUE (account_id, id)
);
SELECT openseal_tenant_table('brands', true);

-- Electronic record and signature disclosure versions (docs/22 §1). Immutable once
-- published: a change is a new version, since consent events record the version's hash.
CREATE TABLE ersd_versions (
    id            uuid PRIMARY KEY,
    account_id    uuid NOT NULL REFERENCES accounts (id),
    version       integer NOT NULL CHECK (version > 0),
    language      text NOT NULL CHECK (char_length(language) BETWEEN 2 AND 35),
    text_sha256   bytea NOT NULL CHECK (octet_length(text_sha256) = 32),
    body          text NOT NULL,
    published_at  timestamptz,
    created_at    timestamptz NOT NULL DEFAULT now(),
    UNIQUE (account_id, id),
    UNIQUE (account_id, version, language)
);
SELECT openseal_tenant_table('ersd_versions', true);

CREATE TABLE retention_policies (
    id                    uuid PRIMARY KEY,
    account_id            uuid NOT NULL REFERENCES accounts (id),
    name                  text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 255),
    -- Days after completion (or void, decline, expiry) before purge; NULL keeps forever.
    keep_completed_days   integer CHECK (keep_completed_days > 0),
    keep_incomplete_days  integer CHECK (keep_incomplete_days > 0),
    created_at            timestamptz NOT NULL DEFAULT now(),
    UNIQUE (account_id, id)
);
SELECT openseal_tenant_table('retention_policies', true);

-- OAuth2 applications and personal API keys (docs/40 §2). Secrets are stored hashed,
-- with a short public prefix for secret scanning (SEC-A10).
CREATE TABLE api_clients (
    id               uuid PRIMARY KEY,
    account_id       uuid NOT NULL REFERENCES accounts (id),
    kind             text NOT NULL CHECK (kind IN ('oauth_app', 'api_key', 'jwt_integration')),
    name             text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 255),
    owner_user_id    uuid,
    key_prefix       text CHECK (key_prefix IS NULL OR char_length(key_prefix) BETWEEN 4 AND 32),
    secret_sha256    bytea UNIQUE CHECK (secret_sha256 IS NULL OR octet_length(secret_sha256) = 32),
    -- PEM public key for the RFC 7523 JWT bearer grant.
    public_key_pem   text,
    redirect_uris    text[] NOT NULL DEFAULT '{}',
    scopes           text[] NOT NULL DEFAULT '{}',
    expires_at       timestamptz,
    last_used_at     timestamptz,
    revoked_at       timestamptz,
    created_at       timestamptz NOT NULL DEFAULT now(),
    UNIQUE (account_id, id),
    FOREIGN KEY (account_id, owner_user_id) REFERENCES account_memberships (account_id, user_id)
);
SELECT openseal_tenant_table('api_clients', true);

-- Folders for envelopes and templates, including each user's recycle folder (docs/22 §9:
-- "deleted" envelopes move to the recycle folder and are purged only by retention).
CREATE TABLE folders (
    id              uuid PRIMARY KEY,
    account_id      uuid NOT NULL REFERENCES accounts (id),
    owner_user_id   uuid,
    kind            text NOT NULL CHECK (kind IN ('envelopes', 'templates', 'recycle')),
    parent_id       uuid,
    name            text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 255),
    created_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (account_id, id),
    FOREIGN KEY (account_id, parent_id) REFERENCES folders (account_id, id),
    FOREIGN KEY (account_id, owner_user_id) REFERENCES account_memberships (account_id, user_id)
);
SELECT openseal_tenant_table('folders', true);
