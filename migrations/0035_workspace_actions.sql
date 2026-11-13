-- 0035: the workspace action catalogue and delegated workspace administration (ORG-07;
-- ADR-028 (d), docs/23 §2.2).
--
-- 1. A custom permission profile may name workspace actions (server `authz.rs`
--    `Action`) as well as the scopes of docs/40 §2 and `view_all_envelopes` it named
--    before (0033): `users.invite` alone, say, instead of the whole of `admin:users`.
--    The list below is the catalogue; a name outside it is refused by the database as
--    well as by the API, so no stored profile carries a name a later server would read
--    as a grant it never meant.
-- 2. `admin_scope_group_ids`: a delegated workspace admin's group scope. NULL is the
--    whole workspace. With a scope, the profile's holders read and change only members
--    of those groups (the server enforces it per request); a profile with a scope never
--    holds a sensitive action (docs/23 §2.2), refused here as well as by the API.
--    The ids are this workspace's groups: the API checks each on write, and a group
--    deleted later simply matches no member (a narrower scope, never a wider one).
--
-- A change to either column is a profile change: 0020's deferred check already refuses
-- one by the application role without its admin event (CS-DB-0008). Row-level security
-- is 0002's: unchanged.

ALTER TABLE permission_profiles DROP CONSTRAINT permission_profiles_known_permissions;
ALTER TABLE permission_profiles
    ADD CONSTRAINT permission_profiles_known_permissions CHECK (permissions <@ ARRAY[
        'envelopes:read', 'envelopes:write', 'envelopes:send', 'templates:read',
        'templates:write', 'bulk:send', 'webhooks:manage', 'admin:users', 'admin:account',
        'audit:read', 'view_all_envelopes',
        'envelopes.read', 'envelopes.write', 'envelopes.send', 'templates.read',
        'templates.write', 'bulk.send', 'audit.read',
        'users.read', 'users.invite', 'users.update', 'users.disable', 'users.remove',
        'groups.manage', 'profiles.manage',
        'settings.sending', 'settings.signing', 'ersd.manage',
        'settings.security', 'brands.manage', 'retention.manage',
        'api_clients.manage', 'webhooks.manage',
        'envelopes.read_all', 'envelopes.transfer',
        'templates.share_workspace', 'reports.read', 'usage.read', 'admin_audit.read'
    ]::text[]);

ALTER TABLE permission_profiles ADD COLUMN admin_scope_group_ids uuid[];

-- Sensitive actions, and the old names that carry them, never with a group scope.
ALTER TABLE permission_profiles
    ADD CONSTRAINT permission_profiles_scope_not_sensitive CHECK (
        admin_scope_group_ids IS NULL
        OR (kind = 'custom' AND NOT (permissions && ARRAY[
            'admin:account', 'webhooks:manage', 'view_all_envelopes',
            'settings.security', 'brands.manage', 'retention.manage',
            'api_clients.manage', 'webhooks.manage',
            'envelopes.read_all', 'envelopes.transfer'
        ]::text[])));
