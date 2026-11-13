# 23 — Organizations, workspaces, delegated administration, platform console and plans

**Status: Designed. ADR-028 Accepted (owner, 2026-11-12, instruction 29). Built so far: the organizations migration
and the organization scope of the store (`ORG-02`, §2.1 As built); the console's server side: the `platform` schema
and role, operator identity with mandatory TOTP, the operator log, organization and workspace reads and first writes,
and health reads (`CON-02`, `CON-03`, parts of `CON-04` and `CON-05`; §5.6 As built)**; each
part is built by the rows named in §12, and a part counts only when its row's exit is met. Owner instructions 24 and 25
([03](03-OWNER-INSTRUCTIONS.md)) set the shape: organization → workspaces; organization admins own SSO, domains and
policy across workspaces; workspace admins run one; delegated admins hold a scoped subset of admin rights; a separate
platform console with its own operator identity and MFA, no access to agreement contents or personal data, and its
own operator audit log; plans as entitlements, quotas, metering, enforcement and usage export, with billing later as a
plugin. The bar: a DocuSign or SignNow customer switches and misses nothing.

Instruction 29 accepted the recommended answer to each of the ten questions, on condition that the adversarial review's
findings were folded in. They are: every CRITICAL, HIGH and MEDIUM finding is fixed in the text below or answered with a
reason, and §13 maps each finding to where.

Reads with [22](22-DATA-MODEL.md) (tenancy as built), [07](07-SECURITY-THREAT-MODEL.md),
[40](40-API-DESIGN.md), [31](31-SEALING-AND-SIGNATURES.md) §5 (keyd), [19](19-WORKSPACE-SCAFFOLD-DESIGN.md),
[24](24-ENVELOPE-LIFECYCLE-AND-ROUTING.md), [32](32-AUDIT-TRAIL-AND-EVIDENCE.md), [48](48-DOCUSIGN-STUDY.md) §9,
[49](49-SIGNNOW-STUDY.md) §8.

## Owner's answers (instruction 29)

| # | Question | Answer |
| --- | --- | --- |
| Q1 | Name of the workspace level | "Workspace" on screen; `account` stays in the database and API v1 (§1) |
| Q2 | Envelopes between workspaces | Never moved. Ownership transfers within a workspace; a completed agreement's evidence package is exported and imported read-only (§2.4) |
| Q3 | Support access to a workspace | No impersonation of any kind; a customer invites a support person as an ordinary member (§5.1) |
| Q4 | Owner lock-out | Recovery by two operators, only to an address in a domain the organization verified, copied into its admin log (§5.1) |
| Q5 | Who creates organizations | Operators; self-sign-up is a console setting, off by default (§5.3) |
| Q6 | What a seat is | Set per plan; default: enabled members whose profile can send (§7.2) |
| Q7 | A spent quota | Each plan sets hard, soft or notify per quota; signing, sealing and timestamping of sent envelopes are never blocked (§7.3) |
| Q8 | Operator passkeys | TOTP now; a permissively licensed WebAuthn crate after review (§5.1) |
| Q9 | Organization admins and agreements | Only by joining the workspace, visibly (§2.2) |
| Q10 | v0.0.2 | Organizations and switching, the console with health, plans with three meters (§12) |

## 0. Where we start (as built at `5657c8e`)

Each claim below was checked against the migrations and code at that commit.

- `accounts` is the only tenant level (`migrations/0002`). It is created by `Store::create_account`
  (`casual-sign-store/src/store.rs`), which inserts under account scope; `openseal_app` holds `SELECT, INSERT, UPDATE`
  on it, and its one policy `tenant_isolation` is `id = openseal_current_account()` for every command. Its `settings`
  JSON is unstructured. The column comment says it holds plan limits; no code writes any.
- Every other tenant table carries `account_id`, `UNIQUE (account_id, id)` and composite foreign keys. Each is declared
  through `openseal_tenant_table()`, with RLS on `openseal_current_account()`. The only door is
  `Store::for_account(id) → Tenant::begin() → TenantTx`. Cross-account paths are `SECURITY DEFINER` functions taking a
  secret's hash or a login identity (`migrations/0007`, `0009`, `0010`).
- `users` is global, one row per normalized email, with one `login_kind` and `UNIQUE (idp_issuer, idp_subject)`, so one
  identity binds at most one identity provider. Its policy `member_of_current_account` has no `FOR` clause, so it
  admits UPDATE as well as SELECT through any membership of the current account. A user can already belong to several
  accounts: `openseal_resolve_user_login` returns every `(user, account)` pair, and `POST /auth/login
  {email, password, account_id?}` picks one. A staff session is bound to one account (`staff_sessions.account_id`).
  Memberships can be disabled per account (`account_memberships.disabled_at`, `migrations/0010`).
- **Existing defect, fixed separately (`SEC-ID-01`, P0).** Because the `users` row is shared, an admin of account B can
  rename, or set the password of, a member who also belongs to account A: `PATCH /users/{id}`
  (`casual-sign-server/src/api/admin.rs`) calls `Users::rename` and `Users::set_password_hash`
  (`casual-sign-store/src/repo/accounts.rs`), whose only guard is a membership of the *acting* account, and
  `Sessions::revoke_all` (`repo/sessions.rs`) revokes sessions in the acting account only. B's admin can then sign in as
  that person in A. This document does not fix it; `SEC-ID-01` does, before stage A ships switching. §2.3 states the
  rule the fix must meet, so the organization design builds on it rather than around it. **The fix is in progress**
  (unmerged at the time of writing): migration `0013_shared_user_guard` makes `member_of_current_account` `FOR SELECT`,
  adds an UPDATE policy admitting only a user whose sole membership is the current account, and adds the user's own
  definer doors (`openseal_update_own_user`, `openseal_accept_user_invitation`), which end the user's sessions in every
  account on a new password. It refuses with store `CS-DB-0009` and the store's own SQLSTATE `OS003`, answered as
  `403 CS-API-0015`. This design therefore takes `OS004` and `OS005` for its own SQLSTATEs (§8).
- Permission profiles are `admin`, `sender`, `viewer` and `custom`. `auth.rs::profile_scopes` maps them onto ten OAuth
  scopes (`SCOPES`); `admin` means every scope plus view-all. There is no delegated admin, organization, operator, plan,
  meter or admin audit log.
- keyd (`server/casual-sign-keyd`, one crate: PKCS#11 through `cryptoki`, the development file key, the mTLS server
  and the client) has two operations: get-certificate-chain and sign-digest. Its operation log records the digest of
  the CMS signed attributes per signature (`oplog.rs`). The `document.sealed` event records the sealed hash, profile,
  certificate fingerprint and TSA time, not that digest (`casual-sign-audit/src/event.rs`). The worker depends on the
  whole keyd crate.
- TSA URLs and trust anchors are worker environment variables (`OPENSEAL_TSA_URLS`, `OPENSEAL_TRUST_ANCHORS`). Dead
  jobs raise an `OperatorAlert` to the log. No service exposes metrics; the server has a `healthcheck` subcommand only.
- The audit chain's insert trigger (`migrations/0005`) checks `sha256(canonical) = hash`, `seq` and `prev`, serialized
  on `envelopes.chain_head` under `FOR UPDATE`; the canonical bytes are made in Rust by `casual-sign-audit`.

## 1. Vocabulary and naming

| Level | DB | API (`/api/v1`) | UI | DocuSign | SignNow |
| --- | --- | --- | --- | --- | --- |
| Platform | `platform` schema | none (console only) | Console | (DocuSign itself) | (SignNow itself) |
| Organization | `organizations`, `organization_id` | `/organizations/me`, `organization_id` | Organization | Organization (Org Admin) | Organization |
| Workspace | `accounts`, `account_id` (unchanged) | `/accounts/me`, `account_id`, token claim `acct` (unchanged) | **Workspace** | Account | Team |
| Member | `account_memberships` | `/users` | Members | Users | Team members |

**The database and API v1 keep `account`; the UI says "Workspace"** (Q1).

- *Database:* renaming `account_id` touches every tenant table, composite key, the RLS helper, the setting, the offline
  query cache and every repository; a partial rename leaves a policy naming a column that no longer exists. Keeping the
  key means the change *adds* a level and changes no isolation predicate.
- *API:* DEC-06 makes DocuSign the reference for API concepts, and its hierarchy is Organization → Account. `/api/v1`
  is frozen except for additions (docs/40 §1). The OpenAPI document describes `account` as "a workspace".
- *UI:* the owner's word. *Rejected:* `workspace_id` everywhere (all risk, no isolation gain); an API v2 for the word.
- *Consequence:* slice 33 (Rooms, docs/06) says "shared transaction workspaces"; it is reworded "rooms" so the word means
  one thing (§12, `ORG-27`).

## 2. Data model

Migration numbers are fixed in merge order (§12, which is the one list): `SEC-ID-01`'s fix (`0013`), then ORG-02 (the
organizations migration, which also creates `organization_admins`, `org_permission_sets`, the owner backfill and the
last-owner constraint), then ORG-05 (the admin logs), then CON-02 (the `platform` schema), then CON-03, CON-04, PLAN-02
and PLAN-03. Every later row that changes the schema (ORG-07, ORG-09 to ORG-12, ORG-14, ORG-18, ORG-20, ORG-22, ORG-23,
CON-07, CON-09, CON-10, PLAN-07 among those planned) takes the next free number when it merges, after all of those. A
worker whose expected number is taken renumbers before merge; a merged migration is never edited.

### 2.1 Organizations and their scope

```sql
-- organizations migration (sketch; forward-only; ORG-02)
CREATE FUNCTION openseal_current_org() RETURNS uuid LANGUAGE sql STABLE PARALLEL SAFE
    SET search_path = pg_catalog AS $$
    -- Fail closed both ways: an account scope never also reads as an organization scope.
    SELECT CASE WHEN NULLIF(current_setting('openseal.account_id', true), '') IS NOT NULL THEN NULL
                ELSE NULLIF(current_setting('openseal.organization_id', true), '')::uuid END
$$;

CREATE TABLE organizations (
    id               uuid PRIMARY KEY,
    name             text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 255),
    status           text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'closed')),
    policy           jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(policy) = 'object'),
    data_regions     text[] NOT NULL DEFAULT '{}',
    admin_chain_head bytea CHECK (admin_chain_head IS NULL OR octet_length(admin_chain_head) = 32),
    created_at       timestamptz NOT NULL DEFAULT now());

ALTER TABLE accounts ADD COLUMN organization_id uuid REFERENCES organizations (id);
ALTER TABLE accounts ADD COLUMN status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'archived'));
ALTER TABLE accounts ADD COLUMN admin_chain_head bytea
    CHECK (admin_chain_head IS NULL OR octet_length(admin_chain_head) = 32);
-- Backfill: one organization per account, with the account's UUID (deterministic; no randomness in SQL).
INSERT INTO organizations (id, name, created_at) SELECT id, name, created_at FROM accounts;
UPDATE accounts SET organization_id = id;
ALTER TABLE accounts ALTER COLUMN organization_id SET NOT NULL;
CREATE INDEX accounts_organization ON accounts (organization_id);

-- A workspace never changes organization (review finding 2). RLS cannot see the old row, so a trigger does.
-- The one exception is the operator's two-person link (ORG-20): the trigger function admits the change only when
-- current_user is openseal_org_mover, a NOLOGIN role with no members that owns exactly one SECURITY DEFINER
-- function, platform.apply_link_workspaces (ORG-20's migration). No session can SET ROLE to it, the owner role is
-- not it, and a GUC would not do: any role may set a custom setting.
CREATE ROLE openseal_org_mover NOLOGIN NOINHERIT;           -- created here, granted nothing until ORG-20
CREATE FUNCTION openseal_refuse_org_change() RETURNS trigger LANGUAGE plpgsql
    SET search_path = pg_catalog AS $$
BEGIN
    IF current_user = 'openseal_org_mover' THEN RETURN NEW; END IF;
    RAISE EXCEPTION 'organization of a workspace is fixed' USING ERRCODE = 'OS004';   -- CS-DB-0013
END $$;
CREATE TRIGGER accounts_organization_fixed BEFORE UPDATE OF organization_id ON accounts
    FOR EACH ROW WHEN (OLD.organization_id IS DISTINCT FROM NEW.organization_id)
    EXECUTE FUNCTION openseal_refuse_org_change();
-- Workspaces are created only through definer functions; the app updates only these columns.
REVOKE INSERT, UPDATE ON accounts FROM openseal_app;
GRANT UPDATE (name, settings, data_region) ON accounts TO openseal_app;
```

- **Content tables are not touched.** `envelopes`, `documents`, `recipients`, `fields`, `field_values`,
  `audit_events`, `templates`, `jobs` and every other `openseal_tenant_table` keep exactly one policy,
  `account_id = openseal_current_account()`. In an organization transaction `openseal_current_account()` is NULL, so
  they return no rows.
- **Organization tables** are declared through a new helper, `openseal_org_table(tbl, writable)`, with the policy
  `organization_id = openseal_current_org()`: `organizations` (on `id`), `organization_admins`, `org_permission_sets`,
  `domain_claims`, `identity_providers`, `user_identities` (§4), `scim_tokens`, `org_admin_events`,
  `org_usage_counters` (§7) and `org_workspace_allocations`. The last carries `account_id` too, as a reference, and is
  an organization table: it is named in the catalog test's exception list.
- **Organization policies are SELECT-only** (review finding 17). Three tenant tables gain one permissive policy each,
  `FOR SELECT` only:
  - `accounts`: `organization_id = openseal_current_org()`;
  - `account_memberships`: the account belongs to the current organization;
  - `users`: through a membership of a workspace of the current organization.

  Every organization-level write to a workspace goes through `for_workspace_of` (below) or a definer function, never
  through an organization policy.
- **`users.password_hash` is not readable by `openseal_app`** (review finding 19). Column `SELECT` on `password_hash`
  is revoked, and the login path reads it only through a definer function `openseal_login_password_hash(p_user,
  p_account)` that requires an enabled membership of that account. Identity-provider subjects move to
  `user_identities` (§4), which organization scope sees only for its own providers.
- **Workspace scope reads its own organization** (name, status, policy) through a `FOR SELECT` policy
  `id = (SELECT organization_id FROM accounts WHERE id = openseal_current_account())`.
- **Definer functions** (`SECURITY DEFINER`, `SET search_path`, executable by `openseal_app` only; none takes an
  account or organization id that is not derived from the current scope or a secret's hash):
  - `openseal_create_workspace(p_id, p_name)`: organization scope only; inserts the account under
    `openseal_current_org()` with its built-in profiles. ORG-02's version writes no event, because the log tables do
    not exist yet; ORG-05's migration, the next one, replaces it (and `openseal_archive_workspace`) with versions that
    append the admin events (§2.5) in the same transaction (built: migration 0020, §2.5 As built). No route calls
    either function before ORG-05 merges: the workspace routes are ORG-03's, which needs ORG-05.
  - `openseal_archive_workspace(p_id)`: organization scope, a workspace of that organization.
  - `openseal_bootstrap_organization(p_org, p_account, p_name)`: succeeds only when no organization exists, so
    `casual-sign-server bootstrap` creates the first organization and workspace of a self-hosted install and nothing
    after it. Later organizations come from the console (§5.3).
  - `openseal_user_workspaces(p_session_token_sha256, p_now)`: derives the user from a live session (review finding 21)
    and returns workspace id, workspace name and organization name for every enabled membership of an enabled identity.
  - `openseal_effective_plan()`, `openseal_org_usage(p_meter, p_from, p_to)`, `openseal_consume_quota(…)` (§7): no
    tenant parameter; the organization is derived from the current account or organization.
- **Store API.** `Store::for_organization(org) → OrgScope::begin() → OrgTx` mirrors `TenantTx`.
  - `OrgTx::workspace(id) -> Result<WorkspaceOf>` returns a proof value only for a workspace of that organization;
    because `organization_id` changes only through ORG-20's operator link (trigger above), a proof cannot be obtained
    for a workspace re-parented by any other path.
  - `Store::for_workspace_of(&WorkspaceOf)` opens an ordinary single-account `TenantTx`; it is how organization routes
    write to a workspace. It first reads the workspace's own `organization_id` in that transaction and refuses
    (404, as for another organization's workspace) when it no longer equals the proof's, so a proof taken before an ORG-20 link is useless after
    it.
  - `Store::for_account` remains the door for principals whose account came from their own credential.
  - RLS never sees two accounts, or an account and an organization, in one transaction.
- **Catalog tests** (extending the one that finds undeclared tenant tables), **scoped to schema `public`** (review
  finding 9; the `platform` schema has its own test, §5.1). They check that:
  1. every `public` table with `account_id` has the `tenant_isolation` policy, and only it, except `accounts`,
     `account_memberships` (one extra `FOR SELECT` organization policy each) and `org_workspace_allocations`
     (an organization table);
  2. no policy on a `public` table with `account_id` mentions `openseal_current_org` outside that list, and every such
     policy is `FOR SELECT`;
  3. every `public` table with `organization_id` is declared through `openseal_org_table`, `accounts` excepted;
  4. setting both settings makes `openseal_current_org()` NULL;
  5. `openseal_app` has no INSERT on `accounts`, UPDATE only on the three named columns, and no SELECT on
     `users.password_hash`; an UPDATE of `accounts.organization_id` by `openseal_app` and by the owner role is
     refused (`CS-DB-0013`);
  6. `openseal_org_mover` cannot log in, has no members, and owns no function or only
     `platform.apply_link_workspaces` (red when a second function is given to it, or a role is granted it).

**Migration path that never weakens RLS.** The migration runs in one transaction as the owner: create the function and
table, add the column as nullable, backfill, set NOT NULL, add the trigger, change the grants, then add the new
`FOR SELECT` policies. Every predicate that existed before is unchanged. The isolation suite as it stands (RLS on and
off, every repository method with another account's ids, `SEC-A04`'s generated route test) must stay green unchanged,
except where `create_account` moves to a definer function, which is a code change in the same row. (The users `UPDATE`
path has already moved, in `SEC-ID-01`'s migration.) The organization isolation suite runs the same way in organization scope (§9, `SEC-O01`).

**An account with no admin.** The organizations migration creates `org_permission_sets` and `organization_admins`
(§2.2) and the deferred last-owner constraint, and its backfill makes every member holding the built-in `admin` profile
an owner of its organization. An account with none gets an organization with no owner and status `active`; the last-owner constraint
(§2.2) is deferred and checked only on later changes to `organization_admins`, so the migration does not fail, and the
console lists such organizations for owner recovery (§5.1). A test migrates a v0.0.1 database containing such an
account.

#### As built (`ORG-02`, migration `0014_organizations.sql`)

Built as sketched above, with these decisions taken within the design (each tested in
`server/casual-sign-store/tests/organizations.rs`):

- **Built-in profiles come with the workspace.** `openseal_create_workspace(p_id, p_name, p_admin_profile,
  p_sender_profile, p_viewer_profile)` and `openseal_bootstrap_organization(p_org, p_account, p_name, …three profile
  ids)` take the profile ids from the host (no randomness in SQL) and record them in `settings.builtin_profiles`, as
  `bootstrap` always did. Both share `openseal_insert_workspace`, which is not granted to the application.
- **The bootstrap is one transaction.** `openseal_bootstrap_organization` runs in the account scope of the workspace it
  creates (it refuses another `p_account`), under an exclusive lock on `organizations`, so the first administrator is
  created in the same commit; `openseal_bootstrap_owner(p_user, p_now)` then makes that administrator the owner, only
  for an organization inserted by the same transaction (the row's `xmin` is the current transaction id), while it has
  no administrator, has this one workspace, and the user is an enabled member here with the built-in admin profile.
  An organization that already existed without an owner is never claimable this way, however few admins it has; its
  owner is named through the console (§5.1). Test:
  `organizations.rs::bootstrap_owner_refuses_an_organization_made_before_this_transaction` (the ORG-02 review's probe,
  seen red before the `xmin` check). `casual-sign-server bootstrap` uses both and is refused (`CS-DB-0006`) once any
  organization exists. `casual_sign_server::bootstrap_workspace` provisions a workspace and its first administrator in
  an existing organization (no organization role), in one transaction: `OrgTx::into_workspace` continues the
  organization transaction in the new workspace's account scope (which makes `openseal_current_org()` NULL), so a
  failing administrator leaves no workspace (test `casual-sign-server/tests/bootstrap.rs`, seen red with two
  transactions); its callers until ORG-03 are tests and, from CON-03, the console.
  Until the console exists, a second organization is made by the owner role (as the tests do).
- **An organization admin is a member.** A `BEFORE INSERT OR UPDATE OF organization_id, user_id` trigger on
  `organization_admins` refuses a user who is not an enabled member of a workspace of that organization (SQLSTATE
  `23503`, constraint `organization_admin_is_a_member`, store `CS-DB-0008`); the foreign key to `users` ignores row
  security, so without it a user of another organization could be named. ORG-03's routes also check it, with their
  own error code. A membership disabled later leaves the row; removal is ORG-03's. Test:
  `organizations.rs::an_organization_admin_must_be_a_member_of_one_of_its_workspaces`, seen red without the trigger.
- **The last-owner constraint** fires on UPDATE or DELETE of an `owner` row and raises SQLSTATE `23514` with
  constraint `organization_keeps_an_owner` (store `CS-DB-0008`, `StoreError::is_last_owner`; the API code `CS-ORG-0008`
  is issued with ORG-03's routes). An organization that never had an owner (an account with no admin at migration) can
  still gain administrators. Disabling an owner's identity (`users.disabled_at`) is not checked here; the platform's
  identity disable (CON-04) must check it.
- **Backfill** makes owners of admin-profile members whose membership is enabled; a disabled one is not an owner.
- **`openseal_login_password_hash(p_user, p_account)`** also requires `p_account` to be the current account.
- **`openseal_user_workspaces`** also returns each workspace's status and its organization's id, for the switcher.
- **`organizations` grants:** `openseal_app` may SELECT, and UPDATE `name` and `policy` (org settings, ORG-03 and
  ORG-08 check who); status is the platform's.
- **Migrator.** Migrations run as a superuser (as Compose does). A non-superuser CREATEROLE migrator is made an ADMIN
  member of every role it creates (PostgreSQL 16+) and cannot revoke that grant, which would break catalog test 6; so
  migration 0014 refuses to finish while `openseal_org_mover` has any member, and such an install has a superuser
  create the role first (`CREATE ROLE openseal_org_mover NOLOGIN NOINHERIT`). With that, test 6 holds on a
  non-superuser CREATEROLE migrator (`catalog_6_holds_on_a_non_superuser_createrole_migrator`).
- **Catalog test 1** names `accounts` (keyed on `id`) beside `account_memberships`; `org_workspace_allocations` does
  not exist yet. The route half of `SEC-O01` waits for ORG-03's routes.

### 2.2 Roles and permissions

The two organization tables below, and the deferred last-owner constraint, are created by ORG-02's migration (§2.1),
so the backfill has somewhere to write; ORG-03 builds the routes over them and adds no migration.
`permission_profiles.admin_scope_group_ids` belongs to delegated workspace administration and is added by ORG-07's
migration.

```sql
CREATE TABLE org_permission_sets (
    id uuid PRIMARY KEY, organization_id uuid NOT NULL REFERENCES organizations (id),
    name text NOT NULL, permissions text[] NOT NULL DEFAULT '{}',
    UNIQUE (organization_id, id), UNIQUE (organization_id, name));
CREATE TABLE organization_admins (
    organization_id uuid NOT NULL REFERENCES organizations (id),
    user_id uuid NOT NULL REFERENCES users (id),
    role text NOT NULL CHECK (role IN ('owner', 'admin', 'delegated')),
    permission_set_id uuid,                   -- required iff role = 'delegated'
    workspace_scope uuid[],                   -- NULL = every workspace of the organization
    created_at timestamptz NOT NULL,
    PRIMARY KEY (organization_id, user_id),
    FOREIGN KEY (organization_id, permission_set_id) REFERENCES org_permission_sets (organization_id, id),
    CHECK ((role = 'delegated') = (permission_set_id IS NOT NULL)));
-- A deferred constraint trigger refuses a commit that leaves an active organization with no owner whose
-- identity is enabled (users.disabled_at IS NULL; review finding 21): CS-ORG-0008.

-- ORG-07's migration:
ALTER TABLE permission_profiles ADD COLUMN admin_scope_group_ids uuid[];  -- NULL = whole workspace
```

**Organization actions.** One catalogue in `casual-sign-server::authz`.

| Action | Owner | Admin | Delegated (if in its set) |
| --- | --- | --- | --- |
| `org.settings.update` (name, branding defaults, ERSD default) | ✓ | ✓ | ✓ |
| `org.admins.manage` (owners, admins) | ✓ | — | — |
| `org.delegates.manage` (delegated admins, permission sets) | ✓ | ✓ | — |
| `org.workspaces.create`, `.update`, `.archive` | ✓ | ✓ | ✓ (within scope for update and archive) |
| `org.workspaces.join` (become a member of a workspace, any profile) | ✓ | ✓ | **never** |
| `org.workspace_admins.assign` (give *another* member a workspace's admin profile) | ✓ | ✓ | ✓ (within scope, never to itself) |
| `org.users.read` (directory across workspaces) | ✓ | ✓ | ✓ (within scope) |
| `org.users.manage` (memberships, profiles, re-homing; identity attributes only as §2.3 allows) | ✓ | ✓ | ✓ (within scope) |
| `org.identity.domains` (claim, verify, release domains), `org.identity.scim` (tokens and mappings), JIT target | ✓ | ✓ | ✓ |
| `org.identity.providers` (create or change an IdP), `org.identity.sso_enforce` (turn SSO-required on or off) | ✓ | — | — |
| `org.policy.tighten` (any security key tightened, any non-security key) | ✓ | ✓ | ✓ |
| `org.policy.loosen` (any security key loosened or unlocked) | ✓ | — | — |
| `org.usage.read`, `org.usage.export` | ✓ | ✓ | ✓ |
| `org.audit.read` | ✓ | ✓ | ✓ |

**Configuration that can capture an identity is owner-only** (review finding 3). An IdP, SSO enforcement, and the
loosening or unlocking of any security key (§3) can each sign in as, or weaken the sign-in of, the organization's
owners. They are owner actions; an admin may *propose* one, which takes effect when an owner approves it (an
`org_admin_events` pair, request and approval, by different identities). Every such change notifies every owner by
e-mail and in the organization overview. As defence in depth, each IdP records the role of whoever configured it last,
and an IdP never signs in an identity holding an organization role above that one; such an identity signs in with its
existing method (`CS-ORG-0006`).

Built-in organization permission sets, editable and copyable: **Identity administrator** (`org.identity.domains`,
`org.identity.scim`, policy read), **User administrator** (users, workspace admins; workspace scope), **Usage and
billing viewer** (usage), **Security auditor** (audit read, policy read).

**Workspace actions.** These replace the coarse `admin` meaning. OAuth scopes stay as the wire grants; each maps to a
set of actions.

| Action | Old scope covering it | Sensitive |
| --- | --- | --- |
| `users.read`, `users.invite`, `users.update`, `users.disable`, `users.remove` | `admin:users` | — |
| `groups.manage`, `profiles.manage` | `admin:users` | — |
| `settings.sending`, `settings.signing`, `ersd.manage` | `admin:account` | — |
| `settings.security`, `brands.manage`, `retention.manage` | `admin:account` | **yes** |
| `api_clients.manage`, `webhooks.manage` | `admin:account`, `webhooks:manage` | **yes** |
| `envelopes.read_all`, `envelopes.transfer` | (`view_all_envelopes`) | **yes** |
| `templates.share_workspace`, `reports.read`, `usage.read`, `admin_audit.read` | `admin:account`, `audit:read` | — |

**Sensitive workspace actions** (review finding 14) reach content or personal data indirectly, or weaken evidence:
`webhooks.manage` sends envelope events with recipient data to an outside host; `retention.manage` can purge;
`settings.security` can weaken recipient authentication; `brands.manage` sets `frame-ancestors`; `api_clients.manage`
mints credentials. Each sensitive action:

- needs a fresh sign-in (within 10 minutes) for the change (`CS-ORG-0014`);
- writes an admin event and notifies the workspace's admins;
- is bounded by the organization's floors (§3: retention minimum, webhook host allow-list, recipient authentication
  methods, allowed `frame-ancestors` origins);
- cannot be delegated with a group scope: a profile with `admin_scope_group_ids` set never holds one.

The built-in `admin` profile holds every action. A **delegated workspace admin** is a `custom` profile holding some
admin actions, with `admin_scope_group_ids` optionally set. With a group scope it reads and changes only users in a
scope group, invites only into one (an invitation must name it), shares templates only to scope groups, and cannot see
or edit profiles holding actions it lacks.

**The rule against escalation** is one function used by every grant path: profile create and edit, member profile
change, organization admin assignment, API key and OAuth client creation, SCIM role mapping, and workspace joining.
`grantable(actor, requested) = requested.actions ⊆ held(actor) ∧ requested.scope ⊆ actor.scope`, where `held` is
defined per level (review finding 4):

- In a workspace, a member holds its profile's actions.
- An organization **owner or admin** is treated as holding every workspace action for workspaces of its organization,
  **for granting only**; holding them never opens content. Content needs a membership, which only `org.workspaces.join`
  creates.
- A **delegated** organization admin holds, in a workspace in its scope, exactly the workspace actions its set names
  (`org.workspace_admins.assign` names the admin profile, for others).
- Every actor, at every level, never grants to itself: no edit of the profile or set it holds, no change of its own
  role, no self-assignment of a profile or `envelopes.read_all`. This already holds for profiles today and now holds
  for every grant path.
- No actor assigns the built-in `admin` profile, or the organization `owner` or `admin` role, unless it holds it.

It is property-tested over random actor and request pairs, and checked by a generated route test (§9, `SEC-O02`).

**Organization admins and content** (Q9). An organization role confers no access to envelopes, documents or field
values. To read agreements an organization owner or admin uses `org.workspaces.join`, which adds a membership with a
chosen profile. The join writes `admin.member_added` with `via: organization` in the workspace's admin log and
`org.workspace_joined` in the organization log, and notifies the workspace's admins. Delegated admins cannot join, and
cannot give themselves content access through `org.workspace_admins.assign` (no self-grants). This matches DocuSign,
where Org Admin manages users of linked accounts but reads envelopes only as an account user. *Rejected:* implicit
view-all across workspaces (silent content access, largest blast radius for a stolen organization-admin session).

**Per-request, per-object, deny by default** (`SEC-A05`'s model, widened):

- each OpenAPI operation gains `x-level: workspace | organization` beside `x-permission`, which names an action;
- the route guard resolves the principal afresh (membership and profile; for organization routes, the
  `organization_admins` row for the session workspace's organization) and refuses an action not held
  (`CS-AUTH-0006`);
- object resolvers apply ownership, sharing, group scope and workspace scope; an object outside the caller's scope
  answers `404 CS-API-0002`, as another tenant's does;
- a route with no catalogue entry fails to register, as a route without `x-permission` does today; this is the existing
  route-table test, extended, not a new gate;
- rights are never cached across requests.

### 2.3 Identities, cross-workspace users and switching

**Identity attributes** (review finding 1; the rule `SEC-ID-01`'s fix must meet). The `users` row (email, name,
password hash, MFA factors, `disabled_at`) is shared by every workspace the person belongs to. It may be changed only by:

1. the person themselves, on a session of their own;
2. an organization owner or admin whose organization holds a **verified domain claim** covering the email (§4),
   through a definer function in organization scope;
3. a workspace admin, **only while the person's sole membership, enabled or disabled, is that workspace**;
4. the platform, for an identity disable only, through the console's two-person path (§5.1).

Everything else answers `403 CS-API-0015`, the code `SEC-ID-01` issues (store `CS-DB-0009`, SQLSTATE `OS003`).

**What applies when.** Rule 2 needs verified domain claims (ORG-11, stage F, after v0.0.3) and rule 4 needs the
console's two-person path (CON-04). Until each merges, only rules 1 and 3 apply, and that is what `SEC-ID-01`'s fix
implements: the user's own definer doors for rule 1, and for rule 3 an UPDATE policy on `users` that admits only a
user whose sole membership is the current account (`member_of_current_account` becomes `FOR SELECT`). ORG-11 and CON-04
each add a definer function for their rule; neither widens the UPDATE policy. A password change, an MFA reset or an identity disable revokes the
person's sessions **in every workspace**, through a definer function, as does a platform-wide disable. A workspace
admin can always disable or remove the *membership* in their own workspace (`account_memberships.disabled_at`), which
is per workspace and harms no other.

**Switching.**

- One identity, many memberships; one password and MFA for every workspace. Organization policy decides whether the
  password is allowed (§3, §4).
- A session is bound to one workspace, as today. `POST /api/v1/auth/switch {account_id}` with the current session and
  CSRF token checks, through `openseal_user_workspaces`, an enabled membership there; then that the current sign-in
  satisfies the target organization's login policy (SSO with its IdP, MFA, maximum session age). If so it issues a new
  `os_session` for the target and revokes the old one; if not, `401 CS-ORG-0007` names the sign-in needed.
- `GET /api/v1/auth/workspaces` lists the user's workspaces by organization. The account always comes from the
  session; no header or parameter chooses another (`SEC-O05`).
- API keys and OAuth clients stay per workspace. Organization automation uses organization SCIM tokens (`osscim_`,
  hashed as API keys) and, later, organization OAuth clients with `org:*` scopes.
- An organization admin is a member of at least one workspace of its organization (the `organization_admins` insert
  checks it); organization routes take the organization from that session. *Rejected:* organization-only sessions.
- *Later:* one workspace per browser tab. For now one active workspace per browser, as in DocuSign.

### 2.4 Moving things between workspaces

| Object | Across workspaces | Within a workspace | What is recorded |
| --- | --- | --- | --- |
| **Envelope** (any state) | **Never moved** (Q2): its rows, chain and blobs carry its `account_id`, and moving them means updating `audit_events`, which every role is refused (`SEC-S07`). A completed envelope's **evidence package** (sealed PDF, certificate, audit trail JSON; verifiable offline, docs/32) is exported, and can be **imported** into another workspace as a read-only *archived agreement* | **Ownership transfer** (DocuSign's envelope transfer, docs/48 §9): workflow command `Transfer` records the new audit type **`envelope.transferred` `{from_user, to_user}`** | Source chain: access event **`envelope.exported`**. Target: a row in `archived_agreements` and `admin.agreement_imported` in its admin log (no envelope, no new chain) |
| **Template** | **Copied**, never moved: an organization-scope operation (below) | Owner change; sharing | `admin.template_copied` in both workspaces' logs |
| **User** | **Re-homed**: membership added in the target and removed from the source in one organization action (`org.users.manage`). The UI offers envelope transfer before removal | Profile, groups | `admin.member_added`, `admin.member_removed` in each; `org.user_moved` in the organization log |
| **Group, brand, webhook, API client** | Not moved; recreated (brands may be organization defaults, §3) | as today | admin events |

- **Import is not an envelope** (review finding 7). An archived agreement is a tenant row
  (`archived_agreements (account_id, id, source_envelope_id, chain_head, sealed_sha256, package blob keys,
  imported_by, imported_at)`) whose package is verified on import by `casual-sign-verify` and the audit-chain verifier
  (a package that does not verify is refused, `CS-ORG-0017`), shown read-only, and never sent, signed or sealed. It
  needs no engine change and no new envelope kind; its provenance is the package itself, which verifies offline.
- **Template copy** (review finding 18) is `POST /organizations/me/template-copies {template_id, from_workspace,
  to_workspace}`, an organization-scope route. It takes a `WorkspaceOf` proof for each side, requires the caller's
  membership with `templates:write` in both, and is allowed only when the organization's
  `sharing.cross_workspace_templates` is on (`CS-ORG-0016`). The copy is made through two single-account transactions
  (read from source, write to target), never one transaction seeing both. No workspace route takes another workspace's
  id, so `SEC-O05` holds as written.
- *Rejected:* re-keying an envelope's rows with triggers disabled (indistinguishable from the insider rewrite `SEC-S07`
  defends against; the chain head in the sealed PDF would no longer match its host's records).

### 2.5 Admin audit logs

Separate from envelope evidence, built the same way:

- `admin_events` is a tenant table (`account_id`), chained per workspace, head in `accounts.admin_chain_head`;
- `org_admin_events` is an organization table, chained per organization, head in `organizations.admin_chain_head`;
- `platform.operator_events` belongs to the console (§5), head in a one-row `platform.operator_chain`.

Each is append-only and hash-chained. The canonical bytes (RFC 8785) are made in Rust by `casual-sign-audit`, as for
envelope events; the insert trigger checks `sha256(canonical) = hash`, `seq` and `prev` under a `FOR UPDATE` lock on the
owner's head column (review finding 16), and triggers refuse UPDATE, DELETE and TRUNCATE (`CS-DB-0004`, its meaning
widened to these logs). The application role has SELECT and INSERT only, and inserts only rows of its own scope.

Writes that cross a scope go through definer functions that lock the head and append:
`openseal_append_org_event(canonical, hash)` (from workspace scope, for an event the organization must see) and
`platform.copy_to_org_log(p_org, canonical, hash)` (from the console, §5.1). A failed append fails the change: the event
is written in the same transaction as the change.

An event records actor (user, API client, SCIM token or operator id), action, target ids, changed keys with old and new
values for settings that are not secret (secrets as "rotated"), request id and the actor's IP (personal data under
docs/07, retained as such). Exported as JSON or CSV through `GET /organizations/me/audit` and `GET /admin-events`. This
meets docs/10's "admin audit log of every configuration change, exportable".

#### As built (`ORG-05`, migration `0020_admin_events.sql`)

Built as above, with these decisions (each tested in `server/casual-sign-store/tests/admin_events.rs`, seen red under a
mutation of the migration):

- **The repositories append the events, not the routes.** Every store method that changes settings, a member, a
  profile, a workspace or the organization appends its event in the same transaction, so no caller can forget one. The
  caller says who acts (`TenantTx::act_as`, `OrgTx::act_as`, carried by `into_workspace`); every guarded API call acts
  as its principal (the user behind a session, the API client behind a key or token) with the request id and client
  address; without it the event records `system` (bootstrap, tests).
- **No change commits without its event.** Deferred constraint triggers on `accounts`, `account_memberships`,
  `permission_profiles`, `organizations`, `organization_admins` and `org_permission_sets` refuse an application-role
  commit whose transaction appended no event to that workspace's log or its organization's (`23514`, constraint
  `admin_change_has_event`, `CS-DB-0008`). "This transaction" is the event row's `xact` (`pg_current_xact_id()`, the
  top-level id even inside a savepoint), set by the insert trigger, never by the caller. The owner role (migrations,
  superuser recovery) is outside, as it is for the envelope chain (`SEC-S07`).
- **Canonical event (v1).** RFC 8785 bytes from `casual-sign-audit::jcs`: `v`, `account` or `organization`, `seq`,
  `prev` (hex or null), `at` (Unix milliseconds), `actor` (`{kind: user|api_client, id}` or `{kind: system}`), `action`,
  `target` (ids by name), `changes` (`key`, `old`, `new`), and `request_id` and `ip` when known. Names and e-mail
  addresses are never recorded, only ids; a member rename names the key without values; settings keys that look secret
  (`secret`, `password`, `token`, `private`, `credential`) and passwords are recorded as `"rotated"`. Actions now:
  `workspace.created`, `workspace.archived`, `workspace.settings_changed`, `organization.created`,
  `organization.admin_added`, `member.added`, `member.removed`, `member.profile_changed`, `member.disabled`,
  `member.enabled`, `member.renamed`, `member.password_set`, `profile.created`. A user changing their own name or
  password, and accepting an invitation, are not administrative changes and write none.
- **The database checks the bytes.** Besides the hash, `seq` and `prev`, the insert trigger requires the owner, `seq`,
  `prev` and `action` columns to be what the bytes state, and refuses an event outside the current scope (`42501`)
  before reading that chain, so another scope's head or next `seq` is never revealed. The workspace functions require
  the event's bytes to name their own action and workspace.
- **Concurrent changes queue on the head.** `openseal_admin_chain_tip()` and `openseal_org_chain_tip()` lock the head
  row (`accounts` or `organizations`) in one statement and read the next `seq` and head in the next, so a transaction
  that waited for the lock sees the event the other one wrote (one statement would read `seq` from its starting
  snapshot and be refused as a broken chain). Two admin changes to one workspace, or two workspace creations in one
  organization, at the same time both commit.
- **The commit check is coarse.** `admin_change_has_event` accepts any event the transaction appended to that
  workspace's log or its organization's; it does not check that the event describes the change. The repositories,
  which write both together, are what pair them.
- **The actor's IP cannot be erased.** It is inside the hashed bytes of an append-only log, personal data kept for
  the log's life by design (docs/07 §Data classification, docs/09 §5).
- **Who sees which event.** Workspace creation and archiving go to the organization log (they are organization
  actions); the bootstrap writes `organization.created` and `organization.admin_added` there through
  `openseal_append_org_event`; workspace settings, members and profiles go to the workspace log.
- **Reading.** `TenantTx::admin_events(after, limit)` and `verified_admin_log()`, the same on `OrgTx`; the verified read
  also requires the stored head to equal the last event's hash. `GET /admin-events` (workspace, `admin:account`)
  re-verifies the whole log, then answers JSON or CSV. `GET /organizations/me/audit` comes with ORG-03's organization
  routes, over `OrgTx::admin_events`.

## 3. Organization policy and inheritance

`organizations.policy` is a typed document validated by `casual-sign-policy::OrgPolicy` (the new crate of §5.2). Each
key is `{ "value": …, "locked": bool }`. A workspace's `accounts.settings` holds its own values. The **effective
policy** is a pure function, `casual-sign-policy::effective(org, workspace) -> Policy`, used by the server (every
request that reads or writes settings, login, send) and the worker (retention, recipient auth, TSA).

| Key | Kind | Rule |
| --- | --- | --- |
| `login.sso_required` (per claimed domain), `login.allowed_methods` | security | Workspace can only narrow; locked by default |
| `login.mfa_required`, `login.password` (min length, breached check), `session.max_age`, `session.idle` | security | Workspace can only tighten |
| `login.ip_allow_list` | security | Intersection |
| `recipient.allowed_auth_methods` | security | Intersection |
| `embedding.frame_ancestors_allowed` | security | Workspace brands may use only listed origins |
| `sending.allowed_seal_profiles`, `sending.min_seal_profile` | evidence | Workspace can only raise the level |
| `retention.min_days`, `retention.max_days` | governance | Workspace retention policies lie within the range |
| `data_regions` | governance | A workspace's `data_region` label is one of the organization's (a label only; no residency claim, §7.5) |
| `api.allowed`, `webhooks.allowed_hosts` | integration | Workspace can only narrow |
| `branding.default_brand`, `ersd.default`, `locale.date_format`, `reminders.default` | defaults | Override unless locked |
| `sharing.cross_workspace_templates` | collaboration | Organization-only |

- **Tighten-only** keys need no lock: a looser workspace value is refused, and the organization value wins on read.
- **Locked** keys refuse any workspace write (`422 CS-ORG-0002`); the UI shows a lock and "Set by your organization".
- Loosening or unlocking any security key at organization level is owner-only (§2.2).
- Tightening does not rewrite workspace rows; the effective value is recomputed per request.
- **Evidence:** what a ceremony depends on (recipient authentication methods, seal profile) is fixed into the envelope
  state at send, as the engine `Policy` already is. A later policy change never alters a sent envelope. Recipients are
  not affected by staff login policy.

## 4. Identity: domains, SSO, SCIM (slice 10, built inside this frame)

- **Domain claims.** `domain_claims (organization_id, domain, token_sha256, verified_at, last_checked_at)`. DNS TXT
  `openseal-verification=<token>` (256-bit), looked up by the worker through the SSRF-checking resolver, re-checked
  daily; a lapse unverifies after 7 days. One verified claim per domain platform-wide; public e-mail domains are
  refused. A conflict answers `CS-ORG-0004` without saying who holds the domain.
- **What a verified claim gives** (DocuSign's model): the organization's login policy applies to every identity with
  that e-mail domain, in any workspace of any organization; its owners and admins may change those identities'
  attributes and disable them platform-wide (§2.3, rule 2); they show in its directory. It never gives membership in,
  or visibility of, another organization's workspaces. **Another organization holding such an identity as a member
  sees a badge "Sign-in managed by its domain's organization"**, and the claim's arrival is an event in that
  organization's log (review finding 13).
- **Identity-provider bindings** (review finding 13). `user_identities (user_id, provider_id, subject, created_at,
  PRIMARY KEY (provider_id, subject))` replaces the single `(idp_issuer, idp_subject)` on `users` (kept, unused, until
  a later migration drops it). An identity may hold one binding per provider. A login by (issuer, subject) is accepted
  only when the binding exists **and** the provider's organization holds a verified claim on the identity's current
  e-mail domain (`SEC-O08`). Since an IdP can sign in only identities of its own verified domains, and a domain has at
  most one claim, one identity is governed by at most one organization's SSO: two organizations cannot both require
  their own SSO of the same person. Members whose domain no organization claims sign in by the method the workspace's
  effective policy allows (password with MFA, by default).
- **IdPs** (`identity_providers`: OIDC issuer and client, SAML metadata) belong to an organization; creating or
  changing one is owner-only (§2.2). JIT provisioning puts new users into a configured workspace and profile, bounded by
  `grantable` of the owner who configured it.
- **SCIM 2.0** at `/scim/v2` with organization tokens. Groups map to (workspace, profile, groups). Each mapping is
  checked by `grantable` against the token creator's rights when saved and when applied.

## 5. Platform console

### 5.1 Identity and separation

**Separate schema, role and code.**

- Schema `platform`, owned by the migrator: `operators`, `operator_mfa`, `operator_sessions`, `operator_events`,
  `operator_chain`, `approval_requests`, `approval_grants`, `approval_uses`, `plans` and its tables (§7), `tsa_endpoints`,
  `trust_anchors`, `seal_profiles`, `service_targets`, `alerts`, `reconciliation_runs`, `settings`.
- The console connects as **`openseal_console`**, distinct from `openseal_app`. It has SELECT on `platform.*`, INSERT on
  `operator_events` and `alerts` (both append-only), and nothing else directly: every other write, plans and approvals
  included, is a definer function (below). It has **no grant at all on any `public` table**.
- It reads tenant metadata only through `platform.*` definer functions that return ids, names, statuses, counts and
  sizes (`platform.organizations_page`, `platform.job_stats`, `platform.pool_stats`, `platform.dead_jobs`,
  `platform.seal_digests`). None returns an e-mail, a person's name, an IP, a document or a field value.
- `openseal_app` has no grant on the `platform` tables except SELECT through `openseal_effective_plan()` and the
  worker's reads of `tsa_endpoints`, `trust_anchors` and `seal_profiles` (through definer functions returning only
  approved rows).
- **Catalog test for the platform schema** (`SEC-X01`): connected as `openseal_console`, SELECT on every `public`
  table is denied, and INSERT, UPDATE and DELETE on every `platform` table other than INSERT on `operator_events` and `alerts` are denied.
  Seen red after one extra GRANT.

**No path from operator to content.**

- The console binary has no blob-store configuration and no keyd signing identity.
- **The crate graph keeps tenant code out** (review findings 5 and 15). `casual-sign-console` depends on
  `casual-sign-platform-store` (the `platform` schema only, its own pool, no tenant repository), `casual-sign-policy`
  (pure), `casual-sign-audit` (canonical JSON for the operator chain), `casual-sign-secrets` and
  `casual-sign-keyd-client`. It does not depend on `casual-sign-store`, `casual-sign-host` or `casual-sign-server`, so
  `TenantTx` is not in its build. This is recorded in docs/19's crate table and reviewed at merge; **no new repository
  check** is added (CLAUDE.md), and the database role is the control that a test proves.
- A console e2e test scans every console response for the e-mail addresses and names seeded into tenants, expecting
  none.
- **Organization and workspace names** are shown to operators: business metadata needed to support a customer.
  docs/07 classifies them as *tenant metadata*: not logged in clear, not exported beyond the console.

**Organization creation is not an oracle** (review finding 12). `platform.create_organization(name, plan, owner_email)`
always answers the same shape and creates an organization, its first workspace and an **owner invitation** bound to the
e-mail, whatever `users` holds. The invitation binds to an identity only when accepted with proof of the address (the
existing invitation flow). The console never sets a password, MFA factor or name on any identity, existing or new, and
cannot read the e-mail back. Owner recovery works the same way.

**Impersonation: none** (Q3). No console code path creates a staff session, API key, token or invitation for an
existing tenant identity; the role lacks the grants (`SEC-X02`). A customer who wants help invites a support person as
an ordinary member, recorded in their own admin log.

**Sign-in.**

- Operator e-mail and password (Argon2id), then **mandatory TOTP**: RFC 6238 over `aws-lc-rs` HMAC (ADR-006; built on a
  library primitive, not hand-rolled), test-vectored against RFC 6238 Appendix B; seed encrypted under a console key
  from `casual-sign-secrets`; codes single-use within their window.
- WebAuthn later, with a permissively licensed crate after review (Q8; `webauthn-rs` is MPL-2.0, which `deny.toml`
  refuses). Optional mTLS client certificates at the proxy.
- Sessions last 8 hours with a 30-minute idle timeout. Approvals and key, trust and suspension actions need TOTP
  re-entry within 5 minutes; the time is recorded on the session row.
- **Separate origin and cookie.** `__Host-os_op`, `SameSite=Strict`, CSRF token, strict CSP, `frame-ancestors 'none'`.
  Serving the console on the public application origin is refused.
- **Operator roles:** `platform_owner` (operators and roles), `operator` (organizations, workspaces, plans),
  `key_custodian` (seal profiles, TSA, trust anchors), `observer` (health and usage, read-only).

**Two-person rule, enforced in the database** (review finding 10). Applies to: changing the active seal key alias;
adding or removing a trust anchor or TSA; suspending, resuming or closing an organization; organization-owner
recovery; adding a `platform_owner`; resetting an operator's MFA; disabling an identity platform-wide; enabling
self-sign-up.

- `approval_requests (id, requester, action, payload_sha256, expires_at)` and `approval_grants (request_id, approver,
  mfa_at)` are insert-only, and written only by `platform.request(p_session_token_sha256, …)` and
  `platform.grant(p_session_token_sha256, p_request_id)`, which take the operator and the TOTP time from a live session
  row, never from a parameter; `approval_uses (request_id UNIQUE)` makes an approval single-use.
- The tables these actions change (`seal_profiles`, `tsa_endpoints`, `trust_anchors`, `operators` roles,
  `operator_mfa`, organization status) have **no direct write grant**. Each action is one definer function,
  `platform.apply_<action>(p_session_token_sha256, p_request_id, payload)`, which resolves the acting operator from a
  live session, recomputes the payload hash, and requires a grant by a *different* operator whose TOTP was entered within
  5 minutes of granting, unexpired and unused. It then applies the change, records the use, and appends the operator
  event naming the request id.
- The worker reads the active seal alias through a function that returns the alias with the approval id of its last
  change, and refuses an alias whose change has no approval event in `operator_events` (`CS-CON-0006`).
- *Residual, stated:* operator sessions are created by the console after it checks password and TOTP; the database
  cannot check TOTP itself. Someone holding `openseal_console`'s database credentials could open sessions for two
  operators and approve alone. The controls against that are the credential's custody (`casual-sign-secrets`, never in
  the public server's environment), the session-creation event in the hash-chained operator log with its IP, and the
  copy of every organization action into that organization's log.

**Break-glass** (`SEC-X07`).

- *Console lock-out* (no operator can sign in): `casual-sign-console recover-operator <email>` on the host, with the
  **migrator** credentials. It mints a one-time enrolment link and writes `operator.break_glass` to the operator log.
- *Tenant owner lock-out* (Q4): two-person, only to an address in a verified domain of that organization, mints an
  owner invitation (as above), and is copied into the organization's admin log.

Neither path reaches content.

**Operator audit log.** `platform.operator_events` is hash-chained like §2.5 and written in the action's transaction. It
records operator id, action, target ids, approval request id, IP and request id. Every action on an organization is also
appended to that organization's `org_admin_events` as `operator.*` through `platform.copy_to_org_log`, so tenants see
what the platform did to them. It is exported from the console, and its daily head is written to the service log for
external anchoring (slice 7).

### 5.2 Deployment and crate placement

**A separate binary: new crate `server/casual-sign-console`** (Host layer, native only, excluded from the wasm32
check), with the dependencies listed in §5.1. Three crates are split out so that it, and the worker, carry only what
they need (review findings 5 and 6):

| New crate | Layer | Holds | Consumers |
| --- | --- | --- | --- |
| `casual-sign-policy` | Host (pure, no I/O, no store) | `OrgPolicy`, `effective` (§3); `plans::effective` (§7); the action catalogue types | server, worker, console |
| `casual-sign-platform-store` | Host | The `platform` schema's repositories and definer-function calls; its own pool as `openseal_console` | console |
| `casual-sign-keyd-client` | Host | keyd's wire format and mTLS client, without `cryptoki`, the file key or the server | worker, console; keyd keeps the server side |

- The console **never depends on `casual-sign-server`, `-host` or `-store`**, and none of them depends on it.
- The web UI is `console-ui/` at the repository root (vanilla ES modules, its own command registry and CSP), embedded
  in this binary at compile time and served only by it. *Not* `webapp/console/`, as first written: the public server
  serves `webapp/` wholesale, so a console folder there would also be served on the public origin (CON-17, §5.6).
- Listens on `OPENSEAL_CONSOLE_LISTEN`, default `127.0.0.1:8090`. A non-loopback bind needs `OPENSEAL_CONSOLE_PUBLIC=1`
  and refuses to start without TLS settings or `OPENSEAL_TRUSTED_PROXIES` (`CS-CON-0005`).
- First consumer: the operators. Added to docs/19 and to Compose as its own service with its own database credentials.

*Why separate:* the public server never holds `openseal_console` credentials, so an RCE in the public tier cannot use
them; it can sit on a private network; the public binary's surface does not grow. *Rejected:* the same binary with a
feature flag (credentials and code still ship in the public image); `/console` on the public listener (one origin bug
from tenant cookies).

### 5.3 Organizations, workspaces and their properties

The console can create an organization (with first workspace, owner invitation and plan); rename it; suspend, resume
and close it (two-person); set data-region labels, plan and overrides (§7); list workspaces with counts; archive a
workspace (organization admins can too); view usage; and turn self-sign-up on (Q5; off by default, two-person).

- **Suspension** refuses tenant writes that start something (`CS-PLAN-0005`). Reads, exports, signer ceremonies and
  sealing of sent envelopes continue (§7.3).
- **An archived workspace** refuses new envelopes, members and settings (`CS-ORG-0010`); **signer ceremonies,
  reminders, sealing and downloads of envelopes already sent continue** (review finding 21), as under suspension.
- **Closing an organization** (review finding 20) suspends it, then after a notice period set by the platform (default
  30 days, during which organization admins can export every workspace's agreements and logs) makes it read-only. Its
  evidence is kept under each workspace's retention policy and purged only by it; closing never purges. The full
  closure lifecycle is `ORG-21`.
- `casual-sign-server bootstrap` stays for a single-tenant self-hosted install and creates the first organization and
  workspace (§2.1). The console's `bootstrap-operator` creates the first `platform_owner`.

### 5.4 Keys, certificates, TSA and trust lists, without holding private keys

- **keyd admin interface.** New read-only operations on the same framed protocol, authorized by a **second allow-list**
  (`OPENSEAL_KEYD_ADMIN_ALLOW_LIST`); a client on it cannot sign, and a signing client cannot call them:
  - `list-keys`: alias, backend kind (`pkcs11`, `kms:*`, `file-dev`), algorithm, certificate chain DER, validity,
    development flag;
  - `oplog-head`: sequence and hash;
  - `oplog-range(from_seq, n)`: sequence, time, caller fingerprint, alias, algorithm, digest, envelope id, outcome; no
    document bytes or personal data;
  - `health`: HSM session state (review finding 21: health over the existing protocol, no HTTP stack on the HSM host).
  Each call is written to keyd's own operation log.
- **Keys are provisioned out of band** by the key custodian in the HSM or KMS. A CSR is made with the offline CLI on the
  keyd host, never through the console (a CSR is a signature over arbitrary data). **Rotation** is a two-person change
  of `platform.seal_profiles.active_alias` with `active_from`, read by the worker per seal job; keyd must report the
  alias, and the worker refuses one it does not list or whose change was not approved (`CS-CON-0006`).
  Per-organization seal identities are a later plan entitlement.
- **TSA and trust anchors move from environment to database**: `platform.tsa_endpoints` (URL, policy OID, priority,
  enabled, expected TSA certificate hash) and `platform.trust_anchors` (DER, SHA-256, purpose `tsa`, `ocsp`, `verify`;
  source `manual`, later EU LOTL and AATL), written by `key_custodian` with two-person approval, read by the worker with
  a short cache. URLs pass the `SEC-W01` address policy when saved and when used. `OPENSEAL_TSA_URLS` and
  `OPENSEAL_TRUST_ANCHORS` remain the fallback when the tables are empty. Values reach the engine as supplied values
  (ADR-004).
- **Expiry alerts.** Daily job `certificate_expiry_scan` over keyd chains, TSA certificates seen in responses, trust
  anchors and the console's TLS certificate: alerts at 90, 30 and 7 days; an alias whose certificate has expired is
  refused for sealing.
- **Reconciliation (`KEYD-03`; review finding 11).** keyd's log records the signed-attributes digest, which no audit
  event carries, and the console has no blob access. So the seal job also writes, in the transaction that records
  `document.sealed`, an operational row `seal_signatures (account_id, envelope_id, digest, alias, at)`. This is a
  tenant table of hashes and ids, not evidence, so no audit schema change. The console pages `oplog-range` and matches
  each signature against `platform.seal_digests(from, to)`, a definer function returning only envelope ids and digests.
  Results go to `platform.reconciliation_runs`:
  - a signature with no matching row whose envelope later sealed is an *orphaned retry* (a seal job that signed and then
    lost its lease), listed;
  - any other unmatched signature, in either direction, raises an alert and an operator event (`CS-CON-0009`).
  *Rejected:* adding the digest to `document.sealed` (an audit schema change for an operational check); reconciling in
  the worker (it would need the admin identity beside its signing one).

### 5.5 Health and monitoring

| Service | Ops listener (`OPENSEAL_OPS_LISTEN`, loopback by default, never the public port) | Key metrics (Prometheus text; no personal data, no account ids as labels) |
| --- | --- | --- |
| server | `/livez`, `/readyz` (DB, blob store), `/metrics` | requests by route template and status, latency, rate-limit refusals, `CS-*` counts by code, login failures |
| worker | same (DB, blob store, SMTP, keyd reachable) | jobs claimed, done, retried and dead by kind and code; seal duration; TSA latency and failures by endpoint; webhook and e-mail failures |
| keyd | none: `health` over its own protocol, read by the console and the worker's `/readyz` | signatures by alias and outcome, latency, refusals, log sequence (through `oplog-head` and `health`) |
| console | same as server | operator logins, MFA failures, approvals pending |
| database | through console functions | `platform.job_stats()` (queued, running, dead by kind; oldest queued age), `platform.pool_stats()` |

- **OpenTelemetry** behind the cargo feature `otel` (off by default; licences checked in `deny.toml`). Span attributes
  are ids and codes only; a scrubber test runs every error code through the exporter.
- **The console Services page** reads the ops endpoints listed in `platform.service_targets`, set by deployment
  configuration, never typed into the UI (`SEC-X06`).
- **Dead letters** show job id, kind, workspace id, envelope id, error code, attempts and time, never the payload.
  `operator` can retry one (attempts reset, operator event).
- `OperatorAlert` (worker) becomes rows in `platform.alerts` through a definer function, plus an optional outbound
  webhook for paging (slice 20).

### 5.6 As built (`CON-02`, `CON-03`, `CON-04` and `CON-05` first parts; migrations 0016 to 0019)

**What exists.** The separate binary `server/casual-sign-console` and its store `server/casual-sign-platform-store`.
The console depends on the platform store and `casual-sign-secrets` only, never on `casual-sign-store`, `-host` or
`-server`. Migrations stay with the store's runner (`casual_sign_store::MIGRATIONS`), so one migrator applies them all;
the platform store never runs migrations. The numbers were the next free ones when this was built (0016 to 0019);
§2's order put ORG-05's admin logs first; the console merged first, so the admin logs became 0020 (§2).

- **0016 `platform` schema.** Role `openseal_console` (NOLOGIN; a LOGIN role is granted membership), USAGE on
  `platform` only. Tables `settings` (self-sign-up `false`), `service_targets` (deployment configuration, written by
  `casual-sign-console set-service-target` as the migrator, `SEC-X06`) and `alerts` (append-only). Definer functions
  returning ids, names, statuses, labels, counts and times only: `organizations_page`, `organization`,
  `organization_workspaces` (members, templates, envelopes by draft, in progress, completed), `job_stats` (queued,
  running, dead by kind; oldest queued age), `dead_jobs` (no payload), `pool_stats`. Each migration ends by revoking
  EXECUTE on every `platform` function from PUBLIC, so the console runs only the functions granted by name.
- **0017 operators.** `operators` (e-mail, Argon2id hash, roles, disabled), `operator_mfa` (sealed seed, last used
  step), `operator_enrolments`, `operator_sessions` (hashes of the token and CSRF token, `mfa_at`), `operator_events`
  and `operator_chain`. Writes only through definer functions that take the operator from a live session row:
  `open_session`, `confirm_mfa`, `resolve_session`, `revoke_session`, `bootstrap_operator`, `create_operator`,
  `begin_enrolment`, `finish_enrolment`, `disable_operator`. The chain trigger checks the hash, `seq`, `prev`, and that
  the canonical JSON names the row's seq, prev, action and operator (`OS005`); UPDATE, DELETE and TRUNCATE are refused
  for every role (`OS001`).
- **0018 single-operator writes** (`operator` or `platform_owner`, re-checked in the database): rename an organization,
  set its data-region labels, set a workspace's label (one of its organization's) and archive or restore it.
- **0019 the two-person rule**, used first for suspending and resuming an organization. `approval_requests`,
  `approval_grants`, `approval_uses` (insert-only for every role, `uses` keyed on the request). The functions are
  `platform.request_approval` and `platform.grant_approval` (§5.1's `request` and `grant`: `GRANT` is a reserved
  word) and `platform.apply_suspend_organization`, `platform.apply_resume_organization`. The payload hash is SHA-256
  of `<action>\n<organization id>`, recomputed by the apply function from its own parameters. Each of the three steps
  needs a second factor entered within 5 minutes (`platform.fresh_operator`, `CS-CON-0002`); the grant must be by
  another operator and records the approver's second-factor time; the apply is by the requester and spends the
  approval once (`CS-CON-0004` for every refusal). Requests live 24 hours. The console has no write grant on
  `organizations.status`, so these functions are its only way to change it (`SEC-X08`).

**Decided while building** (within ADR-028; recorded here as the owning note):

1. **Operators enrol themselves.** §5.1 said the console never sets a password or MFA factor on a tenant identity;
   the same now holds between operators. `bootstrap-operator <email>` and `POST /operators` create an operator with no
   password and no factor and return a one-time enrolment token (24 hours; the database refuses more than 7 days).
   The operator opens it, receives a fresh TOTP seed once (`otpauth://`, labelled with the operator id, never the
   e-mail), then sets their password and proves the seed with a code. Whoever created them never knows either. The
   same link is what `recover-operator` will mint (`CON-14`).
2. **Sign-in is two requests.** `POST /auth/login` checks the password (Argon2id on a blocking thread; an unknown
   e-mail is checked against a dummy hash, and both answer `CS-CON-0001`) and opens a session with `mfa_at` NULL;
   `POST /auth/totp` checks the code against steps −1, 0 and +1 and the database accepts the step only if it is later
   than the operator's last, so a code is single-use. A session without its second factor reaches nothing else
   (`CS-CON-0002`, every route tested).
3. **TOTP** is RFC 6238 over `aws-lc-rs` HMAC (SHA-1, 6 digits, 30 s), test-vectored against RFC 6238 Appendix B and
   RFC 4226 Appendix D. Seeds are sealed with AES-256-GCM under `OPENSEAL_CONSOLE_MFA_KEY` with the operator id as
   associated data.
4. **Deny by default in the type system.** A handler gets an operator only through `Authed<N>`, whose `N` names the
   roles; `ROUTES` lists each route's `x-roles`, and the contract test keeps it equal to `api/console-openapi.yaml`.
   Writes are re-checked by the database (`platform.acting_operator`).
5. **Operator events carry ids, codes, labels and counts only** (`EventDraft` refuses free text): never an
   organization's name, an e-mail or a value. They record the operator's own address and the request id (§5.1).
   Refused sign-ins are recorded too (with the operator id when the e-mail is an operator's).
6. **Listener.** Loopback by default; a non-loopback bind needs `OPENSEAL_CONSOLE_PUBLIC=1` and
   `OPENSEAL_TRUSTED_PROXIES` (TLS terminates at the proxy; no TLS in the binary yet), and the console's origin may not
   equal the application's (`CS-CON-0005`). The console verifies the whole operator log at start and refuses to start
   when it does not verify (`CS-CON-0007`).
7. **Health probes** read `platform.service_targets`: `http` (GET, healthy on 2xx, no redirects, plain HTTP on the
   private network) or `tcp` (connect), 2-second timeout, at most 64. keyd and TLS endpoints (TSA) are `tcp` targets
   until keyd's admin `health` and `list-keys` (`CON-06`) and the servers' ops listeners (`CON-05`) exist.

**API** (`/console/v1`, `api/console-openapi.yaml`): `auth/login`, `auth/totp`, `auth/logout`,
`auth/enrolment/begin`, `auth/enrolment/finish`, `me`, `operators` (GET, POST), `operators/{id}/disable`,
`operator-log` and `operator-log/verify`, `organizations` and `organizations/{id}` (GET, PATCH), `workspaces/{id}`
(PATCH), `approvals` (GET, POST), `approvals/{id}/grant`, `organizations/{id}/suspend` and `…/resume`, `health`,
`dead-letters`, `alerts`; `/livez`, `/readyz`.

**Tests** (Postgres 17, `server/casual-sign-console/tests/`): `catalog.rs` (`SEC-X01`, `SEC-X02` grants, the exact
platform grants, `SEC-X04` in the database), `api.rs` (every route's session and second factor, enrolment, single-use
codes, idle and sign-out, CSRF, roles and the database re-check, reads and writes, the personal-data and content
scan over every GET route, a tampered log, rate limits), `approvals.rs` (`SEC-X08`: no approval, ungranted,
self-approval, another action or organization, the approver applying, reuse, stale second factors, direct writes),
`contract.rs` (route table, OpenAPI and router). Each guard
was seen red by a mutation (docs/07 `SEC-X01` to `SEC-X04`).

**The UI (`CON-17`).** `console-ui/` at the repository root: `index.html`, `console.css`, and ES modules `app.js`
(screens, routing, the command registry, side panels), `api.js` (the `/console/v1` client; the CSRF token sign-in
returned kept in `sessionStorage` for the tab), `model.js` (pure logic, unit-tested with `node --test`), `dom.js`
(`h()` from `webapp/dom.js`) and `art.js` (illustrations), with Geist and Geist Mono in `console-ui/fonts/`
(PROVENANCE.md). No framework, no build step, no inline script or style.

- **Served by the console binary only** (`src/ui.rs`): every file is embedded with `include_bytes!`, so the binary is
  self-contained and no request path reaches the file system; any other path is the API's `404 CS-CON-0011`. Each UI
  file carries the policy `default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src
  'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`; fonts
  (versioned names) are cached for a year, the rest `no-cache`. The request middleware keeps `no-store` and the policy
  that loads nothing on everything else (the API), and no longer overwrites a response's own cache and page policy.
- **Screens**, from the approved canvas (`docs/assets/design-canvas/Console.dc.html`): sign-in (password, then TOTP),
  enrolment from the one-time link (`#/enrol/<token>`, kept in the fragment so it never reaches a server log; the key
  shown once, as text and an `otpauth:` link), Health, Organizations (list, filter of loaded pages, detail with
  workspaces, rename, region labels, workspace label and archive), the two-person suspend and resume (request, grant
  by another operator in Approvals, apply by the requester), Approvals, Operators (owners only: add with the one-time
  link shown once, disable) and the Operator log (paged, verify). Screens follow the API's `x-roles`; the server still
  decides. Every write that needs a fresh second factor says so; when the server answers `CS-CON-0002` a side panel asks
  for a new code, sends it to `/auth/totp` and repeats the action.
- **Only what the API returns.** Health tiles are queue depth (oldest queued, running), dead letters, database and
  connections, services up, and whether the operator log verifies. The canvas's sparklines and usual-range bands need
  metric history the API does not keep, so tiles show current values; alerts are listed with resolved ones dimmed and
  an all-clear state, without the canvas's Acknowledge (the API has no acknowledgement); the canvas's model-service
  card is left out (no model-health API). Loading skeletons, illustrated empty states, error states with retry; fluid
  rem root, controls that never wrap, keyboard and screen-reader use (focus moves to each screen's heading, panels trap
  focus and close on Esc), reduced motion respected.
- **Tests.** `tests/ui.rs`: the page and every file with type, policy and cache; everything the page, modules and
  stylesheet reference is served; unknown files, traversal and source-only files are `404` problems; the API keeps its
  headers (seen red when the middleware overwrote the UI's policy again). `console-ui/tests/model.test.mjs` (15 unit
  tests). `console-ui/e2e/console.spec.mjs` (Playwright, headless): `serve.sh` starts the real binary on a fresh
  migrated database with the console's own LOGIN role, then two operators enrol, sign in, rename, label, request,
  grant (re-entering a second factor the test makes stale), apply a suspension, verify the log and sign out.

**Not yet built** (rows in docs/14): the Compose
service and the console's LOGIN role in deployment (`CON-02`); `casual-sign-keyd-client` (`CON-15`); the other
two-person actions (organization create, close, owner recovery, identity disable, adding a platform owner) and the
server refusing new work in a suspended organization (`CS-PLAN-0005`) (`CON-04`); copies of
operator actions into organization logs through `platform.copy_to_org_log` (`CON-16`, needs `ORG-05`); TOTP re-entry
for key and trust actions (`CON-07`); ops listeners and metrics on server and worker, keyd health (`CON-05`); keys,
certificates and expiry (`CON-06`, `CON-08`); plans and limits (`PLAN-02`).

## 6. API additions (`/api/v1`, additive)

```
/auth/workspaces                          GET    the caller's workspaces, grouped by organization
/auth/switch                              POST   {account_id} → new session for that workspace
/organizations/me                         GET, PATCH         name, policy (with locks)
/organizations/me/workspaces              GET, POST          ; /{id} GET, PATCH, POST …/archive, POST …/join
/organizations/me/users                   GET (directory)    ; /{id} GET, PATCH (identity attributes, §2.3 rule 2)
/organizations/me/users/{id}/memberships  GET, POST, DELETE (re-home)
/organizations/me/admins                  GET, POST          ; /{user} PATCH, DELETE
/organizations/me/permission-sets         CRUD
/organizations/me/domains                 GET, POST          ; /{d} DELETE, POST …/verify
/organizations/me/identity-providers      CRUD (owner)
/organizations/me/approvals               GET ; /{id} POST …/approve (owner)
/organizations/me/scim-tokens             GET, POST, DELETE
/organizations/me/template-copies         POST {template_id, from_workspace, to_workspace}
/organizations/me/usage                   GET ?from&to&meter&workspace&format=json|csv
/organizations/me/audit                   GET ?cursor&format=json|csv
/admin-events                             GET   workspace admin log
/usage                                    GET   workspace usage against its plan
/envelopes/{id}/transfer                  POST {to_user}
/envelopes/{id}/evidence-package          GET   (completed envelopes; records envelope.exported)
/archived-agreements                      GET, POST (import a package) ; /{id} GET
/scim/v2/…                                SCIM 2.0 (Users, Groups), organization token
```

New OAuth scopes: `org:read`, `org:admin`, `org:users`, `org:identity`, `org:usage`, granted only to clients whose
owner holds the matching organization actions, narrowed by `grantable`.

## 7. Plans, metering, enforcement, export

### 7.1 Schema (in `platform`; `openseal_app` reads through `openseal_effective_plan()`)

```
plans                (id, key, version, name, created_at, archived_at)     -- immutable per version
plan_entitlements    (plan_id, feature, enabled)       -- bulk_send, sso_saml, scim, api, webhooks, sms_auth,
                                                       --   conditional_routing, payments, branding_multi, seal_b_lta, ml_suggestions
plan_quotas          (plan_id, meter, limit, period, enforcement, level)  -- period month|year|none;
                                                       --   enforcement hard|soft|notify; level organization|workspace
plan_seat_rule       (plan_id, rule)                   -- Q6: 'can_send' (default) or 'every_member'
plan_assignments     (organization_id, plan_id, starts_at, ends_at, assigned_by)
plan_overrides       (organization_id, workspace_id NULL, key, value, reason, expires_at, operator_id)
```

`plan_overrides` names its column `workspace_id`, not `account_id`, and lives in `platform`, so the `public` catalog
rules do not apply to it (review finding 9). `org_workspace_allocations (organization_id, account_id, meter, limit)` is
a `public` organization table (§2.1), written by organization admins, read by the send path (later, `PLAN-07`).

The effective plan is the assignment current at `now`, plus unexpired overrides, plus allocations, resolved by the pure
`casual-sign-policy::plans::effective`. `accounts.settings` holds no plan limits today (the comment in `migrations/0002`
is the only mention), so there is nothing to copy; the comment is corrected in PLAN-02's migration notes. A plan may
not set `hard` on an approximate meter (§7.2; `CS-PLAN-0006`).

### 7.2 Meters

| Meter | Kind | Counted when | Where written |
| --- | --- | --- | --- |
| `envelopes_sent` | counter | `envelope.sent` committed (once per envelope; corrections, resends and reminders do not count; each bulk row counts) | deciding transaction (`casual-sign-host::apply`) |
| `seats` | gauge | enabled members whose profile meets the plan's seat rule (Q6), distinct identities per organization | recomputed in the membership or profile change's transaction, through `openseal_org_seats()` |
| `storage_bytes` | gauge | bytes of document versions and captures referenced by the workspace (content-addressed blobs counted once per workspace) | on document write and purge |
| `api_calls` | counter | each authenticated `/api/v1` request by a client credential | in memory per instance, flushed each minute; **approximate, so soft or notify only** (review finding 21) |
| `sms_sent`, `phone_calls`, `idv_checks`, `kba_checks` | counter | provider job succeeds | worker job transaction |
| `timestamps`, `seals` | counter | seal job records `document.sealed` | worker |
| `bulk_send_rows`, `signing_link_submissions`, `webhook_deliveries` | counter | as named | deciding or job transaction |
| `workspaces`, `templates` | gauge | create, archive | organization or workspace transaction |

- **Ledger.** `usage_ledger (account_id, meter, quantity, at, source_kind, source_id)`, a tenant table, append-only;
  `UNIQUE (account_id, meter, source_kind, source_id)` makes metering idempotent under job retries. Ids and counts only.
- **Counters.** `usage_counters (account_id, meter, period_start, value)` per workspace, and **`org_usage_counters
  (organization_id, meter, period_start, value)`** per organization (review finding 8), updated in the same
  transaction as the ledger row.

### 7.3 Enforcement (only on actions that create or start something)

| Point | Checks | Code |
| --- | --- | --- |
| `POST /envelopes/{id}/send`, `POST /envelopes` with send, bulk row dispatch | `envelopes_sent`; entitlements the envelope uses (SMS auth, conditional routing, payments, B-LTA) | `CS-PLAN-0002`, `CS-PLAN-0001` |
| Invite, enable or re-profile a member to a seat-counting profile; SCIM create | `seats` | `CS-PLAN-0003` |
| Document upload, signer attachment *before send* | `storage_bytes` | `CS-PLAN-0004` |
| Any `/api/v1` client-credential request | `api` entitlement; `api_calls` (soft or notify) | `CS-PLAN-0001` |
| Create webhook, IdP, SCIM token, brand beyond one, workspace | entitlement or quota | `CS-PLAN-0001`, `CS-PLAN-0002` |
| Any of the above while the organization is suspended | status | `CS-PLAN-0005` |

- **Quota checks are atomic at both levels** (review finding 8). `openseal_consume_quota(p_meter, p_n, p_ws_limit,
  p_org_limit, p_period_start)` is a definer function that derives the organization from the current account, then
  runs the conditional updates `UPDATE … SET value = value + n WHERE … AND value + n <= limit` on the workspace counter
  and on the organization counter (creating each period's row with `INSERT … ON CONFLICT DO NOTHING` first). Zero rows
  on either refuses, and the transaction rolls back both. The organization row is the serialization point, so parallel
  sends in two workspaces cannot overshoot an organization quota (`SEC-U01`). Limits come from
  `plans::effective`, computed in the same request.
- **Seats** are counted by `openseal_org_seats()` (definer; distinct identities across the organization's workspaces)
  under a lock on the organization's `seats` counter row, so two parallel invites cannot both take the last seat.
- **Evidence before billing** (`SEC-U02`). Nothing in a sent envelope's life is refused for plan reasons: recipient
  views, signing, OTP e-mails, reminders, sealing, timestamping, completion e-mails, downloads. An SMS needed by a sent
  envelope is metered even when the quota is spent, and flagged as overage.
- `soft` allows the action, records the overage, notifies organization admins; `notify` only notifies.
- **Problem details** carry `meter`, `limit`, `used`, `period_end` and `feature`, nothing else.

### 7.4 Usage export

- **Organization admins:** `GET /organizations/me/usage?format=csv|json`, per workspace, meter and period, from
  counters, with optional ledger detail (ids only).
- **Console:** every organization, CSV or JSON, for a period.
- At period close, an opt-in `usage.period_closed` webhook to the organization, and a `platform` export record.
- Rows carry stable ids, so a later **`BillingProvider`** host plugin (Stripe first; separate ADR) consumes them
  idempotently.

### 7.5 What is not claimed

`data_regions` and `accounts.data_region` are labels in one database. Nothing here provides or claims data residency
(docs/09); residency needs a per-region deployment, which is its own row (`ORG-26`).

## 8. Error codes (proposed in [20](20-ERROR-CODE-REGISTRY.md))

New ranges `CS-ORG`, `CS-PLAN`, `CS-CON`; two `CS-DB` codes; `CS-DB-0004` widened. All proposed until a row issues
them. Messages carry codes, ids and counts only.

| Code | Meaning (HTTP) |
| --- | --- |
| CS-ORG-0001 | Not a member of that workspace, or the membership is disabled (switch, 403) |
| CS-ORG-0002 | Setting locked or tightened by the organization's policy (422; names the key) |
| CS-ORG-0003 | Domain not verified (TXT record absent or wrong) (422) |
| CS-ORG-0004 | Domain cannot be claimed (already claimed, or a public e-mail domain); never says by whom (409) |
| CS-ORG-0005 | Grant refused: exceeds the granting admin's own rights or scope, or grants to itself (403) |
| CS-ORG-0006 | Sign-in method not allowed for this identity by its governing organization's policy (401) |
| CS-ORG-0007 | Switching needs a fresh sign-in satisfying the target organization's policy (401; names the method) |
| CS-ORG-0008 | The organization must keep at least one enabled owner (409) |
| CS-ORG-0009 | Envelopes do not move between workspaces; transfer within one, or export the evidence package (422) |
| CS-ORG-0010 | Workspace archived: no new envelopes, members or settings (409) |
| CS-ORG-0011 | Identity-provider assertion for an identity outside the provider organization's verified domains, or with no binding (401) |
| CS-ORG-0012 | *Withdrawn before issue:* the identity-attribute refusal is `CS-API-0015`, issued by `SEC-ID-01`. Never reused |
| CS-ORG-0013 | Action reserved to an organization owner, or awaiting an owner's approval (403) |
| CS-ORG-0014 | Sensitive action needs a fresh sign-in (401) |
| CS-ORG-0015 | Organization closed: read-only (409) |
| CS-ORG-0016 | Cross-workspace template copy not allowed by the organization's policy (403) |
| CS-ORG-0017 | Imported evidence package does not verify (422; names the failing check) |
| CS-PLAN-0001 | Feature not in the plan (403; names the feature) |
| CS-PLAN-0002 | Quota for the period reached (403; meter, limit, used, period end) |
| CS-PLAN-0003 | Seat limit reached (403) |
| CS-PLAN-0004 | Storage limit reached (403) |
| CS-PLAN-0005 | Organization suspended by the platform: new work refused, sent envelopes continue (403) |
| CS-PLAN-0006 | Plan, quota or override invalid, including `hard` on an approximate meter (console, 422) |
| CS-PLAN-0007 | Workspace allocations exceed the organization's quota (422) |
| CS-CON-0001 | Operator not authenticated, or the session expired (401) |
| CS-CON-0002 | Second factor required, stale or wrong (401) |
| CS-CON-0003 | Operator role lacks the action (403) |
| CS-CON-0004 | Action needs a second operator's approval; missing, expired, used, by the requester, or for another payload (409) |
| CS-CON-0005 | Console listener refused: public bind without `OPENSEAL_CONSOLE_PUBLIC=1` and TLS or trusted proxies (start-up) |
| CS-CON-0006 | Seal alias, TSA or trust anchor refused: unknown to keyd, expired, unapproved, or fails its check (422) |
| CS-CON-0007 | Operator log does not verify; the console refuses writes (start-up and per write) |
| CS-CON-0008 | keyd admin call refused: caller not on the admin allow-list, or a signing call from an admin client |
| CS-CON-0009 | Reconciliation found a keyd signature with no seal record, or a seal record with no signature (alert) |
| CS-DB-0013 | Change to an immutable column refused (a workspace's organization, outside ORG-20's operator link) (SQLSTATE `OS004`) |
| CS-DB-0014 | Admin or operator log event does not extend its chain: hash, `seq` or `prev` (SQLSTATE `OS005`) |

## 9. Threats this adds (rows in [07](07-SECURITY-THREAT-MODEL.md), status Designed)

| ID | Threat | Control | Test that must be seen red |
| --- | --- | --- | --- |
| SEC-O01 | Cross-workspace leakage through organization scope | Content tables keep single-account RLS; `openseal_current_org()` NULL when an account is set; organization policies `FOR SELECT` on three tables only; reach into a workspace only through `WorkspaceOf` and a single-account `TenantTx` | `OrgTx` selecting from every content table returns 0 rows (red when a content table gets an organization policy); organization admin of org A calls every organization route with ids from org B → 404, RLS on and off (generated, as `SEC-A04`) |
| SEC-O02 | Privilege escalation through delegated admin (wider rights or scope, self-grants, wider API key, SCIM mapping to admin, self-join) | One `grantable()` on every grant path; `org.workspaces.join` never delegated; property test; generated route test | For each grant route, a delegated admin requesting one action or one group beyond its own, or anything for itself → `CS-ORG-0005` (red with `grantable` returning true) |
| SEC-O03 | Workspace admin loosening a locked or tightened organization policy | `effective()` on every settings write and every login | PATCH of each locked key → `CS-ORG-0002`; password login for a claimed-domain identity under SSO-required → `CS-ORG-0006` |
| SEC-O04 | Domain-claim hijack to capture identities or force an IdP; a claim's reach into another organization | 256-bit TXT token, daily re-check; one claim per domain; a claim gives login policy and identity rights only, never membership; other organizations see the badge and an event | Unverified claim changes no login; second claim → `CS-ORG-0004` with no owner in the body |
| SEC-O05 | Session or credential of workspace A acting in workspace B | Account only from the credential; switch issues a new session; template copy is an organization route with proofs for both sides | A's cookie with B's ids → 404; switch without membership → `CS-ORG-0001` |
| SEC-O06 | Stale rights after removal or role change | Rights resolved per request; no cache | Removed organization admin's next request → 403 |
| SEC-O07 | Organization admin reading agreements silently | No content right from a role; only owners and admins join, visibly and notified; no self-grants | Owner with no membership → 404 on an envelope; join writes `admin.member_added` (`via: organization`); a delegated admin's join → `CS-AUTH-0006` |
| SEC-O08 | IdP of organization A asserting an identity it does not govern | Assertion accepted only with a `user_identities` binding and a verified claim of the IdP's organization on the identity's domain | Assertion for another organization's or an unclaimed domain → `CS-ORG-0011`; binding present but claim lapsed → `CS-ORG-0011` |
| SEC-O09 | Cross-workspace takeover through the shared identity (an admin of B changes the password, name, MFA or disabled state of a member of A) — `SEC-ID-01` | §2.3 rule: self, domain-claiming organization, or sole-membership workspace admin (rules 2 and 4 only once ORG-11 and CON-04 merge); definer functions; the `users` UPDATE policy admits sole members only (migration 0013); sessions revoked in every workspace | B's admin sets password or name of a member of A and B → `CS-API-0015` (red on `5657c8e`); user's own change ends sessions in A and B |
| SEC-O10 | Workspace re-parented into another organization, then read through `WorkspaceOf` | Trigger refuses changes to `organization_id`; no INSERT on `accounts` for the app; column grants; the trigger admits only `openseal_org_mover`, a NOLOGIN role without members owning one two-person definer function, `platform.apply_link_workspaces` (`ORG-20`) | UPDATE of `organization_id` in account scope and as owner → `CS-DB-0013`; INSERT into `accounts` as `openseal_app` → denied; catalog test 6 red when `openseal_org_mover` gains a member or a second function |
| SEC-O11 | Delegated or non-owner admin capturing the owner through configuration (own IdP plus SSO-required, MFA or password policy loosened) | IdP, SSO enforcement and security loosening owner-only or owner-approved; all owners notified; IdP never signs in a higher org role than its configurer | Admin and delegated admin creating an IdP, enforcing SSO or unlocking MFA → `CS-ORG-0013` |
| SEC-O12 | Indirect escalation through sensitive workspace actions (webhooks exporting recipient data, short retention, weaker recipient auth, `frame-ancestors`) | Sensitive actions: fresh sign-in, admin event, organization floors, never group-scoped | Group-scoped profile granted `webhooks.manage` → `CS-ORG-0005`; retention below the floor → `CS-ORG-0002`; stale sign-in → `CS-ORG-0014` |
| SEC-X01 | Operator reads agreement content or personal data | `openseal_console` has no grant on `public`; metadata only through definer functions returning ids, names, statuses, counts; console crate graph has no tenant store; no blob or keyd-sign configuration | Catalog-driven SELECT as `openseal_console` on every `public` table → denied (red after one GRANT); console e2e scans responses for seeded e-mails and names |
| SEC-X02 | Operator impersonates a tenant user | No code path; no grant on `staff_sessions`, `api_clients`, `user_invitations`, `users`; organization creation and owner recovery create invitations only, through two-person definer functions | INSERT as `openseal_console` into each → denied; recovery without approval → `CS-CON-0004`; creation for an existing e-mail sets no attribute and answers the same |
| SEC-X03 | Operator credential phishing or theft | Private listener by default, separate origin, `__Host-` cookie, mandatory TOTP, short sessions, TOTP re-entry for sensitive actions, login rate limits | Public bind refused (`CS-CON-0005`); password-only session reaches nothing (`CS-CON-0002`) |
| SEC-X04 | Rogue operator rewrites the operator log | Append-only grants and triggers, hash chain, copies in organization logs, daily head exported | UPDATE or DELETE as both roles → `CS-DB-0004`; tampered row → `CS-CON-0007` at start |
| SEC-X05 | Operator swaps the seal key, TSA or trust anchor | `key_custodian` role, two-person definer functions, keyd lists the alias, worker checks the approval event, published roots for verifiers | Single-operator change → `CS-CON-0004`; alias unknown to keyd or unapproved → `CS-CON-0006` |
| SEC-X06 | Console as an SSRF tool (TSA URLs, health targets) | Health targets from deployment configuration; TSA URLs through the `SEC-W01` policy | Private-address TSA URL refused |
| SEC-X07 | Break-glass abuse | Operator recovery needs migrator credentials on the host; owner recovery needs two operators, a verified domain, a copied event | Recovery without approval refused; event in the organization log |
| SEC-X08 | Two-person rule bypassed by a compromised console or one holder of its database credentials | Sensitive tables have no direct write grant; definer functions check an unused grant by another operator with fresh TOTP; approvals insert-only; residual stated in §5.1 | Direct UPDATE of `seal_profiles` as `openseal_console` → denied; `apply_*` with the requester's own grant, a reused grant or another payload → `CS-CON-0004` |
| SEC-U01 | Quota overshoot by concurrent sends or invites, in one workspace or across an organization's workspaces | Conditional updates of workspace and organization counters in one definer function; seats under a counter-row lock | 50 parallel sends against limit 10, split over two workspaces of one organization → exactly 10 succeed (red with check-then-update) |
| SEC-U02 | Plan enforcement stalling evidence | Enforcement only where something is created or started | Envelope sent, then quota zeroed, organization suspended and workspace archived → signing, sealing and the verified seal still complete |
| SEC-U03 | Usage export or metrics leak personal data | Ledger and metrics hold ids and counts only | Export and `/metrics` scanned for seeded personal data |

## 10. Screens

All screens use the docs/47 design system, rem units and side panels rather than dialogs (instruction 22), with seal red
`#b3141f` as the accent and destructive actions styled distinctly (instruction 26).

**Organization admin** (`app.html#/org`, shown when the user holds an organization role; hidden for an organization of
one workspace until a second is created, as SignNow does): Overview (workspaces, seats, envelopes against limits,
alerts, operator actions); Workspaces (list, create, rename, archive, admins, join); Users (directory with memberships,
status, last sign-in, claimed-domain badge; add, move; identity actions where §2.3 allows); Administrators (owners,
admins, delegated admins; permission sets with workspace scope); Identity (domains, IdPs, SSO enforcement, JIT, SCIM;
owner-only items marked, with pending approvals); Security policy (each key with a lock); Data and retention (range,
region labels, legal hold when `ORG-23` lands); Branding and defaults; Plan and usage (charts per docs/47, export);
Audit log (organization and operator events, filters, export).

**Workspace admin** (`#/admin`, extending today's three tabs): Overview, Users (invite, profile, disable, transfer
envelopes, resend invitation), Groups, Permission profiles (delegated admin with group scope), Sending, Signing and
recipient authentication, Brands, ERSD, Template sharing, Retention, Webhooks, API apps and keys, Seal and timestamp
(read-only unless entitled), Usage, Archived agreements, Admin audit log. Settings set by the organization show a lock
and "Set by your organization". The workspace switcher sits in the top bar's account menu.

**Console** (`console-ui/`, served by the console binary; §5.6): Sign in (password, then TOTP); Dashboard (services, alerts, certificates expiring, dead
letters, queues, pending approvals); Organizations (search, detail, plan, overrides, usage, status, owner recovery,
history); Plans; Usage; Keys and certificates; Timestamping; Trust lists; Services; Reconciliation; Operators;
Approvals; Operator log (verify, export); Platform settings (default plan, self-sign-up, allowed region labels).

## 11. Engine and evidence changes

The earlier draft said "no engine crate changes"; that was wrong (review finding 7). The full list:

- `casual-sign-workflow` (`command.rs`, `engine.rs`): the command `Transfer {to_user}`, allowed on any envelope not
  purged, by a principal holding `envelopes.transfer`.
- `casual-sign-audit` (`event.rs`): two additive types, `envelope.transferred {from_user, to_user}` and the access
  event `envelope.exported {by}`. Additive to ADR-010 exactly as ADR-027 was: earlier chains hash unchanged, and
  earlier verifiers list the types as unrecognised, not failed (`casual-sign-audit::verify`'s `unrecognised`).
- Both compile to wasm32 with no `#[cfg]` fork; the wasm parity check runs on the change. docs/24 (the command) and
  docs/32 §3 (the types) are updated by the row that builds them (`ORG-09`).
- Nothing else enters an engine crate: the archived agreement is a host-side row (§2.4), the admin and operator logs use
  `casual-sign-audit`'s existing canonical JSON, and `casual-sign-policy` is a Host crate.

## 12. Staged build

Rows are in docs/14 (the main session adds them). Each stage is usable end to end and ships with its tests seen red.

| Stage | Rows | Ships in | Exit |
| --- | --- | --- | --- |
| **0. Identity defect** | `SEC-ID-01` (fix in progress) | before A's switching | §2.3 rules 1 and 3 (rules 2 and 4 arrive with ORG-11 and CON-04); `SEC-O09` red on `5657c8e` |
| **A. Organizations exist** | ORG-02, ORG-03, ORG-04, ORG-05, ORG-06 | v0.0.2 | Organizations migration on a v0.0.1 database with isolation suites green; organization admin creates a second workspace and switches; admin logs at both levels |
| **B. Console exists** | CON-15, CON-02, CON-03, CON-04, CON-05 | v0.0.2 | Operator with TOTP creates an organization and suspends it with approval; `SEC-X01`, `X02`, `X08` seen red; dashboard reads health and dead letters |
| **C. Plans enforced** | PLAN-02, PLAN-03, PLAN-04, PLAN-05 | v0.0.2 | `envelopes_sent`, `seats`, `storage_bytes` metered and enforced at both levels; `SEC-U01`, `U02` seen red; usage CSV |
| **D. Delegated administration and policy** | ORG-07, ORG-08, ORG-09, ORG-10 | v0.0.3 | Delegated admin with group scope; locks; owner-only configuration; transfer and template copy; `SEC-O02`, `O03`, `O11`, `O12` seen red |
| **E. Keys and trust in the console** | CON-06, CON-07, CON-08, CON-09, CON-10 | v0.0.3 (list and expiry), later (rotation, reconciliation) | keyd admin list; TSA and anchors from DB with two-person approval; expiry alerts |
| **F. Identity (slice 10)** | ORG-11, ORG-12, ORG-13, ORG-14 | after v0.0.3 | Domains, OIDC and SAML SSO, JIT, SCIM; `SEC-O04`, `O08` |
| **G. Observability (slice 20)** | CON-11, CON-12 | slice 20 | OTel and Prometheus; runbooks |
| **H. Remaining meters and billing seam** | PLAN-06, PLAN-07, PLAN-08 | later | API and SMS meters; allocations; `BillingProvider` |
| **I. Hardening and gaps** | CON-13, CON-14, ORG-15 to ORG-28 | later, each its own slice | WebAuthn; break-glass drill; reports; the review's gap list (finding 20) |

**Sequencing** (review finding 9; CLAUDE.md: two workers never touch one invariant). The stages are not independent at
the database: B's console role and C's counters both need the `organizations` table. So:

1. Start at once, in parallel: `SEC-ID-01`; ORG-02 (the organizations migration, including `organization_admins`,
   `org_permission_sets`, the owner backfill and the last-owner constraint, and `OrgTx`); the parts of B and C that
   touch no migration: the `casual-sign-policy`, `casual-sign-platform-store` and `casual-sign-keyd-client` crates
   (CON-15, CON-02's crate work, PLAN-02's pure part), the ops listeners (CON-05), and the screens against
   the mock server.
2. Migrations then merge one at a time, in this number order, each after the one before it: `SEC-ID-01` (`0013`),
   ORG-02, ORG-05 (admin logs; replaces the workspace definer functions with event-writing versions), CON-02 (`platform`
   schema), CON-03 (operators and the operator log, which copies into ORG-05's organization log), CON-04 (approvals),
   PLAN-02, PLAN-03. ORG-03, ORG-04 and ORG-06 add no migration; ORG-03 and ORG-04 merge after ORG-05, so stage A exits
   as soon as ORG-05 and its routes are in, without waiting for stage B or C.
3. Every later row that changes the schema takes the next free number at its merge (§2), after step 2's list.
4. Files every stage touches (`api/openapi.yaml`, `routes.rs`, docs/07, docs/20, Compose) are merged by the main
   session only, each stage appending to its own sections.

## 13. Review findings and where each is answered

| # | Severity | Finding | Answer |
| --- | --- | --- | --- |
| 1 | CRITICAL | Cross-workspace takeover through the shared `users` row | §0 (existing defect, `SEC-ID-01`); §2.3 rule; `SEC-O09` |
| 2 | HIGH | `accounts.organization_id` not guarded; app can INSERT accounts | §2.1 trigger, revoked INSERT, column grants, catalog tests 5 and 6; `SEC-O10`; operator move `ORG-20` through the one function the trigger admits (`openseal_org_mover`) |
| 3 | HIGH | Delegated identity rights capture the owner | §2.2 owner-only configuration, owner approval, notices, IdP role rule; `SEC-O11` |
| 4 | HIGH | Org-to-workspace grants undefined | §2.2 `held()` per level, `org.workspaces.join`, no self-grants; `SEC-O02`, `SEC-O07` |
| 5 | HIGH | Console depends on host, which reaches `TenantTx` | §5.2 `casual-sign-policy` and `casual-sign-platform-store`; console depends on neither store nor host |
| 6 | HIGH | Console depends on the whole keyd | §5.2 `casual-sign-keyd-client` |
| 7 | HIGH | "No engine changes" false | §11 lists them; import made host-only (§2.4) |
| 8 | HIGH | Organization quotas not atomic | §7.2 `org_usage_counters`; §7.3 `openseal_consume_quota`, seat lock; `SEC-U01` across workspaces |
| 9 | HIGH | Catalog rules, plan tables and staging contradict | §2.1 catalog scoped to `public` with named exceptions; §7.1 `workspace_id` in `platform`; one migration order (§2, §12 step 2) matching what each row's migration contains; no copy step needed (§7.1) |
| 10 | MEDIUM | Two-person rule only in application code | §5.1 definer functions, insert-only approvals, single use, worker check; residual stated; `SEC-X08` |
| 11 | MEDIUM | Reconciliation cannot run in the console | §5.4 `seal_signatures` and `platform.seal_digests`; alternatives rejected with reasons |
| 12 | MEDIUM | Organization creation is an oracle | §5.1 uniform answer, invitation bound on acceptance, no attribute set |
| 13 | MEDIUM | One IdP binding per identity; domain owner's reach | §4 `user_identities`, domain-claim precedence, badge and event; `SEC-O04`, `SEC-O08` |
| 14 | MEDIUM | Indirect escalation through workspace actions | §2.2 sensitive actions; §3 floors; `SEC-O12` |
| 15 | MEDIUM | New repository check | Dropped; crate graph and the role test (§5.1) |
| 16 | MEDIUM | Admin-log heads and console writes | §2.5 head columns and definer appends |
| 17 | MEDIUM | "SELECT-only" contradicted | §2.1: all organization policies `FOR SELECT`; writes through `for_workspace_of` |
| 18 | MEDIUM | Template copy body parameter | §2.4 organization route with proofs for both sides; §6 |
| 19 | MEDIUM | Organization scope reads password hashes | §2.1 column grant revoked; definer read at login |
| 20 | MEDIUM | Gaps with no rows | `ORG-16` to `ORG-27` (§12 stage I); closure lifecycle §5.3 |
| 21 | LOW | Smaller items | `openseal_user_workspaces` from the session (§2.1); platform-wide disable revokes everywhere (§2.3); last owner must be enabled (§2.2); backfill with no admin (§2.1); no plan limits to copy (§7.1); `api_calls` soft only (§7.2); no residency claim (§7.5); keyd health over its protocol (§5.4); TOTP test vectors (§5.1); docs/47 and seal red (§10); ceremonies continue in an archived workspace (§5.3) |

Consistent with owner instructions 24 to 26 and 29 and DEC-06: organization → workspace; a separate console with its own
identity, MFA and log and no content access; plans as entitlements, quotas and metering with billing as a later plugin;
`account` kept in the API.

## 14. Documents updated with this ADR, and those updated by the rows

Updated now: docs/08 (ADR-028), docs/07 (`SEC-O*`, `SEC-X*`, `SEC-U*` Designed; *tenant metadata* class), docs/20
(proposed ranges), docs/22 (Designed notes), docs/00 (this document). Updated by the row that builds each part
(`ORG-28`): docs/19 (four new crates, keyd split), docs/40 (§2 scopes, §3 resources, `x-level`), docs/31 §5 (admin
allow-list, TSA and trust in the database), docs/24 and docs/32 (`Transfer`, `envelope.transferred`,
`envelope.exported`; `ORG-09`), docs/47 (screens), docs/96 (organization admin, delegated admin, usage rows), docs/06
(slice 10 points here; slice 33 wording, `ORG-27`), AGENTS.md and README (state).
