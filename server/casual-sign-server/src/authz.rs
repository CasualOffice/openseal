//! The action catalogue and the rule against escalation (ORG-07; ADR-028 (d), docs/23
//! §2.2).
//!
//! **Actions.** Every `/api/v1` route that needs a right names one action of this
//! catalogue (its `x-permission` in `api/openapi.yaml`, with `x-level`): a workspace
//! [`Action`], held through the caller's permission profile, or an organization
//! [`OrgAction`], held through the caller's `organization_admins` row. Both are typed,
//! so a route cannot name an action the catalogue lacks: it does not compile, and the
//! contract test refuses an `x-permission` outside it. The coarse `admin` meaning is gone:
//! the built-in administrator profile holds every workspace action, and a custom profile
//! names the actions it holds (a delegated workspace admin), optionally limited to some
//! groups (`permission_profiles.admin_scope_group_ids`).
//!
//! OAuth scopes stay the wire grants (docs/40 §2): each workspace action is covered by at
//! most one scope ([`Action::scope`]), and an API key's or token's scopes narrow its
//! owner's actions to those they cover. No scope was widened by the split: an action
//! is covered by the scope that guarded its routes before.
//!
//! **Grants.** One function, [`grantable`], decides every grant: profile create, edit
//! and delete, assigning a profile to a member, and API client creation. It refuses
//! (`403 CS-ORG-0005`) an action the actor does not hold, the administrator profile to
//! one who does not hold it, a group scope wider than the actor's, a sensitive action
//! with a group scope, and anything granted to the actor itself. What the actor holds is
//! [`held`], per level: a member its profile's actions; an organization owner or admin
//! every workspace action of its organization's workspaces, for granting only (content
//! still needs a membership); a delegated organization admin, in a workspace of its
//! scope, the workspace actions its set names.
//!
//! Everything here is pure: the server reads the rows on every request (rights are
//! never cached across requests) and asks these functions.

use std::collections::BTreeSet;

use casual_sign_store::repo::accounts::ProfileKind;
use casual_sign_store::{
    AccountId, GroupId, OrganizationAdmin, OrganizationRole, PermissionProfileId, UserId,
};

/// Where a route's action is held (`x-level` in `api/openapi.yaml`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    /// Through the caller's permission profile in the session's workspace.
    Workspace,
    /// Through the caller's role in the workspace's organization.
    Organization,
}

impl Level {
    /// The `x-level` value.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Workspace => "workspace",
            Self::Organization => "organization",
        }
    }
}

macro_rules! actions {
    ($($(#[$doc:meta])* $v:ident = $name:literal, $scope:expr, $sensitive:literal;)*) => {
        /// A workspace action (docs/23 §2.2): what a permission profile holds.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub enum Action {
            $($(#[$doc])* $v,)*
        }

        impl Action {
            /// The whole catalogue, in order.
            pub const ALL: &'static [Action] = &[$(Self::$v,)*];

            /// The catalogue name (`x-permission`, and what a custom profile stores).
            #[must_use]
            pub fn as_str(self) -> &'static str {
                match self { $(Self::$v => $name,)* }
            }

            /// The OAuth scope covering it, if any: the scope that guarded its routes
            /// before the split. `envelopes.read_all` and `envelopes.transfer` have none
            /// (they come from the profile only, as `view_all_envelopes` did).
            #[must_use]
            pub fn scope(self) -> Option<&'static str> {
                match self { $(Self::$v => $scope,)* }
            }

            /// A sensitive action (docs/23 §2.2, review finding 14): it reaches content or
            /// personal data indirectly, or weakens evidence, and is never held with a
            /// group scope.
            #[must_use]
            pub fn sensitive(self) -> bool {
                match self { $(Self::$v => $sensitive,)* }
            }
        }
    };
}

actions! {
    /// Read envelopes one may see.
    EnvelopesRead = "envelopes.read", Some("envelopes:read"), false;
    /// Create and change drafts.
    EnvelopesWrite = "envelopes.write", Some("envelopes:write"), false;
    /// Send, void, correct, resend.
    EnvelopesSend = "envelopes.send", Some("envelopes:send"), false;
    /// Read templates one may use.
    TemplatesRead = "templates.read", Some("templates:read"), false;
    /// Create and change templates.
    TemplatesWrite = "templates.write", Some("templates:write"), false;
    /// Bulk sends.
    BulkSend = "bulk.send", Some("bulk:send"), false;
    /// An envelope's audit trail.
    AuditRead = "audit.read", Some("audit:read"), false;
    /// List and read members.
    UsersRead = "users.read", Some("admin:users"), false;
    /// Add and invite members.
    UsersInvite = "users.invite", Some("admin:users"), false;
    /// Change a member (name, password, profile).
    UsersUpdate = "users.update", Some("admin:users"), false;
    /// Disable or enable a member.
    UsersDisable = "users.disable", Some("admin:users"), false;
    /// Remove a member.
    UsersRemove = "users.remove", Some("admin:users"), false;
    /// Groups and their members.
    GroupsManage = "groups.manage", Some("admin:users"), false;
    /// Custom permission profiles.
    ProfilesManage = "profiles.manage", Some("admin:users"), false;
    /// Sending settings.
    SettingsSending = "settings.sending", Some("admin:account"), false;
    /// Signing settings (the workflow policy).
    SettingsSigning = "settings.signing", Some("admin:account"), false;
    /// Publish the electronic record and signature disclosure.
    ErsdManage = "ersd.manage", Some("admin:account"), false;
    /// Security settings (second factor, recipient authentication).
    SettingsSecurity = "settings.security", Some("admin:account"), true;
    /// Brands (they set `frame-ancestors`).
    BrandsManage = "brands.manage", Some("admin:account"), true;
    /// Retention (it can purge).
    RetentionManage = "retention.manage", Some("admin:account"), true;
    /// API keys and OAuth clients (they mint credentials).
    ApiClientsManage = "api_clients.manage", Some("admin:account"), true;
    /// Webhooks (they send recipient data to an outside host).
    WebhooksManage = "webhooks.manage", Some("webhooks:manage"), true;
    /// See every envelope of the workspace (`view_all_envelopes`).
    EnvelopesReadAll = "envelopes.read_all", None, true;
    /// Transfer an envelope's ownership within the workspace (ORG-09).
    EnvelopesTransfer = "envelopes.transfer", None, true;
    /// Share a template with the whole workspace.
    TemplatesShareWorkspace = "templates.share_workspace", Some("admin:account"), false;
    /// Workspace reports.
    ReportsRead = "reports.read", Some("admin:account"), false;
    /// Usage.
    UsageRead = "usage.read", Some("admin:account"), false;
    /// The workspace's admin log.
    AdminAuditRead = "admin_audit.read", Some("admin:account"), false;
}

impl Action {
    /// The action a catalogue name names.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|a| a.as_str() == name)
    }

    /// An administrative action (anything but working with one's own envelopes and
    /// templates): the actions a group scope limits.
    #[must_use]
    pub fn administrative(self) -> bool {
        !matches!(
            self,
            Self::EnvelopesRead
                | Self::EnvelopesWrite
                | Self::EnvelopesSend
                | Self::TemplatesRead
                | Self::TemplatesWrite
                | Self::BulkSend
                | Self::AuditRead
        )
    }
}

/// The permission name `view_all_envelopes` profiles stored before the catalogue: read
/// as [`Action::EnvelopesReadAll`].
pub const VIEW_ALL: &str = "view_all_envelopes";

/// The actions an OAuth scope covers.
#[must_use]
pub fn scope_actions(scope: &str) -> BTreeSet<Action> {
    Action::ALL
        .iter()
        .copied()
        .filter(|a| a.scope() == Some(scope))
        .collect()
}

/// The actions a permission profile holds (docs/22 §8, docs/23 §2.2): the
/// administrator profile every one; sender and viewer those of their scopes; a custom
/// profile those it names, a scope name standing for every action it covers and
/// `view_all_envelopes` for `envelopes.read_all`. An unknown name holds nothing.
#[must_use]
pub fn profile_actions(kind: ProfileKind, permissions: &[String]) -> BTreeSet<Action> {
    let of = |names: &[&str]| -> BTreeSet<Action> {
        names
            .iter()
            .flat_map(|n| {
                let mut s = scope_actions(n);
                if *n == VIEW_ALL {
                    s.insert(Action::EnvelopesReadAll);
                }
                if let Some(a) = Action::parse(n) {
                    s.insert(a);
                }
                s
            })
            .collect()
    };
    match kind {
        ProfileKind::Admin => Action::ALL.iter().copied().collect(),
        ProfileKind::Sender => of(&[
            "envelopes:read",
            "envelopes:write",
            "envelopes:send",
            "templates:read",
            "templates:write",
            "bulk:send",
            "audit:read",
        ]),
        ProfileKind::Viewer => of(&["envelopes:read", "templates:read", "audit:read"]),
        _ => {
            let names: Vec<&str> = permissions.iter().map(String::as_str).collect();
            of(&names)
        }
    }
}

/// The scopes of `scopes` whose every action is in `actions`: what a holder of those
/// actions may give an API key.
#[must_use]
pub fn scopes_held<'s>(scopes: &[&'s str], actions: &BTreeSet<Action>) -> BTreeSet<&'s str> {
    scopes
        .iter()
        .copied()
        .filter(|s| {
            let need = scope_actions(s);
            !need.is_empty() && need.is_subset(actions)
        })
        .collect()
}

/// An organization action (docs/23 §2.2's catalogue): what an organization role holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum OrgAction {
    /// Read the organization, its workspaces and its admins (metadata only).
    Read,
    /// `org.settings.update`.
    SettingsUpdate,
    /// `org.admins.manage`: owners and admins (owner only).
    AdminsManage,
    /// `org.workspaces.create`.
    WorkspacesCreate,
    /// `org.workspaces.archive`.
    WorkspacesArchive,
    /// `org.workspaces.join`: owners and admins, never delegated.
    WorkspacesJoin,
    /// `org.audit.read`.
    AuditRead,
}

impl OrgAction {
    /// Every organization action routes name, in order.
    pub const ALL: &'static [OrgAction] = &[
        Self::Read,
        Self::SettingsUpdate,
        Self::AdminsManage,
        Self::WorkspacesCreate,
        Self::WorkspacesArchive,
        Self::WorkspacesJoin,
        Self::AuditRead,
    ];

    /// The catalogue name, as a delegated admin's permission set names it.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Read => "org.read",
            Self::SettingsUpdate => "org.settings.update",
            Self::AdminsManage => "org.admins.manage",
            Self::WorkspacesCreate => "org.workspaces.create",
            Self::WorkspacesArchive => "org.workspaces.archive",
            Self::WorkspacesJoin => "org.workspaces.join",
            Self::AuditRead => "org.audit.read",
        }
    }

    /// An action a delegated admin may hold for some workspaces only: the route guard
    /// lets it through, and the handler checks it per workspace.
    #[must_use]
    pub fn per_workspace(self) -> bool {
        self == Self::WorkspacesArchive
    }
}

/// Whether `admin` holds `action`, on `workspace` when the action is about one
/// (docs/23 §2.2's table): an owner every action; an admin all but managing owners and
/// admins; a delegated admin what its set names, within its workspace scope, and never
/// a join or an admin change.
#[must_use]
pub fn holds(admin: &OrganizationAdmin, action: OrgAction, workspace: Option<AccountId>) -> bool {
    match admin.role {
        OrganizationRole::Owner => true,
        OrganizationRole::Admin => action != OrgAction::AdminsManage,
        OrganizationRole::Delegated => {
            if matches!(action, OrgAction::WorkspacesJoin | OrgAction::AdminsManage) {
                return false;
            }
            if action == OrgAction::Read {
                return true;
            }
            let named = admin.permissions.iter().any(|p| p == action.as_str());
            let in_scope = match (&admin.workspace_scope, workspace) {
                (Some(scope), Some(w)) => scope.contains(&w),
                _ => true,
            };
            named && in_scope
        }
        // A role this build does not know holds nothing (deny by default).
        _ => false,
    }
}

/// The organization permission that lets a delegated admin give another member a
/// workspace's administrator profile.
pub const WORKSPACE_ADMINS_ASSIGN: &str = "org.workspace_admins.assign";

/// What an actor holds in one workspace, for granting (docs/23 §2.2, review finding 4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Held {
    /// The workspace actions.
    pub actions: BTreeSet<Action>,
    /// Whether it may hand out the built-in administrator profile.
    pub admin_profile: bool,
    /// Its group scope: `None` is the whole workspace.
    pub scope: Option<BTreeSet<GroupId>>,
}

/// The caller's own membership in the workspace, as [`held`] reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Membership {
    /// Its profile's actions ([`profile_actions`]), narrowed by an API key's scopes.
    pub actions: BTreeSet<Action>,
    /// Its profile is the built-in administrator's.
    pub admin: bool,
    /// Its profile's group scope.
    pub scope: Option<BTreeSet<GroupId>>,
}

/// What an actor holds in `workspace`, per level: its membership's actions (with the
/// membership's group scope), widened to every workspace action and the whole
/// workspace by an owner's or admin's role in the workspace's organization, or by a
/// delegated organization admin's set within its workspace scope. The organization part
/// is for granting only; content still needs a membership.
#[must_use]
pub fn held(
    member: Option<&Membership>,
    org: Option<&OrganizationAdmin>,
    workspace: AccountId,
) -> Held {
    let mut out = Held {
        actions: BTreeSet::new(),
        admin_profile: false,
        scope: Some(BTreeSet::new()),
    };
    if let Some(m) = member {
        out.actions.clone_from(&m.actions);
        out.admin_profile = m.admin;
        out.scope = if out.actions.iter().any(|a| a.administrative()) {
            m.scope.clone()
        } else {
            Some(BTreeSet::new())
        };
    }
    match org.map(|a| (a.role, a)) {
        Some((OrganizationRole::Owner | OrganizationRole::Admin, _)) => {
            out.actions = Action::ALL.iter().copied().collect();
            out.admin_profile = true;
            out.scope = None;
        }
        Some((OrganizationRole::Delegated, a))
            if a.workspace_scope
                .as_ref()
                .is_none_or(|s| s.contains(&workspace)) =>
        {
            let named: BTreeSet<Action> = a
                .permissions
                .iter()
                .filter_map(|p| Action::parse(p))
                .collect();
            if !named.is_empty() {
                out.actions.extend(named);
                out.scope = None;
            }
            if a.permissions.iter().any(|p| p == WORKSPACE_ADMINS_ASSIGN) {
                out.admin_profile = true;
                out.scope = None;
            }
        }
        _ => {}
    }
    out
}

/// One grant asked for.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Grant {
    /// The workspace actions it gives.
    pub actions: BTreeSet<Action>,
    /// It gives the built-in administrator profile.
    pub admin_profile: bool,
    /// Its group scope (`None`: the whole workspace).
    pub scope: Option<BTreeSet<GroupId>>,
    /// The member it is given to, when it is an assignment.
    pub to_user: Option<UserId>,
    /// The profile it creates, changes or deletes, when it is one.
    pub profile: Option<PermissionProfileId>,
}

/// Why a grant is refused (`CS-ORG-0005`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// Granted to the actor itself, or a change to the profile the actor holds.
    ToItself,
    /// The administrator profile, by one who does not hold it.
    AdminProfile,
    /// An action the actor does not hold.
    Action(Action),
    /// A group scope wider than the actor's.
    Scope,
    /// A sensitive action with a group scope.
    SensitiveScoped(Action),
}

impl Refusal {
    /// What the refusal names (never a person or a value).
    #[must_use]
    pub fn what(self) -> &'static str {
        match self {
            Self::ToItself => "a grant to oneself",
            Self::AdminProfile => "the administrator profile",
            Self::Action(a) | Self::SensitiveScoped(a) => a.as_str(),
            Self::Scope => "groups outside one's own scope",
        }
    }
}

/// The actor of a grant: who, the profile it holds here, and what it holds ([`held`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Actor {
    /// The user granting.
    pub user: UserId,
    /// The profile it holds in the workspace, if a member.
    pub profile: Option<PermissionProfileId>,
    /// What it holds.
    pub held: Held,
}

/// `grantable(actor, requested) = requested.actions ⊆ held(actor) ∧ requested.scope ⊆
/// actor.scope`, never to itself, never the administrator profile unless held, never a
/// sensitive action with a group scope (docs/23 §2.2). The one decision of every grant
/// path.
///
/// # Errors
///
/// The first [`Refusal`] that applies.
pub fn grantable(actor: &Actor, grant: &Grant) -> Result<(), Refusal> {
    if grant.to_user == Some(actor.user)
        || (grant.profile.is_some() && grant.profile == actor.profile)
    {
        return Err(Refusal::ToItself);
    }
    if grant.admin_profile && !actor.held.admin_profile {
        return Err(Refusal::AdminProfile);
    }
    if let Some(a) = grant
        .actions
        .iter()
        .find(|a| !actor.held.actions.contains(*a))
    {
        return Err(Refusal::Action(*a));
    }
    // A grant of no administrative action has no scope to compare: a sender profile is
    // a sender's wherever its holder sits.
    let administrative = grant.admin_profile || grant.actions.iter().any(|a| a.administrative());
    if administrative {
        let within = match (&actor.held.scope, &grant.scope) {
            (None, _) => true,
            (Some(_), None) => false,
            (Some(mine), Some(asked)) => asked.is_subset(mine),
        };
        if !within {
            return Err(Refusal::Scope);
        }
    }
    if grant.scope.is_some()
        && let Some(a) = grant.actions.iter().find(|a| a.sensitive())
    {
        return Err(Refusal::SensitiveScoped(*a));
    }
    Ok(())
}

#[cfg(test)]
// Tests may unwrap and index (CLAUDE.md).
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    use time::OffsetDateTime;
    use uuid::Uuid;

    use super::*;

    #[test]
    fn every_action_has_one_name_and_scopes_cover_what_they_guarded() {
        let names: BTreeSet<&str> = Action::ALL.iter().map(|a| a.as_str()).collect();
        assert_eq!(names.len(), Action::ALL.len());
        for a in Action::ALL {
            assert_eq!(Action::parse(a.as_str()), Some(*a));
            if a.sensitive() {
                assert!(a.administrative(), "{a:?}");
            }
        }
        assert_eq!(
            scope_actions("webhooks:manage"),
            BTreeSet::from([Action::WebhooksManage])
        );
        assert_eq!(scope_actions("admin:users").len(), 7);
        assert!(!scope_actions("admin:account").contains(&Action::WebhooksManage));
        for s in crate::auth::SCOPES {
            assert!(!scope_actions(s).is_empty(), "{s} covers nothing");
        }
    }

    #[test]
    fn profiles_hold_their_kinds_actions_and_custom_names_both_kinds_of_name() {
        assert_eq!(
            profile_actions(ProfileKind::Admin, &[]).len(),
            Action::ALL.len()
        );
        let v = profile_actions(ProfileKind::Viewer, &[]);
        assert_eq!(
            v,
            BTreeSet::from([
                Action::EnvelopesRead,
                Action::TemplatesRead,
                Action::AuditRead
            ])
        );
        let c = profile_actions(
            ProfileKind::Custom,
            &[
                "users.invite".into(),
                "admin:account".into(),
                VIEW_ALL.into(),
                "root".into(),
            ],
        );
        assert!(c.contains(&Action::UsersInvite) && !c.contains(&Action::UsersRemove));
        assert!(c.contains(&Action::ApiClientsManage) && c.contains(&Action::EnvelopesReadAll));
        assert!(!c.contains(&Action::WebhooksManage));
        assert_eq!(
            scopes_held(&crate::auth::SCOPES, &c),
            BTreeSet::from(["admin:account"])
        );
    }

    fn uid(n: u8) -> UserId {
        UserId(Uuid::from_bytes([n; 16]))
    }

    fn gid(n: u8) -> GroupId {
        GroupId(Uuid::from_bytes([n; 16]))
    }

    fn org_admin(
        role: OrganizationRole,
        perms: &[&str],
        scope: Option<Vec<u8>>,
    ) -> OrganizationAdmin {
        OrganizationAdmin {
            user_id: uid(1),
            role,
            permission_set_id: None,
            permissions: perms.iter().map(|p| (*p).to_owned()).collect(),
            workspace_scope: scope.map(|s| {
                s.into_iter()
                    .map(|n| AccountId(Uuid::from_bytes([n; 16])))
                    .collect()
            }),
            created_at: OffsetDateTime::UNIX_EPOCH,
        }
    }

    #[test]
    fn held_is_per_level() {
        let w = AccountId(Uuid::from_bytes([7; 16]));
        let sender = Membership {
            actions: profile_actions(ProfileKind::Sender, &[]),
            admin: false,
            scope: None,
        };
        let h = held(Some(&sender), None, w);
        assert!(!h.admin_profile && !h.actions.contains(&Action::UsersInvite));
        let owner = org_admin(OrganizationRole::Owner, &[], None);
        let h = held(Some(&sender), Some(&owner), w);
        assert!(h.admin_profile && h.actions.len() == Action::ALL.len() && h.scope.is_none());
        let h = held(None, Some(&owner), w);
        assert!(h.admin_profile);
        let d = org_admin(
            OrganizationRole::Delegated,
            &["users.invite"],
            Some(vec![9]),
        );
        assert!(
            held(None, Some(&d), w).actions.is_empty(),
            "outside its scope"
        );
        let d = org_admin(
            OrganizationRole::Delegated,
            &["users.invite", WORKSPACE_ADMINS_ASSIGN],
            Some(vec![7]),
        );
        let h = held(None, Some(&d), w);
        assert_eq!(h.actions, BTreeSet::from([Action::UsersInvite]));
        assert!(h.admin_profile);
    }

    /// A small deterministic generator (no new dependency): xorshift64*.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }
        fn below(&mut self, n: usize) -> usize {
            usize::try_from(self.next() % u64::try_from(n).unwrap()).unwrap()
        }
        fn actions(&mut self) -> BTreeSet<Action> {
            Action::ALL
                .iter()
                .copied()
                .filter(|_| self.below(3) == 0)
                .collect()
        }
        fn scope(&mut self) -> Option<BTreeSet<GroupId>> {
            if self.below(3) == 0 {
                return None;
            }
            Some((0..4u8).filter(|_| self.below(2) == 0).map(gid).collect())
        }
    }

    /// The property (docs/23 §2.2, `SEC-O02`): over random actors and grants, a grant
    /// [`grantable`] allows gives nothing the actor does not hold, no wider scope, no
    /// sensitive action with a scope, and nothing to the actor itself; and every grant
    /// within those bounds is allowed.
    #[test]
    fn grantable_allows_exactly_the_grants_within_the_actors_rights() {
        let mut rng = Rng(0x0005_EA1E_D0C5_0007);
        let (mut allowed, mut refused) = (0, 0);
        for _ in 0..20_000 {
            let actor = Actor {
                user: uid(1),
                profile: Some(PermissionProfileId(Uuid::from_bytes([1; 16]))),
                held: Held {
                    actions: rng.actions(),
                    admin_profile: rng.below(4) == 0,
                    scope: rng.scope(),
                },
            };
            let grant = Grant {
                actions: rng.actions(),
                admin_profile: rng.below(6) == 0,
                scope: rng.scope(),
                to_user: [None, Some(uid(1)), Some(uid(2))][rng.below(3)],
                profile: [
                    None,
                    Some(PermissionProfileId(Uuid::from_bytes([1; 16]))),
                    Some(PermissionProfileId(Uuid::from_bytes([2; 16]))),
                ][rng.below(3)],
            };
            let administrative =
                grant.admin_profile || grant.actions.iter().any(|a| a.administrative());
            let within_scope = !administrative
                || match (&actor.held.scope, &grant.scope) {
                    (None, _) => true,
                    (Some(_), None) => false,
                    (Some(m), Some(a)) => a.is_subset(m),
                };
            let expected = grant.to_user != Some(actor.user)
                && (grant.profile.is_none() || grant.profile != actor.profile)
                && (!grant.admin_profile || actor.held.admin_profile)
                && grant.actions.is_subset(&actor.held.actions)
                && within_scope
                && !(grant.scope.is_some() && grant.actions.iter().any(|a| a.sensitive()));
            let got = grantable(&actor, &grant);
            assert_eq!(got.is_ok(), expected, "{actor:?} {grant:?} {got:?}");
            if got.is_ok() {
                allowed += 1;
            } else {
                refused += 1;
            }
        }
        assert!(allowed > 500 && refused > 500, "{allowed} {refused}");
    }

    #[test]
    fn a_delegated_admin_never_joins_and_never_manages_admins() {
        let every: Vec<&str> = OrgAction::ALL.iter().map(|a| a.as_str()).collect();
        let d = org_admin(OrganizationRole::Delegated, &every, None);
        assert!(!holds(&d, OrgAction::WorkspacesJoin, None));
        assert!(!holds(&d, OrgAction::AdminsManage, None));
        assert!(holds(&d, OrgAction::AuditRead, None));
    }
}
