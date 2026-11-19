//! The route table: every endpoint once, with the scope it needs (its `x-permission`
//! in `api/openapi.yaml`, SEC-A05) and the largest body it reads. The router is built
//! from this table, and the contract tests check the table against the OpenAPI
//! document in both directions.

use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::handler::Handler;
use axum::middleware::from_fn_with_state;
use axum::routing::{MethodFilter, MethodRouter, on};
use tower_http::catch_panic::CatchPanicLayer;

use crate::api::{
    admin, bulk, envelopes as env, factors, folders, groups, mfa, ml, oauth, org, privacy, reports,
    sessions, switch, templates, usetemplates, webhooks,
};
use crate::authz::{Action, Level, OrgAction};
use crate::ceremony;
use crate::http::{Guard, Need, OtherMedia, guard, json_only, panicked, request_context};
use crate::state::AppState;

/// Who may call a route.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    /// Anyone (login, token, JWKS, ceremony: they authenticate themselves).
    Public,
    /// Any authenticated principal that owes no second factor it has not passed.
    /// `x-permission: ""`.
    Member,
    /// Such a principal holding this workspace action of the catalogue (ORG-07,
    /// `x-level: workspace`). The action is typed: a route naming one the catalogue
    /// lacks does not compile, so it cannot register.
    Action(Action),
    /// A staff session whose organization role holds this organization action (ORG-07,
    /// `x-level: organization`), read afresh on every request.
    Org(OrgAction),
    /// Any authenticated principal, a staff session that still owes its second factor
    /// included: the steps of signing in (ASVS-01). `x-permission: signing-in`.
    SigningIn,
}

impl Access {
    /// The route's `x-permission`: `public`, `signing-in`, `""` for any authenticated
    /// caller, or the action's catalogue name.
    #[must_use]
    pub fn permission(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::SigningIn => "signing-in",
            Self::Member => "",
            Self::Action(a) => a.as_str(),
            Self::Org(a) => a.as_str(),
        }
    }

    /// The route's `x-level`, for a route that names an action.
    #[must_use]
    pub fn level(self) -> Option<Level> {
        match self {
            Self::Action(_) => Some(Level::Workspace),
            Self::Org(_) => Some(Level::Organization),
            _ => None,
        }
    }
}

/// One endpoint.
#[derive(Debug)]
pub struct Route {
    /// `GET`, `POST`, `PUT`, `PATCH` or `DELETE`.
    pub method: &'static str,
    /// The path template, as in the OpenAPI document.
    pub path: &'static str,
    /// Who may call it.
    pub access: Access,
    /// The largest request body it reads, in bytes.
    pub max_body: usize,
    handler: MethodRouter<AppState>,
}

fn filter(m: &str) -> MethodFilter {
    match m {
        "POST" => MethodFilter::POST,
        "PUT" => MethodFilter::PUT,
        "PATCH" => MethodFilter::PATCH,
        "DELETE" => MethodFilter::DELETE,
        _ => MethodFilter::GET,
    }
}

const JSON: usize = 1024 * 1024;
/// A 50 MiB document as base64, plus the JSON around it.
const UPLOAD: usize = 70 * 1024 * 1024;
/// The one-call create: documents up to the 200 MiB envelope total, as base64.
const CREATE: usize = 270 * 1024 * 1024;
/// A 5 MiB signature image as base64.
const IMAGE: usize = 7 * 1024 * 1024;
/// A 10 MiB signer attachment as base64 (WEB-06).
const ATTACHMENT: usize = 14 * 1024 * 1024;

fn r<H, T>(method: &'static str, path: &'static str, access: Access, max_body: usize, h: H) -> Route
where
    H: Handler<T, AppState>,
    T: 'static,
{
    Route {
        method,
        path,
        access,
        max_body,
        handler: on(filter(method), h),
    }
}

/// Every endpoint (docs/40 §3, §6).
#[must_use]
#[allow(clippy::too_many_lines)] // One line per endpoint is the point of the table.
pub fn table() -> Vec<Route> {
    use Access::{Action as A, Member, Org, Public, SigningIn};
    use Action::{
        AdminAuditRead, ApiClientsManage, AuditRead, BulkSend, EnvelopesRead, EnvelopesSend,
        EnvelopesTransfer, EnvelopesWrite, ErsdManage, GroupsManage, ProfilesManage, ReportsRead,
        RetentionManage, SettingsSending, TemplatesRead, TemplatesWrite, UsersInvite, UsersRead,
        UsersRemove, UsersUpdate, WebhooksManage,
    };
    let er = A(EnvelopesRead);
    let ew = A(EnvelopesWrite);
    let es = A(EnvelopesSend);
    let tr = A(TemplatesRead);
    let tw = A(TemplatesWrite);
    vec![
        // Authentication (docs/40 §2).
        r("POST", "/api/v1/auth/login", Public, JSON, admin::login),
        r(
            "POST",
            "/api/v1/auth/accept-invite",
            Public,
            JSON,
            admin::accept_invite,
        ),
        r(
            "POST",
            "/api/v1/auth/logout",
            SigningIn,
            JSON,
            admin::logout,
        ),
        r(
            "GET",
            "/api/v1/auth/session",
            SigningIn,
            JSON,
            admin::session,
        ),
        // The staff second factor (ASVS-01, docs/40 §2).
        r(
            "POST",
            "/api/v1/auth/mfa/verify",
            SigningIn,
            JSON,
            mfa::verify,
        ),
        r(
            "POST",
            "/api/v1/auth/mfa/totp/enrol",
            SigningIn,
            JSON,
            mfa::enrol,
        ),
        r(
            "POST",
            "/api/v1/auth/mfa/totp/confirm",
            SigningIn,
            JSON,
            mfa::confirm,
        ),
        // Staff passkeys and a person's own factors (CON-13, ASVS-32).
        r(
            "POST",
            "/api/v1/auth/mfa/passkeys/options",
            SigningIn,
            JSON,
            factors::options,
        ),
        r(
            "POST",
            "/api/v1/auth/mfa/passkeys",
            SigningIn,
            JSON,
            factors::register,
        ),
        r(
            "GET",
            "/api/v1/auth/mfa/passkeys",
            Member,
            JSON,
            factors::list,
        ),
        r(
            "PATCH",
            "/api/v1/auth/mfa/passkeys/{id}",
            Member,
            JSON,
            factors::rename,
        ),
        r(
            "DELETE",
            "/api/v1/auth/mfa/passkeys/{id}",
            Member,
            JSON,
            factors::remove,
        ),
        r(
            "DELETE",
            "/api/v1/auth/mfa/totp",
            Member,
            JSON,
            factors::remove_totp,
        ),
        r(
            "POST",
            "/api/v1/auth/mfa/recovery-codes",
            Member,
            JSON,
            factors::replace_recovery_codes,
        ),
        r(
            "POST",
            "/api/v1/auth/password-reset",
            Public,
            JSON,
            admin::password_reset,
        ),
        r(
            "POST",
            "/api/v1/auth/password-reset/confirm",
            Public,
            JSON,
            admin::password_reset_confirm,
        ),
        r(
            "GET",
            "/api/v1/auth/providers",
            Public,
            JSON,
            admin::providers,
        ),
        // A person's own sessions and re-authentication (ASVS-06, ASVS-07).
        r(
            "POST",
            "/api/v1/auth/reauthenticate",
            Member,
            JSON,
            sessions::reauthenticate,
        ),
        r("GET", "/api/v1/auth/sessions", Member, JSON, sessions::list),
        r(
            "POST",
            "/api/v1/auth/sessions/end-others",
            Member,
            JSON,
            sessions::end_others,
        ),
        r(
            "DELETE",
            "/api/v1/auth/sessions/{id}",
            Member,
            JSON,
            sessions::end_one,
        ),
        // Workspace switching (docs/23 §2.3, ORG-04).
        r(
            "GET",
            "/api/v1/auth/workspaces",
            Member,
            JSON,
            switch::workspaces,
        ),
        r("POST", "/api/v1/auth/switch", Member, JSON, switch::switch),
        r("POST", "/api/v1/oauth/token", Public, JSON, admin::token),
        r("GET", "/.well-known/jwks.json", Public, JSON, admin::jwks),
        // OAuth 2.1 acting for a member: authorization code with PKCE, consent, and the
        // JWT bearer grant's consent (VS-08A, VS-08B).
        r(
            "GET",
            "/.well-known/oauth-authorization-server",
            Public,
            JSON,
            oauth::metadata,
        ),
        r(
            "GET",
            "/api/v1/oauth/authorize",
            Public,
            JSON,
            oauth::authorize_redirect,
        ),
        r(
            "GET",
            "/api/v1/oauth/authorize/request",
            Member,
            JSON,
            oauth::authorize_request,
        ),
        r(
            "POST",
            "/api/v1/oauth/authorize",
            Member,
            JSON,
            oauth::authorize,
        ),
        r(
            "GET",
            "/api/v1/oauth/consents",
            Member,
            JSON,
            oauth::consents,
        ),
        r(
            "DELETE",
            "/api/v1/oauth/consents/{id}",
            Member,
            JSON,
            oauth::revoke_consent,
        ),
        // Account, users, API clients.
        r("GET", "/api/v1/accounts/me", Member, JSON, admin::account),
        r(
            "PATCH",
            "/api/v1/accounts/me",
            A(SettingsSending),
            JSON,
            admin::patch_account,
        ),
        // The workspace's document-analysis switches (docs/33 §6, §7; WEB-19).
        r(
            "GET",
            "/api/v1/account/settings/ml",
            A(SettingsSending),
            JSON,
            ml::settings,
        ),
        r(
            "PATCH",
            "/api/v1/account/settings/ml",
            A(SettingsSending),
            JSON,
            ml::patch_settings,
        ),
        r(
            "GET",
            "/api/v1/ersd-versions",
            A(ErsdManage),
            JSON,
            admin::ersd_versions,
        ),
        r(
            "POST",
            "/api/v1/ersd-versions",
            A(ErsdManage),
            JSON,
            admin::publish_ersd,
        ),
        r(
            "GET",
            "/api/v1/admin-events",
            A(AdminAuditRead),
            JSON,
            admin::admin_events,
        ),
        r("GET", "/api/v1/users/me", Member, JSON, admin::me),
        // Personal-data controls (ASVS-16, ASVS-18).
        r(
            "GET",
            "/api/v1/users/me/export",
            Member,
            JSON,
            privacy::export,
        ),
        r(
            "DELETE",
            "/api/v1/users/me",
            Member,
            JSON,
            privacy::erase_me,
        ),
        r(
            "POST",
            "/api/v1/users/{id}/erase",
            A(UsersRemove),
            JSON,
            privacy::erase_user,
        ),
        r(
            "GET",
            "/api/v1/retention",
            A(RetentionManage),
            JSON,
            privacy::rules,
        ),
        r(
            "PUT",
            "/api/v1/retention",
            A(RetentionManage),
            JSON,
            privacy::set_rules,
        ),
        r(
            "GET",
            "/api/v1/retention/preview",
            A(RetentionManage),
            JSON,
            privacy::preview,
        ),
        r(
            "PUT",
            "/api/v1/envelopes/{id}/legal-hold",
            A(RetentionManage),
            JSON,
            privacy::set_hold,
        ),
        r(
            "DELETE",
            "/api/v1/envelopes/{id}/legal-hold",
            A(RetentionManage),
            JSON,
            privacy::release_hold,
        ),
        r(
            "POST",
            "/api/v1/envelopes/{id}/purge",
            A(RetentionManage),
            JSON,
            privacy::purge,
        ),
        r(
            "PATCH",
            "/api/v1/users/me",
            Member,
            IMAGE * 2,
            admin::patch_me,
        ),
        // Organization (ORG-03): the role is checked per request in the handler.
        r(
            "GET",
            "/api/v1/organizations/me",
            Org(OrgAction::Read),
            JSON,
            org::organization,
        ),
        r(
            "PATCH",
            "/api/v1/organizations/me",
            Org(OrgAction::SettingsUpdate),
            JSON,
            org::patch_organization,
        ),
        r(
            "GET",
            "/api/v1/organizations/me/workspaces",
            Org(OrgAction::Read),
            JSON,
            org::workspaces,
        ),
        r(
            "POST",
            "/api/v1/organizations/me/workspaces",
            Org(OrgAction::WorkspacesCreate),
            JSON,
            org::create_workspace,
        ),
        r(
            "GET",
            "/api/v1/organizations/me/workspaces/{id}",
            Org(OrgAction::Read),
            JSON,
            org::workspace,
        ),
        r(
            "POST",
            "/api/v1/organizations/me/workspaces/{id}/archive",
            Org(OrgAction::WorkspacesArchive),
            JSON,
            org::archive_workspace,
        ),
        r(
            "POST",
            "/api/v1/organizations/me/workspaces/{id}/join",
            Org(OrgAction::WorkspacesJoin),
            JSON,
            org::join_workspace,
        ),
        r(
            "GET",
            "/api/v1/organizations/me/admins",
            Org(OrgAction::Read),
            JSON,
            org::admins,
        ),
        r(
            "POST",
            "/api/v1/organizations/me/admins",
            Org(OrgAction::AdminsManage),
            JSON,
            org::add_admin,
        ),
        r(
            "PATCH",
            "/api/v1/organizations/me/admins/{user}",
            Org(OrgAction::AdminsManage),
            JSON,
            org::patch_admin,
        ),
        r(
            "DELETE",
            "/api/v1/organizations/me/admins/{user}",
            Org(OrgAction::AdminsManage),
            JSON,
            org::remove_admin,
        ),
        r(
            "GET",
            "/api/v1/organizations/me/audit",
            Org(OrgAction::AuditRead),
            JSON,
            org::audit,
        ),
        r("GET", "/api/v1/users", A(UsersRead), JSON, admin::users),
        r(
            "POST",
            "/api/v1/users",
            A(UsersInvite),
            JSON,
            admin::create_user,
        ),
        r("GET", "/api/v1/users/{id}", A(UsersRead), JSON, admin::user),
        r(
            "PATCH",
            "/api/v1/users/{id}",
            A(UsersUpdate),
            JSON,
            admin::patch_user,
        ),
        r(
            "DELETE",
            "/api/v1/users/{id}",
            A(UsersRemove),
            JSON,
            admin::delete_user,
        ),
        r(
            "POST",
            "/api/v1/users/{id}/invite",
            A(UsersInvite),
            JSON,
            admin::reinvite_user,
        ),
        // An administrator's reset of a member's lost factors (ASVS-32, ASVS 2.5.7).
        r(
            "POST",
            "/api/v1/users/{id}/second-factor/reset",
            A(UsersUpdate),
            JSON,
            factors::reset_member,
        ),
        // Admin groups and custom permission profiles (UXW-07).
        r(
            "POST",
            "/api/v1/groups",
            A(GroupsManage),
            JSON,
            groups::create_group,
        ),
        r(
            "GET",
            "/api/v1/groups/{id}",
            A(GroupsManage),
            JSON,
            groups::group,
        ),
        r(
            "PATCH",
            "/api/v1/groups/{id}",
            A(GroupsManage),
            JSON,
            groups::patch_group,
        ),
        r(
            "DELETE",
            "/api/v1/groups/{id}",
            A(GroupsManage),
            JSON,
            groups::delete_group,
        ),
        r(
            "PUT",
            "/api/v1/groups/{id}/members",
            A(GroupsManage),
            JSON,
            groups::put_members,
        ),
        r(
            "GET",
            "/api/v1/permission-profiles",
            A(UsersRead),
            JSON,
            groups::profiles,
        ),
        r(
            "POST",
            "/api/v1/permission-profiles",
            A(ProfilesManage),
            JSON,
            groups::create_profile,
        ),
        r(
            "GET",
            "/api/v1/permission-profiles/{id}",
            A(UsersRead),
            JSON,
            groups::profile,
        ),
        r(
            "PATCH",
            "/api/v1/permission-profiles/{id}",
            A(ProfilesManage),
            JSON,
            groups::patch_profile,
        ),
        r(
            "DELETE",
            "/api/v1/permission-profiles/{id}",
            A(ProfilesManage),
            JSON,
            groups::delete_profile,
        ),
        r(
            "GET",
            "/api/v1/api-clients",
            A(ApiClientsManage),
            JSON,
            admin::clients,
        ),
        r(
            "POST",
            "/api/v1/api-clients",
            A(ApiClientsManage),
            JSON,
            admin::create_client,
        ),
        r(
            "GET",
            "/api/v1/api-clients/{id}",
            A(ApiClientsManage),
            JSON,
            admin::client,
        ),
        r(
            "DELETE",
            "/api/v1/api-clients/{id}",
            A(ApiClientsManage),
            JSON,
            admin::revoke_client,
        ),
        // Workspace reports (VS-06, UXW-25).
        r(
            "GET",
            "/api/v1/reports/{kind}",
            A(ReportsRead),
            JSON,
            reports::report,
        ),
        // Envelopes.
        r("GET", "/api/v1/contacts", er, JSON, env::contacts),
        r("GET", "/api/v1/envelopes", er, JSON, env::list),
        r("POST", "/api/v1/envelopes", ew, CREATE, env::create),
        // Use one template or several together (slice 3, FG-097).
        r(
            "POST",
            "/api/v1/envelopes/from-templates",
            ew,
            JSON,
            usetemplates::create,
        ),
        r("GET", "/api/v1/envelopes/{id}", er, JSON, env::get),
        r("PATCH", "/api/v1/envelopes/{id}", ew, JSON, env::patch),
        r("DELETE", "/api/v1/envelopes/{id}", ew, JSON, env::delete),
        // ADR-031 (UXW-02): back from the Deleted view.
        r(
            "POST",
            "/api/v1/envelopes/{id}/restore",
            ew,
            JSON,
            env::restore,
        ),
        r(
            "GET",
            "/api/v1/envelopes/{id}/status",
            er,
            JSON,
            env::status,
        ),
        r("POST", "/api/v1/envelopes/{id}/send", es, JSON, env::send),
        r(
            "PUT",
            "/api/v1/envelopes/{id}/schedule",
            es,
            JSON,
            env::schedule,
        ),
        r(
            "DELETE",
            "/api/v1/envelopes/{id}/schedule",
            es,
            JSON,
            env::unschedule,
        ),
        r("POST", "/api/v1/envelopes/{id}/void", es, JSON, env::void),
        // Custom fields: sender metadata, searchable (VS-06, FG-139).
        r(
            "GET",
            "/api/v1/envelopes/{id}/custom-fields",
            er,
            JSON,
            env::custom_fields,
        ),
        r(
            "PUT",
            "/api/v1/envelopes/{id}/custom-fields",
            ew,
            JSON,
            env::set_custom_fields,
        ),
        r(
            "POST",
            "/api/v1/envelopes/{id}/transfer",
            A(EnvelopesTransfer),
            JSON,
            env::transfer,
        ),
        r(
            "POST",
            "/api/v1/envelopes/{id}/correct",
            es,
            JSON,
            env::correct,
        ),
        r(
            "POST",
            "/api/v1/envelopes/{id}/resend",
            es,
            JSON,
            env::resend,
        ),
        r(
            "GET",
            "/api/v1/envelopes/{id}/audit",
            A(AuditRead),
            JSON,
            env::audit,
        ),
        r(
            "GET",
            "/api/v1/envelopes/{id}/anchor-proof",
            er,
            JSON,
            env::anchor_proof,
        ),
        r(
            "GET",
            "/api/v1/envelopes/{id}/certificate",
            er,
            JSON,
            env::certificate,
        ),
        r(
            "GET",
            "/api/v1/envelopes/{id}/attachments/{sha256}",
            er,
            JSON,
            env::attachment,
        ),
        r(
            "GET",
            "/api/v1/envelopes/{id}/documents/combined",
            er,
            JSON,
            env::combined,
        ),
        r(
            "GET",
            "/api/v1/envelopes/{id}/documents",
            er,
            JSON,
            env::documents,
        ),
        r(
            "POST",
            "/api/v1/envelopes/{id}/documents",
            ew,
            UPLOAD,
            env::add_document_route,
        ),
        r(
            "GET",
            "/api/v1/envelopes/{id}/documents/{doc}",
            er,
            JSON,
            env::document,
        ),
        r(
            "DELETE",
            "/api/v1/envelopes/{id}/documents/{doc}",
            ew,
            JSON,
            env::delete_document,
        ),
        r(
            "GET",
            "/api/v1/envelopes/{id}/documents/{doc}/content",
            er,
            JSON,
            env::content,
        ),
        r(
            "POST",
            "/api/v1/envelopes/{id}/documents/{doc}/detect-fields",
            ew,
            JSON,
            env::detect_fields,
        ),
        // Document analysis (docs/33 §6, WEB-19).
        r(
            "POST",
            "/api/v1/envelopes/{id}/documents/{doc}/analysis",
            ew,
            JSON,
            ml::request_envelope,
        ),
        r(
            "GET",
            "/api/v1/envelopes/{id}/documents/{doc}/analysis",
            er,
            JSON,
            ml::envelope_analysis,
        ),
        r(
            "GET",
            "/api/v1/envelopes/{id}/suggestions",
            er,
            JSON,
            ml::suggestions,
        ),
        r(
            "POST",
            "/api/v1/envelopes/{id}/suggestions/{s}/accept",
            ew,
            JSON,
            ml::accept,
        ),
        r(
            "POST",
            "/api/v1/envelopes/{id}/suggestions/{s}/dismiss",
            ew,
            JSON,
            ml::dismiss,
        ),
        r(
            "GET",
            "/api/v1/envelopes/{id}/recipients",
            er,
            JSON,
            env::recipients,
        ),
        r(
            "POST",
            "/api/v1/envelopes/{id}/recipients",
            ew,
            JSON,
            env::add_recipients,
        ),
        r(
            "GET",
            "/api/v1/envelopes/{id}/recipients/{r}",
            er,
            JSON,
            env::recipient,
        ),
        r(
            "PATCH",
            "/api/v1/envelopes/{id}/recipients/{r}",
            ew,
            JSON,
            env::patch_recipient,
        ),
        r(
            "DELETE",
            "/api/v1/envelopes/{id}/recipients/{r}",
            ew,
            JSON,
            env::delete_recipient,
        ),
        r(
            "GET",
            "/api/v1/envelopes/{id}/fields",
            er,
            JSON,
            env::fields,
        ),
        r(
            "POST",
            "/api/v1/envelopes/{id}/fields",
            ew,
            JSON,
            env::add_fields,
        ),
        r(
            "GET",
            "/api/v1/envelopes/{id}/fields/{f}",
            er,
            JSON,
            env::field,
        ),
        r(
            "PATCH",
            "/api/v1/envelopes/{id}/fields/{f}",
            ew,
            JSON,
            env::patch_field,
        ),
        r(
            "DELETE",
            "/api/v1/envelopes/{id}/fields/{f}",
            ew,
            JSON,
            env::delete_field,
        ),
        r(
            "GET",
            "/api/v1/envelopes/{id}/form-data",
            er,
            JSON,
            env::form_data,
        ),
        r(
            "POST",
            "/api/v1/envelopes/{id}/recipients/{r}/host",
            es,
            JSON,
            env::host_in_person,
        ),
        // The Inbox (UXW-01): any signed-in member, as the recipient they are.
        r(
            "POST",
            "/api/v1/envelopes/{id}/sign-link",
            Member,
            JSON,
            env::sign_link,
        ),
        // Bulk send from a template (UXW-04).
        r("GET", "/api/v1/bulk-sends", er, JSON, bulk::list),
        r(
            "POST",
            "/api/v1/bulk-sends",
            A(BulkSend),
            JSON,
            bulk::create,
        ),
        r("GET", "/api/v1/bulk-sends/{id}", er, JSON, bulk::get),
        r(
            "POST",
            "/api/v1/bulk-sends/{id}/send",
            A(BulkSend),
            JSON,
            bulk::send,
        ),
        r(
            "POST",
            "/api/v1/bulk-sends/{id}/cancel",
            A(BulkSend),
            JSON,
            bulk::cancel,
        ),
        // Folders (UXW-02): each member's own.
        r("GET", "/api/v1/folders", er, JSON, folders::list),
        r("POST", "/api/v1/folders", ew, JSON, folders::create),
        r("PATCH", "/api/v1/folders/{id}", ew, JSON, folders::rename),
        r("DELETE", "/api/v1/folders/{id}", ew, JSON, folders::delete),
        r(
            "POST",
            "/api/v1/folders/{id}/envelopes",
            ew,
            JSON,
            folders::file,
        ),
        // Template folders (TSH-03): each member's own.
        r(
            "POST",
            "/api/v1/folders/{id}/templates",
            tr,
            JSON,
            folders::file_templates,
        ),
        r(
            "POST",
            "/api/v1/envelopes/{id}/views/signing",
            es,
            JSON,
            env::view_signing,
        ),
        // Templates.
        r(
            "GET",
            "/api/v1/templates",
            A(TemplatesRead),
            JSON,
            templates::list,
        ),
        r(
            "POST",
            "/api/v1/templates",
            A(TemplatesWrite),
            JSON,
            templates::create,
        ),
        r(
            "GET",
            "/api/v1/templates/{id}",
            A(TemplatesRead),
            JSON,
            templates::get,
        ),
        r(
            "PATCH",
            "/api/v1/templates/{id}",
            A(TemplatesWrite),
            JSON,
            templates::patch,
        ),
        // Template editing (WEB-06).
        r(
            "DELETE",
            "/api/v1/templates/{id}",
            tw,
            JSON,
            templates::delete,
        ),
        r(
            "POST",
            "/api/v1/templates/{id}/restore",
            tw,
            JSON,
            templates::restore,
        ),
        // Template sharing and Favourites (UXW-06).
        r(
            "GET",
            "/api/v1/templates/{id}/shares",
            tr,
            JSON,
            templates::shares,
        ),
        r(
            "PUT",
            "/api/v1/templates/{id}/shares",
            tw,
            JSON,
            templates::put_shares,
        ),
        r(
            "PUT",
            "/api/v1/templates/{id}/favourite",
            tr,
            JSON,
            templates::favourite,
        ),
        r(
            "DELETE",
            "/api/v1/templates/{id}/favourite",
            tr,
            JSON,
            templates::unfavourite,
        ),
        r("GET", "/api/v1/groups", tr, JSON, templates::groups),
        r(
            "POST",
            "/api/v1/templates/{id}/duplicate",
            tw,
            JSON,
            templates::duplicate,
        ),
        r(
            "POST",
            "/api/v1/templates/{id}/documents",
            tw,
            UPLOAD,
            templates::add_document,
        ),
        r(
            "DELETE",
            "/api/v1/templates/{id}/documents/{doc}",
            tw,
            JSON,
            templates::delete_document,
        ),
        r(
            "GET",
            "/api/v1/templates/{id}/documents/{doc}/content",
            tr,
            JSON,
            templates::document_content,
        ),
        r(
            "POST",
            "/api/v1/templates/{id}/documents/{doc}/analysis",
            tw,
            JSON,
            ml::request_template,
        ),
        r(
            "GET",
            "/api/v1/templates/{id}/documents/{doc}/analysis",
            tr,
            JSON,
            ml::template_analysis,
        ),
        r(
            "POST",
            "/api/v1/templates/{id}/roles",
            tw,
            JSON,
            templates::add_role,
        ),
        r(
            "PATCH",
            "/api/v1/templates/{id}/roles/{role}",
            tw,
            JSON,
            templates::patch_role,
        ),
        r(
            "DELETE",
            "/api/v1/templates/{id}/roles/{role}",
            tw,
            JSON,
            templates::delete_role,
        ),
        r(
            "GET",
            "/api/v1/templates/{id}/fields",
            tr,
            JSON,
            templates::fields,
        ),
        r(
            "POST",
            "/api/v1/templates/{id}/fields",
            tw,
            JSON,
            templates::add_fields,
        ),
        r(
            "PATCH",
            "/api/v1/templates/{id}/fields/{f}",
            tw,
            JSON,
            templates::patch_field,
        ),
        r(
            "DELETE",
            "/api/v1/templates/{id}/fields/{f}",
            tw,
            JSON,
            templates::delete_field,
        ),
        // Webhooks.
        r(
            "GET",
            "/api/v1/webhooks",
            A(WebhooksManage),
            JSON,
            webhooks::list,
        ),
        r(
            "POST",
            "/api/v1/webhooks",
            A(WebhooksManage),
            JSON,
            webhooks::create,
        ),
        r(
            "GET",
            "/api/v1/webhooks/{id}",
            A(WebhooksManage),
            JSON,
            webhooks::get,
        ),
        r(
            "DELETE",
            "/api/v1/webhooks/{id}",
            A(WebhooksManage),
            JSON,
            webhooks::delete,
        ),
        r(
            "PATCH",
            "/api/v1/webhooks/{id}",
            A(WebhooksManage),
            JSON,
            webhooks::patch,
        ),
        r(
            "POST",
            "/api/v1/webhooks/{id}/test",
            A(WebhooksManage),
            JSON,
            webhooks::test,
        ),
        r(
            "POST",
            "/api/v1/webhooks/{id}/deliveries/{delivery}/redeliver",
            A(WebhooksManage),
            JSON,
            webhooks::redeliver,
        ),
        r(
            "GET",
            "/api/v1/webhooks/{id}/deliveries",
            A(WebhooksManage),
            JSON,
            webhooks::deliveries,
        ),
        // Ceremony (docs/40 §6).
        r("GET", "/s/{token}", Public, JSON, ceremony::view_or_page),
        r(
            "POST",
            "/s/{token}/session",
            Public,
            JSON,
            ceremony::session,
        ),
        r(
            "POST",
            "/s/{token}/consent",
            Public,
            JSON,
            ceremony::consent,
        ),
        r(
            "POST",
            "/s/{token}/authenticate",
            Public,
            JSON,
            ceremony::authenticate,
        ),
        r("POST", "/s/{token}/otp", Public, JSON, ceremony::otp_send),
        r(
            "POST",
            "/s/{token}/otp/verify",
            Public,
            JSON,
            ceremony::otp_verify,
        ),
        r("POST", "/s/{token}/sso", Public, JSON, ceremony::sso_start),
        r(
            "POST",
            "/s/{token}/sso/verify",
            Public,
            JSON,
            ceremony::sso_verify,
        ),
        r(
            "GET",
            "/s/{token}/documents/{doc}/content",
            Public,
            JSON,
            ceremony::document,
        ),
        r(
            "GET",
            "/s/{token}/document",
            Public,
            JSON,
            ceremony::download,
        ),
        r(
            "GET",
            "/s/{token}/certificate",
            Public,
            JSON,
            ceremony::certificate,
        ),
        r(
            "POST",
            "/s/{token}/documents/{doc}/viewed",
            Public,
            JSON,
            ceremony::viewed,
        ),
        r("POST", "/s/{token}/adopt", Public, IMAGE, ceremony::adopt),
        r(
            "PUT",
            "/s/{token}/fields/{field}",
            Public,
            JSON,
            ceremony::fill,
        ),
        r(
            "PUT",
            "/s/{token}/fields/{field}/attachment",
            Public,
            ATTACHMENT,
            ceremony::attach,
        ),
        r("POST", "/s/{token}/finish", Public, JSON, ceremony::finish),
        r(
            "POST",
            "/s/{token}/recipients",
            Public,
            JSON,
            ceremony::recipients,
        ),
        r(
            "POST",
            "/s/{token}/approve",
            Public,
            JSON,
            ceremony::approve,
        ),
        r(
            "POST",
            "/s/{token}/decline",
            Public,
            JSON,
            ceremony::decline,
        ),
        r(
            "POST",
            "/s/{token}/withdraw-consent",
            Public,
            JSON,
            ceremony::withdraw_consent,
        ),
        r(
            "POST",
            "/s/{token}/finish-later",
            Public,
            JSON,
            ceremony::finish_later,
        ),
        r("GET", "/s/{token}/history", Public, JSON, ceremony::history),
        r(
            "GET",
            "/s/{token}/disclosure",
            Public,
            JSON,
            ceremony::disclosure,
        ),
        r(
            "POST",
            "/s/{token}/reassign",
            Public,
            JSON,
            ceremony::reassign,
        ),
    ]
}

/// The application: every route of [`table`] behind its guard and body limit, the
/// request middleware around everything, and problem details for anything unmatched.
pub fn app(state: AppState) -> Router {
    let mut router: Router<AppState> = Router::new();
    let routes = table();
    crate::security::templates(routes.iter().map(|r| r.path));
    for route in routes {
        let mut h = route.handler.layer(DefaultBodyLimit::max(route.max_body));
        let guarded = match route.access {
            Access::Public => None,
            Access::Member => Some((Need::Any, false)),
            Access::Action(a) => Some((Need::Action(a), false)),
            Access::Org(a) => Some((Need::Org(a), false)),
            Access::SigningIn => Some((Need::Any, true)),
        };
        if let Some((need, signing_in)) = guarded {
            h = h.route_layer(from_fn_with_state(
                (
                    state.clone(),
                    Guard {
                        need,
                        max_body: route.max_body,
                        signing_in,
                    },
                ),
                guard,
            ));
        }
        if route.path.starts_with("/api/v1/") {
            // ASVS-09, outside the guard (a refused body needs no authentication): JSON
            // only, but for the token endpoint's RFC 6749 form and a raw PDF upload.
            let extra: OtherMedia = match route.path {
                "/api/v1/oauth/token" => &["application/x-www-form-urlencoded"],
                "/api/v1/envelopes/{id}/documents" => &["application/pdf"],
                _ => &[],
            };
            h = h.route_layer(from_fn_with_state(extra, json_only));
        }
        router = router.route(route.path, h);
    }
    finish(router, state)
}

/// Around the routes: problem details for anything unmatched, the last-resort panic
/// answer, and the request middleware.
fn finish(router: Router<AppState>, state: AppState) -> Router {
    router
        .fallback(crate::web::fallback)
        // ASVS-26: inside the request context, so the answer carries the request id.
        .layer(CatchPanicLayer::custom(panicked))
        .layer(from_fn_with_state(state.clone(), request_context))
        .with_state(state)
}

#[cfg(test)]
// Test code: a panic is the failure report (CLAUDE.md).
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use std::sync::Arc;

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::routing::get;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    use super::*;
    use crate::state::{Blobs, Config, SystemClock};

    /// An application whose database is never reached: a lazy pool on a closed port.
    fn offline() -> AppState {
        let pool = sqlx::postgres::PgPool::connect_lazy("postgres://nobody:none@127.0.0.1:9/none")
            .unwrap();
        let dir = std::env::temp_dir().join(format!("os-routes-{}", uuid::Uuid::now_v7()));
        AppState::new(
            casual_sign_store::Store::from_pool(pool),
            Blobs::Fs(Arc::new(
                casual_sign_store::blob::FsBlobStore::new(dir).unwrap(),
            )),
            crate::crypto::JwtKeys::generate().unwrap(),
            Arc::new(SystemClock),
            Config::default(),
        )
        .unwrap()
    }

    async fn call(app: Router, req: Request<Body>) -> (StatusCode, String, String) {
        let r = app.oneshot(req).await.unwrap();
        let id = r.headers()["x-request-id"].to_str().unwrap().to_owned();
        let status = r.status();
        let body = r.into_body().collect().await.unwrap().to_bytes();
        (status, id, String::from_utf8(body.to_vec()).unwrap())
    }

    async fn boom() -> &'static str {
        panic!("secret-in-panic")
    }

    /// ASVS-26: a handler that panics answers `500` problem details carrying the request
    /// id, and nothing of the panic.
    #[tokio::test]
    async fn a_handler_that_panics_answers_a_problem_with_the_request_id_only() {
        let st = offline();
        let routes: Router<AppState> = Router::new().route("/boom", get(boom));
        let req = Request::get("/boom").body(Body::empty()).unwrap();
        let (status, id, body) = call(finish(routes, st), req).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(body.contains("CS-API-0010") && body.contains(&id), "{body}");
        assert!(!body.contains("secret-in-panic"), "{body}");
    }

    /// ASVS-09: a cross-site form or a `text/plain` fetch cannot log in or create; the
    /// refusal comes before the handler or the guard (no database is reached).
    #[tokio::test]
    async fn api_v1_refuses_a_body_that_is_not_json() {
        let app = app(offline());
        for (path, media, body) in [
            (
                "/api/v1/auth/login",
                "text/plain",
                r#"{"email":"a@b","password":"x"}"#,
            ),
            (
                "/api/v1/auth/login",
                "application/x-www-form-urlencoded",
                "email=a%40b&password=x",
            ),
            (
                "/api/v1/envelopes",
                "application/x-www-form-urlencoded",
                "subject=x",
            ),
            (
                "/api/v1/envelopes",
                "multipart/form-data; boundary=b",
                "--b--",
            ),
        ] {
            let req = Request::post(path)
                .header("content-type", media)
                .body(Body::from(body))
                .unwrap();
            let (status, _, problem) = call(app.clone(), req).await;
            assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE, "{path} {media}");
            assert!(problem.contains("CS-API-0007"), "{problem}");
        }
        let bare = Request::post("/api/v1/auth/login")
            .body(Body::from("{}"))
            .unwrap();
        assert_eq!(call(app, bare).await.0, StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    /// ASVS 14.4.2, `ASVS-10`: every route of the table, and an unknown API path and a
    /// panic, answers with `Content-Disposition: attachment` and a filename, here on the
    /// refusals a server without its database makes (the contract scenario checks the
    /// successful answers, files included).
    #[tokio::test]
    async fn every_route_answers_as_a_named_attachment() {
        // As `offline`, but a request that needs the database fails at once.
        let pool = sqlx::postgres::PgPoolOptions::new()
            .acquire_timeout(std::time::Duration::from_millis(50))
            .connect_lazy("postgres://nobody:none@127.0.0.1:9/none")
            .unwrap();
        let dir = std::env::temp_dir().join(format!("os-routes-{}", uuid::Uuid::now_v7()));
        let st = AppState::new(
            casual_sign_store::Store::from_pool(pool),
            Blobs::Fs(Arc::new(
                casual_sign_store::blob::FsBlobStore::new(dir).unwrap(),
            )),
            crate::crypto::JwtKeys::generate().unwrap(),
            Arc::new(SystemClock),
            Config::default(),
        )
        .unwrap();
        let app = app(st.clone());
        let mut paths: Vec<(&str, String)> = table()
            .iter()
            .map(|r| {
                let path = r
                    .path
                    .split('/')
                    .map(|s| {
                        if s.starts_with('{') {
                            "0190a0a0-0000-7000-8000-000000000000"
                        } else {
                            s
                        }
                    })
                    .collect::<Vec<_>>()
                    .join("/");
                (r.method, path)
            })
            .collect();
        paths.push(("GET", "/api/v1/no-such-route".to_owned()));
        for (method, path) in paths {
            let req = Request::builder()
                .method(method)
                .uri(&path)
                .header("accept", "application/json")
                .body(Body::empty())
                .unwrap();
            let r = app.clone().oneshot(req).await.unwrap();
            let h = r.headers();
            let media = h
                .get("content-type")
                .map(|v| v.to_str().unwrap().to_owned());
            if media.as_deref().is_none_or(|m| m.starts_with("text/html")) {
                continue;
            }
            let d = h
                .get("content-disposition")
                .map(|v| v.to_str().unwrap().to_owned())
                .unwrap_or_default();
            assert!(
                d.starts_with("attachment; filename=\""),
                "{method} {path} ({}, {media:?}): {d:?}",
                r.status()
            );
        }
        let routes: Router<AppState> = Router::new().route("/api/v1/boom", get(boom));
        let req = Request::get("/api/v1/boom").body(Body::empty()).unwrap();
        let r = finish(routes, st).oneshot(req).await.unwrap();
        assert_eq!(
            r.headers()["content-disposition"],
            "attachment; filename=\"api.json\""
        );
    }
}
