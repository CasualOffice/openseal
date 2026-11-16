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
    admin, bulk, envelopes as env, folders, groups, mfa, ml, org, switch, templates, webhooks,
};
use crate::ceremony;
use crate::http::{Guard, OtherMedia, guard, json_only, panicked, request_context};
use crate::state::AppState;

/// Who may call a route.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    /// Anyone (login, token, JWKS, ceremony: they authenticate themselves).
    Public,
    /// An authenticated principal holding this scope (`""`: any) that owes no second
    /// factor it has not passed.
    Scope(&'static str),
    /// Any authenticated principal, a staff session that still owes its second factor
    /// included: the steps of signing in (ASVS-01). `x-permission: signing-in`.
    SigningIn,
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
    use Access::{Public, Scope, SigningIn};
    let er = Scope("envelopes:read");
    let ew = Scope("envelopes:write");
    let es = Scope("envelopes:send");
    let tr = Scope("templates:read");
    let tw = Scope("templates:write");
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
        // Workspace switching (docs/23 §2.3, ORG-04).
        r(
            "GET",
            "/api/v1/auth/workspaces",
            Scope(""),
            JSON,
            switch::workspaces,
        ),
        r(
            "POST",
            "/api/v1/auth/switch",
            Scope(""),
            JSON,
            switch::switch,
        ),
        r("POST", "/api/v1/oauth/token", Public, JSON, admin::token),
        r("GET", "/.well-known/jwks.json", Public, JSON, admin::jwks),
        // Account, users, API clients.
        r(
            "GET",
            "/api/v1/accounts/me",
            Scope(""),
            JSON,
            admin::account,
        ),
        r(
            "PATCH",
            "/api/v1/accounts/me",
            Scope("admin:account"),
            JSON,
            admin::patch_account,
        ),
        // The workspace's document-analysis switches (docs/33 §6, §7; WEB-19).
        r(
            "GET",
            "/api/v1/account/settings/ml",
            Scope("admin:account"),
            JSON,
            ml::settings,
        ),
        r(
            "PATCH",
            "/api/v1/account/settings/ml",
            Scope("admin:account"),
            JSON,
            ml::patch_settings,
        ),
        r(
            "GET",
            "/api/v1/ersd-versions",
            Scope("admin:account"),
            JSON,
            admin::ersd_versions,
        ),
        r(
            "POST",
            "/api/v1/ersd-versions",
            Scope("admin:account"),
            JSON,
            admin::publish_ersd,
        ),
        r(
            "GET",
            "/api/v1/admin-events",
            Scope("admin:account"),
            JSON,
            admin::admin_events,
        ),
        r("GET", "/api/v1/users/me", Scope(""), JSON, admin::me),
        r(
            "PATCH",
            "/api/v1/users/me",
            Scope(""),
            IMAGE * 2,
            admin::patch_me,
        ),
        // Organization (ORG-03): the role is checked per request in the handler.
        r(
            "GET",
            "/api/v1/organizations/me",
            Scope(""),
            JSON,
            org::organization,
        ),
        r(
            "PATCH",
            "/api/v1/organizations/me",
            Scope(""),
            JSON,
            org::patch_organization,
        ),
        r(
            "GET",
            "/api/v1/organizations/me/workspaces",
            Scope(""),
            JSON,
            org::workspaces,
        ),
        r(
            "POST",
            "/api/v1/organizations/me/workspaces",
            Scope(""),
            JSON,
            org::create_workspace,
        ),
        r(
            "GET",
            "/api/v1/organizations/me/workspaces/{id}",
            Scope(""),
            JSON,
            org::workspace,
        ),
        r(
            "POST",
            "/api/v1/organizations/me/workspaces/{id}/archive",
            Scope(""),
            JSON,
            org::archive_workspace,
        ),
        r(
            "POST",
            "/api/v1/organizations/me/workspaces/{id}/join",
            Scope(""),
            JSON,
            org::join_workspace,
        ),
        r(
            "GET",
            "/api/v1/organizations/me/admins",
            Scope(""),
            JSON,
            org::admins,
        ),
        r(
            "POST",
            "/api/v1/organizations/me/admins",
            Scope(""),
            JSON,
            org::add_admin,
        ),
        r(
            "PATCH",
            "/api/v1/organizations/me/admins/{user}",
            Scope(""),
            JSON,
            org::patch_admin,
        ),
        r(
            "DELETE",
            "/api/v1/organizations/me/admins/{user}",
            Scope(""),
            JSON,
            org::remove_admin,
        ),
        r(
            "GET",
            "/api/v1/organizations/me/audit",
            Scope(""),
            JSON,
            org::audit,
        ),
        r(
            "GET",
            "/api/v1/users",
            Scope("admin:users"),
            JSON,
            admin::users,
        ),
        r(
            "POST",
            "/api/v1/users",
            Scope("admin:users"),
            JSON,
            admin::create_user,
        ),
        r(
            "GET",
            "/api/v1/users/{id}",
            Scope("admin:users"),
            JSON,
            admin::user,
        ),
        r(
            "PATCH",
            "/api/v1/users/{id}",
            Scope("admin:users"),
            JSON,
            admin::patch_user,
        ),
        r(
            "DELETE",
            "/api/v1/users/{id}",
            Scope("admin:users"),
            JSON,
            admin::delete_user,
        ),
        r(
            "POST",
            "/api/v1/users/{id}/invite",
            Scope("admin:users"),
            JSON,
            admin::reinvite_user,
        ),
        // Admin groups and custom permission profiles (UXW-07).
        r(
            "POST",
            "/api/v1/groups",
            Scope("admin:users"),
            JSON,
            groups::create_group,
        ),
        r(
            "GET",
            "/api/v1/groups/{id}",
            Scope("admin:users"),
            JSON,
            groups::group,
        ),
        r(
            "PATCH",
            "/api/v1/groups/{id}",
            Scope("admin:users"),
            JSON,
            groups::patch_group,
        ),
        r(
            "DELETE",
            "/api/v1/groups/{id}",
            Scope("admin:users"),
            JSON,
            groups::delete_group,
        ),
        r(
            "PUT",
            "/api/v1/groups/{id}/members",
            Scope("admin:users"),
            JSON,
            groups::put_members,
        ),
        r(
            "GET",
            "/api/v1/permission-profiles",
            Scope("admin:users"),
            JSON,
            groups::profiles,
        ),
        r(
            "POST",
            "/api/v1/permission-profiles",
            Scope("admin:users"),
            JSON,
            groups::create_profile,
        ),
        r(
            "GET",
            "/api/v1/permission-profiles/{id}",
            Scope("admin:users"),
            JSON,
            groups::profile,
        ),
        r(
            "PATCH",
            "/api/v1/permission-profiles/{id}",
            Scope("admin:users"),
            JSON,
            groups::patch_profile,
        ),
        r(
            "DELETE",
            "/api/v1/permission-profiles/{id}",
            Scope("admin:users"),
            JSON,
            groups::delete_profile,
        ),
        r(
            "GET",
            "/api/v1/api-clients",
            Scope("admin:account"),
            JSON,
            admin::clients,
        ),
        r(
            "POST",
            "/api/v1/api-clients",
            Scope("admin:account"),
            JSON,
            admin::create_client,
        ),
        r(
            "GET",
            "/api/v1/api-clients/{id}",
            Scope("admin:account"),
            JSON,
            admin::client,
        ),
        r(
            "DELETE",
            "/api/v1/api-clients/{id}",
            Scope("admin:account"),
            JSON,
            admin::revoke_client,
        ),
        // Envelopes.
        r("GET", "/api/v1/contacts", er, JSON, env::contacts),
        r("GET", "/api/v1/envelopes", er, JSON, env::list),
        r("POST", "/api/v1/envelopes", ew, CREATE, env::create),
        r("GET", "/api/v1/envelopes/{id}", er, JSON, env::get),
        r("PATCH", "/api/v1/envelopes/{id}", ew, JSON, env::patch),
        r("DELETE", "/api/v1/envelopes/{id}", ew, JSON, env::delete),
        r(
            "GET",
            "/api/v1/envelopes/{id}/status",
            er,
            JSON,
            env::status,
        ),
        r("POST", "/api/v1/envelopes/{id}/send", es, JSON, env::send),
        r("POST", "/api/v1/envelopes/{id}/void", es, JSON, env::void),
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
            Scope("audit:read"),
            JSON,
            env::audit,
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
            Scope(""),
            JSON,
            env::sign_link,
        ),
        // Bulk send from a template (UXW-04).
        r("GET", "/api/v1/bulk-sends", er, JSON, bulk::list),
        r(
            "POST",
            "/api/v1/bulk-sends",
            Scope("bulk:send"),
            JSON,
            bulk::create,
        ),
        r("GET", "/api/v1/bulk-sends/{id}", er, JSON, bulk::get),
        r(
            "POST",
            "/api/v1/bulk-sends/{id}/send",
            Scope("bulk:send"),
            JSON,
            bulk::send,
        ),
        r(
            "POST",
            "/api/v1/bulk-sends/{id}/cancel",
            Scope("bulk:send"),
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
            Scope("templates:read"),
            JSON,
            templates::list,
        ),
        r(
            "POST",
            "/api/v1/templates",
            Scope("templates:write"),
            JSON,
            templates::create,
        ),
        r(
            "GET",
            "/api/v1/templates/{id}",
            Scope("templates:read"),
            JSON,
            templates::get,
        ),
        r(
            "PATCH",
            "/api/v1/templates/{id}",
            Scope("templates:write"),
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
            Scope("webhooks:manage"),
            JSON,
            webhooks::list,
        ),
        r(
            "POST",
            "/api/v1/webhooks",
            Scope("webhooks:manage"),
            JSON,
            webhooks::create,
        ),
        r(
            "GET",
            "/api/v1/webhooks/{id}",
            Scope("webhooks:manage"),
            JSON,
            webhooks::get,
        ),
        r(
            "DELETE",
            "/api/v1/webhooks/{id}",
            Scope("webhooks:manage"),
            JSON,
            webhooks::delete,
        ),
        r(
            "PATCH",
            "/api/v1/webhooks/{id}",
            Scope("webhooks:manage"),
            JSON,
            webhooks::patch,
        ),
        r(
            "POST",
            "/api/v1/webhooks/{id}/test",
            Scope("webhooks:manage"),
            JSON,
            webhooks::test,
        ),
        r(
            "POST",
            "/api/v1/webhooks/{id}/deliveries/{delivery}/redeliver",
            Scope("webhooks:manage"),
            JSON,
            webhooks::redeliver,
        ),
        r(
            "GET",
            "/api/v1/webhooks/{id}/deliveries",
            Scope("webhooks:manage"),
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
            Access::Scope(scope) => Some((scope, false)),
            Access::SigningIn => Some(("", true)),
        };
        if let Some((scope, signing_in)) = guarded {
            h = h.route_layer(from_fn_with_state(
                (
                    state.clone(),
                    Guard {
                        scope,
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
}
