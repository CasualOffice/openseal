//! The route table: every endpoint once, with the scope it needs (its `x-permission`
//! in `api/openapi.yaml`, SEC-A05) and the largest body it reads. The router is built
//! from this table, and the contract tests check the table against the OpenAPI
//! document in both directions.

use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::handler::Handler;
use axum::middleware::from_fn_with_state;
use axum::routing::{MethodFilter, MethodRouter, on};

use crate::api::{admin, envelopes as env, templates, webhooks};
use crate::ceremony;
use crate::http::{Guard, guard, request_context};
use crate::state::AppState;

/// Who may call a route.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    /// Anyone (login, token, JWKS, ceremony: they authenticate themselves).
    Public,
    /// An authenticated principal holding this scope (`""`: any).
    Scope(&'static str),
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
    use Access::{Public, Scope};
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
            Scope(""),
            JSON,
            admin::logout,
        ),
        r(
            "GET",
            "/api/v1/auth/session",
            Scope(""),
            JSON,
            admin::session,
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
        r(
            "GET",
            "/api/v1/admin-events",
            Scope("admin:account"),
            JSON,
            admin::admin_events,
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
    for route in table() {
        let mut h = route.handler.layer(DefaultBodyLimit::max(route.max_body));
        if let Access::Scope(scope) = route.access {
            h = h.route_layer(from_fn_with_state(
                (
                    state.clone(),
                    Guard {
                        scope,
                        max_body: route.max_body,
                    },
                ),
                guard,
            ));
        }
        router = router.route(route.path, h);
    }
    router
        .fallback(crate::web::fallback)
        .layer(from_fn_with_state(state.clone(), request_context))
        .with_state(state)
}
