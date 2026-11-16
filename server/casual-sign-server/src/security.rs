//! The server's security events (`ASVS-08`, docs/07 §Security event log), written
//! through `casual-sign-seclog` as one JSON line each, beside the access log.
//!
//! Two sources:
//!
//! - **Every request**, in [`after`] (called by the request middleware once the
//!   answer is made): a `401` is `access.unauthenticated`, a `403` `access.denied` (or
//!   `auth.lockout` for a locked recipient, `CS-AUTH-0004`), a `429`
//!   `access.rate_limited`, a `413` or a refused admission `input.upload_refused`; a
//!   committed change on an administrative route `admin.change`, and a staff read of a
//!   document, certificate, attachment or audit trail `data.document_read`, with the
//!   ids the path named.
//! - **The sign-in handlers**, through [`emit`]: password sign-in and sign-out, the
//!   second factor, password reset and change, invitation acceptance and the OAuth
//!   token endpoint.
//!
//! Each event carries the request id, the route template, the client address as a
//! keyed pseudonym, the code of a refusal, and the principal: the user (or client) the
//! guard authenticated, or, before anyone is known, a pseudonym of the e-mail or client
//! id presented. Never an address, a name, a token, a path or document content.

use std::collections::HashSet;
use std::sync::{Arc, Mutex, OnceLock};

use axum::http::{Method, StatusCode};
use axum::response::Response;
use casual_sign_seclog::{
    Domain, Kind, Outcome, Principal as SecPrincipal, Pseudonym, SecurityEvent, Uuid, Value,
};

use crate::anomaly::{self, Rule, Subject};
use crate::auth::Principal;
use crate::state::AppState;

/// The code of the problem a response answers (set by `ApiError` and the token
/// endpoint), for the event that records it.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ProblemCode(pub &'static str);

/// Marks a refusal of an upload's content by admission (`casual-sign-sdk`).
#[derive(Debug, Clone, Copy)]
pub(crate) struct AdmissionRefused;

/// What the current request knows for its events.
#[derive(Debug)]
pub(crate) struct Scope {
    request: Option<Uuid>,
    client: Option<Pseudonym>,
    route: Option<&'static str>,
    who: Mutex<Option<(SecPrincipal, Uuid, Option<Uuid>)>>,
    /// The request already counted toward a detection rule (a refused sign-in is
    /// both `auth.sign_in` and `access.unauthenticated`: one failure, `ASVS-13`).
    counted: Mutex<Vec<Rule>>,
}

tokio::task_local! {
    static SCOPE: Arc<Scope>;
}

/// Every route template, so a matched path's template can be named as `&'static str`.
static TEMPLATES: OnceLock<HashSet<&'static str>> = OnceLock::new();

/// Remember the route templates (once, as the router is built).
pub(crate) fn templates(paths: impl Iterator<Item = &'static str>) {
    let _ = TEMPLATES.set(paths.collect());
}

fn template(route: &str) -> Option<&'static str> {
    TEMPLATES.get().and_then(|t| t.get(route).copied())
}

/// The scope for one request.
pub(crate) fn scope(
    st: &AppState,
    request: &str,
    ip: Option<std::net::IpAddr>,
    route: &str,
) -> Arc<Scope> {
    Arc::new(Scope {
        request: Uuid::parse_str(request).ok(),
        client: ip.map(|i| {
            st.security()
                .pseudonym(Domain::Ip, i.to_string().as_bytes())
        }),
        route: template(route),
        who: Mutex::new(None),
        counted: Mutex::new(Vec::new()),
    })
}

/// Run `f` inside `scope`.
pub(crate) async fn within<F: Future>(scope: Arc<Scope>, f: F) -> F::Output {
    SCOPE.scope(scope, f).await
}

/// The guard authenticated `p`: later events of the request name them.
pub(crate) fn authenticated(p: &Principal) {
    identify(p.user.0, p.account.0, p.client().map(|c| c.0));
}

/// The request is `user`'s in `account` (through `client`), as far as is known: a
/// session found before its CSRF token is checked names its holder.
pub(crate) fn identify(user: Uuid, account: Uuid, client: Option<Uuid>) {
    let _ = SCOPE.try_with(|s| {
        if let Ok(mut w) = s.who.lock() {
            *w = Some((SecPrincipal::User(user), account, client));
        }
    });
}

/// Fill `ev` from the request's scope (request id, client, route and principal, where
/// `ev` has none) and write it.
pub(crate) fn emit(st: &AppState, mut ev: SecurityEvent) {
    let filled = SCOPE.try_with(|s| {
        if let Some(r) = s.request {
            ev = ev.clone().request(r);
        }
        if let Some(c) = &s.client {
            ev = ev.clone().client(c.clone());
        }
        if let Some(r) = s.route {
            ev = ev.clone().route(r);
        }
        if let Ok(w) = s.who.lock()
            && let Some((p, account, client)) = w.as_ref()
        {
            ev = ev
                .clone()
                .principal_if_none(p.clone())
                .account_if_none(*account);
            if let Some(c) = client {
                ev = ev.clone().with("api_client", Value::Id(*c));
            }
        }
    });
    let _ = filled;
    st.security().emit(&ev);
    if let Some(rule) = rule_of(&ev)
        && first_count(rule)
    {
        let mut subjects = Vec::with_capacity(2);
        if let Some(p) = ev.principal_ref() {
            subjects.push(Subject::Principal(p));
        }
        if let Some(c) = ev.client_ref() {
            subjects.push(Subject::Address(c));
        }
        detect(st, rule, &subjects);
    }
}

/// Whether this is the request's first event counted toward `rule` (outside a
/// request, always).
fn first_count(rule: Rule) -> bool {
    SCOPE
        .try_with(|s| {
            s.counted.lock().is_ok_and(|mut c| {
                let first = !c.contains(&rule);
                if first {
                    c.push(rule);
                }
                first
            })
        })
        .unwrap_or(true)
}

/// What a security event counts toward (`ASVS-13`).
fn rule_of(ev: &SecurityEvent) -> Option<Rule> {
    let failed = ev.outcome() == Outcome::Failure;
    match ev.kind() {
        Kind::RateLimited => Some(Rule::RateLimited),
        Kind::Denied => Some(Rule::Denied),
        Kind::DocumentRead if !failed => Some(Rule::DocumentReads),
        Kind::SignIn
        | Kind::Mfa
        | Kind::MfaEnrol
        | Kind::PasswordReset
        | Kind::PasswordChange
        | Kind::InviteAccept
        | Kind::Token
        | Kind::Lockout
        | Kind::Unauthenticated
            if failed =>
        {
            Some(Rule::AuthFailures)
        }
        _ => None,
    }
}

/// Count one `rule` event by `subjects`; raise what is due: an
/// `alert.abnormal_activity` security event and an operator alert (`ASVS-13`).
fn detect(st: &AppState, rule: Rule, subjects: &[Subject<'_>]) {
    for trip in st.anomaly().observe(rule, subjects, st.now()) {
        let mut ev = SecurityEvent::new(Kind::Alert, Outcome::Failure)
            .code(if trip.rule.is_some() {
                anomaly::CODE_THRESHOLD
            } else {
                anomaly::CODE_TABLE_FULL
            })
            .with(
                "rule",
                Value::Word(trip.rule.map_or("tracking_full", Rule::as_str)),
            )
            .with("count", Value::Count(trip.count))
            .with("threshold", Value::Count(trip.threshold))
            .with("window_s", Value::Count(st.anomaly().window_secs()))
            .with("suppressed", Value::Count(trip.suppressed))
            .with("dropped", Value::Count(trip.dropped));
        let (mut principal, mut client) = (None, None);
        for i in &trip.over {
            match subjects.get(*i) {
                Some(Subject::Principal(p)) => {
                    ev = ev.principal((*p).clone());
                    principal = Some(p.text());
                }
                Some(Subject::Address(a)) => {
                    ev = ev.client((*a).clone());
                    client = Some(a.as_str().to_owned());
                }
                None => {}
            }
        }
        // The request that tripped it, never its principal unless that is what
        // tripped.
        let _ = SCOPE.try_with(|s| {
            if let Some(r) = s.request {
                ev = ev.clone().request(r);
            }
            if let Some(r) = s.route {
                ev = ev.clone().route(r);
            }
        });
        st.security().emit(&ev);
        st.alerts().alert(&anomaly::AbnormalActivity {
            rule: trip.rule.map_or("tracking_full", Rule::as_str),
            code: if trip.rule.is_some() {
                anomaly::CODE_THRESHOLD
            } else {
                anomaly::CODE_TABLE_FULL
            },
            count: trip.count,
            threshold: trip.threshold,
            window_secs: st.anomaly().window_secs(),
            principal,
            client,
            suppressed: trip.suppressed,
            dropped: trip.dropped,
        });
    }
}

/// Count the request itself, and a void, by the request's principal and address.
fn count_request(st: &AppState, method: &Method, resp: &Response) {
    let Ok((who, client, route)) = SCOPE.try_with(|s| {
        let who = s
            .who
            .lock()
            .ok()
            .and_then(|w| w.as_ref().map(|w| w.0.clone()));
        (who, s.client.clone(), s.route)
    }) else {
        return;
    };
    let mut subjects = Vec::with_capacity(2);
    if let Some(p) = &who {
        subjects.push(Subject::Principal(p));
    }
    if let Some(c) = &client {
        subjects.push(Subject::Address(c));
    }
    detect(st, Rule::Requests, &subjects);
    if *method == Method::POST
        && resp.status().is_success()
        && route == Some("/api/v1/envelopes/{id}/void")
    {
        detect(st, Rule::Voids, &subjects);
    }
}

/// The event of a handler's answer: success on a `2xx`, otherwise failure with the
/// answer's code.
pub(crate) fn answered(
    st: &AppState,
    kind: Kind,
    resp: &Response,
    build: impl FnOnce(SecurityEvent) -> SecurityEvent,
) {
    let outcome = if resp.status().is_success() {
        Outcome::Success
    } else {
        Outcome::Failure
    };
    let mut ev = SecurityEvent::new(kind, outcome);
    if let Some(c) = resp.extensions().get::<ProblemCode>() {
        ev = ev.code(c.0);
    }
    emit(st, build(ev));
}

/// The pseudonym of an e-mail address someone presented.
pub(crate) fn subject_email(st: &AppState, email: &str) -> SecPrincipal {
    SecPrincipal::Subject(
        st.security()
            .pseudonym(Domain::Email, email.trim().to_lowercase().as_bytes()),
    )
}

/// The pseudonym of an identifier someone presented.
pub(crate) fn subject(st: &AppState, id: &str) -> SecPrincipal {
    SecPrincipal::Subject(st.security().pseudonym(Domain::Identifier, id.as_bytes()))
}

/// What a successful request on `template` is, if it is a security event: a change on
/// an administrative route, or a staff read of a document, of data taken from one
/// (analysis, suggestions, field values) or of the evidence.
#[must_use]
pub fn classify(method: &str, template: &str) -> Option<Kind> {
    const ADMIN: &[&str] = &[
        "/api/v1/accounts/me",
        "/api/v1/account/settings/",
        "/api/v1/ersd-versions",
        "/api/v1/organizations/me",
        "/api/v1/users",
        "/api/v1/groups",
        "/api/v1/permission-profiles",
        "/api/v1/api-clients",
        "/api/v1/webhooks",
    ];
    const READS: &[&str] = &[
        "/api/v1/envelopes/{id}/documents/{doc}/content",
        "/api/v1/envelopes/{id}/documents/combined",
        "/api/v1/envelopes/{id}/certificate",
        "/api/v1/envelopes/{id}/attachments/{sha256}",
        "/api/v1/envelopes/{id}/audit",
        "/api/v1/envelopes/{id}/form-data",
        // What analysis found in a document (the suggestions carry values read from
        // its text) and the fields with their filled values (ASVS 8.3.5).
        "/api/v1/envelopes/{id}/documents/{doc}/analysis",
        "/api/v1/envelopes/{id}/suggestions",
        "/api/v1/envelopes/{id}/fields",
        "/api/v1/envelopes/{id}/fields/{f}",
        // The envelope itself embeds every field with its value.
        "/api/v1/envelopes/{id}",
        "/api/v1/templates/{id}/documents/{doc}/content",
        "/api/v1/templates/{id}/documents/{doc}/analysis",
        "/api/v1/organizations/me/audit",
        "/api/v1/admin-events",
    ];
    if method == "GET" {
        return READS.contains(&template).then_some(Kind::DocumentRead);
    }
    // A member's own profile and password are not administration; a password change
    // is its own event.
    if template == "/api/v1/users/me" {
        return None;
    }
    ADMIN
        .iter()
        .any(|p| {
            template == *p
                || template.starts_with(&format!("{p}/"))
                || (p.ends_with('/') && template.starts_with(p))
        })
        .then_some(Kind::AdminChange)
}

/// The ids a path names where its template has parameters (UUIDs only; anything else,
/// such as a ceremony token, is never taken).
fn ids(template: &str, path: &str) -> Vec<Uuid> {
    template
        .split('/')
        .zip(path.split('/'))
        .filter(|(t, _)| t.starts_with('{'))
        .filter_map(|(_, p)| Uuid::parse_str(p).ok())
        .collect()
}

/// The request's own events, once it is answered.
pub(crate) fn after(st: &AppState, method: &Method, path: &str, resp: &Response) {
    let code = resp.extensions().get::<ProblemCode>().map(|c| c.0);
    let refused = |kind: Kind| {
        let mut ev = SecurityEvent::new(kind, Outcome::Failure);
        if let Some(c) = code {
            ev = ev.code(c);
        }
        ev
    };
    let status = resp.status();
    let ev = match status {
        StatusCode::UNAUTHORIZED => Some(refused(Kind::Unauthenticated)),
        StatusCode::FORBIDDEN if code == Some("CS-AUTH-0004") => Some(refused(Kind::Lockout)),
        StatusCode::FORBIDDEN => Some(refused(Kind::Denied)),
        StatusCode::TOO_MANY_REQUESTS => Some(refused(Kind::RateLimited)),
        StatusCode::PAYLOAD_TOO_LARGE => Some(refused(Kind::UploadRefused)),
        _ if resp.extensions().get::<AdmissionRefused>().is_some() => {
            Some(refused(Kind::UploadRefused))
        }
        s if s.is_success() => {
            let route = SCOPE.try_with(|s| s.route).ok().flatten();
            route.and_then(|t| {
                classify(method.as_str(), t).map(|kind| {
                    SecurityEvent::new(kind, Outcome::Success)
                        .with("method", Value::Word(method_word(method)))
                        .with("objects", Value::Ids(ids(t, path)))
                })
            })
        }
        _ => None,
    };
    if let Some(ev) = ev {
        emit(st, ev);
    }
    count_request(st, method, resp);
}

fn method_word(m: &Method) -> &'static str {
    match *m {
        Method::GET => "GET",
        Method::POST => "POST",
        Method::PUT => "PUT",
        Method::PATCH => "PATCH",
        Method::DELETE => "DELETE",
        _ => "OTHER",
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn every_administrative_change_and_staff_read_is_classified() {
        for r in crate::routes::table() {
            let admin_scope = matches!(
                r.access,
                crate::routes::Access::Scope("admin:account" | "admin:users" | "webhooks:manage")
            );
            let class = classify(r.method, r.path);
            if admin_scope && r.method != "GET" {
                assert_eq!(class, Some(Kind::AdminChange), "{} {}", r.method, r.path);
            }
            if r.path.starts_with("/s/") {
                assert_eq!(class, None, "{} {}", r.method, r.path);
            }
        }
        assert_eq!(
            classify("GET", "/api/v1/envelopes/{id}/documents/{doc}/content"),
            Some(Kind::DocumentRead)
        );
        // What analysis found in a document and the fields' values are document data
        // too (ASVS 8.3.5).
        for t in [
            "/api/v1/envelopes/{id}/documents/{doc}/analysis",
            "/api/v1/envelopes/{id}/suggestions",
            "/api/v1/envelopes/{id}/fields",
            "/api/v1/envelopes/{id}/fields/{f}",
            "/api/v1/envelopes/{id}",
            "/api/v1/templates/{id}/documents/{doc}/analysis",
        ] {
            assert_eq!(classify("GET", t), Some(Kind::DocumentRead), "{t}");
        }
        assert_eq!(classify("PATCH", "/api/v1/users/me"), None);
        assert_eq!(classify("POST", "/api/v1/envelopes"), None);
        assert_eq!(
            classify("PATCH", "/api/v1/account/settings/ml"),
            Some(Kind::AdminChange)
        );
    }

    #[test]
    fn only_uuids_are_taken_from_a_path() {
        let a = Uuid::now_v7();
        assert_eq!(
            ids(
                "/api/v1/envelopes/{id}/documents/{doc}/content",
                &format!("/api/v1/envelopes/{a}/documents/x/content")
            ),
            vec![a]
        );
        assert!(ids("/s/{token}", "/s/secret-token").is_empty());
    }
}
