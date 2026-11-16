//! The console's security events (`ASVS-08`, docs/07 §Security event log), written
//! through `casual-sign-seclog` as one JSON line each. The operator log (hash-chained, in
//! the database) stays the record of what operators did; these lines are what an
//! operator's log collector sees, off the box.
//!
//! The request middleware (`auth::context`) calls `after` once the answer is
//! made: sign-in (`auth.sign_in`), the TOTP step (`auth.mfa`, with `reason: reused` for a
//! code of a step already used, ASVS 2.8.5), sign-out, enrolment (`auth.mfa_enrol`), a
//! committed change (`admin.change`), and every `401`, `403` and `429`. The operator is
//! named by id once known, before that by a keyed pseudonym of the e-mail presented; the
//! client address only as a pseudonym.

use std::convert::Infallible;
use std::sync::{Arc, Mutex};

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::{Method, StatusCode};
use axum::response::Response;
use casual_sign_seclog::{Domain, Kind, Outcome, Principal, SecurityEvent, Value};
use uuid::Uuid;

use crate::auth::Ctx;
use crate::state::AppState;

/// The code of the problem a response answers, for the event that records it.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ProblemCode(pub &'static str);

#[derive(Debug, Default)]
struct Slot {
    who: Option<Principal>,
    reason: Option<&'static str>,
}

/// What a request's handlers learned for its security event: who, and why a refusal.
#[derive(Debug, Clone, Default)]
pub struct SecSlot(Arc<Mutex<Slot>>);

impl SecSlot {
    /// The request is `who`'s.
    pub(crate) fn identify(&self, who: Principal) {
        if let Ok(mut s) = self.0.lock() {
            s.who = Some(who);
        }
    }

    /// Why the request was refused (a fixed word).
    pub(crate) fn reason(&self, why: &'static str) {
        if let Ok(mut s) = self.0.lock() {
            s.reason = Some(why);
        }
    }
}

impl<S: Send + Sync> FromRequestParts<S> for SecSlot {
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Infallible> {
        Ok(parts.extensions.get::<Self>().cloned().unwrap_or_default())
    }
}

/// The pseudonym of an e-mail address someone presented.
pub(crate) fn subject_email(st: &AppState, email: &str) -> Principal {
    Principal::Subject(
        st.security()
            .pseudonym(Domain::Email, email.trim().to_lowercase().as_bytes()),
    )
}

/// The event a successful or refused request on `route` is.
fn kind_of(method: &Method, route: &str, status: StatusCode) -> Option<(Kind, Outcome)> {
    let outcome = if status.is_success() {
        Outcome::Success
    } else {
        Outcome::Failure
    };
    let specific = match route {
        "/console/v1/auth/login" => Some(Kind::SignIn),
        "/console/v1/auth/totp" => Some(Kind::Mfa),
        "/console/v1/auth/logout" => Some(Kind::SignOut),
        "/console/v1/auth/enrolment/finish" => Some(Kind::MfaEnrol),
        _ => None,
    };
    if let Some(k) = specific {
        return Some((k, outcome));
    }
    let changes = !matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS);
    (changes
        && status.is_success()
        && route.starts_with("/console/v1/")
        && !route.starts_with("/console/v1/auth/"))
    .then_some((Kind::AdminChange, Outcome::Success))
}

/// The UUIDs a path names where its template has parameters.
fn ids(template: &str, path: &str) -> Vec<Uuid> {
    template
        .split('/')
        .zip(path.split('/'))
        .filter(|(t, _)| t.starts_with('{'))
        .filter_map(|(_, p)| Uuid::parse_str(p).ok())
        .collect()
}

/// The request's events, once it is answered.
pub(crate) fn after(
    st: &AppState,
    ctx: Ctx,
    method: &Method,
    route: Option<&str>,
    path: &str,
    slot: &SecSlot,
    resp: &Response,
) {
    let (who, reason) = slot
        .0
        .lock()
        .map(|s| (s.who.clone(), s.reason))
        .unwrap_or_default();
    let code = resp.extensions().get::<ProblemCode>().map(|c| c.0);
    let base = |kind: Kind, outcome: Outcome| {
        let mut ev = SecurityEvent::new(kind, outcome).request(ctx.request);
        if let Some(ip) = ctx.ip {
            ev = ev.client(
                st.security()
                    .pseudonym(Domain::Ip, ip.to_string().as_bytes()),
            );
        }
        if let Some(r) = route {
            ev = ev.route(r.to_owned());
        }
        if let Some(c) = code {
            ev = ev.code(c);
        }
        if let Some(w) = &who {
            ev = ev.principal(w.clone());
        }
        ev
    };
    let status = resp.status();
    if let Some((kind, outcome)) = route.and_then(|r| kind_of(method, r, status)) {
        let mut ev = base(kind, outcome);
        ev = match kind {
            Kind::SignIn => ev.with("via", Value::Word("password")),
            Kind::Mfa | Kind::MfaEnrol => ev.with("factor", Value::Word("totp")),
            Kind::AdminChange => ev.with(
                "objects",
                Value::Ids(route.map(|r| ids(r, path)).unwrap_or_default()),
            ),
            _ => ev,
        };
        if let (Outcome::Failure, Some(r)) = (outcome, reason) {
            ev = ev.with("reason", Value::Word(r));
        }
        st.security().emit(&ev);
    }
    let generic = match status {
        StatusCode::UNAUTHORIZED => Some(Kind::Unauthenticated),
        StatusCode::FORBIDDEN => Some(Kind::Denied),
        StatusCode::TOO_MANY_REQUESTS => Some(Kind::RateLimited),
        _ => None,
    };
    if let Some(kind) = generic {
        st.security().emit(&base(kind, Outcome::Failure));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_in_steps_and_changes_are_classified() {
        let ok = StatusCode::OK;
        assert_eq!(
            kind_of(
                &Method::POST,
                "/console/v1/auth/login",
                StatusCode::UNAUTHORIZED
            ),
            Some((Kind::SignIn, Outcome::Failure))
        );
        assert_eq!(
            kind_of(&Method::POST, "/console/v1/plans/{id}/archive", ok),
            Some((Kind::AdminChange, Outcome::Success))
        );
        assert_eq!(kind_of(&Method::GET, "/console/v1/organizations", ok), None);
        assert_eq!(
            kind_of(&Method::POST, "/console/v1/auth/enrolment/begin", ok),
            None
        );
    }
}
