//! The console's errors, each with a stable `CS-CON-*` code (docs/20) and an RFC 9457
//! problem body. Messages carry codes and ids only, never a name, an e-mail or a value.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use casual_sign_platform_store::PlatformError;
use serde_json::json;

/// Every error the console answers or starts with.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConsoleError {
    /// `CS-CON-0001` (401): no operator session, or it expired.
    NotAuthenticated,
    /// `CS-CON-0002` (401): second factor required, stale or wrong.
    SecondFactor,
    /// `CS-CON-0003` (403): the operator's roles lack the action.
    Forbidden,
    /// `CS-CON-0004` (409): the action needs a second operator's approval.
    ApprovalRequired,
    /// `CS-CON-0005` (start-up): a public bind without `OPENSEAL_CONSOLE_PUBLIC=1` and
    /// trusted proxies, or the console on the public application's origin.
    ListenerRefused(&'static str),
    /// `CS-CON-0007`: the operator log does not verify at `seq`; writes refused.
    LogBroken(u64),
    /// `CS-PLAN-0006` (422): a plan, quota, assignment or override is invalid, including
    /// `hard` enforcement on an approximate meter; names the field.
    PlanInvalid(&'static str),
    /// `CS-CON-0010` (400 or 422): the request is malformed or a value is invalid; names
    /// the field.
    Invalid(&'static str),
    /// `CS-CON-0011` (404): no such object.
    NotFound,
    /// `CS-CON-0012` (429): rate limit; retry after the seconds given.
    RateLimited(u64),
    /// `CS-CON-0013` (403): a state-changing request without its CSRF token, or with a
    /// wrong one, or not JSON.
    Csrf,
    /// `CS-CON-0014` (500): an internal failure; names the step, never a value.
    Internal(&'static str),
    /// `CS-CON-0015` (503): the database is unavailable.
    Unavailable,
    /// `CS-CON-0016` (409): the object already exists (an operator's e-mail).
    Conflict,
    /// `CS-CON-0017` (start-up): configuration invalid or a secret missing; names the
    /// variable.
    Config(&'static str),
}

impl ConsoleError {
    /// The stable code.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::NotAuthenticated => "CS-CON-0001",
            Self::SecondFactor => "CS-CON-0002",
            Self::Forbidden => "CS-CON-0003",
            Self::ApprovalRequired => "CS-CON-0004",
            Self::ListenerRefused(_) => "CS-CON-0005",
            Self::LogBroken(_) => "CS-CON-0007",
            Self::PlanInvalid(_) => "CS-PLAN-0006",
            Self::Invalid(_) => "CS-CON-0010",
            Self::NotFound => "CS-CON-0011",
            Self::RateLimited(_) => "CS-CON-0012",
            Self::Csrf => "CS-CON-0013",
            Self::Internal(_) => "CS-CON-0014",
            Self::Unavailable => "CS-CON-0015",
            Self::Conflict => "CS-CON-0016",
            Self::Config(_) => "CS-CON-0017",
        }
    }

    /// The HTTP status.
    #[must_use]
    pub fn status(&self) -> StatusCode {
        match self {
            Self::NotAuthenticated | Self::SecondFactor => StatusCode::UNAUTHORIZED,
            Self::Forbidden | Self::Csrf => StatusCode::FORBIDDEN,
            Self::ApprovalRequired | Self::Conflict => StatusCode::CONFLICT,
            Self::Invalid(_) | Self::PlanInvalid(_) => StatusCode::UNPROCESSABLE_ENTITY,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::RateLimited(_) => StatusCode::TOO_MANY_REQUESTS,
            Self::Unavailable | Self::LogBroken(_) => StatusCode::SERVICE_UNAVAILABLE,
            Self::ListenerRefused(_) | Self::Internal(_) | Self::Config(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
        }
    }

    fn title(&self) -> &'static str {
        match self {
            Self::NotAuthenticated => "Operator not signed in",
            Self::SecondFactor => "Second factor required",
            Self::Forbidden => "Operator role lacks this action",
            Self::ApprovalRequired => "Needs a second operator's approval",
            Self::ListenerRefused(_) => "Console listener refused",
            Self::LogBroken(_) => "Operator log does not verify",
            Self::PlanInvalid(_) => "Plan, quota or override invalid",
            Self::Invalid(_) => "Request invalid",
            Self::NotFound => "Not found",
            Self::RateLimited(_) => "Too many requests",
            Self::Csrf => "CSRF token missing or wrong",
            Self::Internal(_) => "Internal error",
            Self::Unavailable => "Database unavailable",
            Self::Conflict => "Already exists",
            Self::Config(_) => "Console configuration invalid",
        }
    }
}

impl core::fmt::Display for ConsoleError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ListenerRefused(why)
            | Self::Invalid(why)
            | Self::PlanInvalid(why)
            | Self::Internal(why)
            | Self::Config(why) => {
                write!(f, "{}: {} ({why})", self.code(), self.title())
            }
            Self::LogBroken(seq) => write!(f, "{}: {} at seq {seq}", self.code(), self.title()),
            _ => write!(f, "{}: {}", self.code(), self.title()),
        }
    }
}

impl std::error::Error for ConsoleError {}

impl From<PlatformError> for ConsoleError {
    fn from(e: PlatformError) -> Self {
        match e {
            PlatformError::NotAuthenticated => Self::NotAuthenticated,
            PlatformError::SecondFactor => Self::SecondFactor,
            PlatformError::Forbidden => Self::Forbidden,
            PlatformError::ApprovalRequired => Self::ApprovalRequired,
            PlatformError::LogBroken { seq } => Self::LogBroken(seq),
            PlatformError::Invalid { .. } => Self::Invalid("value"),
            PlatformError::PlanInvalid => Self::PlanInvalid("plan"),
            PlatformError::Unavailable => Self::Unavailable,
            _ => Self::Internal("database"),
        }
    }
}

impl IntoResponse for ConsoleError {
    fn into_response(self) -> Response {
        let status = self.status();
        let mut body = json!({
            "type": format!("https://openseal.dev/errors/{}", self.code()),
            "title": self.title(),
            "status": status.as_u16(),
            "code": self.code(),
        });
        if let Some(obj) = body.as_object_mut() {
            match &self {
                Self::Invalid(field) | Self::PlanInvalid(field) => {
                    obj.insert("field".into(), json!(field));
                }
                Self::RateLimited(secs) => {
                    obj.insert("retry_after".into(), json!(secs));
                }
                _ => {}
            }
        }
        if status.is_server_error() {
            tracing::warn!(code = self.code(), "console request failed: {self}");
        }
        let mut resp = (status, Json(body)).into_response();
        resp.headers_mut().insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/problem+json"),
        );
        if let Self::RateLimited(secs) = self
            && let Ok(v) = axum::http::HeaderValue::from_str(&secs.to_string())
        {
            resp.headers_mut()
                .insert(axum::http::header::RETRY_AFTER, v);
        }
        resp
    }
}
