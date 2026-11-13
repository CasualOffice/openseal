//! RFC 9457 problem details with stable `CS-*` codes (docs/40 §1, docs/20).
//!
//! Every refusal the server answers is an [`ApiError`]. Its body names a code, a title
//! fixed per code, the request id, optionally a detail made of ids and counts, and
//! field-level problems as JSON pointers. Never document content, names, addresses or
//! values (SEC-D01): details are built from ids only, and errors from the store and the
//! engine contribute their codes, never their text.

use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use casual_sign_store::StoreError;
use casual_sign_workflow::WorkflowError;
use serde::Serialize;

tokio::task_local! {
    /// The current request's id, set by the request middleware.
    pub(crate) static REQUEST_ID: String;
}

/// The current request's id, when inside one.
pub(crate) fn request_id() -> Option<String> {
    REQUEST_ID.try_with(Clone::clone).ok()
}

/// One field-level problem.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FieldProblem {
    /// JSON pointer into the request body.
    pub pointer: String,
    /// The code.
    pub code: &'static str,
}

/// A refusal, as problem details.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiError {
    status: StatusCode,
    code: &'static str,
    detail: Option<String>,
    errors: Vec<FieldProblem>,
    retry_after: Option<u64>,
}

impl ApiError {
    fn new(status: StatusCode, code: &'static str) -> Self {
        Self {
            status,
            code,
            detail: None,
            errors: Vec::new(),
            retry_after: None,
        }
    }

    /// With a detail: ids and counts only.
    #[must_use]
    pub fn detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    /// With field-level problems.
    #[must_use]
    pub fn fields(mut self, errors: Vec<FieldProblem>) -> Self {
        self.errors = errors;
        self
    }

    /// The HTTP status.
    #[must_use]
    pub fn status(&self) -> StatusCode {
        self.status
    }

    /// The stable code.
    #[must_use]
    pub fn code(&self) -> &'static str {
        self.code
    }

    /// `CS-API-0001` 400: the request could not be read.
    pub fn malformed(detail: &str) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "CS-API-0001").detail(detail)
    }

    /// `CS-API-0001` 422: the request was read and its content is invalid.
    pub fn invalid(pointer: &str) -> Self {
        Self::new(StatusCode::UNPROCESSABLE_ENTITY, "CS-API-0001").fields(vec![FieldProblem {
            pointer: pointer.into(),
            code: "CS-API-0001",
        }])
    }

    /// `CS-API-0001` 422 with the member's own code `exists` at `pointer`: a name the
    /// caller already uses (a folder, UXW-02).
    pub fn exists(pointer: &str) -> Self {
        Self::new(StatusCode::UNPROCESSABLE_ENTITY, "CS-API-0001").fields(vec![FieldProblem {
            pointer: pointer.into(),
            code: "exists",
        }])
    }

    /// `CS-WF-0007` 409: routing has not reached the caller as a recipient, or has
    /// passed them (the Inbox's sign-link, UXW-01).
    pub fn not_reached() -> Self {
        Self::new(StatusCode::CONFLICT, "CS-WF-0007")
    }

    /// `CS-API-0002` 404: no such object, including another account's.
    pub fn not_found() -> Self {
        Self::new(StatusCode::NOT_FOUND, "CS-API-0002")
    }

    /// `CS-API-0003` 429.
    pub fn rate_limited(retry_after: u64) -> Self {
        let mut e = Self::new(StatusCode::TOO_MANY_REQUESTS, "CS-API-0003");
        e.retry_after = Some(retry_after);
        e
    }

    /// `CS-API-0004` 422: an idempotency key reused with another request.
    pub fn idempotency_mismatch() -> Self {
        Self::new(StatusCode::UNPROCESSABLE_ENTITY, "CS-API-0004")
    }

    /// `CS-API-0005` 412.
    pub fn precondition_failed() -> Self {
        Self::new(StatusCode::PRECONDITION_FAILED, "CS-API-0005")
    }

    /// `CS-API-0006` 413.
    pub fn too_large() -> Self {
        Self::new(StatusCode::PAYLOAD_TOO_LARGE, "CS-API-0006")
    }

    /// `CS-API-0007` 415.
    pub fn unsupported_media() -> Self {
        Self::new(StatusCode::UNSUPPORTED_MEDIA_TYPE, "CS-API-0007")
    }

    /// `CS-API-0008` 428: `If-Match` required and absent.
    pub fn precondition_required() -> Self {
        Self::new(StatusCode::PRECONDITION_REQUIRED, "CS-API-0008")
    }

    /// `CS-API-0009` 409: not available in the object's state.
    pub fn not_available(detail: &str) -> Self {
        Self::new(StatusCode::CONFLICT, "CS-API-0009").detail(detail)
    }

    /// `CS-API-0010` 500. `what` names the failing step (never data).
    pub fn internal(what: &str) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "CS-API-0010").detail(what)
    }

    /// `CS-API-0011` 409: a request with this idempotency key is still running.
    pub fn idempotency_in_progress() -> Self {
        Self::new(StatusCode::CONFLICT, "CS-API-0011")
    }

    /// `CS-API-0012` 405.
    pub fn method_not_allowed() -> Self {
        Self::new(StatusCode::METHOD_NOT_ALLOWED, "CS-API-0012")
    }

    /// `CS-API-0013` 422: a webhook URL that is not public HTTPS (SEC-W01).
    pub fn webhook_url() -> Self {
        Self::new(StatusCode::UNPROCESSABLE_ENTITY, "CS-API-0013").fields(vec![FieldProblem {
            pointer: "/url".into(),
            code: "CS-API-0013",
        }])
    }

    /// `CS-API-0014` 409: the authentication method is not available on this server.
    pub fn method_unavailable() -> Self {
        Self::new(StatusCode::CONFLICT, "CS-API-0014")
    }

    /// `CS-API-0015` 403: the user is also a member of another account, so only they
    /// may change their password or name (SEC-ID-01).
    pub fn shared_user() -> Self {
        Self::new(StatusCode::FORBIDDEN, "CS-API-0015")
    }

    /// `CS-AUTH-0001` 401.
    pub fn unauthenticated() -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "CS-AUTH-0001")
    }

    /// `CS-AUTH-0002` 401: expired or revoked.
    pub fn expired() -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "CS-AUTH-0002")
    }

    /// `CS-AUTH-0006` 403: the credential lacks the scope or permission.
    pub fn forbidden(scope: &str) -> Self {
        Self::new(StatusCode::FORBIDDEN, "CS-AUTH-0006").detail(format!("needs {scope}"))
    }

    /// `CS-AUTH-0007` 401: wrong credentials.
    pub fn bad_credentials() -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "CS-AUTH-0007")
    }

    /// `CS-AUTH-0008` 403: CSRF token missing or wrong.
    pub fn csrf() -> Self {
        Self::new(StatusCode::FORBIDDEN, "CS-AUTH-0008")
    }

    /// `CS-AUTH-0009` 403: the ceremony link is bound to another browser.
    pub fn other_browser() -> Self {
        Self::new(StatusCode::FORBIDDEN, "CS-AUTH-0009")
    }

    /// `CS-AUTH-0010` 403: the host client does not own this embedding (row WF-05).
    pub fn not_embedding_owner() -> Self {
        Self::new(StatusCode::FORBIDDEN, "CS-AUTH-0010")
    }

    /// The fixed title of a code.
    fn title(&self) -> &'static str {
        match self.code {
            "CS-API-0001" => "Malformed or invalid request",
            "CS-API-0002" => "Not found",
            "CS-API-0003" => "Rate limited",
            "CS-API-0004" => "Idempotency key reused with a different request",
            "CS-API-0005" => "Precondition failed",
            "CS-API-0006" => "Request too large",
            "CS-API-0007" => "Unsupported media type",
            "CS-API-0008" => "Precondition required",
            "CS-API-0009" => "Not available in this state",
            "CS-API-0010" => "Internal error",
            "CS-API-0011" => "Request with this idempotency key in progress",
            "CS-API-0012" => "Method not allowed",
            "CS-API-0013" => "Webhook URL refused",
            "CS-API-0014" => "Authentication method not available",
            "CS-API-0015" => "User belongs to another account too",
            "CS-AUTH-0001" => "Not authenticated",
            "CS-AUTH-0002" => "Credential expired or revoked",
            "CS-AUTH-0003" => "Recipient authentication required or failed",
            "CS-AUTH-0004" => "Recipient locked",
            "CS-AUTH-0005" => "Consent required",
            "CS-AUTH-0006" => "Insufficient scope or permission",
            "CS-AUTH-0007" => "Invalid credentials",
            "CS-AUTH-0008" => "CSRF token missing or wrong",
            "CS-AUTH-0009" => "Link bound to another browser",
            "CS-AUTH-0010" => "Host does not own this embedding",
            c if c.starts_with("CS-WF") => "Workflow refused the command",
            c if c.starts_with("CS-FLD") => "Field rules refused the value",
            c if c.starts_with("CS-PDF") || c.starts_with("CS-WRT") => "Document refused",
            c if c.starts_with("CS-DB") || c.starts_with("CS-BLOB") => "Storage error",
            _ => "Error",
        }
    }
}

#[derive(Serialize)]
struct Problem<'a> {
    #[serde(rename = "type")]
    kind: String,
    title: &'static str,
    status: u16,
    code: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_id: Option<String>,
    #[serde(skip_serializing_if = "<[_]>::is_empty")]
    errors: &'a [FieldProblem],
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = Problem {
            kind: format!("urn:openseal:problem:{}", self.code),
            title: self.title(),
            status: self.status.as_u16(),
            code: self.code,
            detail: self.detail.as_deref(),
            request_id: request_id(),
            errors: &self.errors,
        };
        let bytes = serde_json::to_vec(&body).unwrap_or_default();
        let mut resp = (self.status, bytes).into_response();
        resp.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/problem+json"),
        );
        if let Some(s) = self.retry_after
            && let Ok(v) = HeaderValue::from_str(&s.to_string())
        {
            resp.headers_mut().insert(header::RETRY_AFTER, v);
        }
        if self.status == StatusCode::UNAUTHORIZED {
            resp.headers_mut().insert(
                header::WWW_AUTHENTICATE,
                HeaderValue::from_static("Bearer realm=\"openseal\""),
            );
        }
        resp
    }
}

impl From<StoreError> for ApiError {
    fn from(e: StoreError) -> Self {
        match e {
            e if e.is_shared_user() => Self::shared_user(),
            StoreError::NotFound { .. } | StoreError::BlobNotFound => Self::not_found(),
            StoreError::StaleVersion { .. } => {
                Self::new(StatusCode::PRECONDITION_FAILED, "CS-WF-0002")
            }
            StoreError::Conflict { .. } => Self::new(StatusCode::CONFLICT, e.code()),
            StoreError::Constraint { .. } => Self::new(StatusCode::UNPROCESSABLE_ENTITY, e.code()),
            StoreError::Unavailable | StoreError::BlobUnavailable { .. } => {
                Self::new(StatusCode::SERVICE_UNAVAILABLE, e.code())
            }
            StoreError::BlobTooLarge { .. } => Self::too_large(),
            _ => Self::new(StatusCode::INTERNAL_SERVER_ERROR, e.code()),
        }
    }
}

impl From<WorkflowError> for ApiError {
    fn from(e: WorkflowError) -> Self {
        let code = e.code();
        let status = match &e {
            WorkflowError::StaleVersion { .. } => StatusCode::PRECONDITION_FAILED,
            WorkflowError::NotPermitted { .. }
            | WorkflowError::AuthRequired { .. }
            | WorkflowError::AuthLocked { .. }
            | WorkflowError::ConsentRequired { .. } => StatusCode::FORBIDDEN,
            WorkflowError::Invalid { .. }
            | WorkflowError::Unknown { .. }
            | WorkflowError::DuplicateId { .. }
            | WorkflowError::CommandIdReused
            | WorkflowError::Fields { .. }
            | WorkflowError::Model(_)
            | WorkflowError::TimeOutOfRange
            | WorkflowError::Encoding => StatusCode::UNPROCESSABLE_ENTITY,
            _ => StatusCode::CONFLICT,
        };
        let mut out = Self::new(status, code).detail(e.to_string());
        if let WorkflowError::Invalid { violations } = &e {
            out.errors = violations
                .iter()
                .map(|v| FieldProblem {
                    pointer: String::new(),
                    code: v.code(),
                })
                .collect();
        }
        out
    }
}

impl From<casual_sign_host::HostError> for ApiError {
    fn from(e: casual_sign_host::HostError) -> Self {
        use casual_sign_host::HostError as H;
        match e {
            H::Workflow(w) => w.into(),
            H::Store(s) => s.into(),
            // An unreadable state, a non-UUID id, a clock out of range, a chain that
            // does not append: the server's fault, named by code only.
            other => Self::new(StatusCode::INTERNAL_SERVER_ERROR, other.code()),
        }
    }
}

impl From<casual_sign_sdk::SdkError> for ApiError {
    fn from(e: casual_sign_sdk::SdkError) -> Self {
        Self::new(StatusCode::UNPROCESSABLE_ENTITY, e.code())
    }
}

impl From<casual_sign_model::ModelError> for ApiError {
    fn from(e: casual_sign_model::ModelError) -> Self {
        Self::new(StatusCode::UNPROCESSABLE_ENTITY, e.code())
    }
}
