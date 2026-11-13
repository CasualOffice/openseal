//! OpenSeal's one log line and its security events (`ASVS-08`, ASVS 1.7.1, 1.7.2,
//! 7.1.3, 7.1.4, 7.2.1, 7.2.2; docs/07 `SEC-D01`, `SEC-D06`).
//!
//! **One format.** Every host process (server, worker, keyd, modeld, console) writes one
//! JSON object per line to standard error:
//!
//! ```json
//! {"ts":"2026-11-13T10:00:00.123Z","level":"WARN","service":"server","event":"security",
//!  "kind":"auth.sign_in","outcome":"failure","request_id":"0193…","principal":"subject:p1:9f…",
//!  "client":"p1:4c…","code":"CS-AUTH-0007","route":"/api/v1/auth/login","via":"password"}
//! ```
//!
//! Standard error is what a container runtime collects, so shipping the logs off the box
//! is the runtime's job: docs/65 §Logs and the `deploy/compose.log-forwarding.yml`
//! override send them over syslog on TLS (RFC 5425), to a collector that may forward as
//! OTLP. Nothing here opens a socket.
//!
//! **Security events** ([`SecurityEvent`]) have a closed taxonomy ([`Kind`]), an
//! [`Outcome`], and fields that are typed so that free text cannot enter them: ids are
//! [`Uuid`]s, codes and words are `&'static str`, names of keys and callers are
//! [`Label`]s (`[A-Za-z0-9._-]{1,64}`, so never an address or a sentence), and an
//! identifier a caller merely *claims* (a submitted e-mail, a client address) is a
//! keyed [`Pseudonym`], never the value. They are never filtered by `RUST_LOG`.
//!
//! **Pseudonyms** are HMAC-SHA-256 under the deployment's `OPENSEAL_LOG_PSEUDONYM_KEY`
//! (32 bytes, base64; `_FILE` accepted), truncated to 128 bits, so the same address
//! gives the same pseudonym in every process sharing the key and correlates attempts,
//! while the log alone cannot be reversed with a dictionary of addresses. Without the
//! key, each process draws its own (correlation then ends at a restart).
//!
//! The crate depends on no other OpenSeal crate but `casual-sign-secrets`, so every
//! host can use it.

use std::borrow::Cow;
use std::fmt::{self, Write as _};
use std::io::Write as _;
use std::sync::{Arc, Mutex};

use aws_lc_rs::hmac;
use serde_json::{Map, Value as Json};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
pub use uuid::Uuid;

#[cfg(feature = "tracing-layer")]
mod layer;
#[cfg(feature = "tracing-layer")]
pub use layer::JsonLayer;

/// The environment variable naming the pseudonym key (32 bytes as base64).
pub const PSEUDONYM_KEY_VAR: &str = "OPENSEAL_LOG_PSEUDONYM_KEY";

/// The process writing a line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Service {
    /// `casual-sign-server`.
    Server,
    /// `casual-sign-worker`.
    Worker,
    /// `casual-sign-keyd`.
    Keyd,
    /// `casual-sign-modeld`.
    Modeld,
    /// `casual-sign-console`.
    Console,
}

impl Service {
    /// The name in the line's `service`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Server => "server",
            Self::Worker => "worker",
            Self::Keyd => "keyd",
            Self::Modeld => "modeld",
            Self::Console => "console",
        }
    }
}

/// A line's severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    /// Detail for a developer.
    Debug,
    /// Normal operation, a successful security event.
    Info,
    /// Something refused or failed that the process survives: a failed security event.
    Warn,
    /// The process cannot do what it is for.
    Error,
}

impl Level {
    /// The name in the line's `level`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Debug => "DEBUG",
            Self::Info => "INFO",
            Self::Warn => "WARN",
            Self::Error => "ERROR",
        }
    }
}

/// The closed taxonomy of security events (docs/07 §Security event log). Each kind
/// names the services that emit it ([`Kind::services`]); the services' tests show
/// every one is emitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Kind {
    /// A staff or operator password sign-in, passed or refused.
    SignIn,
    /// A session ended by its holder.
    SignOut,
    /// A second factor checked (TOTP or recovery code): passed, wrong, or reused.
    Mfa,
    /// A second factor enrolled.
    MfaEnrol,
    /// A password reset asked for (answered alike whether or not the address exists).
    PasswordResetRequest,
    /// A password set through a reset link, or a link refused.
    PasswordReset,
    /// A password changed by its holder, or the current password refused.
    PasswordChange,
    /// An invitation accepted (the first password set), or a link refused.
    InviteAccept,
    /// An OAuth client-credentials token issued or refused.
    Token,
    /// A recipient locked out after too many failed authentications.
    Lockout,
    /// A request without a valid credential (401).
    Unauthenticated,
    /// A request refused for lack of permission, scope, CSRF token, second factor or
    /// binding (403), or a keyd call outside its caller's role.
    Denied,
    /// A request over its rate limit.
    RateLimited,
    /// An upload refused: too large or failing admission.
    UploadRefused,
    /// An administrative change committed (users, groups, profiles, clients, webhooks,
    /// account or organization settings; the console's platform changes).
    AdminChange,
    /// A staff read of a document, combined PDF, certificate, attachment or audit trail.
    DocumentRead,
    /// A signing key used (a signature or a chain asked of keyd), or refused.
    KeyUse,
    /// An mTLS caller refused: a failed handshake or a certificate off the allow list.
    CallerRefused,
    /// A back end (keyd, a time-stamping authority) not reached or refusing.
    BackendFailed,
}

impl Kind {
    /// Every kind.
    pub const ALL: [Self; 19] = [
        Self::SignIn,
        Self::SignOut,
        Self::Mfa,
        Self::MfaEnrol,
        Self::PasswordResetRequest,
        Self::PasswordReset,
        Self::PasswordChange,
        Self::InviteAccept,
        Self::Token,
        Self::Lockout,
        Self::Unauthenticated,
        Self::Denied,
        Self::RateLimited,
        Self::UploadRefused,
        Self::AdminChange,
        Self::DocumentRead,
        Self::KeyUse,
        Self::CallerRefused,
        Self::BackendFailed,
    ];

    /// The name in the line's `kind`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SignIn => "auth.sign_in",
            Self::SignOut => "auth.sign_out",
            Self::Mfa => "auth.mfa",
            Self::MfaEnrol => "auth.mfa_enrol",
            Self::PasswordResetRequest => "auth.password_reset_request",
            Self::PasswordReset => "auth.password_reset",
            Self::PasswordChange => "auth.password_change",
            Self::InviteAccept => "auth.invite_accept",
            Self::Token => "auth.token",
            Self::Lockout => "auth.lockout",
            Self::Unauthenticated => "access.unauthenticated",
            Self::Denied => "access.denied",
            Self::RateLimited => "access.rate_limited",
            Self::UploadRefused => "input.upload_refused",
            Self::AdminChange => "admin.change",
            Self::DocumentRead => "data.document_read",
            Self::KeyUse => "key.use",
            Self::CallerRefused => "transport.caller_refused",
            Self::BackendFailed => "transport.backend_failed",
        }
    }

    /// The services that emit this kind.
    #[must_use]
    pub const fn services(self) -> &'static [Service] {
        use Service::{Console, Keyd, Modeld, Server, Worker};
        match self {
            Self::SignIn | Self::SignOut | Self::Mfa | Self::MfaEnrol | Self::AdminChange => {
                &[Server, Console]
            }
            Self::Unauthenticated => &[Server, Console],
            Self::Denied | Self::RateLimited => &[Server, Console, Keyd],
            Self::PasswordResetRequest
            | Self::PasswordReset
            | Self::PasswordChange
            | Self::InviteAccept
            | Self::Token
            | Self::Lockout
            | Self::UploadRefused
            | Self::DocumentRead => &[Server],
            Self::KeyUse => &[Keyd],
            Self::CallerRefused => &[Keyd, Modeld],
            Self::BackendFailed => &[Worker],
        }
    }

    /// The kinds `service` emits.
    #[must_use]
    pub fn emitted_by(service: Service) -> Vec<Self> {
        Self::ALL
            .into_iter()
            .filter(|k| k.services().contains(&service))
            .collect()
    }
}

/// Whether the act succeeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Passed, done.
    Success,
    /// Refused or failed.
    Failure,
}

impl Outcome {
    /// The name in the line's `outcome`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failure => "failure",
        }
    }
}

/// A keyed pseudonym of an identifier a caller presented but that names no known
/// principal yet: `p1:` and 32 hex digits.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Pseudonym(String);

impl Pseudonym {
    /// The text in a line.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// What a pseudonym is of: the same value in two domains gives two pseudonyms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Domain {
    /// An e-mail address (normalised by the caller: trimmed, lower case).
    Email,
    /// A client network address.
    Ip,
    /// Any other presented identifier (a client id that did not parse).
    Identifier,
}

impl Domain {
    const fn tag(self) -> &'static [u8] {
        match self {
            Self::Email => b"email",
            Self::Ip => b"ip",
            Self::Identifier => b"identifier",
        }
    }
}

/// A name that cannot be personal data or prose: `[A-Za-z0-9._-]{1,64}` (a key alias,
/// a certificate fingerprint, an allow-list name, a back end's index).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Label(String);

impl Label {
    /// `s`, when it has the shape; `None` otherwise.
    #[must_use]
    pub fn new(s: &str) -> Option<Self> {
        let ok = !s.is_empty()
            && s.len() <= 64
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
        ok.then(|| Self(s.to_owned()))
    }

    /// The text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Who acted, as far as the event knows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Principal {
    /// A staff user.
    User(Uuid),
    /// An API client (key or OAuth app).
    Client(Uuid),
    /// A platform operator (console).
    Operator(Uuid),
    /// An envelope recipient.
    Recipient(Uuid),
    /// An mTLS caller, by certificate fingerprint or allow-list name.
    Caller(Label),
    /// An identifier presented but not (or not yet) a known principal: a submitted
    /// e-mail, a client id that matched nothing.
    Subject(Pseudonym),
}

impl Principal {
    fn text(&self) -> String {
        match self {
            Self::User(u) => format!("user:{u}"),
            Self::Client(c) => format!("client:{c}"),
            Self::Operator(o) => format!("operator:{o}"),
            Self::Recipient(r) => format!("recipient:{r}"),
            Self::Caller(l) => format!("caller:{}", l.as_str()),
            Self::Subject(p) => format!("subject:{}", p.as_str()),
        }
    }
}

/// An event's extra field. No variant holds text from a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    /// An id.
    Id(Uuid),
    /// Several ids (the objects a request named).
    Ids(Vec<Uuid>),
    /// A fixed word from the code (`totp`, `keyd`, `password`).
    Word(&'static str),
    /// A count.
    Count(u64),
    /// A pseudonym.
    Pseudonym(Pseudonym),
    /// A label.
    Label(Label),
}

impl Value {
    fn json(&self) -> Json {
        match self {
            Self::Id(u) => Json::String(u.to_string()),
            Self::Ids(v) => Json::Array(v.iter().map(|u| Json::String(u.to_string())).collect()),
            Self::Word(w) => Json::String((*w).to_owned()),
            Self::Count(n) => Json::from(*n),
            Self::Pseudonym(p) => Json::String(p.as_str().to_owned()),
            Self::Label(l) => Json::String(l.as_str().to_owned()),
        }
    }
}

/// Keys every security line has or may have; [`SecurityEvent::with`] drops a field
/// that would overwrite one.
const RESERVED: &[&str] = &[
    "ts",
    "level",
    "service",
    "event",
    "kind",
    "outcome",
    "request_id",
    "principal",
    "account_id",
    "client",
    "code",
    "route",
];

/// One security event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityEvent {
    kind: Kind,
    outcome: Outcome,
    request_id: Option<Uuid>,
    principal: Option<Principal>,
    account: Option<Uuid>,
    client: Option<Pseudonym>,
    code: Option<&'static str>,
    route: Option<Cow<'static, str>>,
    fields: Vec<(&'static str, Value)>,
}

impl SecurityEvent {
    /// A `kind` event with `outcome`.
    #[must_use]
    pub const fn new(kind: Kind, outcome: Outcome) -> Self {
        Self {
            kind,
            outcome,
            request_id: None,
            principal: None,
            account: None,
            client: None,
            code: None,
            route: None,
            fields: Vec::new(),
        }
    }

    /// The kind.
    #[must_use]
    pub const fn kind(&self) -> Kind {
        self.kind
    }

    /// The outcome.
    #[must_use]
    pub const fn outcome(&self) -> Outcome {
        self.outcome
    }

    /// The request it answers.
    #[must_use]
    pub fn request(mut self, id: Uuid) -> Self {
        self.request_id = Some(id);
        self
    }

    /// Who acted.
    #[must_use]
    pub fn principal(mut self, p: Principal) -> Self {
        self.principal = Some(p);
        self
    }

    /// Who acted, unless the event already names someone.
    #[must_use]
    pub fn principal_if_none(mut self, p: Principal) -> Self {
        if self.principal.is_none() {
            self.principal = Some(p);
        }
        self
    }

    /// The account, unless the event already names one.
    #[must_use]
    pub fn account_if_none(mut self, id: Uuid) -> Self {
        if self.account.is_none() {
            self.account = Some(id);
        }
        self
    }

    /// The account (workspace) it happened in.
    #[must_use]
    pub fn account(mut self, id: Uuid) -> Self {
        self.account = Some(id);
        self
    }

    /// The client address, pseudonymised.
    #[must_use]
    pub fn client(mut self, p: Pseudonym) -> Self {
        self.client = Some(p);
        self
    }

    /// The refusal's code (docs/20).
    #[must_use]
    pub fn code(mut self, code: &'static str) -> Self {
        self.code = Some(code);
        self
    }

    /// The route template the router matched (never the path: ceremony paths carry
    /// tokens).
    #[must_use]
    pub fn route(mut self, template: impl Into<Cow<'static, str>>) -> Self {
        self.route = Some(template.into());
        self
    }

    /// An extra field; one named like a fixed field is dropped.
    #[must_use]
    pub fn with(mut self, key: &'static str, value: Value) -> Self {
        if !RESERVED.contains(&key) {
            self.fields.push((key, value));
        }
        self
    }

    /// The line for `service`, time-stamped `at`.
    #[must_use]
    pub fn line(&self, service: Service, at: OffsetDateTime) -> String {
        let mut m = Map::new();
        if let Some(r) = self.request_id {
            m.insert("request_id".into(), Json::String(r.to_string()));
        }
        if let Some(p) = &self.principal {
            m.insert("principal".into(), Json::String(p.text()));
        }
        if let Some(a) = self.account {
            m.insert("account_id".into(), Json::String(a.to_string()));
        }
        if let Some(c) = &self.client {
            m.insert("client".into(), Json::String(c.as_str().to_owned()));
        }
        if let Some(c) = self.code {
            m.insert("code".into(), Json::from(c));
        }
        if let Some(r) = &self.route {
            m.insert("route".into(), Json::from(r.as_ref()));
        }
        for (k, v) in &self.fields {
            m.insert((*k).to_owned(), v.json());
        }
        let level = match self.outcome {
            Outcome::Success => Level::Info,
            Outcome::Failure => Level::Warn,
        };
        let lead = [
            ("kind", Json::from(self.kind.as_str())),
            ("outcome", Json::from(self.outcome.as_str())),
        ];
        line_at(at, service, level, "security", &lead, &m)
    }
}

/// One line: `ts`, `level`, `service` and `event` first, then `fields` (a field named
/// like one of the four is dropped). Callers put ids, kinds, counts and codes in
/// `fields`, never personal data or document content (`SEC-D01`).
#[must_use]
pub fn line(service: Service, level: Level, event: &str, fields: Map<String, Json>) -> String {
    line_at(
        OffsetDateTime::now_utc(),
        service,
        level,
        event,
        &[],
        &fields,
    )
}

fn line_at(
    at: OffsetDateTime,
    service: Service,
    level: Level,
    event: &str,
    lead: &[(&str, Json)],
    fields: &Map<String, Json>,
) -> String {
    // The four fixed fields first, so a line reads from its time and kind; then the
    // rest in key order (serde_json's map is sorted).
    let fixed = [
        ("ts", Json::String(at.format(&Rfc3339).unwrap_or_default())),
        ("level", Json::from(level.as_str())),
        ("service", Json::from(service.as_str())),
        ("event", Json::from(event)),
    ];
    let mut out = String::from("{");
    let mut push = |k: &str, v: &Json| {
        if out.len() > 1 {
            out.push(',');
        }
        out.push_str(&Json::from(k).to_string());
        out.push(':');
        out.push_str(&v.to_string());
    };
    for (k, v) in fixed.iter().chain(lead) {
        push(k, v);
    }
    for (k, v) in fields {
        if !fixed.iter().chain(lead).any(|(f, _)| f == k) {
            push(k, v);
        }
    }
    out.push('}');
    out
}

/// Write [`line()`] to standard error.
pub fn write(service: Service, level: Level, event: &str, fields: Map<String, Json>) {
    Stderr.write_line(&line(service, level, event, fields));
}

/// [`write()`] with string fields, for a host's own lines (`start_failed`, a development
/// key in use): ids, codes, setting names and fixed words only (`SEC-D01`).
pub fn write_strs(service: Service, level: Level, event: &str, fields: &[(&str, &str)]) {
    let m = fields
        .iter()
        .map(|(k, v)| ((*k).to_owned(), Json::from(*v)))
        .collect();
    write(service, level, event, m);
}

/// The `start_failed` line of a host that does not start (`ERROR`): `what` as `error`
/// (a setting name, a fixed word, a code; never a secret's value) and, when `what`
/// names a docs/20 code, that code as `code` too, so an alert keyed on `code` sees
/// every failure that has one (docs/65 §Logs).
pub fn start_failed(service: Service, what: &str) {
    let mut fields = Vec::with_capacity(2);
    if let Some(c) = code_in(what) {
        fields.push(("code", c));
    }
    fields.push(("error", what));
    write_strs(service, Level::Error, "start_failed", &fields);
}

/// The first docs/20 code in `text` (`CS-`, two to four capitals, `-`, four digits, not
/// inside a longer word), if any.
#[must_use]
pub fn code_in(text: &str) -> Option<&str> {
    let b = text.as_bytes();
    let mut from = 0;
    while let Some(off) = text.get(from..).and_then(|t| t.find("CS-")) {
        let at = from.saturating_add(off);
        from = at.saturating_add(3);
        let before_ok = at == 0
            || b.get(at.wrapping_sub(1))
                .is_some_and(|c| !c.is_ascii_alphanumeric());
        let rest = b.get(at.saturating_add(3)..).unwrap_or_default();
        let caps = rest.iter().take_while(|c| c.is_ascii_uppercase()).count();
        let tail = rest.get(caps..).unwrap_or_default();
        let digits = tail
            .get(1..)
            .unwrap_or_default()
            .iter()
            .take_while(|c| c.is_ascii_digit())
            .count();
        let after = tail.get(1usize.saturating_add(digits));
        if before_ok
            && (2..=4).contains(&caps)
            && tail.first() == Some(&b'-')
            && digits == 4
            && after.is_none_or(|c| !c.is_ascii_alphanumeric())
        {
            let len = caps.saturating_add(8); // "CS-", the capitals, "-", four digits
            return text.get(at..at.saturating_add(len));
        }
    }
    None
}

/// Where lines go.
pub trait Sink: Send + Sync + fmt::Debug {
    /// Write one line (no newline). Failures are swallowed: a log never fails a request.
    fn write_line(&self, line: &str);
}

/// Standard error, one `write` per line so lines from threads do not interleave.
#[derive(Debug, Clone, Copy, Default)]
pub struct Stderr;

impl Sink for Stderr {
    fn write_line(&self, line: &str) {
        let mut buf = Vec::with_capacity(line.len().saturating_add(1));
        buf.extend_from_slice(line.as_bytes());
        buf.push(b'\n');
        let _ = std::io::stderr().lock().write_all(&buf);
    }
}

/// Lines kept in memory: for tests, and for an embedder that forwards them itself.
#[derive(Debug, Clone, Default)]
pub struct Memory(Arc<Mutex<Vec<String>>>);

impl Memory {
    /// An empty sink.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Every line written so far.
    #[must_use]
    pub fn lines(&self) -> Vec<String> {
        self.0.lock().map(|l| l.clone()).unwrap_or_default()
    }

    /// Every line, parsed.
    #[must_use]
    pub fn json(&self) -> Vec<Json> {
        self.lines()
            .iter()
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect()
    }
}

impl Sink for Memory {
    fn write_line(&self, line: &str) {
        if let Ok(mut l) = self.0.lock() {
            l.push(line.to_owned());
        }
    }
}

/// The pseudonym key could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SeclogError {
    /// `OPENSEAL_LOG_PSEUDONYM_KEY` (or its file) is not 32 bytes as base64, or both
    /// forms are set, or randomness failed.
    Key,
}

impl SeclogError {
    /// The stable code (docs/20).
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Key => "CS-LOG-0001",
        }
    }
}

impl fmt::Display for SeclogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Key => write!(
                f,
                "{}: {PSEUDONYM_KEY_VAR} is not 32 bytes as base64",
                self.code()
            ),
        }
    }
}

impl std::error::Error for SeclogError {}

/// Makes [`Pseudonym`]s under one key.
pub struct Pseudonymizer {
    key: hmac::Key,
    from_env: bool,
}

impl fmt::Debug for Pseudonymizer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Pseudonymizer")
            .field("from_env", &self.from_env)
            .finish_non_exhaustive()
    }
}

impl Pseudonymizer {
    /// Pseudonyms under `key`.
    #[must_use]
    pub fn new(key: &[u8; 32]) -> Self {
        Self {
            key: hmac::Key::new(hmac::HMAC_SHA256, key),
            from_env: false,
        }
    }

    /// Pseudonyms under a key drawn now (they correlate only within this process).
    ///
    /// # Errors
    /// `CS-LOG-0001` when randomness fails.
    pub fn random() -> Result<Self, SeclogError> {
        let mut k = [0u8; 32];
        aws_lc_rs::rand::fill(&mut k).map_err(|_| SeclogError::Key)?;
        Ok(Self::new(&k))
    }

    /// The key in `OPENSEAL_LOG_PSEUDONYM_KEY` (or the file `_FILE` names), else a
    /// random one.
    ///
    /// # Errors
    /// `CS-LOG-0001` when the variable is set but is not 32 bytes as base64.
    pub fn from_env() -> Result<Self, SeclogError> {
        use base64::Engine as _;
        match casual_sign_secrets::env_secret(PSEUDONYM_KEY_VAR).map_err(|_| SeclogError::Key)? {
            Some(s) => {
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(s.expose().trim())
                    .map_err(|_| SeclogError::Key)?;
                let key: [u8; 32] = bytes.try_into().map_err(|_| SeclogError::Key)?;
                Ok(Self {
                    from_env: true,
                    ..Self::new(&key)
                })
            }
            None => Self::random(),
        }
    }

    /// Whether the key came from the environment (pseudonyms survive a restart and
    /// match across processes).
    #[must_use]
    pub const fn from_environment(&self) -> bool {
        self.from_env
    }

    /// The pseudonym of `value` in `domain`.
    #[must_use]
    pub fn of(&self, domain: Domain, value: &[u8]) -> Pseudonym {
        let mut ctx = hmac::Context::with_key(&self.key);
        ctx.update(domain.tag());
        ctx.update(&[0]);
        ctx.update(value);
        let tag = ctx.sign();
        let mut s = String::from("p1:");
        for b in tag.as_ref().iter().take(16) {
            let _ = write!(s, "{b:02x}");
        }
        Pseudonym(s)
    }
}

/// A process's security log: its service name, sink and pseudonym key.
#[derive(Debug, Clone)]
pub struct SecurityLog {
    service: Service,
    sink: Arc<dyn Sink>,
    pseudonyms: Arc<Pseudonymizer>,
}

impl SecurityLog {
    /// A log for `service` writing to `sink`.
    #[must_use]
    pub fn new(service: Service, sink: Arc<dyn Sink>, pseudonyms: Pseudonymizer) -> Self {
        Self {
            service,
            sink,
            pseudonyms: Arc::new(pseudonyms),
        }
    }

    /// A log for `service` on standard error with the environment's key (a random one
    /// when unset or unreadable: a log never stops the process; the unreadable key is
    /// reported once as a `log_key_unreadable` line).
    #[must_use]
    pub fn from_env(service: Service) -> Self {
        let pseudonyms = match Pseudonymizer::from_env() {
            Ok(p) => Some(p),
            Err(e) => {
                let mut m = Map::new();
                m.insert("code".into(), Json::from(e.code()));
                write(service, Level::Error, "log_key_unreadable", m);
                Pseudonymizer::random().ok()
            }
        };
        let pseudonyms = pseudonyms.unwrap_or_else(|| Pseudonymizer::new(&[0; 32]));
        Self::new(service, Arc::new(Stderr), pseudonyms)
    }

    /// A log for `service` keeping its lines in the returned [`Memory`] (tests).
    #[must_use]
    pub fn memory(service: Service) -> (Self, Memory) {
        let m = Memory::new();
        (
            Self::new(service, Arc::new(m.clone()), Pseudonymizer::new(&[7; 32])),
            m,
        )
    }

    /// The service.
    #[must_use]
    pub const fn service(&self) -> Service {
        self.service
    }

    /// The pseudonym of `value` in `domain` under this log's key.
    #[must_use]
    pub fn pseudonym(&self, domain: Domain, value: &[u8]) -> Pseudonym {
        self.pseudonyms.of(domain, value)
    }

    /// Write `event`.
    pub fn emit(&self, event: &SecurityEvent) {
        self.sink
            .write_line(&event.line(self.service, OffsetDateTime::now_utc()));
    }

    /// Write a plain line through this log's sink (`fields`: ids, kinds, counts, codes).
    pub fn info(&self, level: Level, event: &str, fields: Map<String, Json>) {
        self.sink
            .write_line(&line(self.service, level, event, fields));
    }
}

#[cfg(test)]
mod tests {
    // Test code: a panic is the failure report.
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;

    #[test]
    fn a_docs20_code_is_found_in_a_startup_failure_wherever_it_stands() {
        assert_eq!(code_in("CS-DB-0012"), Some("CS-DB-0012"));
        assert_eq!(
            code_in("OPENSEAL_CONSOLE_MFA_KEY is not set (CS-CON-0017)"),
            Some("CS-CON-0017")
        );
        assert_eq!(
            code_in("OPENSEAL_BLOB_DIR: CS-BLOB-0003"),
            Some("CS-BLOB-0003")
        );
        assert_eq!(
            code_in("XCS-DB-0012 then CS-AUTH-0001."),
            Some("CS-AUTH-0001")
        );
        for none in [
            "",
            "OPENSEAL_DATABASE_URL is not set",
            "CS-",
            "CS-D-0001",
            "CS-TOOLONG-0001",
            "CS-DB-001",
            "CS-DB-00123",
            "CS-db-0012",
            "CS-DB-0012x",
            "é CS-DB",
        ] {
            assert_eq!(code_in(none), None, "{none}");
        }
    }

    #[test]
    fn a_security_line_has_the_fixed_fields_first_and_no_free_text_field() {
        let p = Pseudonymizer::new(&[1; 32]);
        let ev = SecurityEvent::new(Kind::SignIn, Outcome::Failure)
            .request(Uuid::nil())
            .principal(Principal::Subject(p.of(Domain::Email, b"ada@example.test")))
            .client(p.of(Domain::Ip, b"198.51.100.7"))
            .code("CS-AUTH-0007")
            .route("/api/v1/auth/login")
            .with("via", Value::Word("password"))
            .with("kind", Value::Word("overwritten"));
        let at = OffsetDateTime::from_unix_timestamp(1_794_391_200).unwrap();
        let line = ev.line(Service::Server, at);
        assert!(
            line.starts_with(
                r#"{"ts":"2026-11-11T10:00:00Z","level":"WARN","service":"server","event":"security","kind":"auth.sign_in","outcome":"failure""#
            ),
            "{line}"
        );
        assert!(!line.contains("ada@example.test"), "{line}");
        assert!(!line.contains("198.51.100.7"), "{line}");
        assert!(!line.contains("overwritten"), "{line}");
        let j: Json = serde_json::from_str(&line).unwrap();
        assert_eq!(
            j["principal"].as_str().unwrap().len(),
            "subject:p1:".len() + 32
        );
        assert_eq!(j["via"], "password");
    }

    #[test]
    fn pseudonyms_are_keyed_and_domain_separated() {
        let a = Pseudonymizer::new(&[1; 32]);
        let b = Pseudonymizer::new(&[2; 32]);
        let v = b"ada@example.test";
        assert_eq!(a.of(Domain::Email, v), a.of(Domain::Email, v));
        assert_ne!(a.of(Domain::Email, v), b.of(Domain::Email, v));
        assert_ne!(a.of(Domain::Email, v), a.of(Domain::Identifier, v));
        // Not the unkeyed SHA-256 of the value (a dictionary would reverse that).
        let plain = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, v);
        let plain_hex: String = plain.as_ref()[..16]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_ne!(a.of(Domain::Email, v).as_str(), format!("p1:{plain_hex}"));
    }

    #[test]
    fn a_label_refuses_addresses_and_prose() {
        assert!(Label::new("platform").is_some());
        assert!(Label::new(&"a".repeat(64)).is_some());
        for bad in [
            "",
            "ada@example.test",
            "two words",
            "198.51.100.7:80",
            "a/b",
        ] {
            assert!(Label::new(bad).is_none(), "{bad}");
        }
        assert!(Label::new(&"a".repeat(65)).is_none());
    }

    #[test]
    fn every_kind_is_emitted_by_some_service_and_named_once() {
        let mut names: Vec<&str> = Kind::ALL.iter().map(|k| k.as_str()).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), Kind::ALL.len());
        for k in Kind::ALL {
            assert!(!k.services().is_empty(), "{k:?}");
        }
    }

    #[test]
    fn a_plain_line_cannot_overwrite_the_fixed_fields() {
        let mut m = Map::new();
        m.insert("service".into(), Json::from("forged"));
        m.insert("job".into(), Json::from("x"));
        let l = line(Service::Worker, Level::Info, "started", m);
        let j: Json = serde_json::from_str(&l).unwrap();
        assert_eq!(j["service"], "worker");
        assert_eq!(j["job"], "x");
    }
}
