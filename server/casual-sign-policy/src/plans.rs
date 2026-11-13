//! Plans: entitlements, quotas, overrides and the effective plan (docs/23 §7.1).
//!
//! A plan version is immutable. An organization has a timeline of assignments, each
//! current on the half-open interval `[starts_at, ends_at)`, so at the instant one ends
//! the next is current and never both. Overrides change one entitlement, one quota's
//! limit or enforcement, or the seat rule, until their expiry instant (exclusive). The
//! effective plan is the assignment current at `now` with the live overrides applied;
//! organization allocations to workspaces join it with `PLAN-07`.
//!
//! A plan may not set `hard` enforcement on an approximate meter (`api_calls`, counted in
//! memory and flushed each minute, docs/23 §7.2): validation answers `CS-PLAN-0006`, and so
//! does the database (SQLSTATE `OS010`).

use std::collections::BTreeMap;

use serde::Deserialize;
use time::OffsetDateTime;
use uuid::Uuid;

/// The code of every plan validation error (docs/20).
pub const PLAN_INVALID: &str = "CS-PLAN-0006";

/// Largest quota limit: the database stores it as `bigint`.
pub const MAX_LIMIT: u64 = i64::MAX as u64;

/// Most quotas one plan may carry (every meter at both levels is fewer).
pub const MAX_QUOTAS: usize = 64;

macro_rules! names {
    ($(#[$m:meta])* $ty:ident { $($(#[$vm:meta])* $v:ident = $s:literal),+ $(,)? }) => {
        $(#[$m])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub enum $ty {
            $($(#[$vm])* $v),+
        }

        impl $ty {
            /// Every value, in declaration order.
            pub const ALL: &'static [$ty] = &[$($ty::$v),+];

            /// The stored name.
            #[must_use]
            pub fn as_str(self) -> &'static str {
                match self {
                    $($ty::$v => $s),+
                }
            }

            /// The value named `s`.
            #[must_use]
            pub fn parse(s: &str) -> Option<Self> {
                match s {
                    $($s => Some($ty::$v),)+
                    _ => None,
                }
            }
        }
    };
}

names! {
    /// A feature a plan enables or not (docs/23 §7.1). Absent from a plan means disabled.
    Feature {
        /// Bulk send.
        BulkSend = "bulk_send",
        /// SAML single sign-on.
        SsoSaml = "sso_saml",
        /// SCIM provisioning.
        Scim = "scim",
        /// The `/api/v1` client-credential API.
        Api = "api",
        /// Webhooks.
        Webhooks = "webhooks",
        /// SMS recipient authentication.
        SmsAuth = "sms_auth",
        /// Conditional routing.
        ConditionalRouting = "conditional_routing",
        /// Payments.
        Payments = "payments",
        /// More than one brand.
        BrandingMulti = "branding_multi",
        /// B-LTA sealing.
        SealBLta = "seal_b_lta",
        /// Model suggestions (ADR-029).
        MlSuggestions = "ml_suggestions",
    }
}

names! {
    /// What is metered (docs/23 §7.2).
    Meter {
        /// Envelopes sent.
        EnvelopesSent = "envelopes_sent",
        /// Seats (a gauge).
        Seats = "seats",
        /// Stored bytes (a gauge).
        StorageBytes = "storage_bytes",
        /// API calls: approximate, so never `hard`.
        ApiCalls = "api_calls",
        /// SMS messages sent.
        SmsSent = "sms_sent",
        /// Phone calls.
        PhoneCalls = "phone_calls",
        /// Identity-document checks.
        IdvChecks = "idv_checks",
        /// Knowledge-based checks.
        KbaChecks = "kba_checks",
        /// Timestamps.
        Timestamps = "timestamps",
        /// Seals.
        Seals = "seals",
        /// Bulk-send rows.
        BulkSendRows = "bulk_send_rows",
        /// Signing-link submissions.
        SigningLinkSubmissions = "signing_link_submissions",
        /// Webhook deliveries.
        WebhookDeliveries = "webhook_deliveries",
        /// Workspaces (a gauge, organization level only).
        Workspaces = "workspaces",
        /// Templates (a gauge).
        Templates = "templates",
    }
}

/// Whether a meter counts events in a period or measures a current amount.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeterKind {
    /// Counts events in a period.
    Counter,
    /// Measures what exists now.
    Gauge,
}

impl Meter {
    /// Counter or gauge (docs/23 §7.2).
    #[must_use]
    pub fn kind(self) -> MeterKind {
        match self {
            Self::Seats | Self::StorageBytes | Self::Workspaces | Self::Templates => {
                MeterKind::Gauge
            }
            _ => MeterKind::Counter,
        }
    }

    /// Whether the count is approximate (kept in memory and flushed), so that a quota on
    /// it may only be `soft` or `notify`.
    #[must_use]
    pub fn is_approximate(self) -> bool {
        matches!(self, Self::ApiCalls)
    }
}

names! {
    /// A quota's period.
    Period {
        /// Calendar month (UTC).
        Month = "month",
        /// Calendar year (UTC).
        Year = "year",
        /// No period: a standing limit (every gauge).
        None = "none",
    }
}

names! {
    /// What reaching a quota does (docs/23 Q7).
    Enforcement {
        /// Refuse the action.
        Hard = "hard",
        /// Allow, record the overage, notify the organization's admins.
        Soft = "soft",
        /// Only notify.
        Notify = "notify",
    }
}

names! {
    /// Where a quota is counted.
    Level {
        /// Across the organization's workspaces.
        Organization = "organization",
        /// In each workspace.
        Workspace = "workspace",
    }
}

names! {
    /// What a seat is (docs/23 Q6).
    SeatRule {
        /// Enabled members whose profile can send (the default).
        CanSend = "can_send",
        /// Every enabled member.
        EveryMember = "every_member",
    }
}

/// One quota of a plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Quota {
    /// The meter.
    pub meter: Meter,
    /// The limit, at most [`MAX_LIMIT`].
    pub limit: u64,
    /// The period.
    pub period: Period,
    /// What reaching it does.
    pub enforcement: Enforcement,
    /// Where it is counted.
    pub level: Level,
}

/// A plan as an operator submits it, before it gets an id and a version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanDraft {
    /// The plan family's key (`[a-z][a-z0-9_-]{0,63}`); each submission is its next
    /// version.
    pub key: String,
    /// Display name, 1 to 120 characters.
    pub name: String,
    /// Features this plan sets; any feature not named is disabled.
    pub entitlements: BTreeMap<Feature, bool>,
    /// Quotas, at most one per meter and level.
    pub quotas: Vec<Quota>,
    /// What a seat is.
    pub seat_rule: SeatRule,
}

/// Why a plan, quota or override is invalid. Every variant is `CS-PLAN-0006`; messages
/// name codes, meters and levels only.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PlanError {
    /// The key is not `[a-z][a-z0-9_-]{0,63}`.
    Key,
    /// The name is empty, longer than 120 characters, or holds a control character.
    Name,
    /// `hard` enforcement on an approximate meter.
    HardOnApproximate {
        /// The meter.
        meter: Meter,
    },
    /// Two quotas for one meter and level.
    DuplicateQuota {
        /// The meter.
        meter: Meter,
        /// The level.
        level: Level,
    },
    /// A gauge with a period other than `none`.
    GaugeWithPeriod {
        /// The meter.
        meter: Meter,
    },
    /// A meter counted at a level it has no meaning at (`workspaces` per workspace).
    LevelNotAllowed {
        /// The meter.
        meter: Meter,
    },
    /// A limit above [`MAX_LIMIT`].
    LimitTooLarge {
        /// The meter.
        meter: Meter,
    },
    /// More than [`MAX_QUOTAS`] quotas.
    TooManyQuotas,
    /// A name that is not a feature, meter, period, enforcement, level or seat rule.
    UnknownName {
        /// Which field.
        field: &'static str,
    },
    /// An override key outside the grammar.
    OverrideKey,
    /// An override value that does not fit its key.
    OverrideValue,
    /// A workspace override of anything but a workspace-level quota.
    OverrideScope,
    /// An override or assignment interval that ends at or before it starts, or an
    /// override that has already expired.
    Interval,
}

impl PlanError {
    /// The stable code (docs/20).
    #[must_use]
    pub fn code(&self) -> &'static str {
        PLAN_INVALID
    }

    /// The request field the error is about.
    #[must_use]
    pub fn field(&self) -> &'static str {
        match self {
            Self::Key => "key",
            Self::Name => "name",
            Self::HardOnApproximate { .. }
            | Self::DuplicateQuota { .. }
            | Self::GaugeWithPeriod { .. }
            | Self::LevelNotAllowed { .. }
            | Self::LimitTooLarge { .. }
            | Self::TooManyQuotas => "quotas",
            Self::UnknownName { field } => field,
            Self::OverrideKey => "key",
            Self::OverrideValue => "value",
            Self::OverrideScope => "workspace",
            Self::Interval => "expires_at",
        }
    }
}

impl core::fmt::Display for PlanError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let code = self.code();
        match self {
            Self::HardOnApproximate { meter } => {
                write!(f, "{code}: `hard` on approximate meter {}", meter.as_str())
            }
            Self::DuplicateQuota { meter, level } => write!(
                f,
                "{code}: two quotas for {} at {} level",
                meter.as_str(),
                level.as_str()
            ),
            Self::GaugeWithPeriod { meter } => {
                write!(f, "{code}: gauge {} takes period none", meter.as_str())
            }
            Self::LevelNotAllowed { meter } => {
                write!(f, "{code}: {} is counted per organization", meter.as_str())
            }
            Self::LimitTooLarge { meter } => {
                write!(f, "{code}: limit of {} too large", meter.as_str())
            }
            other => write!(f, "{code}: invalid {}", other.field()),
        }
    }
}

impl std::error::Error for PlanError {}

/// Whether `key` is a plan key.
#[must_use]
pub fn is_plan_key(key: &str) -> bool {
    let mut bytes = key.bytes();
    key.len() <= 64
        && bytes.next().is_some_and(|b| b.is_ascii_lowercase())
        && bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}

/// Check a quota on its own.
///
/// # Errors
/// `CS-PLAN-0006` ([`PlanError`]) for `hard` on an approximate meter, a gauge with a
/// period, `workspaces` per workspace, or a limit above [`MAX_LIMIT`].
pub fn validate_quota(q: &Quota) -> Result<(), PlanError> {
    let meter = q.meter;
    if q.enforcement == Enforcement::Hard && meter.is_approximate() {
        return Err(PlanError::HardOnApproximate { meter });
    }
    if meter.kind() == MeterKind::Gauge && q.period != Period::None {
        return Err(PlanError::GaugeWithPeriod { meter });
    }
    if meter == Meter::Workspaces && q.level == Level::Workspace {
        return Err(PlanError::LevelNotAllowed { meter });
    }
    if q.limit > MAX_LIMIT {
        return Err(PlanError::LimitTooLarge { meter });
    }
    Ok(())
}

/// Check a plan before it is stored (the database checks the same rules again).
///
/// # Errors
/// `CS-PLAN-0006` ([`PlanError`]): a bad key or name, too many or duplicate quotas, or any
/// quota [`validate_quota`] refuses.
pub fn validate_plan(plan: &PlanDraft) -> Result<(), PlanError> {
    if !is_plan_key(&plan.key) {
        return Err(PlanError::Key);
    }
    let name = plan.name.trim();
    if name.is_empty() || name.chars().count() > 120 || name.chars().any(char::is_control) {
        return Err(PlanError::Name);
    }
    if plan.quotas.len() > MAX_QUOTAS {
        return Err(PlanError::TooManyQuotas);
    }
    let mut seen = std::collections::BTreeSet::new();
    for q in &plan.quotas {
        validate_quota(q)?;
        if !seen.insert((q.meter, q.level)) {
            return Err(PlanError::DuplicateQuota {
                meter: q.meter,
                level: q.level,
            });
        }
    }
    Ok(())
}

/// What an override changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum OverrideKey {
    /// `feature.<feature>`: enable or disable a feature.
    Feature(Feature),
    /// `quota.<meter>.<level>.limit`: a quota's limit.
    QuotaLimit(Meter, Level),
    /// `quota.<meter>.<level>.enforcement`: a quota's enforcement.
    QuotaEnforcement(Meter, Level),
    /// `seat_rule`: what a seat is.
    SeatRule,
}

impl OverrideKey {
    /// Parse the stored key.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        if s == "seat_rule" {
            return Some(Self::SeatRule);
        }
        if let Some(f) = s.strip_prefix("feature.") {
            return Feature::parse(f).map(Self::Feature);
        }
        let rest = s.strip_prefix("quota.")?;
        let mut parts = rest.split('.');
        let meter = Meter::parse(parts.next()?)?;
        let level = Level::parse(parts.next()?)?;
        let what = parts.next()?;
        if parts.next().is_some() {
            return None;
        }
        match what {
            "limit" => Some(Self::QuotaLimit(meter, level)),
            "enforcement" => Some(Self::QuotaEnforcement(meter, level)),
            _ => None,
        }
    }

    /// The stored key.
    #[must_use]
    pub fn to_key(self) -> String {
        match self {
            Self::Feature(f) => format!("feature.{}", f.as_str()),
            Self::QuotaLimit(m, l) => format!("quota.{}.{}.limit", m.as_str(), l.as_str()),
            Self::QuotaEnforcement(m, l) => {
                format!("quota.{}.{}.enforcement", m.as_str(), l.as_str())
            }
            Self::SeatRule => "seat_rule".to_owned(),
        }
    }

    /// Whether a workspace override may change it: only a workspace-level quota.
    #[must_use]
    pub fn workspace_scoped(self) -> bool {
        matches!(
            self,
            Self::QuotaLimit(_, Level::Workspace) | Self::QuotaEnforcement(_, Level::Workspace)
        )
    }
}

/// An override's new value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverrideValue {
    /// For a feature.
    Flag(bool),
    /// For a quota's limit.
    Limit(u64),
    /// For a quota's enforcement.
    Enforcement(Enforcement),
    /// For the seat rule.
    SeatRule(SeatRule),
}

impl OverrideValue {
    /// The stored value.
    #[must_use]
    pub fn to_value(self) -> String {
        match self {
            Self::Flag(b) => b.to_string(),
            Self::Limit(n) => n.to_string(),
            Self::Enforcement(e) => e.as_str().to_owned(),
            Self::SeatRule(r) => r.as_str().to_owned(),
        }
    }
}

/// Parse and check an override as stored or submitted: its key, its value for that key,
/// and its scope (`workspace` is `Some` for a workspace override).
///
/// # Errors
/// `CS-PLAN-0006` ([`PlanError`]): a key outside the grammar, a value that does not fit
/// it, `hard` on an approximate meter, or a workspace override of anything but a
/// workspace-level quota.
pub fn parse_override(
    workspace: Option<Uuid>,
    key: &str,
    value: &str,
) -> Result<(OverrideKey, OverrideValue), PlanError> {
    let k = OverrideKey::parse(key).ok_or(PlanError::OverrideKey)?;
    if workspace.is_some() && !k.workspace_scoped() {
        return Err(PlanError::OverrideScope);
    }
    let v = match k {
        OverrideKey::Feature(_) => match value {
            "true" => OverrideValue::Flag(true),
            "false" => OverrideValue::Flag(false),
            _ => return Err(PlanError::OverrideValue),
        },
        OverrideKey::QuotaLimit(meter, _) => {
            // Digits only: no sign, space or exponent.
            if value.is_empty() || value.len() > 19 || !value.bytes().all(|b| b.is_ascii_digit()) {
                return Err(PlanError::OverrideValue);
            }
            let n: u64 = value.parse().map_err(|_| PlanError::OverrideValue)?;
            if n > MAX_LIMIT {
                return Err(PlanError::LimitTooLarge { meter });
            }
            OverrideValue::Limit(n)
        }
        OverrideKey::QuotaEnforcement(meter, _) => {
            let e = Enforcement::parse(value).ok_or(PlanError::OverrideValue)?;
            if e == Enforcement::Hard && meter.is_approximate() {
                return Err(PlanError::HardOnApproximate { meter });
            }
            OverrideValue::Enforcement(e)
        }
        OverrideKey::SeatRule => {
            OverrideValue::SeatRule(SeatRule::parse(value).ok_or(PlanError::OverrideValue)?)
        }
    };
    Ok((k, v))
}

/// A stored plan version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    /// Its id.
    pub id: Uuid,
    /// The family's key.
    pub key: String,
    /// The version within the key, from 1.
    pub version: u32,
    /// Display name.
    pub name: String,
    /// Features set; any other is disabled.
    pub entitlements: BTreeMap<Feature, bool>,
    /// Quotas.
    pub quotas: Vec<Quota>,
    /// What a seat is.
    pub seat_rule: SeatRule,
    /// Archived: no new assignment may name it; current ones continue.
    pub archived: bool,
}

/// One assignment of a plan to an organization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assignment {
    /// Its id.
    pub id: Uuid,
    /// The plan version assigned.
    pub plan: Plan,
    /// First instant it is current.
    pub starts_at: OffsetDateTime,
    /// First instant it is no longer current; `None` for open-ended.
    pub ends_at: Option<OffsetDateTime>,
}

impl Assignment {
    /// Whether it is current at `now`: `starts_at <= now < ends_at`.
    #[must_use]
    pub fn is_current(&self, now: OffsetDateTime) -> bool {
        self.starts_at <= now && self.ends_at.is_none_or(|e| now < e)
    }
}

/// One override.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Override {
    /// Its id.
    pub id: Uuid,
    /// The workspace it is for, or `None` for the whole organization.
    pub workspace: Option<Uuid>,
    /// What it changes.
    pub key: OverrideKey,
    /// The new value.
    pub value: OverrideValue,
    /// First instant it no longer applies; `None` for no expiry.
    pub expires_at: Option<OffsetDateTime>,
    /// When it was set; the later of two overrides of one key and scope wins.
    pub created_at: OffsetDateTime,
    /// Why (the console only; empty for the application).
    pub reason: Option<String>,
    /// The operator who set it (the console only).
    pub operator: Option<Uuid>,
}

impl Override {
    /// Whether it applies at `now`: `now < expires_at`.
    #[must_use]
    pub fn is_live(&self, now: OffsetDateTime) -> bool {
        self.expires_at.is_none_or(|e| now < e)
    }
}

/// An organization's assignments and overrides, as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanInputs {
    /// The organization.
    pub organization: Uuid,
    /// Its assignments (the application's read carries the current one only).
    pub assignments: Vec<Assignment>,
    /// Its overrides (the application's read carries the live ones for its workspace
    /// and the organization only).
    pub overrides: Vec<Override>,
}

/// Stored plan rows that do not read back: the JSON's shape, or a name this build does not
/// know. The store reports it as `CS-DB-0010`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputsError {
    /// What could not be read.
    pub what: &'static str,
}

impl core::fmt::Display for InputsError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "stored plan rows unreadable: {}", self.what)
    }
}

impl std::error::Error for InputsError {}

#[derive(Deserialize)]
struct WireInputs {
    organization: Uuid,
    assignments: Vec<WireAssignment>,
    overrides: Vec<WireOverride>,
}

#[derive(Deserialize)]
struct WireAssignment {
    id: Uuid,
    plan: WirePlan,
    starts_at: i64,
    ends_at: Option<i64>,
}

#[derive(Deserialize)]
struct WirePlan {
    id: Uuid,
    key: String,
    version: u32,
    name: String,
    seat_rule: String,
    entitlements: BTreeMap<String, bool>,
    quotas: Vec<WireQuota>,
    archived: bool,
}

#[derive(Deserialize)]
struct WireQuota {
    meter: String,
    limit: i64,
    period: String,
    enforcement: String,
    level: String,
}

#[derive(Deserialize)]
struct WireOverride {
    id: Uuid,
    workspace: Option<Uuid>,
    key: String,
    value: String,
    expires_at: Option<i64>,
    created_at: i64,
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    operator: Option<Uuid>,
}

/// Microseconds since the Unix epoch, as the database's JSON carries times.
fn from_micros(us: i64) -> Result<OffsetDateTime, InputsError> {
    let bad = InputsError { what: "time" };
    let nanos = i128::from(us).checked_mul(1000).ok_or(bad.clone())?;
    OffsetDateTime::from_unix_timestamp_nanos(nanos).map_err(|_| bad)
}

impl WirePlan {
    fn into_plan(self) -> Result<Plan, InputsError> {
        let mut entitlements = BTreeMap::new();
        for (name, on) in self.entitlements {
            let f = Feature::parse(&name).ok_or(InputsError { what: "feature" })?;
            entitlements.insert(f, on);
        }
        let quotas = self
            .quotas
            .into_iter()
            .map(|q| {
                Ok(Quota {
                    meter: Meter::parse(&q.meter).ok_or(InputsError { what: "meter" })?,
                    limit: u64::try_from(q.limit).map_err(|_| InputsError { what: "limit" })?,
                    period: Period::parse(&q.period).ok_or(InputsError { what: "period" })?,
                    enforcement: Enforcement::parse(&q.enforcement).ok_or(InputsError {
                        what: "enforcement",
                    })?,
                    level: Level::parse(&q.level).ok_or(InputsError { what: "level" })?,
                })
            })
            .collect::<Result<Vec<_>, InputsError>>()?;
        Ok(Plan {
            id: self.id,
            key: self.key,
            version: self.version,
            name: self.name,
            entitlements,
            quotas,
            seat_rule: SeatRule::parse(&self.seat_rule).ok_or(InputsError { what: "seat_rule" })?,
            archived: self.archived,
        })
    }
}

impl Plan {
    /// Read one plan version as `platform.plan_json` writes it.
    ///
    /// # Errors
    /// [`InputsError`] when the shape is wrong or a name is unknown to this build.
    pub fn from_json(v: &serde_json::Value) -> Result<Self, InputsError> {
        WirePlan::deserialize(v)
            .map_err(|_| InputsError { what: "shape" })?
            .into_plan()
    }
}

impl PlanInputs {
    /// Read the JSON `openseal_effective_plan(now)` and `platform.plan_inputs` return.
    ///
    /// # Errors
    /// [`InputsError`] when the shape is wrong or a name is unknown to this build.
    pub fn from_json(v: &serde_json::Value) -> Result<Self, InputsError> {
        let w = WireInputs::deserialize(v).map_err(|_| InputsError { what: "shape" })?;
        let assignments = w
            .assignments
            .into_iter()
            .map(|a| {
                Ok(Assignment {
                    id: a.id,
                    plan: a.plan.into_plan()?,
                    starts_at: from_micros(a.starts_at)?,
                    ends_at: a.ends_at.map(from_micros).transpose()?,
                })
            })
            .collect::<Result<Vec<_>, InputsError>>()?;
        let overrides = w
            .overrides
            .into_iter()
            .map(|o| {
                let (key, value) = parse_override(o.workspace, &o.key, &o.value)
                    .map_err(|_| InputsError { what: "override" })?;
                Ok(Override {
                    id: o.id,
                    workspace: o.workspace,
                    key,
                    value,
                    expires_at: o.expires_at.map(from_micros).transpose()?,
                    created_at: from_micros(o.created_at)?,
                    reason: o.reason,
                    operator: o.operator,
                })
            })
            .collect::<Result<Vec<_>, InputsError>>()?;
        Ok(Self {
            organization: w.organization,
            assignments,
            overrides,
        })
    }
}

/// The plan in force for an organization, or for one of its workspaces, at one instant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectivePlan {
    /// The assignment it comes from.
    pub assignment: Uuid,
    /// The plan version.
    pub plan: Uuid,
    /// The plan's key.
    pub key: String,
    /// The plan's version.
    pub version: u32,
    /// The plan's name.
    pub name: String,
    /// When the assignment started.
    pub starts_at: OffsetDateTime,
    /// When it ends, if scheduled.
    pub ends_at: Option<OffsetDateTime>,
    /// Features after overrides; any feature not named is disabled.
    pub entitlements: BTreeMap<Feature, bool>,
    /// Quotas after overrides.
    pub quotas: Vec<Quota>,
    /// What a seat is, after overrides.
    pub seat_rule: SeatRule,
    /// Overrides applied, in key order.
    pub applied: Vec<Uuid>,
    /// Live overrides that changed nothing: a quota the plan does not have.
    pub ignored: Vec<Uuid>,
}

impl EffectivePlan {
    /// Whether `feature` is enabled (deny by default).
    #[must_use]
    pub fn entitled(&self, feature: Feature) -> bool {
        self.entitlements.get(&feature).copied().unwrap_or(false)
    }

    /// The quota on `meter` at `level`, if the plan sets one (none means unlimited).
    #[must_use]
    pub fn quota(&self, meter: Meter, level: Level) -> Option<&Quota> {
        self.quotas
            .iter()
            .find(|q| q.meter == meter && q.level == level)
    }
}

/// The effective plan at `now` for the organization (`workspace` `None`) or one of its
/// workspaces: the assignment current at `now` (the latest-starting one, should two
/// overlap), with every live override applied. For each key, a workspace override beats
/// an organization one, then the later `created_at` (then the larger id) wins. `None`
/// when no assignment is current: what that allows is the enforcement's to decide
/// (`PLAN-04`).
#[must_use]
pub fn effective(
    inputs: &PlanInputs,
    workspace: Option<Uuid>,
    now: OffsetDateTime,
) -> Option<EffectivePlan> {
    let a = inputs
        .assignments
        .iter()
        .filter(|a| a.is_current(now))
        .max_by_key(|a| (a.starts_at, a.id))?;
    let mut out = EffectivePlan {
        assignment: a.id,
        plan: a.plan.id,
        key: a.plan.key.clone(),
        version: a.plan.version,
        name: a.plan.name.clone(),
        starts_at: a.starts_at,
        ends_at: a.ends_at,
        entitlements: a.plan.entitlements.clone(),
        quotas: a.plan.quotas.clone(),
        seat_rule: a.plan.seat_rule,
        applied: Vec::new(),
        ignored: Vec::new(),
    };
    // The winning override of each key.
    let mut winners: BTreeMap<OverrideKey, &Override> = BTreeMap::new();
    for o in &inputs.overrides {
        let in_scope = match o.workspace {
            None => true,
            Some(w) => workspace == Some(w),
        };
        if !in_scope || !o.is_live(now) {
            continue;
        }
        let rank = |x: &Override| (x.workspace.is_some(), x.created_at, x.id);
        match winners.get(&o.key) {
            Some(cur) if rank(cur) >= rank(o) => {}
            _ => {
                winners.insert(o.key, o);
            }
        }
    }
    for (key, o) in winners {
        let changed = match (key, o.value) {
            (OverrideKey::Feature(f), OverrideValue::Flag(on)) => {
                out.entitlements.insert(f, on);
                true
            }
            (OverrideKey::QuotaLimit(m, l), OverrideValue::Limit(n)) => {
                match out.quotas.iter_mut().find(|q| q.meter == m && q.level == l) {
                    Some(q) => {
                        q.limit = n;
                        true
                    }
                    None => false,
                }
            }
            (OverrideKey::QuotaEnforcement(m, l), OverrideValue::Enforcement(e))
                if !(e == Enforcement::Hard && m.is_approximate()) =>
            {
                match out.quotas.iter_mut().find(|q| q.meter == m && q.level == l) {
                    Some(q) => {
                        q.enforcement = e;
                        true
                    }
                    None => false,
                }
            }
            (OverrideKey::SeatRule, OverrideValue::SeatRule(r)) => {
                out.seat_rule = r;
                true
            }
            _ => false,
        };
        if changed {
            out.applied.push(o.id);
        } else {
            out.ignored.push(o.id);
        }
    }
    Some(out)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;
    use time::Duration;
    use time::macros::datetime;

    const T0: OffsetDateTime = datetime!(2026-11-01 00:00 UTC);

    fn id(n: u128) -> Uuid {
        Uuid::from_u128(n)
    }

    fn quota(meter: Meter, limit: u64, enforcement: Enforcement, level: Level) -> Quota {
        let period = if meter.kind() == MeterKind::Gauge {
            Period::None
        } else {
            Period::Month
        };
        Quota {
            meter,
            limit,
            period,
            enforcement,
            level,
        }
    }

    fn plan(n: u128, key: &str) -> Plan {
        Plan {
            id: id(n),
            key: key.into(),
            version: 1,
            name: key.into(),
            entitlements: BTreeMap::from([(Feature::Api, true), (Feature::BulkSend, false)]),
            quotas: vec![
                quota(
                    Meter::EnvelopesSent,
                    100,
                    Enforcement::Hard,
                    Level::Organization,
                ),
                quota(
                    Meter::EnvelopesSent,
                    40,
                    Enforcement::Hard,
                    Level::Workspace,
                ),
                quota(
                    Meter::ApiCalls,
                    1000,
                    Enforcement::Soft,
                    Level::Organization,
                ),
            ],
            seat_rule: SeatRule::CanSend,
            archived: false,
        }
    }

    fn assignment(
        n: u128,
        p: Plan,
        starts: OffsetDateTime,
        ends: Option<OffsetDateTime>,
    ) -> Assignment {
        Assignment {
            id: id(n),
            plan: p,
            starts_at: starts,
            ends_at: ends,
        }
    }

    fn over(
        n: u128,
        workspace: Option<Uuid>,
        key: &str,
        value: &str,
        created: OffsetDateTime,
        expires: Option<OffsetDateTime>,
    ) -> Override {
        let (key, value) = parse_override(workspace, key, value).unwrap();
        Override {
            id: id(n),
            workspace,
            key,
            value,
            expires_at: expires,
            created_at: created,
            reason: None,
            operator: None,
        }
    }

    fn inputs(assignments: Vec<Assignment>, overrides: Vec<Override>) -> PlanInputs {
        PlanInputs {
            organization: id(999),
            assignments,
            overrides,
        }
    }

    fn draft(quotas: Vec<Quota>) -> PlanDraft {
        PlanDraft {
            key: "team".into(),
            name: "Team".into(),
            entitlements: BTreeMap::new(),
            quotas,
            seat_rule: SeatRule::CanSend,
        }
    }

    #[test]
    fn hard_on_an_approximate_meter_is_cs_plan_0006() {
        let d = draft(vec![quota(
            Meter::ApiCalls,
            10,
            Enforcement::Hard,
            Level::Organization,
        )]);
        let e = validate_plan(&d).unwrap_err();
        assert_eq!(
            e,
            PlanError::HardOnApproximate {
                meter: Meter::ApiCalls
            }
        );
        assert_eq!(e.code(), "CS-PLAN-0006");
        // Soft and notify are allowed on it; hard on an exact meter is allowed.
        for enf in [Enforcement::Soft, Enforcement::Notify] {
            validate_plan(&draft(vec![quota(
                Meter::ApiCalls,
                10,
                enf,
                Level::Organization,
            )]))
            .unwrap();
        }
        validate_plan(&draft(vec![quota(
            Meter::EnvelopesSent,
            10,
            Enforcement::Hard,
            Level::Organization,
        )]))
        .unwrap();
        // And through an override.
        assert_eq!(
            parse_override(None, "quota.api_calls.organization.enforcement", "hard").unwrap_err(),
            PlanError::HardOnApproximate {
                meter: Meter::ApiCalls
            }
        );
        parse_override(None, "quota.api_calls.organization.enforcement", "soft").unwrap();
    }

    #[test]
    fn every_approximate_meter_refuses_hard() {
        for m in Meter::ALL {
            let r = validate_quota(&quota(*m, 1, Enforcement::Hard, Level::Organization));
            assert_eq!(r.is_err(), m.is_approximate(), "{}", m.as_str());
        }
    }

    #[test]
    fn plans_with_bad_keys_names_duplicates_gauge_periods_or_limits_are_refused() {
        let mut d = draft(vec![]);
        d.key = "Team".into();
        assert_eq!(validate_plan(&d), Err(PlanError::Key));
        d.key = "team".into();
        d.name = "  ".into();
        assert_eq!(validate_plan(&d), Err(PlanError::Name));
        let q = quota(Meter::EnvelopesSent, 1, Enforcement::Hard, Level::Workspace);
        assert!(matches!(
            validate_plan(&draft(vec![q, q])),
            Err(PlanError::DuplicateQuota { .. })
        ));
        let mut g = quota(Meter::Seats, 5, Enforcement::Hard, Level::Organization);
        g.period = Period::Month;
        assert!(matches!(
            validate_plan(&draft(vec![g])),
            Err(PlanError::GaugeWithPeriod { .. })
        ));
        let w = quota(Meter::Workspaces, 5, Enforcement::Hard, Level::Workspace);
        assert!(matches!(
            validate_plan(&draft(vec![w])),
            Err(PlanError::LevelNotAllowed { .. })
        ));
        let big = quota(
            Meter::EnvelopesSent,
            MAX_LIMIT + 1,
            Enforcement::Hard,
            Level::Workspace,
        );
        assert!(matches!(
            validate_plan(&draft(vec![big])),
            Err(PlanError::LimitTooLarge { .. })
        ));
    }

    #[test]
    fn override_keys_values_and_scope_are_checked() {
        let ws = Some(id(7));
        assert_eq!(
            parse_override(None, "feature.teleport", "true"),
            Err(PlanError::OverrideKey)
        );
        assert_eq!(
            parse_override(None, "quota.seats.organization.limit.x", "1"),
            Err(PlanError::OverrideKey)
        );
        assert_eq!(
            parse_override(None, "feature.api", "yes"),
            Err(PlanError::OverrideValue)
        );
        for bad in ["", "-1", "+1", "1e3", " 1", "99999999999999999999"] {
            assert!(
                parse_override(None, "quota.seats.organization.limit", bad).is_err(),
                "{bad:?}"
            );
        }
        assert_eq!(
            parse_override(
                None,
                "quota.seats.organization.limit",
                "9223372036854775808"
            ),
            Err(PlanError::LimitTooLarge {
                meter: Meter::Seats
            })
        );
        // A workspace override changes only a workspace-level quota.
        assert_eq!(
            parse_override(ws, "feature.api", "true"),
            Err(PlanError::OverrideScope)
        );
        assert_eq!(
            parse_override(ws, "quota.envelopes_sent.organization.limit", "5"),
            Err(PlanError::OverrideScope)
        );
        assert_eq!(
            parse_override(ws, "seat_rule", "every_member"),
            Err(PlanError::OverrideScope)
        );
        parse_override(ws, "quota.envelopes_sent.workspace.limit", "5").unwrap();
        // Keys round-trip.
        for k in [
            "feature.seal_b_lta",
            "quota.storage_bytes.workspace.limit",
            "quota.api_calls.organization.enforcement",
            "seat_rule",
        ] {
            assert_eq!(OverrideKey::parse(k).unwrap().to_key(), k);
        }
    }

    #[test]
    fn an_assignment_is_current_from_its_start_until_just_before_its_end() {
        let end = T0 + Duration::days(30);
        let old = assignment(1, plan(10, "starter"), T0, Some(end));
        let new = assignment(2, plan(20, "team"), end, None);
        let inp = inputs(vec![old, new], vec![]);
        let before_start = T0 - Duration::nanoseconds(1);
        assert_eq!(effective(&inp, None, before_start), None);
        assert_eq!(effective(&inp, None, T0).unwrap().key, "starter");
        let last = end - Duration::nanoseconds(1);
        assert_eq!(effective(&inp, None, last).unwrap().key, "starter");
        // At the boundary instant the next one is current, never both.
        assert_eq!(effective(&inp, None, end).unwrap().key, "team");
        assert_eq!(
            effective(&inp, None, end + Duration::days(3650))
                .unwrap()
                .key,
            "team"
        );
    }

    #[test]
    fn a_gap_between_assignments_has_no_plan() {
        let a = assignment(1, plan(10, "a"), T0, Some(T0 + Duration::days(1)));
        let b = assignment(2, plan(20, "b"), T0 + Duration::days(2), None);
        let inp = inputs(vec![a, b], vec![]);
        assert!(effective(&inp, None, T0 + Duration::hours(36)).is_none());
        assert_eq!(
            effective(&inp, None, T0 + Duration::days(2)).unwrap().key,
            "b"
        );
    }

    #[test]
    fn overlapping_assignments_resolve_to_the_latest_start() {
        let a = assignment(1, plan(10, "a"), T0, None);
        let b = assignment(2, plan(20, "b"), T0 + Duration::days(1), None);
        let inp = inputs(vec![b, a], vec![]);
        assert_eq!(effective(&inp, None, T0).unwrap().key, "a");
        assert_eq!(
            effective(&inp, None, T0 + Duration::days(1)).unwrap().key,
            "b"
        );
    }

    #[test]
    fn an_override_applies_until_just_before_it_expires() {
        let a = assignment(1, plan(10, "team"), T0, None);
        let exp = T0 + Duration::days(7);
        let o = over(
            50,
            None,
            "quota.envelopes_sent.organization.limit",
            "500",
            T0,
            Some(exp),
        );
        let inp = inputs(vec![a], vec![o]);
        let limit = |now| {
            effective(&inp, None, now)
                .unwrap()
                .quota(Meter::EnvelopesSent, Level::Organization)
                .unwrap()
                .limit
        };
        assert_eq!(limit(T0), 500);
        assert_eq!(limit(exp - Duration::nanoseconds(1)), 500);
        assert_eq!(limit(exp), 100, "expired at its expiry instant");
        let e = effective(&inp, None, T0).unwrap();
        assert_eq!(e.applied, vec![id(50)]);
        assert!(effective(&inp, None, exp).unwrap().applied.is_empty());
    }

    #[test]
    fn overrides_change_features_enforcement_and_seat_rule() {
        let a = assignment(1, plan(10, "team"), T0, None);
        let os = vec![
            over(51, None, "feature.bulk_send", "true", T0, None),
            over(52, None, "feature.api", "false", T0, None),
            over(
                53,
                None,
                "quota.api_calls.organization.enforcement",
                "notify",
                T0,
                None,
            ),
            over(54, None, "seat_rule", "every_member", T0, None),
        ];
        let e = effective(&inputs(vec![a], os), None, T0).unwrap();
        assert!(e.entitled(Feature::BulkSend));
        assert!(!e.entitled(Feature::Api));
        assert!(!e.entitled(Feature::Scim), "absent is disabled");
        assert_eq!(
            e.quota(Meter::ApiCalls, Level::Organization)
                .unwrap()
                .enforcement,
            Enforcement::Notify
        );
        assert_eq!(e.seat_rule, SeatRule::EveryMember);
        assert_eq!(e.applied.len(), 4);
    }

    #[test]
    fn a_workspace_override_beats_the_organization_one_only_in_that_workspace() {
        let a = assignment(1, plan(10, "team"), T0, None);
        let ws = id(7);
        let os = vec![
            // Organization-wide, set later than the workspace one: the workspace one
            // still wins in its workspace.
            over(
                60,
                None,
                "quota.envelopes_sent.workspace.limit",
                "60",
                T0 + Duration::hours(1),
                None,
            ),
            over(
                61,
                Some(ws),
                "quota.envelopes_sent.workspace.limit",
                "70",
                T0,
                None,
            ),
        ];
        let inp = inputs(vec![a], os);
        let limit = |w| {
            effective(&inp, w, T0 + Duration::hours(2))
                .unwrap()
                .quota(Meter::EnvelopesSent, Level::Workspace)
                .unwrap()
                .limit
        };
        assert_eq!(limit(Some(ws)), 70);
        assert_eq!(limit(Some(id(8))), 60);
        assert_eq!(limit(None), 60);
    }

    #[test]
    fn of_two_overrides_of_one_key_the_later_wins_and_expiry_uncovers_the_earlier() {
        let a = assignment(1, plan(10, "team"), T0, None);
        let os = vec![
            over(
                70,
                None,
                "quota.envelopes_sent.organization.limit",
                "200",
                T0,
                None,
            ),
            over(
                71,
                None,
                "quota.envelopes_sent.organization.limit",
                "300",
                T0 + Duration::hours(1),
                Some(T0 + Duration::days(1)),
            ),
        ];
        let inp = inputs(vec![a], os);
        let limit = |now| {
            effective(&inp, None, now)
                .unwrap()
                .quota(Meter::EnvelopesSent, Level::Organization)
                .unwrap()
                .limit
        };
        assert_eq!(limit(T0 + Duration::hours(2)), 300);
        assert_eq!(limit(T0 + Duration::days(1)), 200);
    }

    #[test]
    fn an_override_of_a_quota_the_plan_lacks_is_ignored() {
        let a = assignment(1, plan(10, "team"), T0, None);
        let o = over(80, None, "quota.seats.organization.limit", "5", T0, None);
        let e = effective(&inputs(vec![a], vec![o]), None, T0).unwrap();
        assert!(e.quota(Meter::Seats, Level::Organization).is_none());
        assert_eq!(e.ignored, vec![id(80)]);
        assert!(e.applied.is_empty());
    }

    #[test]
    fn overrides_without_a_current_assignment_give_no_plan() {
        let o = over(90, None, "feature.api", "true", T0, None);
        assert!(effective(&inputs(vec![], vec![o]), None, T0).is_none());
    }

    #[test]
    fn stored_json_reads_back() {
        let v = serde_json::json!({
            "organization": id(999),
            "workspace": null,
            "assignments": [{
                "id": id(1), "starts_at": 1_793_491_200_000_000_i64, "ends_at": null,
                "plan": {
                    "id": id(10), "key": "team", "version": 2, "name": "Team",
                    "seat_rule": "can_send", "archived": false,
                    "entitlements": {"api": true},
                    "quotas": [{"meter": "envelopes_sent", "limit": 100, "period": "month",
                                "enforcement": "hard", "level": "organization"}]
                }
            }],
            "overrides": [{
                "id": id(50), "workspace": null, "key": "feature.bulk_send", "value": "true",
                "expires_at": null, "created_at": 1_793_491_200_000_000_i64
            }]
        });
        let inp = PlanInputs::from_json(&v).unwrap();
        assert_eq!(inp.assignments[0].starts_at, T0);
        let e = effective(&inp, None, T0).unwrap();
        assert_eq!((e.key.as_str(), e.version), ("team", 2));
        assert!(e.entitled(Feature::BulkSend));
        let mut bad = v.clone();
        bad["assignments"][0]["plan"]["entitlements"] = serde_json::json!({"teleport": true});
        assert_eq!(
            PlanInputs::from_json(&bad).unwrap_err(),
            InputsError { what: "feature" }
        );
    }
}
