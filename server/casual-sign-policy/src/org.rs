//! Organization policy (ORG-08, ADR-028 (c), docs/23 §3): the typed document an
//! organization keeps in `organizations.policy`, and the pure function that combines it
//! with one workspace's `accounts.settings` into the policy that workspace runs under.
//!
//! Each key is `{ "value": …, "locked": bool }`. Three rules govern a workspace's own
//! value:
//!
//! - **Locked** keys refuse any workspace change ([`check_write`], `CS-ORG-0002`) and the
//!   organization's value is the effective one.
//! - **Tighten-only** keys (security and evidence) refuse a workspace value looser than
//!   the organization's, and on read the stricter of the two wins, so tightening at
//!   organization level never rewrites a workspace row.
//! - **Defaults** are the workspace's to override unless locked.
//!
//! The functions here read and decide only: no I/O, no clock. The server calls
//! [`check_write`] on every settings write and [`effective`] (or
//! [`effective_mfa`]) on every read and sign-in; a later policy change never reaches a
//! sent envelope, whose ceremony inputs are in its state (docs/23 §3 Evidence).

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use serde_json::{Map, Value};

/// The most items a list-valued key takes.
pub const MAX_LIST: usize = 256;

/// What a key governs (docs/23 §3's "Kind" column).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Class {
    /// Staff sign-in and sessions, recipient authentication, embedding.
    Security,
    /// What a sealed agreement carries.
    Evidence,
    /// Retention and region labels.
    Governance,
    /// API and webhooks.
    Integration,
    /// Defaults a workspace may override unless locked.
    Defaults,
    /// Cross-workspace collaboration, set by the organization only.
    Collaboration,
}

/// How a workspace's own value relates to the organization's (docs/23 §3's "Rule").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Rule {
    /// The workspace may only be stricter (a higher level, a shorter time, `true`).
    Tighten,
    /// The workspace may only narrow: a subset of a list, or `false` for an allowed flag.
    Narrow,
    /// The effective list is the intersection; a workspace item outside it is refused.
    Intersection,
    /// The workspace's value lies within the organization's range or list.
    Within,
    /// The workspace overrides unless locked.
    Default,
    /// Organization only; a workspace holds no value.
    OrgOnly,
}

macro_rules! keys {
    ($($(#[$m:meta])* $v:ident = $name:literal, $class:ident, $rule:ident, $locked:literal;)*) => {
        /// A key of the organization policy (docs/23 §3).
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub enum Key {
            $($(#[$m])* $v,)*
        }

        impl Key {
            /// Every key, in the order of docs/23 §3.
            pub const ALL: &'static [Key] = &[$(Key::$v,)*];

            /// The key's name in the policy document.
            #[must_use]
            pub fn as_str(self) -> &'static str {
                match self { $(Key::$v => $name,)* }
            }

            /// The key a name names, if any.
            #[must_use]
            pub fn from_name(name: &str) -> Option<Self> {
                match name { $($name => Some(Key::$v),)* _ => None }
            }

            /// What the key governs.
            #[must_use]
            pub fn class(self) -> Class {
                match self { $(Key::$v => Class::$class,)* }
            }

            /// How a workspace value relates to the organization's.
            #[must_use]
            pub fn rule(self) -> Rule {
                match self { $(Key::$v => Rule::$rule,)* }
            }

            /// Whether a key written without `locked` is locked (docs/23 §3: sign-in
            /// methods and SSO enforcement are locked by default).
            #[must_use]
            pub fn locked_by_default(self) -> bool {
                match self { $(Key::$v => $locked,)* }
            }
        }
    };
}

keys! {
    /// SSO required for identities of the organization's claimed domains.
    LoginSsoRequired = "login.sso_required", Security, Tighten, true;
    /// The staff sign-in methods allowed (`password`, `sso`).
    LoginAllowedMethods = "login.allowed_methods", Security, Narrow, true;
    /// Who must sign in with a second factor (`optional` < `administrators` < `everyone`).
    LoginMfaRequired = "login.mfa_required", Security, Tighten, false;
    /// Password rules: `{min_length, breached_check}`.
    LoginPassword = "login.password", Security, Tighten, false;
    /// Longest staff session, in seconds.
    SessionMaxAge = "session.max_age", Security, Tighten, false;
    /// Longest idle staff session, in seconds.
    SessionIdle = "session.idle", Security, Tighten, false;
    /// Networks staff may sign in from (CIDR).
    LoginIpAllowList = "login.ip_allow_list", Security, Intersection, false;
    /// Recipient authentication methods senders may require.
    RecipientAllowedAuthMethods = "recipient.allowed_auth_methods", Security, Intersection, false;
    /// Origins a workspace brand may allow to frame the signing page.
    EmbeddingFrameAncestorsAllowed = "embedding.frame_ancestors_allowed", Security, Narrow, false;
    /// Seal profiles envelopes may use.
    SendingAllowedSealProfiles = "sending.allowed_seal_profiles", Evidence, Narrow, false;
    /// The lowest seal profile envelopes may use.
    SendingMinSealProfile = "sending.min_seal_profile", Evidence, Tighten, false;
    /// The shortest retention a workspace policy may set, in days.
    RetentionMinDays = "retention.min_days", Governance, Within, false;
    /// The longest retention a workspace policy may set, in days.
    RetentionMaxDays = "retention.max_days", Governance, Within, false;
    /// The region labels a workspace may carry (a label only; docs/23 §7.5).
    DataRegions = "data_regions", Governance, Within, false;
    /// Whether workspaces may use the API.
    ApiAllowed = "api.allowed", Integration, Narrow, false;
    /// Hosts webhooks may deliver to.
    WebhooksAllowedHosts = "webhooks.allowed_hosts", Integration, Narrow, false;
    /// The default brand (`{name, color}`, as a workspace's `branding`).
    BrandingDefaultBrand = "branding.default_brand", Defaults, Default, false;
    /// The default consumer disclosure (`{version, hash}`).
    ErsdDefault = "ersd.default", Defaults, Default, false;
    /// The date format of `date_signed` fields.
    LocaleDateFormat = "locale.date_format", Defaults, Default, false;
    /// Days before the first reminder (0 for none).
    RemindersDefault = "reminders.default", Defaults, Default, false;
    /// Whether templates may be copied between the organization's workspaces.
    SharingCrossWorkspaceTemplates = "sharing.cross_workspace_templates", Collaboration, OrgOnly, false;
}

impl Key {
    /// The workspace setting this key governs today, as a path into `accounts.settings`
    /// (`workflow_policy.date_format`), or `None` for a key no workspace setting holds yet.
    #[must_use]
    pub fn workspace_setting(self) -> Option<&'static str> {
        match self {
            Key::LoginMfaRequired => Some("mfa_policy"),
            Key::RemindersDefault => Some("first_reminder_days"),
            Key::LocaleDateFormat => Some("workflow_policy.date_format"),
            Key::BrandingDefaultBrand => Some("branding"),
            _ => None,
        }
    }

    /// Whether loosening or unlocking the key is reserved to an organization owner
    /// (docs/23 §2.2, §3; `SEC-O11`).
    #[must_use]
    pub fn owner_only_to_loosen(self) -> bool {
        self.class() == Class::Security
    }
}

/// Why a policy document or a workspace write was refused. Names the key, never the
/// value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyError {
    /// The document is not an object, or a member is not a known key.
    UnknownKey(String),
    /// A key's entry is not `{value, locked?}` or its value is out of shape or range.
    InvalidValue(Key),
}

impl PolicyError {
    /// The JSON pointer of the offending member, under `/policy`.
    #[must_use]
    pub fn pointer(&self) -> String {
        match self {
            Self::UnknownKey(k) if k.is_empty() => "/policy".to_owned(),
            Self::UnknownKey(k) => format!("/policy/{}", escape(k)),
            Self::InvalidValue(k) => format!("/policy/{}", escape(k.as_str())),
        }
    }
}

fn escape(s: &str) -> String {
    s.replace('~', "~0").replace('/', "~1")
}

impl std::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownKey(_) => write!(f, "unknown organization policy key"),
            Self::InvalidValue(k) => write!(f, "invalid value for {}", k.as_str()),
        }
    }
}

impl std::error::Error for PolicyError {}

/// One key's organization value.
#[derive(Debug, Clone, PartialEq)]
pub struct Entry {
    /// The value, validated for its key.
    pub value: Value,
    /// Whether a workspace may change its own value.
    pub locked: bool,
}

/// An organization's policy document, validated (docs/23 §3).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct OrgPolicy {
    entries: BTreeMap<Key, Entry>,
}

impl OrgPolicy {
    /// Parse and validate `organizations.policy`. An empty object is the empty policy.
    ///
    /// # Errors
    ///
    /// [`PolicyError::UnknownKey`] for a non-object or an unknown member;
    /// [`PolicyError::InvalidValue`] for an entry out of shape or range, or
    /// `retention.min_days` above `retention.max_days`.
    pub fn parse(doc: &Value) -> Result<Self, PolicyError> {
        let Value::Object(m) = doc else {
            return Err(PolicyError::UnknownKey(String::new()));
        };
        let mut entries = BTreeMap::new();
        for (name, entry) in m {
            let key = Key::from_name(name).ok_or_else(|| PolicyError::UnknownKey(name.clone()))?;
            let bad = || PolicyError::InvalidValue(key);
            let Value::Object(e) = entry else {
                return Err(bad());
            };
            if e.keys().any(|k| k != "value" && k != "locked") {
                return Err(bad());
            }
            let value = e.get("value").ok_or_else(bad)?;
            let locked = match e.get("locked") {
                None => key.locked_by_default(),
                Some(Value::Bool(b)) => *b,
                Some(_) => return Err(bad()),
            };
            if !valid(key, value) {
                return Err(bad());
            }
            entries.insert(
                key,
                Entry {
                    value: value.clone(),
                    locked,
                },
            );
        }
        if let (Some(min), Some(max)) = (
            entries.get(&Key::RetentionMinDays).and_then(|e| e.value.as_u64()),
            entries.get(&Key::RetentionMaxDays).and_then(|e| e.value.as_u64()),
        ) && min > max
        {
            return Err(PolicyError::InvalidValue(Key::RetentionMinDays));
        }
        Ok(Self { entries })
    }

    /// The policy as stored: `{key: {value, locked}}`.
    #[must_use]
    pub fn to_value(&self) -> Value {
        let mut m = Map::new();
        for (k, e) in &self.entries {
            let mut o = Map::new();
            o.insert("value".into(), e.value.clone());
            o.insert("locked".into(), Value::Bool(e.locked));
            m.insert(k.as_str().to_owned(), Value::Object(o));
        }
        Value::Object(m)
    }

    /// The organization's entry for `key`, if it sets one.
    #[must_use]
    pub fn get(&self, key: Key) -> Option<&Entry> {
        self.entries.get(&key)
    }

    /// Whether `key` is locked.
    #[must_use]
    pub fn locked(&self, key: Key) -> bool {
        self.entries.get(&key).is_some_and(|e| e.locked)
    }
}

// Validation ------------------------------------------------------------------------------

const MFA_LEVELS: [&str; 3] = ["optional", "administrators", "everyone"];
const SEAL_PROFILES: [&str; 3] = ["pades-b-t", "pades-b-lt", "pades-b-lta"];
const LOGIN_METHODS: [&str; 2] = ["password", "sso"];

fn valid(key: Key, v: &Value) -> bool {
    match key {
        Key::LoginSsoRequired | Key::ApiAllowed | Key::SharingCrossWorkspaceTemplates => {
            v.is_boolean()
        }
        Key::LoginAllowedMethods => list(v, |s| LOGIN_METHODS.contains(&s), true),
        Key::LoginMfaRequired => v.as_str().is_some_and(|s| MFA_LEVELS.contains(&s)),
        Key::LoginPassword => password(v).is_some(),
        Key::SessionMaxAge | Key::SessionIdle => int_in(v, 60, 31_536_000),
        Key::LoginIpAllowList => list(v, cidr, false),
        Key::RecipientAllowedAuthMethods => list(
            v,
            |s| {
                serde_json::from_value::<casual_sign_audit::AuthMethod>(Value::String(s.into()))
                    .is_ok()
            },
            true,
        ),
        Key::EmbeddingFrameAncestorsAllowed => list(v, origin, false),
        Key::SendingAllowedSealProfiles => list(v, |s| SEAL_PROFILES.contains(&s), true),
        Key::SendingMinSealProfile => v.as_str().is_some_and(|s| SEAL_PROFILES.contains(&s)),
        Key::RetentionMinDays | Key::RetentionMaxDays => int_in(v, 1, 36_500),
        Key::DataRegions => list(v, label, true),
        Key::WebhooksAllowedHosts => list(v, host, false),
        Key::BrandingDefaultBrand => brand(v),
        Key::ErsdDefault => ersd(v),
        Key::LocaleDateFormat => {
            serde_json::from_value::<casual_sign_model::DateFormat>(v.clone()).is_ok()
        }
        Key::RemindersDefault => int_in(v, 0, 60),
    }
}

fn int_in(v: &Value, lo: u64, hi: u64) -> bool {
    v.as_u64().is_some_and(|n| (lo..=hi).contains(&n))
}

/// A list of distinct strings each passing `item`, at most [`MAX_LIST`]; `non_empty`
/// refuses `[]`.
fn list(v: &Value, item: impl Fn(&str) -> bool, non_empty: bool) -> bool {
    let Some(a) = v.as_array() else { return false };
    if a.len() > MAX_LIST || (non_empty && a.is_empty()) {
        return false;
    }
    let mut seen = BTreeSet::new();
    a.iter()
        .all(|x| x.as_str().is_some_and(|s| item(s) && seen.insert(s)))
}

fn password(v: &Value) -> Option<(u64, bool)> {
    let o = v.as_object()?;
    if o.keys().any(|k| k != "min_length" && k != "breached_check") {
        return None;
    }
    let min = o.get("min_length")?.as_u64().filter(|n| (8..=128).contains(n))?;
    let breached = o.get("breached_check")?.as_bool()?;
    Some((min, breached))
}

fn cidr(s: &str) -> bool {
    let (addr, prefix) = s.split_once('/').unwrap_or((s, ""));
    let Ok(ip) = addr.parse::<IpAddr>() else {
        return false;
    };
    let max = if ip.is_ipv4() { 32 } else { 128 };
    prefix.is_empty() || prefix.parse::<u8>().is_ok_and(|p| p <= max)
}

fn host(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && s.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

fn origin(s: &str) -> bool {
    let Some(rest) = s.strip_prefix("https://") else {
        return false;
    };
    let (h, port) = rest.split_once(':').unwrap_or((rest, ""));
    host(h) && (port.is_empty() || port.parse::<u16>().is_ok_and(|p| p > 0))
}

fn label(s: &str) -> bool {
    (1..=32).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

fn brand(v: &Value) -> bool {
    let Some(o) = v.as_object() else { return false };
    o.iter().all(|(k, x)| match (k.as_str(), x.as_str()) {
        ("name", Some(s)) => s.chars().count() <= 255,
        ("color", Some(s)) => {
            s.is_empty()
                || (s.len() == 7
                    && s.starts_with('#')
                    && s.bytes().skip(1).all(|b| b.is_ascii_hexdigit()))
        }
        _ => false,
    })
}

fn ersd(v: &Value) -> bool {
    let Some(o) = v.as_object() else { return false };
    o.len() == 2
        && o.get("version")
            .and_then(Value::as_str)
            .is_some_and(|s| (1..=64).contains(&s.len()))
        && o.get("hash").and_then(Value::as_str).is_some_and(|s| {
            s.strip_prefix("sha256:")
                .is_some_and(|h| h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()))
        })
}

// Comparison ------------------------------------------------------------------------------

fn rank(order: &[&str], v: &Value) -> Option<usize> {
    let s = v.as_str()?;
    order.iter().position(|x| *x == s)
}

fn strings(v: &Value) -> BTreeSet<&str> {
    v.as_array()
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default()
}

/// Whether a workspace value `ws` is allowed under the organization's value `org` for
/// `key`: as strict or stricter for tighten-only keys, a subset for narrowing and
/// intersected lists, inside for ranges; always for defaults (the lock is checked
/// separately). An unreadable value is not allowed (fail closed).
#[must_use]
pub fn permits(key: Key, org: &Value, ws: &Value) -> bool {
    match key {
        Key::LoginSsoRequired => ws.as_bool().unwrap_or(false) || !org.as_bool().unwrap_or(true),
        Key::LoginMfaRequired => match (rank(&MFA_LEVELS, org), rank(&MFA_LEVELS, ws)) {
            (Some(o), Some(w)) => w >= o,
            _ => false,
        },
        Key::SendingMinSealProfile => match (rank(&SEAL_PROFILES, org), rank(&SEAL_PROFILES, ws))
        {
            (Some(o), Some(w)) => w >= o,
            _ => false,
        },
        Key::LoginPassword => match (password(org), password(ws)) {
            (Some((om, ob)), Some((wm, wb))) => wm >= om && (wb || !ob),
            _ => false,
        },
        Key::SessionMaxAge | Key::SessionIdle => match (org.as_u64(), ws.as_u64()) {
            (Some(o), Some(w)) => w <= o,
            _ => false,
        },
        Key::ApiAllowed => !ws.as_bool().unwrap_or(true) || org.as_bool().unwrap_or(false),
        Key::LoginAllowedMethods
        | Key::LoginIpAllowList
        | Key::RecipientAllowedAuthMethods
        | Key::EmbeddingFrameAncestorsAllowed
        | Key::SendingAllowedSealProfiles
        | Key::WebhooksAllowedHosts => {
            ws.is_array() && org.is_array() && strings(ws).is_subset(&strings(org))
        }
        Key::DataRegions => ws.as_str().is_some_and(|w| strings(org).contains(w)),
        Key::RetentionMinDays => match (org.as_u64(), ws.as_u64()) {
            (Some(o), Some(w)) => w >= o,
            _ => false,
        },
        Key::RetentionMaxDays => match (org.as_u64(), ws.as_u64()) {
            (Some(o), Some(w)) => w <= o,
            _ => false,
        },
        Key::BrandingDefaultBrand
        | Key::ErsdDefault
        | Key::LocaleDateFormat
        | Key::RemindersDefault => true,
        Key::SharingCrossWorkspaceTemplates => false,
    }
}

// The workspace side ----------------------------------------------------------------------

/// The value at a dotted path of the workspace's settings.
fn at<'a>(settings: &'a Value, path: &str) -> Option<&'a Value> {
    path.split('.')
        .try_fold(settings, |v, p| v.get(p))
        .filter(|v| !v.is_null())
}

/// The workspace's own value for `key`, from its settings (the stored default when the
/// setting is absent: `administrators` for the second factor, migration 0036).
#[must_use]
pub fn workspace_value(key: Key, settings: &Value) -> Option<Value> {
    let path = key.workspace_setting()?;
    match at(settings, path) {
        Some(v) => Some(v.clone()),
        None if key == Key::LoginMfaRequired => Some(Value::String("administrators".into())),
        None => None,
    }
}

/// Why a workspace settings write was refused (`422 CS-ORG-0002`, naming the key).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Refused {
    /// The organization key.
    pub key: Key,
    /// The workspace setting it governs.
    pub setting: &'static str,
    /// Locked (`true`) or looser than the organization's value (`false`).
    pub locked: bool,
}

/// Check a workspace settings write against the organization's policy (`SEC-O03`):
/// every governed setting whose value changes from `old` to `new` must not be locked
/// and, for a rule that bounds it, must be allowed by [`permits`]. A setting that does
/// not change is not checked, so an unrelated edit of a workspace that predates a
/// tightening still saves.
///
/// # Errors
///
/// The first [`Refused`] setting, in key order.
pub fn check_write(org: &OrgPolicy, old: &Value, new: &Value) -> Result<(), Refused> {
    for &key in Key::ALL {
        let Some(setting) = key.workspace_setting() else {
            continue;
        };
        let before = workspace_value(key, old);
        let after = workspace_value(key, new);
        if before == after {
            continue;
        }
        let Some(entry) = org.get(key) else { continue };
        if entry.locked {
            return Err(Refused {
                key,
                setting,
                locked: true,
            });
        }
        if let Some(v) = &after
            && !permits(key, &entry.value, v)
        {
            return Err(Refused {
                key,
                setting,
                locked: false,
            });
        }
    }
    Ok(())
}

/// One key of the effective policy.
#[derive(Debug, Clone, PartialEq)]
pub struct Effective {
    /// The value the workspace runs under.
    pub value: Value,
    /// Locked by the organization: shown with a lock and "Set by your organization".
    pub locked: bool,
    /// The organization's value is the effective one (locked, stricter, or the
    /// workspace has none).
    pub from_organization: bool,
}

/// The effective policy of a workspace: for every key either side sets, the value the
/// workspace runs under (docs/23 §3). Locked keys take the organization's value;
/// tighten-only keys the stricter; intersected lists their intersection; defaults the
/// workspace's own value when it has one.
#[must_use]
pub fn effective(org: &OrgPolicy, settings: &Value) -> BTreeMap<Key, Effective> {
    let mut out = BTreeMap::new();
    for &key in Key::ALL {
        let ws = workspace_value(key, settings);
        let e = match (org.get(key), ws) {
            (None, None) => continue,
            (None, Some(w)) => Effective {
                value: w,
                locked: false,
                from_organization: false,
            },
            (Some(o), w) => {
                let own = w.filter(|w| {
                    !o.locked && key.rule() != Rule::OrgOnly && permits(key, &o.value, w)
                });
                match own {
                    Some(w) if key.rule() == Rule::Intersection => Effective {
                        value: Value::Array(
                            strings(&w)
                                .intersection(&strings(&o.value))
                                .map(|s| Value::String((*s).to_owned()))
                                .collect(),
                        ),
                        locked: false,
                        from_organization: false,
                    },
                    Some(w) => Effective {
                        value: w,
                        locked: false,
                        from_organization: false,
                    },
                    None => Effective {
                        value: o.value.clone(),
                        locked: o.locked,
                        from_organization: true,
                    },
                }
            }
        };
        out.insert(key, e);
    }
    out
}

/// The second-factor level a workspace's staff sign in under: the stricter of the
/// organization's `login.mfa_required` and the workspace's `mfa_policy` (`setting`),
/// or the organization's when locked. An unreadable organization policy fails closed,
/// as `everyone`.
#[must_use]
pub fn effective_mfa(org: &Value, setting: &str) -> &'static str {
    let Ok(policy) = OrgPolicy::parse(org) else {
        return "everyone";
    };
    let settings = serde_json::json!({ "mfa_policy": setting });
    let level = effective(&policy, &settings)
        .remove(&Key::LoginMfaRequired)
        .map(|e| e.value);
    match level.as_ref().and_then(|v| rank(&MFA_LEVELS, v)) {
        Some(i) => MFA_LEVELS.get(i).copied().unwrap_or("everyone"),
        None => "everyone",
    }
}

/// The first security key a change from `old` to `new` loosens: unlocks, removes, or
/// sets looser than before. Loosening security is reserved to an organization owner
/// (`403 CS-ORG-0013`, `SEC-O11`).
#[must_use]
pub fn loosened(old: &OrgPolicy, new: &OrgPolicy) -> Option<Key> {
    Key::ALL.iter().copied().find(|&key| {
        if !key.owner_only_to_loosen() {
            return false;
        }
        match (old.get(key), new.get(key)) {
            (Some(_), None) => true,
            (Some(o), Some(n)) => (o.locked && !n.locked) || !permits(key, &o.value, &n.value),
            _ => false,
        }
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)] // Tests: a panic is the failure.
mod tests {
    use super::*;
    use serde_json::json;

    fn pol(v: Value) -> OrgPolicy {
        OrgPolicy::parse(&v).unwrap()
    }

    #[test]
    fn every_key_parses_with_a_valid_value_and_refuses_junk() {
        let good = json!({
            "login.sso_required": {"value": true},
            "login.allowed_methods": {"value": ["sso"]},
            "login.mfa_required": {"value": "everyone", "locked": true},
            "login.password": {"value": {"min_length": 12, "breached_check": true}},
            "session.max_age": {"value": 3600},
            "session.idle": {"value": 900},
            "login.ip_allow_list": {"value": ["10.0.0.0/8", "2001:db8::/32"]},
            "recipient.allowed_auth_methods": {"value": ["email_link", "sms_otp"]},
            "embedding.frame_ancestors_allowed": {"value": ["https://app.example.com"]},
            "sending.allowed_seal_profiles": {"value": ["pades-b-lt", "pades-b-lta"]},
            "sending.min_seal_profile": {"value": "pades-b-lt"},
            "retention.min_days": {"value": 30},
            "retention.max_days": {"value": 3650},
            "data_regions": {"value": ["eu-west"]},
            "api.allowed": {"value": false},
            "webhooks.allowed_hosts": {"value": ["hooks.example.com"]},
            "branding.default_brand": {"value": {"name": "Acme", "color": "#112233"}},
            "ersd.default": {"value": {"version": "3", "hash": format!("sha256:{}", "a".repeat(64))}},
            "locale.date_format": {"value": "dd_mm_yyyy", "locked": true},
            "reminders.default": {"value": 3},
            "sharing.cross_workspace_templates": {"value": true},
        });
        let p = pol(good.clone());
        assert_eq!(p.entries.len(), Key::ALL.len());
        assert!(p.locked(Key::LoginSsoRequired), "locked by default");
        assert!(!p.locked(Key::SessionIdle));
        assert_eq!(OrgPolicy::parse(&p.to_value()).unwrap(), p);

        for (k, bad) in [
            ("login.mfa_required", json!("sometimes")),
            ("login.password", json!({"min_length": 4, "breached_check": true})),
            ("login.ip_allow_list", json!(["10.0.0.0/33"])),
            ("recipient.allowed_auth_methods", json!(["telepathy"])),
            ("embedding.frame_ancestors_allowed", json!(["http://x.example"])),
            ("sending.min_seal_profile", json!("pades-b-b")),
            ("webhooks.allowed_hosts", json!(["a", "a"])),
            ("reminders.default", json!(61)),
        ] {
            let mut doc = Map::new();
            doc.insert(k.into(), json!({ "value": bad }));
            let e = OrgPolicy::parse(&Value::Object(doc)).unwrap_err();
            assert_eq!(e, PolicyError::InvalidValue(Key::from_name(k).unwrap()));
            assert!(e.pointer().starts_with("/policy/"));
        }
        assert_eq!(
            OrgPolicy::parse(&json!({"nope": {"value": 1}})).unwrap_err(),
            PolicyError::UnknownKey("nope".into())
        );
        assert!(
            OrgPolicy::parse(&json!({
                "retention.min_days": {"value": 90}, "retention.max_days": {"value": 30}
            }))
            .is_err()
        );
    }

    #[test]
    fn a_locked_key_refuses_any_change_and_an_unchanged_one_saves() {
        let p = pol(json!({
            "locale.date_format": {"value": "dd_mm_yyyy", "locked": true},
            "reminders.default": {"value": 2, "locked": true},
            "branding.default_brand": {"value": {"name": "Acme"}, "locked": true},
            "login.mfa_required": {"value": "administrators", "locked": true},
        }));
        let old = json!({"first_reminder_days": 5, "workflow_policy": {"date_format": "yyyy_mm_dd"}});
        for (new, setting) in [
            (json!({"first_reminder_days": 6, "workflow_policy": {"date_format": "yyyy_mm_dd"}}), "first_reminder_days"),
            (json!({"first_reminder_days": 5, "workflow_policy": {"date_format": "mm_dd_yyyy"}}), "workflow_policy.date_format"),
            (json!({"first_reminder_days": 5, "workflow_policy": {"date_format": "yyyy_mm_dd"}, "branding": {"name": "B"}}), "branding"),
            (json!({"first_reminder_days": 5, "workflow_policy": {"date_format": "yyyy_mm_dd"}, "mfa_policy": "everyone"}), "mfa_policy"),
        ] {
            let r = check_write(&p, &old, &new).unwrap_err();
            assert_eq!(r.setting, setting);
            assert!(r.locked);
        }
        assert_eq!(check_write(&p, &old, &old), Ok(()));
    }

    #[test]
    fn tighten_only_refuses_looser_and_takes_the_stricter_on_read() {
        let p = pol(json!({"login.mfa_required": {"value": "administrators"}}));
        let old = json!({});
        let r = check_write(&p, &old, &json!({"mfa_policy": "optional"})).unwrap_err();
        assert_eq!((r.key, r.locked), (Key::LoginMfaRequired, false));
        assert_eq!(check_write(&p, &old, &json!({"mfa_policy": "everyone"})), Ok(()));
        // A workspace that predates the tightening runs under the organization's level.
        let e = effective(&p, &json!({"mfa_policy": "optional"}));
        assert_eq!(e[&Key::LoginMfaRequired].value, json!("administrators"));
        assert!(e[&Key::LoginMfaRequired].from_organization);
        assert_eq!(effective_mfa(&p.to_value(), "optional"), "administrators");
        assert_eq!(effective_mfa(&p.to_value(), "everyone"), "everyone");
        assert_eq!(effective_mfa(&json!({}), "optional"), "optional");
        assert_eq!(effective_mfa(&json!({"junk": 1}), "optional"), "everyone");
    }

    #[test]
    fn rules_compare_as_documented() {
        assert!(permits(Key::SessionIdle, &json!(900), &json!(600)));
        assert!(!permits(Key::SessionIdle, &json!(900), &json!(1200)));
        assert!(permits(Key::ApiAllowed, &json!(false), &json!(false)));
        assert!(!permits(Key::ApiAllowed, &json!(false), &json!(true)));
        assert!(permits(Key::SendingMinSealProfile, &json!("pades-b-lt"), &json!("pades-b-lta")));
        assert!(!permits(Key::SendingMinSealProfile, &json!("pades-b-lt"), &json!("pades-b-t")));
        assert!(!permits(Key::WebhooksAllowedHosts, &json!(["a.example"]), &json!(["b.example"])));
        assert!(permits(Key::DataRegions, &json!(["eu"]), &json!("eu")));
        assert!(!permits(
            Key::LoginPassword,
            &json!({"min_length": 12, "breached_check": true}),
            &json!({"min_length": 14, "breached_check": false})
        ));
    }

    #[test]
    fn loosening_security_is_found_and_tightening_is_not() {
        let old = pol(json!({"login.mfa_required": {"value": "administrators", "locked": true}}));
        let unlock = pol(json!({"login.mfa_required": {"value": "administrators", "locked": false}}));
        let lower = pol(json!({"login.mfa_required": {"value": "optional", "locked": true}}));
        let higher = pol(json!({"login.mfa_required": {"value": "everyone", "locked": true}}));
        assert_eq!(loosened(&old, &unlock), Some(Key::LoginMfaRequired));
        assert_eq!(loosened(&old, &lower), Some(Key::LoginMfaRequired));
        assert_eq!(loosened(&old, &OrgPolicy::default()), Some(Key::LoginMfaRequired));
        assert_eq!(loosened(&old, &higher), None);
        // Defaults are not security: changing them is an admin's.
        let a = pol(json!({"reminders.default": {"value": 1, "locked": true}}));
        assert_eq!(loosened(&a, &OrgPolicy::default()), None);
    }
}
