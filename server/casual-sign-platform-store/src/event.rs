//! The operator log's events: their canonical bytes and the chain check (docs/23 §5.1).
//!
//! An event is RFC 8785 canonical JSON made by `casual-sign-audit`, hashed with SHA-256,
//! and chained by `seq` and `prev` like every other OpenSeal chain. It records who (the
//! operator id), what (the action and the ids it touched), when, the request id and the
//! operator's own address. It never records an organization or workspace name, an e-mail,
//! a person's name, a document or a field value: targets and details are ids, codes,
//! labels and counts, and [`EventDraft`] accepts only values of those shapes.

use casual_sign_audit::Hash256;
use casual_sign_audit::json::{self, Value};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use uuid::Uuid;

use crate::error::{PlatformError, Result};

/// The format version written into every event.
pub const EVENT_VERSION: u64 = 1;

/// Largest canonical event (bytes); the table's check is the same.
pub const MAX_EVENT_BYTES: usize = 65_536;

/// Most targets or details on one event.
pub const MAX_EVENT_ITEMS: usize = 32;

/// A value an event may carry: an id, a short code or label, or a count. Never free text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Detail {
    /// An id.
    Id(Uuid),
    /// A code or label: 1 to 64 characters of `[A-Za-z0-9_.:-]`.
    Code(String),
    /// A list of codes or labels.
    Codes(Vec<String>),
    /// A count.
    Count(u32),
    /// A flag.
    Flag(bool),
}

/// Whether `s` is a code or label an event may carry.
#[must_use]
pub fn is_code(s: &str) -> bool {
    (1..=64).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b':' | b'-'))
}

impl Detail {
    fn value(&self) -> Result<Value> {
        let bad = || PlatformError::Invalid {
            sqlstate: "22023".into(),
        };
        Ok(match self {
            Self::Id(id) => Value::String(id.to_string()),
            Self::Code(s) if is_code(s) => Value::String(s.clone()),
            Self::Code(_) => return Err(bad()),
            Self::Codes(list)
                if list.len() <= MAX_EVENT_ITEMS && list.iter().all(|s| is_code(s)) =>
            {
                Value::Array(list.iter().map(|s| Value::String(s.clone())).collect())
            }
            Self::Codes(_) => return Err(bad()),
            Self::Count(n) => Value::Number(f64::from(*n)),
            Self::Flag(b) => Value::Bool(*b),
        })
    }
}

/// An event before it is placed on the chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventDraft {
    /// `operator.*`, lower case.
    pub action: String,
    /// The acting operator, when one is signed in.
    pub operator: Option<Uuid>,
    /// When it happened (supplied by the caller's clock).
    pub at: OffsetDateTime,
    /// The request that caused it.
    pub request: Option<Uuid>,
    /// The operator's address.
    pub ip: Option<String>,
    /// Named details: ids, codes, labels, counts.
    pub details: Vec<(&'static str, Detail)>,
}

impl EventDraft {
    /// A draft for `action` by `operator` at `at`.
    #[must_use]
    pub fn new(action: &str, operator: Option<Uuid>, at: OffsetDateTime) -> Self {
        Self {
            action: action.to_owned(),
            operator,
            at,
            request: None,
            ip: None,
            details: Vec::new(),
        }
    }

    /// With a detail.
    #[must_use]
    pub fn with(mut self, name: &'static str, detail: Detail) -> Self {
        self.details.push((name, detail));
        self
    }

    /// With the request id and the operator's address.
    #[must_use]
    pub fn from_request(mut self, request: Uuid, ip: Option<String>) -> Self {
        self.request = Some(request);
        self.ip = ip;
        self
    }

    /// The canonical bytes of this event at `seq` after `prev`.
    ///
    /// # Errors
    /// `CS-DB-0008` when the action, a detail or the address has the wrong shape, or the
    /// event is too large.
    pub fn canonical(&self, seq: u64, prev: Option<&Hash256>) -> Result<Vec<u8>> {
        let bad = || PlatformError::Invalid {
            sqlstate: "22023".into(),
        };
        let action_ok = self
            .action
            .strip_prefix("operator.")
            .is_some_and(|rest| !rest.is_empty() && rest.len() <= 63 && is_code(rest));
        if !action_ok
            || self.action.bytes().any(|b| b.is_ascii_uppercase())
            || self.details.len() > MAX_EVENT_ITEMS
            || self
                .ip
                .as_ref()
                .is_some_and(|ip| ip.len() > 64 || !is_code(ip))
        {
            return Err(bad());
        }
        let mut details = Vec::with_capacity(self.details.len());
        for (k, v) in &self.details {
            if !is_code(k) || details.iter().any(|(n, _): &(String, Value)| n == k) {
                return Err(bad());
            }
            details.push(((*k).to_owned(), v.value()?));
        }
        let opt = |s: Option<String>| s.map_or(Value::Null, Value::String);
        let at = self.at.format(&Rfc3339).map_err(|_| bad())?;
        let value = Value::Object(vec![
            ("v".into(), Value::Number(EVENT_VERSION as f64)),
            ("seq".into(), number(seq)?),
            ("prev".into(), opt(prev.map(Hash256::hex))),
            ("at".into(), Value::String(at)),
            ("action".into(), Value::String(self.action.clone())),
            ("operator".into(), opt(self.operator.map(|u| u.to_string()))),
            ("request".into(), opt(self.request.map(|u| u.to_string()))),
            ("ip".into(), opt(self.ip.clone())),
            ("details".into(), Value::Object(details)),
        ]);
        let bytes = casual_sign_audit::jcs::to_vec(&value).map_err(|_| bad())?;
        if bytes.len() > MAX_EVENT_BYTES {
            return Err(bad());
        }
        Ok(bytes)
    }
}

/// `n` as a JSON number, refusing one beyond 2^53 − 1.
fn number(n: u64) -> Result<Value> {
    const MAX_SAFE: u64 = (1 << 53) - 1;
    if n > MAX_SAFE {
        return Err(PlatformError::Invalid {
            sqlstate: "22003".into(),
        });
    }
    // Exact: n is at most 2^53 − 1.
    #[allow(clippy::cast_precision_loss)] // checked above: every value up to 2^53 − 1 is exact
    Ok(Value::Number(n as f64))
}

/// One stored event, as read back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredEvent {
    /// Position in the chain, from 0.
    pub seq: u64,
    /// The previous event's hash; `None` for the first.
    pub prev: Option<Hash256>,
    /// SHA-256 of `canonical`.
    pub hash: Hash256,
    /// The action.
    pub action: String,
    /// The operator.
    pub operator: Option<Uuid>,
    /// When it happened.
    pub at: OffsetDateTime,
    /// The canonical bytes.
    pub canonical: Vec<u8>,
}

/// What a verification found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainReport {
    /// Events checked.
    pub events: u64,
    /// The last event's hash.
    pub head: Option<Hash256>,
}

/// Incremental verifier: feed events in `seq` order from 0.
#[derive(Debug, Clone, Default)]
pub struct ChainVerifier {
    next: u64,
    head: Option<Hash256>,
}

impl ChainVerifier {
    /// Check the next event: its hash is its bytes', its `seq` and `prev` extend the
    /// chain, and its canonical JSON names the same seq, prev, action and operator.
    ///
    /// # Errors
    /// `CS-CON-0007` naming the event's `seq`.
    pub fn push(&mut self, e: &StoredEvent) -> Result<()> {
        let broken = || PlatformError::LogBroken { seq: e.seq };
        if e.seq != self.next || e.prev != self.head || Hash256::digest(&e.canonical) != e.hash {
            return Err(broken());
        }
        let body = json::parse(&e.canonical, 4).map_err(|_| broken())?;
        if casual_sign_audit::jcs::to_vec(&body).map_err(|_| broken())? != e.canonical {
            return Err(broken());
        }
        let text = |k: &str| body.get(k).and_then(Value::as_str).map(str::to_owned);
        let same = body.get("seq").and_then(Value::as_safe_u64) == Some(e.seq)
            && text("prev") == e.prev.as_ref().map(Hash256::hex)
            && text("action").as_deref() == Some(e.action.as_str())
            && text("operator") == e.operator.map(|u| u.to_string())
            && body.get("v").and_then(Value::as_safe_u64) == Some(EVENT_VERSION);
        if !same {
            return Err(broken());
        }
        self.next = self.next.checked_add(1).ok_or_else(broken)?;
        self.head = Some(e.hash);
        Ok(())
    }

    /// The result so far, checked against the stored head `expected`.
    ///
    /// # Errors
    /// `CS-CON-0007` when the stored head is not the last event's hash (an event was
    /// removed from the end).
    pub fn finish(&self, expected: Option<Hash256>) -> Result<ChainReport> {
        if expected != self.head {
            return Err(PlatformError::LogBroken { seq: self.next });
        }
        Ok(ChainReport {
            events: self.next,
            head: self.head,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)] // tests may unwrap (CLAUDE.md)
mod tests {
    use super::*;

    fn at() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap()
    }

    fn stored(seq: u64, prev: Option<Hash256>, d: &EventDraft) -> StoredEvent {
        let canonical = d.canonical(seq, prev.as_ref()).unwrap();
        StoredEvent {
            seq,
            prev,
            hash: Hash256::digest(&canonical),
            action: d.action.clone(),
            operator: d.operator,
            at: d.at,
            canonical,
        }
    }

    #[test]
    fn canonical_bytes_are_sorted_and_carry_only_ids_and_codes() {
        let op = Uuid::from_u128(7);
        let d = EventDraft::new("operator.organization.renamed", Some(op), at())
            .with("organization", Detail::Id(Uuid::from_u128(9)))
            .from_request(Uuid::from_u128(1), Some("127.0.0.1".into()));
        let text = String::from_utf8(d.canonical(0, None).unwrap()).unwrap();
        assert_eq!(
            text,
            "{\"action\":\"operator.organization.renamed\",\"at\":\"2027-01-15T08:00:00Z\",\
             \"details\":{\"organization\":\"00000000-0000-0000-0000-000000000009\"},\
             \"ip\":\"127.0.0.1\",\"operator\":\"00000000-0000-0000-0000-000000000007\",\
             \"prev\":null,\"request\":\"00000000-0000-0000-0000-000000000001\",\"seq\":0,\"v\":1}"
        );
    }

    #[test]
    fn free_text_is_refused_in_details_actions_and_addresses() {
        let base = EventDraft::new("operator.x", None, at());
        for d in [
            base.clone().with("name", Detail::Code("Acme Corp".into())),
            base.clone()
                .with("email", Detail::Code("a@example.com".into())),
            base.clone()
                .with("labels", Detail::Codes(vec!["eu".into(), "j doe".into()])),
            EventDraft::new("organization.renamed", None, at()),
            EventDraft::new("operator.Renamed", None, at()),
            base.clone().from_request(Uuid::nil(), Some("x y".into())),
            base.clone()
                .with("a", Detail::Count(1))
                .with("a", Detail::Count(2)),
        ] {
            assert_eq!(
                d.canonical(0, None).unwrap_err().code(),
                "CS-DB-0008",
                "{d:?}"
            );
        }
    }

    #[test]
    fn the_verifier_accepts_a_chain_and_names_the_first_bad_event() {
        let d = EventDraft::new("operator.signed_in", Some(Uuid::from_u128(3)), at());
        let e0 = stored(0, None, &d);
        let e1 = stored(1, Some(e0.hash), &d);
        let e2 = stored(2, Some(e1.hash), &d);
        let mut v = ChainVerifier::default();
        for e in [&e0, &e1, &e2] {
            v.push(e).unwrap();
        }
        assert_eq!(v.finish(Some(e2.hash)).unwrap().events, 3);
        // Head ahead of the events: the last one was removed.
        assert_eq!(
            v.finish(Some(Hash256::digest(b"x"))).unwrap_err(),
            PlatformError::LogBroken { seq: 3 }
        );

        // A rewritten event (bytes and hash recomputed) breaks the next link.
        let mut forged = stored(
            1,
            Some(e0.hash),
            &EventDraft::new("operator.other", None, at()),
        );
        forged.seq = 1;
        let mut v = ChainVerifier::default();
        v.push(&e0).unwrap();
        v.push(&forged).unwrap();
        assert_eq!(
            v.push(&e2).unwrap_err(),
            PlatformError::LogBroken { seq: 2 }
        );

        // Columns that disagree with the bytes.
        let mut lying = e1.clone();
        lying.action = "operator.else".into();
        let mut v = ChainVerifier::default();
        v.push(&e0).unwrap();
        assert_eq!(
            v.push(&lying).unwrap_err(),
            PlatformError::LogBroken { seq: 1 }
        );

        // Changed bytes with the old hash.
        let mut tampered = e1.clone();
        tampered.canonical[2] ^= 1;
        let mut v = ChainVerifier::default();
        v.push(&e0).unwrap();
        assert_eq!(
            v.push(&tampered).unwrap_err(),
            PlatformError::LogBroken { seq: 1 }
        );
    }
}
