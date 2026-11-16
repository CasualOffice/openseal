//! Admin audit logs (ORG-05, ADR-028, docs/23 §2.5): every settings, member, profile,
//! workspace and organization change, in the transaction that makes it.
//!
//! Two logs, separate from envelope evidence and built the same way: `admin_events`,
//! chained per workspace, and `org_admin_events`, chained per organization (migration
//! 0020). Each event is stored as its RFC 8785 canonical bytes, written here with
//! [`casual_sign_audit::jcs`], exactly what its SHA-256 covers. The database recomputes
//! the hash, checks that the columns are what the bytes say and that `seq` and `prev`
//! extend the chain under a lock on the head (`CS-DB-0014`), refuses UPDATE, DELETE and
//! TRUNCATE (`CS-DB-0004`), and refuses to commit a change by the application role to an
//! administered table when the transaction appended no event for it (`CS-DB-0008`,
//! constraint [`ADMIN_EVENT_CONSTRAINT`]).
//!
//! The repositories append the events themselves, so a caller cannot forget one: what a
//! caller supplies is who acts ([`TenantTx::act_as`], [`crate::OrgTx::act_as`]). An event
//! records the actor, the action, target ids, and changed keys with old and new values;
//! secret-looking keys are recorded as `"rotated"`, and names and emails are never
//! recorded (only ids). The actor's IP is personal data (docs/07): never log it.

use casual_sign_audit::json::Value as J;
use casual_sign_audit::{Hash256, Personal, jcs};
use time::OffsetDateTime;

use crate::error::{Result, StoreError, db};
use crate::ids::{AccountId, ApiClientId, OrganizationId, UserId};
use crate::repo::{hash32, opt_hash32};
use crate::store::TenantTx;

/// The constraint a commit violates when it changed an administered table (workspace
/// settings, members, profiles, the workspace itself, the organization, its
/// administrators or permission sets) without appending that change's admin event.
pub const ADMIN_EVENT_CONSTRAINT: &str = "admin_change_has_event";

/// Format of an admin event's canonical bytes.
pub const ADMIN_EVENT_VERSION: u32 = 1;

/// Who made an administrative change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ActorKind {
    /// A staff member, through their session.
    User(UserId),
    /// An API client (personal key or OAuth client).
    ApiClient(ApiClientId),
    /// The server itself: `bootstrap`, migrations of data, tests.
    System,
}

/// The actor of the changes in one transaction, and the request they came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminActor {
    /// Who.
    pub kind: ActorKind,
    /// When (the request's time, supplied by the caller).
    pub at: OffsetDateTime,
    /// The request id, when there is one.
    pub request_id: Option<String>,
    /// The actor's IP address (personal data under docs/07: never logged).
    pub ip: Option<Personal<String>>,
}

impl AdminActor {
    /// The server itself, at `at`.
    #[must_use]
    pub fn system(at: OffsetDateTime) -> Self {
        Self {
            kind: ActorKind::System,
            at,
            request_id: None,
            ip: None,
        }
    }
}

/// One changed key: its old and new values (`None`: absent).
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Change {
    pub key: String,
    pub old: Option<serde_json::Value>,
    pub new: Option<serde_json::Value>,
}

impl Change {
    pub(crate) fn new(
        key: &str,
        old: Option<serde_json::Value>,
        new: Option<serde_json::Value>,
    ) -> Self {
        Self {
            key: key.to_owned(),
            old,
            new,
        }
    }
}

/// An event before it is chained: the action, its targets (name → id) and changes.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct AdminChange {
    pub action: &'static str,
    pub target: Vec<(&'static str, String)>,
    pub changes: Vec<Change>,
}

impl AdminChange {
    pub(crate) fn new(action: &'static str) -> Self {
        Self {
            action,
            target: Vec::new(),
            changes: Vec::new(),
        }
    }

    pub(crate) fn target(mut self, name: &'static str, id: impl ToString) -> Self {
        self.target.push((name, id.to_string()));
        self
    }

    pub(crate) fn change(mut self, c: Change) -> Self {
        self.changes.push(c);
        self
    }
}

/// Whether a settings key holds a secret, whose values are recorded only as `"rotated"`.
fn secret_key(key: &str) -> bool {
    let k = key.to_ascii_lowercase();
    ["secret", "password", "token", "private", "credential"]
        .iter()
        .any(|s| k.contains(s))
}

/// The top-level keys whose values differ between two settings objects, by key.
pub(crate) fn settings_changes(old: &serde_json::Value, new: &serde_json::Value) -> Vec<Change> {
    let empty = serde_json::Map::new();
    let o = old.as_object().unwrap_or(&empty);
    let n = new.as_object().unwrap_or(&empty);
    let mut keys: Vec<&String> = o.keys().chain(n.keys()).collect();
    keys.sort();
    keys.dedup();
    keys.into_iter()
        .filter(|k| o.get(*k) != n.get(*k))
        .map(|k| {
            if secret_key(k) {
                let r = || serde_json::Value::from("rotated");
                Change::new(k, o.get(k).map(|_| r()), n.get(k).map(|_| r()))
            } else {
                Change::new(k, o.get(k).cloned(), n.get(k).cloned())
            }
        })
        .collect()
}

/// A `serde_json` value as the audit crate's tree. Integers beyond 2^53 and other
/// numbers a double cannot hold exactly are written as their decimal text.
fn tree(v: &serde_json::Value) -> J {
    match v {
        serde_json::Value::Null => J::Null,
        serde_json::Value::Bool(b) => J::Bool(*b),
        serde_json::Value::Number(n) => match (n.as_i64(), n.as_u64(), n.as_f64()) {
            (Some(i), _, _) if i.unsigned_abs() <= casual_sign_audit::json::MAX_SAFE_INTEGER => {
                #[allow(clippy::cast_precision_loss)] // Bounded by 2^53 just above.
                J::Number(i as f64)
            }
            (None, Some(_), _) => J::String(n.to_string()),
            (_, _, Some(f)) if f.is_finite() && n.is_f64() => J::Number(f),
            _ => J::String(n.to_string()),
        },
        serde_json::Value::String(s) => J::String(s.clone()),
        serde_json::Value::Array(a) => J::Array(a.iter().map(tree).collect()),
        serde_json::Value::Object(m) => {
            J::Object(m.iter().map(|(k, v)| (k.clone(), tree(v))).collect())
        }
    }
}

fn s(v: impl Into<String>) -> J {
    J::String(v.into())
}

/// Milliseconds since the epoch, bounded to what JSON carries exactly.
fn millis(at: OffsetDateTime) -> Result<u64> {
    let ms = at.unix_timestamp_nanos() / 1_000_000;
    u64::try_from(ms)
        .ok()
        .filter(|m| *m <= casual_sign_audit::json::MAX_SAFE_INTEGER)
        .ok_or(StoreError::Corrupt { column: "at" })
}

/// The event's own time, truncated to the millisecond the bytes state.
fn at_of(ms: u64) -> Result<OffsetDateTime> {
    OffsetDateTime::from_unix_timestamp_nanos(i128::from(ms).saturating_mul(1_000_000))
        .map_err(|_| StoreError::Corrupt { column: "at" })
}

/// Which log an event belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Owner {
    Workspace(AccountId),
    Organization(OrganizationId),
}

/// An event ready to insert: its columns and canonical bytes.
#[derive(Debug, Clone)]
pub(crate) struct Sealed {
    pub seq: i64,
    pub prev: Option<Vec<u8>>,
    pub hash: Vec<u8>,
    pub action: &'static str,
    pub at: OffsetDateTime,
    pub canonical: Vec<u8>,
}

/// Build the canonical bytes of `change` as event `seq` after `prev` in `owner`'s log.
pub(crate) fn seal(
    owner: Owner,
    seq: i64,
    prev: Option<Vec<u8>>,
    actor: &AdminActor,
    change: &AdminChange,
) -> Result<Sealed> {
    let broken = StoreError::AdminChainBroken {
        seq: u64::try_from(seq).unwrap_or(0),
    };
    let ms = millis(actor.at)?;
    let seq_u = u64::try_from(seq).map_err(|_| broken.clone())?;
    if seq_u > casual_sign_audit::json::MAX_SAFE_INTEGER {
        return Err(broken);
    }
    let (owner_key, owner_id) = match owner {
        Owner::Workspace(a) => ("account", a.0),
        Owner::Organization(o) => ("organization", o.0),
    };
    let actor_v = match actor.kind {
        ActorKind::User(u) => J::Object(vec![
            ("kind".into(), s("user")),
            ("id".into(), s(u.to_string())),
        ]),
        ActorKind::ApiClient(c) => J::Object(vec![
            ("kind".into(), s("api_client")),
            ("id".into(), s(c.to_string())),
        ]),
        ActorKind::System => J::Object(vec![("kind".into(), s("system"))]),
    };
    #[allow(clippy::cast_precision_loss)] // Both bounded by 2^53 above.
    let mut members = vec![
        ("v".to_owned(), J::Number(f64::from(ADMIN_EVENT_VERSION))),
        (owner_key.to_owned(), s(owner_id.to_string())),
        ("seq".to_owned(), J::Number(seq_u as f64)),
        (
            "prev".to_owned(),
            prev.as_ref().map_or(J::Null, |p| s(hex(p))),
        ),
        ("at".to_owned(), J::Number(ms as f64)),
        ("actor".to_owned(), actor_v),
        ("action".to_owned(), s(change.action)),
        (
            "target".to_owned(),
            J::Object(
                change
                    .target
                    .iter()
                    .map(|(k, v)| ((*k).to_owned(), s(v.clone())))
                    .collect(),
            ),
        ),
        (
            "changes".to_owned(),
            J::Array(
                change
                    .changes
                    .iter()
                    .map(|c| {
                        J::Object(vec![
                            ("key".into(), s(c.key.clone())),
                            ("old".into(), c.old.as_ref().map_or(J::Null, tree)),
                            ("new".into(), c.new.as_ref().map_or(J::Null, tree)),
                        ])
                    })
                    .collect(),
            ),
        ),
    ];
    if let Some(r) = &actor.request_id {
        members.push(("request_id".to_owned(), s(r.clone())));
    }
    if let Some(ip) = &actor.ip {
        members.push(("ip".to_owned(), s(ip.get().clone())));
    }
    let canonical = jcs::to_vec(&J::Object(members)).map_err(|_| broken)?;
    let hash = Hash256::digest(&canonical).as_bytes().to_vec();
    Ok(Sealed {
        seq,
        prev,
        hash,
        action: change.action,
        at: at_of(ms)?,
        canonical,
    })
}

fn hex(b: &[u8]) -> String {
    use core::fmt::Write as _;
    b.iter().fold(
        String::with_capacity(b.len().saturating_mul(2)),
        |mut s, x| {
            let _ = write!(s, "{x:02x}");
            s
        },
    )
}

/// An admin event as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredAdminEvent {
    /// Position in its chain.
    pub seq: u64,
    /// The previous event's hash.
    pub prev: Option<[u8; 32]>,
    /// This event's hash: SHA-256 of `canonical`.
    pub hash: [u8; 32],
    /// The action (`workspace.settings_changed`, `member.added`, ...).
    pub action: String,
    /// The event's own time.
    pub at: OffsetDateTime,
    /// The RFC 8785 canonical bytes (may hold the actor's IP: never log).
    pub canonical: Vec<u8>,
}

/// Re-check a stored chain from its first event: each hash is SHA-256 of its bytes,
/// the `at` column is the instant the bytes state, `seq` runs 0, 1, 2, … and each `prev`
/// is the previous hash. Returns the head.
///
/// # Errors
///
/// `CS-DB-0014` naming the first event that does not verify.
pub fn verify_admin_chain(events: &[StoredAdminEvent]) -> Result<Option<[u8; 32]>> {
    verify_segment(0, None, events)
}

/// Re-check one stretch of a chain: `events` must be `seq` `start`, `start + 1`, … with
/// the first linked to `prev`. Returns the hash of the last (or `prev` when empty).
fn verify_segment(
    start: u64,
    prev: Option<[u8; 32]>,
    events: &[StoredAdminEvent],
) -> Result<Option<[u8; 32]>> {
    let mut head = prev;
    let mut want = Some(start);
    for e in events {
        if want != Some(e.seq) || e.prev != head {
            return Err(StoreError::AdminChainBroken { seq: e.seq });
        }
        verify_event(e)?;
        head = Some(e.hash);
        want = e.seq.checked_add(1);
    }
    Ok(head)
}

/// One event on its own: its hash is SHA-256 of its bytes, and its `at` column is the
/// millisecond the bytes state (the column is what the API serves).
fn verify_event(e: &StoredAdminEvent) -> Result<()> {
    let broken = StoreError::AdminChainBroken { seq: e.seq };
    if Hash256::digest(&e.canonical).as_bytes() != &e.hash {
        return Err(broken);
    }
    match stated_at(&e.canonical).map(at_of) {
        Some(Ok(at)) if at == e.at => Ok(()),
        _ => Err(broken),
    }
}

/// The `at` an event's bytes state, read as migration 0020's check reads it: the top
/// level is an object stating `at` once, as a whole number. Every other value is skipped
/// without being interpreted, so bytes the database accepted (a number beyond `f64`,
/// nesting deeper than serde_json's own limit) cannot make a stored event unverifiable.
/// `None` when the bytes state no such `at`.
fn stated_at(canonical: &[u8]) -> Option<u64> {
    use serde::de::{Deserializer as _, IgnoredAny, MapAccess, Visitor};

    struct At;
    impl<'de> Visitor<'de> for At {
        type Value = Option<u64>;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("an admin event object")
        }
        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Option<u64>, A::Error> {
            let (mut at, mut twice) = (None, false);
            while let Some(key) = map.next_key::<String>()? {
                if key == "at" {
                    twice |= at.is_some();
                    at = Some(map.next_value::<u64>()?);
                } else {
                    map.next_value::<IgnoredAny>()?;
                }
            }
            Ok(if twice { None } else { at })
        }
    }
    let mut de = serde_json::Deserializer::from_slice(canonical);
    let at = de.deserialize_map(At).ok().flatten()?;
    de.end().ok().map(|()| at)
}

/// Verify one page of a log as it is read (docs/23 §2.5), so that walking the whole log
/// by cursor checks every link once rather than re-reading the log for every page.
///
/// `rows` is what the query returned from `seq` `after` inclusive (or from the start),
/// at most `limit` events after it. The event at `after` is the anchor: its own hash
/// and time are checked and the page must link to it (its link to its own predecessor
/// was checked when the page holding it was read). A short page is the end of the log,
/// whose last hash must be `stored_head`. Returns the page without the anchor.
pub(crate) fn verify_page(
    after: Option<u64>,
    rows: Vec<StoredAdminEvent>,
    limit: usize,
    stored_head: Option<&[u8]>,
) -> Result<Vec<StoredAdminEvent>> {
    let (start, prev, page) = match after {
        None => (0, None, rows),
        Some(c) => {
            let mut it = rows.into_iter();
            let Some(anchor) = it.next() else {
                // The cursor is past the end: nothing to show.
                return Ok(Vec::new());
            };
            if anchor.seq != c {
                return Err(StoreError::AdminChainBroken { seq: c });
            }
            verify_event(&anchor)?;
            let Some(start) = c.checked_add(1) else {
                return Ok(Vec::new());
            };
            (start, Some(anchor.hash), it.collect::<Vec<_>>())
        }
    };
    let head = verify_segment(start, prev, &page)?;
    if page.len() < limit && stored_head != head.as_ref().map(<[u8; 32]>::as_slice) {
        return Err(StoreError::AdminChainBroken {
            seq: page.last().map_or(start.saturating_sub(1), |e| e.seq),
        });
    }
    Ok(page)
}

/// The `seq` from which a verified page reads (inclusive of its anchor), as the
/// exclusive bound the queries take, and how many rows: the anchor and `limit` more.
/// `None` when the cursor is beyond any `seq` a log can hold.
pub(crate) fn page_bounds(after: Option<u64>, limit: i64) -> Option<(i64, i64)> {
    let limit = limit.clamp(1, MAX_PAGE);
    match after {
        None => Some((-1, limit)),
        Some(c) => {
            let c = i64::try_from(c).ok()?;
            Some((c.checked_sub(1)?, limit.checked_add(1)?))
        }
    }
}

pub(crate) fn stored(
    seq: i64,
    prev: Option<Vec<u8>>,
    hash: Vec<u8>,
    action: String,
    at: OffsetDateTime,
    canonical: Vec<u8>,
) -> Result<StoredAdminEvent> {
    Ok(StoredAdminEvent {
        seq: u64::try_from(seq).map_err(|_| StoreError::Corrupt { column: "seq" })?,
        prev: opt_hash32(prev, "prev_hash")?,
        hash: hash32(hash, "hash")?,
        action,
        at,
        canonical,
    })
}

/// Map an insert's error: a broken chain keeps its `seq`.
pub(crate) fn append_error(seq: i64) -> impl Fn(sqlx::Error) -> StoreError {
    move |e| StoreError::from_sqlx(&e, u64::try_from(seq).ok())
}

/// Most events one page of a log returns.
pub const MAX_PAGE: i64 = 1000;

/// What kind of upload a malware scan judged (ASVS-11).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum UploadKind {
    /// A document added to an envelope.
    Document,
    /// A document added to a template.
    TemplateDocument,
    /// A file a signer attached to an attachment field.
    Attachment,
    /// A signature or initials image a recipient adopted.
    SignatureImage,
    /// A signature or initials image a staff user saved to their profile.
    ProfileMark,
}

impl UploadKind {
    /// The name recorded in the event.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Document => "document",
            Self::TemplateDocument => "template_document",
            Self::Attachment => "attachment",
            Self::SignatureImage => "signature_image",
            Self::ProfileMark => "profile_mark",
        }
    }
}

/// The scan outcomes an admin event records (ASVS-11). A clean scan of a document is
/// recorded in its admission report, which the envelope's chain binds; these are the
/// others.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum UploadScreening {
    /// The scanner found malware; the upload was refused and nothing of it stored.
    MalwareRefused {
        /// The scanner's signature name (printable ASCII, at most 128 characters).
        signature: String,
    },
    /// The scanner could not judge the file (`reason`: `connect`, `timeout`,
    /// `too_large`, `error` or `protocol`) and the server, failing closed, refused it.
    UnscannedRefused {
        /// Why the scan did not complete.
        reason: &'static str,
    },
    /// The scanner could not judge the file and the operator's fail-open switch let it
    /// in unscanned.
    UnscannedAdmitted {
        /// Why the scan did not complete.
        reason: &'static str,
    },
}

impl UploadScreening {
    /// The admin-log action of this outcome.
    #[must_use]
    pub fn action(&self) -> &'static str {
        match self {
            Self::MalwareRefused { .. } => "upload.malware_refused",
            Self::UnscannedRefused { .. } => "upload.unscanned_refused",
            Self::UnscannedAdmitted { .. } => "upload.unscanned_admitted",
        }
    }
}

/// A scanned upload worth recording: its kind, what it was for (ids by name), its
/// SHA-256 and length, and the outcome. Never its name or content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScreenedUpload {
    /// What kind of upload.
    pub kind: UploadKind,
    /// The objects it was for, by name (`envelope`, `template`, `recipient`, `field`,
    /// `user`): ids only.
    pub target: Vec<(&'static str, String)>,
    /// SHA-256 of the bytes as uploaded.
    pub sha256: [u8; 32],
    /// Their length.
    pub bytes: u64,
    /// The outcome.
    pub outcome: UploadScreening,
}

impl TenantTx {
    /// Append a malware-scan outcome to this workspace's admin log (ASVS-11):
    /// `upload.malware_refused`, `upload.unscanned_refused` or
    /// `upload.unscanned_admitted`, naming the upload's kind and targets, its SHA-256
    /// and length, and the signature found or the reason it was not scanned. The caller
    /// commits it in a transaction of its own, so a refusal stays recorded although the
    /// request that carried the upload is rolled back.
    ///
    /// # Errors
    ///
    /// `CS-DB-0014` when the chain cannot be extended; `CS-DB-0001`.
    pub async fn record_upload_screening(&mut self, u: &ScreenedUpload) -> Result<()> {
        let mut change = AdminChange::new(u.outcome.action()).target("kind", u.kind.as_str());
        for (name, id) in &u.target {
            change = change.target(name, id);
        }
        let (key, value) = match &u.outcome {
            UploadScreening::MalwareRefused { signature } => ("signature", signature.clone()),
            UploadScreening::UnscannedRefused { reason }
            | UploadScreening::UnscannedAdmitted { reason } => ("reason", (*reason).to_owned()),
        };
        change = change
            .change(Change::new(key, None, Some(serde_json::Value::from(value))))
            .change(Change::new(
                "sha256",
                None,
                Some(serde_json::Value::from(hex(&u.sha256))),
            ))
            .change(Change::new(
                "bytes",
                None,
                Some(serde_json::Value::from(u.bytes)),
            ));
        self.admin_event(change).await
    }
}

impl TenantTx {
    /// Who acts in this transaction: every admin event it appends records them. Without
    /// it, events record the server itself ([`ActorKind::System`]).
    pub fn act_as(&mut self, actor: AdminActor) {
        self.actor = Some(actor);
    }

    pub(crate) fn actor(&self) -> AdminActor {
        self.actor
            .clone()
            .unwrap_or_else(|| AdminActor::system(OffsetDateTime::now_utc()))
    }

    /// Append `change` to this workspace's admin log.
    pub(crate) async fn admin_event(&mut self, change: AdminChange) -> Result<()> {
        let tip =
            sqlx::query!(r#"SELECT next_seq AS "next_seq!", head FROM openseal_admin_chain_tip()"#)
                .fetch_one(self.conn())
                .await
                .map_err(db)?;
        let actor = self.actor();
        let e = seal(
            Owner::Workspace(self.account_id()),
            tip.next_seq,
            tip.head,
            &actor,
            &change,
        )?;
        let acct = self.acct();
        sqlx::query!(
            "INSERT INTO admin_events (account_id, seq, prev_hash, hash, action, at, canonical) \
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
            acct,
            e.seq,
            e.prev,
            e.hash,
            e.action,
            e.at,
            e.canonical
        )
        .execute(self.conn())
        .await
        .map_err(append_error(e.seq))?;
        Ok(())
    }

    /// Append `change` to the log of this workspace's organization (docs/23 §2.5: an
    /// event the organization must see), through the definer that derives it.
    pub(crate) async fn org_admin_event(&mut self, change: AdminChange) -> Result<()> {
        let tip = sqlx::query!(
            r#"SELECT organization_id AS "organization_id!", next_seq AS "next_seq!", head
               FROM openseal_org_chain_tip()"#
        )
        .fetch_optional(self.conn())
        .await
        .map_err(db)?
        .ok_or(StoreError::NotFound {
            entity: "organization",
        })?;
        let actor = self.actor();
        let e = seal(
            Owner::Organization(OrganizationId(tip.organization_id)),
            tip.next_seq,
            tip.head,
            &actor,
            &change,
        )?;
        sqlx::query!(
            "SELECT openseal_append_org_event($1, $2, $3, $4, $5, $6)",
            e.seq,
            e.prev,
            e.hash,
            e.action,
            e.at,
            e.canonical
        )
        .fetch_one(self.conn())
        .await
        .map_err(append_error(e.seq))?;
        Ok(())
    }

    /// This workspace's admin log, from `after` (exclusive; `None` from the start), at
    /// most `limit` events (1 to [`MAX_PAGE`]), as stored, unverified.
    ///
    /// # Errors
    ///
    /// `CS-DB-0010` for an unreadable row.
    pub async fn admin_events(
        &mut self,
        after: Option<u64>,
        limit: i64,
    ) -> Result<Vec<StoredAdminEvent>> {
        let from = after.map_or(Ok(-1), i64::try_from).unwrap_or(i64::MAX);
        self.admin_rows(from, limit.clamp(1, MAX_PAGE)).await
    }

    async fn admin_rows(&mut self, from: i64, limit: i64) -> Result<Vec<StoredAdminEvent>> {
        let acct = self.acct();
        let rows = sqlx::query!(
            "SELECT seq, prev_hash, hash, action, at, canonical FROM admin_events \
             WHERE account_id = $1 AND seq > $2 ORDER BY seq LIMIT $3",
            acct,
            from,
            limit
        )
        .fetch_all(self.conn())
        .await
        .map_err(db)?;
        rows.into_iter()
            .map(|r| stored(r.seq, r.prev_hash, r.hash, r.action, r.at, r.canonical))
            .collect()
    }

    async fn admin_head(&mut self) -> Result<Option<Vec<u8>>> {
        let acct = self.acct();
        sqlx::query_scalar!("SELECT admin_chain_head FROM accounts WHERE id = $1", acct)
            .fetch_one(self.conn())
            .await
            .map_err(db)
    }

    /// One page of this workspace's admin log, as [`Self::admin_events`], verified as it
    /// is read: each event against the one before it (the event at `after` included),
    /// and the last page against the stored head. Walking the log by cursor so checks
    /// every link once; [`Self::verified_admin_log`] re-checks the whole log at once.
    ///
    /// # Errors
    ///
    /// `CS-DB-0014` naming the first event that does not verify; `CS-DB-0010` for an
    /// unreadable row.
    pub async fn verified_admin_events(
        &mut self,
        after: Option<u64>,
        limit: i64,
    ) -> Result<Vec<StoredAdminEvent>> {
        let Some((from, rows)) = page_bounds(after, limit) else {
            return Ok(Vec::new());
        };
        let page = self.admin_rows(from, rows).await?;
        let head = self.admin_head().await?;
        let limit = usize::try_from(limit.clamp(1, MAX_PAGE)).unwrap_or(usize::MAX);
        verify_page(after, page, limit, head.as_deref())
    }

    /// This workspace's whole admin log, re-verified ([`verify_admin_chain`]); the
    /// stored head must be the last event's hash.
    ///
    /// # Errors
    ///
    /// `CS-DB-0014` naming the first event that does not verify.
    pub async fn verified_admin_log(&mut self) -> Result<Vec<StoredAdminEvent>> {
        let mut all = Vec::new();
        let mut after = None;
        loop {
            let page = self.admin_events(after, MAX_PAGE).await?;
            let Some(last) = page.last() else { break };
            after = Some(last.seq);
            all.extend(page);
        }
        let head = verify_admin_chain(&all)?;
        let stored = self.admin_head().await?;
        if stored.as_deref() != head.as_ref().map(<[u8; 32]>::as_slice) {
            return Err(StoreError::AdminChainBroken {
                seq: all.last().map_or(0, |e| e.seq),
            });
        }
        Ok(all)
    }
}
