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
/// `seq` runs 0, 1, 2, … and each `prev` is the previous hash. Returns the head.
///
/// # Errors
///
/// `CS-DB-0014` naming the first event that does not verify.
pub fn verify_admin_chain(events: &[StoredAdminEvent]) -> Result<Option<[u8; 32]>> {
    let mut head: Option<[u8; 32]> = None;
    for (i, e) in events.iter().enumerate() {
        let broken = StoreError::AdminChainBroken { seq: e.seq };
        if u64::try_from(i).ok() != Some(e.seq)
            || e.prev != head
            || Hash256::digest(&e.canonical).as_bytes() != &e.hash
        {
            return Err(broken);
        }
        head = Some(e.hash);
    }
    Ok(head)
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
    /// most `limit` events (1 to [`MAX_PAGE`]).
    ///
    /// # Errors
    ///
    /// `CS-DB-0010` for an unreadable row.
    pub async fn admin_events(
        &mut self,
        after: Option<u64>,
        limit: i64,
    ) -> Result<Vec<StoredAdminEvent>> {
        let acct = self.acct();
        let from = after.map_or(Ok(-1), i64::try_from).unwrap_or(i64::MAX);
        let rows = sqlx::query!(
            "SELECT seq, prev_hash, hash, action, at, canonical FROM admin_events \
             WHERE account_id = $1 AND seq > $2 ORDER BY seq LIMIT $3",
            acct,
            from,
            limit.clamp(1, MAX_PAGE)
        )
        .fetch_all(self.conn())
        .await
        .map_err(db)?;
        rows.into_iter()
            .map(|r| stored(r.seq, r.prev_hash, r.hash, r.action, r.at, r.canonical))
            .collect()
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
        let acct = self.acct();
        let stored =
            sqlx::query_scalar!("SELECT admin_chain_head FROM accounts WHERE id = $1", acct)
                .fetch_one(self.conn())
                .await
                .map_err(db)?;
        if stored.as_deref() != head.as_ref().map(<[u8; 32]>::as_slice) {
            return Err(StoreError::AdminChainBroken {
                seq: all.last().map_or(0, |e| e.seq),
            });
        }
        Ok(all)
    }
}
