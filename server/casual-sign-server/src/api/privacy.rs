//! Personal-data controls (ASVS-16, ASVS-18; ASVS 8.3.2, 8.3.8; docs/40 §3 Privacy and
//! retention, docs/07 §Data classification).
//!
//! - `GET /users/me/export`: the signed-in member's own data in this workspace, as one
//!   JSON document. Rate-limited per user; logged as a `data.document_read` security
//!   event (it reads personal data).
//! - `DELETE /users/me` and `POST /users/{id}/erase`: erase a member's identity (the
//!   person themselves, or an administrator), after a recent re-authentication.
//! - `GET`/`PUT /retention`, `GET /retention/preview`: the account's retention rules and
//!   the retention job's dry run.
//! - `PUT`/`DELETE /envelopes/{id}/legal-hold`, `POST /envelopes/{id}/purge`: holds,
//!   and a controller's request to purge one envelope now (a signer's erasure request
//!   is made to the account that sent them the envelope, which decides).
//!
//! **What erasure and purge keep.** Evidence is never altered: audit events, the admin
//! logs, tombstones and sealed bytes stay as they are (docs/32 §1, §7). An erased
//! member's name and email in the audit events of envelopes they acted on, and their id
//! in the admin logs, stay inside hashed, append-only chains; the erasure is itself an
//! admin event (`member.erased`) and a purge an audit event (`envelope.purged`). Nothing
//! here claims any legal effect (docs/09).

use std::collections::BTreeMap;

use axum::body::Bytes;
use axum::extract::Path;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use casual_sign_model::Text;
use casual_sign_store::repo::privacy::{DataClass, MAX_KEEP_DAYS};
use casual_sign_store::{AccountId, EnvelopeId, UserId};
use casual_sign_workflow::{Command, Principal as WfPrincipal};
use serde::Deserialize;
use serde_json::{Value, json};

use super::envelopes::rfc3339;
use super::{json, path_id};
use crate::apply::{eid, run};
use crate::auth::Credential;
use crate::call::Call;
use crate::dto::parse;
use crate::error::ApiError;
use crate::state::AppState;

/// Exports per user per minute: an export reads every record of theirs.
pub const EXPORTS_PER_MINUTE: u32 = 3;

/// Envelopes a dry run lists by id (the counts cover all of them).
const PREVIEW_LIMIT: i64 = 100;

fn rate_limit(c: &Call) -> Result<(), ApiError> {
    let d = c.st.0.limiter.hit(
        &format!("export:{}", c.p.user),
        EXPORTS_PER_MINUTE,
        c.st.now(),
    );
    if d.allowed {
        Ok(())
    } else {
        Err(ApiError::rate_limited(d.reset_secs))
    }
}

/// `GET /users/me/export` (ASVS-16): the caller's own data in this workspace, as one
/// JSON document `{format: "openseal.personal-data-export", v: 1, exported_at,
/// workspace, user, profile, sessions, api_clients, envelopes, templates, kept}`: their
/// profile (name, email, notices, saved signature and initials as base64), their
/// sessions here, the API clients they own, the envelopes they sent (ids, statuses,
/// subjects, times, and the routes that serve each one's documents, certificate and
/// audit trail, each authorized and logged per object), the templates they own, and what
/// is kept and where. Nothing of another workspace or another member.
pub(crate) async fn export(c: Call) -> Result<Response, ApiError> {
    rate_limit(&c)?;
    let mut tx = c.tx().await?;
    let me = super::admin::me_json(&c, &mut tx).await?;
    let account = tx.account().get().await?;
    let member = tx
        .users()
        .get(c.p.user)
        .await?
        .ok_or_else(ApiError::not_found)?;
    let profile = tx.users().profile(member.permission_profile_id).await?;
    let sessions: Vec<Value> = match c.p.credential {
        Credential::Session(s) => tx
            .sessions()
            .own_sessions(s, c.st.now())
            .await?
            .into_iter()
            .filter(|x| x.account_id == c.p.account)
            .map(|x| {
                json!({
                    "id": x.id.to_string(), "method": x.method.as_str(), "client": x.client_label,
                    "created_at": rfc3339(x.created_at), "last_seen_at": rfc3339(x.last_seen_at),
                    "expires_at": rfc3339(x.expires_at),
                })
            })
            .collect(),
        _ => Vec::new(),
    };
    let clients: Vec<Value> = tx
        .api_clients()
        .list()
        .await?
        .into_iter()
        .filter(|k| k.owner_user_id == Some(c.p.user))
        .map(|k| {
            json!({
                "id": k.id.to_string(), "kind": k.kind.as_str(), "name": k.name,
                "key_prefix": k.key_prefix, "scopes": k.scopes,
                "expires_at": k.expires_at.map(rfc3339), "revoked": k.revoked_at.is_some(),
            })
        })
        .collect();
    let envelopes: Vec<Value> = tx
        .privacy()
        .sent_by(c.p.user)
        .await?
        .into_iter()
        .map(|e| {
            let base = format!("/api/v1/envelopes/{}", e.id.0);
            json!({
                "id": e.id.to_string(), "status": e.status, "subject": e.subject,
                "created_at": rfc3339(e.created_at), "updated_at": rfc3339(e.updated_at),
                "completed_at": e.completed_at.map(rfc3339), "purged": e.purged,
                "links": if e.purged { json!({}) } else { json!({
                    "envelope": base, "documents": format!("{base}/documents"),
                    "certificate": format!("{base}/certificate"), "audit": format!("{base}/audit"),
                }) },
            })
        })
        .collect();
    let templates: Vec<Value> = tx
        .privacy()
        .templates_of(c.p.user)
        .await?
        .into_iter()
        .map(|t| json!({"id": t.id.to_string(), "name": t.name, "created_at": rfc3339(t.created_at)}))
        .collect();
    tx.commit().await?;
    let body = json!({
        "format": "openseal.personal-data-export",
        "v": 1,
        "exported_at": rfc3339(c.st.now()),
        "workspace": { "id": account.id.to_string(), "name": account.name },
        "user": me,
        "login_kind": member.login_kind.as_str(),
        "profile": profile.map(|p| json!({"id": p.id.to_string(), "name": p.name})),
        "sessions": sessions,
        "api_clients": clients,
        "envelopes": envelopes,
        "templates": templates,
        "kept": KEPT,
    });
    Ok(json(StatusCode::OK, &body))
}

/// What an export and an erasure state is kept, and why (docs/07 §Data classification).
const KEPT: &str = "Audit events of envelopes you acted on record your name and email as they were then, inside hashed, append-only chains that every party can check; the workspace's admin log records your user id for changes you made. Neither can be altered without breaking that evidence, so neither is changed by an erasure. Envelopes you sent stay with the workspace that holds them, under its retention rules.";

/// Refuse (`409 CS-API-0018`) an erasure that would leave the workspace without an
/// enabled administrator, or that targets an administrator of the organization (who
/// must be removed there first).
async fn erasable(st: &AppState, account: AccountId, user: UserId) -> Result<(), ApiError> {
    let mut tx = st.store().for_account(account).begin().await?;
    let member = tx
        .users()
        .get(user)
        .await?
        .ok_or_else(ApiError::not_found)?;
    let admin = tx
        .users()
        .profile(member.permission_profile_id)
        .await?
        .is_some_and(|p| p.kind == casual_sign_store::repo::accounts::ProfileKind::Admin);
    let others = tx.privacy().other_administrators(user).await?;
    let org = tx.account().get().await?.organization_id;
    tx.rollback().await?;
    if admin && member.disabled_at.is_none() && others == 0 {
        return Err(ApiError::erasure_blocked("last administrator"));
    }
    let mut otx = st.store().for_organization(org).begin().await?;
    let org_admin = otx.admin(user).await?;
    otx.rollback().await?;
    if org_admin.is_some() {
        return Err(ApiError::erasure_blocked("organization administrator"));
    }
    Ok(())
}

/// `DELETE /users/me` (ASVS-16): erase the caller's own identity in this workspace,
/// after a recent re-authentication: name and email replaced, login, password and
/// second factor removed, sessions here ended, saved signature, notices, invitations and
/// password resets deleted, owned API clients revoked; the admin event `member.erased`
/// records it. Only for a member of this workspace alone (`403 CS-API-0015` otherwise:
/// the person is then removed from each other workspace by its administrators, and
/// erased in the last); `409 CS-API-0018` for the last administrator.
pub(crate) async fn erase_me(c: Call) -> Result<Response, ApiError> {
    c.p.require_recent_auth(c.st.now())?;
    if !matches!(c.p.credential, Credential::Session(_)) {
        // Only the person, from a session of theirs; never an API key.
        return Err(ApiError::invalid("/credential"));
    }
    erasable(&c.st, c.p.account, c.p.user).await?;
    let mut tx = c.tx().await?;
    tx.privacy().erase_member(c.p.user, c.st.now()).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// `POST /users/{id}/erase` (`users.remove`; ASVS-16): an administrator erases a
/// member's identity as `DELETE /users/me` does, after a recent re-authentication;
/// never their own (`422`), never a member above them (`403 CS-ORG-0005`), never one of
/// another workspace too (`403 CS-API-0015`), never the last administrator or an
/// organization administrator (`409 CS-API-0018`). A member outside a group-scoped
/// caller's groups is `404`.
pub(crate) async fn erase_user(c: Call, Path(id): Path<String>) -> Result<Response, ApiError> {
    let id = UserId(path_id(&id)?);
    {
        let mut tx = c.tx().await?;
        super::admin::member_in_scope(&c, &mut tx, id).await?;
        tx.rollback().await?;
    }
    if id == c.p.user {
        return Err(ApiError::invalid("/id"));
    }
    c.p.require_recent_auth(c.st.now())?;
    let mut tx = c.tx().await?;
    let target = super::admin::member_in_scope(&c, &mut tx, id).await?;
    super::admin::outranks(&c, &mut tx, &target).await?;
    tx.rollback().await?;
    erasable(&c.st, c.p.account, id).await?;
    let mut tx = c.tx().await?;
    tx.privacy().erase_member(id, c.st.now()).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

fn rules_json(rules: &[casual_sign_store::repo::privacy::RetentionRule]) -> Value {
    let mut out = serde_json::Map::new();
    for class in DataClass::ALL {
        let r = rules.iter().find(|r| r.data_class == class);
        out.insert(
            class.as_str().to_owned(),
            r.map_or(Value::Null, |r| Value::from(r.keep_days)),
        );
    }
    json!({ "keep_days": out, "max_keep_days": MAX_KEEP_DAYS })
}

/// `GET /retention` (`retention.manage`): the account's rules, `{keep_days: {draft,
/// ended, completed, sessions}, max_keep_days}`, each a number of days or `null`
/// (kept for ever, the default).
pub(crate) async fn rules(c: Call) -> Result<Response, ApiError> {
    let mut tx = c.tx().await?;
    let rules = tx.privacy().rules().await?;
    tx.commit().await?;
    Ok(json(StatusCode::OK, &rules_json(&rules)))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RulesIn {
    /// Class → days (`null` removes the rule). Classes left out are unchanged.
    keep_days: BTreeMap<String, Option<i32>>,
}

/// `PUT /retention {keep_days: {class: days | null}}` (`retention.manage`, after a
/// recent re-authentication: a rule deletes records): set or remove the rules named,
/// each change an admin event (`retention.rule_set`). Answers the rules as `GET` does.
pub(crate) async fn set_rules(c: Call, body: Bytes) -> Result<Response, ApiError> {
    c.p.require_recent_auth(c.st.now())?;
    let req: RulesIn = parse(&body)?;
    let mut changes = Vec::new();
    for (name, days) in &req.keep_days {
        let class = DataClass::from_name(name)
            .ok_or_else(|| ApiError::invalid(&format!("/keep_days/{name}")))?;
        if days.is_some_and(|d| !(1..=MAX_KEEP_DAYS).contains(&d)) {
            return Err(ApiError::invalid(&format!("/keep_days/{name}")));
        }
        changes.push((class, *days));
    }
    let mut tx = c.tx().await?;
    for (class, days) in changes {
        tx.privacy().set_rule(class, days, c.st.now()).await?;
    }
    let rules = tx.privacy().rules().await?;
    tx.commit().await?;
    Ok(json(StatusCode::OK, &rules_json(&rules)))
}

/// `GET /retention/preview` (`retention.manage`): the retention job's dry run now,
/// changing nothing: `{at, counts: {draft, ended, completed}, sessions, held,
/// envelopes: [{id, class, since}]}` (at most 100 listed, oldest first).
pub(crate) async fn preview(c: Call) -> Result<Response, ApiError> {
    let now = c.st.now();
    let mut tx = c.tx().await?;
    let p = tx.privacy().preview(now, PREVIEW_LIMIT).await?;
    tx.commit().await?;
    let counts: serde_json::Map<String, Value> = p
        .counts
        .iter()
        .map(|(c, n)| (c.as_str().to_owned(), Value::from(*n)))
        .collect();
    let envelopes: Vec<Value> = p
        .envelopes
        .iter()
        .map(|e| {
            json!({"id": e.envelope.to_string(), "class": e.class.as_str(), "since": rfc3339(e.since)})
        })
        .collect();
    Ok(json(
        StatusCode::OK,
        &json!({
            "at": rfc3339(now), "counts": counts, "sessions": p.sessions, "held": p.held,
            "envelopes": envelopes,
        }),
    ))
}

async fn legal_hold(c: &Call, id: &str, hold: bool) -> Result<Response, ApiError> {
    let env = EnvelopeId(path_id(id)?);
    let mut tx = c.tx().await?;
    // Another workspace's envelope is 404 (the repository is this account's).
    tx.privacy().set_legal_hold(env, hold, c.st.now()).await?;
    let at = tx.privacy().legal_hold(env).await?;
    tx.commit().await?;
    Ok(json(
        StatusCode::OK,
        &json!({"envelope_id": env.to_string(), "legal_hold": at.is_some(), "since": at.map(rfc3339)}),
    ))
}

/// `PUT /envelopes/{id}/legal-hold` (`retention.manage`): keep the envelope from every
/// retention rule and purge until released (`envelope.legal_hold_set` in the admin
/// log). Answers `{envelope_id, legal_hold, since}`. Holding twice changes nothing.
pub(crate) async fn set_hold(c: Call, Path(id): Path<String>) -> Result<Response, ApiError> {
    legal_hold(&c, &id, true).await
}

/// `DELETE /envelopes/{id}/legal-hold` (`retention.manage`): release the hold
/// (`envelope.legal_hold_released`).
pub(crate) async fn release_hold(c: Call, Path(id): Path<String>) -> Result<Response, ApiError> {
    legal_hold(&c, &id, false).await
}

/// `POST /envelopes/{id}/purge` (`retention.manage`, after a recent re-authentication):
/// the controller purges an envelope that ended, completed or was never sent, now,
/// as a retention rule would (`envelope.purged` with the policy `request`, then the
/// purge job): the way a signer's erasure request is carried out by the account that
/// holds their envelope. `409 CS-API-0019` under legal hold; `409 CS-WF-0001` in flight
/// or already purged.
pub(crate) async fn purge(c: Call, Path(id): Path<String>) -> Result<Response, ApiError> {
    let env = EnvelopeId(path_id(&id)?);
    let mut tx = c.tx().await?;
    let mut l = crate::apply::load(&mut tx, env)
        .await?
        .ok_or_else(ApiError::not_found)?;
    c.p.require_recent_auth(c.st.now())?;
    if tx.privacy().legal_hold_for_update(env).await?.is_some() {
        return Err(ApiError::legal_hold());
    }
    let mut cmds = c.commands(&mut tx).await?;
    let ctx = cmds.ctx(
        WfPrincipal::Admin {
            user_id: eid(c.p.user.0)?,
        },
        None,
    )?;
    let policy = Text::new("request".to_owned()).map_err(|_| ApiError::internal("policy"))?;
    run(&mut tx, &mut l, &Command::Purge { policy }, &ctx).await?;
    tx.commit().await?;
    Ok(json(
        StatusCode::ACCEPTED,
        &json!({"envelope_id": env.to_string(), "purged": true}),
    ))
}
