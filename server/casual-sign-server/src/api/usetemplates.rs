//! Using templates (slice 3 `VS-03`, docs/40 As built): `POST /envelopes/from-templates`
//! makes one envelope from one template, or from several (DocuSign's composite
//! templates, `FG-097`), on the server, from the templates' stored documents: nothing is
//! downloaded and uploaded again.
//!
//! - The documents are each template's, in the order the templates are named.
//! - The roles of every template are matched by name, ignoring case, as DocuSign
//!   matches composite templates' roles: a role named in two templates is one
//!   recipient, who gets both templates' fields. Its type and routing order are those of
//!   the first template that names it; the same name with another type is refused.
//! - Each role is filled by one person (`{role, name, email}`); people with no `role`
//!   are added after every role in routing order, as a copy or a signer (whose fields
//!   are placed in the editor before sending, so such an envelope is a draft).
//! - The envelope is made by the same code path as `POST /envelopes` (`create_in`), so
//!   it is checked, audited and sent exactly as one made there.
//!
//! Access is the templates' (UXW-06): each must be one the caller may use; one they may
//! not, or another account's, is refused as missing (`422` at `/template_ids/{i}`, as a
//! bulk send's template is).

use std::collections::BTreeMap;

use axum::body::Bytes;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::Response;
use casual_sign_store::repo::recipients::RecipientType;
use casual_sign_store::repo::templates::{
    Template, TemplateAccess, TemplateDocument, TemplateField, TemplateRole,
};
use casual_sign_store::{TemplateId, UploadKind};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use super::envelopes::{create_in, envelope_response};
use crate::call::Call;
use crate::dto::{EnvelopeCreate, parse};
use crate::error::ApiError;

/// The most templates one envelope is made from (docs/21).
pub(crate) const MAX_TEMPLATES: usize = 10;
/// The most people one request names.
pub(crate) const MAX_PEOPLE: usize = 100;

/// One template as stored, with its parts.
pub(crate) struct Part {
    pub(crate) template: Template,
    pub(crate) roles: Vec<TemplateRole>,
    pub(crate) docs: Vec<TemplateDocument>,
    pub(crate) fields: Vec<TemplateField>,
}

/// A role of the envelope: one or more templates' roles of the same name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Role {
    /// The name as the first template that names it spells it.
    pub(crate) name: String,
    /// Its type, from that template.
    pub(crate) kind: RecipientType,
    /// Its routing order, from that template.
    pub(crate) routing_order: i32,
}

/// The envelope's roles, and for each part and each of its roles (by position) the
/// envelope role it is. A role named again with another type is `422` at
/// `/template_ids/{i}` of the template that names it so.
pub(crate) fn merge_roles(parts: &[Part]) -> Result<(Vec<Role>, Vec<Vec<usize>>), ApiError> {
    let mut roles: Vec<Role> = Vec::new();
    let mut by_name: BTreeMap<String, usize> = BTreeMap::new();
    let mut map = Vec::with_capacity(parts.len());
    for (i, p) in parts.iter().enumerate() {
        let mut ours = Vec::with_capacity(p.roles.len());
        for r in &p.roles {
            let key = r.name.trim().to_lowercase();
            let at = if let Some(&at) = by_name.get(&key) {
                if roles.get(at).map(|x| x.kind) != Some(r.kind) {
                    return Err(ApiError::invalid(&format!("/template_ids/{i}"))
                        .detail("a role of this template has another type in an earlier one"));
                }
                at
            } else {
                roles.push(Role {
                    name: r.name.trim().to_owned(),
                    kind: r.kind,
                    routing_order: r.routing_order,
                });
                let at = roles.len().saturating_sub(1);
                by_name.insert(key, at);
                at
            };
            ours.push(at);
        }
        map.push(ours);
    }
    Ok((roles, map))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersonIn {
    /// The role this person fills; none for a person added beyond the roles.
    #[serde(default)]
    role: Option<String>,
    name: String,
    #[serde(default)]
    email: Option<String>,
    /// For a person beyond the roles: `cc` (default) or `signer`.
    #[serde(default, rename = "type")]
    rtype: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FromTemplatesIn {
    template_ids: Vec<String>,
    #[serde(default)]
    recipients: Vec<PersonIn>,
    #[serde(default)]
    subject: Option<String>,
    #[serde(default)]
    message: Option<String>,
    /// `draft` (default) or `sent`.
    #[serde(default)]
    status: Option<String>,
}

/// The one-call create request: every part's documents in order, the roles filled with
/// `people`, every role-bound field on its envelope role and document.
fn envelope_request(parts: &[Part], req: &FromTemplatesIn) -> Result<EnvelopeCreate, ApiError> {
    let (roles, map) = merge_roles(parts)?;
    let mut filled: Vec<Option<&PersonIn>> = vec![None; roles.len()];
    let mut extra = Vec::new();
    for (i, p) in req.recipients.iter().enumerate() {
        match p.role.as_deref() {
            Some(name) => {
                let key = name.trim().to_lowercase();
                let at = roles
                    .iter()
                    .position(|r| r.name.to_lowercase() == key)
                    .ok_or_else(|| ApiError::invalid(&format!("/recipients/{i}/role")))?;
                let slot = filled
                    .get_mut(at)
                    .ok_or_else(|| ApiError::internal("role"))?;
                if slot.is_some() {
                    return Err(ApiError::invalid(&format!("/recipients/{i}/role")));
                }
                if p.rtype.is_some() {
                    return Err(ApiError::invalid(&format!("/recipients/{i}/type")));
                }
                *slot = Some(p);
            }
            None => {
                let kind = match p.rtype.as_deref() {
                    None | Some("cc") => "cc",
                    Some("signer") => "signer",
                    Some(_) => return Err(ApiError::invalid(&format!("/recipients/{i}/type"))),
                };
                extra.push((kind, p));
            }
        }
    }
    if let Some(missing) = filled.iter().position(Option::is_none) {
        return Err(
            ApiError::invalid("/recipients").detail(format!("role {missing} has no recipient"))
        );
    }
    let mut rs: Vec<Value> = roles
        .iter()
        .zip(&filled)
        .enumerate()
        .map(|(i, (r, p))| {
            json!({
                "ref": format!("role{i}"), "type": r.kind.as_str(),
                "name": p.map_or("", |p| p.name.as_str()),
                "email": p.and_then(|p| p.email.clone()),
                "routing_order": r.routing_order,
            })
        })
        .collect();
    let last = roles.iter().map(|r| r.routing_order).max().unwrap_or(0);
    for (i, (kind, p)) in extra.iter().enumerate() {
        rs.push(json!({
            "ref": format!("extra{i}"), "type": kind, "name": p.name, "email": p.email,
            "routing_order": last.saturating_add(1),
        }));
    }
    let mut fs = Vec::new();
    let mut doc_base = 0usize;
    for (pi, part) in parts.iter().enumerate() {
        let roles_of = map.get(pi).ok_or_else(|| ApiError::internal("roles"))?;
        for f in &part.fields {
            let (Some(ri), Some(di)) = (
                part.roles.iter().position(|r| r.id == f.role_id),
                part.docs
                    .iter()
                    .position(|d| d.id == f.template_document_id),
            ) else {
                continue;
            };
            let Some(&er) = roles_of.get(ri) else {
                continue;
            };
            let mut v = f.spec.get().clone();
            if let Some(o) = v.as_object_mut() {
                o.remove("id");
                o.insert("recipient_id".into(), json!(format!("role{er}")));
                o.insert("document_id".into(), json!(doc_base.saturating_add(di)));
            }
            fs.push(v);
        }
        doc_base = doc_base.saturating_add(part.docs.len());
    }
    let first = parts
        .first()
        .ok_or_else(|| ApiError::invalid("/template_ids"))?;
    let subject = req
        .subject
        .clone()
        .or_else(|| {
            first
                .template
                .email_subject
                .as_ref()
                .map(|s| s.get().clone())
                .filter(|s| !s.trim().is_empty())
        })
        .unwrap_or_else(|| first.template.name.chars().take(255).collect());
    let message = req.message.clone().unwrap_or_else(|| {
        first
            .template
            .email_message
            .as_ref()
            .map(|s| s.get().clone())
            .unwrap_or_default()
    });
    serde_json::from_value(json!({
        "subject": subject, "message": message,
        "status": req.status, "recipients": rs, "fields": fs,
    }))
    .map_err(|_| ApiError::internal("from-templates request"))
}

/// `POST /envelopes/from-templates {template_ids, recipients, subject?, message?,
/// status?}`: one envelope from 1 to [`MAX_TEMPLATES`] templates; `201` with it, as
/// `POST /envelopes` answers.
pub(crate) async fn create(c: Call, body: Bytes) -> Result<Response, ApiError> {
    c.p.require("envelopes:write")?;
    c.p.require("templates:read")?;
    let req: FromTemplatesIn = parse(&body)?;
    let send = match req.status.as_deref() {
        None | Some("draft") => false,
        Some("sent") => {
            c.p.require("envelopes:send")?;
            true
        }
        Some(_) => return Err(ApiError::invalid("/status")),
    };
    if req.template_ids.is_empty() || req.template_ids.len() > MAX_TEMPLATES {
        return Err(ApiError::invalid("/template_ids"));
    }
    if req.recipients.len() > MAX_PEOPLE {
        return Err(ApiError::invalid("/recipients"));
    }
    let mut ids: Vec<TemplateId> = Vec::with_capacity(req.template_ids.len());
    for (i, s) in req.template_ids.iter().enumerate() {
        let at = format!("/template_ids/{i}");
        let t = TemplateId(Uuid::parse_str(s).map_err(|_| ApiError::invalid(&at))?);
        if ids.contains(&t) {
            return Err(ApiError::invalid(&at));
        }
        ids.push(t);
    }
    // Read every template the caller may use, then their documents' bytes.
    let mut tx = c.tx().await?;
    let mut parts = Vec::with_capacity(ids.len());
    for (i, id) in ids.iter().enumerate() {
        let at = format!("/template_ids/{i}");
        let template = super::templates::found(&mut tx, &c, *id, TemplateAccess::Use)
            .await
            .map_err(|e| {
                if e.status() == StatusCode::NOT_FOUND {
                    ApiError::invalid(&at)
                } else {
                    e
                }
            })?;
        parts.push(Part {
            template,
            roles: tx.templates().roles(*id).await?,
            docs: tx.templates().documents(*id).await?,
            fields: tx.templates().fields(*id).await?,
        });
    }
    tx.commit().await?;
    let total = parts
        .iter()
        .flat_map(|p| &p.docs)
        .fold(0i64, |n, d| n.saturating_add(d.byte_len));
    if usize::try_from(total).map_or(true, |t| t > c.st.config().max_envelope_bytes) {
        return Err(ApiError::too_large());
    }
    let create = envelope_request(&parts, &req)?;
    let mut decoded = Vec::new();
    for p in &parts {
        for d in &p.docs {
            let bytes =
                c.st.0
                    .blobs
                    .get(&casual_sign_store::blob::BlobKey(d.sha256))
                    .await?
                    .to_vec();
            // Scanned again, outside any transaction (ASVS-11), as a bulk send's are.
            let note = crate::scan::screen(
                &c.st,
                c.uploader(),
                UploadKind::TemplateDocument,
                vec![("template", p.template.id.0.to_string())],
                &bytes,
            )
            .await?;
            decoded.push((d.name.clone(), bytes, note));
        }
    }
    let mut tx = c.tx().await?;
    let (env, l) = create_in(&c, &mut tx, &create, decoded, send).await?;
    tx.commit().await?;
    let mut r = envelope_response(StatusCode::CREATED, &l.state);
    if let Ok(v) = HeaderValue::from_str(&format!("/api/v1/envelopes/{env}")) {
        r.headers_mut().insert(header::LOCATION, v);
    }
    if send {
        r.extensions_mut().insert(crate::security::EnvelopeSent);
    }
    Ok(r)
}

#[cfg(test)]
// Tests may unwrap, index and panic (CLAUDE.md).
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use casual_sign_store::{TemplateRoleId, UserId};

    fn part(roles: &[(&str, RecipientType, i32)]) -> Part {
        let tid = TemplateId(Uuid::now_v7());
        Part {
            template: Template {
                id: tid,
                owner_user_id: UserId(Uuid::now_v7()),
                name: "T".into(),
                email_subject: None,
                email_message: None,
                settings: json!({}),
                matching_rules: json!({}),
                version: 1,
            },
            roles: roles
                .iter()
                .map(|(n, k, o)| TemplateRole {
                    id: TemplateRoleId(Uuid::now_v7()),
                    template_id: tid,
                    name: (*n).into(),
                    routing_order: *o,
                    kind: *k,
                    default_auth: json!([]),
                })
                .collect(),
            docs: Vec::new(),
            fields: Vec::new(),
        }
    }

    #[test]
    fn roles_of_the_same_name_ignoring_case_are_one_recipient() {
        let a = part(&[
            ("Buyer", RecipientType::Signer, 1),
            ("Agent", RecipientType::Cc, 3),
        ]);
        let b = part(&[
            ("buyer ", RecipientType::Signer, 2),
            ("Seller", RecipientType::Signer, 2),
        ]);
        let (roles, map) = merge_roles(&[a, b]).unwrap();
        let names: Vec<&str> = roles.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(names, ["Buyer", "Agent", "Seller"]);
        assert_eq!(roles[0].routing_order, 1, "the first template's order");
        assert_eq!(map, vec![vec![0, 1], vec![0, 2]]);
    }

    #[test]
    fn a_role_named_again_with_another_type_is_refused_at_its_template() {
        let a = part(&[("Buyer", RecipientType::Signer, 1)]);
        let b = part(&[("Buyer", RecipientType::Cc, 1)]);
        let e = merge_roles(&[a, b]).unwrap_err();
        assert_eq!(e.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert!(format!("{e:?}").contains("/template_ids/1"), "{e:?}");
    }
}
