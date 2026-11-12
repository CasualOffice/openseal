//! One account's worth of every kind of row a repository reaches, written through the
//! repositories themselves.

use casual_sign_audit::{
    Actor, AuditEvent, Chain, Context, EventData, Hash256, Personal, Timestamp,
};
use casual_sign_model::{FieldType, Id};
use casual_sign_store::repo::accounts::{LoginKind, NewUser, PermissionProfile, ProfileKind};
use casual_sign_store::repo::api_clients::{ApiClientKind, NewApiClient};
use casual_sign_store::repo::documents::{Document, NewVersion, VersionKind};
use casual_sign_store::repo::envelopes::{NewEnvelope, RoutingMode, SealProfile};
use casual_sign_store::repo::fields::{Field, FieldValue, Rect};
use casual_sign_store::repo::jobs::NewJob;
use casual_sign_store::repo::recipients::{
    Delivery as RecipientDelivery, NewRecipient, NewToken, RecipientType, TokenPurpose,
};
use casual_sign_store::repo::templates::{Template, TemplateDocument, TemplateField, TemplateRole};
use casual_sign_store::repo::webhooks::{Delivery, Subscription};
use casual_sign_store::*;
use rust_decimal::Decimal;
use time::OffsetDateTime;
use uuid::Uuid;

/// Ids of everything seeded for one account.
#[derive(Debug, Clone)]
pub struct World {
    pub organization: OrganizationId,
    pub account: AccountId,
    pub profile: PermissionProfileId,
    pub user: UserId,
    pub api_client: ApiClientId,
    pub api_secret_sha256: [u8; 32],
    pub envelope: EnvelopeId,
    pub document: DocumentId,
    pub version: DocumentVersionId,
    pub recipient: RecipientId,
    pub token: RecipientTokenId,
    pub token_sha256: [u8; 32],
    pub field: FieldId,
    pub job: JobId,
    pub template: TemplateId,
    pub role: TemplateRoleId,
    pub template_document: TemplateDocumentId,
    pub template_field: TemplateFieldId,
    pub subscription: WebhookSubscriptionId,
    pub delivery: WebhookDeliveryId,
    pub events: u64,
}

pub fn id() -> Uuid {
    Uuid::now_v7()
}

pub fn now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_794_302_043).unwrap()
}

pub fn hash(tag: &str) -> [u8; 32] {
    *Hash256::digest(tag.as_bytes()).as_bytes()
}

/// The `n`th event of a chain for `envelope` (n from 0), built through `Chain` so it
/// links to the previous ones.
pub fn events(envelope: EnvelopeId, n: usize) -> Vec<AuditEvent> {
    let mut chain = Chain::new(Id::new(envelope.to_string()).unwrap());
    let mut out = Vec::new();
    for i in 0..n {
        let at = Timestamp::from_unix_millis(1_794_302_043_512 + i64::try_from(i).unwrap() * 1000)
            .unwrap();
        let data = if i == 0 {
            EventData::EnvelopeCreated {
                subject_hash: Hash256::digest(b"subject"),
            }
        } else {
            EventData::EnvelopeSent {
                recipients: 1,
                documents: 1,
            }
        };
        let e = chain.next(at, Actor::system(), Context::default(), data);
        chain.append(e.clone()).unwrap();
        out.push(e);
    }
    out
}

pub fn new_envelope(id: EnvelopeId, sender: UserId) -> NewEnvelope {
    NewEnvelope {
        id,
        sender_user_id: sender,
        subject: Personal("Please sign".into()),
        message: Personal(String::new()),
        routing_mode: RoutingMode::Sequential,
        expires_at: None,
        reminder_policy: serde_json::json!({}),
        signing_options: serde_json::json!({}),
        seal_profile: SealProfile::PadesBT,
        completion_delivery: serde_json::json!({}),
        template_ids: vec![],
    }
}

pub fn new_recipient(id: RecipientId, envelope: EnvelopeId) -> NewRecipient {
    NewRecipient {
        id,
        envelope_id: envelope,
        routing_order: 1,
        kind: RecipientType::Signer,
        role_name: None,
        name: Personal("Ada Signer".into()),
        email: Some(Personal(format!("ada+{}@example.test", id.0.simple()))),
        phone: None,
        delivery: RecipientDelivery::Email,
        embedded_client_user_id: None,
        language: None,
    }
}

pub fn rect() -> Rect {
    Rect {
        page: 1,
        x: Decimal::new(7200, 2),
        y: Decimal::new(14400, 2),
        width: Decimal::new(200, 0),
        height: Decimal::new(40, 0),
    }
}

pub fn new_field(
    id: FieldId,
    envelope: EnvelopeId,
    document: DocumentId,
    recipient: RecipientId,
) -> Field {
    Field {
        id,
        envelope_id: envelope,
        document_id: document,
        recipient_id: recipient,
        kind: FieldType::Signature,
        rect: rect(),
        required: true,
        read_only: false,
        locked: false,
        label: Some("sig".into()),
        spec: Personal(serde_json::json!({})),
    }
}

pub fn new_version(id: DocumentVersionId, document: DocumentId) -> NewVersion {
    NewVersion {
        id,
        document_id: document,
        kind: VersionKind::Normalized,
        sha256: hash("pdf"),
        byte_len: 1234,
        page_count: 1,
        admission_report: Some(serde_json::json!({"findings": []})),
        pages: serde_json::json!([{"width": 612, "height": 792}]),
    }
}

pub fn new_job(id: JobId, envelope: Option<EnvelopeId>, key: &str) -> NewJob {
    NewJob {
        id,
        envelope_id: envelope,
        kind: "send_invitation".into(),
        idempotency_key: key.into(),
        payload: serde_json::json!({}),
        run_at: now(),
        max_attempts: 3,
    }
}

/// Seed one account, a workspace of an organization of its own, through the
/// repositories.
pub async fn seed(db: &super::TestDb, name: &str) -> World {
    let store = &db.store;
    let (organization, account) = db.account(name).await;
    let w = World {
        organization,
        account,
        profile: PermissionProfileId(id()),
        user: UserId(id()),
        api_client: ApiClientId(id()),
        api_secret_sha256: hash(&format!("key-{name}")),
        envelope: EnvelopeId(id()),
        document: DocumentId(id()),
        version: DocumentVersionId(id()),
        recipient: RecipientId(id()),
        token: RecipientTokenId(id()),
        token_sha256: hash(&format!("token-{name}")),
        field: FieldId(id()),
        job: JobId(id()),
        template: TemplateId(id()),
        role: TemplateRoleId(id()),
        template_document: TemplateDocumentId(id()),
        template_field: TemplateFieldId(id()),
        subscription: WebhookSubscriptionId(id()),
        delivery: WebhookDeliveryId(id()),
        events: 2,
    };
    let mut tx = store.for_account(account).begin().await.unwrap();
    tx.users()
        .create_profile(&PermissionProfile {
            id: w.profile,
            name: "Senders".into(),
            kind: ProfileKind::Sender,
            permissions: vec!["send".into()],
        })
        .await
        .unwrap();
    tx.users()
        .create_member(
            &NewUser {
                id: w.user,
                email: Personal(format!("{name}@example.test")),
                email_normalized: Personal(format!("{name}@example.test")),
                name: Personal(format!("Sender {name}")),
                login_kind: LoginKind::Local,
                idp: None,
            },
            w.profile,
        )
        .await
        .unwrap();
    tx.api_clients()
        .create(&NewApiClient {
            id: w.api_client,
            kind: ApiClientKind::ApiKey,
            name: "script".into(),
            owner_user_id: Some(w.user),
            key_prefix: Some("osk_test".into()),
            secret_sha256: Some(w.api_secret_sha256),
            scopes: vec!["envelopes:read".into()],
            expires_at: None,
        })
        .await
        .unwrap();
    tx.envelopes()
        .insert(&new_envelope(w.envelope, w.user))
        .await
        .unwrap();
    tx.documents()
        .insert(&Document {
            id: w.document,
            envelope_id: w.envelope,
            ord: 0,
            name: "contract.pdf".into(),
        })
        .await
        .unwrap();
    tx.documents()
        .add_version(&new_version(w.version, w.document))
        .await
        .unwrap();
    tx.recipients()
        .insert(&new_recipient(w.recipient, w.envelope))
        .await
        .unwrap();
    tx.recipients()
        .issue_token(&NewToken {
            id: w.token,
            envelope_id: w.envelope,
            recipient_id: w.recipient,
            token_sha256: w.token_sha256,
            purpose: TokenPurpose::Invitation,
            host_user_id: None,
            expires_at: now() + time::Duration::days(30),
        })
        .await
        .unwrap();
    tx.fields()
        .insert(&new_field(w.field, w.envelope, w.document, w.recipient))
        .await
        .unwrap();
    tx.fields()
        .set_value(&FieldValue {
            field_id: w.field,
            envelope_id: w.envelope,
            recipient_id: w.recipient,
            value: Personal(serde_json::json!("Ada")),
            value_sha256: hash("Ada"),
            set_at: now(),
        })
        .await
        .unwrap();
    for e in events(w.envelope, 2) {
        tx.audit().append(w.envelope, &e).await.unwrap();
    }
    assert!(
        tx.jobs()
            .enqueue(&new_job(w.job, Some(w.envelope), "seed"))
            .await
            .unwrap()
    );
    tx.templates()
        .insert(&Template {
            id: w.template,
            owner_user_id: w.user,
            name: "NDA".into(),
            email_subject: None,
            email_message: None,
            settings: serde_json::json!({}),
            matching_rules: serde_json::json!([]),
            version: 1,
        })
        .await
        .unwrap();
    tx.templates()
        .add_role(&TemplateRole {
            id: w.role,
            template_id: w.template,
            name: "Signer".into(),
            routing_order: 1,
            kind: RecipientType::Signer,
            default_auth: serde_json::json!([]),
        })
        .await
        .unwrap();
    tx.templates()
        .add_document(&TemplateDocument {
            id: w.template_document,
            template_id: w.template,
            ord: 0,
            name: "nda.pdf".into(),
            sha256: hash("nda"),
            byte_len: 99,
            page_count: 1,
            pages: serde_json::json!([]),
        })
        .await
        .unwrap();
    tx.templates()
        .add_field(&TemplateField {
            id: w.template_field,
            template_id: w.template,
            template_document_id: w.template_document,
            role_id: w.role,
            kind: FieldType::Signature,
            rect: rect(),
            required: true,
            label: None,
            spec: Personal(serde_json::json!({})),
        })
        .await
        .unwrap();
    tx.webhooks()
        .subscribe(&Subscription {
            id: w.subscription,
            envelope_id: None,
            url: "https://hooks.example.test/openseal".into(),
            event_types: vec!["envelope.completed".into()],
            secret_refs: vec!["secret/webhook/1".into()],
            active: true,
        })
        .await
        .unwrap();
    tx.webhooks()
        .record_delivery(&Delivery {
            id: w.delivery,
            subscription_id: w.subscription,
            event_id: id(),
            event_type: "envelope.completed".into(),
            payload: serde_json::json!({"id": "x"}),
            status: "pending".into(),
            attempts: 0,
            last_status_code: None,
        })
        .await
        .unwrap();
    tx.commit().await.unwrap();
    w
}
