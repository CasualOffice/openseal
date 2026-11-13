//! Typed ids (docs/22 §2): UUIDs minted by the host (UUIDv7 in production), one type per
//! entity so that an envelope id cannot be passed where a recipient id is expected.

use uuid::Uuid;

macro_rules! id_type {
    ($(#[$doc:meta] $name:ident),* $(,)?) => {$(
        #[$doc]
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(pub Uuid);

        impl $name {
            /// The UUID.
            #[must_use]
            pub fn as_uuid(&self) -> Uuid {
                self.0
            }
        }

        impl From<Uuid> for $name {
            fn from(value: Uuid) -> Self {
                Self(value)
            }
        }

        impl core::fmt::Display for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                self.0.fmt(f)
            }
        }
    )*};
}

id_type!(
    /// An organization: the level above accounts (ADR-028, docs/23 §2.1).
    OrganizationId,
    /// An account (tenant): a workspace of one organization.
    AccountId,
    /// A staff user.
    UserId,
    /// A permission profile.
    PermissionProfileId,
    /// An envelope.
    EnvelopeId,
    /// A document in an envelope.
    DocumentId,
    /// An immutable version of a document.
    DocumentVersionId,
    /// A recipient of an envelope.
    RecipientId,
    /// A recipient's invitation token record (not the token).
    RecipientTokenId,
    /// A field placed on a document.
    FieldId,
    /// A queued job.
    JobId,
    /// A template.
    TemplateId,
    /// A template role.
    TemplateRoleId,
    /// A template document.
    TemplateDocumentId,
    /// A template field.
    TemplateFieldId,
    /// A webhook subscription.
    WebhookSubscriptionId,
    /// A webhook delivery.
    WebhookDeliveryId,
    /// An API client or key.
    ApiClientId,
    /// A signing link (PowerForm).
    SigningLinkId,
    /// A user invitation (WEB-06).
    UserInvitationId,
    /// A staff user's session.
    StaffSessionId,
    /// One analysis of one stored document (docs/33 §2, WEB-19).
    AnalysisRunId,
    /// One suggestion of an analysis (docs/33 §6).
    SuggestionId,
);
