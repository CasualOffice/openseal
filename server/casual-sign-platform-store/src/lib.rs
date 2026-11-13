//! The platform console's store (CON-02, ADR-028, docs/23 §5.1, §5.2).
//!
//! It reaches the `platform` schema only, through a pool that connects as
//! `openseal_console`: SELECT on the platform tables, INSERT on the append-only operator
//! log and alerts, and every other write through a SECURITY DEFINER function that takes
//! the acting operator from a live session. Tenant metadata (organization and workspace
//! ids, names, statuses, counts; queue depth; dead letters without payloads) comes only
//! from definer functions that return no e-mail, person, document or field value.
//!
//! This crate has no tenant repository and does not depend on `casual-sign-store`, so
//! `TenantTx` is not in the console's build (docs/23 §5.1, review finding 5). Migrations
//! are owned by `casual-sign-store` and applied by the migrator; this crate never runs
//! them.

mod error;
pub mod event;
mod plans;
mod store;

pub use error::{PlatformError, Result};
pub use event::{ChainReport, Detail, EventDraft, StoredEvent};
pub use plans::{NewOverride, PlanRow};
pub use store::{
    AlertRow, ApprovalRow, DeadJob, JobStat, MAX_PAGE, NewOperator, OperatorLogin, OperatorSummary,
    OrgAction, OrganizationRow, PlatformStore, PlatformTx, Role, ServiceTarget, Session,
    WorkspaceRow, remove_service_target, set_service_target,
};

/// The driver, re-exported so the console builds its pool with the same version.
pub use sqlx;
