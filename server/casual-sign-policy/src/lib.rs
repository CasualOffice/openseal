//! OpenSeal policy (ADR-028, docs/23 §3, §5.2, §7): pure decisions the server, the worker
//! and the platform console share, with no I/O, no store and no clock.
//!
//! Today it holds [`plans`]: what a plan may say (validation, `CS-PLAN-0006`) and which
//! entitlements and quotas apply to an organization or one of its workspaces at a given
//! instant ([`plans::effective`]). The organization policy (`OrgPolicy`, docs/23 §3) joins
//! it with `ORG-08`.
//!
//! The rows come from the `platform` schema: the console reads them as
//! `openseal_console`, the application through `openseal_effective_plan(now)`; both hand
//! the same JSON shape to [`plans::PlanInputs::from_json`].

pub mod plans;
