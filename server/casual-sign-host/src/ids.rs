//! Engine ids and times as the database keeps them, and the context of a command the
//! platform issues.

use casual_sign_audit::Timestamp;
use casual_sign_model::Id;
use casual_sign_store::JobId;
use casual_sign_workflow::{Context, Policy, Principal};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::{HostError, Result};

/// The UUID an engine id names. Engine ids of envelopes, recipients, documents and
/// users are the database's UUIDs in their canonical hyphenated form.
///
/// # Errors
///
/// `CS-WRK-0003` for anything else.
pub fn uuid_of(id: &Id, what: &'static str) -> Result<Uuid> {
    let u = Uuid::parse_str(id.as_str()).map_err(|_| HostError::NotUuid { what })?;
    if u.hyphenated().to_string() == id.as_str() {
        Ok(u)
    } else {
        Err(HostError::NotUuid { what })
    }
}

/// The engine id of a database UUID.
///
/// # Errors
///
/// `CS-WRK-0003` (never, for a UUID: its hyphenated form is a valid id).
pub fn id_of(u: Uuid, what: &'static str) -> Result<Id> {
    Id::new(u.hyphenated().to_string()).map_err(|_| HostError::NotUuid { what })
}

/// The command id a job feeds its result under: the same on every run of the job.
///
/// # Errors
///
/// `CS-WRK-0003` (never, for a UUID).
pub fn job_command_id(job: JobId) -> Result<Id> {
    Id::new(format!("job-{}", job.0.simple())).map_err(|_| HostError::NotUuid { what: "job" })
}

/// A database time as the engine's (milliseconds).
///
/// # Errors
///
/// `CS-WRK-0001` for a time outside the engine's range (never from a sane clock).
pub fn ts(t: OffsetDateTime) -> Result<Timestamp> {
    let ms = t.unix_timestamp_nanos() / 1_000_000;
    i64::try_from(ms)
        .ok()
        .and_then(Timestamp::from_unix_millis)
        .ok_or(HostError::Clock)
}

/// The engine's time as the database's.
///
/// # Errors
///
/// `CS-WRK-0001` (never, for a timestamp the engine accepted).
pub fn odt(t: Timestamp) -> Result<OffsetDateTime> {
    OffsetDateTime::from_unix_timestamp_nanos(i128::from(t.unix_millis()).saturating_mul(1_000_000))
        .map_err(|_| HostError::Clock)
}

/// A context for a command the platform issues (a job's result, a timer).
#[must_use]
pub fn system_context(command_id: Id, now: Timestamp, policy: Policy) -> Context {
    Context {
        command_id,
        now,
        principal: Principal::System,
        request: casual_sign_audit::Context::default(),
        expected_version: None,
        policy,
    }
}

#[cfg(test)]
// Tests may unwrap (CLAUDE.md).
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn ids_round_trip_only_in_canonical_form() {
        let u = Uuid::new_v4();
        let id = id_of(u, "envelope").unwrap();
        assert_eq!(uuid_of(&id, "envelope").unwrap(), u);
        let upper = Id::new(u.hyphenated().to_string().to_uppercase()).unwrap();
        assert_eq!(
            uuid_of(&upper, "envelope").unwrap_err().code(),
            "CS-WRK-0003"
        );
        let simple = Id::new(u.simple().to_string()).unwrap();
        assert!(uuid_of(&simple, "envelope").is_err());
    }

    #[test]
    fn times_round_trip_at_millisecond_precision() {
        let t = Timestamp::from_unix_millis(1_762_000_000_123).unwrap();
        assert_eq!(ts(odt(t).unwrap()).unwrap(), t);
    }
}
