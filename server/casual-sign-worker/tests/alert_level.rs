//! ASVS-13B (docs/65 §Logs): an operator alert (`job_dead`, `seal_failed`) is written at
//! `ERROR`, so a collector rule on level pages on it; it was written at `INFO`.

// Test code: a panic is the failure report (CLAUDE.md).
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use casual_sign_seclog::{SecurityLog, Service};
use casual_sign_worker::{AlertSink as _, LogAlerts, OperatorAlert};
use uuid::Uuid;

#[test]
fn an_operator_alert_is_written_at_error() {
    let (log, mem) = SecurityLog::memory(Service::Worker);
    casual_sign_worker::set_security_log(log);
    for kind in ["job_dead", "seal_failed"] {
        LogAlerts.alert(&OperatorAlert {
            kind: kind.into(),
            code: "CS-SEAL-0001".into(),
            account: Uuid::nil(),
            envelope: Some(Uuid::nil()),
            job: Uuid::nil(),
        });
    }
    let lines = mem.json();
    assert_eq!(lines.len(), 2, "{lines:?}");
    for (line, kind) in lines.iter().zip(["job_dead", "seal_failed"]) {
        assert_eq!(line["event"], kind, "{line}");
        assert_eq!(line["level"], "ERROR", "{line}");
        assert_eq!(line["code"], "CS-SEAL-0001", "{line}");
    }
}
