//! The worker's container health check (`HRD-06`): it serves no port, so while it can
//! reach its database it writes the time to a file (`OPENSEAL_HEALTH_FILE`, on a tmpfs),
//! and `casual-sign-worker healthcheck` passes only while that time is recent. A worker
//! whose runtime has stalled, or which has lost its database, turns unhealthy within
//! [`MAX_AGE_SECONDS`].

use std::path::Path;

/// How often a healthy worker writes the file.
pub const BEAT_SECONDS: u64 = 10;

/// How old the last beat may be before the check fails: three missed beats.
pub const MAX_AGE_SECONDS: u64 = 3 * BEAT_SECONDS;

/// Record a beat at `now` (Unix seconds): written beside the file and renamed over it, so
/// the check never reads half a number.
///
/// # Errors
///
/// The file system's error.
pub fn beat(path: &Path, now: u64) -> std::io::Result<()> {
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".new");
    std::fs::write(&tmp, now.to_string())?;
    std::fs::rename(&tmp, path)
}

/// Whether the file holds a beat no older than `max_age` seconds at `now`. A missing,
/// unreadable or malformed file, or a beat from the future beyond a second's skew, is
/// unhealthy.
#[must_use]
pub fn check(path: &Path, now: u64, max_age: u64) -> bool {
    let Ok(text) = std::fs::read_to_string(path) else {
        return false;
    };
    let Ok(at) = text.trim().parse::<u64>() else {
        return false;
    };
    at <= now.saturating_add(1) && now.saturating_sub(at) <= max_age
}

#[cfg(test)]
// Test code: a panic is the failure report (CLAUDE.md).
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn a_recent_beat_is_healthy_and_a_stale_or_missing_one_is_not() {
        let dir = std::env::temp_dir().join(format!("openseal-health-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("health");
        assert!(!check(&file, 1_000, MAX_AGE_SECONDS), "no file yet");
        beat(&file, 1_000).unwrap();
        assert!(check(&file, 1_000, MAX_AGE_SECONDS));
        assert!(check(&file, 1_000 + MAX_AGE_SECONDS, MAX_AGE_SECONDS));
        assert!(
            !check(&file, 1_001 + MAX_AGE_SECONDS, MAX_AGE_SECONDS),
            "stale"
        );
        assert!(!check(&file, 990, MAX_AGE_SECONDS), "from the future");
        std::fs::write(&file, "not a time").unwrap();
        assert!(!check(&file, 1_000, MAX_AGE_SECONDS), "malformed");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
