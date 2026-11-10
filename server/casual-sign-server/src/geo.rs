//! Signer location (owner instruction 17, row GEO-01): a device location the browser's
//! Geolocation API gave, or the recipient declining to share one. Coordinates are
//! personal data: they go into audit events only, never into logs.

use serde::Deserialize;

/// What a ceremony request says about the device's location.
#[derive(Debug, Clone, Copy, PartialEq, Deserialize)]
#[serde(untagged)]
pub enum DeviceLocation {
    /// The browser's fix.
    Fix {
        /// Degrees, -90 to 90.
        latitude: f64,
        /// Degrees, -180 to 180.
        longitude: f64,
        /// Accuracy radius in metres, 0 to 1,000,000.
        accuracy_m: f64,
    },
    /// The recipient declined, or the device could not tell.
    Declined {
        /// Always true.
        declined: bool,
    },
}

impl DeviceLocation {
    /// The fix when it is within range; `None` for a decline or an impossible value
    /// (which counts as no device location, so the server may approximate).
    #[must_use]
    pub fn fix(&self) -> Option<(f64, f64, f64)> {
        match *self {
            Self::Fix {
                latitude,
                longitude,
                accuracy_m,
            } if (-90.0..=90.0).contains(&latitude)
                && (-180.0..=180.0).contains(&longitude)
                && (0.0..=1_000_000.0).contains(&accuracy_m) =>
            {
                Some((latitude, longitude, accuracy_m))
            }
            _ => None,
        }
    }
}

#[cfg(test)]
// Tests may unwrap, index and panic (CLAUDE.md).
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn fixes_and_declines_parse_and_out_of_range_fixes_count_as_none() {
        let f: DeviceLocation =
            serde_json::from_str(r#"{"latitude":51.5,"longitude":-0.12,"accuracy_m":20}"#).unwrap();
        assert_eq!(f.fix(), Some((51.5, -0.12, 20.0)));
        let d: DeviceLocation = serde_json::from_str(r#"{"declined":true}"#).unwrap();
        assert_eq!(d.fix(), None);
        let bad: DeviceLocation =
            serde_json::from_str(r#"{"latitude":91,"longitude":0,"accuracy_m":1}"#).unwrap();
        assert_eq!(bad.fix(), None);
        assert!(serde_json::from_str::<DeviceLocation>(r#"{"lat":1}"#).is_err());
    }
}
