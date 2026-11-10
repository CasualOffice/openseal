//! Where a signer was when they acted (GEO-01, docs/32 §2 `context.location`).
//!
//! A [`Location`] says how it was obtained and what it is:
//!
//! - **from the device** ([`LocationSource::Device`]): the signer's browser or app gave
//!   coordinates after the signer was asked. They are rounded to 4 decimal places
//!   (about 11 m) before they are recorded, and the device's stated accuracy is kept.
//! - **approximated from the IP address** ([`LocationSource::Ip`]): the host looked the
//!   request's IP up in a GeoIP database, named with its build date. The reason says why
//!   the device was not used: the signer **declined**, the device gave nothing
//!   (**unavailable**), or the envelope did not ask (**not requested**). The fact of a
//!   refusal is therefore part of the event, whether or not the lookup found anything.
//!
//! The host does the lookup (the engine holds no database and does no I/O). Every value
//! is checked on construction and on decoding: coordinates in range and finite, a device
//! coordinate at most 4 decimal places, a two-letter country code, and short texts
//! without control characters. A location is personal data: it travels inside
//! [`crate::Personal`], and its own `Debug` prints only how it was obtained.
//!
//! Wire form (members absent when unset):
//!
//! ```json
//! {"source":"device","accuracy_m":12,"latitude":51.5074,"longitude":-0.1278,
//!  "country":"GB","region":"England","city":"London"}
//! {"source":"ip","reason":"declined","database":"GeoLite2-City 2026-11-04",
//!  "latitude":51.5,"longitude":-0.13,"country":"GB","city":"London"}
//! ```

use serde::{Deserialize, Serialize};

use crate::error::{AuditError, LocationFault};

/// Most bytes in `region` or `city` (UTF-8). A decision of GEO-01; docs/21 records it.
pub const MAX_PLACE_BYTES: usize = 128;
/// Most bytes in the GeoIP database's name and build date. A decision of GEO-01.
pub const MAX_DATABASE_BYTES: usize = 128;
/// The largest device accuracy recorded, in metres: half the Earth's circumference.
pub const MAX_ACCURACY_M: u32 = 20_037_509;

/// Why a location was approximated from the IP address rather than taken from the
/// device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FallbackReason {
    /// The signer was asked and refused to share their device's location.
    Declined,
    /// The signer was asked, but the device gave no position (no permission API, a
    /// timeout, no fix).
    Unavailable,
    /// The envelope does not capture location; the host recorded an IP approximation
    /// anyway.
    NotRequested,
}

/// How a location was obtained.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum LocationSource {
    /// The signer's device, after the signer agreed.
    Device {
        /// The radius the device stated, in whole metres (rounded up).
        accuracy_m: u32,
    },
    /// A GeoIP lookup of the request's IP address.
    Ip {
        /// Why the device was not used.
        reason: FallbackReason,
        /// The database's name and build date (`GeoLite2-City 2026-11-04`); `None` when
        /// no lookup ran (no database configured, or a private address).
        database: Option<String>,
    },
}

/// A latitude and longitude in decimal degrees (WGS 84), finite and in range.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Coordinates {
    latitude: f64,
    longitude: f64,
}

// `Coordinates` holds only finite numbers (checked by every constructor), so equality is
// reflexive and `Eq` holds.
impl Eq for Coordinates {}

impl Coordinates {
    /// Checks a pair: both finite, latitude −90 to 90, longitude −180 to 180.
    ///
    /// # Errors
    ///
    /// `CS-AUD-0011` naming the coordinate.
    pub fn new(latitude: f64, longitude: f64) -> Result<Self, AuditError> {
        if !latitude.is_finite() || !(-90.0..=90.0).contains(&latitude) {
            return Err(AuditError::location(LocationFault::Latitude));
        }
        if !longitude.is_finite() || !(-180.0..=180.0).contains(&longitude) {
            return Err(AuditError::location(LocationFault::Longitude));
        }
        // `-0` is written `0` by RFC 8785; keep one zero so decoding gives the same value.
        Ok(Self {
            latitude: latitude + 0.0,
            longitude: longitude + 0.0,
        })
    }

    /// Latitude in decimal degrees.
    #[must_use]
    pub fn latitude(self) -> f64 {
        self.latitude
    }

    /// Longitude in decimal degrees.
    #[must_use]
    pub fn longitude(self) -> f64 {
        self.longitude
    }

    /// The pair rounded to 4 decimal places (about 11 m at the equator).
    fn rounded(self) -> Self {
        Self {
            latitude: round4(self.latitude),
            longitude: round4(self.longitude),
        }
    }

    fn is_rounded(self) -> bool {
        round4(self.latitude) == self.latitude && round4(self.longitude) == self.longitude
    }
}

/// `x` rounded to 4 decimal places. Idempotent: `k / 1e4` is the double nearest that
/// decimal, and scaling it back rounds to `k` again. In range of a coordinate the
/// product is at most 1.8e6, so it is exact enough and never overflows.
fn round4(x: f64) -> f64 {
    (x * 10_000.0).round() / 10_000.0 + 0.0
}

/// Where a signer was when they acted. Personal data (docs/07): it is recorded inside
/// [`crate::Personal`] and never logged.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "LocationWire", into = "LocationWire")]
pub struct Location {
    source: LocationSource,
    coordinates: Option<Coordinates>,
    country: Option<String>,
    region: Option<String>,
    city: Option<String>,
}

impl core::fmt::Debug for Location {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // How it was obtained only: coordinates and place are personal (SEC-D01).
        match &self.source {
            LocationSource::Device { .. } => f.write_str("Location(device, <personal>)"),
            LocationSource::Ip { reason, .. } => {
                write!(f, "Location(ip, {reason:?}, <personal>)")
            }
        }
    }
}

impl Location {
    /// A location the device gave, after the signer agreed. Coordinates are rounded to 4
    /// decimal places; `accuracy_m` is rounded up to whole metres.
    ///
    /// # Errors
    ///
    /// `CS-AUD-0011` when a coordinate is out of range or not finite, or the accuracy is
    /// negative, not finite or over [`MAX_ACCURACY_M`].
    pub fn device(latitude: f64, longitude: f64, accuracy_m: f64) -> Result<Self, AuditError> {
        let coordinates = Coordinates::new(latitude, longitude)?.rounded();
        if !accuracy_m.is_finite() || !(0.0..=f64::from(MAX_ACCURACY_M)).contains(&accuracy_m) {
            return Err(AuditError::location(LocationFault::Accuracy));
        }
        // Finite and in 0..=MAX_ACCURACY_M (checked above): the cast is exact after `ceil`.
        let accuracy_m = accuracy_m.ceil() as u32;
        Ok(Self {
            source: LocationSource::Device { accuracy_m },
            coordinates: Some(coordinates),
            country: None,
            region: None,
            city: None,
        })
    }

    /// A location approximated from the IP address by `database`, coordinates as the
    /// database gave them.
    ///
    /// # Errors
    ///
    /// `CS-AUD-0011` when a coordinate is out of range or the database name is empty,
    /// too long or has a control character.
    pub fn ip(
        reason: FallbackReason,
        database: &str,
        latitude: f64,
        longitude: f64,
    ) -> Result<Self, AuditError> {
        Ok(Self {
            source: LocationSource::Ip {
                reason,
                database: Some(text(database, MAX_DATABASE_BYTES, LocationFault::Database)?),
            },
            coordinates: Some(Coordinates::new(latitude, longitude)?),
            country: None,
            region: None,
            city: None,
        })
    }

    /// No device location, and no IP approximation: the lookup found nothing or did not
    /// run (`database` names the database when it ran). The reason is still recorded.
    ///
    /// # Errors
    ///
    /// `CS-AUD-0011` when the database name is empty, too long or has a control
    /// character.
    pub fn ip_unresolved(
        reason: FallbackReason,
        database: Option<&str>,
    ) -> Result<Self, AuditError> {
        let database = database
            .map(|d| text(d, MAX_DATABASE_BYTES, LocationFault::Database))
            .transpose()?;
        Ok(Self {
            source: LocationSource::Ip { reason, database },
            coordinates: None,
            country: None,
            region: None,
            city: None,
        })
    }

    /// The place, as the GeoIP database or the host's reverse lookup named it. Each is
    /// optional; `country` is an ISO 3166-1 alpha-2 code.
    ///
    /// # Errors
    ///
    /// `CS-AUD-0011` when the country is not two upper-case ASCII letters, a name is
    /// empty, over [`MAX_PLACE_BYTES`] or has a control character, or a place is named on
    /// an IP location whose lookup did not run (no database).
    pub fn with_place(
        mut self,
        country: Option<&str>,
        region: Option<&str>,
        city: Option<&str>,
    ) -> Result<Self, AuditError> {
        self.country = country.map(country_code).transpose()?;
        self.region = region
            .map(|r| text(r, MAX_PLACE_BYTES, LocationFault::Region))
            .transpose()?;
        self.city = city
            .map(|c| text(c, MAX_PLACE_BYTES, LocationFault::City))
            .transpose()?;
        self.check()?;
        Ok(self)
    }

    /// How it was obtained.
    #[must_use]
    pub fn source(&self) -> &LocationSource {
        &self.source
    }

    /// The coordinates, when there are any.
    #[must_use]
    pub fn coordinates(&self) -> Option<Coordinates> {
        self.coordinates
    }

    /// ISO 3166-1 alpha-2 country code.
    #[must_use]
    pub fn country(&self) -> Option<&str> {
        self.country.as_deref()
    }

    /// Region (state, province) name.
    #[must_use]
    pub fn region(&self) -> Option<&str> {
        self.region.as_deref()
    }

    /// City name.
    #[must_use]
    pub fn city(&self) -> Option<&str> {
        self.city.as_deref()
    }

    /// Whether the signer declined to share their device's location.
    #[must_use]
    pub fn declined(&self) -> bool {
        matches!(
            self.source,
            LocationSource::Ip {
                reason: FallbackReason::Declined,
                ..
            }
        )
    }

    /// The rules joining members: a device location has rounded coordinates; an IP
    /// location with coordinates or a place names its database.
    fn check(&self) -> Result<(), AuditError> {
        match &self.source {
            LocationSource::Device { accuracy_m } => {
                if *accuracy_m > MAX_ACCURACY_M {
                    return Err(AuditError::location(LocationFault::Accuracy));
                }
                match self.coordinates {
                    Some(c) if c.is_rounded() => Ok(()),
                    Some(_) => Err(AuditError::location(LocationFault::Precision)),
                    None => Err(AuditError::location(LocationFault::Coordinates)),
                }
            }
            LocationSource::Ip { database, .. } => {
                let found = self.coordinates.is_some()
                    || self.country.is_some()
                    || self.region.is_some()
                    || self.city.is_some();
                if found && database.is_none() {
                    Err(AuditError::location(LocationFault::Database))
                } else {
                    Ok(())
                }
            }
        }
    }
}

/// A bounded, non-empty text without control characters.
fn text(s: &str, max: usize, fault: LocationFault) -> Result<String, AuditError> {
    if s.is_empty() || s.len() > max || s.chars().any(char::is_control) {
        return Err(AuditError::location(fault));
    }
    Ok(s.to_owned())
}

/// Two upper-case ASCII letters (the shape of ISO 3166-1 alpha-2; whether the code is
/// assigned is the database's matter).
fn country_code(s: &str) -> Result<String, AuditError> {
    if s.len() == 2 && s.bytes().all(|b| b.is_ascii_uppercase()) {
        Ok(s.to_owned())
    } else {
        Err(AuditError::location(LocationFault::Country))
    }
}

/// The wire form: flat, members absent when unset. Unknown members are ignored, as a
/// later version may add some (docs/32 §2).
#[derive(Serialize, Deserialize)]
struct LocationWire {
    source: SourceKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    accuracy_m: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reason: Option<FallbackReason>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    database: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    latitude: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    longitude: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    country: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    region: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    city: Option<String>,
}

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum SourceKind {
    Device,
    Ip,
}

/// Decodes a location from a serde tree with its own fault: the wire's shape
/// ([`LocationFault::Source`]) or a value's.
pub(crate) fn location_from_serde(v: serde_json::Value) -> Result<Location, AuditError> {
    let wire: LocationWire =
        serde_json::from_value(v).map_err(|_| AuditError::location(LocationFault::Source))?;
    Location::try_from(wire)
}

impl TryFrom<LocationWire> for Location {
    type Error = AuditError;

    fn try_from(w: LocationWire) -> Result<Self, Self::Error> {
        let source = match (w.source, w.accuracy_m, w.reason) {
            (SourceKind::Device, Some(accuracy_m), None) if w.database.is_none() => {
                LocationSource::Device { accuracy_m }
            }
            (SourceKind::Ip, None, Some(reason)) => LocationSource::Ip {
                reason,
                database: w
                    .database
                    .as_deref()
                    .map(|d| text(d, MAX_DATABASE_BYTES, LocationFault::Database))
                    .transpose()?,
            },
            _ => return Err(AuditError::location(LocationFault::Source)),
        };
        let coordinates = match (w.latitude, w.longitude) {
            (Some(lat), Some(lon)) => Some(Coordinates::new(lat, lon)?),
            (None, None) => None,
            _ => return Err(AuditError::location(LocationFault::Coordinates)),
        };
        let mut location = Self {
            source,
            coordinates,
            country: None,
            region: None,
            city: None,
        };
        location =
            location.with_place(w.country.as_deref(), w.region.as_deref(), w.city.as_deref())?;
        Ok(location)
    }
}

impl From<Location> for LocationWire {
    fn from(l: Location) -> Self {
        let (source, accuracy_m, reason, database) = match l.source {
            LocationSource::Device { accuracy_m } => {
                (SourceKind::Device, Some(accuracy_m), None, None)
            }
            LocationSource::Ip { reason, database } => {
                (SourceKind::Ip, None, Some(reason), database)
            }
        };
        Self {
            source,
            accuracy_m,
            reason,
            database,
            latitude: l.coordinates.map(Coordinates::latitude),
            longitude: l.coordinates.map(Coordinates::longitude),
            country: l.country,
            region: l.region,
            city: l.city,
        }
    }
}

// Tests may unwrap, index and panic (CLAUDE.md).
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
#[cfg(test)]
mod tests {
    use super::*;

    fn fault(e: AuditError) -> LocationFault {
        assert_eq!(e.code(), "CS-AUD-0011");
        match e {
            AuditError::Location { fault } => fault,
            other => panic!("{other:?}"),
        }
    }

    fn decode(json: &str) -> Result<Location, String> {
        serde_json::from_str::<Location>(json).map_err(|e| e.to_string())
    }

    #[test]
    fn device_coordinates_are_rounded_to_four_places() {
        let l = Location::device(51.507_412_345, -0.127_758_9, 12.2).unwrap();
        let c = l.coordinates().unwrap();
        assert_eq!((c.latitude(), c.longitude()), (51.5074, -0.1278));
        assert_eq!(l.source(), &LocationSource::Device { accuracy_m: 13 });
        assert_eq!(
            serde_json::to_string(&l).unwrap(),
            r#"{"source":"device","accuracy_m":13,"latitude":51.5074,"longitude":-0.1278}"#
        );
    }

    #[test]
    fn rounding_is_idempotent_across_the_range() {
        let mut x = -180.0;
        while x <= 180.0 {
            let r = round4(x);
            assert_eq!(round4(r), r, "{x}");
            // And survives the wire: the shortest text parses back to the same double.
            assert_eq!(r.to_string().parse::<f64>().unwrap(), r);
            x += 0.012_345_67;
        }
    }

    #[test]
    fn coordinates_are_range_checked() {
        for (lat, lon, want) in [
            (90.000_1, 0.0, LocationFault::Latitude),
            (-90.000_1, 0.0, LocationFault::Latitude),
            (f64::NAN, 0.0, LocationFault::Latitude),
            (f64::INFINITY, 0.0, LocationFault::Latitude),
            (0.0, 180.000_1, LocationFault::Longitude),
            (0.0, -180.000_1, LocationFault::Longitude),
            (0.0, f64::NAN, LocationFault::Longitude),
        ] {
            assert_eq!(fault(Coordinates::new(lat, lon).unwrap_err()), want);
            assert_eq!(fault(Location::device(lat, lon, 5.0).unwrap_err()), want);
        }
        for (lat, lon) in [(90.0, 180.0), (-90.0, -180.0), (0.0, 0.0)] {
            assert!(Coordinates::new(lat, lon).is_ok());
        }
        // Negative zero is kept as one zero, so decoding `0` gives an equal value.
        let z = Coordinates::new(-0.0, -0.0).unwrap();
        assert!(z.latitude().is_sign_positive() && z.longitude().is_sign_positive());
    }

    #[test]
    fn accuracy_is_bounded() {
        for bad in [
            -1.0,
            f64::NAN,
            f64::INFINITY,
            f64::from(MAX_ACCURACY_M) + 1.0,
        ] {
            assert_eq!(
                fault(Location::device(1.0, 1.0, bad).unwrap_err()),
                LocationFault::Accuracy
            );
        }
        assert!(Location::device(1.0, 1.0, f64::from(MAX_ACCURACY_M)).is_ok());
        assert!(
            decode(r#"{"source":"device","accuracy_m":20037510,"latitude":1,"longitude":1}"#)
                .is_err()
        );
    }

    #[test]
    fn place_texts_are_bounded_and_clean() {
        let base = || {
            Location::ip(
                FallbackReason::Declined,
                "GeoLite2-City 2026-11-04",
                1.0,
                2.0,
            )
            .unwrap()
        };
        let long = "x".repeat(MAX_PLACE_BYTES + 1);
        let max = "é".repeat(MAX_PLACE_BYTES / 2);
        assert!(
            base()
                .with_place(Some("GB"), Some(&max), Some(&max))
                .is_ok()
        );
        for (c, r, ci, want) in [
            (Some("gb"), None, None, LocationFault::Country),
            (Some("GBR"), None, None, LocationFault::Country),
            (Some("G"), None, None, LocationFault::Country),
            (None, Some(long.as_str()), None, LocationFault::Region),
            (None, Some(""), None, LocationFault::Region),
            (None, None, Some(long.as_str()), LocationFault::City),
            (None, None, Some("Lon\ndon"), LocationFault::City),
            (None, None, Some("\u{202e}x\u{7}"), LocationFault::City),
        ] {
            assert_eq!(fault(base().with_place(c, r, ci).unwrap_err()), want);
        }
        let long_db = "d".repeat(MAX_DATABASE_BYTES + 1);
        assert_eq!(
            fault(Location::ip(FallbackReason::Declined, &long_db, 0.0, 0.0).unwrap_err()),
            LocationFault::Database
        );
        assert_eq!(
            fault(Location::ip_unresolved(FallbackReason::Unavailable, Some("")).unwrap_err()),
            LocationFault::Database
        );
    }

    #[test]
    fn an_unresolved_ip_location_states_the_refusal_but_no_place() {
        let l = Location::ip_unresolved(FallbackReason::Declined, None).unwrap();
        assert!(l.declined());
        assert_eq!(
            serde_json::to_string(&l).unwrap(),
            r#"{"source":"ip","reason":"declined"}"#
        );
        // A place without a lookup is refused: it would have come from nowhere.
        assert_eq!(
            fault(l.with_place(Some("GB"), None, None).unwrap_err()),
            LocationFault::Database
        );
    }

    #[test]
    fn wire_round_trips_and_refuses_inconsistent_members() {
        let l = Location::ip(
            FallbackReason::NotRequested,
            "GeoLite2-City 2026-11-04",
            48.8566,
            2.3522,
        )
        .unwrap()
        .with_place(Some("FR"), Some("Île-de-France"), Some("Paris"))
        .unwrap();
        let s = serde_json::to_string(&l).unwrap();
        assert_eq!(
            s,
            r#"{"source":"ip","reason":"not_requested","database":"GeoLite2-City 2026-11-04","latitude":48.8566,"longitude":2.3522,"country":"FR","region":"Île-de-France","city":"Paris"}"#
        );
        assert_eq!(decode(&s).unwrap(), l);
        // A later version's member is ignored.
        assert!(decode(r#"{"source":"ip","reason":"unavailable","altitude_m":3}"#).is_ok());
        for bad in [
            // Device with a reason, without accuracy, with a database.
            r#"{"source":"device","accuracy_m":5,"reason":"declined","latitude":1,"longitude":1}"#,
            r#"{"source":"device","latitude":1,"longitude":1}"#,
            r#"{"source":"device","accuracy_m":5,"database":"x","latitude":1,"longitude":1}"#,
            // Device without coordinates, or more precise than 4 places.
            r#"{"source":"device","accuracy_m":5}"#,
            r#"{"source":"device","accuracy_m":5,"latitude":1.00001,"longitude":1}"#,
            // IP without a reason, or with accuracy.
            r#"{"source":"ip","database":"x","latitude":1,"longitude":1}"#,
            r#"{"source":"ip","reason":"declined","accuracy_m":3}"#,
            // One coordinate only; out of range; coordinates without a database.
            r#"{"source":"ip","reason":"declined","database":"x","latitude":1}"#,
            r#"{"source":"ip","reason":"declined","database":"x","latitude":91,"longitude":1}"#,
            r#"{"source":"ip","reason":"declined","latitude":1,"longitude":1}"#,
            // Unknown source or reason.
            r#"{"source":"gps","accuracy_m":5,"latitude":1,"longitude":1}"#,
            r#"{"source":"ip","reason":"maybe"}"#,
        ] {
            assert!(decode(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn debug_never_prints_coordinates_or_place() {
        let l = Location::device(51.5074, -0.1278, 10.0)
            .unwrap()
            .with_place(Some("GB"), Some("England"), Some("London"))
            .unwrap();
        let d = format!("{l:?}");
        assert!(
            !d.contains("51") && !d.contains("London") && !d.contains("GB"),
            "{d}"
        );
        let ip = Location::ip_unresolved(FallbackReason::Declined, None).unwrap();
        assert_eq!(format!("{ip:?}"), "Location(ip, Declined, <personal>)");
    }
}
