//! Signer location (owner instruction 17, row GEO-01): a device location the browser's
//! Geolocation API gave, or the recipient declining to share one; and, when the
//! envelope captures location and the device gave none, an approximation from the
//! client's address in an operator-supplied GeoIP database (`.mmdb`, for example DB-IP
//! Lite under CC BY 4.0; never committed or bundled; its path from
//! `OPENSEAL_GEOIP_DB`). Coordinates and addresses are personal data: they go into audit
//! events only, never into logs.
//!
//! **Evidence** ([`evidence`], docs/32 §2): when the envelope's
//! `signing_options.capture_location` is on, every ceremony request that records a
//! recipient action carries a location: the device's fix; else an approximation of the
//! client address with the reason (`declined` when the signer refused, `unavailable`
//! when the device gave nothing or was not asked yet) and the database's name and build
//! date; else, when there is no database, no address or no record, the reason alone
//! (`ip_unresolved`). Never omitted, so a refusal never blocks signing. When the
//! setting is off nothing is recorded, whatever the request says.

use std::net::IpAddr;
use std::path::Path;

use casual_sign_audit::{FallbackReason, Location};
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

/// A GeoIP database.
pub struct GeoIp {
    reader: maxminddb::Reader<Vec<u8>>,
}

impl core::fmt::Debug for GeoIp {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("GeoIp")
            .field("database", &self.reader.metadata.database_type)
            .field("build_epoch", &self.reader.metadata.build_epoch)
            .finish()
    }
}

#[derive(Deserialize)]
struct Record {
    #[serde(default)]
    location: Option<RecordLocation>,
    #[serde(default)]
    country: Option<RecordCountry>,
}

#[derive(Deserialize)]
struct RecordLocation {
    latitude: Option<f64>,
    longitude: Option<f64>,
    accuracy_radius: Option<u16>,
}

#[derive(Deserialize)]
struct RecordCountry {
    iso_code: Option<String>,
}

/// Where location evidence came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    /// The device's own fix.
    Device,
    /// A GeoIP lookup of the client address in the named database.
    GeoIp {
        /// The database's `database_type`, from its metadata.
        database: String,
        /// Its build time, Unix seconds, from its metadata.
        build_epoch: u64,
    },
}

/// A location as evidence records it.
#[derive(Debug, Clone, PartialEq)]
pub struct Located {
    /// Degrees.
    pub latitude: f64,
    /// Degrees.
    pub longitude: f64,
    /// Accuracy radius in metres.
    pub accuracy_m: f64,
    /// ISO 3166-1 alpha-2 country, when the database names one.
    pub country: Option<String>,
    /// Where it came from.
    pub source: Source,
}

impl GeoIp {
    /// Open the database at `path`.
    ///
    /// # Errors
    ///
    /// A message naming the problem (never the file's content).
    pub fn open(path: &Path) -> Result<Self, String> {
        let bytes =
            std::fs::read(path).map_err(|e| format!("geoip database unreadable: {}", e.kind()))?;
        Self::from_bytes(bytes)
    }

    /// A database from its bytes.
    ///
    /// # Errors
    ///
    /// When the bytes are not a MaxMind DB.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, String> {
        let reader = maxminddb::Reader::from_source(bytes)
            .map_err(|_| "not a MaxMind DB file".to_owned())?;
        Ok(Self { reader })
    }

    /// The approximate location of `ip`, when the database has one.
    #[must_use]
    pub fn locate(&self, ip: IpAddr) -> Option<Located> {
        let rec: Record = self.reader.lookup(ip).ok()?.decode().ok()??;
        let loc = rec.location?;
        let (latitude, longitude) = (loc.latitude?, loc.longitude?);
        if !(-90.0..=90.0).contains(&latitude) || !(-180.0..=180.0).contains(&longitude) {
            return None;
        }
        Some(Located {
            latitude,
            longitude,
            // GeoIP radii are kilometres; none given means country scale.
            accuracy_m: f64::from(loc.accuracy_radius.unwrap_or(1000)) * 1000.0,
            country: rec.country.and_then(|c| c.iso_code),
            source: Source::GeoIp {
                database: self.reader.metadata.database_type.clone(),
                build_epoch: self.reader.metadata.build_epoch,
            },
        })
    }
}

impl GeoIp {
    /// The database as events name it: its type and build date, for example
    /// `GeoLite2-City 2026-11-04` (at most 128 bytes, no control characters).
    #[must_use]
    pub fn name(&self) -> String {
        let m = &self.reader.metadata;
        let date = i64::try_from(m.build_epoch)
            .ok()
            .and_then(|e| time::OffsetDateTime::from_unix_timestamp(e).ok())
            .map(|t| t.date().to_string())
            .unwrap_or_else(|| "unknown".to_owned());
        let kind: String = m
            .database_type
            .chars()
            .filter(|c| !c.is_control())
            .take(100)
            .collect();
        let kind = if kind.trim().is_empty() {
            "GeoIP".to_owned()
        } else {
            kind
        };
        format!("{kind} {date}")
    }
}

/// The location a ceremony request records (GEO-01): `None` exactly when the envelope
/// does not capture location; otherwise the device's fix, else the IP approximation
/// with its reason, else the reason alone.
#[must_use]
pub fn evidence(
    device: Option<&DeviceLocation>,
    capture: bool,
    ip: Option<IpAddr>,
    geoip: Option<&GeoIp>,
) -> Option<Location> {
    if !capture {
        return None;
    }
    if let Some((latitude, longitude, accuracy_m)) = device.and_then(DeviceLocation::fix)
        && let Ok(l) = Location::device(latitude, longitude, accuracy_m)
    {
        return Some(l);
    }
    let reason = match device {
        Some(DeviceLocation::Declined { declined: true }) => FallbackReason::Declined,
        _ => FallbackReason::Unavailable,
    };
    let name = geoip.map(GeoIp::name);
    let approx = geoip.zip(ip).and_then(|(g, ip)| g.locate(ip));
    if let (Some(a), Some(n)) = (approx, name.as_deref())
        && let Ok(l) = Location::ip(reason, n, a.latitude, a.longitude)
    {
        // A country the database names in another shape is left out, not fatal.
        return Some(
            l.clone()
                .with_place(a.country.as_deref(), None, None)
                .unwrap_or(l),
        );
    }
    Location::ip_unresolved(reason, name.as_deref())
        .or_else(|_| Location::ip_unresolved(reason, None))
        .ok()
}

#[cfg(test)]
// Tests may unwrap, index and panic (CLAUDE.md).
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)]
pub(crate) mod tests {
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

    // A minimal MaxMind DB built here from the format's specification (no real geodata
    // is committed): an IPv4 tree of one node whose left half (0.0.0.0/1) points at one
    // record and whose right half (128.0.0.0/1) has none.
    fn ctl(kind: u8, size: usize, out: &mut Vec<u8>) {
        if kind <= 7 {
            out.push((kind << 5) | size as u8);
        } else {
            out.push(size as u8);
            out.push(kind - 7);
        }
    }
    fn s(v: &str, out: &mut Vec<u8>) {
        ctl(2, v.len(), out);
        out.extend_from_slice(v.as_bytes());
    }
    fn d(v: f64, out: &mut Vec<u8>) {
        ctl(3, 8, out);
        out.extend_from_slice(&v.to_be_bytes());
    }
    fn u(kind: u8, v: u64, width: usize, out: &mut Vec<u8>) {
        ctl(kind, width, out);
        out.extend_from_slice(&v.to_be_bytes()[8 - width..]);
    }

    pub(crate) fn test_mmdb() -> Vec<u8> {
        let mut data = Vec::new();
        ctl(7, 2, &mut data);
        s("country", &mut data);
        ctl(7, 1, &mut data);
        s("iso_code", &mut data);
        s("GB", &mut data);
        s("location", &mut data);
        ctl(7, 3, &mut data);
        s("latitude", &mut data);
        d(51.5, &mut data);
        s("longitude", &mut data);
        d(-0.125, &mut data);
        s("accuracy_radius", &mut data);
        u(5, 50, 2, &mut data);
        let node_count: u32 = 1;
        let pointer = node_count + 16;
        let mut out = Vec::new();
        out.extend_from_slice(&pointer.to_be_bytes()[1..]);
        out.extend_from_slice(&node_count.to_be_bytes()[1..]);
        out.extend_from_slice(&[0u8; 16]);
        out.extend_from_slice(&data);
        out.extend_from_slice(&[0xAB, 0xCD, 0xEF]);
        out.extend_from_slice(b"MaxMind.com");
        let mut m = Vec::new();
        ctl(7, 9, &mut m);
        s("binary_format_major_version", &mut m);
        u(5, 2, 1, &mut m);
        s("binary_format_minor_version", &mut m);
        u(5, 0, 0, &mut m);
        s("build_epoch", &mut m);
        u(9, 1_794_000_000, 8, &mut m);
        s("database_type", &mut m);
        s("OpenSeal-Test-City", &mut m);
        s("description", &mut m);
        ctl(7, 0, &mut m);
        s("ip_version", &mut m);
        u(5, 4, 1, &mut m);
        s("languages", &mut m);
        ctl(11, 0, &mut m);
        s("node_count", &mut m);
        u(6, u64::from(node_count), 4, &mut m);
        s("record_size", &mut m);
        u(5, 24, 1, &mut m);
        out.extend_from_slice(&m);
        out
    }

    #[test]
    fn geoip_locates_from_the_database_and_names_it() {
        let g = GeoIp::from_bytes(test_mmdb()).unwrap();
        let l = g.locate("1.2.3.4".parse().unwrap()).unwrap();
        assert_eq!(
            (l.latitude, l.longitude, l.accuracy_m),
            (51.5, -0.125, 50_000.0)
        );
        assert_eq!(l.country.as_deref(), Some("GB"));
        assert_eq!(
            l.source,
            Source::GeoIp {
                database: "OpenSeal-Test-City".into(),
                build_epoch: 1_794_000_000
            }
        );
        assert!(
            g.locate("200.1.1.1".parse().unwrap()).is_none(),
            "no record"
        );
        assert!(
            g.locate("2001:db8::1".parse().unwrap()).is_none(),
            "v6 in v4"
        );
        assert!(GeoIp::from_bytes(b"not a database".to_vec()).is_err());
    }

    #[test]
    fn evidence_is_the_device_else_the_ip_with_its_reason_and_never_absent_when_on() {
        use casual_sign_audit::LocationSource;
        let g = GeoIp::from_bytes(test_mmdb()).unwrap();
        assert_eq!(g.name(), "OpenSeal-Test-City 2026-11-06");
        let ip = Some("1.2.3.4".parse().unwrap());
        let fix: DeviceLocation =
            serde_json::from_str(r#"{"latitude":48.85,"longitude":2.35,"accuracy_m":15}"#).unwrap();
        let declined: DeviceLocation = serde_json::from_str(r#"{"declined":true}"#).unwrap();
        // Off: nothing, whatever the request says.
        assert!(evidence(Some(&fix), false, ip, Some(&g)).is_none());
        assert!(evidence(None, false, ip, Some(&g)).is_none());
        // The device wins.
        let d = evidence(Some(&fix), true, ip, Some(&g)).unwrap();
        assert!(matches!(
            d.source(),
            LocationSource::Device { accuracy_m: 15 }
        ));
        // Declined: the approximation, the reason and the database.
        let a = evidence(Some(&declined), true, ip, Some(&g)).unwrap();
        assert_eq!(
            a.source(),
            &LocationSource::Ip {
                reason: FallbackReason::Declined,
                database: Some("OpenSeal-Test-City 2026-11-06".into())
            }
        );
        assert!(a.coordinates().is_some());
        assert_eq!(a.country(), Some("GB"));
        // Nothing from the device: unavailable.
        let u = evidence(None, true, ip, Some(&g)).unwrap();
        assert!(matches!(
            u.source(),
            LocationSource::Ip {
                reason: FallbackReason::Unavailable,
                ..
            }
        ));
        // No record, no database, no address: the reason alone.
        let miss = evidence(None, true, Some("200.1.1.1".parse().unwrap()), Some(&g)).unwrap();
        assert!(miss.coordinates().is_none());
        assert!(matches!(
            miss.source(),
            LocationSource::Ip {
                database: Some(_),
                ..
            }
        ));
        let none = evidence(Some(&declined), true, ip, None).unwrap();
        assert_eq!(
            none.source(),
            &LocationSource::Ip {
                reason: FallbackReason::Declined,
                database: None
            }
        );
        assert!(
            evidence(None, true, None, Some(&g))
                .unwrap()
                .coordinates()
                .is_none()
        );
    }
}
