//! A minimal MaxMind DB built from the format's specification (no real geodata is
//! committed): an IPv4 tree of one node whose left half (0.0.0.0/1) points at one
//! record (GB, 51.5, -0.125, radius 50 km) and whose right half (128.0.0.0/1) has none.
//! Its type is `OpenSeal-Test-City`, built 2026-11-06. The same construction as the
//! unit test in `src/geo.rs`.

// Test code: fixed small values (CLAUDE.md: tests may index and do arithmetic).
#![allow(
    clippy::cast_possible_truncation,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing
)]

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

/// The database's bytes.
pub fn test_mmdb() -> Vec<u8> {
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
