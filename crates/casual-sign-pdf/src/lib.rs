//! Bounded PDF reading and incremental writing for OpenSeal.
//!
//! Every uploaded PDF is hostile (docs/07). This crate will admit a PDF within the
//! limits of docs/21, classify what it contains, neutralize active content, and append
//! incremental updates without ever rewriting earlier bytes (docs/30). It performs no
//! I/O, reads no clock and holds no key: the host supplies bytes, limits and a
//! cancellation predicate.
//!
//! **Phase 0 skeleton.** The reader arrives with stage 1A (`T-1A` in docs/14), after
//! `SPK-01` decides between our own reader and an existing crate (ADR-005). Until then
//! this crate only fixes the limits' home, so the fuzz workspace and the dependency gate
//! have a first consumer.

/// Hard limits on what a PDF may make the reader do (docs/21).
///
/// Defaults are the proposed values in docs/21; a host may lower or raise them. No
/// limit is ever taken from the file itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Largest input accepted, in bytes (`CS-PDF-0001`).
    pub max_input_bytes: u64,
    /// Most indirect objects or cross-reference entries (`CS-PDF-0002`).
    pub max_objects: u32,
    /// Deepest nesting of arrays and dictionaries (`CS-PDF-0004`).
    pub max_depth: u16,
    /// Most revisions along a `/Prev` chain (`CS-PDF-0006`).
    pub max_revisions: u16,
    /// Most pages (`CS-PDF-0007`).
    pub max_pages: u32,
    /// Largest single decoded stream, in bytes (`CS-PDF-0003`).
    pub max_stream_bytes: u64,
    /// Largest total decoded across the document, in bytes (`CS-PDF-0003`).
    pub max_total_decoded_bytes: u64,
}

impl Default for Limits {
    fn default() -> Self {
        const MIB: u64 = 1024 * 1024;
        Self {
            max_input_bytes: 50 * MIB,
            max_objects: 1_000_000,
            max_depth: 256,
            max_revisions: 1_000,
            max_pages: 5_000,
            max_stream_bytes: 256 * MIB,
            max_total_decoded_bytes: 1024 * MIB,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_limits_match_docs_21() {
        let limits = Limits::default();
        assert_eq!(limits.max_input_bytes, 52_428_800);
        assert_eq!(limits.max_objects, 1_000_000);
        assert_eq!(limits.max_depth, 256);
        assert_eq!(limits.max_revisions, 1_000);
        assert_eq!(limits.max_pages, 5_000);
        assert_eq!(limits.max_stream_bytes, 268_435_456);
        assert_eq!(limits.max_total_decoded_bytes, 1_073_741_824);
    }
}
