//! Hard limits on what a PDF may make the reader do (docs/21).

const MIB: u64 = 1024 * 1024;

/// Hard limits on what a PDF may make the reader do (docs/21).
///
/// Defaults are the values in docs/21; a host may lower or raise them. No limit is
/// ever taken from the file itself, and no allocation is ever sized by a number read
/// from the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Largest input accepted, in bytes (`CS-PDF-0001`).
    pub max_input_bytes: u64,
    /// Most distinct indirect objects, and most cross-reference entries read from any
    /// one section (`CS-PDF-0002`).
    pub max_objects: u32,
    /// Deepest nesting of arrays and dictionaries (`CS-PDF-0004`). Values above 4,096
    /// are treated as 4,096: deeper values could overflow the stack when dropped.
    pub max_depth: u16,
    /// Most reference hops when resolving one value (`CS-PDF-0004`).
    pub max_ref_depth: u16,
    /// Most revisions along a `/Prev` chain (`CS-PDF-0006`).
    pub max_revisions: u16,
    /// Most pages (`CS-PDF-0007`).
    pub max_pages: u32,
    /// Largest single decoded stream, in bytes, applied to every filter stage
    /// (`CS-PDF-0003`).
    pub max_stream_bytes: u64,
    /// Largest total decoded across the document, in bytes, counting every filter
    /// stage (`CS-PDF-0003`).
    pub max_total_decoded_bytes: u64,
    /// Decode ratio per stream: output may be at most `ratio_grace_bytes +
    /// max_decode_ratio × encoded length` (`CS-PDF-0003`).
    pub max_decode_ratio: u32,
    /// Output a stream may produce before the ratio applies (docs/21: the first 1 MiB).
    pub ratio_grace_bytes: u64,
    /// Longest filter chain on one stream (`CS-PDF-0011`).
    pub max_filter_chain: u8,
    /// Longest string, in decoded bytes (`CS-PDF-0008`).
    pub max_string_bytes: u32,
    /// Longest name, in decoded bytes (`CS-PDF-0008`).
    pub max_name_bytes: u16,
    /// Most content-stream operators counted per page (`CS-PDF-0013`).
    pub max_content_ops: u32,
    /// Decoded object-stream bytes kept in memory for reuse. Beyond it the oldest is
    /// dropped and decoded again (and charged again) when needed. Not a docs/21 limit:
    /// it bounds memory, not work.
    pub objstm_cache_bytes: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_input_bytes: 50 * MIB,
            max_objects: 1_000_000,
            max_depth: 256,
            max_ref_depth: 64,
            max_revisions: 1_000,
            max_pages: 5_000,
            max_stream_bytes: 256 * MIB,
            max_total_decoded_bytes: 1024 * MIB,
            max_decode_ratio: 1_000,
            ratio_grace_bytes: MIB,
            max_filter_chain: 8,
            max_string_bytes: 16 * 1024 * 1024,
            max_name_bytes: 127,
            max_content_ops: 2_000_000,
            objstm_cache_bytes: 64 * MIB,
        }
    }
}

/// The highest object number ISO 32000-1 Annex C allows; a `/Size` above it is damage.
pub(crate) const MAX_XREF_SIZE: u64 = 8_388_607;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_limits_match_docs_21() {
        let limits = Limits::default();
        assert_eq!(limits.max_input_bytes, 52_428_800);
        assert_eq!(limits.max_objects, 1_000_000);
        assert_eq!(limits.max_depth, 256);
        assert_eq!(limits.max_ref_depth, 64);
        assert_eq!(limits.max_revisions, 1_000);
        assert_eq!(limits.max_pages, 5_000);
        assert_eq!(limits.max_stream_bytes, 268_435_456);
        assert_eq!(limits.max_total_decoded_bytes, 1_073_741_824);
        assert_eq!(limits.max_decode_ratio, 1_000);
        assert_eq!(limits.ratio_grace_bytes, 1_048_576);
        assert_eq!(limits.max_filter_chain, 8);
        assert_eq!(limits.max_string_bytes, 16_777_216);
        assert_eq!(limits.max_name_bytes, 127);
        assert_eq!(limits.max_content_ops, 2_000_000);
    }
}
