//! The XFA packets' XML, read by `casual-sign-xml` (ADR-026; the reader moved there by
//! ADR-047 so the India eSign host can share it), in its lenient mode, with each of its
//! errors given this crate's docs/20 code.

pub(crate) use casual_sign_xml::{Dom, NodeId};
use casual_sign_xml::{Limits, XmlError};

use crate::error::XfaError;

/// Limits the reader holds (from [`crate::XfaLimits`]).
#[derive(Debug, Clone, Copy)]
pub(crate) struct XmlLimits {
    pub max_depth: usize,
    pub max_nodes: usize,
    pub max_attributes: usize,
}

/// Parse `bytes` as one XML document within `limits`.
pub(crate) fn parse(
    bytes: &[u8],
    limits: XmlLimits,
    cancel: &dyn Fn() -> bool,
) -> Result<Dom, XfaError> {
    let lim = Limits::lenient(limits.max_depth, limits.max_nodes, limits.max_attributes);
    casual_sign_xml::parse(bytes, &lim, cancel).map_err(|e| match e {
        XmlError::TooDeep { offset } => XfaError::TooDeep { offset },
        XmlError::TooManyNodes { offset } => XfaError::TooManyNodes { offset },
        XmlError::Dtd { offset } => XfaError::Dtd { offset },
        XmlError::Cancelled => XfaError::Cancelled,
        // The size is checked by the caller (`CS-XFA-0001`) and lenient mode decodes
        // every byte, so the rest are malformed input.
        XmlError::Malformed { offset } => XfaError::Malformed { offset },
        _ => XfaError::Malformed { offset: 0 },
    })
}

#[cfg(test)]
mod tests {
    // Test code: a panic is the failure report (CLAUDE.md).
    #![allow(clippy::unwrap_used)]
    use super::*;

    const LIM: XmlLimits = XmlLimits {
        max_depth: 8,
        max_nodes: 100,
        max_attributes: 4,
    };

    #[test]
    fn the_readers_errors_keep_their_xfa_codes() {
        let p = |s: &str| parse(s.as_bytes(), LIM, &|| false).map(|_| ());
        assert_eq!(p("<a></b>").unwrap_err().code(), "CS-XFA-0004");
        assert_eq!(p("<!DOCTYPE a><a/>").unwrap_err().code(), "CS-XFA-0005");
        let deeper = "<a>".repeat(9) + &"</a>".repeat(9);
        assert_eq!(p(&deeper).unwrap_err().code(), "CS-XFA-0002");
        assert_eq!(
            p("<a q='1' r='1' s='1' t='1' u='1'/>").unwrap_err().code(),
            "CS-XFA-0003"
        );
        let many = "<a>".to_owned() + &"<b/>".repeat(5000) + "</a>";
        let big = XmlLimits {
            max_nodes: 10_000,
            ..LIM
        };
        assert_eq!(
            parse(many.as_bytes(), big, &|| true).unwrap_err().code(),
            "CS-XFA-0009"
        );
        assert!(p("<a k='v'><b>t</b></a>").is_ok());
    }
}
