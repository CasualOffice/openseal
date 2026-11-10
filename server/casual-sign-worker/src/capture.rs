//! Signature art as the seal job reads it.
//!
//! **Contract with the API (stage 2C).** A captured signature, initials or stamp is
//! stored in the blob store as a small JSON document (below); its blob key, the
//! SHA-256 of those bytes as 64 lower-case hex digits, is both the `image_hash` of the
//! recipient's `AdoptSignature` and the id a `FieldValue::Signature` names. An uploaded
//! image is a second blob, named from the capture by its key.
//!
//! ```json
//! {"kind":"drawn","strokes":[[[0.0,10.5],[3.2,11.0]]],"color":[0,0,128]}
//! {"kind":"typed","text":"Ada Lovelace","style":0}
//! {"kind":"image","image":"<64 hex: the PNG or JPEG's blob key>"}
//! ```
//!
//! Captures are hostile input: bounded in bytes, strokes and points, and every number
//! must be finite. The flattener applies its own image and point limits (docs/21).

use casual_sign_model::Rgb;
use casual_sign_sdk::{Art, Ink, InkPoint};
use serde::Deserialize;

use crate::error::{Result, WorkerError};

/// Largest capture document read, in bytes.
pub const MAX_CAPTURE_BYTES: usize = 1024 * 1024;
/// Most strokes in a drawn capture.
pub const MAX_STROKES: usize = 1_000;
/// Most points over all strokes of a drawn capture.
pub const MAX_POINTS: usize = 100_000;
/// Longest typed signature, in bytes.
pub const MAX_TYPED: usize = 1_000;
/// Largest uploaded signature image, in bytes (docs/21: images are re-encoded by the API
/// first; this is the worker's own cap).
pub const MAX_IMAGE_BYTES: usize = 5 * 1024 * 1024;

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Doc {
    Drawn {
        strokes: Vec<Vec<[f64; 2]>>,
        #[serde(default)]
        color: Option<[u8; 3]>,
    },
    Typed {
        text: String,
        #[serde(default)]
        style: usize,
    },
    Image {
        image: String,
    },
}

/// A capture read from its bytes: the art, or the blob key of the image to fetch.
#[derive(Debug, Clone, PartialEq)]
pub enum Parsed {
    /// Ready to draw.
    Art(Art),
    /// An uploaded image: fetch this blob (64 hex), then [`image_art`].
    Image(String),
}

/// Parse a capture document.
///
/// # Errors
///
/// `CS-WRK-0016` when it is malformed or over a limit.
pub fn parse(bytes: &[u8]) -> Result<Parsed> {
    if bytes.len() > MAX_CAPTURE_BYTES {
        return Err(WorkerError::BadCapture);
    }
    let doc: Doc = serde_json::from_slice(bytes).map_err(|_| WorkerError::BadCapture)?;
    match doc {
        Doc::Drawn { strokes, color } => {
            let points: usize = strokes.iter().map(Vec::len).sum();
            if strokes.is_empty() || strokes.len() > MAX_STROKES || points > MAX_POINTS {
                return Err(WorkerError::BadCapture);
            }
            let mut out = Vec::with_capacity(strokes.len());
            for s in strokes {
                let mut pts = Vec::with_capacity(s.len());
                for [x, y] in s {
                    if !x.is_finite() || !y.is_finite() {
                        return Err(WorkerError::BadCapture);
                    }
                    pts.push(InkPoint { x, y });
                }
                out.push(pts);
            }
            Ok(Parsed::Art(Art::Drawn(Ink {
                strokes: out,
                color: color.map(Rgb),
            })))
        }
        Doc::Typed { text, style } => {
            if text.trim().is_empty()
                || text.len() > MAX_TYPED
                || text.chars().any(char::is_control)
            {
                return Err(WorkerError::BadCapture);
            }
            Ok(Parsed::Art(Art::Typed { text, style }))
        }
        Doc::Image { image } => {
            if image.len() != 64
                || !image
                    .bytes()
                    .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
            {
                return Err(WorkerError::BadCapture);
            }
            Ok(Parsed::Image(image))
        }
    }
}

/// An uploaded image's art.
///
/// # Errors
///
/// `CS-WRK-0016` over [`MAX_IMAGE_BYTES`].
pub fn image_art(bytes: Vec<u8>) -> Result<Art> {
    if bytes.len() > MAX_IMAGE_BYTES || bytes.is_empty() {
        return Err(WorkerError::BadCapture);
    }
    Ok(Art::Image(bytes))
}

#[cfg(test)]
// Tests may unwrap (CLAUDE.md).
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn captures_parse_within_bounds() {
        assert!(matches!(
            parse(br#"{"kind":"drawn","strokes":[[[0,1],[2,3]]]}"#).unwrap(),
            Parsed::Art(Art::Drawn(_))
        ));
        assert!(matches!(
            parse(br#"{"kind":"typed","text":"Ada","style":1}"#).unwrap(),
            Parsed::Art(Art::Typed { .. })
        ));
        let key = "a".repeat(64);
        assert_eq!(
            parse(format!(r#"{{"kind":"image","image":"{key}"}}"#).as_bytes()).unwrap(),
            Parsed::Image(key)
        );
        for bad in [
            &br#"{"kind":"drawn","strokes":[]}"#[..],
            br#"{"kind":"drawn","strokes":[[[1e999,0]]]}"#,
            br#"{"kind":"typed","text":"  "}"#,
            br#"{"kind":"typed","text":"a\nb"}"#,
            br#"{"kind":"image","image":"../../etc/passwd"}"#,
            br#"{"kind":"video"}"#,
            br#"{"kind":"typed","text":"a","extra":1}"#,
            b"not json",
        ] {
            assert_eq!(parse(bad).unwrap_err().code(), "CS-WRK-0016");
        }
        let many = format!(
            r#"{{"kind":"drawn","strokes":[{}]}}"#,
            vec!["[[0,0]]"; MAX_STROKES + 1].join(",")
        );
        assert!(parse(many.as_bytes()).is_err());
    }
}
