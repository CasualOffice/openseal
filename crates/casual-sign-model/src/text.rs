//! Bounded strings: ids, data labels, values and formula text.

use core::fmt;

use serde::{Deserialize, Serialize};

use crate::ModelError;
use crate::limits::{MAX_FORMULA_CHARS, MAX_ID_BYTES, MAX_LABEL_BYTES, MAX_VALUE_BYTES};

/// An opaque id minted by the host (docs/22 §2): 1 to 64 bytes of `[A-Za-z0-9_-]`.
///
/// The engine never interprets it; a UUIDv7 in its hyphenated form fits.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Id(String);

impl Id {
    /// Builds an id, refusing an empty, overlong or oddly-charactered one (`CS-FLD-0005`).
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        let ok = !value.is_empty()
            && value.len() <= MAX_ID_BYTES
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
        if ok {
            Ok(Self(value))
        } else {
            Err(ModelError::InvalidId { bytes: value.len() })
        }
    }

    /// The id as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for Id {
    type Error = ModelError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<Id> for String {
    fn from(value: Id) -> Self {
        value.0
    }
}

impl fmt::Display for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A field's data label (docs/22 §6): the name formulas and conditions refer to, and the
/// key that links fields carrying the same value.
///
/// 1 to 255 bytes of any Unicode except control characters. Labels are compared after
/// NFC normalization by `casual-sign-fields`, so two spellings of "café" are one label.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct DataLabel(String);

impl DataLabel {
    /// Builds a label, refusing an empty, overlong or control-bearing one (`CS-FLD-0002`).
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        let ok = !value.is_empty()
            && value.len() <= MAX_LABEL_BYTES
            && !value.chars().any(char::is_control);
        if ok {
            Ok(Self(value))
        } else {
            Err(ModelError::InvalidLabel { bytes: value.len() })
        }
    }

    /// The label as written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for DataLabel {
    type Error = ModelError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<DataLabel> for String {
    fn from(value: DataLabel) -> Self {
        value.0
    }
}

/// A text value, option, message, tooltip or placeholder: at most 4,000 bytes (docs/21).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Text(String);

impl Text {
    /// Builds a text value, refusing one over 4,000 bytes (`CS-FLD-0002`).
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if value.len() > MAX_VALUE_BYTES {
            return Err(ModelError::TextTooLong {
                bytes: value.len(),
                limit: MAX_VALUE_BYTES,
            });
        }
        Ok(Self(value))
    }

    /// The text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether the text is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl TryFrom<String> for Text {
    type Error = ModelError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<Text> for String {
    fn from(value: Text) -> Self {
        value.0
    }
}

/// A formula expression: at most 1,024 characters (docs/21). Its grammar is checked by
/// `casual-sign-fields`, which also bounds depth and references.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct FormulaText(String);

impl FormulaText {
    /// Builds formula text, refusing more than 1,024 characters (`CS-FLD-0021`).
    ///
    /// The count stops one past the limit, so a megabyte of input costs no more than
    /// a kilobyte.
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if value.chars().nth(MAX_FORMULA_CHARS).is_some() {
            return Err(ModelError::FormulaTooLong {
                chars: MAX_FORMULA_CHARS.saturating_add(1),
                limit: MAX_FORMULA_CHARS,
            });
        }
        Ok(Self(value))
    }

    /// The expression.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for FormulaText {
    type Error = ModelError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<FormulaText> for String {
    fn from(value: FormulaText) -> Self {
        value.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_accepts_a_uuid_and_refuses_odd_characters() {
        assert!(Id::new("0190b7a2-6d3e-7c1f-8a2b-1234567890ab").is_ok());
        for bad in ["", "a b", "a/b", "é", &"x".repeat(65)] {
            assert_eq!(
                Id::new(bad).map_err(|e| e.code()),
                Err("CS-FLD-0005"),
                "{bad:?}"
            );
        }
        assert!(Id::new("x".repeat(64)).is_ok());
    }

    #[test]
    fn label_accepts_unicode_and_refuses_control_characters() {
        assert!(DataLabel::new("Prix unitaire (€) — café 単価").is_ok());
        assert!(DataLabel::new("").is_err());
        assert!(DataLabel::new("a\u{0}b").is_err());
        assert!(DataLabel::new("a\nb").is_err());
        assert!(DataLabel::new("x".repeat(255)).is_ok());
        assert_eq!(
            DataLabel::new("x".repeat(256)).map_err(|e| e.code()),
            Err("CS-FLD-0002")
        );
    }

    #[test]
    fn text_is_bounded_at_4000_bytes() {
        assert!(Text::new("a".repeat(4_000)).is_ok());
        let err = Text::new("a".repeat(4_001)).err();
        assert_eq!(
            err,
            Some(ModelError::TextTooLong {
                bytes: 4_001,
                limit: 4_000
            })
        );
        // Bytes, not characters: 1,334 three-byte characters are 4,002 bytes.
        assert!(Text::new("€".repeat(1_334)).is_err());
    }

    #[test]
    fn formula_text_is_bounded_at_1024_characters() {
        assert!(FormulaText::new("1".repeat(1_024)).is_ok());
        assert!(FormulaText::new("€".repeat(1_024)).is_ok());
        let err = FormulaText::new("1".repeat(1_025)).err().map(|e| e.code());
        assert_eq!(err, Some("CS-FLD-0021"));
        assert!(FormulaText::new("1".repeat(100_000)).is_err());
    }

    #[test]
    fn deserializing_enforces_the_same_limits() {
        let long = format!("\"{}\"", "a".repeat(4_001));
        assert!(serde_json::from_str::<Text>(&long).is_err());
        assert!(serde_json::from_str::<Id>("\"a b\"").is_err());
        assert_eq!(
            serde_json::from_str::<Id>("\"ab\"").ok(),
            Id::new("ab").ok()
        );
    }
}
