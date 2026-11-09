//! The PDF object model (ISO 32000-2 §7.3).

use core::ops::Range;

/// An indirect reference `num gen R`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ObjRef {
    /// Object number.
    pub num: u32,
    /// Generation number.
    pub generation: u16,
}

/// A dictionary: keys are names without the leading `/`, in file order.
///
/// Duplicate keys are kept as read; [`Dictionary::get`] returns the last, as most
/// readers do.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Dictionary {
    entries: Vec<(Vec<u8>, Object)>,
}

impl Dictionary {
    /// An empty dictionary.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The value for `key` (a name without `/`), if present.
    #[must_use]
    pub fn get(&self, key: &[u8]) -> Option<&Object> {
        self.entries
            .iter()
            .rev()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v)
    }

    /// True when `key` is present.
    #[must_use]
    pub fn contains(&self, key: &[u8]) -> bool {
        self.get(key).is_some()
    }

    /// The name stored under `key`, if it is a name.
    #[must_use]
    pub fn name(&self, key: &[u8]) -> Option<&[u8]> {
        match self.get(key) {
            Some(Object::Name(n)) => Some(n),
            _ => None,
        }
    }

    /// Entries in file order.
    pub fn iter(&self) -> impl Iterator<Item = (&[u8], &Object)> {
        self.entries.iter().map(|(k, v)| (k.as_slice(), v))
    }

    /// Number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when there are no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub(crate) fn push(&mut self, key: Vec<u8>, value: Object) {
        self.entries.push((key, value));
    }
}

/// A stream: its dictionary and where its encoded bytes lie in the file.
#[derive(Debug, Clone, PartialEq)]
pub struct Stream {
    /// The stream dictionary.
    pub dict: Dictionary,
    /// Byte range of the encoded data in the input.
    pub data: Range<usize>,
}

/// A PDF object.
#[derive(Debug, Clone, PartialEq)]
pub enum Object {
    /// `null`, and the value of any reference to a missing or free object.
    Null,
    /// `true` or `false`.
    Bool(bool),
    /// An integer.
    Integer(i64),
    /// A real number.
    Real(f64),
    /// A literal or hexadecimal string, decoded to bytes.
    String(Vec<u8>),
    /// A name, decoded (`#xx` escapes applied), without the leading `/`.
    Name(Vec<u8>),
    /// An array.
    Array(Vec<Object>),
    /// A dictionary.
    Dictionary(Dictionary),
    /// A stream (only ever the value of an indirect object).
    Stream(Stream),
    /// An indirect reference.
    Reference(ObjRef),
}

impl Object {
    /// The dictionary of a dictionary or a stream.
    #[must_use]
    pub fn dict(&self) -> Option<&Dictionary> {
        match self {
            Self::Dictionary(d) => Some(d),
            Self::Stream(s) => Some(&s.dict),
            _ => None,
        }
    }

    /// The value under `key` in a dictionary or stream dictionary.
    #[must_use]
    pub fn get(&self, key: &[u8]) -> Option<&Object> {
        self.dict().and_then(|d| d.get(key))
    }

    /// The integer value, if this is an integer.
    #[must_use]
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Self::Integer(i) => Some(*i),
            _ => None,
        }
    }

    /// The numeric value of an integer or real.
    #[must_use]
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            // Rounds above 2^53, which no meaningful PDF number reaches.
            Self::Integer(i) => Some(*i as f64),
            Self::Real(r) => Some(*r),
            _ => None,
        }
    }

    /// The name, if this is a name.
    #[must_use]
    pub fn as_name(&self) -> Option<&[u8]> {
        match self {
            Self::Name(n) => Some(n),
            _ => None,
        }
    }

    /// The reference, if this is a reference.
    #[must_use]
    pub fn as_ref(&self) -> Option<ObjRef> {
        match self {
            Self::Reference(r) => Some(*r),
            _ => None,
        }
    }
}
