//! Conversion errors, each with a stable `CS-CNV-*` code (docs/20 §Conversion) and a
//! reason from a closed list, so the daemon, the child and the API server agree on them
//! over the wire. Shaped as modeld's `error.rs`.
//!
//! Messages carry the code and the reason only: never a part name, a file name, text or
//! anything else from the document (`SEC-D01`).

use core::fmt;

/// Why a reason was given: the closed list every [`ConvertError`] carries one of. Each
/// has a stable wire number (its index in [`Reason::ALL`]) and a stable spelling (the
/// problem's `detail`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Reason {
    /// Not a ZIP archive.
    NotZip,
    /// A ZIP archive that is not a Word document (no main document part).
    NotWord,
    /// A Word template (`.dotx`) rather than a document.
    Template,
    /// An encrypted or password-protected archive or entry.
    Encrypted,
    /// No converter is configured on this server.
    ConversionOff,
    /// The archive or a part of it is malformed.
    Malformed,
    /// The converter failed on the document.
    Failed,
    /// The input is larger than the converter takes.
    Input,
    /// More archive entries than allowed.
    Entries,
    /// The parts' expanded size is over the cap.
    Expanded,
    /// One part's expanded size is over the cap.
    Part,
    /// A part's expansion ratio is over the cap (a zip bomb).
    Ratio,
    /// More pages than allowed.
    Pages,
    /// The conversion overran its time and was killed.
    Time,
    /// The conversion ended abnormally (its memory limit, a signal).
    Memory,
    /// The converted PDF is larger than allowed.
    Output,
    /// The daemon could not be reached.
    Connect,
    /// Every conversion slot is in use.
    Busy,
    /// An answer that is not the protocol's.
    Protocol,
    /// Macros (a `.docm`, a VBA project).
    Macros,
}

impl Reason {
    /// Every reason, in wire order. A new reason is appended, never inserted.
    pub const ALL: [Self; 20] = [
        Self::NotZip,
        Self::NotWord,
        Self::Template,
        Self::Encrypted,
        Self::ConversionOff,
        Self::Malformed,
        Self::Failed,
        Self::Input,
        Self::Entries,
        Self::Expanded,
        Self::Part,
        Self::Ratio,
        Self::Pages,
        Self::Time,
        Self::Memory,
        Self::Output,
        Self::Connect,
        Self::Busy,
        Self::Protocol,
        Self::Macros,
    ];

    /// The stable spelling, used as a problem's `detail`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotZip => "not_zip",
            Self::NotWord => "not_word",
            Self::Template => "template",
            Self::Encrypted => "encrypted",
            Self::ConversionOff => "conversion_off",
            Self::Malformed => "malformed",
            Self::Failed => "failed",
            Self::Input => "input",
            Self::Entries => "entries",
            Self::Expanded => "expanded",
            Self::Part => "part",
            Self::Ratio => "ratio",
            Self::Pages => "pages",
            Self::Time => "time",
            Self::Memory => "memory",
            Self::Output => "output",
            Self::Connect => "connect",
            Self::Busy => "busy",
            Self::Protocol => "protocol",
            Self::Macros => "macros",
        }
    }

    /// The wire number.
    #[must_use]
    pub fn number(self) -> u8 {
        let mut i = 0u8;
        for r in Self::ALL {
            if r == self {
                return i;
            }
            i = i.saturating_add(1);
        }
        u8::MAX
    }

    /// The reason a wire number names, if any.
    #[must_use]
    pub fn from_number(n: u8) -> Option<Self> {
        Self::ALL.get(usize::from(n)).copied()
    }
}

/// Why a conversion did not produce a PDF.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConvertError {
    /// `CS-CNV-0001` (422): the document is malformed or the converter failed on it.
    Failed(Reason),
    /// `CS-CNV-0002` (415): not a format OpenSeal converts: not a Word document, a
    /// template, encrypted, or conversion is off on this server.
    Unsupported(Reason),
    /// `CS-CNV-0003` (422): over a conversion limit (input, entries, expanded size, a
    /// part, a ratio, pages, time, memory, output).
    OverLimit(Reason),
    /// `CS-CNV-0004` (415): a macro-enabled document (`.docm`, a VBA project) is
    /// refused; macros are never run or kept.
    Macros,
    /// `CS-CNV-0005` (503): the converter could not take the job (not reached, busy, or
    /// an answer outside the protocol). Retrying later may succeed.
    Unavailable(Reason),
}

impl ConvertError {
    /// The stable code (docs/20).
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Failed(_) => "CS-CNV-0001",
            Self::Unsupported(_) => "CS-CNV-0002",
            Self::OverLimit(_) => "CS-CNV-0003",
            Self::Macros => "CS-CNV-0004",
            Self::Unavailable(_) => "CS-CNV-0005",
        }
    }

    /// The reason, a problem's `detail`.
    #[must_use]
    pub const fn reason(&self) -> Reason {
        match self {
            Self::Failed(r) | Self::Unsupported(r) | Self::OverLimit(r) | Self::Unavailable(r) => {
                *r
            }
            Self::Macros => Reason::Macros,
        }
    }

    /// The code's number on the wire (1 to 5).
    #[must_use]
    pub const fn number(&self) -> u8 {
        match self {
            Self::Failed(_) => 1,
            Self::Unsupported(_) => 2,
            Self::OverLimit(_) => 3,
            Self::Macros => 4,
            Self::Unavailable(_) => 5,
        }
    }

    /// The error a wire `(number, reason)` pair names; `None` for a pair outside the
    /// protocol.
    #[must_use]
    pub fn from_wire(number: u8, reason: u8) -> Option<Self> {
        let r = Reason::from_number(reason)?;
        Some(match number {
            1 => Self::Failed(r),
            2 => Self::Unsupported(r),
            3 => Self::OverLimit(r),
            4 => Self::Macros,
            5 => Self::Unavailable(r),
            _ => return None,
        })
    }
}

impl fmt::Display for ConvertError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.code(), self.reason().as_str())
    }
}

impl std::error::Error for ConvertError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_error_round_trips_over_the_wire() {
        for r in Reason::ALL {
            assert_eq!(Reason::from_number(r.number()), Some(r));
            for e in [
                ConvertError::Failed(r),
                ConvertError::Unsupported(r),
                ConvertError::OverLimit(r),
                ConvertError::Unavailable(r),
            ] {
                assert_eq!(ConvertError::from_wire(e.number(), r.number()), Some(e));
            }
        }
        assert_eq!(
            ConvertError::from_wire(4, 0),
            Some(ConvertError::Macros),
            "macros carry no reason of their own"
        );
        assert_eq!(ConvertError::from_wire(6, 0), None);
        assert_eq!(ConvertError::from_wire(1, 200), None);
    }

    #[test]
    fn spellings_are_unique() {
        let mut seen = std::collections::HashSet::new();
        for r in Reason::ALL {
            assert!(seen.insert(r.as_str()), "{}", r.as_str());
        }
    }
}
