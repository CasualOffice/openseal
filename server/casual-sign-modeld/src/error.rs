//! modeld's errors, each with a stable `CS-ML-*` code (docs/33 §12, reserved for
//! docs/20 §ML). Shaped as keyd's `error.rs` (`server/casual-sign-keyd/src/error.rs`).
//!
//! Messages carry setting names, file names from the bundle manifest, counts and I/O
//! error kinds. Never document text, OCR text, labels' matches, boxes, hashes of content,
//! vectors or a runtime's own message (docs/33 invariant 5, `SEC-I05`).

use core::fmt;

/// Why a modeld operation failed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ModeldError {
    /// `CS-ML-0001`: a modeld or ML setting is missing or invalid (named, never its value).
    Setting(&'static str),
    /// `CS-ML-0002`: the model bundle does not verify: a file missing, unlisted, over its
    /// size cap or not matching its SHA-256. modeld does not start.
    Bundle(BundleProblem),
    /// `CS-ML-0003`: a model file is refused: external data, a custom op domain, a pickle
    /// format, or a licence not on the allow list. modeld does not start.
    ModelRefused(ModelRefusal),
    /// `CS-ML-0004`: a frame is malformed or over a bound (length, count, id alphabet,
    /// UTF-8).
    Malformed(&'static str),
    /// `CS-ML-0005`: an input is over its bound (page pixels, decoded image data, text
    /// bytes). Final for that page or call.
    OverBound(&'static str),
    /// `CS-ML-0006`: a page could not be rasterised (encrypted, unsupported, damaged, or
    /// over its time).
    Raster(&'static str),
    /// `CS-ML-0007`: the inference deadline passed.
    Deadline,
    /// `CS-ML-0008`: modeld is unreachable, TLS was refused, or the connection closed.
    Transport(String),
    /// `CS-ML-0009`: every slot is busy; retry with back-off.
    Busy,
    /// `CS-ML-0010`: the model this op needs is not installed in the bundle.
    NotInstalled,
    /// `CS-ML-0011`: the feature is off for the workspace or not in its plan. Raised by
    /// the API server; listed here so the code table is complete.
    FeatureOff,
    /// `CS-ML-0012`: a suggestion is stale or already decided. Raised by the API server.
    Stale,
    /// `CS-ML-0013`: inference failed inside the runtime. The runtime's own text is never
    /// passed on.
    Inference,
    /// `CS-ML-0001` on the TLS side: the certificates or keys do not load. Kept apart from
    /// [`ModeldError::Setting`] because rustls names the failure, never a value.
    TlsConfig(String),
    /// `CS-ML-0015`: the caller's certificate chains to the client CA but its fingerprint
    /// is not on the allow list. Final: retrying cannot succeed until the operator adds it.
    NotAuthorized,
    /// `CS-ML-0001` on the op log: it cannot be opened, read back or written.
    OperationLog(String),
}

/// What is wrong with the model bundle (`CS-ML-0002`).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum BundleProblem {
    /// The manifest does not parse; the line number.
    ManifestLine(usize),
    /// Two manifest entries share an id or a path.
    Duplicate(String),
    /// A listed file is absent from the bundle directory.
    Missing(String),
    /// A file in the bundle directory is not in the manifest.
    Unlisted(String),
    /// A file's size is not the manifest's.
    Size(String),
    /// A file's SHA-256 is not the manifest's.
    Hash(String),
    /// A file, or the whole bundle, is over its cap.
    OverCap(String),
    /// The bundle directory cannot be read (the I/O error kind).
    Unreadable(String),
    /// A profile was asked for that no manifest entry has.
    UnknownProfile(String),
}

/// Why a model file is refused (`CS-ML-0003`).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ModelRefusal {
    /// A pickle format (`.bin`, `.pt`, `.pth`, `.pkl`, `.ckpt`) is never loaded.
    Pickle(String),
    /// The licence is not on the allow list (deny.toml's).
    Licence(String),
    /// An ONNX graph refers to external data.
    ExternalData(String),
    /// An ONNX graph uses a custom op domain.
    CustomOp(String),
}

impl ModeldError {
    /// The stable `CS-ML-` code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Setting(_) | Self::TlsConfig(_) | Self::OperationLog(_) => "CS-ML-0001",
            Self::Bundle(_) => "CS-ML-0002",
            Self::ModelRefused(_) => "CS-ML-0003",
            Self::Malformed(_) => "CS-ML-0004",
            Self::OverBound(_) => "CS-ML-0005",
            Self::Raster(_) => "CS-ML-0006",
            Self::Deadline => "CS-ML-0007",
            Self::Transport(_) => "CS-ML-0008",
            Self::Busy => "CS-ML-0009",
            Self::NotInstalled => "CS-ML-0010",
            Self::FeatureOff => "CS-ML-0011",
            Self::Stale => "CS-ML-0012",
            Self::Inference => "CS-ML-0013",
            Self::NotAuthorized => "CS-ML-0015",
        }
    }

    /// The code's number, as the wire protocol carries it.
    #[must_use]
    pub const fn number(&self) -> u16 {
        match self {
            Self::Setting(_) | Self::TlsConfig(_) | Self::OperationLog(_) => 1,
            Self::Bundle(_) => 2,
            Self::ModelRefused(_) => 3,
            Self::Malformed(_) => 4,
            Self::OverBound(_) => 5,
            Self::Raster(_) => 6,
            Self::Deadline => 7,
            Self::Transport(_) => 8,
            Self::Busy => 9,
            Self::NotInstalled => 10,
            Self::FeatureOff => 11,
            Self::Stale => 12,
            Self::Inference => 13,
            Self::NotAuthorized => 15,
        }
    }

    /// The error a remote modeld reported by number. Detail stays on the server; the
    /// caller learns only the code.
    #[must_use]
    pub fn from_number(n: u16) -> Self {
        match n {
            1 => Self::Setting("reported by modeld"),
            2 => Self::Bundle(BundleProblem::Unreadable("reported by modeld".into())),
            3 => Self::ModelRefused(ModelRefusal::Licence("reported by modeld".into())),
            4 => Self::Malformed("refused by modeld"),
            5 => Self::OverBound("reported by modeld"),
            6 => Self::Raster("reported by modeld"),
            7 => Self::Deadline,
            8 => Self::Transport("reported by modeld".into()),
            9 => Self::Busy,
            10 => Self::NotInstalled,
            13 => Self::Inference,
            15 => Self::NotAuthorized,
            _ => Self::Transport(format!("modeld answered with unknown error {n}")),
        }
    }

    /// Whether a retry may succeed (the worker's back-off decision): busy, deadline and
    /// transport failures are transient; everything else is final for that input.
    #[must_use]
    pub const fn is_transient(&self) -> bool {
        matches!(self, Self::Busy | Self::Deadline | Self::Transport(_))
    }
}

impl fmt::Display for BundleProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ManifestLine(n) => write!(f, "manifest line {n} does not parse"),
            Self::Duplicate(id) => write!(f, "manifest lists {id} twice"),
            Self::Missing(p) => write!(f, "{p} is listed but missing"),
            Self::Unlisted(p) => write!(f, "{p} is not in the manifest"),
            Self::Size(p) => write!(f, "{p} is not its listed size"),
            Self::Hash(p) => write!(f, "{p} does not match its SHA-256"),
            Self::OverCap(p) => write!(f, "{p} is over its size cap"),
            Self::Unreadable(why) => write!(f, "bundle unreadable: {why}"),
            Self::UnknownProfile(p) => write!(f, "no manifest entry has profile {p}"),
        }
    }
}

impl fmt::Display for ModelRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pickle(p) => write!(f, "{p} is a pickle format, never loaded"),
            Self::Licence(id) => write!(f, "{id} has a licence not on the allow list"),
            Self::ExternalData(p) => write!(f, "{p} refers to external data"),
            Self::CustomOp(p) => write!(f, "{p} uses a custom op domain"),
        }
    }
}

impl fmt::Display for ModeldError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: ", self.code())?;
        match self {
            Self::Setting(name) => write!(f, "setting {name} is missing or invalid"),
            Self::Bundle(p) => write!(f, "model bundle: {p}"),
            Self::ModelRefused(r) => write!(f, "model refused: {r}"),
            Self::Malformed(why) => write!(f, "malformed message: {why}"),
            Self::OverBound(what) => write!(f, "input over its bound: {what}"),
            Self::Raster(why) => write!(f, "page not rasterised: {why}"),
            Self::Deadline => f.write_str("inference deadline passed"),
            Self::Transport(why) => write!(f, "modeld unreachable: {why}"),
            Self::Busy => f.write_str("modeld busy"),
            Self::NotInstalled => f.write_str("the model for this operation is not installed"),
            Self::FeatureOff => f.write_str("the feature is off or not in the plan"),
            Self::Stale => f.write_str("suggestion stale or already decided"),
            Self::Inference => f.write_str("inference failed"),
            Self::TlsConfig(why) => write!(f, "TLS configuration: {why}"),
            Self::NotAuthorized => f.write_str("caller not authorized"),
            Self::OperationLog(why) => write!(f, "operation log: {why}"),
        }
    }
}

impl std::error::Error for ModeldError {}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every number the server sends maps back to the same code on the client, so the
    /// worker's retry decision is the server's.
    #[test]
    fn numbers_round_trip_to_the_same_code() {
        let all = [
            ModeldError::Setting("x"),
            ModeldError::Bundle(BundleProblem::Missing("a".into())),
            ModeldError::ModelRefused(ModelRefusal::Pickle("a.bin".into())),
            ModeldError::Malformed("x"),
            ModeldError::OverBound("x"),
            ModeldError::Raster("x"),
            ModeldError::Deadline,
            ModeldError::NotAuthorized,
            ModeldError::Busy,
            ModeldError::NotInstalled,
            ModeldError::Inference,
        ];
        for e in all {
            let back = ModeldError::from_number(e.number());
            assert_eq!(back.code(), e.code(), "{e}");
            assert_eq!(back.is_transient(), e.is_transient(), "{e}");
        }
        assert_eq!(ModeldError::Busy.code(), "CS-ML-0009");
    }

    /// A caller refused by the allow list is final; a transport failure is retried. The
    /// two must not share a number, or the client cannot tell them apart (review D4).
    #[test]
    fn a_refused_caller_has_its_own_final_code_apart_from_transport() {
        let refused = ModeldError::NotAuthorized;
        let transport = ModeldError::Transport("reset".into());
        assert_ne!(refused.code(), transport.code());
        assert_ne!(refused.number(), transport.number());
        assert_eq!(refused.code(), "CS-ML-0015");
        assert!(!refused.is_transient());
        let back = ModeldError::from_number(transport.number());
        assert_eq!(back.code(), "CS-ML-0008");
        assert!(back.is_transient(), "{back}");
        assert_eq!(ModeldError::from_number(refused.number()), refused);
        assert!(ModeldError::Busy.is_transient());
        assert!(!ModeldError::NotInstalled.is_transient());
    }
}
