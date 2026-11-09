//! Typed errors with the stable codes of docs/20.

use core::fmt;

use casual_sign_model::{Id, ModelError};

/// Why a field, a value or an envelope's fields were refused. `code()` gives the
/// docs/20 code.
///
/// Messages carry ids, counts and limits, never a field's value or a formula's text
/// (`SEC-D01`): both are a signer's or sender's data.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum FieldError {
    /// A required, visible field has no value (`CS-FLD-0001`).
    Required,
    /// A value fails its validation, or a rule is itself unusable (`CS-FLD-0002`).
    Invalid(Invalid),
    /// A checkbox group's rule is not met (`CS-FLD-0003`).
    GroupRule {
        /// The group.
        group: Id,
        /// How many visible boxes were checked.
        checked: u32,
    },
    /// Members of one group state different rules, or a non-checkbox is in a group
    /// (`CS-FLD-0003`).
    GroupMismatch {
        /// The group.
        group: Id,
    },
    /// A required radio group has no option chosen: exactly one must be (`CS-FLD-0003`).
    RadioNotChosen,
    /// A condition names a data label no field carries (`CS-FLD-0005`).
    UnknownLabel,
    /// A value was supplied for a field id the envelope does not have (`CS-FLD-0005`).
    UnknownField,
    /// Two fields share one id; both are set aside (`CS-FLD-0005`).
    DuplicateId,
    /// The field is part of, or depends on, a cycle of formulas or conditions
    /// (`CS-FLD-0020`).
    Cycle,
    /// The field's formula is invalid or over its bounds (`CS-FLD-0021`).
    Formula(FormulaError),
    /// The value the client computed or kept differs from the server's (`CS-FLD-0022`).
    ClientMismatch,
    /// A model invariant failed; the code is the model's.
    Model(ModelError),
}

/// What exactly made a value or rule invalid (all `CS-FLD-0002`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum Invalid {
    /// Not an email address.
    Email,
    /// Not a number in the accepted notation.
    Number,
    /// Below the rule's minimum.
    BelowMinimum,
    /// Above the rule's maximum.
    AboveMaximum,
    /// More decimal places than the rule allows.
    TooManyDecimals,
    /// Not a real date in the field's format.
    Date,
    /// Not a US ZIP code.
    Zip,
    /// Not a US social security number.
    Ssn,
    /// Not a phone number.
    Phone,
    /// Fewer characters than the rule's minimum.
    TooShort,
    /// More characters than the rule's maximum.
    TooLong,
    /// Does not match the sender's pattern.
    Pattern,
    /// The sender's pattern is over 1,024 bytes.
    PatternTooLong,
    /// The sender's pattern compiles to more than the size limit.
    PatternTooBig,
    /// The sender's pattern is not valid syntax.
    PatternSyntax,
    /// The kind of value does not suit the field (a checkmark on a text field).
    WrongKind,
    /// A choice that is not one of the field's options.
    NotAnOption,
    /// A dropdown or radio group with no options.
    NoOptions,
}

/// Why a formula was refused (`CS-FLD-0021`), found before any evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum FormulaError {
    /// Over 1,024 characters; refused before lexing.
    TooLong {
        /// Characters allowed.
        limit: usize,
    },
    /// Nested deeper than 32 levels.
    TooDeep {
        /// Levels allowed.
        limit: usize,
    },
    /// More than 100 label references.
    TooManyReferences {
        /// References allowed.
        limit: usize,
    },
    /// Not valid syntax at this byte offset.
    Syntax {
        /// Byte offset into the expression.
        offset: usize,
    },
    /// A number literal too large or too precise for a decimal, at this offset.
    NumberOutOfRange {
        /// Byte offset into the expression.
        offset: usize,
    },
    /// A function this language does not have, at this offset.
    UnknownFunction {
        /// Byte offset into the expression.
        offset: usize,
    },
    /// A function given the wrong number or kind of arguments, at this offset.
    Arguments {
        /// Byte offset into the expression.
        offset: usize,
    },
    /// A reference to a data label no field carries; the index is the reference's
    /// position among the formula's references.
    UnknownLabel {
        /// Zero-based reference index.
        reference: usize,
    },
    /// A formula field with no formula, or a formula on a field of another type.
    Misplaced,
}

impl FieldError {
    /// The stable code from docs/20.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Required => "CS-FLD-0001",
            Self::Invalid(_) => "CS-FLD-0002",
            Self::GroupRule { .. } | Self::GroupMismatch { .. } | Self::RadioNotChosen => {
                "CS-FLD-0003"
            }
            Self::UnknownLabel | Self::UnknownField | Self::DuplicateId => "CS-FLD-0005",
            Self::Cycle => "CS-FLD-0020",
            Self::Formula(_) => "CS-FLD-0021",
            Self::ClientMismatch => "CS-FLD-0022",
            Self::Model(e) => e.code(),
        }
    }
}

impl From<Invalid> for FieldError {
    fn from(value: Invalid) -> Self {
        Self::Invalid(value)
    }
}

impl From<FormulaError> for FieldError {
    fn from(value: FormulaError) -> Self {
        Self::Formula(value)
    }
}

impl From<ModelError> for FieldError {
    fn from(value: ModelError) -> Self {
        Self::Model(value)
    }
}

impl fmt::Display for FieldError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let code = self.code();
        match self {
            Self::Required => write!(f, "{code}: required field is empty"),
            Self::Invalid(why) => write!(f, "{code}: value fails validation ({why:?})"),
            Self::GroupRule { group, checked } => write!(
                f,
                "{code}: group {group} rule not met with {checked} checked"
            ),
            Self::GroupMismatch { group } => {
                write!(f, "{code}: group {group} members disagree on the rule")
            }
            Self::RadioNotChosen => write!(f, "{code}: required radio group has no choice"),
            Self::UnknownLabel => write!(f, "{code}: condition names an unknown data label"),
            Self::UnknownField => write!(f, "{code}: value for an unknown field"),
            Self::DuplicateId => write!(f, "{code}: field id used more than once"),
            Self::Cycle => write!(f, "{code}: formula or condition cycle"),
            Self::Formula(e) => write!(f, "{code}: formula refused ({e:?})"),
            Self::ClientMismatch => write!(f, "{code}: client value differs from the server's"),
            Self::Model(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for FieldError {}

/// One problem with one field, as `evaluate_envelope` and the send checks report it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Issue {
    /// The field the problem is on. For a group rule, the group's lowest-id member.
    pub field_id: Id,
    /// The problem.
    pub error: FieldError,
}

impl Issue {
    /// The docs/20 code of the problem.
    #[must_use]
    pub fn code(&self) -> &'static str {
        self.error.code()
    }
}
