//! Fields (docs/22 §6): what a recipient fills, where it sits, and the rules on it.

use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};

use crate::limits::{MAX_OPTIONS, MAX_PAGE, MAX_POINTS, MAX_PRECISION};
use crate::{DataLabel, FormulaText, Id, ModelError, Text};

/// What kind of field this is (docs/22 §6, docs/48 §5, docs/49 §3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum FieldType {
    /// A signature, optional or required.
    Signature,
    /// Initials, optional or required.
    Initials,
    /// An uploaded company stamp image.
    Stamp,
    /// Filled by the server at the recipient's completion.
    DateSigned,
    /// The recipient's full name, auto-filled.
    Name,
    /// The recipient's first name, auto-filled.
    FirstName,
    /// The recipient's last name, auto-filled.
    LastName,
    /// The recipient's email, auto-filled.
    Email,
    /// The recipient's company, auto-filled.
    Company,
    /// The recipient's title, auto-filled.
    Title,
    /// The envelope id, auto-filled (docs/48 §5).
    EnvelopeId,
    /// Free text.
    Text,
    /// A number, validated as one.
    Number,
    /// A date, validated in one of the fixed formats.
    Date,
    /// An email address typed by the recipient.
    EmailAddress,
    /// A phone number.
    Phone,
    /// A US social security number (docs/48 §5).
    Ssn,
    /// A US ZIP code (docs/48 §5).
    Zip,
    /// A checkbox; may belong to a group with a rule.
    Checkbox,
    /// A set of mutually exclusive options; exactly one is chosen.
    RadioGroup,
    /// A choice from a list.
    Dropdown,
    /// Any number of choices from a list (a PDF multi-select list box, `ACRO-02`); its
    /// value is [`FieldValue::Choices`].
    MultiSelect,
    /// Read-only, computed from a formula.
    Formula,
    /// A file the signer uploads.
    Attachment,
    /// Read-only text shown to the recipient.
    Note,
    /// A button that completes.
    Approve,
    /// A button that declines.
    Decline,
    /// A link: shown, never followed automatically.
    Hyperlink,
    /// A payment (later, via `PaymentGateway`).
    Payment,
    /// A free drawing area (later).
    Drawing,
}

impl FieldType {
    /// Whether a recipient enters a value into this field, so `required` applies.
    ///
    /// Computed, display-only, server-stamped and button fields hold no recipient value.
    #[must_use]
    pub fn takes_input(self) -> bool {
        !matches!(
            self,
            Self::DateSigned
                | Self::EnvelopeId
                | Self::Formula
                | Self::Note
                | Self::Approve
                | Self::Decline
                | Self::Hyperlink
        )
    }
}

/// A coordinate or size in points of the page as displayed (docs/22 §6, ADR-019):
/// a decimal from 0 to 14,400.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "Decimal", into = "Decimal")]
pub struct Points(Decimal);

impl Points {
    /// Builds a point value, refusing a negative one or one over 14,400 (`CS-FLD-0004`).
    pub fn new(value: Decimal) -> Result<Self, ModelError> {
        if value.is_sign_negative() && !value.is_zero() || value > Decimal::from(MAX_POINTS) {
            return Err(ModelError::PlacementOutOfRange);
        }
        Ok(Self(value.normalize()))
    }

    /// The value in points.
    #[must_use]
    pub fn get(self) -> Decimal {
        self.0
    }
}

impl TryFrom<Decimal> for Points {
    type Error = ModelError;
    fn try_from(value: Decimal) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<Points> for Decimal {
    fn from(value: Points) -> Self {
        value.0
    }
}

/// Where a field sits: page number (1-based) and a rectangle in the page's displayed
/// space, points, origin top-left (docs/22 §6). Never pixels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "PlacementWire", into = "PlacementWire")]
pub struct Placement {
    page: u32,
    x: Points,
    y: Points,
    width: Points,
    height: Points,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PlacementWire {
    page: u32,
    x: Points,
    y: Points,
    width: Points,
    height: Points,
}

impl Placement {
    /// Builds a placement. The page is 1 to 5,000; width and height are positive; the
    /// rectangle's far edges stay within 14,400 points (`CS-FLD-0004`). Whether it lies
    /// inside its actual page is checked against the PDF at send time.
    pub fn new(
        page: u32,
        x: Points,
        y: Points,
        width: Points,
        height: Points,
    ) -> Result<Self, ModelError> {
        let max = Decimal::from(MAX_POINTS);
        let right = x.0.checked_add(width.0);
        let bottom = y.0.checked_add(height.0);
        let fits = matches!(right, Some(r) if r <= max) && matches!(bottom, Some(b) if b <= max);
        if page == 0 || page > MAX_PAGE || width.0.is_zero() || height.0.is_zero() || !fits {
            return Err(ModelError::PlacementOutOfRange);
        }
        Ok(Self {
            page,
            x,
            y,
            width,
            height,
        })
    }

    /// 1-based page number.
    #[must_use]
    pub fn page(&self) -> u32 {
        self.page
    }
    /// Left edge.
    #[must_use]
    pub fn x(&self) -> Points {
        self.x
    }
    /// Top edge.
    #[must_use]
    pub fn y(&self) -> Points {
        self.y
    }
    /// Width.
    #[must_use]
    pub fn width(&self) -> Points {
        self.width
    }
    /// Height.
    #[must_use]
    pub fn height(&self) -> Points {
        self.height
    }
}

impl TryFrom<PlacementWire> for Placement {
    type Error = ModelError;
    fn try_from(w: PlacementWire) -> Result<Self, Self::Error> {
        Self::new(w.page, w.x, w.y, w.width, w.height)
    }
}

impl From<Placement> for PlacementWire {
    fn from(p: Placement) -> Self {
        Self {
            page: p.page,
            x: p.x,
            y: p.y,
            width: p.width,
            height: p.height,
        }
    }
}

/// A field's value, typed by what the recipient did (docs/22 §6).
///
/// Numbers and dates travel as the text the recipient typed: `casual-sign-fields`
/// parses them with the field's validation, so the stored value is exactly what was
/// seen.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum FieldValue {
    /// Typed text, including numbers, dates and auto-filled values.
    Text(Text),
    /// A checkbox state.
    Checked(bool),
    /// The chosen option of a radio group or dropdown.
    Choice(Text),
    /// The chosen options of a multi-select field: at most 500, none repeated (the
    /// bounds of [`FieldOptions`], which carries them). Empty means none chosen.
    Choices(FieldOptions),
    /// An uploaded file, by the host's id.
    Attachment(Id),
    /// A captured signature, initials or stamp, by the host's id.
    Signature(Id),
}

impl FieldValue {
    /// Whether this counts as no value for `required`: empty text or choice, or an
    /// unchecked box.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        match self {
            Self::Text(t) | Self::Choice(t) => t.is_empty(),
            Self::Choices(c) => c.is_empty(),
            Self::Checked(c) => !c,
            Self::Attachment(_) | Self::Signature(_) => false,
        }
    }
}

/// The options of a dropdown, radio group or multi-select, or the options chosen in a
/// multi-select: at most 500, no two alike (docs/21).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(try_from = "Vec<Text>", into = "Vec<Text>")]
pub struct FieldOptions(Vec<Text>);

impl FieldOptions {
    /// Builds an option list, refusing more than 500 or a repeat (`CS-FLD-0002`).
    pub fn new(options: Vec<Text>) -> Result<Self, ModelError> {
        if options.len() > MAX_OPTIONS {
            return Err(ModelError::TooManyOptions {
                count: options.len(),
                limit: MAX_OPTIONS,
            });
        }
        let mut seen = std::collections::BTreeSet::new();
        for (index, option) in options.iter().enumerate() {
            if !seen.insert(option.as_str()) {
                return Err(ModelError::DuplicateOption { index });
            }
        }
        Ok(Self(options))
    }

    /// The options, in the sender's order.
    #[must_use]
    pub fn as_slice(&self) -> &[Text] {
        &self.0
    }

    /// Whether `value` is one of the options.
    #[must_use]
    pub fn contains(&self, value: &str) -> bool {
        self.0.iter().any(|o| o.as_str() == value)
    }

    /// Whether there are no options.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl TryFrom<Vec<Text>> for FieldOptions {
    type Error = ModelError;
    fn try_from(value: Vec<Text>) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<FieldOptions> for Vec<Text> {
    fn from(value: FieldOptions) -> Self {
        value.0
    }
}

/// The date formats a date field accepts (docs/22 §6). A fixed set, parsed by our own
/// code and never by the operating system's locale.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DateFormat {
    /// `YYYY-MM-DD` (ISO 8601).
    #[default]
    YyyyMmDd,
    /// `MM/DD/YYYY`.
    MmDdYyyy,
    /// `DD/MM/YYYY`.
    DdMmYyyy,
    /// `DD.MM.YYYY`.
    DdMmYyyyDot,
    /// `D MMM YYYY`, English month abbreviations: `7 Mar 2026`.
    DMmmYyyy,
}

/// An ISO 4217 currency code: three upper-case ASCII letters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct CurrencyCode([u8; 3]);

impl CurrencyCode {
    /// Builds a code, refusing anything but three upper-case ASCII letters (`CS-FLD-0002`).
    pub fn new(code: &str) -> Result<Self, ModelError> {
        match code.as_bytes() {
            &[a, b, c] if [a, b, c].iter().all(u8::is_ascii_uppercase) => Ok(Self([a, b, c])),
            _ => Err(ModelError::InvalidCurrency),
        }
    }

    /// The code as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        core::str::from_utf8(&self.0).unwrap_or("XXX")
    }
}

impl TryFrom<String> for CurrencyCode {
    type Error = ModelError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(&value)
    }
}

impl From<CurrencyCode> for String {
    fn from(value: CurrencyCode) -> Self {
        value.as_str().to_owned()
    }
}

/// Bounds on a number field (docs/48 §5 `numericalTabs`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(try_from = "NumberRuleWire", into = "NumberRuleWire")]
pub struct NumberRule {
    min: Option<Decimal>,
    max: Option<Decimal>,
    currency: Option<CurrencyCode>,
    decimals: Option<u8>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NumberRuleWire {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    min: Option<Decimal>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    max: Option<Decimal>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    currency: Option<CurrencyCode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    decimals: Option<u8>,
}

impl NumberRule {
    /// Builds a number rule. `min` ≤ `max` (`CS-FLD-0002`); `decimals` ≤ 15 (`CS-FLD-0021`).
    /// With a currency and no `decimals`, two places are allowed.
    pub fn new(
        min: Option<Decimal>,
        max: Option<Decimal>,
        currency: Option<CurrencyCode>,
        decimals: Option<u8>,
    ) -> Result<Self, ModelError> {
        if let (Some(lo), Some(hi)) = (min, max)
            && lo > hi
        {
            return Err(ModelError::RuleBoundsInverted);
        }
        if let Some(d) = decimals
            && d > MAX_PRECISION
        {
            return Err(ModelError::PrecisionOutOfRange { precision: d });
        }
        Ok(Self {
            min,
            max,
            currency,
            decimals,
        })
    }
    /// Smallest value allowed.
    #[must_use]
    pub fn min(&self) -> Option<Decimal> {
        self.min
    }
    /// Largest value allowed.
    #[must_use]
    pub fn max(&self) -> Option<Decimal> {
        self.max
    }
    /// The currency, if this is an amount of money.
    #[must_use]
    pub fn currency(&self) -> Option<CurrencyCode> {
        self.currency
    }
    /// Most decimal places allowed: the explicit count, else 2 for a currency, else 15.
    #[must_use]
    pub fn max_decimals(&self) -> u8 {
        match (self.decimals, self.currency) {
            (Some(d), _) => d,
            (None, Some(_)) => 2,
            (None, None) => MAX_PRECISION,
        }
    }
}

impl TryFrom<NumberRuleWire> for NumberRule {
    type Error = ModelError;
    fn try_from(w: NumberRuleWire) -> Result<Self, Self::Error> {
        Self::new(w.min, w.max, w.currency, w.decimals)
    }
}

impl From<NumberRule> for NumberRuleWire {
    fn from(r: NumberRule) -> Self {
        Self {
            min: r.min,
            max: r.max,
            currency: r.currency,
            decimals: r.decimals,
        }
    }
}

/// Bounds on a value's length in characters (Unicode scalar values).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(try_from = "LengthRuleWire", into = "LengthRuleWire")]
pub struct LengthRule {
    min: Option<u32>,
    max: Option<u32>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LengthRuleWire {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    min: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    max: Option<u32>,
}

impl LengthRule {
    /// Builds a length rule; `min` ≤ `max` (`CS-FLD-0002`).
    pub fn new(min: Option<u32>, max: Option<u32>) -> Result<Self, ModelError> {
        if let (Some(lo), Some(hi)) = (min, max)
            && lo > hi
        {
            return Err(ModelError::RuleBoundsInverted);
        }
        Ok(Self { min, max })
    }
    /// Fewest characters.
    #[must_use]
    pub fn min(&self) -> Option<u32> {
        self.min
    }
    /// Most characters.
    #[must_use]
    pub fn max(&self) -> Option<u32> {
        self.max
    }
}

impl TryFrom<LengthRuleWire> for LengthRule {
    type Error = ModelError;
    fn try_from(w: LengthRuleWire) -> Result<Self, Self::Error> {
        Self::new(w.min, w.max)
    }
}

impl From<LengthRule> for LengthRuleWire {
    fn from(r: LengthRule) -> Self {
        Self {
            min: r.min,
            max: r.max,
        }
    }
}

/// What a value must look like (docs/22 §6 `validation.kind`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[non_exhaustive]
pub enum ValidationRule {
    /// An email address.
    Email,
    /// A number, parsed without locale, with optional bounds and currency.
    Number(NumberRule),
    /// A date in one fixed format.
    Date {
        /// The accepted format.
        format: DateFormat,
    },
    /// A US ZIP code: five digits, or five plus four.
    Zip,
    /// A US social security number.
    Ssn,
    /// A phone number, E.164 read leniently.
    Phone,
    /// A length in characters.
    Length(LengthRule),
    /// A sender's regular expression, matched against the whole value in linear time.
    Regex {
        /// The pattern, `regex` crate syntax.
        pattern: Text,
    },
}

/// A validation rule and the message shown when it fails (docs/22 §6).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Validation {
    /// The rule.
    #[serde(flatten)]
    pub rule: ValidationRule,
    /// The sender's message for the signer, shown instead of the default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<Text>,
}

/// The standard font families a field's text is set in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FontFamily {
    /// Helvetica (the default).
    #[default]
    Helvetica,
    /// Times.
    Times,
    /// Courier.
    Courier,
}

/// Horizontal alignment of a field's text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Align {
    /// Left (the default).
    #[default]
    Left,
    /// Centred.
    Center,
    /// Right.
    Right,
}

/// An sRGB colour, written `#rrggbb`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Rgb(pub [u8; 3]);

impl Rgb {
    /// Parses `#rrggbb` (`CS-FLD-0002` otherwise).
    pub fn parse(text: &str) -> Result<Self, ModelError> {
        let hex = text.strip_prefix('#').ok_or(ModelError::InvalidColor)?;
        if hex.len() != 6 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(ModelError::InvalidColor);
        }
        let byte = |range: core::ops::Range<usize>| {
            hex.get(range)
                .and_then(|h| u8::from_str_radix(h, 16).ok())
                .ok_or(ModelError::InvalidColor)
        };
        Ok(Self([byte(0..2)?, byte(2..4)?, byte(4..6)?]))
    }
}

impl TryFrom<String> for Rgb {
    type Error = ModelError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl From<Rgb> for String {
    fn from(value: Rgb) -> Self {
        let [r, g, b] = value.0;
        format!("#{r:02x}{g:02x}{b:02x}")
    }
}

/// How a field's value is shown (docs/22 §6 `format`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Format {
    /// Font family.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub font_family: Option<FontFamily>,
    /// Font size in points.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub font_size: Option<Points>,
    /// Text colour.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub color: Option<Rgb>,
    /// Alignment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub align: Option<Align>,
    /// The date format of a date field, when no date validation names one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub date_format: Option<DateFormat>,
    /// Conceal the value on the document (DocuSign's `concealValueOnDocument`).
    #[serde(default, skip_serializing_if = "core::ops::Not::not")]
    pub mask: bool,
}

/// How many boxes of a checkbox group must be checked (docs/22 §6, docs/48 §5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "GroupRuleWire", into = "GroupRuleWire")]
pub enum GroupRule {
    /// At least `min`.
    SelectAtLeast {
        /// Fewest checked.
        min: u32,
    },
    /// At most `max`.
    SelectAtMost {
        /// Most checked.
        max: u32,
    },
    /// Exactly `count`.
    SelectExactly {
        /// The number checked.
        count: u32,
    },
    /// Between `min` and `max`, inclusive.
    SelectRange {
        /// Fewest checked.
        min: u32,
        /// Most checked.
        max: u32,
    },
}

// The variant names are the wire names docs/22 §6 fixes (`select_at_least`, ...).
#[allow(clippy::enum_variant_names)]
#[derive(Serialize, Deserialize)]
#[serde(tag = "rule", rename_all = "snake_case", deny_unknown_fields)]
enum GroupRuleWire {
    SelectAtLeast { min: u32 },
    SelectAtMost { max: u32 },
    SelectExactly { count: u32 },
    SelectRange { min: u32, max: u32 },
}

impl GroupRule {
    /// Checks a rule's own bounds: a range's `min` ≤ `max` (`CS-FLD-0003`).
    pub fn validated(self) -> Result<Self, ModelError> {
        match self {
            Self::SelectRange { min, max } if min > max => Err(ModelError::InvalidGroupRule),
            other => Ok(other),
        }
    }

    /// Whether `checked` boxes satisfy the rule.
    #[must_use]
    pub fn admits(self, checked: u32) -> bool {
        match self {
            Self::SelectAtLeast { min } => checked >= min,
            Self::SelectAtMost { max } => checked <= max,
            Self::SelectExactly { count } => checked == count,
            Self::SelectRange { min, max } => (min..=max).contains(&checked),
        }
    }
}

impl TryFrom<GroupRuleWire> for GroupRule {
    type Error = ModelError;
    fn try_from(w: GroupRuleWire) -> Result<Self, Self::Error> {
        match w {
            GroupRuleWire::SelectAtLeast { min } => Self::SelectAtLeast { min },
            GroupRuleWire::SelectAtMost { max } => Self::SelectAtMost { max },
            GroupRuleWire::SelectExactly { count } => Self::SelectExactly { count },
            GroupRuleWire::SelectRange { min, max } => Self::SelectRange { min, max },
        }
        .validated()
    }
}

impl From<GroupRule> for GroupRuleWire {
    fn from(r: GroupRule) -> Self {
        match r {
            GroupRule::SelectAtLeast { min } => Self::SelectAtLeast { min },
            GroupRule::SelectAtMost { max } => Self::SelectAtMost { max },
            GroupRule::SelectExactly { count } => Self::SelectExactly { count },
            GroupRule::SelectRange { min, max } => Self::SelectRange { min, max },
        }
    }
}

/// Membership of a checkbox group, and the group's rule (docs/22 §6 `group`).
///
/// Every member states the rule; members that disagree are refused at send time.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Group {
    /// The group's id.
    pub id: Id,
    /// The group's rule.
    pub rule: GroupRule,
}

/// When a conditional field shows (docs/22 §6 `conditional.when`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Condition {
    /// The parent's value equals this text, or its chosen option is this.
    Value(Text),
    /// The parent checkbox is checked.
    Checked,
    /// The parent checkbox is unchecked (or empty).
    Unchecked,
    /// The parent has any non-empty value.
    Any,
}

/// Show this field only when the field labelled `parent_label` meets `when`
/// (docs/22 §6, DocuSign's `conditionalParentLabel`). A hidden field's value is dropped.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Conditional {
    /// The parent's data label.
    pub parent_label: DataLabel,
    /// The condition on the parent.
    pub when: Condition,
}

/// A computed field's expression and the decimal places its result keeps (docs/30 §6).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "FormulaWire", into = "FormulaWire")]
pub struct Formula {
    expression: FormulaText,
    precision: u8,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FormulaWire {
    expression: FormulaText,
    #[serde(default)]
    precision: u8,
}

impl Formula {
    /// Builds a formula; `precision` is 0 to 15 (`CS-FLD-0021`).
    pub fn new(expression: FormulaText, precision: u8) -> Result<Self, ModelError> {
        if precision > MAX_PRECISION {
            return Err(ModelError::PrecisionOutOfRange { precision });
        }
        Ok(Self {
            expression,
            precision,
        })
    }
    /// The expression.
    #[must_use]
    pub fn expression(&self) -> &FormulaText {
        &self.expression
    }
    /// Decimal places of the result.
    #[must_use]
    pub fn precision(&self) -> u8 {
        self.precision
    }
}

impl TryFrom<FormulaWire> for Formula {
    type Error = ModelError;
    fn try_from(w: FormulaWire) -> Result<Self, Self::Error> {
        Self::new(w.expression, w.precision)
    }
}

impl From<Formula> for FormulaWire {
    fn from(f: Formula) -> Self {
        Self {
            expression: f.expression,
            precision: f.precision,
        }
    }
}

/// A field on a document (docs/22 §6).
///
/// Every member is a checked type, so a `Field` that exists is within docs/21's limits.
/// Rules that relate fields to each other (labels, groups, cycles) are checked by
/// `casual-sign-fields` at send and at completion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Field {
    /// The field's id.
    pub id: Id,
    /// The document the field is on.
    pub document_id: Id,
    /// The recipient who fills it; `None` only on templates, bound to a role.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recipient_id: Option<Id>,
    /// The kind of field.
    #[serde(rename = "type")]
    pub field_type: FieldType,
    /// Page and rectangle.
    pub placement: Placement,
    /// The recipient must give a value.
    #[serde(default, skip_serializing_if = "core::ops::Not::not")]
    pub required: bool,
    /// The recipient sees but cannot change the value.
    #[serde(default, skip_serializing_if = "core::ops::Not::not")]
    pub read_only: bool,
    /// The sender fixed the value; nobody changes it.
    #[serde(default, skip_serializing_if = "core::ops::Not::not")]
    pub locked: bool,
    /// The data label formulas and conditions refer to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<DataLabel>,
    /// The current value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<FieldValue>,
    /// The value the field starts with.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default: Option<FieldValue>,
    /// What the value must look like.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validation: Option<Validation>,
    /// How the value is shown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<Format>,
    /// Checkbox group membership and rule.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<Group>,
    /// When the field shows.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditional: Option<Conditional>,
    /// The expression of a formula field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub formula: Option<Formula>,
    /// Options of a dropdown, radio group or multi-select.
    #[serde(default, skip_serializing_if = "FieldOptions::is_empty")]
    pub options: FieldOptions,
    /// A dropdown accepts a value outside its options (SignNow's custom-defined options).
    #[serde(default, skip_serializing_if = "core::ops::Not::not")]
    pub allow_custom: bool,
    /// Hover help.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tooltip: Option<Text>,
    /// Text shown in an empty field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub placeholder: Option<Text>,
}

impl Field {
    /// A field with nothing set but its identity, kind and place.
    #[must_use]
    pub fn new(id: Id, document_id: Id, field_type: FieldType, placement: Placement) -> Self {
        Self {
            id,
            document_id,
            recipient_id: None,
            field_type,
            placement,
            required: false,
            read_only: false,
            locked: false,
            label: None,
            value: None,
            default: None,
            validation: None,
            format: None,
            group: None,
            conditional: None,
            formula: None,
            options: FieldOptions::default(),
            allow_custom: false,
            tooltip: None,
            placeholder: None,
        }
    }
}

#[cfg(test)]
mod tests {
    // Tests may unwrap (CLAUDE.md): a failure here is the test failing.
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn pts(n: i64) -> Points {
        Points::new(Decimal::from(n)).unwrap()
    }

    fn sample() -> Field {
        let placement = Placement::new(1, pts(72), pts(100), pts(144), pts(20)).unwrap();
        let mut f = Field::new(
            Id::new("f1").unwrap(),
            Id::new("d1").unwrap(),
            FieldType::Number,
            placement,
        );
        f.recipient_id = Some(Id::new("r1").unwrap());
        f.required = true;
        f.label = Some(DataLabel::new("Quantité").unwrap());
        f.value = Some(FieldValue::Text(Text::new("12").unwrap()));
        f.validation = Some(Validation {
            rule: ValidationRule::Number(
                NumberRule::new(Some(Decimal::ZERO), Some(Decimal::from(100)), None, Some(0))
                    .unwrap(),
            ),
            message: Some(Text::new("Whole numbers to 100").unwrap()),
        });
        f.group = Some(Group {
            id: Id::new("g1").unwrap(),
            rule: GroupRule::SelectRange { min: 1, max: 2 },
        });
        f.conditional = Some(Conditional {
            parent_label: DataLabel::new("Agree").unwrap(),
            when: Condition::Checked,
        });
        f.format = Some(Format {
            color: Some(Rgb([0, 0x80, 0xff])),
            ..Format::default()
        });
        f
    }

    #[test]
    fn a_field_round_trips_through_json_with_stable_snake_case_names() {
        let field = sample();
        let json = serde_json::to_string(&field).unwrap();
        for name in [
            "\"type\":\"number\"",
            "\"kind\":\"number\"",
            "\"rule\":\"select_range\"",
            "\"parent_label\":\"Quantité\""
                .replace("Quantité", "Agree")
                .as_str(),
            "\"when\":\"checked\"",
            "\"color\":\"#0080ff\"",
            "\"value\":{\"text\":\"12\"}",
            "\"x\":\"72\"",
        ] {
            assert!(json.contains(name), "{name} missing from {json}");
        }
        let back: Field = serde_json::from_str(&json).unwrap();
        assert_eq!(back, field);
    }

    #[test]
    fn every_field_type_has_a_snake_case_name() {
        let json = serde_json::to_string(&[
            FieldType::DateSigned,
            FieldType::EmailAddress,
            FieldType::RadioGroup,
        ])
        .unwrap();
        assert_eq!(json, "[\"date_signed\",\"email_address\",\"radio_group\"]");
    }

    #[test]
    fn placement_refuses_page_zero_negative_and_oversized_rectangles() {
        assert!(Placement::new(0, pts(0), pts(0), pts(1), pts(1)).is_err());
        assert!(Placement::new(5_001, pts(0), pts(0), pts(1), pts(1)).is_err());
        assert!(Placement::new(1, pts(0), pts(0), pts(0), pts(1)).is_err());
        assert!(Placement::new(1, pts(14_000), pts(0), pts(401), pts(1)).is_err());
        assert!(Placement::new(1, pts(14_000), pts(0), pts(400), pts(1)).is_ok());
        assert!(Points::new(Decimal::from(-1)).is_err());
        assert!(Points::new(Decimal::from(14_401)).is_err());
        let err = serde_json::from_str::<Placement>(
            r#"{"page":1,"x":"0","y":"0","width":"0","height":"1"}"#,
        );
        assert!(err.is_err());
    }

    #[test]
    fn options_are_bounded_at_500_and_unique() {
        let many = |n: usize| {
            (0..n)
                .map(|i| Text::new(format!("o{i}")).unwrap())
                .collect::<Vec<_>>()
        };
        assert!(FieldOptions::new(many(500)).is_ok());
        let err = FieldOptions::new(many(501)).err();
        assert_eq!(
            err,
            Some(ModelError::TooManyOptions {
                count: 501,
                limit: 500
            })
        );
        assert_eq!(err.map(|e| e.code()), Some("CS-FLD-0002"));
        let dup = vec![Text::new("a").unwrap(), Text::new("a").unwrap()];
        assert_eq!(
            FieldOptions::new(dup).err(),
            Some(ModelError::DuplicateOption { index: 1 })
        );
        let json = serde_json::to_string(&many(501)).unwrap();
        assert!(serde_json::from_str::<FieldOptions>(&json).is_err());
    }

    #[test]
    fn rules_refuse_inverted_bounds_and_precision_over_15() {
        assert!(NumberRule::new(Some(Decimal::ONE), Some(Decimal::ZERO), None, None).is_err());
        assert_eq!(
            NumberRule::new(None, None, None, Some(16))
                .err()
                .map(|e| e.code()),
            Some("CS-FLD-0021")
        );
        assert!(LengthRule::new(Some(3), Some(2)).is_err());
        assert!(
            serde_json::from_str::<GroupRule>(r#"{"rule":"select_range","min":3,"max":2}"#)
                .is_err()
        );
        assert_eq!(
            serde_json::from_str::<GroupRule>(r#"{"rule":"select_at_most","max":2}"#).unwrap(),
            GroupRule::SelectAtMost { max: 2 }
        );
        let text = FormulaText::new("a+b").unwrap();
        assert!(Formula::new(text.clone(), 15).is_ok());
        assert_eq!(
            Formula::new(text, 16).err().map(|e| e.code()),
            Some("CS-FLD-0021")
        );
    }

    #[test]
    fn number_rule_defaults_two_places_for_currency() {
        let usd = CurrencyCode::new("USD").unwrap();
        assert_eq!(
            NumberRule::new(None, None, Some(usd), None)
                .unwrap()
                .max_decimals(),
            2
        );
        assert_eq!(NumberRule::default().max_decimals(), 15);
        assert!(CurrencyCode::new("usd").is_err());
        assert!(CurrencyCode::new("US").is_err());
    }

    #[test]
    fn group_rules_admit_the_counts_they_name() {
        assert!(GroupRule::SelectAtLeast { min: 2 }.admits(2));
        assert!(!GroupRule::SelectAtLeast { min: 2 }.admits(1));
        assert!(GroupRule::SelectAtMost { max: 1 }.admits(0));
        assert!(!GroupRule::SelectAtMost { max: 1 }.admits(2));
        assert!(GroupRule::SelectExactly { count: 1 }.admits(1));
        assert!(!GroupRule::SelectExactly { count: 1 }.admits(0));
        assert!(GroupRule::SelectRange { min: 1, max: 3 }.admits(3));
        assert!(!GroupRule::SelectRange { min: 1, max: 3 }.admits(4));
    }

    #[test]
    fn a_multi_select_holds_a_bounded_set_of_choices() {
        // ACRO-02: a PDF multi-select list box converts to a field of its own kind
        // whose value is the chosen options, at most 500, none repeated.
        let mut f = sample();
        f.field_type = FieldType::MultiSelect;
        f.validation = None;
        let opts = |l: &[&str]| {
            FieldOptions::new(l.iter().map(|o| Text::new(*o).unwrap()).collect()).unwrap()
        };
        f.options = opts(&["Red", "Green", "Blue"]);
        f.value = Some(FieldValue::Choices(opts(&["Red", "Blue"])));
        let json = serde_json::to_string(&f).unwrap();
        assert!(json.contains(r#""type":"multi_select""#), "{json}");
        assert!(
            json.contains(r#""value":{"choices":["Red","Blue"]}"#),
            "{json}"
        );
        assert_eq!(serde_json::from_str::<Field>(&json).unwrap(), f);
        assert!(FieldType::MultiSelect.takes_input());
        assert!(FieldValue::Choices(FieldOptions::default()).is_empty());
        assert!(!FieldValue::Choices(opts(&["Red"])).is_empty());
        // Repeats and more than 500 are refused when read.
        assert!(serde_json::from_str::<FieldValue>(r#"{"choices":["a","a"]}"#).is_err());
        let many: Vec<String> = (0..501).map(|i| format!("o{i}")).collect();
        let json = serde_json::json!({ "choices": many }).to_string();
        assert!(serde_json::from_str::<FieldValue>(&json).is_err());
    }

    #[test]
    fn unknown_members_are_refused() {
        let mut json = serde_json::to_value(sample()).unwrap();
        json.as_object_mut()
            .unwrap()
            .insert("evil".into(), serde_json::Value::Bool(true));
        assert!(serde_json::from_value::<Field>(json).is_err());
    }
}
