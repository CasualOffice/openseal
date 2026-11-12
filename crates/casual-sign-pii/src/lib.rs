//! Deterministic personal-data recognisers (`ML-08` layer 1, ADR-029 D7, docs/33).
//!
//! Finds structured personal data in a document's text: email addresses, phone
//! numbers, IBANs, payment card numbers, US Social Security numbers, UK National
//! Insurance numbers, Indian PAN and Aadhaar numbers, IP addresses, and dates of birth
//! (a date only when a context word such as "born" or "date of birth" precedes it);
//! and, each kept only when its check digits or structural rules hold (`ML-08C`, owner
//! instruction 33: validation before models), US ITIN and EIN, ABA routing numbers,
//! Canadian SIN, UK NHS numbers, Australian TFN and Medicare numbers, the German
//! Steuer-ID, French NIR, Spanish DNI and NIE, Italian codice fiscale, Dutch BSN, EU
//! VAT numbers of twelve member states, passport MRZ lines, SWIFT/BIC codes, IMEIs, MAC
//! addresses and Bitcoin addresses. Each result is a [`Span`]: byte offsets into the text, a [`Kind`] and a score.
//! Spans never carry the matched text, so a result can be logged or sent across a
//! process boundary without carrying the personal data it points at.
//!
//! The rules are a port of the pattern, checksum and context logic of Microsoft
//! Presidio's predefined recognisers (MIT, `LICENSE-PRESIDIO`;
//! data-privacy-stack/presidio at tag 2.2.364, commit `779dbd2`), adapted to a
//! linear-time regex engine with no look-around. Departures are listed where they
//! occur and in docs/33.
//!
//! Pure: no I/O, no clock, no randomness; the same text and options give the same
//! spans, natively and in WASM. Every result is a suggestion a person accepts; nothing
//! here enters a sealed document or the evidence (ADR-029).
#![forbid(unsafe_code)]

mod checksum;
mod coin;
mod context;
mod error;
mod iban;
mod ids;
mod mrz;
mod phone;
mod recognise;
mod vat;

pub use error::PiiError;

/// Scores are in thousandths: 1000 is certain (a checksum held), 0 is never returned.
/// Integers, not floats, so native and WASM agree exactly and a score crosses the
/// modeld wire (`u16`) unchanged.
pub const MAX_SCORE: u16 = 1000;

/// Default bound on the text scanned in one call: 4 MiB, the per-document text limit
/// of docs/21 §ML. Larger text is refused with `CS-PII-0001`, never cut silently.
pub const MAX_TEXT_BYTES: usize = 4 * 1024 * 1024;

/// Default bound on spans returned per call (docs/21 §ML: personal-data suggestions
/// per document). Further spans are dropped and reported as [`Truncation::Spans`].
pub const MAX_SPANS: usize = 5_000;

/// Default bound on candidates one recogniser examines per call. Bounds the checksum
/// and phone-metadata work a hostile text can demand; reported as
/// [`Truncation::Candidates`] when reached.
pub const MAX_CANDIDATES: usize = 20_000;

/// The kind of personal data a span holds. `label()` gives Presidio's entity name, so
/// results line up with Presidio-based tooling used offline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum Kind {
    /// An email address (`EMAIL_ADDRESS`).
    EmailAddress,
    /// A phone number valid for its region under libphonenumber metadata
    /// (`PHONE_NUMBER`).
    PhoneNumber,
    /// An IBAN with a valid mod-97 check and its country's format (`IBAN_CODE`).
    Iban,
    /// A payment card number passing the Luhn check (`CREDIT_CARD`).
    PaymentCard,
    /// A US Social Security number (`US_SSN`).
    UsSsn,
    /// A UK National Insurance number (`UK_NINO`).
    UkNino,
    /// An Indian Permanent Account Number (`IN_PAN`).
    InPan,
    /// An Indian Aadhaar number passing the Verhoeff check (`IN_AADHAAR`).
    InAadhaar,
    /// An IPv4 or IPv6 address (`IP_ADDRESS`).
    IpAddress,
    /// A date preceded by a birth context word (`DATE_OF_BIRTH`).
    DateOfBirth,
    /// A US Individual Taxpayer Identification Number: 9XX-XX-XXXX with an IRS middle group (`US_ITIN`).
    UsItin,
    /// A US Employer Identification Number with an IRS-assigned prefix (`US_EIN`).
    UsEin,
    /// An ABA routing number with a Federal Reserve prefix and the 3-7-1 check (`ABA_ROUTING_NUMBER`).
    AbaRouting,
    /// A Canadian Social Insurance Number passing Luhn (`CA_SIN`).
    CaSin,
    /// A UK NHS number passing its mod-11 check (`UK_NHS`).
    UkNhs,
    /// An Australian Tax File Number passing its weighted mod-11 check (`AU_TFN`).
    AuTfn,
    /// An Australian Medicare card number passing its check digit (`AU_MEDICARE`).
    AuMedicare,
    /// A German tax identification number (Steuer-ID): digit rule and ISO 7064 MOD 11,10 (`DE_TAX_ID`).
    DeTaxId,
    /// A French social security number (NIR) with its mod-97 key (`FR_NIR`).
    FrNir,
    /// A Spanish DNI/NIF with its mod-23 check letter (`ES_NIF`).
    EsNif,
    /// A Spanish NIE with its mod-23 check letter (`ES_NIE`).
    EsNie,
    /// An Italian codice fiscale with its check letter (`IT_FISCAL_CODE`).
    ItFiscalCode,
    /// A Dutch citizen service number (BSN) passing the 11-test (`NL_BSN`).
    NlBsn,
    /// An EU VAT number of a covered member state with its check digits (`EU_VAT`).
    EuVat,
    /// A passport's machine-readable zone, second line, with every 7-3-1 check digit holding (`PASSPORT_MRZ`).
    PassportMrz,
    /// A SWIFT/BIC code with an ISO 3166 country (structure only) (`SWIFT_BIC`).
    SwiftBic,
    /// A mobile device's IMEI passing Luhn (`IMEI`).
    Imei,
    /// A MAC-48 hardware address (`MAC_ADDRESS`).
    MacAddress,
    /// A Bitcoin address with a valid Base58Check or Bech32/Bech32m checksum (`CRYPTO`).
    Crypto,
}

impl Kind {
    /// Every kind, in a fixed order.
    pub const ALL: [Kind; 29] = [
        Kind::EmailAddress,
        Kind::PhoneNumber,
        Kind::Iban,
        Kind::PaymentCard,
        Kind::UsSsn,
        Kind::UkNino,
        Kind::InPan,
        Kind::InAadhaar,
        Kind::IpAddress,
        Kind::DateOfBirth,
        Kind::UsItin,
        Kind::UsEin,
        Kind::AbaRouting,
        Kind::CaSin,
        Kind::UkNhs,
        Kind::AuTfn,
        Kind::AuMedicare,
        Kind::DeTaxId,
        Kind::FrNir,
        Kind::EsNif,
        Kind::EsNie,
        Kind::ItFiscalCode,
        Kind::NlBsn,
        Kind::EuVat,
        Kind::PassportMrz,
        Kind::SwiftBic,
        Kind::Imei,
        Kind::MacAddress,
        Kind::Crypto,
    ];

    /// Presidio's entity name for this kind; stable, used on the wire and in reports.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Kind::EmailAddress => "EMAIL_ADDRESS",
            Kind::PhoneNumber => "PHONE_NUMBER",
            Kind::Iban => "IBAN_CODE",
            Kind::PaymentCard => "CREDIT_CARD",
            Kind::UsSsn => "US_SSN",
            Kind::UkNino => "UK_NINO",
            Kind::InPan => "IN_PAN",
            Kind::InAadhaar => "IN_AADHAAR",
            Kind::IpAddress => "IP_ADDRESS",
            Kind::DateOfBirth => "DATE_OF_BIRTH",
            Kind::UsItin => "US_ITIN",
            Kind::UsEin => "US_EIN",
            Kind::AbaRouting => "ABA_ROUTING_NUMBER",
            Kind::CaSin => "CA_SIN",
            Kind::UkNhs => "UK_NHS",
            Kind::AuTfn => "AU_TFN",
            Kind::AuMedicare => "AU_MEDICARE",
            Kind::DeTaxId => "DE_TAX_ID",
            Kind::FrNir => "FR_NIR",
            Kind::EsNif => "ES_NIF",
            Kind::EsNie => "ES_NIE",
            Kind::ItFiscalCode => "IT_FISCAL_CODE",
            Kind::NlBsn => "NL_BSN",
            Kind::EuVat => "EU_VAT",
            Kind::PassportMrz => "PASSPORT_MRZ",
            Kind::SwiftBic => "SWIFT_BIC",
            Kind::Imei => "IMEI",
            Kind::MacAddress => "MAC_ADDRESS",
            Kind::Crypto => "CRYPTO",
        }
    }
}

/// One finding: `text[start..end]` holds personal data of `kind`. Offsets are UTF-8
/// byte offsets on character boundaries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Span {
    /// Start, inclusive.
    pub start: usize,
    /// End, exclusive.
    pub end: usize,
    /// What it is.
    pub kind: Kind,
    /// Confidence in thousandths, 1 to [`MAX_SCORE`].
    pub score: u16,
}

/// Bounds and threshold for one call. `Default` gives the docs/21 limits and returns
/// every span with a score above zero, as Presidio does; callers choose their own
/// threshold for display or redaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Options {
    /// Text larger than this is refused (`CS-PII-0001`).
    pub max_text_bytes: usize,
    /// Spans past this many are dropped and reported.
    pub max_spans: usize,
    /// Candidates past this many per recogniser are not examined, and reported.
    pub max_candidates: usize,
    /// Spans scoring below this are not returned.
    pub min_score: u16,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            max_text_bytes: MAX_TEXT_BYTES,
            max_spans: MAX_SPANS,
            max_candidates: MAX_CANDIDATES,
            min_score: 1,
        }
    }
}

/// A bound that was reached; carries the kind and the limit, never text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Truncation {
    /// One recogniser stopped after `limit` candidates; later ones were not examined.
    Candidates {
        /// The recogniser's kind.
        kind: Kind,
        /// The limit reached.
        limit: usize,
    },
    /// More than `limit` spans were found; the first `limit` in text order are kept.
    Spans {
        /// The limit reached.
        limit: usize,
    },
}

/// The result of [`detect`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Detection {
    /// Spans in text order (by start, then end, then kind).
    pub spans: Vec<Span>,
    /// Bounds reached, if any. Empty means the whole text was examined.
    pub truncated: Vec<Truncation>,
}

/// Finds personal data in `text`.
///
/// # Errors
///
/// [`PiiError::TextTooLarge`] when `text` is over `options.max_text_bytes`.
pub fn detect(text: &str, options: &Options) -> Result<Detection, PiiError> {
    if text.len() > options.max_text_bytes {
        return Err(PiiError::TextTooLarge {
            bytes: text.len(),
            limit: options.max_text_bytes,
        });
    }
    let mut scan = Scan {
        text,
        options,
        spans: Vec::new(),
        examined: [0; Kind::ALL.len()],
        truncated: Vec::new(),
    };
    recognise::run_all(&mut scan);
    let Scan {
        mut spans,
        mut truncated,
        ..
    } = scan;
    spans.retain(|s| s.score >= options.min_score.max(1));
    let mut spans = resolve(spans);
    if spans.len() > options.max_spans {
        spans.truncate(options.max_spans);
        truncated.push(Truncation::Spans {
            limit: options.max_spans,
        });
    }
    Ok(Detection { spans, truncated })
}

/// One call's working state: the text, the spans found so far and each recogniser's
/// candidate count.
pub(crate) struct Scan<'t> {
    pub(crate) text: &'t str,
    options: &'t Options,
    spans: Vec<Span>,
    examined: [usize; Kind::ALL.len()],
    truncated: Vec<Truncation>,
}

impl Scan<'_> {
    /// Counts one candidate for `kind`; false once its budget is spent (reported once).
    pub(crate) fn take(&mut self, kind: Kind) -> bool {
        let i = Kind::ALL.iter().position(|k| *k == kind).unwrap_or(0);
        let Some(n) = self.examined.get_mut(i) else {
            return false;
        };
        if *n >= self.options.max_candidates {
            let t = Truncation::Candidates {
                kind,
                limit: self.options.max_candidates,
            };
            if !self.truncated.contains(&t) {
                self.truncated.push(t);
            }
            return false;
        }
        *n = n.saturating_add(1);
        true
    }

    pub(crate) fn push(&mut self, start: usize, end: usize, kind: Kind, score: u16) {
        if start < end {
            self.spans.push(Span {
                start,
                end,
                kind,
                score: score.min(MAX_SCORE),
            });
        }
    }
}

/// Overlaps, as Presidio's `remove_duplicates` with one extension. A span is dropped
/// when another of the same kind covers it with an equal or higher score (Presidio),
/// or when a strictly longer span of any kind covers it with an equal or higher score
/// (here: the card digits inside a valid IBAN are not a second finding). Spans of
/// different kinds over exactly the same text are all kept, as Presidio keeps them.
fn resolve(mut spans: Vec<Span>) -> Vec<Span> {
    // Every span that could cover another comes before it in this order.
    spans.sort_by(|a, b| {
        a.start
            .cmp(&b.start)
            .then(b.end.cmp(&a.end))
            .then(b.score.cmp(&a.score))
            .then(a.kind.cmp(&b.kind))
    });
    let mut kept: Vec<Span> = Vec::with_capacity(spans.len());
    // Indices into `kept` of spans still open at the current start.
    let mut open: Vec<usize> = Vec::new();
    for s in spans {
        open.retain(|&i| kept.get(i).is_some_and(|k| k.end > s.start));
        let covered = open.iter().filter_map(|&i| kept.get(i)).any(|k| {
            let covers = k.start <= s.start && s.end <= k.end;
            let longer = k.end.saturating_sub(k.start) > s.end.saturating_sub(s.start);
            covers && k.score >= s.score && (k.kind == s.kind || longer)
        });
        if !covered {
            open.push(kept.len());
            kept.push(s);
        }
    }
    kept.sort_by(|a, b| {
        a.start
            .cmp(&b.start)
            .then(a.end.cmp(&b.end))
            .then(a.kind.cmp(&b.kind))
    });
    kept
}
