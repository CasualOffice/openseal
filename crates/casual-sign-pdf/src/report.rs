//! The admission report: what the reader found and what it stepped over (docs/30 §2).
//!
//! Findings carry codes, object numbers and page indexes only. The report's inventory
//! (field names, page geometry) is data for the sender's review, never logged.

use std::collections::BTreeSet;

use crate::error::PdfError;
use crate::xref::XrefKind;

/// Most findings kept in a report; further ones are counted in
/// [`AdmissionReport::findings_dropped`].
pub const MAX_FINDINGS: usize = 10_000;

/// What a finding is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum FindingKind {
    /// The xref was rebuilt by scanning for objects (`CS-PDF-0101`).
    XrefRebuilt,
    /// Xref offsets or `startxref` were wrong and corrected to the object or section
    /// found nearby (`CS-PDF-0101`).
    XrefCorrected,
    /// An object could not be read and was dropped (`CS-PDF-0102`).
    ObjectUnreadable,
    /// A limit was crossed by one value or stream, which was dropped; the code is the
    /// limit's (`CS-PDF-0002`, `-0003`, `-0004`, `-0006`, `-0008`, `-0011`, `-0013`).
    LimitCrossed,
    /// JavaScript, or an action that runs or sends data (`CS-PDF-0103`).
    Action(ActionKind),
    /// An XFA form (`CS-PDF-0103`).
    Xfa,
    /// An embedded file (`CS-PDF-0104`).
    EmbeddedFile,
    /// A RichMedia or 3D annotation or stream (`CS-PDF-0104`).
    RichMedia,
    /// An action or stream that reaches outside the file (`CS-PDF-0105`).
    ExternalReference(ActionKind),
    /// A stream whose data is in an external file (`/F` on a stream) (`CS-PDF-0105`).
    ExternalStream,
    /// Existing AcroForm fields (`CS-PDF-0106`).
    FormFields,
    /// Existing signatures, `/Perms` or DocMDP (`CS-PDF-0107`).
    Signatures,
    /// A usage-rights signature (`/Perms /UR3` or `/UR`, Adobe Reader extensions)
    /// (`CS-PDF-0107`). It attests no content and does not make a document signed for
    /// the repair rule (docs/30 §2); normalization removes it.
    UsageRights,
    /// Optional content (`CS-PDF-0108`).
    OptionalContent,
}

/// The kind of an action found (ISO 32000-2 §12.6.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum ActionKind {
    /// `/S /JavaScript`, a `/JS` entry, or the document JavaScript name tree.
    JavaScript,
    /// `/S /Launch`.
    Launch,
    /// `/S /GoToR`.
    GoToR,
    /// `/S /GoToE`.
    GoToE,
    /// `/S /URI`.
    Uri,
    /// `/S /SubmitForm`.
    SubmitForm,
    /// `/S /ImportData`.
    ImportData,
    /// `/S /Rendition`, `/Movie`, `/Sound` and other multimedia actions.
    Multimedia,
    /// Any other action (`/GoTo`, `/Named`, …) or a destination. Admission never
    /// reports it; normalization reports it when it removes a whole `/OpenAction` or
    /// `/AA` entry (docs/30 §3).
    Other,
}

/// One thing the reader found or stepped over.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Finding {
    /// The `CS-PDF-*` code from docs/20.
    pub code: &'static str,
    /// What it is about.
    pub kind: FindingKind,
    /// The object it concerns, when there is one.
    pub object: Option<u32>,
    /// The zero-based page it concerns, when there is one.
    pub page: Option<u32>,
}

impl Finding {
    pub(crate) fn new(code: &'static str, kind: FindingKind, object: Option<u32>) -> Self {
        Self {
            code,
            kind,
            object,
            page: None,
        }
    }

    /// A limit crossed by one value or stream, reported instead of refused.
    pub(crate) fn limit(e: &PdfError, object: Option<u32>, page: Option<u32>) -> Self {
        let kind = match e {
            PdfError::Malformed { .. } | PdfError::NotPdf { .. } => FindingKind::ObjectUnreadable,
            _ => FindingKind::LimitCrossed,
        };
        let code = if kind == FindingKind::ObjectUnreadable {
            "CS-PDF-0102"
        } else {
            e.code()
        };
        Self {
            code,
            kind,
            object,
            page,
        }
    }
}

/// A bounded, de-duplicated list of findings in discovery order.
#[derive(Debug, Default, Clone)]
pub(crate) struct Findings {
    pub(crate) list: Vec<Finding>,
    seen: BTreeSet<Finding>,
    pub(crate) dropped: u64,
}

impl Findings {
    pub(crate) fn push(&mut self, f: Finding) {
        if self.seen.contains(&f) {
            return;
        }
        if self.list.len() >= MAX_FINDINGS {
            self.dropped = self.dropped.saturating_add(1);
            return;
        }
        self.seen.insert(f);
        self.list.push(f);
    }

    pub(crate) fn has(&self, kind: FindingKind) -> bool {
        self.list.iter().any(|f| f.kind == kind)
    }
}

/// The PDF version, from the header or the catalog's `/Version`, whichever is later.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PdfVersion {
    /// Major version.
    pub major: u8,
    /// Minor version.
    pub minor: u8,
}

/// One revision of the file, oldest first (ISO 32000-2 §7.5.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Revision {
    /// Byte offset of this revision's xref section; `None` for a rebuilt xref.
    pub xref_offset: Option<u64>,
    /// Byte offset just past this revision's `%%EOF` line: where an incremental
    /// update to it would begin.
    pub end_offset: u64,
    /// The section's form.
    pub kind: XrefKind,
}

/// A rectangle in default user space units, normalized so `llx <= urx`, `lly <= ury`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Rect {
    /// Lower-left x.
    pub llx: f64,
    /// Lower-left y.
    pub lly: f64,
    /// Upper-right x.
    pub urx: f64,
    /// Upper-right y.
    pub ury: f64,
}

/// One page's geometry, with inherited attributes applied.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PageInfo {
    /// The page object's number.
    pub object: u32,
    /// `/MediaBox`; US Letter when absent or unreadable (then `media_box_defaulted`).
    pub media_box: Rect,
    /// `/CropBox`, defaulting to the media box, clipped to it.
    pub crop_box: Rect,
    /// `/Rotate`, normalized to 0, 90, 180 or 270.
    pub rotate: u16,
    /// `/UserUnit`, default 1.0.
    pub user_unit: f64,
    /// True when the media box was missing or unreadable.
    pub media_box_defaulted: bool,
}

/// The type of an existing form field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FieldType {
    /// Text field (`/Tx`).
    Text,
    /// Check box (`/Btn`).
    CheckBox,
    /// Radio button group (`/Btn` with the radio flag).
    Radio,
    /// Push button (`/Btn` with the push-button flag).
    PushButton,
    /// Choice field (`/Ch`).
    Choice,
    /// Signature field (`/Sig`).
    Signature,
    /// No or unknown `/FT`.
    Unknown,
}

/// A widget of a form field: where it is drawn.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Widget {
    /// The widget annotation's object number, when it is indirect.
    pub object: Option<u32>,
    /// `/Rect`, normalized.
    pub rect: Rect,
    /// Zero-based page index from `/P`, when it names a page of the document.
    pub page: Option<u32>,
}

/// An existing AcroForm field (a terminal field).
#[derive(Debug, Clone, PartialEq)]
pub struct FormField {
    /// The field object's number, when indirect.
    pub object: Option<u32>,
    /// Fully qualified name (`/T` parts joined with `.`), decoded from PDF text.
    pub name: String,
    /// Field type, with inheritance applied.
    pub field_type: FieldType,
    /// Widgets, with their rectangles.
    pub widgets: Vec<Widget>,
}

/// What an existing signature is (ISO 32000-2 §12.8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum SignatureKind {
    /// An approval signature: a signature field's value.
    Approval,
    /// A certification signature: the value of `/Perms /DocMDP`.
    Certification,
    /// A usage-rights signature: the value of `/Perms /UR3` (or `/UR`), which grants
    /// Adobe Reader features and attests no content.
    UsageRights,
    /// A document timestamp (`/Type /DocTimeStamp`).
    DocTimeStamp,
}

/// An existing signature.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SignatureInfo {
    /// The signature field's object number, when indirect.
    pub field: Option<u32>,
    /// The signature dictionary's object number, when indirect.
    pub value: Option<u32>,
    /// `/SubFilter` (a name from the specification, e.g. `ETSI.CAdES.detached`).
    pub sub_filter: Option<String>,
    /// What the signature is.
    pub kind: SignatureKind,
}

/// One action found, and how it is triggered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActionInfo {
    /// The object holding the action.
    pub object: u32,
    /// The action's kind.
    pub kind: ActionKind,
    /// True when it runs without a click: from `/OpenAction` or an `/AA` dictionary.
    pub automatic: bool,
}

/// The rule behind [`AdmissionReport::is_signed`] (docs/30 §2, `PDF-REAL-02`).
pub(crate) fn counts_as_signed(docmdp: Option<u8>, signatures: &[SignatureInfo]) -> bool {
    docmdp.is_some()
        || signatures
            .iter()
            .any(|s| s.kind != SignatureKind::UsageRights)
}

/// Everything admission found in a document.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct AdmissionReport {
    /// PDF version.
    pub version: Option<PdfVersion>,
    /// Number of pages.
    pub page_count: u32,
    /// Geometry of every page, in order.
    pub pages: Vec<PageInfo>,
    /// Revisions, oldest first.
    pub revisions: Vec<Revision>,
    /// Number of in-use objects in the xref.
    pub object_count: u32,
    /// True when the file needed any xref repair (`CS-PDF-0101`): such a file is not
    /// structurally sound for appending (docs/30 §2).
    pub repaired: bool,
    /// Streams whose `/Length` was wrong and whose end was found by `endstream`.
    pub stream_lengths_corrected: u32,
    /// Existing AcroForm fields.
    pub fields: Vec<FormField>,
    /// Existing signatures.
    pub signatures: Vec<SignatureInfo>,
    /// The catalog has `/Perms`.
    pub has_perms: bool,
    /// DocMDP permission level (1, 2 or 3), when a certification signature sets one.
    pub docmdp: Option<u8>,
    /// Actions found.
    pub actions: Vec<ActionInfo>,
    /// Embedded file streams and file specifications with `/EF`.
    pub embedded_files: Vec<u32>,
    /// RichMedia and 3D objects.
    pub rich_media: Vec<u32>,
    /// Streams with data in external files.
    pub external_streams: Vec<u32>,
    /// The AcroForm has `/XFA`.
    pub has_xfa: bool,
    /// The catalog has `/OCProperties`.
    pub has_optional_content: bool,
    /// Total bytes decoded during admission (charged to the document budget).
    pub decoded_bytes: u64,
    /// Findings, in discovery order.
    pub findings: Vec<Finding>,
    /// Findings not kept because the list reached [`MAX_FINDINGS`].
    pub findings_dropped: u64,
}

impl AdmissionReport {
    /// True when the document counts as signed (docs/30 §2): it has a certification
    /// (`/Perms /DocMDP`), or any signature other than a usage-rights one. A document
    /// whose only signatures are usage rights is not signed: Reader extensions attest
    /// no content, and normalization removes them. A signed document is never
    /// repaired (`CS-PDF-0014`) or normalized.
    #[must_use]
    pub fn is_signed(&self) -> bool {
        counts_as_signed(self.docmdp, &self.signatures)
    }

    /// True when any finding carries `code`.
    #[must_use]
    pub fn has_code(&self, code: &str) -> bool {
        self.findings.iter().any(|f| f.code == code)
    }
}
