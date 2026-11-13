//! OpenSeal's certificate of completion and the audit trail embedded with it (docs/30
//! §8, docs/32 §6, stage 1I `T-1I`).
//!
//! - [`render_certificate`] makes a standalone certificate PDF.
//! - [`append_certificate`] appends the certificate's pages to the document it certifies,
//!   as one incremental update (the document's bytes stay a prefix of the output).
//!
//! Both embed the chain's trail file, `audit-trail.json` (RFC 8785 canonical JSON, byte
//! for byte what [`casual_sign_audit::Chain::to_trail_json`] gives), as the document's
//! associated file: `/AF` on the catalog with `/AFRelationship /Supplement`, an
//! `/EmbeddedFiles` name-tree entry, `/Subtype /application#2Fjson` and `/Params` with
//! the size and `/CheckSum`. Admission reports the file like any embedded file
//! (`CS-PDF-0104`); normalization removes embedded files from uploads only, and the
//! certificate is added after it.
//!
//! **Certificate and seal.** The certificate is part of the document the seal covers, so
//! it cannot print the sealed file's hash (that hash would have to cover itself). It
//! prints each document's hash as delivered and the chain head: the hash of the last
//! event before sealing (`envelope.completing`). The seal then covers every page, this
//! certificate and the embedded trail, and the `document.sealed` event that follows in
//! the chain records the sealed hash. A certificate made after sealing, delivered
//! separately, may print sealed hashes and the seal's details ([`SealInfo::Applied`]).
//!
//! Sections follow docs/32 §6: envelope summary, documents, signer events with signature
//! and initials images, consent with the disclosure's hash (text inline or in an
//! appendix), carbon copies and viewers, seal, how to verify. Dates use the account's
//! format and a supplied UTC offset; emails are masked per [`EmailMask`]. Text and
//! signatures are drawn by `casual-sign-flatten`, in subset embedded faces with
//! `ToUnicode` maps. Output is deterministic: the same input gives the same bytes.

mod error;
mod input;
mod layout;
mod pdf;
mod text;

use casual_sign_audit::{Hash256, VerifyOptions, verify_trail};
use casual_sign_flatten::FontSet;
use casual_sign_pdf::{Admitted, Change, Dictionary, IncrementalUpdate, Limits, Object, admit};

pub use error::CertificateError;
pub use input::{
    AttachmentRow, AuthStep, CertificateInput, CertificateOptions, Consent, CopyKind, CopyRow,
    Disclosure, DisclosurePlacement, DocumentRow, EmailMask, EndKind, Ending, EnvelopeSummary,
    Mark, Outcome, PageSize, Party, RecipientRow, Role, SealInfo,
};

/// Bounds on certificate input (`CS-AUD-0020`, `CS-AUD-0021`). Decisions of `T-1I`
/// unless marked; docs/21 records them.
pub mod limits {
    /// Most recipients (docs/21 "Recipients per envelope").
    pub const MAX_RECIPIENTS: usize = 100;
    /// Most documents.
    pub const MAX_DOCUMENTS: usize = 100;
    /// Most carbon copies and viewers.
    pub const MAX_COPIES: usize = 100;
    /// Most signer attachments listed (WEB-06; docs/21).
    pub const MAX_ATTACHMENTS: usize = 1_000;
    /// Most bytes in any one text value (docs/21 "Text field value").
    pub const MAX_TEXT_BYTES: usize = 4_000;
    /// Most bytes of disclosure text.
    pub const MAX_DISCLOSURE_BYTES: usize = 256 * 1024;
    /// Most certificate pages.
    pub const MAX_PAGES: usize = 500;
}

/// A standalone certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Rendered {
    /// The PDF.
    pub bytes: Vec<u8>,
    /// Its pages.
    pub pages: usize,
    /// SHA-256 of the embedded `audit-trail.json`.
    pub trail_sha256: Hash256,
    /// Lines set smaller than asked because a supplied face is wider than the measure
    /// used to break lines (0 with the bundled faces).
    pub lines_shrunk: usize,
}

/// A document with its certificate appended.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Appended {
    /// The input bytes followed by one update.
    pub bytes: Vec<u8>,
    /// Pages the certificate added.
    pub pages_added: usize,
    /// The index of its first page, from 0.
    pub first_page: usize,
    /// SHA-256 of the embedded `audit-trail.json`.
    pub trail_sha256: Hash256,
    /// As [`Rendered::lines_shrunk`].
    pub lines_shrunk: usize,
}

fn bounded(s: &str, what: &'static str) -> Result<(), CertificateError> {
    if s.len() > limits::MAX_TEXT_BYTES {
        return Err(CertificateError::Input { what });
    }
    Ok(())
}

/// Check the input against its bounds and the chain, and return the trail file.
fn checked(input: &CertificateInput<'_>) -> Result<Vec<u8>, CertificateError> {
    let e = &input.envelope;
    for (s, what) in [
        (e.id.as_str(), "envelope.id"),
        (&e.subject, "envelope.subject"),
        (&e.status, "envelope.status"),
        (&e.sender.name, "envelope.sender"),
        (&e.sender.email, "envelope.sender"),
        (&e.account, "envelope.account"),
        (&e.seal_profile, "envelope.seal_profile"),
    ] {
        bounded(s, what)?;
    }
    if input.recipients.len() > limits::MAX_RECIPIENTS {
        return Err(CertificateError::Input { what: "recipients" });
    }
    if input.documents.len() > limits::MAX_DOCUMENTS {
        return Err(CertificateError::Input { what: "documents" });
    }
    if input.copies.len() > limits::MAX_COPIES {
        return Err(CertificateError::Input { what: "copies" });
    }
    for d in &input.documents {
        bounded(&d.name, "documents.name")?;
    }
    for r in &input.recipients {
        bounded(&r.party.name, "recipients.name")?;
        bounded(&r.party.email, "recipients.email")?;
        bounded(r.ip.as_deref().unwrap_or(""), "recipients.ip")?;
        bounded(
            r.user_agent.as_deref().unwrap_or(""),
            "recipients.user_agent",
        )?;
        if let Outcome::Declined {
            reason: Some(why), ..
        } = &r.outcome
        {
            bounded(why, "recipients.reason")?;
        }
        if let Some(c) = &r.consent {
            bounded(&c.version, "recipients.consent")?;
        }
    }
    if input.attachments.len() > limits::MAX_ATTACHMENTS {
        return Err(CertificateError::Input {
            what: "attachments",
        });
    }
    for a in &input.attachments {
        bounded(&a.recipient, "attachments.recipient")?;
        bounded(&a.field, "attachments.field")?;
        bounded(&a.media_type, "attachments.media_type")?;
    }
    for c in &input.copies {
        bounded(&c.party.name, "copies.name")?;
        bounded(&c.party.email, "copies.email")?;
    }
    if let Some(d) = &input.disclosure {
        bounded(&d.version, "disclosure.version")?;
        if d.text.len() > limits::MAX_DISCLOSURE_BYTES {
            return Err(CertificateError::Input {
                what: "disclosure.text",
            });
        }
    }
    if let SealInfo::Applied {
        subject,
        issuer,
        tsa,
        ..
    } = &input.seal
    {
        bounded(subject, "seal.subject")?;
        bounded(issuer, "seal.issuer")?;
        bounded(tsa.as_deref().unwrap_or(""), "seal.tsa")?;
    }
    bounded(input.verify_url.as_deref().unwrap_or(""), "verify_url")?;
    if let Some(end) = &input.ending {
        bounded(end.by.as_deref().unwrap_or(""), "ending.by")?;
        bounded(end.reason.as_deref().unwrap_or(""), "ending.reason")?;
    }
    // The chain: not empty, this envelope's, and its own trail must verify.
    if input.chain.is_empty() {
        return Err(CertificateError::Input { what: "chain" });
    }
    if input.chain.envelope_id().as_str() != e.id {
        return Err(CertificateError::Input {
            what: "chain.envelope_id",
        });
    }
    let trail = input.chain.to_trail_json()?;
    let report = verify_trail(
        &trail,
        &VerifyOptions {
            expected_head: input.chain.head(),
            ..VerifyOptions::default()
        },
    );
    report.into_result()?;
    Ok(trail)
}

/// The certificate's pages drawn, before the trail is attached.
struct Drawn {
    bytes: Vec<u8>,
    pages: usize,
    trail_sha256: Hash256,
    lines_shrunk: usize,
}

/// Lay out and draw the certificate's pages.
fn drawn(
    input: &CertificateInput<'_>,
    fonts: &FontSet,
    options: &CertificateOptions,
    trail: &[u8],
) -> Result<Drawn, CertificateError> {
    let trail_sha256 = Hash256::digest(trail);
    let plan = layout::plan(input, options, &trail_sha256);
    if plan.pages.len() > limits::MAX_PAGES {
        return Err(CertificateError::TooManyPages {
            pages: plan.pages.len(),
            limit: limits::MAX_PAGES,
        });
    }
    let file_id = trail_sha256
        .as_bytes()
        .get(..16)
        .unwrap_or_default()
        .to_vec();
    let (bytes, lines_shrunk) = pdf::draw(&plan, fonts, &file_id)?;
    Ok(Drawn {
        bytes,
        pages: plan.pages.len(),
        trail_sha256,
        lines_shrunk,
    })
}

/// A standalone certificate of completion for `input`, with the trail embedded.
///
/// # Errors
///
/// `CS-AUD-0020` for input over its bounds or a chain that is empty, not this
/// envelope's, or does not verify; `CS-AUD-0021` over 500 pages; `CS-AUD-0024` for text
/// that did not fit; `CS-FLT-0001` for a character no face in `fonts` has; the image
/// codes for a signature image the flattener refuses.
pub fn render_certificate(
    input: &CertificateInput<'_>,
    fonts: &FontSet,
    options: &CertificateOptions,
) -> Result<Rendered, CertificateError> {
    let trail = checked(input)?;
    let d = drawn(input, fonts, options, &trail)?;
    let mut admitted = admit(&d.bytes, &Limits::default(), &pdf::never)?;
    let (root, catalog) = pdf::catalog(&mut admitted.document)?;
    let names = pdf::names(&mut admitted.document, &catalog)?;
    let shared: &Admitted<'_> = &admitted;
    let mut u = IncrementalUpdate::new(shared, Change::Other)?;
    pdf::attach(
        &mut u,
        root,
        catalog,
        names,
        &trail,
        input.chain.len(),
        input.generated,
    )?;
    let mut info = Dictionary::new();
    info.insert(
        b"Title",
        Object::String(layout::title(input).as_bytes().to_vec()),
    );
    info.insert(
        b"Producer",
        Object::String(b"OpenSeal casual-sign-certificate".to_vec()),
    );
    info.insert(
        b"CreationDate",
        Object::String(pdf::pdf_date(input.generated).into_bytes()),
    );
    let info = u.add(Object::Dictionary(info))?;
    u.set_info(info);
    Ok(Rendered {
        bytes: u.finish()?,
        pages: d.pages,
        trail_sha256: d.trail_sha256,
        lines_shrunk: d.lines_shrunk,
    })
}

/// `admitted` (the flattened document, before sealing) with the certificate's pages
/// appended after its last page and the trail embedded, in one incremental update.
///
/// The new pages set every inheritable attribute, so nothing of the document's page
/// tree changes how they look. Reading the catalog and page tree needs `&mut` (the
/// reader caches).
///
/// # Errors
///
/// As [`render_certificate`], and `CS-AUD-0022` when the document already has `/AF` or
/// embedded files, `CS-AUD-0023` when its catalog or page tree cannot be followed, and
/// the writer's codes (`CS-WRT-0003` for a file that needed repair, `CS-WRT-0004` when a
/// certification signature forbids the change).
pub fn append_certificate(
    admitted: &mut Admitted<'_>,
    input: &CertificateInput<'_>,
    fonts: &FontSet,
    options: &CertificateOptions,
) -> Result<Appended, CertificateError> {
    let trail = checked(input)?;
    let d = drawn(input, fonts, options, &trail)?;
    let mut src = admit(&d.bytes, &Limits::default(), &pdf::never)?;
    let src_pages: Vec<u32> = src.report.pages.iter().map(|p| p.object).collect();

    let doc = &mut admitted.document;
    let (root, catalog) = pdf::catalog(doc)?;
    let names = pdf::names(doc, &catalog)?;
    let pages_ref = catalog
        .get(b"Pages")
        .and_then(Object::as_ref)
        .ok_or(CertificateError::PageTree { object: Some(root) })?;
    let mut tree = match doc.object(pages_ref.num, &pdf::never)? {
        Object::Dictionary(d) if d.name(b"Type") != Some(b"Page") => d,
        _ => {
            return Err(CertificateError::PageTree {
                object: Some(pages_ref.num),
            });
        }
    };
    let mut kids = match tree.get(b"Kids").cloned() {
        Some(v) => match doc.resolve(&v, &pdf::never)? {
            Object::Array(a) => a,
            _ => {
                return Err(CertificateError::PageTree {
                    object: Some(pages_ref.num),
                });
            }
        },
        None => Vec::new(),
    };
    let count = match tree.get(b"Count").cloned() {
        Some(v) => doc.resolve(&v, &pdf::never)?.as_i64(),
        None => None,
    }
    .ok_or(CertificateError::PageTree {
        object: Some(pages_ref.num),
    })?;
    let first_page = admitted.report.pages.len();

    let shared: &Admitted<'_> = admitted;
    let mut u = IncrementalUpdate::new(shared, Change::Other)?;
    let new_pages = pdf::copy_pages(&mut src, &src_pages, &mut u, pages_ref)?;
    kids.extend(new_pages.iter().map(|r| Object::Reference(*r)));
    let added = i64::try_from(new_pages.len()).unwrap_or(i64::MAX);
    tree.insert(b"Kids", Object::Array(kids));
    tree.insert(b"Count", Object::Integer(count.saturating_add(added)));
    u.replace(pages_ref.num, Object::Dictionary(tree))?;
    pdf::attach(
        &mut u,
        root,
        catalog,
        names,
        &trail,
        input.chain.len(),
        input.generated,
    )?;
    Ok(Appended {
        bytes: u.finish()?,
        pages_added: d.pages,
        first_page,
        trail_sha256: d.trail_sha256,
        lines_shrunk: d.lines_shrunk,
    })
}
