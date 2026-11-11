//! The certificate's layout (docs/32 §6): sections flowed down pages, cut where a block
//! no longer fits, each page with a header and a "Page i of N" footer.
//!
//! The result is a plan: per page, vector rules and boxes as content-stream operators,
//! text runs (one line each) and signature pictures, all in points from the page's top
//! left. `pdf::draw` turns runs and pictures into fields the flattener draws, so the
//! certificate's text and signatures go through the same layout, font subsetting and
//! image checks as every signed document.

use casual_sign_audit::{
    AdoptionMethod, AuthMethod, Chain, FallbackReason, Hash256, Location, LocationSource,
};
use casual_sign_flatten::Art;
use casual_sign_model::{Align, Rgb};

use crate::input::{
    CertificateInput, CertificateOptions, CopyKind, DisclosurePlacement, Mark, Outcome, Role,
    SealInfo,
};
use crate::text::{Face, datetime, email, maybe, wrap, zone};

/// A line of text: its box, from the page's top left, in points.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Run {
    pub x: f64,
    pub top: f64,
    pub w: f64,
    pub h: f64,
    pub text: String,
    pub size: f64,
    pub face: Face,
    pub color: Rgb,
    pub align: Align,
}

/// A signature or initials in its box.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Picture {
    pub x: f64,
    pub top: f64,
    pub w: f64,
    pub h: f64,
    pub art: Art,
}

/// One page of the plan.
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct PagePlan {
    /// Content-stream operators for rules and boxes (PDF coordinates).
    pub ops: String,
    pub runs: Vec<Run>,
    pub pictures: Vec<Picture>,
}

/// The whole certificate.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Plan {
    pub width: f64,
    pub height: f64,
    pub pages: Vec<PagePlan>,
}

const NAVY: Rgb = Rgb([0x1f, 0x3a, 0x5f]);
const GREY: Rgb = Rgb([0x55, 0x5b, 0x63]);
const BLACK: Rgb = Rgb([0x11, 0x11, 0x11]);
const RULE: [f64; 3] = [0.78, 0.80, 0.83];
const BOX_FILL: [f64; 3] = [0.97, 0.975, 0.98];

const MARGIN: f64 = 48.0;
const TOP: f64 = 60.0;
const BOTTOM_GAP: f64 = 52.0;
const LABEL_W: f64 = 128.0;
const GAP: f64 = 6.0;
const BODY: f64 = 8.5;
const LABEL: f64 = 7.5;
const HASH: f64 = 7.2;
const HEADING: f64 = 11.0;
const SIG_W: f64 = 168.0;
const SIG_H: f64 = 54.0;
const INI_W: f64 = 84.0;
const INI_H: f64 = 38.0;

/// The height of a one-line field at `size`: the face's line (ascent to descent, at
/// most 1.15 em for the bundled faces) plus the flattener's 2-point padding each side.
pub(crate) fn line_h(size: f64) -> f64 {
    size * 1.15 + 4.5
}

/// A pending text value and how to set it.
struct Value {
    text: String,
    face: Face,
    size: f64,
}

impl Value {
    fn plain(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            face: Face::Sans,
            size: BODY,
        }
    }
    fn hash(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            face: Face::Mono,
            size: HASH,
        }
    }
}

struct Writer {
    w: f64,
    h: f64,
    /// Pages finished.
    done: Vec<PagePlan>,
    /// The page being written.
    cur: PagePlan,
    y: f64,
}

/// A rule from `x1` to `x2` at `top`, as operators on a page `h` high.
fn rule_op(h: f64, x1: f64, x2: f64, top: f64, color: [f64; 3], weight: f64) -> String {
    let y = h - top;
    let [r, g, b] = color;
    format!(
        "q {} {} {} RG {} w {} {} m {} {} l S Q\n",
        n(r),
        n(g),
        n(b),
        n(weight),
        n(x1),
        n(y),
        n(x2),
        n(y)
    )
}

// The arguments are the run's own fields; a builder would only rename them.
#[allow(clippy::too_many_arguments)]
/// One line of text in a box `w` wide at (`x`, `top`).
fn make_run(
    x: f64,
    top: f64,
    w: f64,
    text: String,
    size: f64,
    face: Face,
    color: Rgb,
    align: Align,
) -> Run {
    Run {
        x,
        top,
        w,
        h: line_h(size),
        text,
        size,
        face,
        color,
        align,
    }
}

fn n(v: f64) -> String {
    let s = format!("{v:.2}");
    let s = s.trim_end_matches('0').trim_end_matches('.');
    if s.is_empty() || s == "-0" {
        "0".to_owned()
    } else {
        s.to_owned()
    }
}

impl Writer {
    fn content_w(&self) -> f64 {
        self.w - 2.0 * MARGIN
    }
    fn bottom(&self) -> f64 {
        self.h - BOTTOM_GAP
    }
    /// The current page's index, from 0.
    fn index(&self) -> usize {
        self.done.len()
    }
    fn new_page(&mut self) {
        self.done.push(core::mem::take(&mut self.cur));
        self.y = TOP;
    }
    /// Start a new page unless `h` more points fit on this one.
    fn ensure(&mut self, h: f64) {
        if self.y + h > self.bottom() {
            self.new_page();
        }
    }
    // As `make_run`.
    #[allow(clippy::too_many_arguments)]
    fn run(
        &mut self,
        x: f64,
        w: f64,
        text: String,
        size: f64,
        face: Face,
        color: Rgb,
        align: Align,
    ) {
        let r = make_run(x, self.y, w, text, size, face, color, align);
        self.cur.runs.push(r);
    }
    fn rule(&mut self, x1: f64, x2: f64, top: f64, color: [f64; 3], weight: f64) {
        let op = rule_op(self.h, x1, x2, top, color, weight);
        self.cur.ops.push_str(&op);
    }
    fn frame(&mut self, x: f64, top: f64, w: f64, h: f64) {
        let y = self.h - top - h;
        let [fr, fg, fb] = BOX_FILL;
        let [r, g, b] = RULE;
        let op = format!(
            "q {} {} {} rg {} {} {} RG 0.6 w {} {} {} {} re B Q\n",
            n(fr),
            n(fg),
            n(fb),
            n(r),
            n(g),
            n(b),
            n(x),
            n(y),
            n(w),
            n(h)
        );
        self.cur.ops.push_str(&op);
    }

    /// A paragraph flowed down the page, breaking pages between lines.
    fn para(&mut self, x: f64, w: f64, v: &Value, color: Rgb) {
        let lh = line_h(v.size);
        for line in wrap(&v.text, v.size, w - 4.0, v.face) {
            self.ensure(lh);
            self.run(x, w, line, v.size, v.face, color, Align::Left);
            self.y += lh;
        }
    }

    /// A section heading, kept with the start of what follows.
    fn heading(&mut self, text: &str) {
        let lh = line_h(HEADING);
        self.ensure(lh + 10.0 + 3.0 * line_h(BODY));
        self.y += 8.0;
        let w = self.content_w();
        self.run(
            MARGIN,
            w,
            text.to_owned(),
            HEADING,
            Face::Sans,
            NAVY,
            Align::Left,
        );
        self.y += lh;
        let y = self.y;
        self.rule(MARGIN, MARGIN + w, y, [0.12, 0.23, 0.37], 0.8);
        self.y += 3.0;
    }

    /// The height a label and value take in a column `w` wide.
    fn row_height(label: &str, v: &Value, w: f64) -> f64 {
        let label_lines = wrap(label, LABEL, LABEL_W - 4.0, Face::Sans).len();
        let value_lines = wrap(&v.text, v.size, w - LABEL_W - GAP - 4.0, v.face).len();
        let a = label_lines as f64 * line_h(LABEL);
        let b = value_lines as f64 * line_h(v.size);
        a.max(b)
    }

    /// A label and its value at `x`, in a column `w` wide. Kept on one page when it fits
    /// one; otherwise its value flows on.
    fn row(&mut self, x: f64, w: f64, label: &str, v: &Value) {
        let h = Self::row_height(label, v, w);
        let page_h = self.bottom() - TOP;
        self.ensure(h.min(page_h));
        let top = self.y;
        let page = self.index();
        let lh_l = line_h(LABEL);
        for (i, line) in wrap(label, LABEL, LABEL_W - 4.0, Face::Sans)
            .into_iter()
            .enumerate()
        {
            let saved = self.y;
            self.y = top + i as f64 * lh_l;
            self.run(x, LABEL_W, line, LABEL, Face::Sans, GREY, Align::Left);
            self.y = saved;
        }
        let vx = x + LABEL_W + GAP;
        let vw = w - LABEL_W - GAP;
        let lh = line_h(v.size);
        for line in wrap(&v.text, v.size, vw - 4.0, v.face) {
            self.ensure(lh);
            self.run(vx, vw, line, v.size, v.face, BLACK, Align::Left);
            self.y += lh;
        }
        if self.index() == page {
            self.y = self.y.max(top + h);
        }
    }

    fn rows(&mut self, rows: &[(String, Value)]) {
        let w = self.content_w();
        for (label, v) in rows {
            self.row(MARGIN, w, label, v);
        }
    }

    /// Every page, with its header and its "Page i of N" footer.
    fn finish(mut self, envelope_id: &str, generated: &str) -> Vec<PagePlan> {
        self.done.push(core::mem::take(&mut self.cur));
        let total = self.done.len();
        let (w, h) = (self.w, self.h);
        let cw = w - 2.0 * MARGIN;
        let title = "Certificate of Completion";
        for (i, page) in self.done.iter_mut().enumerate() {
            let page_no = format!("Page {} of {total}", i.saturating_add(1));
            let made = format!("OpenSeal \u{b7} generated {generated}");
            let env = format!("Envelope {envelope_id}");
            let half = cw / 2.0;
            page.runs.extend([
                make_run(
                    MARGIN,
                    26.0,
                    half,
                    title.to_owned(),
                    LABEL,
                    Face::Sans,
                    GREY,
                    Align::Left,
                ),
                make_run(
                    MARGIN + half,
                    26.0,
                    half,
                    env,
                    LABEL,
                    Face::Sans,
                    GREY,
                    Align::Right,
                ),
                make_run(
                    MARGIN,
                    h - 38.0,
                    cw * 0.7,
                    made,
                    LABEL,
                    Face::Sans,
                    GREY,
                    Align::Left,
                ),
                make_run(
                    MARGIN + cw * 0.7,
                    h - 38.0,
                    cw * 0.3,
                    page_no,
                    LABEL,
                    Face::Sans,
                    GREY,
                    Align::Right,
                ),
            ]);
            page.ops
                .push_str(&rule_op(h, MARGIN, w - MARGIN, 44.0, RULE, 0.5));
            page.ops
                .push_str(&rule_op(h, MARGIN, w - MARGIN, h - 42.0, RULE, 0.5));
        }
        self.done
    }
}

fn auth_name(m: AuthMethod) -> &'static str {
    match m {
        AuthMethod::EmailLink => "Email link",
        AuthMethod::AccessCode => "Access code",
        AuthMethod::SmsOtp => "SMS one-time code",
        AuthMethod::VoiceOtp => "Voice one-time code",
        AuthMethod::Kba => "Knowledge-based",
        AuthMethod::IdVerification => "ID verification",
        AuthMethod::Sso => "Single sign-on",
        AuthMethod::AccountLogin => "Account sign-in",
        AuthMethod::HostAsserted => "Asserted by host application",
        AuthMethod::EmailOtp => "Email one-time code",
        _ => "Other",
    }
}

fn adoption(m: AdoptionMethod) -> &'static str {
    match m {
        AdoptionMethod::Draw => "Drawn",
        AdoptionMethod::Type => "Typed",
        AdoptionMethod::Upload => "Uploaded image",
        _ => "Other",
    }
}

fn role(r: Role) -> &'static str {
    match r {
        Role::Signer => "Signer",
        Role::Approver => "Approver",
        Role::InPersonSigner => "In-person signer",
        Role::Witness => "Witness",
    }
}

fn hash_text(h: &Hash256) -> String {
    h.to_string()
}

/// Lay out `input`.
pub(crate) fn plan(
    input: &CertificateInput<'_>,
    o: &CertificateOptions,
    trail_sha256: &Hash256,
) -> Plan {
    let (w, h) = o.page.points();
    let mut wr = Writer {
        w,
        h,
        done: Vec::new(),
        cur: PagePlan::default(),
        y: TOP,
    };
    let cw = wr.content_w();
    let chain: &Chain = input.chain;
    let head = chain
        .head()
        .map_or_else(|| "(empty)".to_owned(), |h| hash_text(&h));
    let mask = o.email_mask;
    let e = &input.envelope;

    // Title.
    wr.run(
        MARGIN,
        cw,
        "Certificate of Completion".to_owned(),
        18.0,
        Face::Sans,
        NAVY,
        Align::Left,
    );
    wr.y += line_h(18.0);
    wr.para(
        MARGIN,
        cw,
        &Value {
            text: format!(
                "This certificate records who received, viewed, consented to and signed the documents of envelope {}, when, and how they were authenticated. The complete audit trail is attached to this PDF as audit-trail.json.",
                e.id
            ),
            face: Face::Sans,
            size: BODY,
        },
        GREY,
    );

    // 1. Envelope summary.
    wr.heading("Envelope summary");
    let pages: u64 = input.documents.iter().map(|d| u64::from(d.pages)).sum();
    let mut rows: Vec<(String, Value)> = vec![
        ("Envelope ID".into(), Value::hash(e.id.clone())),
        ("Subject".into(), Value::plain(e.subject.clone())),
        ("Status".into(), Value::plain(e.status.clone())),
        (
            "Sender".into(),
            Value::plain(format!(
                "{} <{}>",
                e.sender.name,
                email(&e.sender.email, mask)
            )),
        ),
        ("Account".into(), Value::plain(e.account.clone())),
        ("Created".into(), Value::plain(datetime(e.created, o))),
        ("Sent".into(), Value::plain(maybe(e.sent, o))),
        ("Completed".into(), Value::plain(maybe(e.completed, o))),
        ("Time zone".into(), Value::plain(zone(o))),
        ("Seal profile".into(), Value::plain(e.seal_profile.clone())),
        (
            "Documents".into(),
            Value::plain(format!("{} ({pages} pages)", input.documents.len())),
        ),
        (
            "Recipients".into(),
            Value::plain(input.recipients.len().to_string()),
        ),
        ("Audit events".into(), Value::plain(chain.len().to_string())),
        ("Audit chain head".into(), Value::hash(head.clone())),
    ];
    wr.rows(&rows);

    // 2. Documents.
    wr.heading("Documents");
    for (i, d) in input.documents.iter().enumerate() {
        rows = vec![
            (
                format!("Document {}", i.saturating_add(1)),
                Value::plain(d.name.clone()),
            ),
            ("Pages".into(), Value::plain(d.pages.to_string())),
            (
                "SHA-256 as delivered".into(),
                Value::hash(hash_text(&d.delivered)),
            ),
            (
                "SHA-256 as sealed".into(),
                match &d.sealed {
                    Some(s) => Value::hash(hash_text(s)),
                    None => Value::plain(
                        "Not printed here: the seal covers this certificate, so the sealed file's hash cannot appear in it. It is recorded in the document.sealed audit event and shown by any verifier.",
                    ),
                },
            ),
        ];
        let block: f64 = rows.iter().map(|(l, v)| Writer::row_height(l, v, cw)).sum();
        wr.ensure(block.min(wr.bottom() - TOP));
        wr.rows(&rows);
        wr.y += 4.0;
    }

    // 3. Signer events.
    wr.heading("Signer events");
    if input.recipients.is_empty() {
        wr.para(MARGIN, cw, &Value::plain("No signers."), GREY);
    }
    for r in &input.recipients {
        recipient(&mut wr, r, o);
    }

    // 4. Consent.
    wr.heading("Electronic record and signature disclosure");
    if let Some(d) = &input.disclosure {
        let dh = Hash256::digest(d.text.as_bytes());
        wr.rows(&[
            ("Disclosure version".into(), Value::plain(d.version.clone())),
            ("Disclosure SHA-256".into(), Value::hash(hash_text(&dh))),
        ]);
    }
    let consents: Vec<_> = input
        .recipients
        .iter()
        .filter(|r| r.consent.is_some())
        .collect();
    if consents.is_empty() {
        wr.para(
            MARGIN,
            cw,
            &Value::plain("No recipient was asked to consent."),
            GREY,
        );
    }
    for r in consents {
        if let Some(c) = &r.consent {
            let v = Value::plain(format!(
                "Accepted version {} at {} (disclosure SHA-256 {})",
                c.version,
                datetime(c.accepted, o),
                hash_text(&c.hash)
            ));
            wr.row(MARGIN, cw, &r.party.name, &v);
        }
    }
    if let Some(d) = &input.disclosure {
        match o.disclosure {
            DisclosurePlacement::Inline => {
                wr.y += 4.0;
                wr.para(MARGIN, cw, &Value::plain(d.text.clone()), BLACK);
            }
            _ => wr.para(
                MARGIN,
                cw,
                &Value::plain("The disclosure's full text is in Appendix A."),
                GREY,
            ),
        }
    }

    // 5. Carbon copies and viewers.
    wr.heading("Carbon copies and viewers");
    if input.copies.is_empty() {
        wr.para(MARGIN, cw, &Value::plain("None."), GREY);
    }
    for c in &input.copies {
        let kind = match c.kind {
            CopyKind::Viewer => "Viewer",
            _ => "Carbon copy",
        };
        let v = Value::plain(format!(
            "{} \u{b7} {} \u{b7} delivered {}",
            email(&c.party.email, mask),
            kind,
            maybe(c.delivered, o)
        ));
        wr.row(MARGIN, cw, &c.party.name, &v);
    }

    // 5a. Signer attachments (WEB-06): listed by hash, only when there are any.
    if !input.attachments.is_empty() {
        wr.heading("Signer attachments");
        wr.para(
            MARGIN,
            cw,
            &Value::plain(
                "Files signers attached. Each file's SHA-256 is recorded in its recipient.field_completed event; the files are kept with the envelope.",
            ),
            GREY,
        );
        for a in &input.attachments {
            wr.row(
                MARGIN,
                cw,
                &a.recipient,
                &Value::plain(format!(
                    "{} \u{b7} {} \u{b7} {} bytes",
                    a.field, a.media_type, a.bytes
                )),
            );
            wr.row(MARGIN, cw, "SHA-256", &Value::hash(hash_text(&a.sha256)));
        }
    }

    // 6. Seal.
    wr.heading("Seal");
    match &input.seal {
        SealInfo::Applied {
            subject,
            issuer,
            fingerprint,
            tsa,
            time,
        } => wr.rows(&[
            ("Profile".into(), Value::plain(e.seal_profile.clone())),
            ("Certificate subject".into(), Value::plain(subject.clone())),
            ("Issuer".into(), Value::plain(issuer.clone())),
            (
                "Fingerprint (SHA-256)".into(),
                Value::hash(hash_text(fingerprint)),
            ),
            (
                "Timestamp authority".into(),
                Value::plain(tsa.clone().unwrap_or_else(|| "\u{2014}".into())),
            ),
            ("Timestamp".into(), Value::plain(maybe(*time, o))),
        ]),
        _ => {
            wr.rows(&[("Profile".into(), Value::plain(e.seal_profile.clone()))]);
            wr.para(
                MARGIN,
                cw,
                &Value::plain(
                    "The seal is applied after this certificate is made. It is a PAdES digital signature over the whole file: every page of the document, this certificate and the attached audit trail. Its certificate, timestamp and validation data are in the document's signature panel.",
                ),
                BLACK,
            );
        }
    }

    // 7. How to verify.
    wr.heading("How to verify");
    let mut how = String::from(
        "1. Open the document in a PDF reader and check that its digital signature is valid and covers the whole file.\n2. Extract the attached audit-trail.json. For each event, compute SHA-256 over its RFC 8785 canonical JSON without the \"hash\" member; it must equal \"hash\". Each event's \"prev\" must equal the hash of the event before it, \"seq\" must run 0, 1, 2, ... without gaps, and the last event's hash must equal the audit chain head printed above.\n3. Check that each document's SHA-256 as delivered matches its document.fixed event, and each signer's events match section 3.",
    );
    match &input.verify_url {
        Some(u) => how.push_str(&format!(
            "\nVerify online at {u}, or offline with the OpenSeal verifier."
        )),
        None => how.push_str("\nThe OpenSeal verifier performs these checks offline."),
    }
    wr.para(MARGIN, cw, &Value::plain(how), BLACK);
    wr.y += 4.0;
    wr.rows(&[
        (
            "Attached file".into(),
            Value::plain(format!("audit-trail.json, {} events", chain.len())),
        ),
        (
            "Attached file SHA-256".into(),
            Value::hash(hash_text(trail_sha256)),
        ),
        ("Audit chain head".into(), Value::hash(head)),
    ]);

    // Appendix A.
    if let (Some(d), DisclosurePlacement::Appendix) = (&input.disclosure, o.disclosure) {
        wr.new_page();
        wr.heading(&format!(
            "Appendix A \u{b7} Disclosure, version {}",
            d.version
        ));
        wr.para(MARGIN, cw, &Value::plain(d.text.clone()), BLACK);
    }

    let generated = datetime(input.generated, o);
    Plan {
        width: w,
        height: h,
        pages: wr.finish(&e.id, &generated),
    }
}

/// The location row (GEO-01): place, coordinates, then how it was obtained, e.g.
/// `London, England, GB · 51.5074, -0.1278 · device (±14 m)` or
/// `Paris, FR · 48.8566, 2.3522 · declined — approximate from IP (database …)`.
pub(crate) fn location_text(l: Option<&Location>) -> String {
    let Some(l) = l else {
        return "\u{2014}".to_owned();
    };
    let mut parts: Vec<String> = Vec::new();
    let place: Vec<&str> = [l.city(), l.region(), l.country()]
        .into_iter()
        .flatten()
        .collect();
    if !place.is_empty() {
        parts.push(place.join(", "));
    }
    if let Some(c) = l.coordinates() {
        // `Display` of a double never uses an exponent, and gives the shortest text that
        // reads back as the recorded value.
        parts.push(format!("{}, {}", c.latitude(), c.longitude()));
    }
    let located = !parts.is_empty();
    parts.push(match l.source() {
        LocationSource::Device { accuracy_m } => format!("device (\u{b1}{accuracy_m} m)"),
        LocationSource::Ip { reason, database } => {
            let why = match reason {
                FallbackReason::Declined => "declined \u{2014} ",
                FallbackReason::Unavailable => "device location unavailable \u{2014} ",
                _ => "",
            };
            let how = match (located, database) {
                (true, Some(d)) => format!("approximate from IP (database {d})"),
                (_, Some(d)) => format!("IP address not located (database {d})"),
                (_, None) => "IP address not located".to_owned(),
            };
            format!("{why}{how}")
        }
    });
    parts.join(" \u{b7} ")
}

fn mark_caption(label: &str, m: Option<&Mark>) -> String {
    match m {
        Some(m) => format!("{label} \u{b7} {}", adoption(m.method)),
        None => format!("{label} \u{b7} none adopted"),
    }
}

fn recipient(wr: &mut Writer, r: &crate::input::RecipientRow, o: &CertificateOptions) {
    let cw = wr.content_w();
    let right_w = SIG_W;
    let left_w = cw - right_w - 12.0;
    let mask = o.email_mask;
    let auth = if r.auth.is_empty() {
        "\u{2014}".to_owned()
    } else {
        r.auth
            .iter()
            .map(|a| {
                let when =
                    a.at.map(|t| format!(" {}", datetime(t, o)))
                        .unwrap_or_default();
                format!(
                    "{}: {}{when}",
                    auth_name(a.method),
                    if a.passed { "passed" } else { "failed" }
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    };
    let (outcome_label, outcome) = match &r.outcome {
        Outcome::Signed(t) => ("Signed", datetime(*t, o)),
        Outcome::Approved(t) => ("Approved", datetime(*t, o)),
        Outcome::Declined { at, reason } => (
            "Declined",
            match reason {
                Some(why) => format!("{} \u{b7} reason: {why}", datetime(*at, o)),
                None => datetime(*at, o),
            },
        ),
        _ => ("Status", "Pending".to_owned()),
    };
    let consent = match &r.consent {
        Some(c) => format!("Version {} accepted {}", c.version, datetime(c.accepted, o)),
        None => "\u{2014}".to_owned(),
    };
    let rows: Vec<(String, Value)> = vec![
        ("Email".into(), Value::plain(email(&r.party.email, mask))),
        (
            "Role".into(),
            Value::plain(format!(
                "{} \u{b7} routing order {}",
                role(r.role),
                r.routing_order
            )),
        ),
        ("Authentication".into(), Value::plain(auth)),
        (
            "IP address".into(),
            Value::plain(r.ip.clone().unwrap_or_else(|| "\u{2014}".into())),
        ),
        (
            "User agent".into(),
            Value::plain(r.user_agent.clone().unwrap_or_else(|| "\u{2014}".into())),
        ),
        (
            "Location".into(),
            Value::plain(location_text(r.location.as_ref())),
        ),
        ("Sent".into(), Value::plain(maybe(r.sent, o))),
        ("Viewed".into(), Value::plain(maybe(r.viewed, o))),
        (outcome_label.into(), Value::plain(outcome)),
        ("Consent".into(), Value::plain(consent)),
    ];
    let header_h = line_h(10.0) + 2.0;
    let rows_h: f64 = rows
        .iter()
        .map(|(l, v)| Writer::row_height(l, v, left_w))
        .sum();
    let cap = line_h(LABEL);
    let right_h = SIG_H + cap + 4.0 + INI_H + cap;
    let block = header_h + rows_h.max(right_h) + 10.0;
    let page_h = wr.bottom() - TOP;
    wr.ensure(if block <= page_h {
        block
    } else {
        header_h + right_h
    });

    // Header: order and name, role on the right.
    wr.run(
        MARGIN,
        cw * 0.75,
        format!("{}. {}", r.routing_order, r.party.name),
        10.0,
        Face::Sans,
        BLACK,
        Align::Left,
    );
    wr.run(
        MARGIN + cw * 0.75,
        cw * 0.25,
        role(r.role).to_owned(),
        LABEL,
        Face::Sans,
        GREY,
        Align::Right,
    );
    wr.y += header_h;
    let top = wr.y;
    let page = wr.index();

    // Right column: signature and initials boxes, each with its caption.
    let sx = MARGIN + cw - right_w;
    wr.frame(sx, top, SIG_W, SIG_H);
    if let Some(m) = &r.signature {
        wr.cur.pictures.push(Picture {
            x: sx + 4.0,
            top: top + 3.0,
            w: SIG_W - 8.0,
            h: SIG_H - 6.0,
            art: m.art.clone(),
        });
    }
    wr.y = top + SIG_H + 1.0;
    wr.run(
        sx,
        SIG_W,
        mark_caption("Signature", r.signature.as_ref()),
        LABEL,
        Face::Sans,
        GREY,
        Align::Left,
    );
    let itop = top + SIG_H + cap + 4.0;
    wr.frame(sx, itop, INI_W, INI_H);
    if let Some(m) = &r.initials {
        wr.cur.pictures.push(Picture {
            x: sx + 3.0,
            top: itop + 3.0,
            w: INI_W - 6.0,
            h: INI_H - 6.0,
            art: m.art.clone(),
        });
    }
    wr.y = itop + INI_H + 1.0;
    wr.run(
        sx,
        SIG_W,
        mark_caption("Initials", r.initials.as_ref()),
        LABEL,
        Face::Sans,
        GREY,
        Align::Left,
    );

    // Left column: the rows.
    wr.y = top;
    for (label, v) in &rows {
        wr.row(MARGIN, left_w, label, v);
    }
    if wr.index() == page {
        wr.y = wr.y.max(top + right_h);
    }
    wr.y += 4.0;
    let y = wr.y;
    wr.rule(MARGIN, MARGIN + cw, y, RULE, 0.4);
    wr.y += 6.0;
}

// Tests may unwrap, index and panic (CLAUDE.md).
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn location_rows_say_where_and_how() {
        use casual_sign_audit::{FallbackReason, Location};
        let db = "GeoLite2-City 2026-11-04";
        assert_eq!(location_text(None), "\u{2014}");
        let device = Location::device(51.507_412, -0.127_758, 13.2)
            .unwrap()
            .with_place(Some("GB"), Some("England"), Some("London"))
            .unwrap();
        assert_eq!(
            location_text(Some(&device)),
            "London, England, GB \u{b7} 51.5074, -0.1278 \u{b7} device (\u{b1}14 m)"
        );
        let declined = Location::ip(FallbackReason::Declined, db, 48.8566, 2.3522)
            .unwrap()
            .with_place(Some("FR"), None, Some("Paris"))
            .unwrap();
        assert_eq!(
            location_text(Some(&declined)),
            "Paris, FR \u{b7} 48.8566, 2.3522 \u{b7} declined \u{2014} approximate from IP (database GeoLite2-City 2026-11-04)"
        );
        let unavailable = Location::ip(FallbackReason::Unavailable, db, -33.87, 151.21).unwrap();
        assert_eq!(
            location_text(Some(&unavailable)),
            "-33.87, 151.21 \u{b7} device location unavailable \u{2014} approximate from IP (database GeoLite2-City 2026-11-04)"
        );
        let not_requested = Location::ip(FallbackReason::NotRequested, db, 1e-4, -1e-4).unwrap();
        assert_eq!(
            location_text(Some(&not_requested)),
            "0.0001, -0.0001 \u{b7} approximate from IP (database GeoLite2-City 2026-11-04)"
        );
        let unresolved = Location::ip_unresolved(FallbackReason::Declined, None).unwrap();
        assert_eq!(
            location_text(Some(&unresolved)),
            "declined \u{2014} IP address not located"
        );
        let missed = Location::ip_unresolved(FallbackReason::Unavailable, Some(db)).unwrap();
        assert_eq!(
            location_text(Some(&missed)),
            "device location unavailable \u{2014} IP address not located (database GeoLite2-City 2026-11-04)"
        );
    }

    #[test]
    fn numbers_in_operators_have_no_exponent() {
        assert_eq!(n(0.0), "0");
        assert_eq!(n(1.5), "1.5");
        assert_eq!(n(595.28), "595.28");
        assert_eq!(n(1e-9), "0");
        assert_eq!(n(-0.001), "0");
        assert_eq!(n(12.0), "12");
    }
}
