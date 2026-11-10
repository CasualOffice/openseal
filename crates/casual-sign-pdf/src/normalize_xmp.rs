//! The document metadata check of normalization (`NORM-03`, docs/30 §3).
//!
//! The catalog's `/Metadata` must be an XMP packet (ISO 16684-1): well-formed XML whose
//! root element is `x:xmpmeta` in the `adobe:ns:meta/` namespace. Validators read it
//! whenever a later revision touches the catalog (pyHanko's metadata rule refuses any
//! other stream, so a B-LT or B-LTA seal's DSS update would be called a suspicious
//! change). XMP allows `rdf:RDF` as the outermost element; such a packet is wrapped in
//! `x:xmpmeta` here. Anything else is dropped by the caller.
//!
//! The check is a bounded, non-recursive well-formedness scan: valid UTF-8 of XML
//! characters, one root element, matched tags, attributes quoted and not repeated,
//! only the five predefined entities and character references, no document type
//! declaration (a DOCTYPE may declare entities, which validators refuse in XMP),
//! namespace prefixes declared. It never builds a tree and never resolves anything.

use std::collections::BTreeSet;

/// Largest decoded metadata stream examined (docs/21, `NORM-03`): a larger one is
/// dropped. XMP packets are kilobytes; Adobe pads them to a few.
pub(crate) const MAX_XMP_BYTES: usize = 4 * 1024 * 1024;

/// Deepest element nesting accepted (docs/21, `NORM-03`). XMP is a handful deep.
pub(crate) const MAX_XMP_DEPTH: usize = 256;

/// Most attributes on one element (docs/21, `NORM-03`).
pub(crate) const MAX_XMP_ATTRIBUTES: usize = 1_024;

const XMP_NS: &[u8] = b"adobe:ns:meta/";
const RDF_NS: &[u8] = b"http://www.w3.org/1999/02/22-rdf-syntax-ns#";

/// What the metadata is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Xmp {
    /// An XMP packet as validators expect it: root `x:xmpmeta`.
    Packet,
    /// Well-formed XML whose root is `rdf:RDF`, spanning `start..end` of the data with
    /// any byte order mark removed.
    RdfRoot { start: usize, end: usize },
}

/// Why metadata is not usable as it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum MetadataProblem {
    /// `/Metadata` is not a reference to a stream (validators require one).
    NotStream,
    /// The stream could not be decoded within its limits.
    Unreadable,
    /// The decoded stream is over 4 MiB (docs/21).
    TooLarge,
    /// Not well-formed XML (or nested deeper than docs/21 allows).
    NotXml,
    /// A document type declaration, which may declare entities.
    Doctype,
    /// Well-formed XML whose root is neither `x:xmpmeta` nor `rdf:RDF`.
    NotXmp,
}

/// The data without a UTF-8 byte order mark.
pub(crate) fn without_bom(data: &[u8]) -> &[u8] {
    data.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(data)
}

/// Check `data` (a decoded metadata stream).
pub(crate) fn check(data: &[u8]) -> Result<Xmp, MetadataProblem> {
    if data.len() > MAX_XMP_BYTES {
        return Err(MetadataProblem::TooLarge);
    }
    let b = without_bom(data);
    let s = core::str::from_utf8(b).map_err(|_| MetadataProblem::NotXml)?;
    if !s.chars().all(is_xml_char) {
        return Err(MetadataProblem::NotXml);
    }
    let mut p = Scan { b, pos: 0 };
    p.prolog()?;
    let start = p.pos;
    let root = p.element()?;
    let end = p.pos;
    p.misc_to_end()?;
    match (root.0.as_slice(), root.1.as_slice()) {
        (XMP_NS, b"xmpmeta") => Ok(Xmp::Packet),
        (RDF_NS, b"RDF") => Ok(Xmp::RdfRoot { start, end }),
        _ => Err(MetadataProblem::NotXmp),
    }
}

/// An XMP packet holding the `rdf:RDF` element `rdf`.
pub(crate) fn wrap(rdf: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(rdf.len().saturating_add(160));
    out.extend_from_slice(
        "<?xpacket begin=\"\u{feff}\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?>\n".as_bytes(),
    );
    out.extend_from_slice(b"<x:xmpmeta xmlns:x=\"adobe:ns:meta/\">\n");
    out.extend_from_slice(rdf);
    out.extend_from_slice(b"\n</x:xmpmeta>\n<?xpacket end=\"r\"?>");
    out
}

fn is_xml_char(c: char) -> bool {
    matches!(c, '\t' | '\n' | '\r' | '\u{20}'..='\u{D7FF}' | '\u{E000}'..='\u{FFFD}' | '\u{10000}'..)
}

fn is_space(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\r' | b'\n')
}

fn is_name_start(c: u8) -> bool {
    c.is_ascii_alphabetic() || c == b'_' || c == b':' || c >= 0x80
}

fn is_name(c: u8) -> bool {
    is_name_start(c) || c.is_ascii_digit() || c == b'-' || c == b'.'
}

/// A namespace in scope: (prefix, URI); the default namespace has an empty prefix.
type Binding<'a> = (&'a [u8], &'a [u8]);

/// An open element: its qualified name and the namespace bindings before it.
struct Open<'a> {
    name: &'a [u8],
    scope: usize,
}

struct Scan<'a> {
    b: &'a [u8],
    pos: usize,
}

type R<T> = Result<T, MetadataProblem>;

const BAD: MetadataProblem = MetadataProblem::NotXml;

impl<'a> Scan<'a> {
    fn rest(&self) -> &'a [u8] {
        self.b.get(self.pos..).unwrap_or(&[])
    }

    fn at(&self, lit: &[u8]) -> bool {
        self.rest().starts_with(lit)
    }

    fn peek(&self) -> Option<u8> {
        self.b.get(self.pos).copied()
    }

    fn bump(&mut self, n: usize) {
        self.pos = self.pos.saturating_add(n).min(self.b.len());
    }

    fn skip_space(&mut self) -> bool {
        let start = self.pos;
        while self.peek().is_some_and(is_space) {
            self.bump(1);
        }
        self.pos != start
    }

    /// Advance past the first `lit` at or after the cursor.
    fn past(&mut self, lit: &[u8]) -> R<&'a [u8]> {
        let rest = self.rest();
        let i = rest.windows(lit.len()).position(|w| w == lit).ok_or(BAD)?;
        let body = rest.get(..i).ok_or(BAD)?;
        self.bump(i.saturating_add(lit.len()));
        Ok(body)
    }

    fn name(&mut self) -> R<&'a [u8]> {
        let start = self.pos;
        if !self.peek().is_some_and(is_name_start) {
            return Err(BAD);
        }
        while self.peek().is_some_and(is_name) {
            self.bump(1);
        }
        let n = self.b.get(start..self.pos).ok_or(BAD)?;
        // A qualified name: at most one colon, not first or last.
        let colons = n.iter().filter(|&&c| c == b':').count();
        if colons > 1 || n.first() == Some(&b':') || n.last() == Some(&b':') {
            return Err(BAD);
        }
        Ok(n)
    }

    /// `<!-- … -->`, the cursor after `<!--`: no `--` inside.
    fn comment(&mut self) -> R<()> {
        self.past(b"--")?;
        if self.peek() == Some(b'>') {
            self.bump(1);
            Ok(())
        } else {
            Err(BAD)
        }
    }

    /// `<?target … ?>`, the cursor after `<?`. The target `xml` is the declaration's only.
    fn pi(&mut self) -> R<()> {
        let target = self.name()?;
        if target.eq_ignore_ascii_case(b"xml") {
            return Err(BAD);
        }
        if self.at(b"?>") {
            self.bump(2);
            return Ok(());
        }
        if !self.skip_space() {
            return Err(BAD);
        }
        self.past(b"?>").map(|_| ())
    }

    /// Comments, processing instructions and white space; a DOCTYPE is refused.
    fn misc(&mut self) -> R<()> {
        loop {
            self.skip_space();
            if self.at(b"<!--") {
                self.bump(4);
                self.comment()?;
            } else if self.at(b"<!DOCTYPE") {
                return Err(MetadataProblem::Doctype);
            } else if self.at(b"<?") {
                self.bump(2);
                self.pi()?;
            } else {
                return Ok(());
            }
        }
    }

    fn prolog(&mut self) -> R<()> {
        if self.at(b"<?xml") && self.b.get(5).copied().is_some_and(is_space) {
            self.bump(5);
            self.past(b"?>")?;
        }
        self.misc()?;
        if self.peek() == Some(b'<') {
            Ok(())
        } else {
            Err(BAD)
        }
    }

    fn misc_to_end(&mut self) -> R<()> {
        self.misc()?;
        if self.pos == self.b.len() {
            Ok(())
        } else {
            Err(BAD)
        }
    }

    /// `&…;`, the cursor on `&`.
    fn reference(&mut self) -> R<()> {
        self.bump(1);
        let body = self.past(b";")?;
        if body.len() > 10 {
            return Err(BAD);
        }
        let value = if let Some(hex) = body.strip_prefix(b"#x") {
            parse_num(hex, 16)
        } else if let Some(dec) = body.strip_prefix(b"#") {
            parse_num(dec, 10)
        } else if matches!(body, b"lt" | b"gt" | b"amp" | b"apos" | b"quot") {
            return Ok(());
        } else {
            None
        };
        match value.and_then(char::from_u32) {
            Some(c) if is_xml_char(c) => Ok(()),
            _ => Err(BAD),
        }
    }

    /// An attribute value, the cursor on its quote.
    fn attr_value(&mut self) -> R<&'a [u8]> {
        let q = self.peek().ok_or(BAD)?;
        if q != b'"' && q != b'\'' {
            return Err(BAD);
        }
        self.bump(1);
        let start = self.pos;
        loop {
            match self.peek() {
                None | Some(b'<') => return Err(BAD),
                Some(c) if c == q => break,
                Some(b'&') => self.reference()?,
                Some(_) => self.bump(1),
            }
        }
        let v = self.b.get(start..self.pos).ok_or(BAD)?;
        self.bump(1);
        Ok(v)
    }

    /// A start tag, the cursor after `<`: (name, attributes, empty-element).
    #[allow(clippy::type_complexity)] // A private helper's one return.
    fn start_tag(&mut self) -> R<(&'a [u8], Vec<(&'a [u8], &'a [u8])>, bool)> {
        let name = self.name()?;
        let mut attrs: Vec<(&'a [u8], &'a [u8])> = Vec::new();
        let mut seen: BTreeSet<&'a [u8]> = BTreeSet::new();
        loop {
            let spaced = self.skip_space();
            if self.at(b"/>") {
                self.bump(2);
                return Ok((name, attrs, true));
            }
            if self.at(b">") {
                self.bump(1);
                return Ok((name, attrs, false));
            }
            if !spaced || attrs.len() >= MAX_XMP_ATTRIBUTES {
                return Err(BAD);
            }
            let an = self.name()?;
            if !seen.insert(an) {
                return Err(BAD);
            }
            self.skip_space();
            if self.peek() != Some(b'=') {
                return Err(BAD);
            }
            self.bump(1);
            self.skip_space();
            let v = self.attr_value()?;
            attrs.push((an, v));
        }
    }

    /// The root element and everything in it, the cursor on its `<`; the root's
    /// (namespace, local name).
    fn element(&mut self) -> R<(Vec<u8>, Vec<u8>)> {
        let mut ns: Vec<Binding<'a>> = Vec::new();
        let mut open: Vec<Open<'a>> = Vec::new();
        let mut root: Option<(Vec<u8>, Vec<u8>)> = None;
        loop {
            if open.is_empty() && root.is_some() {
                break;
            }
            if self.at(b"</") {
                self.bump(2);
                let name = self.name()?;
                self.skip_space();
                if self.peek() != Some(b'>') {
                    return Err(BAD);
                }
                self.bump(1);
                let top = open.pop().ok_or(BAD)?;
                if top.name != name {
                    return Err(BAD);
                }
                ns.truncate(top.scope);
            } else if self.at(b"<!--") {
                self.bump(4);
                self.comment()?;
            } else if self.at(b"<![CDATA[") {
                if open.is_empty() {
                    return Err(BAD);
                }
                self.bump(9);
                self.past(b"]]>")?;
            } else if self.at(b"<?") {
                self.bump(2);
                self.pi()?;
            } else if self.at(b"<!") {
                return Err(BAD);
            } else if self.at(b"<") {
                self.bump(1);
                let scope = ns.len();
                let (name, attrs, empty) = self.start_tag()?;
                for (an, v) in &attrs {
                    if *an == b"xmlns" {
                        ns.push((b"", v));
                    } else if let Some(p) = an.strip_prefix(b"xmlns:") {
                        ns.push((p, v));
                    }
                }
                let resolve = |prefix: &[u8]| -> Option<&'a [u8]> {
                    ns.iter().rev().find(|(p, _)| *p == prefix).map(|(_, u)| *u)
                };
                for (an, _) in &attrs {
                    if let Some((p, _)) = split(an)
                        && p != b"xmlns"
                        && p != b"xml"
                        && resolve(p).is_none()
                    {
                        return Err(BAD);
                    }
                }
                let (uri, local) = match split(name) {
                    Some((b"xml", l)) => (&b"http://www.w3.org/XML/1998/namespace"[..], l),
                    Some((p, l)) => (resolve(p).ok_or(BAD)?, l),
                    None => (resolve(b"").unwrap_or(b""), name),
                };
                if root.is_none() {
                    root = Some((uri.to_vec(), local.to_vec()));
                }
                if empty {
                    ns.truncate(scope);
                } else {
                    if open.len() >= MAX_XMP_DEPTH {
                        return Err(BAD);
                    }
                    open.push(Open { name, scope });
                }
            } else if open.is_empty() {
                return Err(BAD);
            } else if self.peek() == Some(b'&') {
                self.reference()?;
            } else if self.at(b"]]>") {
                return Err(BAD);
            } else if self.peek().is_some() {
                self.bump(1);
                while self
                    .peek()
                    .is_some_and(|c| c != b'<' && c != b'&' && c != b']')
                {
                    self.bump(1);
                }
            } else {
                return Err(BAD);
            }
        }
        root.ok_or(BAD)
    }
}

/// `prefix:local` of a qualified name.
fn split(name: &[u8]) -> Option<(&[u8], &[u8])> {
    let i = name.iter().position(|&c| c == b':')?;
    Some((name.get(..i)?, name.get(i.checked_add(1)?..)?))
}

fn parse_num(digits: &[u8], radix: u32) -> Option<u32> {
    if digits.is_empty() {
        return None;
    }
    let s = core::str::from_utf8(digits).ok()?;
    u32::from_str_radix(s, radix).ok()
}

#[cfg(test)]
mod tests {
    // Test code: a panic is the failure report.
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
    use super::*;

    const PACKET: &str = "<?xpacket begin=\"\u{feff}\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?>\n\
<x:xmpmeta xmlns:x=\"adobe:ns:meta/\"><rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\">\
<rdf:Description rdf:about=\"\" xmlns:dc=\"http://purl.org/dc/elements/1.1/\"><dc:format>application/pdf</dc:format>\
</rdf:Description></rdf:RDF></x:xmpmeta>\n<?xpacket end=\"w\"?>";

    const RDF: &str = "<?xpacket begin='' id='W5M0MpCehiHzreSzNTczkc9d'?>\
<rdf:RDF xmlns:rdf='http://www.w3.org/1999/02/22-rdf-syntax-ns#'>\
<rdf:Description about='' xmlns:pdf='http://ns.adobe.com/pdf/1.3/' pdf:Producer='A &amp; B &#x41;'/>\
</rdf:RDF><?xpacket end='r'?>";

    #[test]
    fn a_packet_is_xmp() {
        assert_eq!(check(PACKET.as_bytes()), Ok(Xmp::Packet));
        let mut bom = b"\xEF\xBB\xBF".to_vec();
        bom.extend_from_slice(PACKET.as_bytes());
        assert_eq!(check(&bom), Ok(Xmp::Packet));
    }

    #[test]
    fn an_rdf_root_is_found_and_wrapped_into_a_packet() {
        let Ok(Xmp::RdfRoot { start, end }) = check(RDF.as_bytes()) else {
            panic!("not found as rdf root");
        };
        let rdf = &RDF.as_bytes()[start..end];
        assert!(rdf.starts_with(b"<rdf:RDF") && rdf.ends_with(b"</rdf:RDF>"));
        assert_eq!(check(&wrap(rdf)), Ok(Xmp::Packet));
    }

    #[test]
    fn what_is_not_well_formed_is_refused() {
        for bad in [
            &b""[..],
            b"not xml",
            b"<a>",
            b"<a></b>",
            b"<a/><b/>",
            b"<a x='1' x='2'/>",
            b"<a x='1'y='2'/>",
            b"<a>&nbsp;</a>",
            b"<a>&#0;</a>",
            b"<a>x\x00</a>",
            b"<a><!-- a -- b --></a>",
            b"<p:a/>",
            b"<a p:x='1'/>",
            b"<a>]]></a>",
            b"\xFF<a/>",
            b"<a x='<'/>",
            b"<?xml version='1.0'?><?xml version='1.0'?><a/>",
            b"text<a/>",
            b"<a/>text",
        ] {
            assert_eq!(
                check(bad),
                Err(MetadataProblem::NotXml),
                "{}",
                String::from_utf8_lossy(bad)
            );
        }
        assert_eq!(
            check(b"<!DOCTYPE a [<!ENTITY e 'x'>]><a>&e;</a>"),
            Err(MetadataProblem::Doctype)
        );
        assert_eq!(check(b"<a xmlns='urn:x'/>"), Err(MetadataProblem::NotXmp));
        assert_eq!(
            check(b"<x:xapmeta xmlns:x='adobe:ns:meta/'/>"),
            Err(MetadataProblem::NotXmp)
        );
    }

    #[test]
    fn depth_and_size_are_bounded() {
        let deep = "<a>".repeat(MAX_XMP_DEPTH + 1);
        assert_eq!(check(deep.as_bytes()), Err(MetadataProblem::NotXml));
        let big = vec![b' '; MAX_XMP_BYTES + 1];
        assert_eq!(check(&big), Err(MetadataProblem::TooLarge));
        let mut ok = String::from("<x:xmpmeta xmlns:x='adobe:ns:meta/'>");
        ok.push_str(&"<a>".repeat(MAX_XMP_DEPTH - 1));
        ok.push_str(&"</a>".repeat(MAX_XMP_DEPTH - 1));
        ok.push_str("</x:xmpmeta>");
        assert_eq!(check(ok.as_bytes()), Ok(Xmp::Packet));
    }

    #[test]
    fn attributes_per_element_are_bounded() {
        let element = |n: usize| {
            let mut x = String::from("<x:xmpmeta xmlns:x='adobe:ns:meta/'");
            for i in 1..n {
                x.push_str(&format!(" a{i}='v'"));
            }
            x.push_str("/>");
            x
        };
        assert_eq!(
            check(element(MAX_XMP_ATTRIBUTES).as_bytes()),
            Ok(Xmp::Packet)
        );
        assert_eq!(
            check(element(MAX_XMP_ATTRIBUTES + 1).as_bytes()),
            Err(MetadataProblem::NotXml)
        );
    }

    #[test]
    fn cdata_comments_and_pis_inside_are_fine() {
        let s = "<x:xmpmeta xmlns:x='adobe:ns:meta/'><!-- c --><?pi data?><![CDATA[ <&> ]]>t &lt;</x:xmpmeta>";
        assert_eq!(check(s.as_bytes()), Ok(Xmp::Packet));
    }
}
