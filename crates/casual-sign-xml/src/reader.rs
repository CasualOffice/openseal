//! The reader: one pass over the text, iterative, every limit checked as it is crossed.

use crate::error::XmlError;

/// An index into [`Dom::nodes`].
pub type NodeId = usize;

/// The namespace the `xml` prefix is bound to by definition (Namespaces in XML §3).
pub const XML_NAMESPACE: &str = "http://www.w3.org/XML/1998/namespace";

/// One attribute with its qualified name, as canonicalization needs it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Attribute {
    /// The prefix, empty for none.
    pub prefix: String,
    /// The local name.
    pub local: String,
    /// The value, references resolved (and, strict, white space normalized).
    pub value: String,
}

/// One element or text node.
#[derive(Debug, Clone, Default)]
pub struct Node {
    /// Local name; empty for a text node.
    pub name: String,
    /// The element's prefix, empty for none.
    pub prefix: String,
    /// Attributes by local name, in document order; namespace declarations excluded.
    pub attrs: Vec<(String, String)>,
    /// The same attributes with their prefixes, in document order.
    pub attributes: Vec<Attribute>,
    /// The namespace declarations made on this element, in document order: the prefix
    /// (empty for the default namespace) and the URI (empty to undeclare the default).
    pub namespaces: Vec<(String, String)>,
    /// Children, elements and text, in document order.
    pub children: Vec<NodeId>,
    /// The text of a text node.
    pub text: String,
    /// The parent element; `None` only for the document node.
    pub parent: Option<NodeId>,
}

impl Node {
    /// Whether this is a text node.
    #[must_use]
    pub fn is_text(&self) -> bool {
        self.name.is_empty() && self.parent.is_some()
    }
}

/// A parsed document: node 0 is a synthetic document node whose children are the
/// top-level elements (exactly one).
#[derive(Debug, Clone, Default)]
pub struct Dom {
    /// Every node; node 0 is the document.
    pub nodes: Vec<Node>,
}

/// Limits the reader holds (docs/21).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Largest input, in bytes (`CS-XML-0001`).
    pub max_bytes: usize,
    /// Deepest element nesting (`CS-XML-0002`).
    pub max_depth: usize,
    /// Most nodes, elements and text (`CS-XML-0003`).
    pub max_nodes: usize,
    /// Most elements (`CS-XML-0003`).
    pub max_elements: usize,
    /// Most attributes on one element, namespace declarations included (`CS-XML-0003`).
    pub max_attributes: usize,
    /// The mode for signed XML (see the crate documentation).
    pub strict: bool,
}

impl Limits {
    /// The XFA reader's mode: lenient, sized by the caller.
    #[must_use]
    pub const fn lenient(max_depth: usize, max_nodes: usize, max_attributes: usize) -> Self {
        Self {
            max_bytes: usize::MAX,
            max_depth,
            max_nodes,
            max_elements: max_nodes,
            max_attributes,
            strict: false,
        }
    }

    /// An India eSign answer (ADR-047 §3.5, docs/21 §eSign): 512 KiB, depth 16, 256
    /// elements, 32 attributes on one element, strict.
    #[must_use]
    pub const fn esign() -> Self {
        Self {
            max_bytes: 512 * 1024,
            max_depth: 16,
            max_nodes: 1024,
            max_elements: 256,
            max_attributes: 32,
            strict: true,
        }
    }
}

static EMPTY: Node = Node {
    name: String::new(),
    prefix: String::new(),
    attrs: Vec::new(),
    attributes: Vec::new(),
    namespaces: Vec::new(),
    children: Vec::new(),
    text: String::new(),
    parent: None,
};

impl Dom {
    /// The node, or an empty one for an id out of range.
    #[must_use]
    pub fn node(&self, id: NodeId) -> &Node {
        self.nodes.get(id).unwrap_or(&EMPTY)
    }

    /// The local name.
    #[must_use]
    pub fn name(&self, id: NodeId) -> &str {
        &self.node(id).name
    }

    /// The value of the attribute with local name `name`.
    #[must_use]
    pub fn attr(&self, id: NodeId, name: &str) -> Option<&str> {
        self.node(id)
            .attrs
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    /// Element children, in order.
    pub fn elements(&self, id: NodeId) -> impl Iterator<Item = NodeId> + '_ {
        self.node(id)
            .children
            .iter()
            .copied()
            .filter(|c| !self.node(*c).is_text())
    }

    /// The first element child named `name`.
    #[must_use]
    pub fn child(&self, id: NodeId, name: &str) -> Option<NodeId> {
        self.elements(id).find(|c| self.name(*c) == name)
    }

    /// Every element child named `name`.
    pub fn children_named<'a>(
        &'a self,
        id: NodeId,
        name: &'a str,
    ) -> impl Iterator<Item = NodeId> + 'a {
        self.elements(id).filter(move |c| self.name(*c) == name)
    }

    /// A path of first children: `path(n, &["ui", "textEdit"])`.
    #[must_use]
    pub fn path(&self, id: NodeId, names: &[&str]) -> Option<NodeId> {
        let mut at = id;
        for n in names {
            at = self.child(at, n)?;
        }
        Some(at)
    }

    /// The concatenated text of every text node under `id`, in document order.
    #[must_use]
    pub fn text(&self, id: NodeId) -> String {
        let mut out = String::new();
        let mut stack = vec![id];
        while let Some(n) = stack.pop() {
            let node = self.node(n);
            if node.is_text() {
                out.push_str(&node.text);
            } else {
                stack.extend(node.children.iter().rev().copied());
            }
        }
        out
    }

    /// The first element anywhere under `id` (depth first, document order) named
    /// `name`, `id` itself included.
    #[must_use]
    pub fn find(&self, id: NodeId, name: &str) -> Option<NodeId> {
        let mut stack = vec![id];
        while let Some(n) = stack.pop() {
            let node = self.node(n);
            if !node.is_text() && node.name == name {
                return Some(n);
            }
            stack.extend(node.children.iter().rev().copied());
        }
        None
    }

    /// True when the element has element children (a data group, in the data DOM).
    #[must_use]
    pub fn has_elements(&self, id: NodeId) -> bool {
        self.elements(id).next().is_some()
    }

    /// The root element.
    #[must_use]
    pub fn root(&self) -> Option<NodeId> {
        self.elements(0).next()
    }

    /// The URI `prefix` is bound to at element `id` (empty prefix: the default
    /// namespace; `None` when undeclared or undeclared again with `xmlns=""`).
    #[must_use]
    pub fn namespace(&self, id: NodeId, prefix: &str) -> Option<&str> {
        if prefix == "xml" {
            return Some(XML_NAMESPACE);
        }
        let mut at = Some(id);
        while let Some(n) = at {
            let node = self.node(n);
            if let Some((_, uri)) = node.namespaces.iter().find(|(p, _)| p == prefix) {
                return if uri.is_empty() {
                    None
                } else {
                    Some(uri.as_str())
                };
            }
            at = node.parent;
        }
        None
    }

    /// The namespace URI of element `id`'s name.
    #[must_use]
    pub fn element_namespace(&self, id: NodeId) -> Option<&str> {
        self.namespace(id, &self.node(id).prefix)
    }

    /// Every element under `id` in document order, `id` included.
    #[must_use]
    pub fn descendants(&self, id: NodeId) -> Vec<NodeId> {
        let mut out = Vec::new();
        let mut stack = vec![id];
        while let Some(n) = stack.pop() {
            let node = self.node(n);
            if node.is_text() {
                continue;
            }
            out.push(n);
            stack.extend(node.children.iter().rev().copied());
        }
        out
    }
}

/// Decode the bytes: UTF-8 unless the declaration names a Latin-1 encoding (lenient);
/// strictly UTF-8 with line ends normalized (strict).
fn decode(bytes: &[u8], strict: bool) -> Result<String, XmlError> {
    let head = bytes.get(..bytes.len().min(200)).unwrap_or(bytes);
    let head = String::from_utf8_lossy(head).to_ascii_lowercase();
    let declared = |names: &[&str]| {
        head.starts_with("<?xml")
            && names
                .iter()
                .any(|e| head.split("?>").next().is_some_and(|d| d.contains(e)))
    };
    if strict {
        let text = core::str::from_utf8(bytes).map_err(|_| XmlError::Encoding)?;
        let decl = head.split("?>").next().unwrap_or("");
        if head.starts_with("<?xml")
            && decl.contains("encoding")
            && !declared(&["\"utf-8\"", "'utf-8'"])
        {
            return Err(XmlError::Encoding);
        }
        // XML 1.0 §2.11: CR LF and a lone CR are read as LF.
        return Ok(text.replace("\r\n", "\n").replace('\r', "\n"));
    }
    if declared(&["iso-8859-1", "latin1", "windows-1252", "iso8859-1"]) {
        Ok(bytes.iter().map(|b| char::from(*b)).collect())
    } else {
        Ok(String::from_utf8_lossy(bytes).into_owned())
    }
}

fn is_name_char(c: char) -> bool {
    !(c.is_whitespace() || matches!(c, '<' | '>' | '/' | '=' | '"' | '\'' | '&' | '!' | '?'))
}

/// `(prefix, local)` of a qualified name.
fn split(qname: &str) -> (&str, &str) {
    match qname.rsplit_once(':') {
        Some((p, l)) => (p, l),
        None => ("", qname),
    }
}

/// Whether `c` may appear in a strict document (XML 1.0 §2.2 `Char`).
fn is_xml_char(c: char) -> bool {
    matches!(c, '\t' | '\n' | '\r') || (c >= ' ' && c != '\u{fffe}' && c != '\u{ffff}')
}

/// Resolve the references in `raw` (text or an attribute value).
fn unescape(raw: &str, offset: usize, strict: bool) -> Result<String, XmlError> {
    let bad = XmlError::Malformed { offset };
    if strict && !raw.chars().all(is_xml_char) {
        return Err(bad);
    }
    if !raw.contains('&') {
        return Ok(raw.to_owned());
    }
    let mut out = String::with_capacity(raw.len());
    let mut rest = raw;
    while let Some(i) = rest.find('&') {
        out.push_str(rest.get(..i).ok_or(bad.clone())?);
        let after = rest.get(i.saturating_add(1)..).ok_or(bad.clone())?;
        let end = after.find(';').filter(|e| *e <= 32).ok_or(bad.clone())?;
        let name = after.get(..end).ok_or(bad.clone())?;
        let c = match name {
            "lt" => '<',
            "gt" => '>',
            "amp" => '&',
            "quot" => '"',
            "apos" => '\'',
            _ => {
                let v = if let Some(h) = name.strip_prefix("#x").or(name.strip_prefix("#X")) {
                    u32::from_str_radix(h, 16).ok()
                } else if let Some(d) = name.strip_prefix('#') {
                    d.parse::<u32>().ok()
                } else {
                    None
                };
                v.and_then(char::from_u32)
                    .filter(|c| *c != '\0' && (!strict || is_xml_char(*c)))
                    .ok_or(bad.clone())?
            }
        };
        out.push(c);
        rest = after.get(end.saturating_add(1)..).ok_or(bad.clone())?;
    }
    out.push_str(rest);
    Ok(out)
}

struct Parser<'s> {
    s: &'s str,
    pos: usize,
    dom: Dom,
    stack: Vec<NodeId>,
    limits: Limits,
    roots: usize,
    elements: usize,
    /// Open elements' qualified names, for matching end tags.
    names: Vec<String>,
}

fn ws_len(s: &str) -> usize {
    s.len().saturating_sub(s.trim_start().len())
}

impl Parser<'_> {
    fn rest(&self) -> &str {
        self.s.get(self.pos..).unwrap_or("")
    }

    fn bad(&self) -> XmlError {
        XmlError::Malformed { offset: self.pos }
    }

    fn advance(&mut self, n: usize) {
        self.pos = self.pos.saturating_add(n);
    }

    /// Skip past `end`, or fail.
    fn skip_past(&mut self, end: &str) -> Result<(), XmlError> {
        let i = self.rest().find(end).ok_or(self.bad())?;
        self.advance(i.saturating_add(end.len()));
        Ok(())
    }

    fn push(&mut self, node: Node) -> Result<NodeId, XmlError> {
        if self.dom.nodes.len() >= self.limits.max_nodes {
            return Err(XmlError::TooManyNodes { offset: self.pos });
        }
        let id = self.dom.nodes.len();
        let parent = node.parent;
        self.dom.nodes.push(node);
        if let Some(p) = parent.and_then(|p| self.dom.nodes.get_mut(p)) {
            p.children.push(id);
        }
        Ok(id)
    }

    fn text(&mut self, raw: &str, offset: usize) -> Result<(), XmlError> {
        let Some(&parent) = self.stack.last() else {
            if raw.trim().is_empty() {
                return Ok(());
            }
            return Err(XmlError::Malformed { offset });
        };
        if parent == 0 {
            if raw.trim().is_empty() {
                return Ok(());
            }
            return Err(XmlError::Malformed { offset });
        }
        let text = unescape(raw, offset, self.limits.strict)?;
        self.push(Node {
            text,
            parent: Some(parent),
            ..Node::default()
        })?;
        Ok(())
    }

    /// Whether `prefix` is bound at the element being opened (its own declarations
    /// `own`) or above it.
    fn declared(&self, own: &[(String, String)], parent: NodeId, prefix: &str) -> bool {
        if prefix.is_empty() || prefix == "xml" {
            return true;
        }
        own.iter().any(|(p, u)| p == prefix && !u.is_empty())
            || self.dom.namespace(parent, prefix).is_some()
    }

    // One start tag, read in the order the grammar gives it.
    #[allow(clippy::too_many_lines)]
    fn start_tag(&mut self) -> Result<(), XmlError> {
        let start = self.pos;
        let strict = self.limits.strict;
        self.advance(1);
        let name: String = self
            .rest()
            .chars()
            .take_while(|c| is_name_char(*c))
            .collect();
        if name.is_empty() {
            return Err(self.bad());
        }
        self.advance(name.len());
        let mut attrs: Vec<(String, String)> = Vec::new();
        let mut attributes: Vec<Attribute> = Vec::new();
        let mut namespaces: Vec<(String, String)> = Vec::new();
        let mut seen: Vec<String> = Vec::new();
        let empty = loop {
            let ws = ws_len(self.rest());
            self.advance(ws);
            let rest = self.rest();
            if rest.starts_with("/>") {
                self.advance(2);
                break true;
            }
            if rest.starts_with('>') {
                self.advance(1);
                break false;
            }
            if ws == 0 {
                return Err(self.bad());
            }
            let an: String = rest.chars().take_while(|c| is_name_char(*c)).collect();
            if an.is_empty() {
                return Err(self.bad());
            }
            self.advance(an.len());
            let ws = ws_len(self.rest());
            self.advance(ws);
            if !self.rest().starts_with('=') {
                return Err(self.bad());
            }
            self.advance(1);
            let ws = ws_len(self.rest());
            self.advance(ws);
            let quote = self.rest().chars().next().ok_or(self.bad())?;
            if quote != '"' && quote != '\'' {
                return Err(self.bad());
            }
            self.advance(1);
            let end = self.rest().find(quote).ok_or(self.bad())?;
            let mut raw = self.rest().get(..end).ok_or(self.bad())?.to_owned();
            if raw.contains('<') {
                return Err(self.bad());
            }
            if strict {
                // XML 1.0 §3.3.3: literal white space in a value reads as a space.
                raw = raw.replace(['\t', '\n'], " ");
            }
            let value = unescape(&raw, self.pos, strict)?;
            self.advance(end.saturating_add(1));
            if seen.contains(&an) {
                return Err(XmlError::Malformed { offset: start });
            }
            seen.push(an.clone());
            if seen.len() > self.limits.max_attributes {
                return Err(XmlError::TooManyNodes { offset: start });
            }
            if an == "xmlns" {
                namespaces.push((String::new(), value));
                continue;
            }
            if let Some(p) = an.strip_prefix("xmlns:") {
                if strict && (p.is_empty() || p.contains(':') || value.is_empty()) {
                    return Err(XmlError::Malformed { offset: start });
                }
                namespaces.push((p.to_owned(), value));
                continue;
            }
            let (prefix, local) = split(&an);
            if strict && (local.is_empty() || (an.contains(':') && prefix.is_empty())) {
                return Err(XmlError::Malformed { offset: start });
            }
            attrs.push((local.to_owned(), value.clone()));
            attributes.push(Attribute {
                prefix: prefix.to_owned(),
                local: local.to_owned(),
                value,
            });
        };
        let parent = *self.stack.last().ok_or(self.bad())?;
        if parent == 0 {
            self.roots = self.roots.saturating_add(1);
            if self.roots > 1 {
                return Err(XmlError::Malformed { offset: start });
            }
        }
        // The document node is on the stack too; depth counts elements only.
        if !empty && self.stack.len() > self.limits.max_depth {
            return Err(XmlError::TooDeep { offset: start });
        }
        self.elements = self.elements.saturating_add(1);
        if self.elements > self.limits.max_elements {
            return Err(XmlError::TooManyNodes { offset: start });
        }
        let (prefix, local) = split(&name);
        if strict {
            let undeclared = !self.declared(&namespaces, parent, prefix)
                || attributes
                    .iter()
                    .any(|a| !self.declared(&namespaces, parent, &a.prefix));
            // Two attributes with one expanded name (Namespaces in XML §6.3).
            let mut expanded: Vec<(Option<String>, &str)> = Vec::new();
            for a in &attributes {
                let uri = if a.prefix.is_empty() {
                    None
                } else {
                    namespaces
                        .iter()
                        .find(|(p, _)| *p == a.prefix)
                        .map(|(_, u)| u.clone())
                        .or_else(|| self.dom.namespace(parent, &a.prefix).map(str::to_owned))
                };
                if expanded.iter().any(|(u, l)| *u == uri && *l == a.local) {
                    return Err(XmlError::Malformed { offset: start });
                }
                expanded.push((uri, &a.local));
            }
            if undeclared || local.is_empty() || (name.contains(':') && prefix.is_empty()) {
                return Err(XmlError::Malformed { offset: start });
            }
        }
        let id = self.push(Node {
            name: local.to_owned(),
            prefix: if name.contains(':') {
                prefix.to_owned()
            } else {
                String::new()
            },
            attrs,
            attributes,
            namespaces,
            parent: Some(parent),
            ..Node::default()
        })?;
        if !empty {
            self.stack.push(id);
            self.names.push(name);
        }
        Ok(())
    }
}

/// Parse `bytes` as one XML document within `limits`; `cancel` is polled every few
/// thousand steps.
///
/// # Errors
/// An [`XmlError`] whose code is in docs/20.
pub fn parse(bytes: &[u8], limits: &Limits, cancel: &dyn Fn() -> bool) -> Result<Dom, XmlError> {
    if bytes.len() > limits.max_bytes {
        return Err(XmlError::TooLarge {
            bytes: bytes.len(),
            limit: limits.max_bytes,
        });
    }
    let s = decode(bytes, limits.strict)?;
    let mut p = Parser {
        s: &s,
        pos: 0,
        dom: Dom::default(),
        stack: vec![0],
        limits: *limits,
        roots: 0,
        elements: 0,
        names: Vec::new(),
    };
    p.dom.nodes.push(Node::default());
    // A byte-order mark is not text.
    if p.rest().starts_with('\u{feff}') {
        p.advance('\u{feff}'.len_utf8());
    }
    let first = p.pos;
    let mut steps: u32 = 0;
    while !p.rest().is_empty() {
        steps = steps.wrapping_add(1);
        if steps.is_multiple_of(4096) && cancel() {
            return Err(XmlError::Cancelled);
        }
        let rest = p.rest();
        let Some(lt) = rest.find('<') else {
            let raw = rest.to_owned();
            let at = p.pos;
            p.text(&raw, at)?;
            p.pos = s.len();
            break;
        };
        if lt > 0 {
            let raw = rest.get(..lt).ok_or(p.bad())?.to_owned();
            let at = p.pos;
            p.text(&raw, at)?;
            p.advance(lt);
            continue;
        }
        if rest.starts_with("<!--") {
            p.skip_past("-->")?;
        } else if rest.starts_with("<![CDATA[") {
            let at = p.pos;
            p.advance(9);
            let end = p.rest().find("]]>").ok_or(p.bad())?;
            let raw = p.rest().get(..end).ok_or(p.bad())?.to_owned();
            if p.stack.len() <= 1 || (limits.strict && !raw.chars().all(is_xml_char)) {
                return Err(XmlError::Malformed { offset: at });
            }
            let parent = *p.stack.last().ok_or(p.bad())?;
            p.push(Node {
                text: raw,
                parent: Some(parent),
                ..Node::default()
            })?;
            p.advance(end.saturating_add(3));
        } else if rest.starts_with("<!DOCTYPE") || rest.starts_with("<!ENTITY") {
            return Err(XmlError::Dtd { offset: p.pos });
        } else if rest.starts_with("<!") {
            return Err(p.bad());
        } else if rest.starts_with("<?") {
            // Strict: only the XML declaration, first in the document.
            if limits.strict && !(p.pos == first && rest.starts_with("<?xml ")) {
                return Err(p.bad());
            }
            p.skip_past("?>")?;
        } else if rest.starts_with("</") {
            let at = p.pos;
            p.advance(2);
            let name: String = p.rest().chars().take_while(|c| is_name_char(*c)).collect();
            p.advance(name.len());
            let ws = ws_len(p.rest());
            p.advance(ws);
            if !p.rest().starts_with('>') {
                return Err(p.bad());
            }
            p.advance(1);
            match p.names.pop() {
                Some(open) if open == name => {
                    p.stack.pop();
                }
                _ => return Err(XmlError::Malformed { offset: at }),
            }
        } else {
            p.start_tag()?;
        }
    }
    if p.stack.len() != 1 || p.roots != 1 {
        return Err(XmlError::Malformed { offset: s.len() });
    }
    Ok(p.dom)
}

#[cfg(test)]
mod tests {
    // Test code: a panic is the failure report (CLAUDE.md).
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;

    const LIM: Limits = Limits::lenient(8, 100, 4);

    fn p(s: &str) -> Result<Dom, XmlError> {
        parse(s.as_bytes(), &LIM, &|| false)
    }

    fn strict(s: &str) -> Result<Dom, XmlError> {
        parse(s.as_bytes(), &Limits::esign(), &|| false)
    }

    #[test]
    fn elements_attributes_text_and_references_are_read() {
        let d = p(r#"<?xml version="1.0"?><!-- c --><a:x xmlns:a="u" a:k='v&amp;w'><y>1 &lt; 2 &#x41;&#66;<![CDATA[<raw>]]></y><?pi x?><z/></a:x>"#).unwrap();
        let x = d.elements(0).next().unwrap();
        assert_eq!(d.name(x), "x");
        assert_eq!(d.node(x).prefix, "a");
        assert_eq!(d.attr(x, "k"), Some("v&w"));
        assert_eq!(d.node(x).attrs.len(), 1, "xmlns is dropped");
        assert_eq!(d.node(x).namespaces, vec![("a".into(), "u".into())]);
        assert_eq!(d.node(x).attributes[0].prefix, "a");
        assert_eq!(d.element_namespace(x), Some("u"));
        let y = d.child(x, "y").unwrap();
        assert_eq!(d.text(y), "1 < 2 AB<raw>");
        assert!(d.child(x, "z").is_some());
    }

    #[test]
    fn latin1_declared_input_is_decoded_as_latin1() {
        let d = parse(
            b"<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><a>\xe9</a>",
            &LIM,
            &|| false,
        )
        .unwrap();
        assert_eq!(d.text(0), "\u{e9}");
    }

    #[test]
    fn malformed_input_is_refused_with_its_offset() {
        for bad in [
            "<a>",
            "<a></b>",
            "<a><b></a></b>",
            "<a x=1/>",
            "<a x='1' x='2'/>",
            "<a>&nope;</a>",
            "<a>&#0;</a>",
            "<a>&#xD800;</a>",
            "<a/><b/>",
            "text<a/>",
            "<a><!x></a>",
            "<a x='<'/>",
            "",
        ] {
            assert!(
                matches!(p(bad), Err(XmlError::Malformed { .. })),
                "{bad}: {:?}",
                p(bad).map(|_| ())
            );
        }
    }

    #[test]
    fn doctype_and_entity_declarations_are_refused() {
        assert_eq!(
            p("<!DOCTYPE a [<!ENTITY e SYSTEM \"file:///etc/passwd\">]><a>&e;</a>").unwrap_err(),
            XmlError::Dtd { offset: 0 }
        );
        assert!(matches!(
            p("<a><!ENTITY e \"x\"></a>"),
            Err(XmlError::Dtd { .. })
        ));
        assert!(matches!(
            strict("<?xml version=\"1.0\"?><!DOCTYPE a><a/>"),
            Err(XmlError::Dtd { .. })
        ));
    }

    #[test]
    fn depth_nodes_and_attributes_are_limited() {
        let deep = "<a>".repeat(8) + &"</a>".repeat(8);
        assert!(p(&deep).is_ok());
        let deeper = "<a>".repeat(9) + &"</a>".repeat(9);
        assert!(matches!(p(&deeper), Err(XmlError::TooDeep { .. })));
        let wide = "<a>".to_owned() + &"<b/>".repeat(98) + "</a>";
        assert!(p(&wide).is_ok());
        let wider = "<a>".to_owned() + &"<b/>".repeat(99) + "</a>";
        assert!(matches!(p(&wider), Err(XmlError::TooManyNodes { .. })));
        assert!(p("<a q='1' r='1' s='1' t='1'/>").is_ok());
        assert!(matches!(
            p("<a q='1' r='1' s='1' t='1' u='1'/>"),
            Err(XmlError::TooManyNodes { .. })
        ));
    }

    #[test]
    fn esign_limits_are_512_kib_depth_16_and_256_elements() {
        let l = Limits::esign();
        let deep = "<a>".repeat(16) + &"</a>".repeat(16);
        assert!(strict(&deep).is_ok());
        let deeper = "<a>".repeat(17) + &"</a>".repeat(17);
        assert!(matches!(strict(&deeper), Err(XmlError::TooDeep { .. })));
        let wide = "<a>".to_owned() + &"<b/>".repeat(255) + "</a>";
        assert!(strict(&wide).is_ok());
        let wider = "<a>".to_owned() + &"<b/>".repeat(256) + "</a>";
        assert!(matches!(strict(&wider), Err(XmlError::TooManyNodes { .. })));
        let big = format!("<a>{}</a>", "x".repeat(l.max_bytes));
        assert_eq!(
            strict(&big).unwrap_err(),
            XmlError::TooLarge {
                bytes: big.len(),
                limit: 512 * 1024
            }
        );
        let fits = format!("<a>{}</a>", "x".repeat(l.max_bytes - 7));
        assert!(strict(&fits).is_ok());
    }

    #[test]
    fn strict_mode_normalizes_line_ends_and_attribute_white_space() {
        let d = strict("<a k=\"x\ty\r\nz\" j=\"&#xA;\">1\r\n2\r3</a>").unwrap();
        let a = d.root().unwrap();
        assert_eq!(d.attr(a, "k"), Some("x y z"));
        assert_eq!(d.attr(a, "j"), Some("\n"), "a reference is not normalized");
        assert_eq!(d.text(a), "1\n2\n3");
    }

    #[test]
    fn strict_mode_refuses_what_signed_xml_must_not_hold() {
        for (bad, why) in [
            ("<a><?pi x?></a>", "a processing instruction"),
            ("<?pi x?><a/>", "a processing instruction before the root"),
            ("<a>\u{1}</a>", "a control character"),
            ("<a>&#x1;</a>", "a reference to a control character"),
            ("<p:a/>", "an undeclared element prefix"),
            ("<a p:k='1'/>", "an undeclared attribute prefix"),
            (
                "<a xmlns:p='u' xmlns:q='u' p:k='1' q:k='2'/>",
                "one expanded name twice",
            ),
            ("<a xmlns:p=''/>", "an undeclared prefix binding"),
            (" <a/><?xml version='1.0'?>", "a late XML declaration"),
        ] {
            assert!(
                matches!(strict(bad), Err(XmlError::Malformed { .. })),
                "{why}: {:?}",
                strict(bad).map(|_| ())
            );
        }
        assert_eq!(
            parse(b"<a>\xff</a>", &Limits::esign(), &|| false).unwrap_err(),
            XmlError::Encoding
        );
        assert_eq!(
            strict("<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><a/>").unwrap_err(),
            XmlError::Encoding
        );
        assert!(strict("<?xml version=\"1.0\" encoding=\"UTF-8\"?><a/>").is_ok());
        assert!(
            p("<a><?pi x?></a>").is_ok(),
            "lenient mode skips instructions"
        );
    }

    #[test]
    fn namespaces_resolve_through_ancestors_and_undeclare() {
        let d = strict("<a xmlns='u' xmlns:p='v'><b xmlns=''><p:c/></b></a>").unwrap();
        let a = d.root().unwrap();
        let b = d.child(a, "b").unwrap();
        let c = d.child(b, "c").unwrap();
        assert_eq!(d.element_namespace(a), Some("u"));
        assert_eq!(d.element_namespace(b), None);
        assert_eq!(d.element_namespace(c), Some("v"));
        assert_eq!(d.namespace(c, "xml"), Some(XML_NAMESPACE));
        assert_eq!(d.descendants(a), vec![a, b, c]);
    }

    #[test]
    fn cancellation_is_polled() {
        let many = "<a>".to_owned() + &"<b/>".repeat(5000) + "</a>";
        let lim = Limits::lenient(8, 10_000, 4);
        assert_eq!(
            parse(many.as_bytes(), &lim, &|| true).unwrap_err(),
            XmlError::Cancelled
        );
    }

    #[test]
    fn truncations_of_a_document_never_panic() {
        let doc = r#"<a k="v"><b>t &amp; u</b><![CDATA[x]]><!-- c --><?p?></a>"#;
        for n in 0..doc.len() {
            if let Some(s) = doc.get(..n) {
                let _ = p(s);
                let _ = strict(s);
            }
        }
    }
}
