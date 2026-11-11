//! A bounded XML reader for XFA packets (XML 1.0 subset, docs/30 §3 XFA, docs/21 §XFA).
//!
//! Written here rather than taken from a crate (ADR-025, proposed): XFA needs elements,
//! attributes, text, CDATA and the five predefined entities with character references,
//! and must refuse everything else that can make a reader do unbounded or outside work.
//!
//! - A document type declaration (`<!DOCTYPE`) or entity declaration (`<!ENTITY`) is
//!   refused (`CS-XFA-0005`): no external entity is ever resolved, no entity expands, so
//!   neither a billion-laughs nor an XXE input can do anything.
//! - Only `&lt;`, `&gt;`, `&amp;`, `&quot;`, `&apos;` and `&#…;` references are known;
//!   any other is malformed (`CS-XFA-0004`).
//! - Element nesting is limited (`CS-XFA-0002`); so is the number of nodes and of
//!   attributes on one element (`CS-XFA-0003`). The parser is iterative: depth costs
//!   no stack.
//! - Comments and processing instructions are skipped (XFA's `renderCache` hints are
//!   not trusted).
//!
//! Names keep their local part: `xfa:data` is `data`. Namespace declarations are
//! dropped; XFA's packets are told apart by their local names, as Adobe's reader does.

use crate::error::XfaError;

/// An index into [`Dom::nodes`].
pub(crate) type NodeId = usize;

/// One element or text node.
#[derive(Debug, Clone, Default)]
pub(crate) struct Node {
    /// Local name; empty for a text node.
    pub name: String,
    /// Attributes by local name, in document order.
    pub attrs: Vec<(String, String)>,
    /// Children, elements and text, in document order.
    pub children: Vec<NodeId>,
    /// The text of a text node.
    pub text: String,
    /// The parent element.
    pub parent: Option<NodeId>,
}

impl Node {
    pub(crate) fn is_text(&self) -> bool {
        self.name.is_empty() && self.parent.is_some()
    }
}

/// A parsed document: node 0 is a synthetic document node whose children are the
/// top-level elements.
#[derive(Debug, Clone, Default)]
pub(crate) struct Dom {
    pub nodes: Vec<Node>,
}

/// Limits the reader holds (from [`crate::XfaLimits`]).
#[derive(Debug, Clone, Copy)]
pub(crate) struct XmlLimits {
    pub max_depth: usize,
    pub max_nodes: usize,
    pub max_attributes: usize,
}

static EMPTY: Node = Node {
    name: String::new(),
    attrs: Vec::new(),
    children: Vec::new(),
    text: String::new(),
    parent: None,
};

impl Dom {
    /// The node, or an empty one for an id out of range.
    pub(crate) fn node(&self, id: NodeId) -> &Node {
        self.nodes.get(id).unwrap_or(&EMPTY)
    }

    pub(crate) fn name(&self, id: NodeId) -> &str {
        &self.node(id).name
    }

    pub(crate) fn attr(&self, id: NodeId, name: &str) -> Option<&str> {
        self.node(id)
            .attrs
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    /// Element children, in order.
    pub(crate) fn elements(&self, id: NodeId) -> impl Iterator<Item = NodeId> + '_ {
        self.node(id)
            .children
            .iter()
            .copied()
            .filter(|c| !self.node(*c).is_text())
    }

    /// The first element child named `name`.
    pub(crate) fn child(&self, id: NodeId, name: &str) -> Option<NodeId> {
        self.elements(id).find(|c| self.name(*c) == name)
    }

    /// Every element child named `name`.
    pub(crate) fn children_named<'a>(
        &'a self,
        id: NodeId,
        name: &'a str,
    ) -> impl Iterator<Item = NodeId> + 'a {
        self.elements(id).filter(move |c| self.name(*c) == name)
    }

    /// A path of first children: `path(n, &["ui", "textEdit"])`.
    pub(crate) fn path(&self, id: NodeId, names: &[&str]) -> Option<NodeId> {
        let mut at = id;
        for n in names {
            at = self.child(at, n)?;
        }
        Some(at)
    }

    /// The concatenated text of every text node under `id`, in document order.
    pub(crate) fn text(&self, id: NodeId) -> String {
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
    pub(crate) fn find(&self, id: NodeId, name: &str) -> Option<NodeId> {
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
    pub(crate) fn has_elements(&self, id: NodeId) -> bool {
        self.elements(id).next().is_some()
    }
}

/// Decode the packets' bytes: UTF-8 unless the declaration names a Latin-1 encoding.
fn decode(bytes: &[u8]) -> String {
    let head = bytes.get(..bytes.len().min(200)).unwrap_or(bytes);
    let head = String::from_utf8_lossy(head).to_ascii_lowercase();
    let latin1 = head.starts_with("<?xml")
        && ["iso-8859-1", "latin1", "windows-1252", "iso8859-1"]
            .iter()
            .any(|e| head.split("?>").next().is_some_and(|d| d.contains(e)));
    if latin1 {
        bytes.iter().map(|b| char::from(*b)).collect()
    } else {
        String::from_utf8_lossy(bytes).into_owned()
    }
}

fn is_name_char(c: char) -> bool {
    !(c.is_whitespace() || matches!(c, '<' | '>' | '/' | '=' | '"' | '\'' | '&' | '!' | '?'))
}

fn local(qname: &str) -> &str {
    qname.rsplit(':').next().unwrap_or(qname)
}

/// Resolve the references in `raw` (text or an attribute value).
fn unescape(raw: &str, offset: usize) -> Result<String, XfaError> {
    if !raw.contains('&') {
        return Ok(raw.to_owned());
    }
    let bad = XfaError::Malformed { offset };
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
                    .filter(|c| *c != '\0')
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
    limits: XmlLimits,
    roots: usize,
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

    fn bad(&self) -> XfaError {
        XfaError::Malformed { offset: self.pos }
    }

    fn advance(&mut self, n: usize) {
        self.pos = self.pos.saturating_add(n);
    }

    /// Skip past `end`, or fail.
    fn skip_past(&mut self, end: &str) -> Result<(), XfaError> {
        let i = self.rest().find(end).ok_or(self.bad())?;
        self.advance(i.saturating_add(end.len()));
        Ok(())
    }

    fn push(&mut self, node: Node) -> Result<NodeId, XfaError> {
        if self.dom.nodes.len() >= self.limits.max_nodes {
            return Err(XfaError::TooManyNodes { offset: self.pos });
        }
        let id = self.dom.nodes.len();
        let parent = node.parent;
        self.dom.nodes.push(node);
        if let Some(p) = parent.and_then(|p| self.dom.nodes.get_mut(p)) {
            p.children.push(id);
        }
        Ok(id)
    }

    fn text(&mut self, raw: &str, offset: usize) -> Result<(), XfaError> {
        let Some(&parent) = self.stack.last() else {
            if raw.trim().is_empty() {
                return Ok(());
            }
            return Err(XfaError::Malformed { offset });
        };
        if parent == 0 {
            if raw.trim().is_empty() {
                return Ok(());
            }
            return Err(XfaError::Malformed { offset });
        }
        let text = unescape(raw, offset)?;
        self.push(Node {
            text,
            parent: Some(parent),
            ..Node::default()
        })?;
        Ok(())
    }

    fn start_tag(&mut self) -> Result<(), XfaError> {
        let start = self.pos;
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
            let raw = self.rest().get(..end).ok_or(self.bad())?.to_owned();
            if raw.contains('<') {
                return Err(self.bad());
            }
            let value = unescape(&raw, self.pos)?;
            self.advance(end.saturating_add(1));
            if seen.contains(&an) {
                return Err(XfaError::Malformed { offset: start });
            }
            seen.push(an.clone());
            if seen.len() > self.limits.max_attributes {
                return Err(XfaError::TooManyNodes { offset: start });
            }
            if an == "xmlns" || an.starts_with("xmlns:") {
                continue;
            }
            attrs.push((local(&an).to_owned(), value));
        };
        let parent = *self.stack.last().ok_or(self.bad())?;
        if parent == 0 {
            self.roots = self.roots.saturating_add(1);
            if self.roots > 1 {
                return Err(XfaError::Malformed { offset: start });
            }
        }
        // The document node is on the stack too; depth counts elements only.
        if !empty && self.stack.len() > self.limits.max_depth {
            return Err(XfaError::TooDeep { offset: start });
        }
        let id = self.push(Node {
            name: local(&name).to_owned(),
            attrs,
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

/// Parse `bytes` as one XML document within `limits`.
pub(crate) fn parse(
    bytes: &[u8],
    limits: XmlLimits,
    cancel: &dyn Fn() -> bool,
) -> Result<Dom, XfaError> {
    let s = decode(bytes);
    let mut p = Parser {
        s: &s,
        pos: 0,
        dom: Dom::default(),
        stack: vec![0],
        limits,
        roots: 0,
        names: Vec::new(),
    };
    p.dom.nodes.push(Node::default());
    // A byte-order mark is not text.
    if p.rest().starts_with('\u{feff}') {
        p.advance('\u{feff}'.len_utf8());
    }
    let mut steps: u32 = 0;
    while !p.rest().is_empty() {
        steps = steps.wrapping_add(1);
        if steps.is_multiple_of(4096) && cancel() {
            return Err(XfaError::Cancelled);
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
            if p.stack.len() <= 1 {
                return Err(XfaError::Malformed { offset: at });
            }
            let parent = *p.stack.last().ok_or(p.bad())?;
            p.push(Node {
                text: raw,
                parent: Some(parent),
                ..Node::default()
            })?;
            p.advance(end.saturating_add(3));
        } else if rest.starts_with("<!DOCTYPE") || rest.starts_with("<!ENTITY") {
            return Err(XfaError::Dtd { offset: p.pos });
        } else if rest.starts_with("<!") {
            return Err(p.bad());
        } else if rest.starts_with("<?") {
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
                _ => return Err(XfaError::Malformed { offset: at }),
            }
        } else {
            p.start_tag()?;
        }
    }
    if p.stack.len() != 1 || p.roots != 1 {
        return Err(XfaError::Malformed { offset: s.len() });
    }
    Ok(p.dom)
}

#[cfg(test)]
mod tests {
    // Test code: a panic is the failure report (CLAUDE.md).
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;

    const LIM: XmlLimits = XmlLimits {
        max_depth: 8,
        max_nodes: 100,
        max_attributes: 4,
    };

    fn p(s: &str) -> Result<Dom, XfaError> {
        parse(s.as_bytes(), LIM, &|| false)
    }

    #[test]
    fn elements_attributes_text_and_references_are_read() {
        let d = p(r#"<?xml version="1.0"?><!-- c --><a:x xmlns:a="u" a:k='v&amp;w'><y>1 &lt; 2 &#x41;&#66;<![CDATA[<raw>]]></y><?pi x?><z/></a:x>"#).unwrap();
        let x = d.elements(0).next().unwrap();
        assert_eq!(d.name(x), "x");
        assert_eq!(d.attr(x, "k"), Some("v&w"));
        assert_eq!(d.node(x).attrs.len(), 1, "xmlns is dropped");
        let y = d.child(x, "y").unwrap();
        assert_eq!(d.text(y), "1 < 2 AB<raw>");
        assert!(d.child(x, "z").is_some());
    }

    #[test]
    fn latin1_declared_input_is_decoded_as_latin1() {
        let d = parse(
            b"<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><a>\xe9</a>",
            LIM,
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
                matches!(p(bad), Err(XfaError::Malformed { .. })),
                "{bad}: {:?}",
                p(bad).map(|_| ())
            );
        }
    }

    #[test]
    fn doctype_and_entity_declarations_are_refused() {
        assert_eq!(
            p("<!DOCTYPE a [<!ENTITY e SYSTEM \"file:///etc/passwd\">]><a>&e;</a>").unwrap_err(),
            XfaError::Dtd { offset: 0 }
        );
        assert!(matches!(
            p("<a><!ENTITY e \"x\"></a>"),
            Err(XfaError::Dtd { .. })
        ));
    }

    #[test]
    fn depth_nodes_and_attributes_are_limited() {
        let deep = "<a>".repeat(8) + &"</a>".repeat(8);
        assert!(p(&deep).is_ok());
        let deeper = "<a>".repeat(9) + &"</a>".repeat(9);
        assert!(matches!(p(&deeper), Err(XfaError::TooDeep { .. })));
        let wide = "<a>".to_owned() + &"<b/>".repeat(98) + "</a>";
        assert!(p(&wide).is_ok());
        let wider = "<a>".to_owned() + &"<b/>".repeat(99) + "</a>";
        assert!(matches!(p(&wider), Err(XfaError::TooManyNodes { .. })));
        assert!(p("<a q='1' r='1' s='1' t='1'/>").is_ok());
        assert!(matches!(
            p("<a q='1' r='1' s='1' t='1' u='1'/>"),
            Err(XfaError::TooManyNodes { .. })
        ));
    }

    #[test]
    fn truncations_of_a_document_never_panic() {
        let doc = r#"<a k="v"><b>t &amp; u</b><![CDATA[x]]><!-- c --><?p?></a>"#;
        for n in 0..doc.len() {
            if let Some(s) = doc.get(..n) {
                let _ = p(s);
            }
        }
    }
}
