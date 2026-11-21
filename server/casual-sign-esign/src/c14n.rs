//! Canonical XML 1.0 and Exclusive XML Canonicalization 1.0, without comments, of an
//! element of a tree read by `casual-sign-xml` in strict mode (ADR-047 §3.5).
//!
//! This is serialization, not cryptography: the rules of W3C `xml-c14n` (2001-03-15)
//! §2.3 and `xml-exc-c14n` (2002-07-18) §3 applied to the subset strict reading leaves
//! (elements, attributes, namespace declarations, text; no comments, processing
//! instructions or DTD). An element subtree is output with:
//!
//! - its name as written, then namespace declarations sorted by prefix (the default
//!   first), then attributes sorted by namespace URI then local name (unqualified
//!   first);
//! - namespace declarations: inclusive, every one in scope that the nearest output
//!   ancestor did not already render with the same value; exclusive, only those the
//!   element visibly uses (its own prefix, its attributes' prefixes), on the same
//!   condition; `xmlns=""` when an unprefixed element sits under a rendered default;
//! - inclusive, an apex that is not the root also takes its ancestors' `xml:`
//!   attributes it lacks (§2.4); exclusive does not;
//! - start and end tags for empty elements; text with `&`, `<`, `>` and CR escaped;
//!   attribute values with `&`, `<`, `"`, TAB, LF and CR escaped.
//!
//! Interoperability is proved against xmlsec1, an independent implementation, on
//! fixtures it signed and in CI on requests we sign (tests/xmlsec.rs, ADR-047 §4).

use std::collections::BTreeMap;

use casual_sign_xml::{Dom, NodeId};

/// Which canonicalization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    /// Canonical XML 1.0, `http://www.w3.org/TR/2001/REC-xml-c14n-20010315`.
    Inclusive,
    /// Exclusive XML Canonicalization 1.0, `http://www.w3.org/2001/10/xml-exc-c14n#`.
    Exclusive,
}

impl Method {
    /// The algorithm URI.
    #[must_use]
    pub const fn uri(self) -> &'static str {
        match self {
            Self::Inclusive => "http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
            Self::Exclusive => "http://www.w3.org/2001/10/xml-exc-c14n#",
        }
    }

    /// The method an algorithm URI names, if it is one of the two (never a
    /// `#WithComments` variant).
    #[must_use]
    pub fn from_uri(uri: &str) -> Option<Self> {
        [Self::Inclusive, Self::Exclusive]
            .into_iter()
            .find(|m| m.uri() == uri)
    }
}

/// Namespace declarations rendered by output ancestors: prefix to URI.
type Rendered = BTreeMap<String, String>;

/// Every namespace in scope at `id`: prefix to URI (an undeclared default removed).
fn in_scope(dom: &Dom, id: NodeId) -> Rendered {
    let mut chain = Vec::new();
    let mut at = Some(id);
    while let Some(n) = at {
        chain.push(n);
        at = dom.node(n).parent;
    }
    let mut out = Rendered::new();
    for n in chain.into_iter().rev() {
        for (p, u) in &dom.node(n).namespaces {
            if u.is_empty() {
                out.remove(p);
            } else {
                out.insert(p.clone(), u.clone());
            }
        }
    }
    out
}

fn escape_text(s: &str, out: &mut String) {
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\r' => out.push_str("&#xD;"),
            c => out.push(c),
        }
    }
}

fn escape_attr(s: &str, out: &mut String) {
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '"' => out.push_str("&quot;"),
            '\t' => out.push_str("&#x9;"),
            '\n' => out.push_str("&#xA;"),
            '\r' => out.push_str("&#xD;"),
            c => out.push(c),
        }
    }
}

fn qname(prefix: &str, local: &str) -> String {
    if prefix.is_empty() {
        local.to_owned()
    } else {
        format!("{prefix}:{local}")
    }
}

struct Writer<'d> {
    dom: &'d Dom,
    method: Method,
    exclude: Option<NodeId>,
    out: String,
}

impl Writer<'_> {
    /// The namespace declarations to write on `id` and the rendered map for its
    /// children.
    fn namespaces(&self, id: NodeId, rendered: &Rendered) -> (Vec<(String, String)>, Rendered) {
        let scope = in_scope(self.dom, id);
        let node = self.dom.node(id);
        let mut next = rendered.clone();
        let mut write = Vec::new();
        let candidates: Vec<String> = match self.method {
            Method::Inclusive => {
                let mut c: Vec<String> = scope.keys().cloned().collect();
                if !c.iter().any(String::is_empty) {
                    c.push(String::new());
                }
                c
            }
            Method::Exclusive => {
                let mut c = vec![node.prefix.clone()];
                for a in &node.attributes {
                    if !a.prefix.is_empty() && !c.contains(&a.prefix) {
                        c.push(a.prefix.clone());
                    }
                }
                c
            }
        };
        for p in candidates {
            if p == "xml" {
                continue;
            }
            match scope.get(&p) {
                Some(uri) => {
                    if rendered.get(&p) != Some(uri) {
                        write.push((p.clone(), uri.clone()));
                        next.insert(p, uri.clone());
                    }
                }
                // An empty default under a rendered non-empty one.
                None if p.is_empty() && rendered.get("").is_some_and(|u| !u.is_empty()) => {
                    write.push((String::new(), String::new()));
                    next.remove("");
                }
                None => {}
            }
        }
        write.sort();
        (write, next)
    }

    /// The attributes to write on `id`, sorted: `(namespace URI, local, qname, value)`.
    fn attributes(&self, id: NodeId, apex: bool) -> Vec<(String, String, String, String)> {
        let node = self.dom.node(id);
        let mut out: Vec<(String, String, String, String)> = node
            .attributes
            .iter()
            .map(|a| {
                let uri = if a.prefix.is_empty() {
                    String::new()
                } else {
                    self.dom
                        .namespace(id, &a.prefix)
                        .unwrap_or_default()
                        .to_owned()
                };
                (
                    uri,
                    a.local.clone(),
                    qname(&a.prefix, &a.local),
                    a.value.clone(),
                )
            })
            .collect();
        if apex && self.method == Method::Inclusive {
            // §2.4: the apex of a document subset takes its ancestors' xml: attributes.
            let mut at = node.parent;
            while let Some(n) = at {
                for a in &self.dom.node(n).attributes {
                    if a.prefix == "xml" && !out.iter().any(|x| x.2 == qname("xml", &a.local)) {
                        out.push((
                            casual_sign_xml::XML_NAMESPACE.to_owned(),
                            a.local.clone(),
                            qname("xml", &a.local),
                            a.value.clone(),
                        ));
                    }
                }
                at = self.dom.node(n).parent;
            }
        }
        out.sort_by(|a, b| (&a.0, &a.1).cmp(&(&b.0, &b.1)));
        out
    }

    /// Write `apex` and everything under it, iteratively.
    fn write(&mut self, apex: NodeId) {
        enum Step {
            Open(NodeId, Rendered, bool),
            Close(String),
        }
        let mut stack = vec![Step::Open(apex, Rendered::new(), true)];
        while let Some(step) = stack.pop() {
            match step {
                Step::Close(name) => {
                    self.out.push_str("</");
                    self.out.push_str(&name);
                    self.out.push('>');
                }
                Step::Open(id, rendered, is_apex) => {
                    if Some(id) == self.exclude {
                        continue;
                    }
                    let node = self.dom.node(id);
                    if node.is_text() {
                        escape_text(&node.text, &mut self.out);
                        continue;
                    }
                    let name = qname(&node.prefix, &node.name);
                    let (decls, next) = self.namespaces(id, &rendered);
                    self.out.push('<');
                    self.out.push_str(&name);
                    for (p, u) in decls {
                        self.out.push_str(" xmlns");
                        if !p.is_empty() {
                            self.out.push(':');
                            self.out.push_str(&p);
                        }
                        self.out.push_str("=\"");
                        escape_attr(&u, &mut self.out);
                        self.out.push('"');
                    }
                    for (_, _, q, v) in self.attributes(id, is_apex) {
                        self.out.push(' ');
                        self.out.push_str(&q);
                        self.out.push_str("=\"");
                        escape_attr(&v, &mut self.out);
                        self.out.push('"');
                    }
                    self.out.push('>');
                    stack.push(Step::Close(name));
                    for c in node.children.iter().rev() {
                        stack.push(Step::Open(*c, next.clone(), false));
                    }
                }
            }
        }
    }
}

/// The canonical form of element `apex` and its subtree, leaving out `exclude` (the
/// enveloped-signature transform removes the `Signature` element) and its subtree.
#[must_use]
pub fn canonicalize(dom: &Dom, apex: NodeId, method: Method, exclude: Option<NodeId>) -> Vec<u8> {
    let mut w = Writer {
        dom,
        method,
        exclude,
        out: String::new(),
    };
    w.write(apex);
    w.out.into_bytes()
}

#[cfg(test)]
mod tests {
    // Test code: a panic is the failure report (CLAUDE.md).
    #![allow(clippy::unwrap_used)]
    use casual_sign_xml::{Limits, parse};

    use super::*;

    fn c14n(xml: &str, path: &[&str], method: Method) -> String {
        let dom = parse(xml.as_bytes(), &Limits::esign(), &|| false).unwrap();
        let root = dom.root().unwrap();
        let at = dom.path(root, path).unwrap();
        String::from_utf8(canonicalize(&dom, at, method, None)).unwrap()
    }

    #[test]
    fn attributes_and_namespaces_are_sorted_and_empty_elements_expanded() {
        let xml = r#"<?xml version="1.0"?>
<doc xmlns:b="urn:b" xmlns:a="urn:a" z="1" a:y='2' b:x="3" b="&quot;&lt;&#x9;"><e/></doc>"#;
        assert_eq!(
            c14n(xml, &[], Method::Inclusive),
            r#"<doc xmlns:a="urn:a" xmlns:b="urn:b" b="&quot;&lt;&#x9;" z="1" a:y="2" b:x="3"><e></e></doc>"#
        );
    }

    #[test]
    fn text_is_escaped_and_cdata_read_as_text() {
        let xml = "<a>x &amp; y &gt; z<![CDATA[<&>]]>&#xD;</a>";
        assert_eq!(
            c14n(xml, &[], Method::Inclusive),
            "<a>x &amp; y &gt; z&lt;&amp;&gt;&#xD;</a>"
        );
    }

    #[test]
    fn a_subset_apex_takes_namespaces_in_scope_inclusive_but_only_used_ones_exclusive() {
        let xml = r#"<r xmlns="urn:d" xmlns:u="urn:u" xml:lang="en"><s><t u:k="1"/></s></r>"#;
        assert_eq!(
            c14n(xml, &["s"], Method::Inclusive),
            r#"<s xmlns="urn:d" xmlns:u="urn:u" xml:lang="en"><t u:k="1"></t></s>"#
        );
        assert_eq!(
            c14n(xml, &["s"], Method::Exclusive),
            r#"<s xmlns="urn:d"><t xmlns:u="urn:u" u:k="1"></t></s>"#
        );
    }

    #[test]
    fn a_default_namespace_undeclared_under_a_rendered_one_is_written_empty() {
        let xml = r#"<r xmlns="urn:d"><s xmlns=""><t/></s></r>"#;
        assert_eq!(
            c14n(xml, &[], Method::Inclusive),
            r#"<r xmlns="urn:d"><s xmlns=""><t></t></s></r>"#
        );
        assert_eq!(
            c14n(xml, &["s"], Method::Inclusive),
            "<s><t></t></s>",
            "nothing rendered above the apex"
        );
    }

    #[test]
    fn redundant_declarations_are_dropped() {
        let xml = r#"<r xmlns:p="urn:p"><p:s xmlns:p="urn:p"/></r>"#;
        assert_eq!(
            c14n(xml, &[], Method::Inclusive),
            r#"<r xmlns:p="urn:p"><p:s></p:s></r>"#
        );
        assert_eq!(
            c14n(xml, &[], Method::Exclusive),
            r#"<r><p:s xmlns:p="urn:p"></p:s></r>"#
        );
    }

    #[test]
    fn the_excluded_subtree_leaves_its_surrounding_text() {
        let xml = "<r>\n  <a>1</a>\n  <s><x/></s>\n</r>";
        let dom = parse(xml.as_bytes(), &Limits::esign(), &|| false).unwrap();
        let r = dom.root().unwrap();
        let s = dom.child(r, "s").unwrap();
        assert_eq!(
            String::from_utf8(canonicalize(&dom, r, Method::Inclusive, Some(s))).unwrap(),
            "<r>\n  <a>1</a>\n  \n</r>"
        );
    }
}
