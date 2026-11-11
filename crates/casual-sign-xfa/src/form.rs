//! The merge (XFA 3.3 "Data binding"): the template's containers instantiated against
//! the data, giving the form tree that layout draws.
//!
//! Built: normal binding (`match="once"`, the default: a named subform takes the next
//! unbound data group of its name in the current data scope, a named field the next
//! unbound data value), `match="global"` (a field takes the first data value of its name
//! anywhere, every such field sharing it), `match="none"` (unbound: the template's
//! default value), `match="dataRef"` with `$`, `$record`, `$data` and `!`-free SOM paths
//! (`a.b[2].c`, `[*]` for every instance), unnamed and unbound subforms as transparent
//! scopes, and instance management by `occur` `min`, `max` and `initial`: as many
//! instances as data groups, within `min` and `max`, else `initial`.
//!
//! Not built (`XFA-01`): `match="global"` on subforms, the data description
//! (`dataDescription`), `xfa:dataNode` hints, record processing beyond the first
//! record, and `use`/`usehref` prototypes.

use std::collections::BTreeSet;

use crate::error::XfaError;
use crate::xml::{Dom, NodeId};

/// What a form node is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    Subform,
    SubformSet,
    Area,
    ExclGroup,
    Field,
    Draw,
}

/// One node of the merged form.
#[derive(Debug, Clone)]
pub(crate) struct FNode {
    pub tpl: NodeId,
    pub kind: Kind,
    pub name: String,
    pub children: Vec<FNode>,
    /// A field's or exclusion group's value as text: bound data, else the template's
    /// default. `None` when it has neither.
    pub value: Option<String>,
}

/// Bounds and counters for one merge.
pub(crate) struct Merge<'d> {
    pub tpl: &'d Dom,
    pub data: Option<&'d Dom>,
    pub data_root: Option<NodeId>,
    bound: BTreeSet<NodeId>,
    pub nodes: usize,
    pub max_nodes: usize,
    /// Current and deepest container nesting.
    depth: usize,
    pub max_depth: usize,
    pub cancel: &'d dyn Fn() -> bool,
}

/// The default value in a `<value>` element: the text of its content element.
pub(crate) fn default_value(dom: &Dom, owner: NodeId) -> Option<String> {
    let v = dom.child(owner, "value")?;
    let content = dom.elements(v).next()?;
    match dom.name(content) {
        "text" | "integer" | "decimal" | "float" | "date" | "time" | "dateTime" | "boolean" => {
            let t = dom.text(content);
            (!t.is_empty()).then_some(t)
        }
        _ => None,
    }
}

fn container_kind(name: &str) -> Option<Kind> {
    Some(match name {
        "subform" => Kind::Subform,
        "subformSet" => Kind::SubformSet,
        "area" => Kind::Area,
        "exclGroup" => Kind::ExclGroup,
        "field" => Kind::Field,
        "draw" => Kind::Draw,
        _ => return None,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Match {
    Once,
    Global,
    None,
    DataRef,
}

fn bind_of(dom: &Dom, n: NodeId) -> (Match, Option<String>) {
    let Some(b) = dom.child(n, "bind") else {
        return (Match::Once, None);
    };
    let m = match dom.attr(b, "match") {
        Some("global") => Match::Global,
        Some("none") => Match::None,
        Some("dataRef") => Match::DataRef,
        _ => Match::Once,
    };
    (m, dom.attr(b, "ref").map(str::to_owned))
}

/// `occur` as (min, max, initial); `max` is `None` for unlimited.
pub(crate) fn occur(dom: &Dom, n: NodeId) -> (usize, Option<usize>, usize) {
    let Some(o) = dom.child(n, "occur") else {
        return (1, Some(1), 1);
    };
    let num = |k: &str| dom.attr(o, k).and_then(|v| v.trim().parse::<i64>().ok());
    let min = num("min").map_or(1, |v| usize::try_from(v.max(0)).unwrap_or(0));
    let max = match num("max") {
        Some(v) if v < 0 => None,
        Some(v) => Some(usize::try_from(v).unwrap_or(0).max(min)),
        None => Some(min.max(1)),
    };
    let initial = num("initial").map_or(min, |v| usize::try_from(v.max(0)).unwrap_or(0));
    (min, max, initial)
}

/// One SOM step: a name and an index (`None` for `[*]`).
fn som_steps(path: &str) -> Vec<(String, Option<usize>)> {
    path.split('.')
        .filter(|s| !s.is_empty())
        .map(|s| match s.split_once('[') {
            Some((n, rest)) => {
                let idx = rest.trim_end_matches(']').trim();
                let i = if idx == "*" {
                    None
                } else {
                    Some(idx.parse().unwrap_or(0))
                };
                (n.to_owned(), i)
            }
            None => (s.to_owned(), Some(0)),
        })
        .collect()
}

impl<'d> Merge<'d> {
    pub(crate) fn new(
        tpl: &'d Dom,
        data: Option<&'d Dom>,
        data_root: Option<NodeId>,
        max_nodes: usize,
        cancel: &'d dyn Fn() -> bool,
    ) -> Self {
        Self {
            tpl,
            data,
            data_root,
            bound: BTreeSet::new(),
            nodes: 0,
            max_nodes,
            depth: 0,
            max_depth: 32,
            cancel,
        }
    }

    fn count(&mut self) -> Result<(), XfaError> {
        self.nodes = self.nodes.saturating_add(1);
        if self.nodes > self.max_nodes {
            return Err(XfaError::TooManyItems {
                limit: self.max_nodes,
            });
        }
        if self.nodes.is_multiple_of(1024) && (self.cancel)() {
            return Err(XfaError::Cancelled);
        }
        Ok(())
    }

    /// Data children of `scope` named `name`: groups (elements with element children,
    /// or empty ones) or values (elements without element children).
    fn data_children(&self, scope: Option<NodeId>, name: &str, groups: bool) -> Vec<NodeId> {
        let (Some(d), Some(s)) = (self.data, scope) else {
            return Vec::new();
        };
        d.children_named(s, name)
            .filter(|c| !groups || d.has_elements(*c) || d.node(*c).children.is_empty())
            .filter(|c| groups || !d.has_elements(*c))
            .collect()
    }

    /// Resolve a `dataRef` SOM path from `scope`.
    fn resolve_ref(&self, scope: Option<NodeId>, path: &str) -> Vec<NodeId> {
        let Some(d) = self.data else {
            return Vec::new();
        };
        let path = path.trim();
        let (start, rest) = if let Some(r) = path.strip_prefix("$record") {
            (self.data_root, r)
        } else if let Some(r) = path.strip_prefix("$data") {
            (self.data_root.and_then(|r| d.node(r).parent), r)
        } else if let Some(r) = path.strip_prefix('$') {
            (scope, r)
        } else {
            (scope, path)
        };
        let mut at: Vec<NodeId> = start.into_iter().collect();
        for (name, idx) in som_steps(rest) {
            let mut next = Vec::new();
            for n in &at {
                let all: Vec<NodeId> = d.children_named(*n, &name).collect();
                match idx {
                    None => next.extend(all),
                    Some(i) => next.extend(all.get(i).copied()),
                }
            }
            at = next;
            if at.is_empty() {
                break;
            }
        }
        at
    }

    fn global(&self, name: &str) -> Option<NodeId> {
        let d = self.data?;
        let root = self.data_root?;
        let mut stack = vec![root];
        while let Some(n) = stack.pop() {
            for c in d.elements(n).collect::<Vec<_>>().into_iter().rev() {
                stack.push(c);
            }
            if n != root && d.name(n) == name && !d.has_elements(n) {
                return Some(n);
            }
        }
        None
    }

    fn data_text(&self, n: NodeId) -> Option<String> {
        self.data.map(|d| d.text(n))
    }

    /// The value a field or exclusion group binds to, consuming it under `once`.
    fn bind_value(&mut self, n: NodeId, name: &str, scope: Option<NodeId>) -> Option<String> {
        let (m, r) = bind_of(self.tpl, n);
        match m {
            Match::None => None,
            Match::Global => {
                if name.is_empty() {
                    return None;
                }
                let g = self.global(name)?;
                self.data_text(g)
            }
            Match::DataRef => {
                let found = self.resolve_ref(scope, r.as_deref().unwrap_or(""));
                let first = found.first().copied()?;
                self.data_text(first)
            }
            Match::Once => {
                if name.is_empty() {
                    return None;
                }
                let c = self
                    .data_children(scope, name, false)
                    .into_iter()
                    .find(|c| !self.bound.contains(c))?;
                self.bound.insert(c);
                self.data_text(c)
            }
        }
    }

    /// Merge the containers under `parent` (a template element) in `scope`.
    pub(crate) fn children(
        &mut self,
        parent: NodeId,
        scope: Option<NodeId>,
    ) -> Result<Vec<FNode>, XfaError> {
        let mut out = Vec::new();
        // Iterative over siblings; recursion follows template nesting, which the XML
        // reader bounds (docs/21 XFA element depth).
        self.depth = self.depth.saturating_add(1);
        if self.depth > self.max_depth {
            return Err(XfaError::TooDeep { offset: 0 });
        }
        let kids: Vec<NodeId> = self.tpl.elements(parent).collect();
        for c in kids {
            let Some(kind) = container_kind(self.tpl.name(c)) else {
                continue;
            };
            let name = self.tpl.attr(c, "name").unwrap_or("").to_owned();
            match kind {
                Kind::Subform => {
                    let (m, r) = bind_of(self.tpl, c);
                    let (min, max, initial) = occur(self.tpl, c);
                    let groups: Vec<NodeId> = match m {
                        Match::DataRef => self.resolve_ref(scope, r.as_deref().unwrap_or("")),
                        Match::Once | Match::Global if !name.is_empty() => self
                            .data_children(scope, &name, true)
                            .into_iter()
                            .filter(|g| !self.bound.contains(g))
                            .collect(),
                        _ => Vec::new(),
                    };
                    let binds = !groups.is_empty();
                    let mut n = if binds {
                        groups.len().max(min)
                    } else {
                        initial.max(min)
                    };
                    if let Some(mx) = max {
                        n = n.min(mx);
                    }
                    let transparent = name.is_empty() || m == Match::None;
                    for i in 0..n {
                        self.count()?;
                        let inner = if transparent {
                            scope
                        } else if let Some(g) = groups.get(i) {
                            self.bound.insert(*g);
                            Some(*g)
                        } else {
                            None
                        };
                        let children = self.children(c, inner)?;
                        out.push(FNode {
                            tpl: c,
                            kind,
                            name: name.clone(),
                            children,
                            value: None,
                        });
                    }
                }
                Kind::SubformSet | Kind::Area => {
                    self.count()?;
                    let children = self.children(c, scope)?;
                    out.push(FNode {
                        tpl: c,
                        kind,
                        name,
                        children,
                        value: None,
                    });
                }
                Kind::ExclGroup => {
                    self.count()?;
                    let bound = self.bind_value(c, &name, scope);
                    let children = self.children(c, scope)?;
                    // The group's value: bound data, else its own default, else the
                    // first member whose default equals its on value.
                    let value = bound.or_else(|| default_value(self.tpl, c));
                    out.push(FNode {
                        tpl: c,
                        kind,
                        name,
                        children,
                        value,
                    });
                }
                Kind::Field => {
                    self.count()?;
                    let bound = self.bind_value(c, &name, scope);
                    let value = bound
                        .filter(|v| !v.is_empty())
                        .or_else(|| default_value(self.tpl, c));
                    out.push(FNode {
                        tpl: c,
                        kind,
                        name,
                        children: Vec::new(),
                        value,
                    });
                }
                Kind::Draw => {
                    self.count()?;
                    out.push(FNode {
                        tpl: c,
                        kind,
                        name,
                        children: Vec::new(),
                        value: None,
                    });
                }
            }
        }
        self.depth = self.depth.saturating_sub(1);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    // Test code: a panic is the failure report (CLAUDE.md).
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;
    use crate::xml::{XmlLimits, parse};

    const LIM: XmlLimits = XmlLimits {
        max_depth: 64,
        max_nodes: 10_000,
        max_attributes: 64,
    };

    fn merged(tpl: &str, data: &str) -> Vec<FNode> {
        let t = parse(tpl.as_bytes(), LIM, &|| false).unwrap();
        let d = parse(data.as_bytes(), LIM, &|| false).unwrap();
        let root = t.find(0, "subform").unwrap();
        let data_root = d.elements(0).next();
        let mut m = Merge::new(&t, Some(&d), data_root, 1000, &|| false);
        m.children(root, data_root).unwrap()
    }

    #[test]
    fn named_fields_take_their_data_values_in_order() {
        let f = merged(
            r#"<subform name="f"><field name="a"/><field name="a"/><field name="b"><value><text>dflt</text></value></field></subform>"#,
            "<f><a>one</a><a>two</a></f>",
        );
        assert_eq!(f.len(), 3);
        assert_eq!(f[0].value.as_deref(), Some("one"));
        assert_eq!(f[1].value.as_deref(), Some("two"));
        assert_eq!(f[2].value.as_deref(), Some("dflt"));
    }

    #[test]
    fn subform_instances_follow_data_within_occur() {
        let tpl = r#"<subform name="f"><subform name="row"><occur min="1" max="3"/><field name="x"/></subform></subform>"#;
        let f = merged(tpl, "<f><row><x>1</x></row><row><x>2</x></row></f>");
        assert_eq!(f.len(), 2);
        assert_eq!(f[1].children[0].value.as_deref(), Some("2"));
        let many = "<f>".to_owned() + &"<row><x>9</x></row>".repeat(5) + "</f>";
        assert_eq!(merged(tpl, &many).len(), 3);
        assert_eq!(merged(tpl, "<f/>").len(), 1);
        let initial = r#"<subform name="f"><subform name="row"><occur min="0" max="-1" initial="4"/></subform></subform>"#;
        assert_eq!(merged(initial, "<f/>").len(), 4);
        let zero = r#"<subform name="f"><subform name="row"><occur min="0" max="2" initial="0"/></subform></subform>"#;
        assert_eq!(merged(zero, "<f/>").len(), 0);
    }

    #[test]
    fn global_none_and_data_ref_bindings() {
        let tpl = r#"<subform name="f">
            <subform name="p"><field name="g"><bind match="global"/></field>
              <field name="n"><bind match="none"/><value><text>keep</text></value></field>
              <field name="r"><bind match="dataRef" ref="$record.deep.v"/></field></subform>
            <field name="g"><bind match="global"/></field></subform>"#;
        let f = merged(
            tpl,
            "<f><p><n>ignored</n></p><g>G</g><deep><v>V</v></deep></f>",
        );
        let p = &f[0];
        assert_eq!(p.children[0].value.as_deref(), Some("G"));
        assert_eq!(p.children[1].value.as_deref(), Some("keep"));
        assert_eq!(p.children[2].value.as_deref(), Some("V"));
        assert_eq!(f[1].value.as_deref(), Some("G"));
    }

    #[test]
    fn unnamed_subforms_are_transparent_scopes() {
        let f = merged(
            r#"<subform name="f"><subform><field name="a"/></subform></subform>"#,
            "<f><a>x</a></f>",
        );
        assert_eq!(f[0].children[0].value.as_deref(), Some("x"));
    }

    #[test]
    fn the_node_limit_stops_an_instance_explosion() {
        let t = parse(
            br#"<subform name="f"><subform name="r"><occur min="100000" max="-1"/></subform></subform>"#,
            LIM,
            &|| false,
        )
        .unwrap();
        let root = t.find(0, "subform").unwrap();
        let mut m = Merge::new(&t, None, None, 500, &|| false);
        assert_eq!(
            m.children(root, None).unwrap_err(),
            XfaError::TooManyItems { limit: 500 }
        );
    }

    #[test]
    fn the_nesting_limit_stops_the_merge_recursion() {
        let t = parse(
            br#"<subform name="f"><subform><subform><subform/></subform></subform></subform>"#,
            LIM,
            &|| false,
        )
        .unwrap();
        let root = t.find(0, "subform").unwrap();
        let mut m = Merge::new(&t, None, None, 500, &|| false);
        m.max_depth = 3;
        assert_eq!(
            m.children(root, None).unwrap_err(),
            XfaError::TooDeep { offset: 0 }
        );
        let mut m = Merge::new(&t, None, None, 500, &|| false);
        m.max_depth = 4;
        assert!(m.children(root, None).is_ok());
    }
}
